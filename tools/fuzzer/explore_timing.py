"""Timing side-channel probe over allowlisted read commands.

Applies ``constant-time-testing`` (dudect-style statistical detection) to the
eUICC's read surface. It measures the response-latency distribution of a fixed
read against a class of varied reads and flags a data-dependent timing gap.

This is strictly read-only. It times the existing allowlisted reads as they pass
through the same ``engine.consider`` chokepoint; it sends nothing new.

Controlling host-side noise. The dominant cost here is host-side subprocess
jitter (fork/exec of the CLI, scheduler wakeups), which swamps any card-internal
timing difference. The harness controls for it the way dudect does:

- Many repeats per class, not a single timing.
- Robust statistics: the median and the median absolute deviation (MAD), so a
  handful of scheduler-stalled outliers do not move the estimate.
- A modified z-score outlier test (0.6745*(x-med)/MAD) to count, not average in,
  the stalls.
- A robust effect size (median gap over pooled MAD) as the flag, instead of a
  raw mean difference that jitter would trip constantly.
- Interleaved measurement of the two classes so slow drift hits both equally.
- A warm-up discard so first-call fork/import cost is not attributed to a class.

A flagged gap is a lead, not a proof: confirm with an isolated CPU core
(``taskset``) and a longer run before treating it as a real side channel.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from engine import FuzzEngine
from explore_common import select_apdu, store_data_get

# Robust-statistics thresholds. 3.5 is the standard modified-z outlier cut; the
# same value gates the effect size so only a gap several MADs wide is flagged.
_OUTLIER_Z = 3.5
_EFFECT_THRESHOLD = 3.5


# ---- pure statistics (unit-testable without a device) ----------------------


def median(values: list[float]) -> float:
    """Median of a non-empty sample. Raises ValueError on empty input."""
    if not values:
        raise ValueError("median of empty sample")
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def mad(values: list[float], center: float | None = None) -> float:
    """Median absolute deviation about the median (or a supplied center)."""
    if not values:
        raise ValueError("MAD of empty sample")
    med = median(values) if center is None else center
    return median([abs(v - med) for v in values])


def percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile of a non-empty sample."""
    if not values:
        raise ValueError("percentile of empty sample")
    if not 0.0 <= pct <= 100.0:
        raise ValueError(f"percentile out of range: {pct}")
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, round(pct / 100.0 * (len(ordered) - 1))))
    return float(ordered[rank])


def modified_z_scores(values: list[float]) -> list[float]:
    """Iglewicz-Hoaglin modified z-scores. Zeros when MAD is 0 (no spread)."""
    med = median(values)
    dispersion = mad(values, med)
    if dispersion == 0:
        return [0.0 for _ in values]
    return [0.6745 * (v - med) / dispersion for v in values]


@dataclass(frozen=True)
class TimingStats:
    """Robust summary of one class's latency sample (nanoseconds)."""

    label: str
    n: int
    median_ns: float
    mad_ns: float
    min_ns: float
    p90_ns: float
    outlier_count: int


def aggregate(label: str, latencies: list[int], *, outlier_z: float = _OUTLIER_Z) -> TimingStats:
    """Reduce a latency sample to robust statistics."""
    if not latencies:
        raise ValueError(f"no latencies for class {label!r}")
    floats = [float(v) for v in latencies]
    med = median(floats)
    scores = modified_z_scores(floats)
    return TimingStats(
        label=label,
        n=len(floats),
        median_ns=med,
        mad_ns=mad(floats, med),
        min_ns=min(floats),
        p90_ns=percentile(floats, 90.0),
        outlier_count=sum(1 for z in scores if abs(z) > outlier_z),
    )


@dataclass(frozen=True)
class TimingComparison:
    """Robust two-class comparison and the side-channel flag."""

    class_a: TimingStats
    class_b: TimingStats
    median_diff_ns: float
    robust_effect: float
    flagged: bool


def compare(
    a: TimingStats, b: TimingStats, *, effect_threshold: float = _EFFECT_THRESHOLD
) -> TimingComparison:
    """Compare two classes with a MAD-pooled robust effect size."""
    diff = a.median_ns - b.median_ns
    pooled = (a.mad_ns + b.mad_ns) / 2.0
    effect = abs(diff) / pooled if pooled > 0 else 0.0
    return TimingComparison(
        class_a=a,
        class_b=b,
        median_diff_ns=diff,
        robust_effect=effect,
        flagged=effect > effect_threshold,
    )


# ---- live probe -------------------------------------------------------------


@dataclass(frozen=True)
class TimingSample:
    """One timed exchange."""

    label: str
    apdu_hex: str
    latency_ns: int
    sw: str | None


@dataclass
class TimingProbe:
    """Time allowlisted reads through the engine chokepoint.

    ``clock`` and the engine are injectable so the loop is unit-testable with a
    scripted clock and a fake engine, no device.
    """

    engine: FuzzEngine
    clock: Callable[[], int] = time.perf_counter_ns
    rng: random.Random = field(default_factory=lambda: random.Random(0xE51C0))

    def measure(self, apdu_hex: str, label: str) -> TimingSample:
        """Time one engine.consider round-trip for an allowlisted read."""
        start = self.clock()
        outcome = self.engine.consider(apdu_hex)
        elapsed = self.clock() - start
        return TimingSample(label=label, apdu_hex=apdu_hex, latency_ns=elapsed, sw=outcome.sw)

    def run_classes(
        self, classes: dict[str, list[str]], *, repeats: int, warmup: int = 8
    ) -> dict[str, list[int]]:
        """Interleave-measure each class ``repeats`` times, dropping ``warmup``.

        Classes are measured round-robin per iteration so slow drift hits both
        equally. Within a class the APDU is chosen at random when the class holds
        several, matching the fixed-vs-varied input design.
        """
        if repeats <= 0:
            raise ValueError("repeats must be positive")
        collected: dict[str, list[int]] = {label: [] for label in classes}
        for _ in range(warmup + repeats):
            for label, apdus in classes.items():
                if not apdus:
                    raise ValueError(f"class {label!r} has no APDUs")
                apdu = apdus[0] if len(apdus) == 1 else self.rng.choice(apdus)
                sample = self.measure(apdu, label)
                collected[label].append(sample.latency_ns)
        # Drop the warm-up prefix per class; fork/import cost lands there.
        return {label: series[warmup:] for label, series in collected.items()}


def default_classes() -> dict[str, list[str]]:
    """The fixed vs varied read classes timed by the live campaign.

    ``fixed`` repeats one allowlisted read; ``varied`` rotates several. All are
    read-only and allowlisted, so the safety gate passes every one.
    """
    return {
        "fixed": [store_data_get(0xBF2E)],  # GetEUICCChallenge, repeated
        "varied": [
            store_data_get(0xBF3E),  # GetEID
            store_data_get(0xBF20),  # GetEUICCInfo1
            store_data_get(0xBF2E),  # GetEUICCChallenge
            select_apdu(bytes.fromhex("A0000005591010FFFFFFFF8900000100")),  # SELECT ISD-R
        ],
    }
