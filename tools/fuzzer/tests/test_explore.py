"""Unit tests for the read-only discovery campaigns. No device is ever touched.

Every candidate generator is checked to emit only allowlisted-INS/tag APDUs, the
sweeps are checked to cover their intended space, and the timing harness is
checked to aggregate medians correctly on synthetic latencies. The drive loop is
exercised with a dry engine (nothing sent) and with a fake live transport.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import explore_getdata
import explore_read
import explore_select
import explore_timing
from engine import FuzzEngine
from euicc_transport import ApduResult
from explore_common import Candidate, drive
from novelty import NoveltyEngine
from reporting import UniqueBehaviourReporter
from safety import Classification, classify


def _ins(apdu_hex: str) -> int:
    return bytes.fromhex(apdu_hex)[1]


# ---- generators emit only allowlisted, never-blocked candidates -------------


def _assert_never_blocked(cands: list[Candidate]) -> None:
    assert cands, "generator produced nothing"
    for cand in cands:
        verdict = classify(cand.apdu_hex)
        assert verdict.classification is not Classification.BLOCKED, cand.apdu_hex


def test_select_generator_only_a4_and_allowed() -> None:
    cands = list(explore_select.candidates())
    _assert_never_blocked(cands)
    for cand in cands:
        assert _ins(cand.apdu_hex) == 0xA4, cand.apdu_hex
        assert classify(cand.apdu_hex).classification is Classification.ALLOWED


def test_select_sweep_covers_known_and_rid_space() -> None:
    targets = {c.target for c in explore_select.candidates()}
    joined = " ".join(targets)
    assert "ISD-R" in joined
    assert "ECASD" in joined
    assert "A0000005591010FFFFFFFF8900000100" in joined  # ISD-R AID literal
    assert "A0000005591010FFFFFFFF8900000200" in joined  # ECASD AID literal
    # RID-prefix partial SELECTs and the empty-AID next-occurrence walk.
    assert any("RID:RID-GSMA" in t for t in targets)
    assert any("RID:RID-GP" in t for t in targets)
    assert any(t == "AID:empty:next" for t in targets)


def test_getdata_generator_only_ca_cb_and_allowed() -> None:
    cands = list(explore_getdata.candidates())
    _assert_never_blocked(cands)
    for cand in cands:
        assert _ins(cand.apdu_hex) in (0xCA, 0xCB), cand.apdu_hex
        assert classify(cand.apdu_hex).classification is Classification.ALLOWED


def test_getdata_sweep_covers_full_1byte_and_curated() -> None:
    cands = list(explore_getdata.candidates())
    one_byte = {c.target for c in cands if c.target.startswith("DO:1byte:")}
    assert len(one_byte) == 256  # full 0x00..0xFF sweep
    assert any(c.target.startswith("DO:CPLC:") for c in cands)
    assert any("9F7F" in c.target for c in cands)
    assert any(_ins(c.apdu_hex) == 0xCB for c in cands)  # odd-INS variant present


def test_read_generator_only_b0_b2_c0_and_allowed() -> None:
    cands = list(explore_read.candidates())
    _assert_never_blocked(cands)
    for cand in cands:
        assert _ins(cand.apdu_hex) in (0xB0, 0xB2, 0xC0), cand.apdu_hex
        assert classify(cand.apdu_hex).classification is Classification.ALLOWED


def test_read_sweep_covers_sfi_range() -> None:
    cands = list(explore_read.candidates())
    bin_sfis = {c.target for c in cands if c.target.startswith("EF-BIN:sfi")}
    rec_sfis = {c.target for c in cands if c.target.startswith("EF-REC:sfi")}
    assert len(bin_sfis) == 30  # SFI 1..30
    assert any("sfi01" in t for t in bin_sfis)
    assert any("sfi30" in t for t in bin_sfis)
    assert rec_sfis  # READ RECORD sweep present
    assert any(c.command == "GETRESP" for c in cands)


# ---- timing: pure statistics on synthetic latencies -------------------------


def test_median_odd_and_even() -> None:
    assert explore_timing.median([3, 1, 2]) == 2
    assert explore_timing.median([4, 1, 3, 2]) == 2.5


def test_mad_and_modified_z_scores() -> None:
    values = [10.0, 10.0, 10.0, 10.0, 100.0]
    med = explore_timing.median(values)
    assert med == 10.0
    assert explore_timing.mad(values, med) == 0.0
    # MAD is zero (no spread in the bulk), so z-scores collapse to zero.
    assert explore_timing.modified_z_scores(values) == [0.0] * 5


def test_aggregate_medians_and_outliers() -> None:
    # 20 tight samples around 100ns plus one 5000ns scheduler stall.
    latencies = [100 + (i % 3) for i in range(20)] + [5000]
    stats = explore_timing.aggregate("fixed", latencies)
    assert stats.n == 21
    assert 100 <= stats.median_ns <= 102
    assert stats.min_ns == 100
    assert stats.outlier_count == 1  # the stall is flagged, not averaged in


def test_compare_flags_wide_gap_not_noise() -> None:
    tight_a = explore_timing.aggregate("a", [100 + (i % 3) for i in range(30)])
    tight_b = explore_timing.aggregate("b", [100 + (i % 3) for i in range(30)])
    same = explore_timing.compare(tight_a, tight_b)
    assert same.flagged is False

    slow = explore_timing.aggregate("c", [900 + (i % 3) for i in range(30)])
    gap = explore_timing.compare(tight_a, slow)
    assert gap.flagged is True
    assert gap.robust_effect > 3.5


# ---- timing: live loop with a scripted clock and fake engine ----------------


class _ClockedEngine:
    """Fake engine whose consider advances a virtual clock by a per-APDU latency."""

    def __init__(self, latency_by_apdu: dict[str, int]) -> None:
        self._t = 0
        self._latency = latency_by_apdu
        self.sent = 0
        self.live = True

    def now(self) -> int:
        return self._t

    def consider(self, apdu_hex: str) -> SimpleNamespace:
        self._t += self._latency[apdu_hex]
        self.sent += 1
        return SimpleNamespace(sw="9000")


def test_timing_probe_aggregates_class_medians() -> None:
    fake = _ClockedEngine({"AA": 100, "BB": 200})
    probe = explore_timing.TimingProbe(engine=fake, clock=fake.now)
    series = probe.run_classes({"fixed": ["AA"], "varied": ["BB"]}, repeats=5, warmup=2)

    assert len(series["fixed"]) == 5  # warm-up prefix dropped
    assert len(series["varied"]) == 5
    fixed = explore_timing.aggregate("fixed", series["fixed"])
    varied = explore_timing.aggregate("varied", series["varied"])
    assert fixed.median_ns == 100
    assert varied.median_ns == 200
    assert explore_timing.compare(fixed, varied).median_diff_ns == -100


# ---- drive loop: dry (nothing sent) and fake-live (discovery populated) ------


def _reporter(tmp_path, mode: str) -> UniqueBehaviourReporter:
    return UniqueBehaviourReporter(
        out_path=tmp_path / f"{mode}.jsonl",
        summary_path=tmp_path / f"{mode}.summary.json",
        mode=mode,
        phase="dry",
        allowlist=["INS_A4"],
    )


def test_drive_dry_writes_rows_no_discovery(tmp_path) -> None:
    engine = FuzzEngine(live=False, transport=None)
    novelty = NoveltyEngine()
    cands = list(explore_select.candidates())[:8]
    with _reporter(tmp_path, "explore_select") as reporter:
        summary = drive(
            angle="select",
            engine=engine,
            novelty=novelty,
            reporter=reporter,
            candidates=cands,
            phase="dry",
            wall=30,
            send_cap=None,
        )
    assert summary["angle"] == "select"
    assert summary["sent"] == 0
    assert summary["discovery"] == []  # nothing sent in dry-run
    on_disk = json.loads((tmp_path / "explore_select.summary.json").read_text())
    assert on_disk["angle"] == "select"


class _FakeTransport:
    def __init__(self, sw: str) -> None:
        self._sw = sw

    def send(self, apdu_hex: str) -> ApduResult:
        resp = f"6F10840E{'AB' * 6}{self._sw}".upper()
        return ApduResult(resp_hex=resp, sw=self._sw, ok=self._sw == "9000", raw={})


def test_drive_live_records_discovery(tmp_path) -> None:
    engine = FuzzEngine(live=True, transport=_FakeTransport("9000"))
    novelty = NoveltyEngine()
    cands = list(explore_select.candidates())[:4]
    with _reporter(tmp_path, "explore_select") as reporter:
        summary = drive(
            angle="select",
            engine=engine,
            novelty=novelty,
            reporter=reporter,
            candidates=cands,
            phase="live",
            wall=30,
            send_cap=None,
        )
    assert summary["sent"] == 4
    assert len(summary["discovery"]) >= 1  # 9000 responses count as hits
    for finding in summary["discovery"]:
        assert finding["sw"] == "9000"
        assert finding["target"].startswith("AID:")


def test_drive_live_send_cap_stops_sending(tmp_path) -> None:
    engine = FuzzEngine(live=True, transport=_FakeTransport("9000"))
    novelty = NoveltyEngine()
    cands = list(explore_select.candidates())[:10]
    with _reporter(tmp_path, "explore_select") as reporter:
        summary = drive(
            angle="select",
            engine=engine,
            novelty=novelty,
            reporter=reporter,
            candidates=cands,
            phase="live",
            wall=30,
            send_cap=3,
        )
    assert summary["sent"] == 3  # cap honoured, rest classified without sending
