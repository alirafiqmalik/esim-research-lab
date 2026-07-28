"""Uniform classified-finding recorder for the autonomous campaign.

Every fuzz/test direction appends findings here so the final report is consistent.
The classification is the whole point of the campaign: a mutation being "accepted"
is only a real finding if the real GSMA protocol also leaves that field mutable.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

CAMPAIGN = Path(__file__).resolve().parent
FINDINGS = CAMPAIGN / "findings.jsonl"

# classification vocabulary
CONFORMANT = "CONFORMANT"          # testbed rejects exactly as a spec-compliant node must
REAL_GAP = "REAL-GAP"             # genuinely unauthenticated/mutable in real RSP too
ARTIFACT = "TESTBED-ARTIFACT"     # accepted only due to our simplification; not real
VALID = {CONFORMANT, REAL_GAP, ARTIFACT}


@dataclass
class Finding:
    round: int
    direction: str
    channel: str
    spec_section: str
    hypothesis: str
    mutation: str
    observed: str
    classification: str
    rationale: str
    severity: str = "info"          # info | low | medium | high
    artifact_path: str = ""
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if self.classification not in VALID:
            raise ValueError(f"classification must be one of {sorted(VALID)}, got {self.classification!r}")


def append(finding: Finding) -> None:
    with FINDINGS.open("a") as fh:
        fh.write(json.dumps(asdict(finding)) + "\n")


def append_many(findings: list[Finding]) -> None:
    with FINDINGS.open("a") as fh:
        for f in findings:
            fh.write(json.dumps(asdict(f)) + "\n")


def load_all() -> list[dict]:
    if not FINDINGS.exists():
        return []
    out = []
    for line in FINDINGS.read_text().splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def summary() -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in load_all():
        counts[f["classification"]] = counts.get(f["classification"], 0) + 1
    return counts


_DEDUP_KEYS = ("direction", "channel", "hypothesis", "mutation", "observed", "classification")


def load_deduped() -> list[dict]:
    """load_all(), collapsing re-runs of the same script to one entry each.

    A campaign script re-run (e.g. after a core fix, to confirm findings still
    hold) legitimately appends identical records again; this view is what
    reporting should use so re-runs don't inflate finding counts."""
    seen: set[tuple] = set()
    out: list[dict] = []
    for f in load_all():
        key = tuple(f.get(k) for k in _DEDUP_KEYS)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
