"""Unique / unexpected behaviour writer for the deep read-only campaign.

Writes ONLY novel-or-unexpected behaviours, one JSON object per line, plus a
``summary.json`` at the end. Every-candidate logging lives elsewhere; this writer
exists so the deep campaign's output is the short list of things worth a human's
attention, not the full firehose.

Nothing here sends anything. It records what the campaign observed.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path

# Keys every JSONL row carries, in schema order.
ROW_KEYS: tuple[str, ...] = (
    "ts",
    "mode",
    "phase",
    "apdu",
    "tag",
    "command",
    "classification",
    "sent",
    "sw",
    "resp",
    "resp_fingerprint",
    "novelty",
    "repeat_consistency",
    "severity",
)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


@dataclass(frozen=True)
class BehaviourRecord:
    """One unique-or-unexpected behaviour row."""

    mode: str
    phase: str
    apdu: str
    tag: str | None
    command: str
    classification: str
    sent: bool
    sw: str | None
    resp: str | None
    resp_fingerprint: str
    novelty: list[str]
    repeat_consistency: str
    severity: str

    def to_row(self) -> dict[str, object]:
        return {
            "ts": _now(),
            "mode": self.mode,
            "phase": self.phase,
            "apdu": self.apdu.upper(),
            "tag": self.tag,
            "command": self.command,
            "classification": self.classification,
            "sent": self.sent,
            "sw": self.sw,
            "resp": self.resp,
            "resp_fingerprint": self.resp_fingerprint,
            "novelty": list(self.novelty),
            "repeat_consistency": self.repeat_consistency,
            "severity": self.severity,
        }


@dataclass
class UniqueBehaviourReporter:
    """Stream unique/unexpected rows to JSONL and tally a final summary."""

    out_path: Path
    summary_path: Path
    mode: str
    phase: str
    allowlist: list[str]

    written: int = 0
    considered: int = 0
    sent: int = 0
    distinct_signatures: int = 0
    _distinct_sws: set[str] = field(default_factory=set)
    _novelty_counts: dict[str, int] = field(default_factory=dict)
    _severity_counts: dict[str, int] = field(default_factory=dict)
    _fh: object = None

    def __enter__(self) -> "UniqueBehaviourReporter":
        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.out_path.open("a")
        return self

    def __exit__(self, *exc: object) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def note_considered(self, sw: str | None, sent: bool) -> None:
        """Count every candidate for the summary, written or not."""
        self.considered += 1
        if sent:
            self.sent += 1
        if sw:
            self._distinct_sws.add(sw)

    def report(self, record: BehaviourRecord) -> bool:
        """Write a row only when it carries novelty. Returns True if written."""
        if not record.novelty:
            return False
        if self._fh is None:
            raise RuntimeError("reporter used outside its context manager")
        row = record.to_row()
        self._fh.write(json.dumps(row) + "\n")
        self._fh.flush()
        self.written += 1
        for label in record.novelty:
            self._novelty_counts[label] = self._novelty_counts.get(label, 0) + 1
        self._severity_counts[record.severity] = (
            self._severity_counts.get(record.severity, 0) + 1
        )
        return True

    def finalize(self, *, distinct_signatures: int) -> dict[str, object]:
        """Write summary.json and return the summary dict."""
        summary: dict[str, object] = {
            "ts": _now(),
            "mode": self.mode,
            "phase": self.phase,
            "considered": self.considered,
            "sent": self.sent,
            "unique_or_unexpected_written": self.written,
            "distinct_signatures": distinct_signatures,
            "distinct_sws": sorted(self._distinct_sws),
            "unexpected_by_type": dict(sorted(self._novelty_counts.items())),
            "severity_counts": dict(sorted(self._severity_counts.items())),
            "allowlist_used": list(self.allowlist),
            "card_state_before": None,
            "card_state_after": None,
        }
        self.summary_path.parent.mkdir(parents=True, exist_ok=True)
        self.summary_path.write_text(json.dumps(summary, indent=2) + "\n")
        return summary
