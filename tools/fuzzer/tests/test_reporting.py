"""Unit tests for the unique/unexpected JSONL reporter. No device."""

from __future__ import annotations

import json
from pathlib import Path

from reporting import ROW_KEYS, BehaviourRecord, UniqueBehaviourReporter


def _record(novelty: list[str], severity: str = "info") -> BehaviourRecord:
    return BehaviourRecord(
        mode="deep",
        phase="dry",
        apdu="81E2910003BF2000",
        tag="BF20",
        command="BF20",
        classification="ALLOWED",
        sent=False,
        sw=None,
        resp=None,
        resp_fingerprint="empty",
        novelty=novelty,
        repeat_consistency="not_tested",
        severity=severity,
    )


def _reporter(tmp_path: Path) -> UniqueBehaviourReporter:
    return UniqueBehaviourReporter(
        out_path=tmp_path / "unique.jsonl",
        summary_path=tmp_path / "summary.json",
        mode="deep",
        phase="dry",
        allowlist=["BF20", "BF3E"],
    )


def test_only_novel_rows_written(tmp_path: Path) -> None:
    with _reporter(tmp_path) as rep:
        assert rep.report(_record([])) is False  # boring: not written
        assert rep.report(_record(["new_signature"])) is True
        assert rep.report(_record([])) is False

    lines = (tmp_path / "unique.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1


def test_written_row_has_all_schema_keys(tmp_path: Path) -> None:
    with _reporter(tmp_path) as rep:
        rep.report(_record(["novel_sw", "rare_sw"], severity="warning"))
    row = json.loads((tmp_path / "unique.jsonl").read_text().strip())
    for key in ROW_KEYS:
        assert key in row, key
    assert row["novelty"] == ["novel_sw", "rare_sw"]
    assert row["severity"] == "warning"


def test_summary_written_with_counts(tmp_path: Path) -> None:
    with _reporter(tmp_path) as rep:
        rep.note_considered("9000", sent=True)
        rep.note_considered("6A80", sent=True)
        rep.report(_record(["new_signature"]))
        rep.report(_record(["success_on_malformed"], severity="warning"))
        summary = rep.finalize(distinct_signatures=7)

    on_disk = json.loads((tmp_path / "summary.json").read_text())
    assert on_disk == summary
    assert summary["considered"] == 2
    assert summary["sent"] == 2
    assert summary["unique_or_unexpected_written"] == 2
    assert summary["distinct_signatures"] == 7
    assert sorted(summary["distinct_sws"]) == ["6A80", "9000"]
    assert summary["unexpected_by_type"]["new_signature"] == 1
    assert summary["unexpected_by_type"]["success_on_malformed"] == 1
    assert summary["allowlist_used"] == ["BF20", "BF3E"]
    assert "card_state_before" in summary
    assert "card_state_after" in summary
