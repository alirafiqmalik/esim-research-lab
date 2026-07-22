"""Unit tests for the length-parser acceptance campaign. No device.

Every candidate is classified through the real safety layer; the transport is
mocked so nothing can reach a card. These tests assert three things:

1. The generator emits the intended length-encoding classes (and reproduces the
   three known lead APDUs verbatim).
2. Every candidate is a STORE DATA command on an allowlisted read tag.
3. The aggregation buckets synthetic rows into the acceptance map correctly.
"""

from __future__ import annotations

from unittest.mock import patch

from lenient_parsing import (
    LENGTH_CLASSES,
    READ_TAGS,
    aggregate,
    analyze_lenient,
    build_and_run,
    generate_candidates,
)
from safety import ALLOWLIST_TAGS, Classification, classify

# The three malformed framings the prior campaign saw accepted with 9000.
_LEAD_APDUS = {
    "81E2910006BF2D82FFFF5A",
    "81E2910004BF2DFF5A",
    "81E2910005BF2D81FF5A",
}


def test_generator_covers_every_length_class() -> None:
    seen = {c.length_class for c in generate_candidates()}
    for cls in LENGTH_CLASSES:
        assert cls in seen, f"missing length class {cls}"
    assert seen == set(LENGTH_CLASSES)


def test_generator_reproduces_lead_apdus() -> None:
    apdus = {c.apdu_hex for c in generate_candidates()}
    assert _LEAD_APDUS <= apdus


def test_every_candidate_is_allowlisted_read_tag() -> None:
    allowed = {f"{t:04X}" for t in ALLOWLIST_TAGS}
    for c in generate_candidates():
        assert c.command in allowed, c.command
        verdict = classify(c.apdu_hex)
        assert verdict.classification is Classification.ALLOWED, c.apdu_hex
        assert verdict.tag in ALLOWLIST_TAGS, c.apdu_hex


def test_every_tag_gets_the_full_class_set() -> None:
    by_tag: dict[str, set[str]] = {}
    for c in generate_candidates():
        by_tag.setdefault(c.command, set()).add(c.length_class)
    assert set(by_tag) == {f"{t:04X}" for t in READ_TAGS}
    for classes in by_tag.values():
        assert classes == set(LENGTH_CLASSES)


def test_well_formed_baselines_not_marked_malformed() -> None:
    by_class: dict[str, bool] = {}
    for c in generate_candidates():
        by_class.setdefault(c.length_class, c.malformed)
    assert by_class["inner_short_true"] is False
    assert by_class["empty_value"] is False
    assert by_class["inner_over_long2"] is True
    assert by_class["inner_truncated"] is True


def test_aggregate_buckets_accept_reject_and_txerror() -> None:
    rows = [
        # accepted 9000 twice
        {"command": "BF2D", "length_class": "inner_over_long2", "sent": True, "sw": "9000", "classification": "ALLOWED", "transport_error": None},
        {"command": "BF2D", "length_class": "inner_over_long2", "sent": True, "sw": "9000", "classification": "ALLOWED", "transport_error": None},
        # rejected with a specific SW
        {"command": "BF2D", "length_class": "inner_truncated", "sent": True, "sw": "6A80", "classification": "ALLOWED", "transport_error": None},
        # transport error
        {"command": "BF2D", "length_class": "lc_over", "sent": False, "sw": None, "classification": "ALLOWED", "transport_error": "boom"},
        # not sent (dry)
        {"command": "BF20", "length_class": "empty_value", "sent": False, "sw": None, "classification": "ALLOWED", "transport_error": None},
    ]
    agg = aggregate(rows)

    over = agg["BF2D"]["inner_over_long2"]
    assert over["total"] == 2
    assert over["accepted_9000"] == 2
    assert over["rejected"] == {}
    assert over["status"] == "accepted"

    trunc = agg["BF2D"]["inner_truncated"]
    assert trunc["rejected"] == {"6A80": 1}
    assert trunc["accepted_9000"] == 0
    assert trunc["status"] == "rejected(6A80)"

    txerr = agg["BF2D"]["lc_over"]
    assert txerr["transport_error"] == 1
    assert txerr["status"] == "transport_error"

    dry = agg["BF20"]["empty_value"]
    assert dry["not_sent"] == 1
    assert dry["status"] == "not_sent(dry)"


def test_aggregate_mixed_status() -> None:
    rows = [
        {"command": "BF2D", "length_class": "inner_zero_with_body", "sent": True, "sw": "9000", "classification": "ALLOWED", "transport_error": None},
        {"command": "BF2D", "length_class": "inner_zero_with_body", "sent": True, "sw": "6A80", "classification": "ALLOWED", "transport_error": None},
    ]
    agg = aggregate(rows)
    bucket = agg["BF2D"]["inner_zero_with_body"]
    assert bucket["accepted_9000"] == 1
    assert bucket["rejected"] == {"6A80": 1}
    assert bucket["status"] == "mixed(6A80)"


def test_dry_build_and_run_writes_map(tmp_path) -> None:
    """End-to-end dry run: no transport is built, map files are written."""
    from engine import FuzzEngine

    engine = FuzzEngine(live=False, allow_destructive=False, transport=None)
    out = tmp_path / "lenient.jsonl"
    with patch("euicc_transport.subprocess.run") as mock_run:
        summary = build_and_run(
            out_path=out,
            summary_path=tmp_path / "summary.json",
            full_path=tmp_path / "full.jsonl",
            map_json=tmp_path / "lenient_map.json",
            map_md=tmp_path / "lenient_map.md",
            phase="dry",
            engine=engine,
            wall=60,
            send_cap=None,
        )
        # Dry run must never touch the transport subprocess.
        mock_run.assert_not_called()

    assert summary["sent"] == 0
    assert summary["considered"] == len(generate_candidates())
    assert (tmp_path / "lenient_map.json").exists()
    assert (tmp_path / "lenient_map.md").exists()

    agg = analyze_lenient(tmp_path / "full.jsonl")
    # Every command bucketed, every class present, all not-sent in dry mode.
    assert set(agg) == {f"{t:04X}" for t in READ_TAGS}
    for classes in agg.values():
        assert set(classes) == set(LENGTH_CLASSES)
        for bucket in classes.values():
            assert bucket["status"] == "not_sent(dry)"


def test_live_engine_only_sends_allowlisted(tmp_path) -> None:
    """Live-mode smoke test with a fully mocked transport: card sees only 9000."""
    from engine import FuzzEngine
    from euicc_transport import ApduResult

    sent: list[str] = []

    class _FakeTransport:
        def send(self, apdu_hex: str) -> ApduResult:
            sent.append(apdu_hex)
            return ApduResult(resp_hex="9000", sw="9000", ok=True, raw={})

    engine = FuzzEngine(live=True, allow_destructive=False, transport=_FakeTransport())
    build_and_run(
        out_path=tmp_path / "lenient.jsonl",
        summary_path=tmp_path / "summary.json",
        full_path=tmp_path / "full.jsonl",
        map_json=tmp_path / "lenient_map.json",
        map_md=tmp_path / "lenient_map.md",
        phase="live",
        engine=engine,
        wall=60,
        send_cap=None,
    )
    # Everything that reached the fake card was an allowlisted read tag.
    assert sent
    for apdu in sent:
        assert classify(apdu).classification is Classification.ALLOWED
