"""Unit tests for the novelty / unexpected-behaviour engine. No device."""

from __future__ import annotations

import pytest

from novelty import (
    NOVELTY_NEW_SIGNATURE,
    NOVELTY_NOVEL_SW,
    NOVELTY_RARE_SW,
    NOVELTY_STRUCTURAL_ANOMALY,
    NOVELTY_SUCCESS_ON_MALFORMED,
    NOVELTY_TRANSPORT_ERROR,
    NoveltyEngine,
    ProbeResult,
    SafetyViolation,
    response_fingerprint,
)


def _ok(command: str, apdu: str, resp: str, sw: str = "9000", malformed: bool = False) -> ProbeResult:
    return ProbeResult(
        apdu_hex=apdu,
        command=command,
        classification="ALLOWED",
        malformed=malformed,
        sent=True,
        sw=sw,
        resp_hex=resp,
    )


def test_fingerprint_collapses_same_shape_different_values() -> None:
    # Two GetEID responses with the same TLV shape but different EID values.
    fp1 = response_fingerprint("BF3E125A1089033023427100000000027143866816")
    fp2 = response_fingerprint("BF3E125A10FFEEDDCCBBAA00112233445566778899")
    assert fp1 == fp2


def test_signature_dedup_collapses_same_shape() -> None:
    eng = NoveltyEngine()
    v1 = eng.evaluate(_ok("BF3E", "AA", "BF3E125A1089033023427100000000027143866816"))
    v2 = eng.evaluate(_ok("BF3E", "BB", "BF3E125A10FFEEDDCCBBAA00112233445566778899"))
    assert NOVELTY_NEW_SIGNATURE in v1.novelty
    assert NOVELTY_NEW_SIGNATURE not in v2.novelty
    assert eng.distinct_signatures() == 1


def test_novel_sw_fires_on_new_status_word() -> None:
    eng = NoveltyEngine()
    eng.evaluate(_ok("BF20", "AA", "BF2003810100"))
    v = eng.evaluate(_ok("BF20", "BB", "6A80", sw="6A80"))
    assert NOVELTY_NOVEL_SW in v.novelty


def test_success_on_malformed_fires() -> None:
    eng = NoveltyEngine()
    v = eng.evaluate(_ok("BF3E", "AA", "BF3E00", sw="9000", malformed=True))
    assert NOVELTY_SUCCESS_ON_MALFORMED in v.novelty
    assert v.severity == "warning"


def test_rare_sw_fires() -> None:
    eng = NoveltyEngine()
    v = eng.evaluate(_ok("BF3E", "AA", "6F00", sw="6F00"))
    assert NOVELTY_RARE_SW in v.novelty


def test_structural_anomaly_on_wrong_leading_tag() -> None:
    eng = NoveltyEngine()
    # GetEID (BF3E) but the response leads with a different tag: possible leak.
    v = eng.evaluate(_ok("BF3E", "AA", "BF2205AABBCCDDEE"))
    assert NOVELTY_STRUCTURAL_ANOMALY in v.novelty


def test_transport_error_flagged() -> None:
    eng = NoveltyEngine()
    result = ProbeResult(
        apdu_hex="AA",
        command="BF3E",
        classification="ALLOWED",
        malformed=False,
        sent=False,
        transport_error="CLI timed out",
    )
    v = eng.evaluate(result)
    assert NOVELTY_TRANSPORT_ERROR in v.novelty
    assert v.severity == "warning"


def test_nondeterminism_detected() -> None:
    eng = NoveltyEngine()
    samples = [
        ("9000", "BF3E125A1089033023427100000000027143866816"),
        ("6A80", "6A80"),
    ]
    assert eng.check_repeats(samples) is True


def test_determinism_consistent() -> None:
    eng = NoveltyEngine()
    samples = [
        ("9000", "BF3E125A1089033023427100000000027143866816"),
        ("9000", "BF3E125A1089033023427100000000027143866816"),
    ]
    assert eng.check_repeats(samples) is False


def test_safety_violation_raises_on_sent_blocklisted_apdu() -> None:
    eng = NoveltyEngine()
    # A blocklisted memory-reset APDU marked as sent must trip the guard.
    result = ProbeResult(
        apdu_hex="81E2910003BF3400",
        command="BF34",
        classification="BLOCKED",
        malformed=False,
        sent=True,
        sw="9000",
        resp_hex="9000",
    )
    with pytest.raises(SafetyViolation):
        eng.evaluate(result)


def test_dry_run_probe_yields_one_signature_per_command() -> None:
    eng = NoveltyEngine()
    dry = ProbeResult(
        apdu_hex="81E2910003BF2000",
        command="BF20",
        classification="ALLOWED",
        malformed=False,
        sent=False,
    )
    v1 = eng.evaluate(dry)
    v2 = eng.evaluate(dry)
    assert NOVELTY_NEW_SIGNATURE in v1.novelty
    assert NOVELTY_NEW_SIGNATURE not in v2.novelty
