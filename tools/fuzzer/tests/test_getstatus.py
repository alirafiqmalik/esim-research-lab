"""Unit tests for the GET STATUS enumeration campaign. No device is ever touched.

Covers three things:
- the F2 allowlist edit makes GET STATUS classify ALLOWED (CLA 80 and 84);
- destructive/unknown INS and store-data tags STAY blocked or unknown, so the F2
  addition widened nothing else and none of them can be sent;
- the E3-template response decoder parses a synthetic GET STATUS response into
  AID / life-cycle / privileges.
"""

from __future__ import annotations

import pytest

import explore_getstatus
from engine import FuzzEngine
from euicc_transport import ApduResult
from explore_getstatus import (
    candidates,
    decode_getstatus,
    enumerate_apps,
    get_status_apdu,
)
from safety import ALLOWLIST_INS, Classification, SafetyError, classify, guard_send


def _ins(apdu_hex: str) -> int:
    return bytes.fromhex(apdu_hex)[1]


# ---- the F2 allowlist edit ---------------------------------------------------


def test_f2_is_on_the_allowlist() -> None:
    assert 0xF2 in ALLOWLIST_INS
    assert ALLOWLIST_INS[0xF2] == "GET STATUS"


def test_get_status_cla80_classifies_allowed() -> None:
    verdict = classify("80F2400000")
    assert verdict.classification is Classification.ALLOWED


def test_get_status_cla84_classifies_allowed() -> None:
    verdict = classify("84F2800000")
    assert verdict.classification is Classification.ALLOWED


def test_get_status_allowed_live_send_permitted() -> None:
    verdict = guard_send("80F24000024F0000", live=True)
    assert verdict.classification is Classification.ALLOWED


# ---- nothing else widened: destructive/unknown stay blocked ------------------

# Each must classify BLOCKED or UNKNOWN and never survive a live guard_send.
DESTRUCTIVE_STILL_BLOCKED = {
    "gp_delete_80E4": "80E4000002AABB",
    "gp_delete_84E4": "84E4000002AABB",
    "memory_reset_BF34": "81E2910003BF3400",
    "delete_profile_BF33": "81E2910003BF3300",
    "put_data_80DA": "80DA00A002AABB",
    "set_status_F0_write": "80F040000180",
}


@pytest.mark.parametrize("name,apdu", DESTRUCTIVE_STILL_BLOCKED.items())
def test_destructive_still_blocked(name: str, apdu: str) -> None:
    verdict = classify(apdu)
    assert verdict.classification is not Classification.ALLOWED, name
    with pytest.raises(SafetyError):
        guard_send(apdu, live=True, allow_destructive=True)


def test_unknown_ins_stays_unknown() -> None:
    # INTERNAL AUTHENTICATE (INS 0x88): on no list, must stay default-deny.
    assert classify("0088000000").classification is Classification.UNKNOWN


def test_set_status_write_not_confused_with_get_status() -> None:
    # SET STATUS (F0) is a blocked write; GET STATUS (F2) is the allowed read.
    assert classify("80F040000180").classification is Classification.BLOCKED
    assert classify("80F2400000").classification is Classification.ALLOWED


def test_f2_not_in_write_or_hard_block() -> None:
    from safety import HARD_BLOCK_INS, WRITE_INS

    assert 0xF2 not in WRITE_INS
    assert 0xF2 not in HARD_BLOCK_INS


# ---- generator: only F2, always allowed --------------------------------------


def test_generator_only_f2_and_allowed() -> None:
    cands = list(candidates())
    assert cands
    for cand in cands:
        assert _ins(cand.apdu_hex) == 0xF2, cand.apdu_hex
        assert classify(cand.apdu_hex).classification is Classification.ALLOWED


def test_generator_covers_scopes_modes_classes() -> None:
    cands = list(candidates())
    targets = " ".join(c.target for c in cands)
    for scope in ("ISD", "apps+SSD", "ELF", "ELF+modules"):
        assert scope in targets
    assert "CLA80" in targets and "CLA84" in targets
    assert any(c.target.endswith("all-aids") for c in cands)
    assert any("reserved" in c.target for c in cands)


def test_builder_shapes_apdu() -> None:
    # Empty body -> Lc=00, then Le=00.
    assert get_status_apdu(cla=0x80, p1=0x40, p2=0x00, body=b"") == "80F240000000"
    assert get_status_apdu(cla=0x84, p1=0x80, p2=0x02, body=bytes.fromhex("4F00")) == "84F28002024F0000"


# ---- response decoder: synthetic E3 templates --------------------------------


def _e3(aid: str, lifecycle: int, priv: str) -> str:
    aid_b = bytes.fromhex(aid)
    priv_b = bytes.fromhex(priv)
    inner = (
        bytes((0x4F, len(aid_b))) + aid_b
        + bytes((0x9F, 0x70, 0x01, lifecycle))
        + bytes((0xC5, len(priv_b))) + priv_b
    )
    return (bytes((0xE3, len(inner))) + inner).hex().upper()


def test_decode_single_template() -> None:
    resp = bytes.fromhex(_e3("A0000005591010", 0x07, "9E"))
    entries = decode_getstatus(resp)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.aid == "A0000005591010"
    assert entry.lifecycle_raw == 0x07
    assert entry.lifecycle == "SELECTABLE"
    assert entry.privileges_raw == "9E"
    assert "Security Domain" in entry.privileges


def test_decode_multiple_templates() -> None:
    resp = bytes.fromhex(
        _e3("A0000005591010FFFFFFFF8900000100", 0x0F, "9E")
        + _e3("A0000005591010FFFFFFFF8900000200", 0x07, "80")
    )
    entries = decode_getstatus(resp)
    aids = {e.aid for e in entries}
    assert len(entries) == 2
    assert "A0000005591010FFFFFFFF8900000100" in aids
    assert "A0000005591010FFFFFFFF8900000200" in aids


def test_decode_no_template_yields_empty() -> None:
    # Legacy tag-value / error response with no E3: empty, not an exception.
    assert decode_getstatus(bytes.fromhex("6A88")) == []
    assert decode_getstatus(b"") == []


def test_decode_truncated_stops_cleanly() -> None:
    # A truncated template must not raise; best-effort decode returns what parsed.
    good = _e3("A0000005591010", 0x07, "9E")
    resp = bytes.fromhex(good + "E30599")  # trailing truncated E3
    entries = decode_getstatus(resp)
    assert len(entries) == 1
    assert entries[0].aid == "A0000005591010"


# ---- enumerate_apps over a fake live engine ----------------------------------


class _E3Transport:
    """Fake transport that returns one E3 template plus a 9000 status word."""

    def send(self, apdu_hex: str) -> ApduResult:
        template = _e3("A0000005591010FFFFFFFF8900000100", 0x0F, "9E")
        resp = (template + "9000").upper()
        return ApduResult(resp_hex=resp, sw="9000", ok=True, raw={})


def test_enumerate_apps_from_engine_outcomes() -> None:
    engine = FuzzEngine(live=True, transport=_E3Transport())
    for cand in list(candidates())[:3]:
        engine.consider(cand.apdu_hex)
    apps = enumerate_apps(engine)
    assert "A0000005591010FFFFFFFF8900000100" in apps
    assert apps["A0000005591010FFFFFFFF8900000100"].lifecycle == "PERSONALIZED"


def test_run_dry_sends_nothing(tmp_path) -> None:
    engine = FuzzEngine(live=False, transport=None)
    summary = explore_getstatus.run(
        engine=engine,
        out_path=tmp_path / "gs.jsonl",
        summary_path=tmp_path / "gs.summary.json",
        phase="dry",
        wall=30,
        send_cap=None,
    )
    assert summary["sent"] == 0
    assert summary["angle"] == "getstatus"
    assert enumerate_apps(engine) == {}
