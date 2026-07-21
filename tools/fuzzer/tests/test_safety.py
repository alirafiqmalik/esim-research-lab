"""Unit tests for the safety layer. These never touch a device."""

from __future__ import annotations

import pytest

from safety import (
    ALLOWLIST_INS,
    ALLOWLIST_TAGS,
    BLOCKLIST_TAGS,
    Classification,
    SafetyError,
    classify,
    guard_send,
    parse_store_data_tag,
)

# Read-only store-data APDUs, one per allowlisted tag.
ALLOWED_APDUS = {
    0xBF3E: "81E2910006BF3E035C015A",
    0xBF20: "81E2910003BF2000",
    0xBF22: "81E2910003BF2200",
    0xBF2E: "81E2910003BF2E00",
    0xBF2D: "81E2910003BF2D00",
    0xBF2B: "81E2910003BF2B00",
    0xBF3C: "81E2910003BF3C00",
    0xBF43: "81E2910003BF4300",
    # Newly vetted read-only store-data tag.
    0xBF28: "81E2910003BF2800",
}

# Read-only ISO-7816 instructions, one representative APDU per allowlisted INS.
ALLOWED_INS_APDUS = {
    0xA4: "00A4040007A0000005591010",  # SELECT by AID
    0xB0: "00B0000000",  # READ BINARY
    0xB2: "00B2010400",  # READ RECORD
    0xC0: "00C0000000",  # GET RESPONSE
    0xCA: "00CA00FE00",  # GET DATA
    0xCB: "00CB3FFF00",  # GET DATA (odd INS)
}

# Destructive probes carried over from the prior security review. Every one must
# stay BLOCKED or UNKNOWN under the expanded config — never ALLOWED, never sent.
DESTRUCTIVE_PROBES = {
    "delete_profile_BF33": "81E2910003BF3300",
    "memory_reset_BF34": "81E2910003BF3400",
    "raw_gp_delete_80E4": "80E4000002AABB",
    "raw_gp_delete_84E4": "84E4000002AABB",
    # eUICCMemoryReset tag hidden behind a bogus long Lc=0xFF.
    "long_lc_reset_disguise": "81E29100FFBF3400",
    "put_data_80DA": "80DA00A002AABB",
    # A 3-byte-tag disguise: parser resolves the leading tag to 0x1FBF, which is
    # on no list, so it must stay default-deny (UNKNOWN), never ALLOWED.
    "three_byte_tag_disguise": "81E29100041FBF3400",
    # A store-data tag on no list at all.
    "unknown_tag_BF7F": "81E2910003BF7F00",
}

# Destructive store-data APDUs, one per blocklisted tag.
BLOCKED_APDUS = {
    0xBF31: "81E2910003BF3100",
    0xBF32: "81E2910003BF3200",
    0xBF33: "81E2910003BF3300",
    0xBF34: "81E2910003BF3400",
    0xBF29: "81E2910003BF2900",
    0xBF3F: "81E2910003BF3F00",
    0xBF37: "81E2910003BF3700",
}


@pytest.mark.parametrize("tag,apdu", ALLOWED_APDUS.items())
def test_allowlisted_tags_pass(tag: int, apdu: str) -> None:
    verdict = classify(apdu)
    assert verdict.classification is Classification.ALLOWED
    assert verdict.tag == tag


@pytest.mark.parametrize("tag,apdu", BLOCKED_APDUS.items())
def test_blocklisted_tags_blocked(tag: int, apdu: str) -> None:
    verdict = classify(apdu)
    assert verdict.classification is Classification.BLOCKED
    assert verdict.tag == tag


def test_allowlist_and_blocklist_are_disjoint() -> None:
    assert set(ALLOWLIST_TAGS) & set(BLOCKLIST_TAGS) == set()


def test_memory_reset_is_blocked_and_hard() -> None:
    verdict = classify("81E2910003BF3400")
    assert verdict.classification is Classification.BLOCKED
    assert verdict.hard_blocked is True


def test_delete_profile_is_hard_blocked() -> None:
    verdict = classify("81E2910003BF3300")
    assert verdict.hard_blocked is True


def test_get_eid_is_allowed() -> None:
    verdict = classify("81E2910006BF3E035C015A")
    assert verdict.classification is Classification.ALLOWED
    assert verdict.tag == 0xBF3E


def test_parse_store_data_tag_two_byte() -> None:
    assert parse_store_data_tag(bytes.fromhex("81E2910003BF3400")) == 0xBF34


def test_gp_delete_ins_is_hard_blocked() -> None:
    verdict = classify("80E4000002AABB")
    assert verdict.classification is Classification.BLOCKED
    assert verdict.hard_blocked is True


def test_write_instruction_blocked() -> None:
    verdict = classify("00D6000001FF")  # UPDATE BINARY
    assert verdict.classification is Classification.BLOCKED


def test_unknown_instruction_is_unknown() -> None:
    # INTERNAL AUTHENTICATE (INS 0x88): a keyed crypto op, on no list. Must stay
    # default-deny.
    verdict = classify("0088000000")
    assert verdict.classification is Classification.UNKNOWN


@pytest.mark.parametrize("ins,apdu", ALLOWED_INS_APDUS.items())
def test_allowlisted_read_instructions_pass(ins: int, apdu: str) -> None:
    verdict = classify(apdu)
    assert verdict.classification is Classification.ALLOWED, apdu
    assert ins in ALLOWLIST_INS


def test_new_listnotification_tag_is_allowed() -> None:
    verdict = classify("81E2910003BF2800")
    assert verdict.classification is Classification.ALLOWED
    assert verdict.tag == 0xBF28


@pytest.mark.parametrize("name,apdu", DESTRUCTIVE_PROBES.items())
def test_destructive_probes_never_allowed(name: str, apdu: str) -> None:
    verdict = classify(apdu)
    assert verdict.classification is not Classification.ALLOWED, name
    # And a live send is refused for every one of them.
    with pytest.raises(SafetyError):
        guard_send(apdu, live=True, allow_destructive=True)


def test_remove_notification_write_stays_blocked() -> None:
    # BF30 RemoveNotification is a WRITE; adding BF28 (read) must not leak it.
    verdict = classify("81E2910003BF3000")
    assert verdict.classification is not Classification.ALLOWED


def test_blocklist_precedence_over_allowlist() -> None:
    # A tag present in both lists must resolve to BLOCKED. Simulate by checking a
    # blocklisted tag is never reported ALLOWED even though the allowlist grew.
    from safety import ALLOWLIST_TAGS as A
    for tag in BLOCKLIST_TAGS:
        assert tag not in A, f"0x{tag:04X} leaked into the allowlist"
    verdict = classify("81E2910003BF3400")  # in blocklist + hard-block
    assert verdict.classification is Classification.BLOCKED


def test_get_data_ins_not_confused_with_put_data() -> None:
    # GET DATA (CA/CB) is allowed; PUT DATA (DA) is a blocked write.
    assert classify("00CA00FE00").classification is Classification.ALLOWED
    assert classify("80DA00A002AABB").classification is Classification.BLOCKED


def test_malformed_hex_raises() -> None:
    with pytest.raises(ValueError):
        classify("81E29100XY")


def test_guard_dry_run_never_raises_even_for_reset() -> None:
    verdict = guard_send("81E2910003BF3400", live=False)
    assert verdict.classification is Classification.BLOCKED


def test_guard_live_allows_allowlisted() -> None:
    verdict = guard_send("81E2910006BF3E035C015A", live=True)
    assert verdict.classification is Classification.ALLOWED


def test_guard_live_blocks_reset_even_with_destructive_flag() -> None:
    with pytest.raises(SafetyError):
        guard_send("81E2910003BF3400", live=True, allow_destructive=True)


def test_guard_live_blocks_unknown() -> None:
    with pytest.raises(SafetyError):
        guard_send("0088000000", live=True)  # INTERNAL AUTHENTICATE, unlisted
