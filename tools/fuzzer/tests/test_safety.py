"""Unit tests for the safety layer. These never touch a device."""

from __future__ import annotations

import pytest

from safety import (
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
    verdict = classify("00A4040000")  # SELECT, read-ish but not on any list
    assert verdict.classification is Classification.UNKNOWN


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
        guard_send("00A4040000", live=True)
