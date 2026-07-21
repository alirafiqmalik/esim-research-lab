"""Safety layer for eUICC APDU fuzzing.

The target is a live eUICC holding two real profiles. This module is the single
gate every candidate APDU must pass before it can be sent. It classifies an APDU
against a read-only allowlist and a destructive blocklist, and refuses live sends
that are not explicitly safe.

Nothing in this module sends anything. It only classifies and gates.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

# ES10x store-data BER-TLV tags that only read state. Safe to send live.
# Derived from the read/write column of docs/reference/euicc-api.md. Each ADDED
# tag carries a one-line read-only justification; the original eight are the
# pre-existing vetted set.
ALLOWLIST_TAGS: dict[int, str] = {
    0xBF3E: "GetEID",
    0xBF20: "GetEUICCInfo1",
    0xBF22: "GetEUICCInfo2",
    0xBF2E: "GetEUICCChallenge",
    0xBF2D: "GetProfilesInfo",
    0xBF2B: "RetrieveNotificationsList",
    0xBF3C: "GetConfiguredAddresses",
    0xBF43: "GetRAT",
    # read-only: ES10b ListNotification returns the pending-notification metadata
    # list; it removes nothing. The write is RemoveNotification (BF30), which
    # stays blocked below.
    0xBF28: "ListNotification",
}

# ISO-7816 / GlobalPlatform instruction bytes that only read state. These are not
# STORE DATA (0xE2); they are classified by INS, not by a BER-TLV tag. Each is a
# read command whose write counterpart is in WRITE_INS and stays blocked.
ALLOWLIST_INS: dict[int, str] = {
    # read-only: applet/file navigation; returns the FCI template. Mutates only
    # the transient current-selection pointer, never persistent card state. This
    # is the op esimctl uses to reach ECASD (docs/reference/euicc-api.md).
    0xA4: "SELECT",
    # read-only: retrieves EF (transparent file) contents. The writes are
    # WRITE/UPDATE BINARY (0xD0/0xD6), both blocked.
    0xB0: "READ BINARY",
    # read-only: retrieves record(s) from a linear/cyclic EF. The writes are
    # WRITE/UPDATE RECORD (0xD2/0xDC), both blocked.
    0xB2: "READ RECORD",
    # read-only: fetches buffered response bytes from the prior command. Pure
    # transport continuation, changes nothing.
    0xC0: "GET RESPONSE",
    # read-only: retrieves a data object. The write is PUT DATA (0xDA), blocked.
    0xCA: "GET DATA",
    # read-only: retrieves a data object (odd-INS variant). PUT DATA (0xDA) stays
    # blocked.
    0xCB: "GET DATA",
}

# Destructive ES10x store-data tags. Never sent, in any mode.
BLOCKLIST_TAGS: dict[int, str] = {
    0xBF31: "EnableProfile",
    0xBF32: "DisableProfile",
    0xBF33: "DeleteProfile",
    0xBF34: "eUICCMemoryReset",
    0xBF29: "SetNickname",
    0xBF3F: "SetDefaultDpAddress",
    0xBF37: "LoadBoundProfilePackage",
}

# Tags that no flag can ever override. A bricked or wiped card is unrecoverable.
HARD_BLOCK_TAGS: dict[int, str] = {
    0xBF34: "eUICCMemoryReset",
    0xBF33: "DeleteProfile",
}

# GlobalPlatform / ISO write instructions. Blocked regardless of payload.
# STORE DATA (0xE2) is handled separately: its BER-TLV tag decides the verdict.
WRITE_INS: dict[int, str] = {
    0x0E: "ERASE BINARY",
    0xD0: "WRITE BINARY",
    0xD2: "WRITE RECORD",
    0xD6: "UPDATE BINARY",
    0xD8: "PUT KEY",
    0xDA: "PUT DATA",
    0xDC: "UPDATE RECORD",
    0xE4: "GP DELETE",
    0xE6: "GP INSTALL",
    0xE8: "GP LOAD",
    0xF0: "GP SET STATUS",
}

# INS values that carry a GP DELETE. Hard-blocked, never overridable.
HARD_BLOCK_INS: dict[int, str] = {
    0xE4: "GP DELETE",
}

INS_STORE_DATA = 0xE2


class Classification(enum.Enum):
    """Verdict for a candidate APDU."""

    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


class SafetyError(Exception):
    """Raised when a live send is refused by the safety layer."""


@dataclass(frozen=True)
class SafetyVerdict:
    """Result of classifying one APDU.

    hard_blocked marks tags/instructions that no flag can override.
    """

    classification: Classification
    reason: str
    apdu_hex: str
    tag: int | None = None
    hard_blocked: bool = False


def _hex_to_bytes(apdu_hex: str) -> bytes:
    cleaned = apdu_hex.strip().replace(" ", "").replace("_", "")
    if not cleaned:
        raise ValueError("empty APDU")
    if len(cleaned) % 2 != 0:
        raise ValueError(f"odd-length APDU hex: {apdu_hex!r}")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"non-hex APDU: {apdu_hex!r}") from exc


def parse_store_data_tag(apdu: bytes) -> int:
    """Return the leading BER-TLV tag from a STORE DATA payload.

    A store-data APDU has the form ``CLA E2 P1 P2 Lc <BER-TLV>``. The BER-TLV
    tag is one or two bytes. A first byte whose low five bits are all set
    (``0x1F``) means the tag continues into the next byte.

    Raises ValueError if the APDU is not a well-formed store-data command.
    """
    if len(apdu) < 5:
        raise ValueError("APDU too short to carry a store-data body")
    if apdu[1] != INS_STORE_DATA:
        raise ValueError("not a STORE DATA (INS != 0xE2) APDU")
    lc = apdu[4]
    body = apdu[5:]
    if lc == 0 or len(body) < 1:
        raise ValueError("store-data APDU has no BER-TLV body")

    first = body[0]
    if (first & 0x1F) != 0x1F:
        return first
    if len(body) < 2:
        raise ValueError("truncated multi-byte BER-TLV tag")
    return (first << 8) | body[1]


def classify(apdu_hex: str) -> SafetyVerdict:
    """Classify one APDU as ALLOWED, BLOCKED, or UNKNOWN.

    Raises ValueError if the hex string itself is malformed. A malformed hex
    string is a programming error, not a fuzz result.
    """
    apdu = _hex_to_bytes(apdu_hex)
    if len(apdu) < 4:
        raise ValueError("APDU shorter than a 4-byte header")

    ins = apdu[1]

    if ins in HARD_BLOCK_INS:
        return SafetyVerdict(
            classification=Classification.BLOCKED,
            reason=f"hard-blocked instruction {HARD_BLOCK_INS[ins]} (INS 0x{ins:02X})",
            apdu_hex=apdu_hex,
            hard_blocked=True,
        )

    if ins == INS_STORE_DATA:
        try:
            tag = parse_store_data_tag(apdu)
        except ValueError as exc:
            return SafetyVerdict(
                classification=Classification.UNKNOWN,
                reason=f"unparseable store-data body: {exc}",
                apdu_hex=apdu_hex,
            )
        if tag in HARD_BLOCK_TAGS:
            return SafetyVerdict(
                classification=Classification.BLOCKED,
                reason=f"hard-blocked tag {HARD_BLOCK_TAGS[tag]} (0x{tag:04X})",
                apdu_hex=apdu_hex,
                tag=tag,
                hard_blocked=True,
            )
        if tag in BLOCKLIST_TAGS:
            return SafetyVerdict(
                classification=Classification.BLOCKED,
                reason=f"destructive tag {BLOCKLIST_TAGS[tag]} (0x{tag:04X})",
                apdu_hex=apdu_hex,
                tag=tag,
            )
        if tag in ALLOWLIST_TAGS:
            return SafetyVerdict(
                classification=Classification.ALLOWED,
                reason=f"read-only tag {ALLOWLIST_TAGS[tag]} (0x{tag:04X})",
                apdu_hex=apdu_hex,
                tag=tag,
            )
        return SafetyVerdict(
            classification=Classification.UNKNOWN,
            reason=f"store-data tag 0x{tag:04X} not on any list",
            apdu_hex=apdu_hex,
            tag=tag,
        )

    # Blocklist precedence: writes are refused before the read-only INS allowlist
    # is ever consulted, so an INS that somehow appears in both is always blocked.
    if ins in WRITE_INS:
        return SafetyVerdict(
            classification=Classification.BLOCKED,
            reason=f"write instruction {WRITE_INS[ins]} (INS 0x{ins:02X})",
            apdu_hex=apdu_hex,
        )

    if ins in ALLOWLIST_INS:
        return SafetyVerdict(
            classification=Classification.ALLOWED,
            reason=f"read-only instruction {ALLOWLIST_INS[ins]} (INS 0x{ins:02X})",
            apdu_hex=apdu_hex,
        )

    return SafetyVerdict(
        classification=Classification.UNKNOWN,
        reason=f"non-store-data instruction INS 0x{ins:02X} not recognized as read-only",
        apdu_hex=apdu_hex,
    )


def guard_send(apdu_hex: str, *, live: bool, allow_destructive: bool = False) -> SafetyVerdict:
    """Gate a candidate APDU immediately before a transport send.

    Returns the verdict when the APDU may proceed. In dry-run the caller never
    reaches the transport, so the verdict is informational. In live mode this
    raises SafetyError unless the APDU is ALLOWED.

    ``allow_destructive`` corresponds to ``--i-understand-destructive``. It is
    forbidden without maintainer sign-off, and it can never release a
    hard-blocked APDU (memory reset, delete profile, GP DELETE).
    """
    verdict = classify(apdu_hex)

    if not live:
        return verdict

    if verdict.classification is Classification.ALLOWED:
        return verdict

    if verdict.hard_blocked:
        raise SafetyError(
            f"refusing live send: {verdict.reason}. This block cannot be overridden."
        )

    if allow_destructive:
        raise SafetyError(
            f"refusing live send: {verdict.reason}. --i-understand-destructive is "
            f"forbidden without maintainer sign-off and is not honored here."
        )

    raise SafetyError(
        f"refusing live send: {verdict.reason}. Only allowlisted read-only tags "
        f"may be sent live."
    )
