"""Applet / AID enumeration by ISO SELECT (INS A4).

Sweeps candidate application identifiers to discover which applets and DFs on the
eUICC are selectable beyond the two known ones (ISD-R and ECASD). Every candidate
is a SELECT, which the safety layer classifies as a read-only navigation command:
it moves only the transient current-selection pointer, never persistent state.

The AID table is the ``fuzzing-dictionary`` for this angle: GSMA and GlobalPlatform
RID prefixes plus known GP application AIDs, so the sweep lands on the eUICC's real
naming grammar instead of random bytes that would always return 6A82.

A selectable AID answers with FCI (9000 + data) or 61xx. A missing one answers
6A82 (file not found), 6A88, or 6999. The drive loop records every AID that
returns data in the summary's ``discovery`` list.
"""

from __future__ import annotations

from collections.abc import Iterator

from engine import FuzzEngine
from explore_common import Candidate, drive, select_apdu
from novelty import NoveltyEngine
from reporting import UniqueBehaviourReporter
from safety import ALLOWLIST_INS

_COMMAND = "SELECT"

# Fully-qualified AIDs known or plausible on an eUICC / GP card.
_FULL_AIDS: tuple[tuple[str, str], ...] = (
    ("ISD-R", "A0000005591010FFFFFFFF8900000100"),
    ("ECASD", "A0000005591010FFFFFFFF8900000200"),
    # Speculative sibling security domains under the GSMA RID, same template.
    ("SD-0300", "A0000005591010FFFFFFFF8900000300"),
    ("SD-0000", "A0000005591010FFFFFFFF8900000000"),
    # GlobalPlatform Issuer Security Domain (card manager).
    ("GP-ISD-8", "A000000151000000"),
    ("GP-ISD-6", "A0000001510000"),
    # GlobalPlatform ARA-M (Access Rule Application master).
    ("ARA-M", "A00000015141435300"),
    # Visa / GP legacy card-manager AIDs.
    ("VISA-CM-7", "A000000003000000"),
    ("VISA-CM-6", "A0000000030000"),
    # ETSI UICC toolkit / USIM RIDs (likely off-channel, swept for completeness).
    ("ETSI-UICC", "A0000000871002"),
    ("PKCS15", "A000000063504B43532D3135"),
)

# RID prefixes for partial-length SELECT-by-name enumeration. A SELECT on a bare
# RID with the first/next occurrence P2 asks the card to walk applets under it.
_RID_PREFIXES: tuple[tuple[str, str], ...] = (
    ("RID-GSMA", "A000000559"),
    ("RID-GP", "A000000151"),
    ("RID-VISA", "A000000003"),
    ("RID-GEMALTO", "A000000018"),
    ("RID-ETSI", "A000000087"),
)

# (P1, P2) navigation variants. P1=04 selects by DF name (AID); P2 low nibble
# selects first/next occurrence; P2 bit 2 (0x0C) suppresses the FCI in the reply.
_SELECT_VARIANTS: tuple[tuple[int, int], ...] = (
    (0x04, 0x00),  # by name, first or only, return FCI
    (0x04, 0x02),  # by name, next occurrence
    (0x04, 0x0C),  # by name, first, no FCI
)


def _hexbytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def candidates() -> Iterator[Candidate]:
    """Yield the full read-only SELECT sweep."""
    # Fully-qualified AIDs across the P1/P2 navigation variants.
    for name, aid_hex in _FULL_AIDS:
        aid = _hexbytes(aid_hex)
        for p1, p2 in _SELECT_VARIANTS:
            yield Candidate(
                apdu_hex=select_apdu(aid, p1=p1, p2=p2),
                command=_COMMAND,
                tag=None,
                target=f"AID:{name}:{aid_hex}",
            )

    # Partial-length SELECTs on RID prefixes: first, then next-occurrence walk.
    for name, rid_hex in _RID_PREFIXES:
        rid = _hexbytes(rid_hex)
        yield Candidate(
            apdu_hex=select_apdu(rid, p1=0x04, p2=0x00),
            command=_COMMAND,
            tag=None,
            target=f"RID:{name}:{rid_hex}:first",
            malformed=True,
        )
        yield Candidate(
            apdu_hex=select_apdu(rid, p1=0x04, p2=0x02),
            command=_COMMAND,
            tag=None,
            target=f"RID:{name}:{rid_hex}:next",
            malformed=True,
        )

    # Empty-AID next-occurrence probe: enumerate whatever the card lists next.
    yield Candidate(
        apdu_hex=select_apdu(b"", p1=0x04, p2=0x02),
        command=_COMMAND,
        tag=None,
        target="AID:empty:next",
        malformed=True,
    )

    # File-id SELECTs for the MF and a couple of standard EFs (INS A4, P1=00).
    for name, fid in (("MF", "3F00"), ("EF-DIR", "2F00"), ("EF-ICCID", "2FE2")):
        yield Candidate(
            apdu_hex=select_apdu(_hexbytes(fid), p1=0x00, p2=0x00),
            command=_COMMAND,
            tag=None,
            target=f"FID:{name}:{fid}",
        )


def run(
    *,
    engine: FuzzEngine,
    out_path,
    summary_path,
    phase: str,
    wall: int,
    send_cap: int | None,
) -> dict[str, object]:
    """Run the SELECT enumeration campaign."""
    novelty = NoveltyEngine()
    allowlist = [f"INS_{i:02X}" for i in sorted(ALLOWLIST_INS)]
    with UniqueBehaviourReporter(
        out_path=out_path,
        summary_path=summary_path,
        mode="explore_select",
        phase=phase,
        allowlist=allowlist,
    ) as reporter:
        return drive(
            angle="select",
            engine=engine,
            novelty=novelty,
            reporter=reporter,
            candidates=candidates(),
            phase=phase,
            wall=wall,
            send_cap=send_cap,
        )
