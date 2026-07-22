"""EF content probing by READ BINARY / READ RECORD / GET RESPONSE.

Sweeps short-EF identifiers, offsets, and record numbers to surface any elementary
file the eUICC exposes for reading. All three instructions are read-only: their
write counterparts (UPDATE/WRITE BINARY D0/D6, UPDATE/WRITE RECORD D2/DC) are
blocked by the safety layer.

Short-EF (SFI) addressing is deliberate. Each APDU carries the target EF in its
own P1/P2, so a READ does not depend on a prior SELECT persisting across the
transport's per-APDU subprocess calls. That keeps every candidate self-contained.

A readable transparent EF answers 9000 (+ data) or 61xx; a record EF answers per
record. Absent or wrong-type files answer 6A82, 6A83 (record not found), 6981
(incompatible file structure), or 6986 (no current EF). The drive loop records
every readable reference in the summary's ``discovery`` list.
"""

from __future__ import annotations

from collections.abc import Iterator

from engine import FuzzEngine
from explore_common import (
    Candidate,
    drive,
    get_response_apdu,
    read_binary_apdu,
    read_record_apdu,
)
from novelty import NoveltyEngine
from reporting import UniqueBehaviourReporter
from safety import ALLOWLIST_INS

_COMMAND_BIN = "READBIN"
_COMMAND_REC = "READREC"
_COMMAND_RESP = "GETRESP"

# Short-EF identifiers to sweep. 0 is the current-EF sentinel; 1..30 are the
# addressable short IDs.
_SFI_RANGE: tuple[int, ...] = tuple(range(1, 31))
# Offsets worth probing inside a transparent EF.
_OFFSETS: tuple[int, ...] = (0x00, 0x01, 0x10, 0x7F)
# Record numbers for linear/cyclic EFs.
_RECORDS: tuple[int, ...] = (0x01, 0x02, 0x03, 0x0A)
# GET RESPONSE lengths to request.
_LE_VALUES: tuple[int, ...] = (0x00, 0x10, 0xFF)


def candidates() -> Iterator[Candidate]:
    """Yield the read-only READ / GET RESPONSE sweep."""
    # READ BINARY by SFI at offset 0, requesting the whole EF.
    for sfi in _SFI_RANGE:
        yield Candidate(
            apdu_hex=read_binary_apdu(sfi=sfi, offset=0x00),
            command=_COMMAND_BIN,
            tag=None,
            target=f"EF-BIN:sfi{sfi:02d}:off0",
        )

    # READ BINARY on the current EF (no SFI) across a few offsets.
    for offset in _OFFSETS:
        yield Candidate(
            apdu_hex=read_binary_apdu(sfi=None, offset=offset),
            command=_COMMAND_BIN,
            tag=None,
            target=f"EF-BIN:cur:off{offset:02X}",
        )

    # READ RECORD by SFI, absolute record number.
    for sfi in _SFI_RANGE:
        for record in _RECORDS:
            yield Candidate(
                apdu_hex=read_record_apdu(record=record, sfi=sfi, mode=0x04),
                command=_COMMAND_REC,
                tag=None,
                target=f"EF-REC:sfi{sfi:02d}:rec{record:02d}",
            )

    # GET RESPONSE for buffered bytes from a prior command.
    for le in _LE_VALUES:
        yield Candidate(
            apdu_hex=get_response_apdu(le=le),
            command=_COMMAND_RESP,
            tag=None,
            target=f"GETRESP:le{le:02X}",
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
    """Run the READ / GET RESPONSE campaign."""
    novelty = NoveltyEngine()
    allowlist = [f"INS_{i:02X}" for i in sorted(ALLOWLIST_INS)]
    with UniqueBehaviourReporter(
        out_path=out_path,
        summary_path=summary_path,
        mode="explore_read",
        phase=phase,
        allowlist=allowlist,
    ) as reporter:
        return drive(
            angle="read",
            engine=engine,
            novelty=novelty,
            reporter=reporter,
            candidates=candidates(),
            phase=phase,
            wall=wall,
            send_cap=send_cap,
        )
