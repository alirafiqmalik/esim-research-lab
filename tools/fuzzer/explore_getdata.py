"""Data-object enumeration by GET DATA (INS CA / CB).

Sweeps the GlobalPlatform / ISO-7816 data-object tag space to map which DOs the
eUICC exposes for reading. GET DATA is read-only: its write counterpart is PUT
DATA (INS DA), which the safety layer blocks.

The curated tag table is the ``fuzzing-dictionary`` for this angle: CPLC, card
data, key-information template, IIN/CIN, counters, and tag-lists — the objects a
GP card actually answers. A full 1-byte sweep backs it up so nothing standard is
missed, and the odd-INS (CB) variant covers the 2-byte constructed tags.

A present DO answers 9000 (+ data) or 61xx. An absent one answers 6A88 (referenced
data not found), 6A80, 6A81, or 6D00. The drive loop records every tag that
returns data in the summary's ``discovery`` list, with a response fingerprint.
"""

from __future__ import annotations

from collections.abc import Iterator

from engine import FuzzEngine
from explore_common import Candidate, drive, get_data_apdu
from novelty import NoveltyEngine
from reporting import UniqueBehaviourReporter
from safety import ALLOWLIST_INS

_COMMAND = "GETDATA"

# Curated GlobalPlatform / ISO-7816 data-object tags known to answer on cards.
_CURATED_TAGS: tuple[tuple[str, int], ...] = (
    ("CPLC", 0x9F7F),
    ("CardData", 0x0066),
    ("CardRecognitionData", 0x0073),
    ("KeyInfoTemplate", 0x00E0),
    ("IIN", 0x0042),
    ("CIN", 0x0045),
    ("SeqCounter", 0x00C1),
    ("ConfirmationCounter", 0x00C2),
    ("CardManagerAID", 0x004F),
    ("ISDCounter", 0x00CF),
    ("CurrentSecurityLevel", 0x00D3),
    ("ExtendedCardResources", 0xFF21),
    ("TagList", 0x005C),
    ("DiscretionaryData", 0x0053),
    ("AppLifeCycle", 0x009F70),
)

# 2-byte constructed / proprietary tags worth the odd-INS (CB) variant.
_ODD_TAGS: tuple[tuple[str, int], ...] = (
    ("CPLC-odd", 0x9F7F),
    ("BF20-info1", 0xBF20),
    ("BF21", 0xBF21),
    ("DF20", 0xDF20),
)


def candidates() -> Iterator[Candidate]:
    """Yield the read-only GET DATA sweep."""
    # Curated 1- and 2-byte tags via the even INS (CA).
    for name, tag in _CURATED_TAGS:
        yield Candidate(
            apdu_hex=get_data_apdu(tag, odd=False),
            command=_COMMAND,
            tag=f"{tag:04X}" if tag > 0xFF else f"{tag:02X}",
            target=f"DO:{name}:{tag:04X}",
        )

    # Full 1-byte tag sweep (P2 = tag, P1 = 00) so no standard DO is missed.
    for tag in range(0x00, 0x100):
        yield Candidate(
            apdu_hex=get_data_apdu(tag, odd=False),
            command=_COMMAND,
            tag=f"{tag:02X}",
            target=f"DO:1byte:{tag:02X}",
        )

    # Odd-INS (CB) variant for the 2-byte constructed tags.
    for name, tag in _ODD_TAGS:
        yield Candidate(
            apdu_hex=get_data_apdu(tag, odd=True),
            command=_COMMAND,
            tag=f"{tag:04X}",
            target=f"DO:odd:{name}:{tag:04X}",
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
    """Run the GET DATA enumeration campaign."""
    novelty = NoveltyEngine()
    allowlist = [f"INS_{i:02X}" for i in sorted(ALLOWLIST_INS)]
    with UniqueBehaviourReporter(
        out_path=out_path,
        summary_path=summary_path,
        mode="explore_getdata",
        phase=phase,
        allowlist=allowlist,
    ) as reporter:
        return drive(
            angle="getdata",
            engine=engine,
            novelty=novelty,
            reporter=reporter,
            candidates=candidates(),
            phase=phase,
            wall=wall,
            send_cap=send_cap,
        )
