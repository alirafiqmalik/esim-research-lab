"""Exhaustive readable-data-object enumeration by GET DATA (INS CA / CB).

Sweeps the GET DATA object space more completely than ``explore_getdata``: every
1-byte tag ``00..FF`` on BOTH the even (CA) and odd (CB) instruction, plus the
standard GlobalPlatform / ISO-7816 2-byte tags (the ``9Fxx`` family, the ``00xx``
family, the ``FFxx`` card-resources family, and the ``5Cxx`` / ``5Fxx`` tag-list
prefixes) on both instructions. GET DATA is read-only: its write counterpart is
PUT DATA (INS DA), which the safety layer blocks.

Every candidate is a plain GET DATA header (no body), so ``safety.classify`` sees
INS CA or CB and returns ALLOWED. Nothing is sent here; each candidate is routed
through ``explore_common.drive`` -> ``engine.FuzzEngine.consider`` ->
``safety.guard_send`` exactly like the other read-only angles.

Skills applied:

- ``fuzzing-dictionary``: ``_TWO_BYTE_TAGS`` is the GP/ISO data-object token table
  that steers the sweep toward tags a card actually answers, on top of the blind
  1-byte sweep that guarantees no standard single-byte DO is missed.
- ``coverage-analysis``: the black-box element exposes no in-process coverage, so
  the effectiveness signal is the SW-diversity proxy plus the explicit
  readable-DO discovery count that ``drive`` accumulates keyed by tag.
"""

from __future__ import annotations

from collections.abc import Iterator

from engine import FuzzEngine
from explore_common import Candidate, drive, get_data_apdu
from novelty import NoveltyEngine
from reporting import UniqueBehaviourReporter
from safety import ALLOWLIST_INS

_COMMAND = "GETDATA"

# Standard GP / ISO 2-byte data-object tags, grouped by family. These are the
# tags whose high byte is non-zero (genuinely two-byte) plus the ISO ``00xx``
# forms the spec allows. The 1-byte sweep below covers everything ``00..FF``, so
# this table exists for the high-byte families the 1-byte sweep cannot reach.
_TWO_BYTE_TAGS: tuple[tuple[str, int], ...] = (
    # 9Fxx family: CPLC and proprietary GP objects.
    ("CPLC", 0x9F7F),
    ("9F65", 0x9F65),
    ("9F6E", 0x9F6E),
    ("9F70-AppLifeCycle", 0x9F70),
    ("9F71", 0x9F71),
    ("9F7E", 0x9F7E),
    # 00xx family: ISO leading-zero forms of common single-byte DOs.
    ("00-CardData", 0x0066),
    ("00-CardRecognitionData", 0x0073),
    ("00-IIN", 0x0042),
    ("00-CIN", 0x0045),
    ("00-CardManagerAID", 0x004F),
    ("00-DiscretionaryData", 0x0053),
    ("00-TagList", 0x005C),
    ("00-KeyInfoTemplate", 0x00E0),
    ("00-SeqCounter", 0x00C1),
    ("00-ConfirmationCounter", 0x00C2),
    ("00-ISDCounter", 0x00CF),
    ("00-CurrentSecurityLevel", 0x00D3),
    # FFxx family: GP Amendment card-resources objects.
    ("FF21-ExtendedCardResources", 0xFF21),
    ("FF22", 0xFF22),
    ("FF23", 0xFF23),
    ("FF24", 0xFF24),
    ("FF25", 0xFF25),
    # 5Cxx / 5Fxx tag-list and interindustry template prefixes.
    ("5F20", 0x5F20),
    ("5F2D", 0x5F2D),
    ("5F50", 0x5F50),
    ("5C00", 0x5C00),
)


def candidates() -> Iterator[Candidate]:
    """Yield the exhaustive read-only GET DATA sweep (CA and CB, 1- and 2-byte)."""
    # Full 1-byte tag sweep on both instructions so no standard single-byte DO is
    # missed on either the even or odd GET DATA variant.
    for odd in (False, True):
        ins = "CB" if odd else "CA"
        for tag in range(0x00, 0x100):
            yield Candidate(
                apdu_hex=get_data_apdu(tag, odd=odd),
                command=_COMMAND,
                tag=f"{tag:02X}",
                target=f"DO:1byte:{ins}:{tag:02X}",
            )

    # Standard 2-byte tags on both instructions.
    for odd in (False, True):
        ins = "CB" if odd else "CA"
        for name, tag in _TWO_BYTE_TAGS:
            yield Candidate(
                apdu_hex=get_data_apdu(tag, odd=odd),
                command=_COMMAND,
                tag=f"{tag:04X}",
                target=f"DO:2byte:{ins}:{name}:{tag:04X}",
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
    """Run the exhaustive GET DATA enumeration campaign."""
    novelty = NoveltyEngine()
    allowlist = [f"INS_{i:02X}" for i in sorted(ALLOWLIST_INS)]
    with UniqueBehaviourReporter(
        out_path=out_path,
        summary_path=summary_path,
        mode="deepdata_getdata_enum",
        phase=phase,
        allowlist=allowlist,
    ) as reporter:
        return drive(
            angle="getdata_enum",
            engine=engine,
            novelty=novelty,
            reporter=reporter,
            candidates=candidates(),
            phase=phase,
            wall=wall,
            send_cap=send_cap,
        )
