"""Prefix fuzzing: enumerate the CLA/INS/P1/P2 prefix space against the ISD-R.

This reuses pyAPDUFuzzer's ``FuzzerInstruction`` iteration model to walk the
prefix space, then routes every candidate through the safety layer. It does not
use pyAPDUFuzzer's ``CardInteractor``: that class talks to a PC/SC reader, while
this project reaches the eUICC through the CLI transport behind the engine.

Every candidate is a 4-byte header with an empty body. Almost all combinations
classify as UNKNOWN or BLOCKED and are never sent. Only headers that form an
allowlisted read-only store-data command can be sent, and only with ``--live``.
"""

from __future__ import annotations

import logging

from engine import FuzzEngine

try:
    from apdu_fuzzer.objects import FuzzerInstruction
    _HAVE_PYAPDUFUZZER = True
except ImportError:
    FuzzerInstruction = None  # type: ignore[assignment, misc]
    _HAVE_PYAPDUFUZZER = False

log = logging.getLogger("fuzzer.prefix")


def iter_prefix_apdus(
    cla_range: tuple[int, int] = (0x80, 0x81),
    ins_range: tuple[int, int] = (0xE2, 0xE2),
    p1_range: tuple[int, int] = (0x00, 0x00),
    p2_range: tuple[int, int] = (0x00, 0x00),
) -> list[str]:
    """Enumerate 4-byte prefix headers as hex APDUs.

    Ranges are inclusive ``(start, end)`` tuples. Defaults stay tight around the
    ISD-R store-data prefix so a dry-run is quick to read. When pyAPDUFuzzer is
    installed its ``FuzzerInstruction`` drives the iteration; otherwise a plain
    nested loop produces the identical sequence.
    """
    if _HAVE_PYAPDUFUZZER:
        header = [cla_range[0], ins_range[0], p1_range[0], p2_range[0], 0x00]
        mask = [
            (cla_range[0], cla_range[1]),
            (ins_range[0], ins_range[1]),
            (p1_range[0], p1_range[1]),
            (p2_range[0], p2_range[1]),
            (0, 0),
        ]
        instruction = FuzzerInstruction(header=header, mask=mask)
        combos = (
            (cla, ins, p1, p2)
            for cla in instruction.get_test_elements(0)
            for ins in instruction.get_test_elements(1)
            for p1 in instruction.get_test_elements(2)
            for p2 in instruction.get_test_elements(3)
        )
    else:
        combos = (
            (cla, ins, p1, p2)
            for cla in range(cla_range[0], cla_range[1] + 1)
            for ins in range(ins_range[0], ins_range[1] + 1)
            for p1 in range(p1_range[0], p1_range[1] + 1)
            for p2 in range(p2_range[0], p2_range[1] + 1)
        )

    return [f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}" for cla, ins, p1, p2 in combos]


def run(engine: FuzzEngine, **ranges: tuple[int, int]) -> FuzzEngine:
    """Feed the enumerated prefix space through the engine."""
    candidates = iter_prefix_apdus(**ranges)
    log.info("prefix mode: %d candidate headers", len(candidates))
    for apdu_hex in candidates:
        outcome = engine.consider(apdu_hex)
        if outcome.new_signal:
            log.info("new signal %s -> %s", apdu_hex, outcome.reason)
    log.info("prefix mode done: %s", engine.summary())
    return engine
