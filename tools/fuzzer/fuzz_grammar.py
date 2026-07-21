"""Grammar synthesis from seed APDUs.

Seeds are all ES10x store-data commands of the shape::

    CLA INS P1 P2 Lc  [ BER-TLV: tag | length | value ]

This module extracts a small grammar from the seed corpus (the header prefix,
the set of BER-TLV tags, and the value templates), then synthesizes new
well-formed candidates by recombining tags with values and mutating length and
value bytes. Every candidate keeps a valid Lc and a valid inner TLV length, so
the fuzzer explores the command layer rather than wasting effort on unparseable
framing. Each candidate still passes through the safety layer.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from corpus import Seed
from engine import FuzzEngine
from safety import parse_store_data_tag

log = logging.getLogger("fuzzer.grammar")

INS_STORE_DATA = 0xE2

# Deterministic byte values used to mutate TLV bodies. No randomness keeps runs
# reproducible.
_VALUE_BYTES = (0x00, 0x01, 0x5A, 0x7F, 0x80, 0xFF)


@dataclass
class ApduGrammar:
    """Grammar learned from the seed corpus."""

    prefixes: set[tuple[int, int, int, int]] = field(default_factory=set)
    tags: set[int] = field(default_factory=set)
    value_templates: set[bytes] = field(default_factory=set)

    @classmethod
    def from_seeds(cls, seeds: list[Seed]) -> "ApduGrammar":
        grammar = cls()
        for seed in seeds:
            grammar._learn(seed.apdu_hex)
        return grammar

    def _learn(self, apdu_hex: str) -> None:
        apdu = bytes.fromhex(apdu_hex)
        if len(apdu) < 5 or apdu[1] != INS_STORE_DATA:
            return
        self.prefixes.add((apdu[0], apdu[1], apdu[2], apdu[3]))
        try:
            tag = parse_store_data_tag(apdu)
        except ValueError:
            return
        self.tags.add(tag)
        body = apdu[5:]
        tag_len = 2 if (body[0] & 0x1F) == 0x1F else 1
        if len(body) > tag_len:
            value = body[tag_len + 1 :]
            self.value_templates.add(bytes(value))


def _encode_tag(tag: int) -> bytes:
    if tag <= 0xFF:
        return bytes([tag])
    return bytes([(tag >> 8) & 0xFF, tag & 0xFF])


def _build_store_data(prefix: tuple[int, int, int, int], tag: int, value: bytes) -> str:
    tag_bytes = _encode_tag(tag)
    tlv = tag_bytes + bytes([len(value)]) + value
    apdu = bytes(prefix) + bytes([len(tlv)]) + tlv
    return apdu.hex().upper()


def synthesize(grammar: ApduGrammar, max_candidates: int = 512) -> list[str]:
    """Synthesize well-formed store-data candidates from the grammar."""
    if not grammar.prefixes:
        raise ValueError("grammar learned no store-data prefixes from the seeds")

    prefixes = sorted(grammar.prefixes)
    tags = sorted(grammar.tags)
    values: list[bytes] = [b""] + sorted(grammar.value_templates)

    # Add deterministic mutant values: single-byte and short fixed patterns.
    for b in _VALUE_BYTES:
        values.append(bytes([b]))
        values.append(bytes([b, b]))

    seen: set[str] = set()
    candidates: list[str] = []
    for prefix in prefixes:
        for tag in tags:
            for value in values:
                apdu_hex = _build_store_data(prefix, tag, value)
                if apdu_hex not in seen:
                    seen.add(apdu_hex)
                    candidates.append(apdu_hex)
                    if len(candidates) >= max_candidates:
                        return candidates
    return candidates


def run(engine: FuzzEngine, seeds: list[Seed], max_candidates: int = 512) -> FuzzEngine:
    """Learn a grammar from seeds, synthesize candidates, drive the engine."""
    grammar = ApduGrammar.from_seeds(seeds)
    log.info(
        "grammar learned: %d prefixes, %d tags, %d value templates",
        len(grammar.prefixes),
        len(grammar.tags),
        len(grammar.value_templates),
    )
    candidates = synthesize(grammar, max_candidates=max_candidates)
    log.info("grammar mode: %d synthesized candidates", len(candidates))
    for apdu_hex in candidates:
        outcome = engine.consider(apdu_hex)
        if outcome.new_signal:
            log.info("new signal %s -> %s", apdu_hex, outcome.reason)
    log.info("grammar mode done: %s", engine.summary())
    return engine
