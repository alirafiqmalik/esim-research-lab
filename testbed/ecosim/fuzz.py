"""Targeted single-field fuzzing on top of the bus mutator hook.

Given a set of `analyze.FieldClass` results (typically the variable fields on
one channel), pick a field + mutation each iteration, install a bus mutator
that rewrites only that field on the matching (channel, kind) message, run a
full end-to-end flow, and classify the outcome against the structure verifier.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, replace
from typing import Callable

from . import codec, tlv
from .analyze import FieldClass
from .bus import Bus, Message

MUTATIONS: tuple[str, ...] = (
    "bitflip",
    "truncate",
    "oversize",
    "empty",
    "type_confusion",
    "huge_int",
)


def _mutate_bytes(data: bytes, mutation: str, rng: random.Random) -> bytes:
    if mutation == "bitflip":
        if not data:
            return data
        mutated = bytearray(data)
        idx = rng.randrange(len(mutated))
        mutated[idx] ^= 1 << rng.randrange(8)
        return bytes(mutated)
    if mutation == "truncate":
        return data[: len(data) // 2]
    if mutation == "oversize":
        seed = data or b"\x41"
        return (seed * ((4096 // len(seed)) + 1))[:4096]
    if mutation == "empty":
        return b""
    if mutation == "type_confusion":
        # Raw bytes have no "type" to confuse -- swap to a structurally
        # different payload shape (empty array/object framing) instead.
        return b"[]" if data else b"{}"
    if mutation == "huge_int":
        value = 2**64 + rng.randrange(10**6)
        return value.to_bytes((value.bit_length() + 7) // 8, "big")
    return data


def _mutate_json_value(value: object, mutation: str, rng: random.Random) -> object:
    if mutation == "bitflip":
        if isinstance(value, str):
            raw = bytearray((value or "\x00").encode("utf-8", "replace"))
            idx = rng.randrange(len(raw))
            raw[idx] ^= 1 << rng.randrange(8)
            return raw.decode("utf-8", "replace")
        if isinstance(value, bool):
            return not value
        if isinstance(value, int):
            return value ^ (1 << rng.randrange(8))
        return value
    if mutation == "truncate":
        if isinstance(value, (str, list)):
            return value[: len(value) // 2]
        return value
    if mutation == "oversize":
        if isinstance(value, str):
            seed = value or "A"
            return (seed * ((4096 // len(seed)) + 1))[:4096]
        return value
    if mutation == "empty":
        if isinstance(value, str):
            return ""
        if isinstance(value, list):
            return []
        if isinstance(value, dict):
            return {}
        return value
    if mutation == "type_confusion":
        if isinstance(value, str):
            return 1337
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, list):
            return "not-a-list"
        if isinstance(value, dict):
            return "not-an-object"
        return value
    if mutation == "huge_int":
        return 2**63 + rng.randrange(10**6)
    return value


def _json_navigate(data: object, parts: list[str]) -> tuple[object, str | int]:
    """Walk all but the last path component, returning (container, final key)."""
    obj = data
    for part in parts[:-1]:
        obj = obj[int(part)] if isinstance(obj, list) else obj[part]
    last = parts[-1]
    return (obj, int(last)) if isinstance(obj, list) else (obj, last)


def _find_tlv_node(nodes: list[tlv.TLV], parts: list[str]) -> tlv.TLV | None:
    if not parts:
        return None
    tag = int(parts[0], 16)
    for node in nodes:
        if node.tag == tag:
            if len(parts) == 1:
                return node
            return _find_tlv_node(node.children, parts[1:])
    return None


def _encode_tlv_node(node: tlv.TLV) -> bytes:
    if node.children:
        return tlv.encode_constructed(node.tag, [_encode_tlv_node(c) for c in node.children])
    return tlv.encode(node.tag, node.value)


def _encode_tlv_tree(nodes: list[tlv.TLV]) -> bytes:
    return b"".join(_encode_tlv_node(n) for n in nodes)


def _apply_mutation_to_wire(
    wire: bytes, encoding: str, path: str, mutation: str, rng: random.Random
) -> bytes:
    try:
        if encoding == "json":
            data = codec.from_json_wire(wire)
            container, key = _json_navigate(data, path.split("."))
            container[key] = _mutate_json_value(container[key], mutation, rng)
            return codec.to_json_wire(data)
        if encoding == "apdu":
            nodes = tlv.walk(wire)
            node = _find_tlv_node(nodes, path.split("/"))
            if node is None:
                return wire
            node.value = _mutate_bytes(node.value, mutation, rng)
            return _encode_tlv_tree(nodes)
        if encoding == "text":
            if path != "raw":
                return wire
            mutated = _mutate_json_value(wire.decode("utf-8"), mutation, rng)
            return str(mutated).encode("utf-8")
        return wire
    except (KeyError, IndexError, TypeError, ValueError, AttributeError, UnicodeDecodeError):
        # A missing/invalid path is a documented no-op, not a fuzzer bug --
        # the campaign still records an iteration instead of aborting the run.
        return wire


def fuzz_field(wire: bytes, encoding: str, path: str, rng: random.Random) -> bytes:
    """Mutate only the value at `path`, leaving structure/other fields intact."""
    mutation = rng.choice(MUTATIONS)
    return _apply_mutation_to_wire(wire, encoding, path, mutation, rng)


@dataclass
class FuzzResult:
    iteration: int
    channel: str
    path: str
    mutation: str
    outcome: str  # "accepted" | "verifier-violation" | "exception"
    detail: str


@dataclass
class FuzzCampaign:
    bus: Bus
    rng: random.Random

    def run(
        self,
        target_channel: str,
        targets: list[FieldClass],
        iterations: int,
        run_flow: Callable[[], list[Message]],
        verify_run: Callable[[list[Message]], list[str]],
    ) -> list[FuzzResult]:
        if not targets:
            raise ValueError("targets must be a non-empty list of FieldClass")

        results: list[FuzzResult] = []
        for iteration in range(iterations):
            target = self.rng.choice(targets)
            mutation = self.rng.choice(MUTATIONS)

            def mutator(msg: Message, target: FieldClass = target, mutation: str = mutation) -> Message:
                if msg.channel != target_channel or msg.kind != target.kind:
                    return msg
                new_wire = _apply_mutation_to_wire(msg.wire, msg.encoding, target.path, mutation, self.rng)
                return replace(msg, wire=new_wire)

            self.bus.set_mutator(target_channel, mutator)
            try:
                messages = run_flow()
                violations = verify_run(messages)
                if violations:
                    outcome, detail = "verifier-violation", "; ".join(violations)
                else:
                    outcome, detail = "accepted", ""
            except Exception as exc:  # deliberate: fuzzing must classify, not propagate
                outcome, detail = "exception", repr(exc)
            finally:
                self.bus.clear_mutators()

            results.append(FuzzResult(
                iteration=iteration,
                channel=target_channel,
                path=target.path,
                mutation=mutation,
                outcome=outcome,
                detail=detail,
            ))
        return results
