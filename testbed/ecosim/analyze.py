"""Invariant/variable field analysis across multiple end-to-end runs.

The idea: run the same simulated eSIM download flow N times (each run generates
its own fresh challenges, ephemeral keys, transaction ids, etc.) and diff the
resulting message logs. Fields that are byte-for-byte identical across every
run are structural/invariant (protocol framing, static config); fields that
differ are candidates for a fuzzer to target, since they represent
attacker-observable or attacker-controllable data points.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import codec, tlv
from .bus import Message


@dataclass
class FieldClass:
    path: str
    channel: str
    kind: str
    invariant: bool
    distinct_values: int
    example: str


def _flatten_json(obj: object, prefix: str, out: dict[str, str]) -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            _flatten_json(value, path, out)
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            path = f"{prefix}.{index}" if prefix else str(index)
            _flatten_json(value, path, out)
    else:
        out[prefix] = obj if isinstance(obj, str) else str(obj)


def _flatten_tlv(nodes: list[tlv.TLV], prefix: str, out: dict[str, str]) -> None:
    for node in nodes:
        tag_hex = format(node.tag, "X")
        path = f"{prefix}/{tag_hex}" if prefix else tag_hex
        if node.children:
            _flatten_tlv(node.children, path, out)
        else:
            out[path] = node.value.hex()


def flatten_message(msg: Message) -> dict[str, str]:
    """Decompose one bus.Message into {dotted/tag path: value repr}."""
    try:
        if msg.encoding == "json":
            data = codec.from_json_wire(msg.wire)
            out: dict[str, str] = {}
            _flatten_json(data, "", out)
            return out
        if msg.encoding == "apdu":
            nodes = tlv.walk(msg.wire)
            out = {}
            _flatten_tlv(nodes, "", out)
            return out
        if msg.encoding == "text":
            return {"raw": msg.wire.decode("utf-8")}
        return {"<unparsable>": msg.wire.hex()}
    except Exception:
        return {"<unparsable>": msg.wire.hex()}


def _group_by_channel_kind(run: list[Message]) -> dict[tuple[str, str], list[Message]]:
    groups: dict[tuple[str, str], list[Message]] = {}
    for msg in run:
        groups.setdefault((msg.channel, msg.kind), []).append(msg)
    return groups


def classify_fields(runs: list[list[Message]]) -> list[FieldClass]:
    """Align messages across runs by (channel, kind, index) and diff their fields."""
    if len(runs) < 2:
        raise ValueError("classify_fields requires at least 2 runs to compare")

    grouped_runs = [_group_by_channel_kind(run) for run in runs]
    all_keys: set[tuple[str, str]] = set()
    for grouped in grouped_runs:
        all_keys.update(grouped.keys())

    classes: list[FieldClass] = []
    for channel, kind in sorted(all_keys):
        max_len = max(len(grouped.get((channel, kind), [])) for grouped in grouped_runs)
        for idx in range(max_len):
            flattened_per_run: list[dict[str, str] | None] = []
            for grouped in grouped_runs:
                msgs = grouped.get((channel, kind), [])
                flattened_per_run.append(flatten_message(msgs[idx]) if idx < len(msgs) else None)

            all_paths: set[str] = set()
            for flat in flattened_per_run:
                if flat is not None:
                    all_paths.update(flat.keys())

            for path in sorted(all_paths):
                present_values: list[str] = []
                present_in_all = True
                for flat in flattened_per_run:
                    if flat is not None and path in flat:
                        present_values.append(flat[path])
                    else:
                        present_in_all = False
                distinct = set(present_values)
                classes.append(FieldClass(
                    path=path,
                    channel=channel,
                    kind=kind,
                    invariant=present_in_all and len(distinct) == 1,
                    distinct_values=len(distinct),
                    example=present_values[0] if present_values else "",
                ))
    return classes


def variable_fields(classes: list[FieldClass]) -> list[FieldClass]:
    return [c for c in classes if not c.invariant]


def summarize(classes: list[FieldClass]) -> str:
    if not classes:
        return "(no fields)"
    header = f"{'path':<42} {'channel':<7} {'kind':<28} {'invariant':<9} {'distinct':<8} example"
    lines = [header, "-" * len(header)]
    for c in classes:
        lines.append(
            f"{c.path:<42} {c.channel:<7} {c.kind:<28} {str(c.invariant):<9} "
            f"{c.distinct_values:<8} {c.example}"
        )
    return "\n".join(lines)
