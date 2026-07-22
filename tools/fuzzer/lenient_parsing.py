"""Focused campaign: map the eUICC TLV/length parser's acceptance boundary.

A prior read-only campaign found the SE returns SW 9000 to over-declared and
otherwise-malformed BER length encodings on GET commands (notably BF2D
GetProfilesInfo). This module characterises that boundary precisely: for each
allowlisted read tag it walks a fixed set of length-encoding classes and records
SW + response fingerprint per class, then aggregates into an acceptance map.

Design notes:

- ``testing-handbook-skills:fuzzing-obstacles`` informed the length/framing
  classes: length is exactly the kind of framing barrier a parser can be lax
  about. We do NOT patch the SUT (it is a black-box card); instead we enumerate
  the framing variants the obstacle guidance says a parser might mishandle
  (over/under-declared, truncated, indefinite, non-minimal long form).
- ``testing-handbook-skills:fuzzing-dictionary`` informed reuse of
  ``dictionary.ber_length_edge_cases`` / ``malformed_framing`` / ``encode_lc``
  as the domain token source, so each inner length field is a meaningful BER
  length token rather than a random byte.

Safety is unchanged and absolute. Every candidate is a STORE DATA command whose
leading BER-TLV tag is one of the already-allowlisted read tags. Every candidate
routes through ``engine.FuzzEngine.consider`` -> ``safety.guard_send``. Nothing
here sends anything; the engine is the only place a send can happen, and only in
live mode for ALLOWED candidates.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from dictionary import (
    STORE_DATA_PREFIX,
    ber_length_edge_cases,
    encode_lc,
    malformed_framing,
)
from engine import FuzzEngine
from novelty import NoveltyEngine, ProbeResult, SafetyViolation
from reporting import BehaviourRecord, UniqueBehaviourReporter
from safety import ALLOWLIST_TAGS

log = logging.getLogger("fuzzer.lenient")

# The read tags this campaign varies framing for. Exactly the allowlisted
# store-data read tags named in the task; nothing is added here.
READ_TAGS: tuple[int, ...] = tuple(sorted(ALLOWLIST_TAGS))

# The length-encoding classes the campaign covers, one bucket each in the map.
LENGTH_CLASSES: tuple[str, ...] = (
    # Inner BER length field of the top-level TLV.
    "inner_short_true",  # short form, declared == body (well-formed baseline)
    "inner_long1_true",  # 81 LL, declared == body (valid but non-minimal)
    "inner_long2_true",  # 82 00 LL, declared == body
    "inner_long3_true",  # 83 00 00 LL, declared == body
    "inner_long4_true",  # 84 00 00 00 LL, declared == body
    "inner_over_short",  # short form, declared > body
    "inner_over_long1",  # 81 FF, declared >> body
    "inner_over_long2",  # 82 FF FF, declared >> body (the lead example)
    "inner_reserved_ff",  # FF length octet (BER-reserved)
    "inner_under",  # declared < body
    "inner_zero_with_body",  # declared 00 with a value byte present
    "inner_indefinite",  # 80 indefinite form (illegal in DER/APDU)
    "inner_truncated",  # long-form marker with too-few length octets
    "inner_leading_zero_long2",  # 82 00 05, non-minimal leading zero
    # Outer APDU Lc vs inner TLV size.
    "lc_match",
    "lc_over",
    "lc_under",
    # Structural framing.
    "nested_valid",
    "deep_nesting",
    "multi_toplevel",
    "unknown_subtag",
    "empty_value",
    "max_value",
)

# Which ber_length_edge_cases entries feed which class. Reuses the shared
# dictionary tokens so the inner length octets are the vetted BER length forms.
_EDGE_TO_CLASS: dict[str, str] = {
    "len_short_true": "inner_short_true",
    "len_long1_true": "inner_long1_true",
    "len_long2_true": "inner_long2_true",
    "len_long1_overstated": "inner_over_long1",
    "len_long2_overstated": "inner_over_long2",
    "len_truncated_long": "inner_truncated",
    "len_indefinite": "inner_indefinite",
    "len_reserved_ff": "inner_reserved_ff",
    "len_zero": "inner_zero_with_body",
}

# Classes that are, by construction, well-formed BER + consistent framing. The
# rest are marked malformed so novelty flags a 9000 as success_on_malformed.
_WELL_FORMED_CLASSES: frozenset[str] = frozenset(
    {
        "inner_short_true",
        "inner_long1_true",
        "inner_long2_true",
        "inner_long3_true",
        "inner_long4_true",
        "lc_match",
        "nested_valid",
        "empty_value",
        "max_value",
    }
)

# One value byte reused across the inner-length probes, matching the lead's 5A.
_V1 = b"\x5A"


@dataclass(frozen=True)
class Candidate:
    """One STORE DATA candidate plus the metadata the map/novelty need."""

    apdu_hex: str
    command: str  # the read tag, e.g. "BF2D"
    tag: str
    length_class: str
    malformed: bool


def _tag_bytes(tag: int) -> bytes:
    if tag > 0xFF:
        return bytes(((tag >> 8) & 0xFF, tag & 0xFF))
    return bytes((tag,))


def _apdu(tlv: bytes, *, lc: bytes | None = None) -> str:
    """Frame a TLV body into a full STORE DATA APDU hex string."""
    if lc is None:
        lc = encode_lc(len(tlv), form="short")
    return (STORE_DATA_PREFIX + lc + tlv).hex().upper()


def _nest(inner: bytes, depth: int) -> bytes:
    """Wrap ``inner`` in ``depth`` levels of A0 constructed TLVs."""
    node = inner
    for _ in range(depth):
        node = b"\xA0" + bytes((len(node),)) + node
    return node


def _candidates_for_tag(tag: int) -> Iterator[Candidate]:
    tag_b = _tag_bytes(tag)
    cmd = f"{tag:04X}" if tag > 0xFF else f"{tag:02X}"

    def make(length_class: str, tlv: bytes, *, lc: bytes | None = None) -> Candidate:
        return Candidate(
            apdu_hex=_apdu(tlv, lc=lc),
            command=cmd,
            tag=cmd,
            length_class=length_class,
            malformed=length_class not in _WELL_FORMED_CLASSES,
        )

    # Inner length classes driven by the shared BER length dictionary tokens.
    for edge in ber_length_edge_cases(len(_V1)):
        cls = _EDGE_TO_CLASS.get(edge.name)
        if cls is None:
            continue
        yield make(cls, tag_b + edge.value + _V1)

    # Long-form true-length variants the dictionary does not carry (83/84).
    yield make("inner_long3_true", tag_b + b"\x83\x00\x00\x01" + _V1)
    yield make("inner_long4_true", tag_b + b"\x84\x00\x00\x00\x01" + _V1)

    # Declared > body (short form) and declared < body.
    yield make("inner_over_short", tag_b + b"\x05" + _V1)
    yield make("inner_under", tag_b + b"\x01" + _V1 * 3)

    # Non-minimal long form with a leading zero octet, length matches body.
    yield make("inner_leading_zero_long2", tag_b + b"\x82\x00\x05" + _V1 * 5)

    # Outer Lc classes. lc_match is the consistent baseline; the two mismatches
    # come straight from the shared malformed_framing helper.
    good_tlv = tag_b + b"\x01" + _V1
    yield make("lc_match", good_tlv)
    for entry in malformed_framing(STORE_DATA_PREFIX, tag_b, _V1):
        if entry.name == "frame_lc_over":
            yield Candidate(entry.value.hex().upper(), cmd, cmd, "lc_over", True)
        elif entry.name == "frame_lc_under":
            yield Candidate(entry.value.hex().upper(), cmd, cmd, "lc_under", True)

    # Structural framing.
    inner_leaf = b"\x80\x01\x00"
    yield make("nested_valid", tag_b + _nest(inner_leaf, 1))
    for depth in range(2, 7):
        node = _nest(inner_leaf, depth)
        yield make("deep_nesting", tag_b + bytes((len(node),)) + node)
    two = (tag_b + b"\x01" + _V1) + (b"\x5C\x01\x5A")
    yield make("multi_toplevel", two)
    yield make("unknown_subtag", tag_b + b"\x03\xDD\x01\x00")
    yield make("empty_value", tag_b + b"\x00")
    big = _V1 * 200
    yield make("max_value", tag_b + b"\x81\xC8" + big)


def generate_candidates(tags: Iterable[int] = READ_TAGS) -> list[Candidate]:
    """Every framing candidate for the given read tags."""
    out: list[Candidate] = []
    for tag in tags:
        out.extend(_candidates_for_tag(tag))
    return out


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


class LenientCampaign:
    """Sweep every framing candidate, record SW + fingerprint, write outputs."""

    def __init__(
        self,
        engine: FuzzEngine,
        novelty: NoveltyEngine,
        reporter: UniqueBehaviourReporter,
        full_path: Path,
        *,
        mode: str = "lenient",
        phase: str = "dry",
        wall: int = 300,
        send_cap: int | None = None,
    ) -> None:
        self._engine = engine
        self._novelty = novelty
        self._reporter = reporter
        self._full_path = full_path
        self._mode = mode
        self._phase = phase
        self._wall = wall
        self._send_cap = send_cap

    def _handle(self, candidate: Candidate, full_fh) -> None:
        outcome = self._engine.consider(candidate.apdu_hex)

        sw = outcome.sw
        resp = outcome.resp_hex
        if outcome.sent and resp and sw and resp.upper().endswith(sw.upper()):
            resp = resp[: -len(sw)] or None

        transport_error = (
            outcome.error
            if outcome.error and outcome.classification.value == "ALLOWED"
            else None
        )
        result = ProbeResult(
            apdu_hex=candidate.apdu_hex,
            command=candidate.command,
            classification=outcome.classification.value,
            malformed=candidate.malformed,
            sent=outcome.sent,
            sw=sw,
            resp_hex=resp,
            transport_error=transport_error,
        )
        verdict = self._novelty.evaluate(result)
        self._reporter.note_considered(sw, outcome.sent)

        # Full per-candidate row (carries length_class) feeds the acceptance map.
        full_fh.write(
            json.dumps(
                {
                    "ts": _now(),
                    "mode": self._mode,
                    "phase": self._phase,
                    "command": candidate.command,
                    "tag": candidate.tag,
                    "length_class": candidate.length_class,
                    "apdu": candidate.apdu_hex.upper(),
                    "classification": outcome.classification.value,
                    "malformed": candidate.malformed,
                    "sent": outcome.sent,
                    "sw": sw,
                    "resp": resp,
                    "resp_fingerprint": verdict.fingerprint,
                    "transport_error": transport_error,
                }
            )
            + "\n"
        )
        full_fh.flush()

        # Unique/unexpected stream: only novel behaviours land here.
        self._reporter.report(
            BehaviourRecord(
                mode=self._mode,
                phase=self._phase,
                apdu=candidate.apdu_hex,
                tag=candidate.tag,
                command=candidate.command,
                classification=outcome.classification.value,
                sent=outcome.sent,
                sw=sw,
                resp=resp,
                resp_fingerprint=verdict.fingerprint,
                novelty=list(verdict.novelty),
                repeat_consistency="not_tested",
                severity=verdict.severity,
            )
        )

    def run(self) -> dict[str, object]:
        deadline = time.monotonic() + self._wall
        candidates = generate_candidates()
        log.info("lenient campaign seeded with %d candidates", len(candidates))

        self._full_path.parent.mkdir(parents=True, exist_ok=True)
        with self._full_path.open("a") as full_fh:
            for candidate in candidates:
                if time.monotonic() > deadline:
                    log.info("lenient campaign hit wall of %ds", self._wall)
                    break
                if self._send_cap is not None and self._engine.sent >= self._send_cap:
                    # Keep classifying without sending once the cap is reached.
                    self._engine.live = False
                try:
                    self._handle(candidate, full_fh)
                except SafetyViolation as exc:
                    self._reporter.report(
                        BehaviourRecord(
                            mode=self._mode,
                            phase=self._phase,
                            apdu=candidate.apdu_hex,
                            tag=candidate.tag,
                            command=candidate.command,
                            classification="BLOCKED",
                            sent=True,
                            sw=None,
                            resp=None,
                            resp_fingerprint="n/a",
                            novelty=["safety_violation"],
                            repeat_consistency="not_tested",
                            severity="critical",
                        )
                    )
                    log.critical("SAFETY VIOLATION, aborting run: %s", exc)
                    break

        return self._reporter.finalize(
            distinct_signatures=self._novelty.distinct_signatures()
        )


# --------------------------------------------------------------------------- #
# Aggregation: bucket results by length-encoding class into an acceptance map.
# --------------------------------------------------------------------------- #


def _empty_bucket() -> dict[str, object]:
    return {
        "total": 0,
        "accepted_9000": 0,
        "rejected": {},
        "transport_error": 0,
        "not_sent": 0,
        "classifications": {},
    }


def _bucket_status(bucket: dict[str, object]) -> str:
    total = bucket["total"]
    if total == 0:
        return "no_data"
    if bucket["not_sent"] == total:
        return "not_sent(dry)"
    accepted = bucket["accepted_9000"]
    rejected: dict[str, int] = bucket["rejected"]  # type: ignore[assignment]
    if bucket["transport_error"] == total:
        return "transport_error"
    if accepted and not rejected:
        return "accepted"
    if accepted and rejected:
        return "mixed(" + ",".join(sorted(rejected)) + ")"
    if rejected and not accepted:
        return "rejected(" + ",".join(sorted(rejected)) + ")"
    return "other"


def aggregate(rows: Iterable[dict]) -> dict[str, dict[str, dict[str, object]]]:
    """Bucket full-candidate rows by command -> length_class -> counts.

    Each row needs at least ``command``, ``length_class``, ``sent``, ``sw``,
    ``classification`` and ``transport_error`` keys.
    """
    agg: dict[str, dict[str, dict[str, object]]] = {}
    for row in rows:
        command = str(row.get("command", "?"))
        length_class = str(row.get("length_class", "?"))
        bucket = agg.setdefault(command, {}).setdefault(length_class, _empty_bucket())
        bucket["total"] = bucket["total"] + 1  # type: ignore[operator]

        classification = str(row.get("classification", "?"))
        classes: dict[str, int] = bucket["classifications"]  # type: ignore[assignment]
        classes[classification] = classes.get(classification, 0) + 1

        if row.get("transport_error"):
            bucket["transport_error"] = bucket["transport_error"] + 1  # type: ignore[operator]
            continue
        if not row.get("sent"):
            bucket["not_sent"] = bucket["not_sent"] + 1  # type: ignore[operator]
            continue

        sw = row.get("sw")
        if sw == "9000":
            bucket["accepted_9000"] = bucket["accepted_9000"] + 1  # type: ignore[operator]
        elif sw:
            rejected: dict[str, int] = bucket["rejected"]  # type: ignore[assignment]
            rejected[str(sw)] = rejected.get(str(sw), 0) + 1

    for command in agg.values():
        for bucket in command.values():
            bucket["status"] = _bucket_status(bucket)
    return agg


def analyze_lenient(jsonl_path: str | Path) -> dict[str, dict[str, dict[str, object]]]:
    """Read a full-candidate JSONL and return the per-command acceptance map."""
    path = Path(jsonl_path)
    rows: list[dict] = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return aggregate(rows)


def render_map_markdown(agg: dict[str, dict[str, dict[str, object]]]) -> str:
    """Render the acceptance map as a Markdown table per command."""
    lines: list[str] = ["# eUICC length-parser acceptance map", ""]
    lines.append(
        "One row per length-encoding class. `status` is the verdict; "
        "`accepted` means the card returned 9000 to that framing."
    )
    lines.append("")
    for command in sorted(agg):
        lines.append(f"## {command}")
        lines.append("")
        lines.append("| length_class | status | n | 9000 | rejected | txerr | not_sent |")
        lines.append("|---|---|---|---|---|---|---|")
        for length_class in sorted(agg[command]):
            b = agg[command][length_class]
            rejected: dict[str, int] = b["rejected"]  # type: ignore[assignment]
            rej = ",".join(f"{sw}:{n}" for sw, n in sorted(rejected.items())) or "-"
            lines.append(
                f"| {length_class} | {b['status']} | {b['total']} | "
                f"{b['accepted_9000']} | {rej} | {b['transport_error']} | "
                f"{b['not_sent']} |"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def write_lenient_map(
    agg: dict[str, dict[str, dict[str, object]]],
    *,
    json_path: Path,
    md_path: Path,
) -> None:
    """Write the acceptance map as JSON and Markdown."""
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(agg, indent=2, sort_keys=True) + "\n")
    md_path.write_text(render_map_markdown(agg))


def build_and_run(
    *,
    out_path: Path,
    summary_path: Path,
    full_path: Path,
    map_json: Path,
    map_md: Path,
    phase: str,
    engine: FuzzEngine,
    wall: int,
    send_cap: int | None,
) -> dict[str, object]:
    """Assemble the campaign pieces, run it, and write the acceptance map."""
    novelty = NoveltyEngine()
    allowlist = [f"{t:04X}" for t in READ_TAGS]
    with UniqueBehaviourReporter(
        out_path=out_path,
        summary_path=summary_path,
        mode="lenient",
        phase=phase,
        allowlist=allowlist,
    ) as reporter:
        campaign = LenientCampaign(
            engine,
            novelty,
            reporter,
            full_path,
            phase=phase,
            wall=wall,
            send_cap=send_cap,
        )
        summary = campaign.run()

    agg = analyze_lenient(full_path)
    write_lenient_map(agg, json_path=map_json, md_path=map_md)
    return summary
