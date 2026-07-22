"""Symbolic behavioural map of the eUICC: abstract APDUs into I/O symbols.

Each concrete APDU is abstracted to a canonical INPUT-SYMBOL and each response
to a canonical OUTPUT-SYMBOL, then the observed mapping ``O = f(I)`` is recorded
from the fuzzer traces. This is the alphabet layer of a Mealy-machine /
automata-learning abstraction of the card.

Reused from the shared fuzzer modules (imported, never edited):

- ``safety.parse_store_data_tag`` — the exact BER-TLV tag parser the guard uses.
- ``safety.ALLOWLIST_TAGS`` / ``BLOCKLIST_TAGS`` / ``ALLOWLIST_INS`` / ``WRITE_INS``
  — the command-name lookup (SGP.22 tag/INS -> function name).
- ``dictionary.STORE_DATA_PREFIX`` — the ES10x store-data header.
- ``lenient_parsing.LENGTH_CLASSES`` — the length-encoding class vocabulary; the
  segmenter emits the ``inner_*`` names from this set.
- ``novelty.response_fingerprint`` — the response-shape fingerprint used as the
  output symbol's ``response_shape``.

Nothing here sends anything. It reads trace JSONLs and derives symbols.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from dictionary import STORE_DATA_PREFIX
from lenient_parsing import LENGTH_CLASSES
from novelty import response_fingerprint
from safety import (
    ALLOWLIST_INS,
    ALLOWLIST_TAGS,
    BLOCKLIST_TAGS,
    INS_STORE_DATA,
    WRITE_INS,
    parse_store_data_tag,
)

# --------------------------------------------------------------------------- #
# Command-name lookup: SGP.22 store-data tag or ISO INS -> functional name.
# --------------------------------------------------------------------------- #

# ES10x store-data BER-TLV tag -> SGP.22 function name. Built from the safety
# allow/block lists plus the few RSP tags that appear in docs/reference and may
# turn up in a trace. Values match docs/reference/euicc-api.md.
_STORE_DATA_TAG_NAMES: dict[int, str] = {
    **ALLOWLIST_TAGS,
    **BLOCKLIST_TAGS,
    0xBF21: "PrepareDownload",
    0xBF38: "AuthenticateServer",
    0xBF30: "RemoveNotificationFromList",
    0xBF41: "CancelSession",
}

# ISO / GlobalPlatform INS -> command name.
_INS_NAMES: dict[int, str] = {
    **ALLOWLIST_INS,
    **WRITE_INS,
    INS_STORE_DATA: "STORE DATA",
}


def command_name_for_apdu(apdu: bytes) -> str:
    """Functional command name for an APDU, from its INS (and store-data tag)."""
    if len(apdu) < 2:
        return "?"
    ins = apdu[1]
    if ins == INS_STORE_DATA:
        try:
            tag = parse_store_data_tag(apdu)
        except ValueError:
            return "STORE DATA"
        return _STORE_DATA_TAG_NAMES.get(tag, f"StoreData_{tag:04X}")
    return _INS_NAMES.get(ins, f"INS_{ins:02X}")


# --------------------------------------------------------------------------- #
# Input symbol: segment-aware abstraction of an APDU bitstring.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Segment:
    """One labelled slice of an APDU bitstring."""

    label: str
    hex: str
    note: str = ""


@dataclass(frozen=True)
class InputSymbol:
    """Canonical abstraction of a concrete APDU.

    ``tag`` is the store-data BER-TLV tag (e.g. ``BF2D``) or, for GET DATA, the
    P1-P2 data-object tag; ``None`` for ISO commands whose object is not a tag.
    """

    cla: str
    command_name: str
    p1_class: str
    p2_class: str
    tag: str | None
    length_class: str
    body_class: str

    def key(self) -> str:
        """Stable string key for grouping / JSON."""
        return "|".join(
            (
                self.cla,
                self.command_name,
                self.p1_class,
                self.p2_class,
                self.tag or "-",
                self.length_class,
                self.body_class,
            )
        )


def _p_class(value: int) -> str:
    return f"0x{value:02X}"


def _body_class(value: bytes) -> str:
    """Coarse class of a store-data TLV value / ISO data field."""
    if not value:
        return "empty"
    first = value[0]
    if first == 0x5C:
        return "taglist"
    if first in (0xA0, 0x30):
        return "constructed"
    if first == 0x80:
        return "ctx_primitive"
    return "value"


def _length_class(length_octet_start: bytes, value: bytes) -> str:
    """Classify the BER-TLV length encoding into a ``lenient`` ``inner_*`` class.

    ``length_octet_start`` is the byte string beginning at the length field;
    ``value`` is the actual bytes that follow it. Returns a name drawn from
    ``lenient_parsing.LENGTH_CLASSES`` so the vocabulary matches that campaign.
    """
    if not length_octet_start:
        return "inner_truncated"
    first = length_octet_start[0]
    actual = len(value)

    if first == 0x80:
        return "inner_indefinite"
    if first == 0xFF:
        return "inner_reserved_ff"

    if first < 0x80:  # short form
        declared = first
        if declared == 0 and actual > 0:
            return "inner_zero_with_body"
        if declared == actual:
            return "inner_short_true"
        if declared > actual:
            return "inner_over_short"
        return "inner_under"

    num = first & 0x7F
    octets = length_octet_start[1 : 1 + num]
    if len(octets) < num:
        return "inner_truncated"
    declared = int.from_bytes(octets, "big") if octets else 0

    if num == 1:
        return "inner_long1_true" if declared == actual else "inner_over_long1"
    if num == 2:
        if octets[0] == 0x00 and declared == actual:
            return "inner_leading_zero_long2"
        return "inner_long2_true" if declared == actual else "inner_over_long2"
    if num == 3:
        return "inner_long3_true"
    if num == 4:
        return "inner_long4_true"
    return "inner_truncated"


def _tag_len(tag: int) -> int:
    return 2 if tag > 0xFF else 1


def segment_apdu(apdu_hex: str) -> list[Segment]:
    """Decompose an APDU bitstring into labelled segments.

    Header segments (CLA, INS->command, P1, P2, Lc) always; for a store-data
    body, the BER-TLV tag, length field, and value as further segments.
    """
    apdu = bytes.fromhex(apdu_hex.strip().replace(" ", ""))
    if len(apdu) < 4:
        raise ValueError(f"APDU shorter than a 4-byte header: {apdu_hex!r}")

    cla, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]
    segments = [
        Segment("CLA", f"{cla:02X}"),
        Segment("INS", f"{ins:02X}", command_name_for_apdu(apdu)),
        Segment("P1", f"{p1:02X}"),
        Segment("P2", f"{p2:02X}"),
    ]
    if len(apdu) <= 4:
        return segments

    lc = apdu[4]
    segments.append(Segment("Lc", f"{lc:02X}"))
    body = apdu[5:]
    if not body:
        return segments

    if ins == INS_STORE_DATA:
        try:
            tag = parse_store_data_tag(apdu)
        except ValueError:
            segments.append(Segment("body", body.hex().upper(), "unparseable"))
            return segments
        tl = _tag_len(tag)
        segments.append(Segment("tag", body[:tl].hex().upper(), command_name_for_apdu(apdu)))
        rest = body[tl:]
        length_octet_start = rest
        first = rest[0] if rest else None
        len_field_len = 1
        if first is not None and 0x80 < first < 0xFF:
            len_field_len = 1 + (first & 0x7F)
        segments.append(Segment("ber_len", rest[:len_field_len].hex().upper()))
        value = rest[len_field_len:]
        segments.append(
            Segment("value", value.hex().upper(), _length_class(length_octet_start, value))
        )
    else:
        segments.append(Segment("data", body.hex().upper(), _body_class(body)))
    return segments


def abstract_input(apdu_hex: str) -> InputSymbol:
    """Abstract a concrete APDU to its canonical INPUT-SYMBOL."""
    apdu = bytes.fromhex(apdu_hex.strip().replace(" ", ""))
    if len(apdu) < 4:
        raise ValueError(f"APDU shorter than a 4-byte header: {apdu_hex!r}")
    cla, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]
    command = command_name_for_apdu(apdu)
    body = apdu[5:] if len(apdu) > 5 else b""

    if ins == INS_STORE_DATA:
        try:
            tag = parse_store_data_tag(apdu)
            tag_hex = f"{tag:04X}" if tag > 0xFF else f"{tag:02X}"
            tl = _tag_len(tag)
            rest = body[tl:]
            first = rest[0] if rest else None
            len_field_len = 1
            if first is not None and 0x80 < first < 0xFF:
                len_field_len = 1 + (first & 0x7F)
            value = rest[len_field_len:]
            length_class = _length_class(rest, value)
            body_class = _body_class(value)
        except ValueError:
            tag_hex = None
            length_class = "unparseable"
            body_class = "unparseable"
        return InputSymbol(
            cla=f"{cla:02X}",
            command_name=command,
            p1_class=_p_class(p1),
            p2_class=_p_class(p2),
            tag=tag_hex,
            length_class=length_class,
            body_class=body_class,
        )

    # ISO / GP command. GET DATA carries the data-object tag in P1-P2.
    tag_hex: str | None = None
    if ins in (0xCA, 0xCB):
        tag_hex = f"{p1:02X}{p2:02X}"
    return InputSymbol(
        cla=f"{cla:02X}",
        command_name=command,
        p1_class=_p_class(p1),
        p2_class=_p_class(p2),
        tag=tag_hex,
        length_class="iso",
        body_class=_body_class(body),
    )


# --------------------------------------------------------------------------- #
# Output symbol: abstraction of a response.
# --------------------------------------------------------------------------- #

# Status-word -> coarse class. Exact matches first, then a family fallback.
_SW_CLASS: dict[str, str] = {
    "9000": "OK",
    "6A80": "WRONG_DATA",
    "6A88": "REF_DATA_NOT_FOUND",
    "6A82": "NOT_FOUND",
    "6A83": "NOT_FOUND",
    "6A86": "WRONG_P1P2",
    "6700": "WRONG_LEN",
    "6985": "COND_NOT_SATISFIED",
    "6D00": "INS_NOT_SUPPORTED",
    "6E00": "CLA_NOT_SUPPORTED",
    "6581": "MEMORY_FAILURE",
    "6999": "APPLET_SELECT_FAILED",
}


def sw_class(sw: str | None, *, transport_error: bool = False) -> str:
    """Coarse class for a status word."""
    if sw is None:
        return "TRANSPORT_ERR" if transport_error else "NO_SW"
    sw = sw.upper()
    if sw in _SW_CLASS:
        return _SW_CLASS[sw]
    if sw.startswith("61"):
        return "MORE_DATA"
    if sw.startswith("6C"):
        return "WRONG_LE"
    if sw.startswith("63"):
        return "WARNING"
    if sw.startswith("68"):
        return "CLA_FUNCTION_ERR"
    if sw.startswith("69"):
        return "COMMAND_NOT_ALLOWED"
    if sw.startswith("6A"):
        return "WRONG_PARAMS"
    if sw.startswith("6F"):
        return "NO_DIAGNOSIS"
    if sw.startswith("9"):
        return "OK"
    return f"SW_{sw}"


# Store-data command tag -> semantic label for a well-formed OK response.
_OK_SEMANTIC_BY_TAG: dict[str, str] = {
    "BF3E": "eid",
    "BF20": "euicc_info1",
    "BF22": "euicc_info2",
    "BF2E": "challenge",
    "BF2D": "profile_list",
    "BF28": "notification_list",
    "BF2B": "notification",
    "BF3C": "addresses",
    "BF43": "rat",
}

# GET DATA data-object tag (P1-P2) -> semantic label.
_OK_SEMANTIC_BY_DO: dict[str, str] = {
    "9F7F": "cplc",
    "0066": "card_data",
    "00E0": "key_info",
    "00CF": "gp_do",
}


def _semantic_label(inp: InputSymbol, sw: str | None, resp_hex: str | None) -> str:
    """Best-effort semantic label for a response, given the input symbol."""
    cls = sw_class(sw)
    if cls == "TRANSPORT_ERR" or (sw is None):
        return "transport_error" if sw is None else "none"
    if cls != "OK":
        return {
            "REF_DATA_NOT_FOUND": "ref_not_found",
            "NOT_FOUND": "not_found",
            "WRONG_DATA": "wrong_data",
            "WRONG_LEN": "wrong_length",
            "WRONG_P1P2": "wrong_p1p2",
            "COND_NOT_SATISFIED": "cond_not_satisfied",
            "INS_NOT_SUPPORTED": "ins_not_supported",
        }.get(cls, cls.lower())

    if not resp_hex:
        return "empty_ok"

    try:
        body = bytes.fromhex(resp_hex)
    except ValueError:
        return "raw_ok"
    lead = body[0] if body else None

    if inp.tag and inp.command_name.startswith(("Get", "List")) and inp.tag in _OK_SEMANTIC_BY_TAG:
        expected = bytes.fromhex(inp.tag)
        if body[: len(expected)] == expected:
            return _OK_SEMANTIC_BY_TAG[inp.tag]
        return "truncated"
    if inp.command_name == "GET DATA" and inp.tag in _OK_SEMANTIC_BY_DO:
        return _OK_SEMANTIC_BY_DO[inp.tag]
    if inp.command_name == "SELECT" and lead == 0x6F:
        return "fci"
    return "ok_data"


@dataclass(frozen=True)
class OutputSymbol:
    """Canonical abstraction of a response."""

    sw_class: str
    response_shape: str
    semantic_label: str

    def key(self) -> str:
        return f"{self.sw_class}|{self.response_shape}|{self.semantic_label}"


def abstract_output(
    inp: InputSymbol,
    sw: str | None,
    resp_hex: str | None,
    *,
    transport_error: bool = False,
) -> OutputSymbol:
    """Abstract a response to its canonical OUTPUT-SYMBOL."""
    return OutputSymbol(
        sw_class=sw_class(sw, transport_error=transport_error),
        response_shape=response_fingerprint(resp_hex),
        semantic_label=_semantic_label(inp, sw, resp_hex),
    )


# --------------------------------------------------------------------------- #
# Observed mapping O = f(I) across trace rows.
# --------------------------------------------------------------------------- #


@dataclass
class Observation:
    """One input-symbol's observed outputs and counts."""

    input_symbol: InputSymbol
    outputs: Counter = field(default_factory=Counter)  # OutputSymbol.key -> count
    output_objs: dict = field(default_factory=dict)  # key -> OutputSymbol
    example_apdu: str = ""

    @property
    def total(self) -> int:
        return sum(self.outputs.values())

    @property
    def nondeterministic(self) -> bool:
        return len(self.outputs) > 1

    @property
    def card_nondeterministic(self) -> bool:
        """True when the card returned >1 distinct *responded* output symbol.

        Excludes TRANSPORT_ERR / NO_SW outputs, so a symbol that only differs
        between a real status word and a host-side transport failure (e.g. the
        known-broken deep-173547 run) is not counted as card state-dependence.
        """
        responded = {
            k for k, o in self.output_objs.items()
            if o.sw_class not in ("TRANSPORT_ERR", "NO_SW")
        }
        return len(responded) > 1


def _is_observation_row(row: dict) -> bool:
    """A trace row is an observation only if the APDU actually reached the card.

    A ``sent`` row (with a status word) is a real exchange. A row that was not
    sent but carries a transport error is an attempted-but-failed exchange, also
    an observation of card/transport behaviour. Dry-run rows are neither.
    """
    if row.get("sent") and row.get("sw"):
        return True
    if _transport_error(row):
        return True
    return False


def _transport_error(row: dict) -> bool:
    if row.get("transport_error"):
        return True
    novelty = row.get("novelty")
    if isinstance(novelty, list) and "transport_error" in novelty:
        return True
    return False


@dataclass
class IOMap:
    """The observed input-symbol -> output-symbol mapping."""

    observations: dict[str, Observation] = field(default_factory=dict)
    input_alphabet: dict[str, InputSymbol] = field(default_factory=dict)
    output_alphabet: dict[str, OutputSymbol] = field(default_factory=dict)
    rows_ingested: int = 0
    rows_used: int = 0

    def add_row(self, row: dict) -> None:
        self.rows_ingested += 1
        apdu = row.get("apdu")
        if not apdu or not _is_observation_row(row):
            return
        try:
            inp = abstract_input(apdu)
        except ValueError:
            return
        self.rows_used += 1

        te = _transport_error(row)
        out = abstract_output(inp, row.get("sw"), row.get("resp"), transport_error=te)

        ikey = inp.key()
        self.input_alphabet.setdefault(ikey, inp)
        self.output_alphabet.setdefault(out.key(), out)
        obs = self.observations.get(ikey)
        if obs is None:
            obs = Observation(input_symbol=inp, example_apdu=str(apdu).upper())
            self.observations[ikey] = obs
        obs.outputs[out.key()] += 1
        obs.output_objs[out.key()] = out

    def nondeterministic(self) -> list[Observation]:
        return [o for o in self.observations.values() if o.nondeterministic]

    def card_nondeterministic(self) -> list[Observation]:
        return [o for o in self.observations.values() if o.card_nondeterministic]

    def distinct_mappings(self) -> int:
        return sum(len(o.outputs) for o in self.observations.values())


def iter_jsonl(path: Path) -> Iterable[dict]:
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def build_map(paths: Iterable[Path]) -> IOMap:
    """Ingest every trace JSONL and build the observed I->O map."""
    io = IOMap()
    for path in paths:
        for row in iter_jsonl(path):
            io.add_row(row)
    return io


# --------------------------------------------------------------------------- #
# Emit: machine JSON + human Markdown.
# --------------------------------------------------------------------------- #


def to_json(io: IOMap) -> dict:
    """Serialise the map to a JSON-able dict."""
    return {
        "input_alphabet": {
            k: {
                "cla": s.cla,
                "command_name": s.command_name,
                "p1_class": s.p1_class,
                "p2_class": s.p2_class,
                "tag": s.tag,
                "length_class": s.length_class,
                "body_class": s.body_class,
            }
            for k, s in sorted(io.input_alphabet.items())
        },
        "output_alphabet": {
            k: {
                "sw_class": o.sw_class,
                "response_shape": o.response_shape,
                "semantic_label": o.semantic_label,
            }
            for k, o in sorted(io.output_alphabet.items())
        },
        "mapping": {
            ikey: {
                "command_name": obs.input_symbol.command_name,
                "example_apdu": obs.example_apdu,
                "total_observations": obs.total,
                "nondeterministic": obs.nondeterministic,
                "card_nondeterministic": obs.card_nondeterministic,
                "outputs": [
                    {"output_symbol": okey, "count": cnt}
                    for okey, cnt in obs.outputs.most_common()
                ],
            }
            for ikey, obs in sorted(io.observations.items())
        },
        "counts": {
            "input_alphabet_size": len(io.input_alphabet),
            "output_alphabet_size": len(io.output_alphabet),
            "distinct_io_mappings": io.distinct_mappings(),
            "rows_ingested": io.rows_ingested,
            "rows_used": io.rows_used,
            "nondeterministic_input_symbols": len(io.nondeterministic()),
            "card_nondeterministic_input_symbols": len(io.card_nondeterministic()),
        },
    }


def _fmt_input(s: InputSymbol) -> str:
    return (
        f"`{s.cla}` {s.command_name} "
        f"p1={s.p1_class} p2={s.p2_class} "
        f"tag={s.tag or '-'} len={s.length_class} body={s.body_class}"
    )


def render_markdown(io: IOMap) -> str:
    """Render the symbolic behavioural map as Markdown."""
    lines: list[str] = ["# eUICC I/O symbol map", ""]
    lines.append(
        f"Abstracted from {io.rows_used} observed exchanges "
        f"({io.rows_ingested} trace rows read). Input alphabet "
        f"{len(io.input_alphabet)}, output alphabet {len(io.output_alphabet)}, "
        f"{io.distinct_mappings()} distinct I->O mappings."
    )
    lines.append("")

    lines.append("## Input alphabet")
    lines.append("")
    lines.append("| command | cla | p1 | p2 | tag | length_class | body_class |")
    lines.append("|---|---|---|---|---|---|---|")
    for _, s in sorted(
        io.input_alphabet.items(), key=lambda kv: (kv[1].command_name, kv[0])
    ):
        lines.append(
            f"| {s.command_name} | {s.cla} | {s.p1_class} | {s.p2_class} | "
            f"{s.tag or '-'} | {s.length_class} | {s.body_class} |"
        )
    lines.append("")

    lines.append("## Output alphabet")
    lines.append("")
    lines.append("| sw_class | response_shape | semantic_label |")
    lines.append("|---|---|---|")
    for _, o in sorted(
        io.output_alphabet.items(), key=lambda kv: (kv[1].sw_class, kv[0])
    ):
        lines.append(f"| {o.sw_class} | `{o.response_shape}` | {o.semantic_label} |")
    lines.append("")

    card_nd = io.card_nondeterministic()
    if card_nd:
        lines.append("## Card-nondeterministic input symbols")
        lines.append("")
        lines.append(
            "These input symbols map to more than one *responded* output symbol "
            "(distinct status word or response shape, transport failures "
            "excluded). Each is a candidate for state-dependence."
        )
        lines.append("")
        for obs in sorted(card_nd, key=lambda o: o.input_symbol.command_name):
            lines.append(f"- {_fmt_input(obs.input_symbol)}")
            for okey, cnt in obs.outputs.most_common():
                lines.append(f"  - -> `{okey}` (x{cnt})")
        lines.append("")

    transport_split = [
        o for o in io.nondeterministic() if not o.card_nondeterministic
    ]
    if transport_split:
        lines.append("## Transport-split input symbols")
        lines.append("")
        lines.append(
            f"{len(transport_split)} input symbols vary only between a real "
            "status word and a host-side transport failure. These come from the "
            "broken deep-173547 live run (21079 transport errors) and are not "
            "card state-dependence. Listed for completeness, not flagged."
        )
        lines.append("")

    lines.append("## Observed mapping (grouped by command)")
    lines.append("")
    by_command: dict[str, list[Observation]] = {}
    for obs in io.observations.values():
        by_command.setdefault(obs.input_symbol.command_name, []).append(obs)
    for command in sorted(by_command):
        lines.append(f"### {command}")
        lines.append("")
        for obs in sorted(by_command[command], key=lambda o: o.input_symbol.key()):
            if obs.card_nondeterministic:
                flag = " **[card-nondeterministic]**"
            elif obs.nondeterministic:
                flag = " *[transport-split]*"
            else:
                flag = ""
            lines.append(f"- {_fmt_input(obs.input_symbol)}{flag}")
            for okey, cnt in obs.outputs.most_common():
                lines.append(f"  - -> `{okey}` (x{cnt})")
        lines.append("")

    return "\n".join(lines) + "\n"


def write_outputs(io: IOMap, *, md_path: Path, json_path: Path) -> None:
    """Write the Markdown and JSON artefacts."""
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown(io))
    json_path.write_text(json.dumps(to_json(io), indent=2, sort_keys=True) + "\n")
