"""Unit tests for the I/O symbol abstraction. Synthetic traces only, no device.

Asserts:
1. The segmenter labels a known store-data APDU (command name + length class).
2. The status-word -> sw_class map.
3. A one-to-many input symbol is flagged nondeterministic.
4. Round-trip: a concrete APDU's derived output matches the trace row.
"""

from __future__ import annotations

from io_symbols import (
    IOMap,
    abstract_input,
    abstract_output,
    build_map,
    command_name_for_apdu,
    segment_apdu,
    sw_class,
    to_json,
)

# The lead over-declared BF2D APDU from the lenient campaign.
_BF2D_OVERLONG = "81E2910006BF2D82FFFF5A"
# A well-formed GetProfilesInfo with a short-form tag-list body.
_BF2D_SHORT = "81E2910006BF2D035C015A"
# GET DATA for the CPLC data object.
_GETDATA_CPLC = "00CA9F7F00"


def test_segmenter_labels_known_apdu() -> None:
    segs = segment_apdu(_BF2D_OVERLONG)
    by_label = {s.label: s for s in segs}

    # INS segment carries the functional command name.
    assert by_label["INS"].hex == "E2"
    assert by_label["INS"].note == "GetProfilesInfo"
    assert command_name_for_apdu(bytes.fromhex(_BF2D_OVERLONG)) == "GetProfilesInfo"

    # The BER-TLV tag is BF2D and the value's length class is over + long-form.
    assert by_label["tag"].hex == "BF2D"
    value_seg = by_label["value"]
    assert "over" in value_seg.note
    assert "long" in value_seg.note


def test_input_symbol_length_class() -> None:
    over = abstract_input(_BF2D_OVERLONG)
    assert over.command_name == "GetProfilesInfo"
    assert over.tag == "BF2D"
    assert over.length_class == "inner_over_long2"

    short = abstract_input(_BF2D_SHORT)
    assert short.command_name == "GetProfilesInfo"
    assert short.length_class == "inner_short_true"
    assert short.body_class == "taglist"


def test_getdata_carries_do_tag_in_p1p2() -> None:
    inp = abstract_input(_GETDATA_CPLC)
    assert inp.command_name == "GET DATA"
    assert inp.tag == "9F7F"


def test_sw_class_map() -> None:
    assert sw_class("9000") == "OK"
    assert sw_class("6A80") == "WRONG_DATA"
    assert sw_class("6A88") == "REF_DATA_NOT_FOUND"
    assert sw_class("6700") == "WRONG_LEN"
    assert sw_class("6985") == "COND_NOT_SATISFIED"
    assert sw_class("6882") == "CLA_FUNCTION_ERR"  # 68xx family fallback
    assert sw_class(None) == "NO_SW"
    assert sw_class(None, transport_error=True) == "TRANSPORT_ERR"


def test_output_semantic_labels() -> None:
    inp = abstract_input(_BF2D_SHORT)
    ok = abstract_output(inp, "9000", "BF2D8190A0818D")
    assert ok.sw_class == "OK"
    assert ok.semantic_label == "profile_list"

    err = abstract_output(inp, "6A80", None)
    assert err.sw_class == "WRONG_DATA"
    assert err.semantic_label == "wrong_data"


def test_one_to_many_flagged_nondeterministic() -> None:
    # Same abstract input (well-formed BF2D) yields two different outputs.
    rows = [
        {"apdu": _BF2D_SHORT, "sent": True, "sw": "9000", "resp": "BF2D8190A0"},
        {"apdu": _BF2D_SHORT, "sent": True, "sw": "6985", "resp": None},
    ]
    io = build_map_from_rows(rows)
    nd = io.nondeterministic()
    assert len(nd) == 1
    assert nd[0].nondeterministic
    assert len(nd[0].outputs) == 2

    payload = to_json(io)
    ikey = abstract_input(_BF2D_SHORT).key()
    assert payload["mapping"][ikey]["nondeterministic"] is True


def test_deterministic_not_flagged() -> None:
    rows = [
        {"apdu": _BF2D_SHORT, "sent": True, "sw": "9000", "resp": "BF2D8190A0"},
        {"apdu": _BF2D_SHORT, "sent": True, "sw": "9000", "resp": "BF2D8191B1"},
    ]
    io = build_map_from_rows(rows)
    assert io.nondeterministic() == []
    # Two rows, one input, one output symbol, two observations.
    obs = next(iter(io.observations.values()))
    assert obs.total == 2
    assert len(obs.outputs) == 1


def test_transport_split_not_card_nondeterministic() -> None:
    # A real SW plus a transport failure is not card state-dependence.
    rows = [
        {"apdu": _BF2D_SHORT, "sent": True, "sw": "9000", "resp": "BF2D01"},
        {"apdu": _BF2D_SHORT, "sent": False, "sw": None, "resp": None,
         "novelty": ["transport_error"]},
    ]
    io = build_map_from_rows(rows)
    assert len(io.nondeterministic()) == 1  # two distinct outputs
    assert io.card_nondeterministic() == []  # but not card-level


def test_card_nondeterministic_counts_two_real_sw() -> None:
    rows = [
        {"apdu": _BF2D_SHORT, "sent": True, "sw": "9000", "resp": "BF2D01"},
        {"apdu": _BF2D_SHORT, "sent": True, "sw": "6985", "resp": None},
    ]
    io = build_map_from_rows(rows)
    assert len(io.card_nondeterministic()) == 1


def test_dry_run_rows_ignored() -> None:
    rows = [
        {"apdu": _BF2D_SHORT, "sent": False, "sw": None, "resp": None},
    ]
    io = build_map_from_rows(rows)
    assert io.rows_used == 0
    assert io.observations == {}


def test_transport_error_is_an_observation() -> None:
    rows = [
        {"apdu": _BF2D_SHORT, "sent": False, "sw": None, "resp": None,
         "novelty": ["transport_error"]},
    ]
    io = build_map_from_rows(rows)
    assert io.rows_used == 1
    obs = next(iter(io.observations.values()))
    okey = next(iter(obs.outputs))
    assert obs.output_objs[okey].sw_class == "TRANSPORT_ERR"


def test_round_trip_from_trace_row() -> None:
    # A concrete trace row -> input symbol -> looked-up output matches the row.
    row = {"apdu": _GETDATA_CPLC, "sent": True, "sw": "9000",
           "resp": "475001CC007720450100FF4A4162C2E64A79000000000000"}
    io = build_map_from_rows([row])
    inp = abstract_input(row["apdu"])
    obs = io.observations[inp.key()]
    expected = abstract_output(inp, row["sw"], row["resp"])
    assert expected.key() in obs.outputs
    assert expected.semantic_label == "cplc"


def build_map_from_rows(rows: list[dict]) -> IOMap:
    io = IOMap()
    for row in rows:
        io.add_row(row)
    return io


def test_build_map_helper_matches_build_map(tmp_path) -> None:
    import json

    path = tmp_path / "t.jsonl"
    rows = [{"apdu": _BF2D_SHORT, "sent": True, "sw": "9000", "resp": "BF2D01"}]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    io = build_map([path])
    assert io.rows_used == 1
