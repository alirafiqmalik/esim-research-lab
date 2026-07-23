"""Unit tests for the stateful / sequence fuzzer.

These never touch a device. ``subprocess.run`` is mocked wherever the transport
would shell out, mirroring the repo rule that tests mock subprocess.run and
never hit real ADB.

The gate-hardening tests are the deliverable: they prove no destructive APDU can
be placed in a sequence in ANY position and reach the transport.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from seq_safety import (
    SequenceSafetyError,
    classify_sequence,
    guard_sequence,
)
from seq_transport import SeqStepResult, SeqTransport, SeqTransportError
from stateful_fuzz import (
    LABEL_PERSISTENT,
    LABEL_STATE_DEPENDENT,
    LABEL_STATELESS,
    SEED_APDUS,
    CardState,
    INITIAL_STATE,
    StatefulCampaign,
    build_differential_probes,
    classify_state_dependence,
    generate_sequences,
    next_state,
    prefix_signature,
)

# --------------------------------------------------------------------------- #
# Read-only allowlisted samples and destructive samples.
# --------------------------------------------------------------------------- #

READ_GET_EID = "81E2910006BF3E035C015A"
READ_SELECT = "00A4040010A0000005591010FFFFFFFF8900000100"
READ_GET_RESPONSE = "00C0000000"

# Destructive APDUs that must NEVER reach the transport.
DESTRUCTIVE_MEMORY_RESET = "81E2910006BF3403A00000"  # BF34 eUICCMemoryReset (STORE DATA)
DESTRUCTIVE_DELETE = "80E400000A4F08A0000005591010FF"  # 80E4.. GP DELETE
DESTRUCTIVE_PUT_DATA = "80DA00A00201"  # 80DA.. PUT DATA
DESTRUCTIVE_DISABLE = "81E2910006BF3203A00000"  # BF32 DisableProfile


# --------------------------------------------------------------------------- #
# guard_sequence: the single chokepoint.
# --------------------------------------------------------------------------- #


def test_guard_accepts_all_read_sequence_with_reset() -> None:
    seq = [READ_GET_EID, "RESET", READ_SELECT, READ_GET_RESPONSE]
    verdict = guard_sequence(seq)
    assert verdict.allowed is True
    # RESET carries a None verdict slot; the three reads each classify ALLOWED.
    assert verdict.element_verdicts[1] is None
    assert all(
        v is None or v.classification.value == "ALLOWED"
        for v in verdict.element_verdicts
    )


@pytest.mark.parametrize("bad", [
    DESTRUCTIVE_MEMORY_RESET,
    DESTRUCTIVE_DELETE,
    DESTRUCTIVE_PUT_DATA,
    DESTRUCTIVE_DISABLE,
])
@pytest.mark.parametrize("position", ["first", "middle", "last"])
def test_guard_rejects_destructive_in_any_position(bad: str, position: str) -> None:
    reads = [READ_GET_EID, READ_SELECT, READ_GET_RESPONSE]
    if position == "first":
        seq = [bad, *reads]
    elif position == "middle":
        seq = [reads[0], "RESET", bad, reads[1]]
    else:
        seq = [*reads, bad]

    with pytest.raises(SequenceSafetyError):
        guard_sequence(seq)

    # Non-raising classifier agrees: the sequence is not allowed.
    assert classify_sequence(seq).allowed is False


def test_guard_rejects_unknown_apdu() -> None:
    # A non-read INS not on any list is UNKNOWN, which rejects the sequence.
    unknown = "00FF000000"
    with pytest.raises(SequenceSafetyError):
        guard_sequence([READ_GET_EID, unknown])


def test_guard_rejects_malformed_hex_element() -> None:
    with pytest.raises(SequenceSafetyError):
        guard_sequence([READ_GET_EID, "ZZZZ"])


def test_guard_rejects_empty_sequence() -> None:
    with pytest.raises(SequenceSafetyError):
        guard_sequence([])


def test_classify_sequence_points_at_first_offender() -> None:
    seq = [READ_GET_EID, DESTRUCTIVE_MEMORY_RESET, DESTRUCTIVE_DELETE]
    verdict = classify_sequence(seq)
    assert verdict.allowed is False
    assert verdict.rejected_index == 1
    assert verdict.rejected_verdict is not None
    assert verdict.rejected_verdict.classification.value == "BLOCKED"


# --------------------------------------------------------------------------- #
# Destructive APDUs never reach the transport, even via the campaign.
# --------------------------------------------------------------------------- #


def test_campaign_send_guards_before_transport() -> None:
    # A campaign _send of a destructive sequence must raise at the guard and
    # never call subprocess.run.
    transport = SeqTransport(repo_root=Path("/repo"), python_executable="python3")
    campaign = StatefulCampaign(transport=transport)
    with patch("seq_transport.subprocess.run") as run:
        with pytest.raises(SequenceSafetyError):
            campaign._send([READ_GET_EID, DESTRUCTIVE_MEMORY_RESET])
    run.assert_not_called()


def test_every_generated_element_is_allowed() -> None:
    # Fuzz the generator across seeds: every element of every generated
    # sequence must classify ALLOWED (RESET excluded).
    for seed in range(25):
        for seq in generate_sequences(30, seed=seed):
            assert classify_sequence(seq).allowed is True


def test_every_differential_sequence_is_allowed() -> None:
    for probe in build_differential_probes():
        for seq in (probe.seq_base, probe.seq_primed, probe.seq_reset):
            assert classify_sequence(list(seq)).allowed is True


# --------------------------------------------------------------------------- #
# Differential state-dependence logic.
# --------------------------------------------------------------------------- #


def test_differential_labels_state_dependent() -> None:
    # B differs when primed by A, and RESET removes the difference.
    label = classify_state_dependence(
        base_key="OK|shapeX|eid",
        primed_key="OK|shapeY|eid",  # different when primed
        reset_key="OK|shapeX|eid",  # RESET restores base
    )
    assert label == LABEL_STATE_DEPENDENT


def test_differential_labels_stateless() -> None:
    # B is identical regardless of the preceding A.
    label = classify_state_dependence(
        base_key="OK|shapeX|eid",
        primed_key="OK|shapeX|eid",
        reset_key="OK|shapeX|eid",
    )
    assert label == LABEL_STATELESS


def test_differential_labels_persistent_when_reset_does_not_restore() -> None:
    label = classify_state_dependence(
        base_key="OK|shapeX|eid",
        primed_key="OK|shapeY|eid",
        reset_key="OK|shapeZ|eid",  # RESET did not restore base
    )
    assert label == LABEL_PERSISTENT


# --------------------------------------------------------------------------- #
# SeqTransport parsing (subprocess.run mocked).
# --------------------------------------------------------------------------- #


def _proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _transport() -> SeqTransport:
    return SeqTransport(repo_root=Path("/repo"), python_executable="python3")


def test_send_sequence_parses_results_array() -> None:
    payload = {
        "op": "seq", "backend": "lpac", "results": [
            {"apdu": READ_GET_EID, "resp": "BF3E125A10...9000", "ok": True},
            {"apdu": "RESET", "resp": "", "ok": True, "reset": True},
            {"apdu": READ_SELECT, "resp": "6F1A...9000", "ok": True},
        ],
    }
    with patch("seq_transport.subprocess.run",
               return_value=_proc(stdout=json.dumps(payload))) as run:
        results = _transport().send_sequence([READ_GET_EID, "RESET", READ_SELECT])

    assert [type(r) for r in results] == [SeqStepResult] * 3
    assert results[0].sw == "9000"
    assert results[0].is_reset is False
    # RESET token passes through untouched and is flagged as a reset step.
    assert results[1].apdu == "RESET"
    assert results[1].is_reset is True
    assert results[1].sw == ""

    cmd = run.call_args.args[0]
    assert cmd == ["python3", "-m", "esim.cli", "euicc", "seq",
                   READ_GET_EID, "RESET", READ_SELECT]
    assert run.call_args.kwargs["cwd"] == Path("/repo")
    assert run.call_args.kwargs["capture_output"] is True
    assert run.call_args.kwargs["text"] is True


def test_send_sequence_reset_token_normalized_but_preserved() -> None:
    payload = {"results": [{"apdu": "RESET", "resp": "", "ok": True, "reset": True}]}
    with patch("seq_transport.subprocess.run",
               return_value=_proc(stdout=json.dumps(payload))) as run:
        _transport().send_sequence(["  reset  "])
    # Lower-case, padded RESET is normalized to the canonical token on the wire.
    assert run.call_args.args[0][-1] == "RESET"


def test_send_sequence_nonzero_exit_raises() -> None:
    with patch("seq_transport.subprocess.run",
               return_value=_proc(returncode=1, stderr="no device")):
        with pytest.raises(SeqTransportError, match="exited 1"):
            _transport().send_sequence([READ_GET_EID])


def test_send_sequence_missing_results_raises() -> None:
    with patch("seq_transport.subprocess.run",
               return_value=_proc(stdout=json.dumps({"op": "seq"}))):
        with pytest.raises(SeqTransportError, match="missing 'results'"):
            _transport().send_sequence([READ_GET_EID])


def test_send_sequence_cli_error_object_raises() -> None:
    with patch("seq_transport.subprocess.run",
               return_value=_proc(stdout=json.dumps({"op": "seq", "error": "boom"}))):
        with pytest.raises(SeqTransportError, match="CLI reported error"):
            _transport().send_sequence([READ_GET_EID])


def test_send_sequence_empty_raises_without_subprocess() -> None:
    with patch("seq_transport.subprocess.run") as run:
        with pytest.raises(SeqTransportError, match="empty sequence"):
            _transport().send_sequence([])
    run.assert_not_called()


# --------------------------------------------------------------------------- #
# Mealy state inference (pure).
# --------------------------------------------------------------------------- #


def _step(apdu: str, resp: str, sw: str, ok: bool = True,
          reset: bool = False) -> SeqStepResult:
    return SeqStepResult(apdu=apdu, resp_hex=resp, sw=sw, ok=ok, reset=reset, raw={})


def test_next_state_select_sets_aid() -> None:
    step = _step(READ_SELECT, "6F1A9000", "9000")
    state = next_state(INITIAL_STATE, READ_SELECT, step)
    assert state.selected_aid == "A0000005591010FFFFFFFF8900000100"
    assert state.pending_response is False


def test_next_state_61xx_sets_pending_and_reset_clears() -> None:
    primed = next_state(INITIAL_STATE, READ_GET_EID,
                        _step(READ_GET_EID, "", "6110"))
    assert primed.pending_response is True
    cleared = next_state(primed, "RESET", None)
    assert cleared == INITIAL_STATE


def test_next_state_get_response_drains_pending() -> None:
    primed = CardState(selected_aid="AA", pending_response=True)
    drained = next_state(primed, READ_GET_RESPONSE,
                        _step(READ_GET_RESPONSE, "DEADBEEF9000", "9000"))
    assert drained.pending_response is False
    assert drained.selected_aid == "AA"


# --------------------------------------------------------------------------- #
# Prefix signature + campaign fold (live path via mocked transport).
# --------------------------------------------------------------------------- #


def test_prefix_signature_orders_symbols_and_marks_reset() -> None:
    sig = prefix_signature([READ_GET_EID, "RESET"])
    assert "RESET" in sig
    assert ";" in sig


def test_campaign_fold_flags_history_dependent_input() -> None:
    # Same input symbol (GET DATA) yields two different outputs under different
    # prefixes -> flagged history-dependent, and both context transitions kept.
    campaign = StatefulCampaign(transport=None)
    get_data = SEED_APDUS["GET_DATA_00"]
    select = SEED_APDUS["SELECT_isdr"]

    seq_a = [get_data]
    campaign._fold(seq_a, [_step(get_data, "AA9000", "9000")])
    seq_b = [select, get_data]
    campaign._fold(seq_b, [
        _step(select, "6F109000", "9000"),
        _step(get_data, "BB6A88", "6A88"),  # different output after SELECT
    ])

    from io_symbols import abstract_input
    ikey = abstract_input(get_data).key()
    assert campaign.mealy.input_is_history_dependent(ikey) is True
    assert ikey in campaign.prefix_recorder.state_dependent_inputs()


def test_campaign_run_sequences_guards_and_sends() -> None:
    # End-to-end live path with a mocked transport: an all-read sequence is
    # guarded and sent; results fold into the models.
    payload = {"results": [
        {"apdu": SEED_APDUS["GetEID"], "resp": "BF3E109000", "ok": True},
        {"apdu": SEED_APDUS["SELECT_isdr"], "resp": "6F109000", "ok": True},
    ]}
    transport = SeqTransport(repo_root=Path("/repo"), python_executable="python3")
    campaign = StatefulCampaign(transport=transport)
    with patch("seq_transport.subprocess.run",
               return_value=_proc(stdout=json.dumps(payload))):
        campaign.run_sequences([[SEED_APDUS["GetEID"], SEED_APDUS["SELECT_isdr"]]])
    assert campaign.sequences_sent == 1
    assert campaign.steps_observed == 2
