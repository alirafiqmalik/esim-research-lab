"""Stateful / sequence fuzzer for the eUICC, toward a Mealy-machine model.

The single-APDU campaigns treat each command in isolation. This campaign sends
BOUNDED sequences of READ-ONLY allowlisted commands on ONE persistent ISD-R
channel, so transient card state carries across the steps, and asks a different
question: does a command's output depend on what preceded it?

Three state-exploration strategies, all over allowlisted reads + non-destructive
RESET:

1. Differential state-dependence. For a target read B and a priming read A,
   compare B's output symbol across ``[B]``, ``[A, B]`` and ``[A, RESET, B]``. If
   B changes when A precedes it, and RESET removes that change, A set transient
   state that B observed: A -> B is a state transition.

2. Sequence fuzzing. Generate bounded sequences (length 2-5) of read-only input
   symbols with occasional RESET, and record each step's output symbol IN
   CONTEXT (its preceding-prefix signature). Dedup with the response fingerprint
   so only prefix-dependent / novel transitions are kept.

3. Light Mealy inference. Model state as ``(selected AID, pending-response
   flag)`` inferred from the step responses, and emit a transition table
   ``state --input-symbol--> (output-symbol, next-state)``, flagging transitions
   whose output depends on history (true state) versus history-independent.

SAFETY: every element of every generated sequence is classified through
``seq_safety.guard_sequence`` before a send. A BLOCKED/UNKNOWN element in ANY
position rejects the whole sequence. The seed pool is read-only allowlisted
APDUs plus the RESET token; the generator is structurally incapable of emitting
a destructive APDU. Profiles are never touched.

Coverage note (testing-handbook coverage-analysis): a black-box secure element
gives no in-process coverage, so the interestingness proxy here is the response
fingerprint of a step output IN CONTEXT of its prefix. A new (prefix -> output)
mapping is the "new edge"; a stable (prefix-independent) mapping is not.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from io_symbols import (
    InputSymbol,
    OutputSymbol,
    abstract_input,
    abstract_output,
)
from seq_safety import RESET_TOKEN, guard_sequence, is_reset
from seq_transport import SeqStepResult, SeqTransport

# --------------------------------------------------------------------------- #
# Read-only seed pool. Every entry MUST classify ALLOWED. The generator draws
# only from here plus the RESET token, so no destructive APDU can be emitted.
# --------------------------------------------------------------------------- #

# Concrete example APDUs pulled from the observed I/O map. Each is a read.
SEED_APDUS: dict[str, str] = {
    # ES10x store-data reads (allowlisted BER-TLV tags).
    "GetEID": "81E2910006BF3E035C015A",
    "GetConfiguredAddresses": "81E2910004BF3C0100",
    "ListNotification": "81E2910013BF281089033023427100000000027143866816",
    "RetrieveNotificationsList": "81E2910004BF2B0100",
    "GetEUICCInfo1": "81E2910003BF2000",
    "GetEUICCInfo2": "81E2910003BF2200",
    "GetEUICCChallenge": "81E2910003BF2E00",
    "GetProfilesInfo": "81E2910006BF2D035C015F",
    "GetRAT": "81E2910003BF4300",
    # ISO / GP reads.
    "SELECT_isdr": "00A4040010A0000005591010FFFFFFFF8900000100",
    "SELECT_iccid": "00A404001089033023427100000000027143866816",
    # SELECTs to a DIFFERENT valid applet — the strong state-changer: after this
    # the channel points at ECASD/GP-ISD, so a following ISD-R read (e.g. GetEID)
    # is refused until a RESET reopens the ISD-R channel.
    "SELECT_ecasd": "00A4040010A0000005591010FFFFFFFF8900000200",
    "SELECT_gpisd": "00A4040008A000000151000000",
    "GET_RESPONSE": "00C0000000",
    "GET_DATA_00": "00CA000000",
    "GET_DATA_72": "00CA007200",
    "GET_DATA_EA": "00CA00EA00",
    "GET_STATUS": "80F2400000",
}

# The known / flagged state-bearing priming commands. SELECT changes the current
# applet; GET RESPONSE drains buffered data; ListNotification and the flagged
# nondeterministic GET DATA / RSP reads were card-nondeterministic in the
# single-command map. These are tried as the priming A in the differential probe.
STATE_BEARING: tuple[str, ...] = (
    "SELECT_ecasd",
    "SELECT_gpisd",
    "SELECT_isdr",
    "SELECT_iccid",
    "GET_RESPONSE",
    "ListNotification",
    "GetConfiguredAddresses",
    "GetEID",
    "RetrieveNotificationsList",
    "GET_DATA_00",
    "GET_DATA_72",
    "GET_DATA_EA",
)


# --------------------------------------------------------------------------- #
# Differential state-dependence.
# --------------------------------------------------------------------------- #

# Labels for the differential verdict.
LABEL_STATELESS = "stateless"
LABEL_STATE_DEPENDENT = "state_dependent"
LABEL_PERSISTENT = "state_dependent_persistent"


def classify_state_dependence(base_key: str, primed_key: str, reset_key: str) -> str:
    """Label a differential triple of output-symbol keys.

    - ``base_key``: B's output alone, ``[B]``.
    - ``primed_key``: B's output primed by A, ``[A, B]``.
    - ``reset_key``: B's output after a channel reset, ``[A, RESET, B]``.

    ``stateless`` when priming did not change B. ``state_dependent`` when A
    changed B and RESET removed the change (transient state that A set and RESET
    cleared). ``state_dependent_persistent`` when B still differs after RESET —
    a difference RESET did not clear, so it is not clean transient state.
    """
    if primed_key == base_key:
        return LABEL_STATELESS
    if reset_key == base_key:
        return LABEL_STATE_DEPENDENT
    return LABEL_PERSISTENT


@dataclass(frozen=True)
class DifferentialProbe:
    """One A->B differential probe and its three guarded sequences."""

    a_name: str
    b_name: str
    seq_base: tuple[str, ...]  # [B]
    seq_primed: tuple[str, ...]  # [A, B]
    seq_reset: tuple[str, ...]  # [A, RESET, B]


@dataclass(frozen=True)
class DifferentialResult:
    """Outcome of running one differential probe live."""

    a_name: str
    b_name: str
    base_output: str
    primed_output: str
    reset_output: str
    label: str


def build_differential_probes(
    b_names: list[str] | None = None,
    a_names: list[str] | None = None,
) -> list[DifferentialProbe]:
    """Build every A->B differential probe over the seed pool.

    Each probe's three sequences are guarded ALLOWED here, so a probe that
    somehow referenced a non-read APDU would raise before any run.
    """
    targets = b_names if b_names is not None else list(SEED_APDUS)
    primers = a_names if a_names is not None else list(STATE_BEARING)
    probes: list[DifferentialProbe] = []
    for a_name in primers:
        a = SEED_APDUS[a_name]
        for b_name in targets:
            if b_name == a_name:
                continue
            b = SEED_APDUS[b_name]
            seq_base = [b]
            seq_primed = [a, b]
            seq_reset = [a, RESET_TOKEN, b]
            for seq in (seq_base, seq_primed, seq_reset):
                guard_sequence(seq)
            probes.append(
                DifferentialProbe(
                    a_name=a_name,
                    b_name=b_name,
                    seq_base=tuple(seq_base),
                    seq_primed=tuple(seq_primed),
                    seq_reset=tuple(seq_reset),
                )
            )
    return probes


# --------------------------------------------------------------------------- #
# Bounded random sequence generation.
# --------------------------------------------------------------------------- #


def generate_sequences(
    max_seqs: int,
    *,
    seed: int = 0,
    min_len: int = 2,
    max_len: int = 5,
    reset_prob: float = 0.2,
) -> list[list[str]]:
    """Generate bounded read-only sequences with occasional RESET.

    Every element is drawn from ``SEED_APDUS`` (all allowlisted reads) or is the
    RESET token, and every returned sequence is guarded ALLOWED. Deterministic
    for a given ``seed`` so a campaign reproduces.
    """
    rng = random.Random(seed)
    names = list(SEED_APDUS)
    sequences: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()

    attempts = 0
    attempt_cap = max_seqs * 20 + 50
    while len(sequences) < max_seqs and attempts < attempt_cap:
        attempts += 1
        length = rng.randint(min_len, max_len)
        seq: list[str] = []
        for position in range(length):
            # Never start with RESET; it is a no-op with no prior state to clear.
            if position > 0 and rng.random() < reset_prob:
                seq.append(RESET_TOKEN)
            else:
                seq.append(SEED_APDUS[rng.choice(names)])
        key = tuple(seq)
        if key in seen:
            continue
        seen.add(key)
        guard_sequence(seq)  # chokepoint before this sequence is ever kept
        sequences.append(seq)
    return sequences


# --------------------------------------------------------------------------- #
# Light Mealy inference. State = (selected AID, pending-response flag).
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CardState:
    """Inferred transient card state on the ISD-R channel."""

    selected_aid: str | None
    pending_response: bool

    def key(self) -> str:
        return f"aid={self.selected_aid or '-'}|pending={int(self.pending_response)}"


INITIAL_STATE = CardState(selected_aid=None, pending_response=False)


def _select_aid_from_apdu(apdu_hex: str) -> str | None:
    """Return the AID a SELECT (INS A4) targets, or None if not a SELECT."""
    try:
        apdu = bytes.fromhex(apdu_hex.strip().replace(" ", ""))
    except ValueError:
        return None
    if len(apdu) < 5 or apdu[1] != 0xA4:
        return None
    lc = apdu[4]
    aid = apdu[5 : 5 + lc]
    return aid.hex().upper() if aid else None


def next_state(state: CardState, token: str, step: SeqStepResult | None) -> CardState:
    """Advance the inferred state given a step token and its result.

    RESET returns to the initial state (channel re-selected, transient state
    cleared). A SELECT sets the selected AID. A ``61xx`` status word raises the
    pending-response flag; a GET RESPONSE (INS C0) drains it.
    """
    if is_reset(token):
        return INITIAL_STATE

    selected = state.selected_aid
    pending = state.pending_response

    aid = _select_aid_from_apdu(token)
    if aid is not None:
        selected = aid

    try:
        ins = bytes.fromhex(token.strip().replace(" ", ""))[1]
    except (ValueError, IndexError):
        ins = None
    if ins == 0xC0:
        pending = False

    sw = step.sw.upper() if step is not None and step.sw else ""
    if sw.startswith("61"):
        pending = True
    elif sw and not sw.startswith("61"):
        # A definite terminal status word clears any pending buffer.
        if ins != 0xA4:
            pending = pending and False

    return CardState(selected_aid=selected, pending_response=pending)


@dataclass
class MealyModel:
    """Accumulated Mealy transition table with history-dependence flags."""

    # (state_key, input_key) -> {output_key: count}
    transitions: dict[tuple[str, str], dict[str, int]] = field(default_factory=dict)
    states: dict[str, CardState] = field(default_factory=dict)
    input_alphabet: dict[str, InputSymbol] = field(default_factory=dict)
    output_alphabet: dict[str, OutputSymbol] = field(default_factory=dict)
    # input_key -> set of output_keys seen across ALL contexts (history sensitivity)
    outputs_by_input: dict[str, set[str]] = field(default_factory=dict)

    def observe(
        self,
        state: CardState,
        inp: InputSymbol,
        out: OutputSymbol,
    ) -> None:
        skey, ikey, okey = state.key(), inp.key(), out.key()
        self.states.setdefault(skey, state)
        self.input_alphabet.setdefault(ikey, inp)
        self.output_alphabet.setdefault(okey, out)
        bucket = self.transitions.setdefault((skey, ikey), {})
        bucket[okey] = bucket.get(okey, 0) + 1
        self.outputs_by_input.setdefault(ikey, set()).add(okey)

    def input_is_history_dependent(self, input_key: str) -> bool:
        """True if one input symbol produced >1 distinct output across contexts."""
        return len(self.outputs_by_input.get(input_key, set())) > 1

    def transition_rows(self) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for (skey, ikey), outputs in sorted(self.transitions.items()):
            for okey, count in sorted(outputs.items(), key=lambda kv: -kv[1]):
                rows.append(
                    {
                        "state": skey,
                        "input_symbol": ikey,
                        "output_symbol": okey,
                        "count": count,
                        "history_dependent": self.input_is_history_dependent(ikey),
                    }
                )
        return rows


# --------------------------------------------------------------------------- #
# Prefix-context transition recording (sequence-fuzzing dedup).
# --------------------------------------------------------------------------- #


@dataclass
class ContextTransition:
    """One deduped (prefix -> step output) observation."""

    prefix_signature: str
    input_key: str
    output_key: str
    example_apdu: str


@dataclass
class PrefixRecorder:
    """Record each step's output IN CONTEXT and dedup by (prefix, input, output).

    An input symbol that maps to different outputs under different prefixes is
    state-dependent. Dedup so each distinct (prefix -> output) is kept once.
    """

    seen: set[tuple[str, str, str]] = field(default_factory=set)
    transitions: list[ContextTransition] = field(default_factory=list)
    outputs_by_input: dict[str, set[str]] = field(default_factory=dict)

    def record(
        self,
        prefix_signature: str,
        inp: InputSymbol,
        out: OutputSymbol,
        example_apdu: str,
    ) -> bool:
        """Record one step. Returns True if it was novel (kept)."""
        ikey, okey = inp.key(), out.key()
        self.outputs_by_input.setdefault(ikey, set()).add(okey)
        key = (prefix_signature, ikey, okey)
        if key in self.seen:
            return False
        self.seen.add(key)
        self.transitions.append(
            ContextTransition(
                prefix_signature=prefix_signature,
                input_key=ikey,
                output_key=okey,
                example_apdu=example_apdu,
            )
        )
        return True

    def state_dependent_inputs(self) -> list[str]:
        return [k for k, outs in self.outputs_by_input.items() if len(outs) > 1]


def prefix_signature(tokens: list[str]) -> str:
    """Signature of a prefix: input-symbol keys and RESET markers, in order."""
    parts: list[str] = []
    for token in tokens:
        if is_reset(token):
            parts.append("RESET")
        else:
            try:
                parts.append(abstract_input(token).key())
            except ValueError:
                parts.append(f"raw:{token}")
    return " ; ".join(parts) if parts else "<empty>"


# --------------------------------------------------------------------------- #
# The campaign driver.
# --------------------------------------------------------------------------- #


@dataclass
class StatefulCampaign:
    """Build (always) and optionally run the stateful exploration.

    In dry-run (``transport is None``) it builds and guards every sequence and
    sends nothing. In live mode it sends each guarded sequence and folds the
    step results into the differential verdicts, the prefix recorder, and the
    Mealy model.
    """

    transport: SeqTransport | None = None
    seed: int = 0
    max_seqs: int = 200

    mealy: MealyModel = field(default_factory=MealyModel)
    prefix_recorder: PrefixRecorder = field(default_factory=PrefixRecorder)
    differential_results: list[DifferentialResult] = field(default_factory=list)
    sequences_sent: int = 0
    steps_observed: int = 0

    def build(self) -> tuple[list[DifferentialProbe], list[list[str]]]:
        """Build and guard all candidate sequences without sending anything."""
        probes = build_differential_probes()
        sequences = generate_sequences(self.max_seqs, seed=self.seed)
        return probes, sequences

    def _send(self, seq: list[str]) -> list[SeqStepResult]:
        if self.transport is None:
            raise RuntimeError("no transport: campaign is in dry-run mode")
        guard_sequence(seq)  # last-line chokepoint before the wire
        results = self.transport.send_sequence(seq)
        self.sequences_sent += 1
        return results

    def _output_for(self, apdu_hex: str, step: SeqStepResult) -> OutputSymbol:
        inp = abstract_input(apdu_hex)
        return abstract_output(inp, step.sw, step.resp_hex)

    def run_differential(self, probes: list[DifferentialProbe]) -> None:
        """Run each differential probe live and label it."""
        for probe in probes:
            base = self._send(list(probe.seq_base))
            primed = self._send(list(probe.seq_primed))
            reset = self._send(list(probe.seq_reset))
            base_out = self._output_for(probe.seq_base[-1], base[-1]).key()
            primed_out = self._output_for(probe.seq_primed[-1], primed[-1]).key()
            reset_out = self._output_for(probe.seq_reset[-1], reset[-1]).key()
            self.differential_results.append(
                DifferentialResult(
                    a_name=probe.a_name,
                    b_name=probe.b_name,
                    base_output=base_out,
                    primed_output=primed_out,
                    reset_output=reset_out,
                    label=classify_state_dependence(base_out, primed_out, reset_out),
                )
            )

    def run_sequences(self, sequences: list[list[str]]) -> None:
        """Run each random sequence live, folding results into the models."""
        for seq in sequences:
            results = self._send(seq)
            self._fold(seq, results)

    def _fold(self, seq: list[str], results: list[SeqStepResult]) -> None:
        state = INITIAL_STATE
        for index, token in enumerate(seq):
            step = results[index] if index < len(results) else None
            if is_reset(token):
                state = next_state(state, token, step)
                continue
            if step is None:
                continue
            self.steps_observed += 1
            inp = abstract_input(token)
            out = abstract_output(inp, step.sw, step.resp_hex)
            self.mealy.observe(state, inp, out)
            self.prefix_recorder.record(
                prefix_signature(seq[:index]), inp, out, token.upper()
            )
            state = next_state(state, token, step)
