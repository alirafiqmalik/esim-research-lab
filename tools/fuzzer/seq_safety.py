"""Sequence-level safety chokepoint for the stateful fuzzer.

The single-APDU gate lives in ``safety.classify`` / ``safety.guard_send``. A
same-channel sequence is only as safe as its worst element, so this module
wraps that gate: it classifies EVERY non-RESET element and rejects the WHOLE
sequence if any element is not ALLOWED (read-only allowlist).

If one element is BLOCKED or UNKNOWN, no element of the sequence is ever sent.
This is the single point through which every candidate sequence must pass before
it reaches :class:`seq_transport.SeqTransport`.

Nothing here sends anything. It classifies and gates.
"""

from __future__ import annotations

from dataclasses import dataclass

from safety import Classification, SafetyVerdict, classify

RESET_TOKEN = "RESET"


class SequenceSafetyError(Exception):
    """Raised when a sequence contains any element that is not ALLOWED."""


@dataclass(frozen=True)
class SequenceVerdict:
    """Per-element verdicts for one candidate sequence.

    ``allowed`` is True only when every non-RESET element classified ALLOWED.
    ``rejected_index`` / ``rejected_verdict`` point at the first offending
    element when ``allowed`` is False.
    """

    allowed: bool
    element_verdicts: tuple[SafetyVerdict | None, ...]
    rejected_index: int | None = None
    rejected_verdict: SafetyVerdict | None = None


def is_reset(token: str) -> bool:
    """True if a sequence token is the non-destructive RESET channel reset."""
    return token.strip().upper() == RESET_TOKEN


def classify_sequence(seq: list[str]) -> SequenceVerdict:
    """Classify every element of a sequence without raising.

    RESET tokens are non-destructive channel resets and carry a ``None`` verdict
    slot. A malformed hex element (a ``ValueError`` from ``classify``) is treated
    as not-ALLOWED and rejects the sequence, so a bad stub can never slip through.
    """
    verdicts: list[SafetyVerdict | None] = []
    rejected_index: int | None = None
    rejected_verdict: SafetyVerdict | None = None
    allowed = True

    for index, token in enumerate(seq):
        if is_reset(token):
            verdicts.append(None)
            continue
        try:
            verdict = classify(token)
        except ValueError as exc:
            verdict = SafetyVerdict(
                classification=Classification.UNKNOWN,
                reason=f"unparseable APDU: {exc}",
                apdu_hex=token,
            )
        verdicts.append(verdict)
        if allowed and verdict.classification is not Classification.ALLOWED:
            allowed = False
            rejected_index = index
            rejected_verdict = verdict

    return SequenceVerdict(
        allowed=allowed,
        element_verdicts=tuple(verdicts),
        rejected_index=rejected_index,
        rejected_verdict=rejected_verdict,
    )


def guard_sequence(seq: list[str]) -> SequenceVerdict:
    """Gate a candidate sequence. Raises unless every element is ALLOWED.

    This is the chokepoint the fuzzer calls immediately before a live send. A
    single BLOCKED or UNKNOWN element rejects the entire sequence, so a
    destructive APDU in ANY position stops the whole sequence from being sent.
    """
    if not seq:
        raise SequenceSafetyError("refusing to send an empty sequence")

    verdict = classify_sequence(seq)
    if verdict.allowed:
        return verdict

    bad = verdict.rejected_verdict
    assert bad is not None  # not-allowed implies a rejected element
    raise SequenceSafetyError(
        f"refusing sequence: element {verdict.rejected_index} "
        f"({bad.apdu_hex}) is {bad.classification.value}: {bad.reason}. "
        f"The whole sequence is rejected and nothing is sent."
    )
