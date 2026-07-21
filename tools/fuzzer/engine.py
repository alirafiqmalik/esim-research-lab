"""Shared driver that routes every candidate APDU through the safety layer.

All three fuzzing modes feed candidates into one :class:`FuzzEngine`. The engine
is the only place that decides whether a candidate reaches the transport, and it
is the place that records the observable signal.

Because the eUICC is a black box behind an opaque APDU pipe, there is no
in-process coverage. The engine records **response / status-word diversity** as a
proxy: each distinct SW (live) or safety classification (dry-run) is a new
observed behaviour class.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from euicc_transport import ApduResult, EuiccTransport, TransportError
from safety import Classification, SafetyError, guard_send


@dataclass
class CandidateOutcome:
    """What happened to one candidate APDU."""

    apdu_hex: str
    classification: Classification
    reason: str
    sent: bool
    sw: str | None = None
    resp_hex: str | None = None
    error: str | None = None
    new_signal: bool = False


@dataclass
class FuzzEngine:
    """Route candidates through the safety layer and record diversity.

    In dry-run (``live=False``) nothing is sent; the transport is never touched.
    In live mode only allowlisted candidates reach the transport.
    """

    live: bool = False
    allow_destructive: bool = False
    transport: EuiccTransport | None = None

    considered: int = 0
    sent: int = 0
    seen_sw: set[str] = field(default_factory=set)
    seen_classes: set[str] = field(default_factory=set)
    outcomes: list[CandidateOutcome] = field(default_factory=list)

    def consider(self, apdu_hex: str) -> CandidateOutcome:
        """Evaluate one candidate. Send it only if live and allowlisted."""
        self.considered += 1

        try:
            verdict = guard_send(
                apdu_hex, live=self.live, allow_destructive=self.allow_destructive
            )
        except SafetyError as exc:
            outcome = CandidateOutcome(
                apdu_hex=apdu_hex,
                classification=Classification.BLOCKED,
                reason=str(exc),
                sent=False,
                error=str(exc),
            )
            self._record(outcome)
            return outcome

        if not self.live or verdict.classification is not Classification.ALLOWED:
            outcome = CandidateOutcome(
                apdu_hex=apdu_hex,
                classification=verdict.classification,
                reason=verdict.reason,
                sent=False,
            )
            self._record(outcome)
            return outcome

        if self.transport is None:
            raise RuntimeError("live mode requires a transport, none was provided")

        try:
            result: ApduResult = self.transport.send(apdu_hex)
        except TransportError as exc:
            outcome = CandidateOutcome(
                apdu_hex=apdu_hex,
                classification=verdict.classification,
                reason=verdict.reason,
                sent=False,
                error=str(exc),
            )
            self._record(outcome)
            return outcome

        self.sent += 1
        outcome = CandidateOutcome(
            apdu_hex=apdu_hex,
            classification=verdict.classification,
            reason=verdict.reason,
            sent=True,
            sw=result.sw,
            resp_hex=result.resp_hex,
        )
        self._record(outcome)
        return outcome

    def _record(self, outcome: CandidateOutcome) -> None:
        key = outcome.sw if outcome.sw is not None else outcome.classification.value
        outcome.new_signal = key not in (self.seen_sw | self.seen_classes)
        self.outcomes.append(outcome)
        self.seen_classes.add(outcome.classification.value)
        if outcome.sw is not None:
            self.seen_sw.add(outcome.sw)

    def summary(self) -> dict[str, int]:
        """Compact diversity summary for logging."""
        return {
            "considered": self.considered,
            "sent": self.sent,
            "distinct_sw": len(self.seen_sw),
            "distinct_classes": len(self.seen_classes),
        }
