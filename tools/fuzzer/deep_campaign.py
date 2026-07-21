"""Deep read-only evolutionary campaign over the allowlisted command surface.

Ties the pieces together:

- ``dictionary.py`` supplies domain tokens and framing edge cases.
- ``engine.FuzzEngine`` is the sole chokepoint; every candidate goes through
  ``safety.guard_send`` inside it. No transport path bypasses that.
- ``novelty.py`` dedups by behaviour signature and flags unexpected behaviour.
- ``reporting.py`` writes only the unique / unexpected rows plus a summary.

The loop is evolutionary in the ``harness-writing`` sense: inputs that produce a
new signature or a flagged behaviour are mutated further; boring inputs are
dropped. Coverage is a response-diversity proxy (``coverage-analysis``): a black
box SE exposes no real coverage.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from dictionary import (
    STORE_DATA_PREFIX,
    FuzzingDictionary,
    ber_length_edge_cases,
    encode_lc,
    malformed_framing,
)
from engine import FuzzEngine
from novelty import NoveltyEngine, ProbeResult, SafetyViolation
from reporting import BehaviourRecord, UniqueBehaviourReporter
from safety import ALLOWLIST_INS, ALLOWLIST_TAGS

log = logging.getLogger("fuzzer.deep")

# How many times to re-send a sampled interesting input to test determinism.
_REPEAT_N = 3
# Re-send determinism check on every Nth interesting input (bounds live traffic).
_REPEAT_EVERY = 5


@dataclass(frozen=True)
class Candidate:
    """One APDU to consider, with the metadata novelty/reporting need."""

    apdu_hex: str
    command: str
    tag: str | None
    malformed: bool


def _encode_tag(tag: int) -> bytes:
    if tag <= 0xFF:
        return bytes((tag,))
    return bytes(((tag >> 8) & 0xFF, tag & 0xFF))


def _store_data(tag: int, value: bytes, *, lc_form: str = "short", inner_len: bytes | None = None) -> str:
    tag_bytes = _encode_tag(tag)
    length = inner_len if inner_len is not None else bytes((len(value),))
    tlv = tag_bytes + length + value
    lc = encode_lc(len(tlv), form=lc_form)
    return (STORE_DATA_PREFIX + lc + tlv).hex().upper()


def _iso_read(ins: int, p1: int, p2: int, body: bytes = b"", le: int | None = None) -> str:
    apdu = bytes((0x00, ins, p1, p2))
    if body:
        apdu += bytes((len(body) & 0xFF,)) + body
    elif le is not None:
        apdu += bytes((le & 0xFF,))
    return apdu.hex().upper()


class DeepCampaign:
    """Drive the evolutionary read-only loop and log unique/unexpected behaviour."""

    def __init__(
        self,
        engine: FuzzEngine,
        dictionary: FuzzingDictionary,
        novelty: NoveltyEngine,
        reporter: UniqueBehaviourReporter,
        *,
        mode: str = "deep",
        phase: str = "dry",
        wall: int = 300,
        send_cap: int | None = None,
    ) -> None:
        self._engine = engine
        self._dict = dictionary
        self._novelty = novelty
        self._reporter = reporter
        self._mode = mode
        self._phase = phase
        self._wall = wall
        self._send_cap = send_cap
        self._interesting_seen = 0

    def _seed_candidates(self) -> list[Candidate]:
        candidates: list[Candidate] = []

        for tag in sorted(ALLOWLIST_TAGS):
            tag_str = f"{tag:04X}"
            for body in self._dict.bodies_for_tag(_encode_tag(tag)):
                candidates.append(
                    Candidate(_store_data(tag, body), tag_str, tag_str, malformed=False)
                )
                # Long-form Lc where a short one would do: framing barrier.
                candidates.append(
                    Candidate(
                        _store_data(tag, body, lc_form="long2"),
                        tag_str,
                        tag_str,
                        malformed=True,
                    )
                )
            # BER inner-length edge cases against a small body.
            for edge in ber_length_edge_cases(1):
                candidates.append(
                    Candidate(
                        _store_data(tag, b"\x5A", inner_len=edge.value),
                        tag_str,
                        tag_str,
                        malformed=True,
                    )
                )
            # Deliberately inconsistent framing.
            for entry in malformed_framing(STORE_DATA_PREFIX, _encode_tag(tag), b"\x5A"):
                candidates.append(
                    Candidate(entry.value.hex().upper(), tag_str, tag_str, malformed=True)
                )

        for ins in sorted(ALLOWLIST_INS):
            cmd = f"INS_{ins:02X}"
            for p1 in self._dict.p1_sweep:
                for p2 in self._dict.p2_sweep:
                    candidates.append(
                        Candidate(_iso_read(ins, p1, p2, le=0x00), cmd, None, malformed=False)
                    )
            # A few bodies for SELECT-style reads (AID / data-object references).
            for value in self._dict.values:
                candidates.append(
                    Candidate(
                        _iso_read(ins, 0x04, 0x00, body=value.value),
                        cmd,
                        None,
                        malformed=False,
                    )
                )

        return candidates

    def _mutate(self, candidate: Candidate) -> list[Candidate]:
        """Produce a few mutants of an interesting store-data candidate."""
        if candidate.tag is None:
            return []
        try:
            base = bytes.fromhex(candidate.apdu_hex)
        except ValueError:
            return []
        if len(base) < 6:
            return []
        tag = int(candidate.tag, 16)
        mutants: list[Candidate] = []
        for b in self._dict.value_bytes:
            mutants.append(
                Candidate(_store_data(tag, bytes((b, b, b))), candidate.command, candidate.tag, malformed=False)
            )
        for edge in ber_length_edge_cases(3):
            mutants.append(
                Candidate(
                    _store_data(tag, b"\x5A\x5A\x5A", inner_len=edge.value),
                    candidate.command,
                    candidate.tag,
                    malformed=True,
                )
            )
        return mutants

    def _resend_samples(self, apdu_hex: str) -> list[tuple[str | None, str | None]]:
        samples: list[tuple[str | None, str | None]] = []
        for _ in range(_REPEAT_N):
            if self._send_cap is not None and self._engine.sent >= self._send_cap:
                break
            outcome = self._engine.consider(apdu_hex)
            samples.append((outcome.sw, outcome.resp_hex))
        return samples

    def _handle(self, candidate: Candidate) -> None:
        outcome = self._engine.consider(candidate.apdu_hex)

        sw = outcome.sw
        resp = outcome.resp_hex
        # Strip a trailing SW the transport may have appended to the response.
        if outcome.sent and resp and sw and resp.upper().endswith(sw.upper()):
            resp = resp[: -len(sw)] or None

        # A transport error surfaces as outcome.error on an ALLOWED candidate
        # that tried to send but the CLI failed; a SafetyError also sets error
        # but re-classifies as BLOCKED, so gate on ALLOWED.
        transport_error = (
            outcome.error if outcome.error and outcome.classification.value == "ALLOWED" else None
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

        repeat_consistency = "not_tested"
        novelty = list(verdict.novelty)
        severity = verdict.severity

        if verdict.interesting and outcome.sent and self._phase == "live":
            self._interesting_seen += 1
            if self._interesting_seen % _REPEAT_EVERY == 0:
                samples = [(sw, resp), *self._resend_samples(candidate.apdu_hex)]
                if self._novelty.check_repeats(samples):
                    from novelty import NOVELTY_NONDETERMINISTIC, SEVERITY_WARNING

                    novelty.append(NOVELTY_NONDETERMINISTIC)
                    severity = SEVERITY_WARNING
                    repeat_consistency = "inconsistent"
                else:
                    repeat_consistency = "consistent"

        record = BehaviourRecord(
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
            novelty=novelty,
            repeat_consistency=repeat_consistency,
            severity=severity,
        )
        self._reporter.report(record)

        if verdict.interesting:
            for mutant in self._mutate(candidate):
                self._queue.append(mutant)

    def run(self) -> dict[str, object]:
        """Run the campaign until the queue drains or the wall/cap is hit."""
        deadline = time.monotonic() + self._wall
        self._queue: deque[Candidate] = deque(self._seed_candidates())
        log.info("deep campaign seeded with %d candidates", len(self._queue))

        while self._queue:
            if time.monotonic() > deadline:
                log.info("deep campaign hit wall of %ds", self._wall)
                break
            if self._send_cap is not None and self._engine.sent >= self._send_cap:
                log.info("deep campaign hit send-cap of %d", self._send_cap)
                # Keep classifying without sending: flip live off on the engine.
                self._engine.live = False
            candidate = self._queue.popleft()
            try:
                self._handle(candidate)
            except SafetyViolation as exc:
                # CRITICAL: a blocklisted APDU reached the transport. Abort.
                record = BehaviourRecord(
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
                self._reporter.report(record)
                log.critical("SAFETY VIOLATION, aborting run: %s", exc)
                break

        return self._reporter.finalize(
            distinct_signatures=self._novelty.distinct_signatures()
        )


def build_and_run(
    *,
    out_path: Path,
    summary_path: Path,
    phase: str,
    engine: FuzzEngine,
    wall: int,
    send_cap: int | None,
) -> dict[str, object]:
    """Assemble the campaign pieces and run one campaign."""
    dictionary = FuzzingDictionary()
    novelty = NoveltyEngine()
    allowlist = [f"{t:04X}" for t in sorted(ALLOWLIST_TAGS)] + [
        f"INS_{i:02X}" for i in sorted(ALLOWLIST_INS)
    ]
    with UniqueBehaviourReporter(
        out_path=out_path,
        summary_path=summary_path,
        mode="deep",
        phase=phase,
        allowlist=allowlist,
    ) as reporter:
        campaign = DeepCampaign(
            engine,
            dictionary,
            novelty,
            reporter,
            phase=phase,
            wall=wall,
            send_cap=send_cap,
        )
        return campaign.run()
