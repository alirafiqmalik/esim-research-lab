"""Novelty, dedup, and unexpected-behaviour engine for the read-only campaign.

Informed by ``testing-handbook-skills:coverage-analysis`` and ``harness-writing``.
A black-box secure element gives no in-process coverage, so this module builds an
*interestingness* proxy: a behaviour signature that collapses trivially-different
responses and a set of rules that flag genuinely unexpected card behaviour. Only
new signatures and flagged behaviours are worth keeping and mutating.

Nothing here sends anything. It consumes probe results and returns verdicts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from safety import Classification, classify

# Length buckets for the response-structure fingerprint. Two responses whose
# byte lengths fall in the same bucket are treated as the same shape, so that a
# different EID value does not read as a new behaviour.
_LENGTH_BUCKETS: tuple[int, ...] = (0, 1, 2, 4, 8, 16, 32, 64, 128, 256)

# Rare / odd status words that mean "something unusual happened" when a plain
# read was expected to succeed. Patterns, because families like 6Fxx vary in the
# low byte. Anchored, matched against the 4-hex-char SW.
_RARE_SW_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^6F[0-9A-F]{2}$"),  # no precise diagnosis
    re.compile(r"^6581$"),  # memory failure
    re.compile(r"^93[0-9A-F]{2}$"),  # SIM app toolkit busy / proprietary
    re.compile(r"^6A88$"),  # referenced data not found
    re.compile(r"^6884$"),  # command chaining not supported
    re.compile(r"^6D00$"),  # INS not supported (read was expected to work)
)

_SUCCESS_SW = "9000"

# Novelty labels, matching the reporting schema.
NOVELTY_NEW_SIGNATURE = "new_signature"
NOVELTY_NOVEL_SW = "novel_sw"
NOVELTY_SUCCESS_ON_MALFORMED = "success_on_malformed"
NOVELTY_NONDETERMINISTIC = "nondeterministic"
NOVELTY_RARE_SW = "rare_sw"
NOVELTY_STRUCTURAL_ANOMALY = "structural_anomaly"
NOVELTY_TRANSPORT_ERROR = "transport_error"
NOVELTY_SAFETY_VIOLATION = "safety_violation"

SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"


class SafetyViolation(Exception):
    """Raised when a blocklisted APDU is observed as sent. Must never happen."""


@dataclass(frozen=True)
class ProbeResult:
    """One observed card exchange, handed to the novelty engine."""

    apdu_hex: str
    command: str
    classification: str
    malformed: bool
    sent: bool
    sw: str | None = None
    resp_hex: str | None = None
    transport_error: str | None = None


@dataclass(frozen=True)
class BehaviourSignature:
    """(command, SW, response-structure fingerprint). The dedup key."""

    command: str
    sw: str
    fingerprint: str


@dataclass(frozen=True)
class NoveltyVerdict:
    """What the engine concluded about one probe."""

    signature: BehaviourSignature
    fingerprint: str
    novelty: list[str]
    severity: str
    interesting: bool


def _bucket(length: int) -> str:
    chosen = _LENGTH_BUCKETS[0]
    for bound in _LENGTH_BUCKETS:
        if length >= bound:
            chosen = bound
    return f"{chosen}+" if length >= _LENGTH_BUCKETS[-1] else f"{chosen}"


def _read_tag(body: bytes, index: int) -> tuple[int, int]:
    first = body[index]
    if (first & 0x1F) != 0x1F:
        return first, index + 1
    if index + 1 >= len(body):
        return first, index + 1
    return (first << 8) | body[index + 1], index + 2


def response_fingerprint(resp_hex: str | None) -> str:
    """Fingerprint a response by its top-level TLV shape and length buckets.

    Same-shaped responses collapse to one fingerprint regardless of the concrete
    values, so a fuzzer that only changes an EID or ICCID does not manufacture
    endless false novelty. Unparseable responses fingerprint by length bucket
    plus a ``raw`` marker.
    """
    if not resp_hex:
        return "empty"
    try:
        body = bytes.fromhex(resp_hex)
    except ValueError:
        return f"raw:len{_bucket(len(resp_hex) // 2)}"

    parts: list[str] = []
    index = 0
    guard = 0
    while index < len(body) and guard < 8:
        guard += 1
        tag, after_tag = _read_tag(body, index)
        if after_tag >= len(body):
            parts.append(f"{tag:X}:?")
            break
        length = body[after_tag]
        parts.append(f"{tag:X}:L{_bucket(length)}")
        index = after_tag + 1 + length
        if length == 0:
            index = after_tag + 1
        if index <= after_tag:
            break
    shape = ",".join(parts) if parts else "raw"
    return f"{shape}|total{_bucket(len(body))}"


@dataclass
class NoveltyEngine:
    """Track seen signatures and flag unexpected card behaviour."""

    seen_signatures: set[BehaviourSignature] = field(default_factory=set)
    seen_sw_by_command: dict[str, set[str]] = field(default_factory=dict)
    baseline_fp_by_command: dict[str, set[str]] = field(default_factory=dict)
    corpus: list[str] = field(default_factory=list)

    def _expected_leading_tag(self, command: str) -> int | None:
        try:
            return int(command, 16)
        except ValueError:
            return None

    def _structural_anomaly(self, result: ProbeResult, fingerprint: str) -> bool:
        if not result.sent or not result.resp_hex:
            return False
        # A read of a two-byte command tag should echo that tag as the leading
        # TLV of its response. A different leading tag is a structural surprise
        # (possible info leak or wrong-object response).
        expected = self._expected_leading_tag(result.command)
        if expected is not None and expected > 0xFF:
            try:
                body = bytes.fromhex(result.resp_hex)
            except ValueError:
                return True
            if body:
                lead, _ = _read_tag(body, 0)
                if lead != expected:
                    return True
        # A fingerprint never seen for this command, produced by a malformed
        # input, is a structural anomaly worth logging.
        known = self.baseline_fp_by_command.get(result.command, set())
        if result.malformed and fingerprint not in known:
            return True
        return False

    def evaluate(self, result: ProbeResult) -> NoveltyVerdict:
        """Classify one probe. Records its signature as seen as a side effect."""
        # Defense in depth: a blocklisted APDU must never be observed as sent.
        # A sent APDU already passed guard_send, so it parses; guard the classify
        # anyway so a malformed stub cannot mask the check with a ValueError.
        if result.sent:
            try:
                verdict = classify(result.apdu_hex)
            except ValueError:
                verdict = None
            if verdict is not None and verdict.classification is Classification.BLOCKED:
                raise SafetyViolation(
                    f"blocklisted APDU reached transport: {result.apdu_hex} "
                    f"({verdict.reason})"
                )

        sw = result.sw or ("ERR" if result.transport_error else "NONE")
        fingerprint = response_fingerprint(result.resp_hex)
        signature = BehaviourSignature(
            command=result.command, sw=sw, fingerprint=fingerprint
        )

        novelty: list[str] = []
        severity = SEVERITY_INFO

        if result.transport_error is not None:
            novelty.append(NOVELTY_TRANSPORT_ERROR)
            severity = SEVERITY_WARNING

        seen_sw = self.seen_sw_by_command.setdefault(result.command, set())
        if result.sent and sw not in seen_sw and sw not in ("NONE", "ERR"):
            novelty.append(NOVELTY_NOVEL_SW)

        if result.sent and sw == _SUCCESS_SW and result.malformed:
            novelty.append(NOVELTY_SUCCESS_ON_MALFORMED)
            severity = SEVERITY_WARNING

        if result.sent and _is_rare_sw(sw):
            novelty.append(NOVELTY_RARE_SW)

        if self._structural_anomaly(result, fingerprint):
            novelty.append(NOVELTY_STRUCTURAL_ANOMALY)
            severity = SEVERITY_WARNING

        is_new_signature = signature not in self.seen_signatures
        if is_new_signature:
            novelty.append(NOVELTY_NEW_SIGNATURE)

        interesting = is_new_signature or bool(
            set(novelty) - {NOVELTY_NEW_SIGNATURE}
        )

        # Commit state after deciding novelty.
        self.seen_signatures.add(signature)
        if result.sent and sw not in ("NONE", "ERR"):
            seen_sw.add(sw)
        self.baseline_fp_by_command.setdefault(result.command, set()).add(fingerprint)
        if interesting:
            self.corpus.append(result.apdu_hex)

        return NoveltyVerdict(
            signature=signature,
            fingerprint=fingerprint,
            novelty=novelty,
            severity=severity,
            interesting=interesting,
        )

    def check_repeats(self, samples: list[tuple[str | None, str | None]]) -> bool:
        """True if a re-sent input gave inconsistent SW/response fingerprints.

        ``samples`` is a list of ``(sw, resp_hex)`` from N resends of the same
        input. Non-determinism is a flagged, always-logged behaviour.
        """
        if len(samples) < 2:
            return False
        keyed = {(sw, response_fingerprint(resp)) for sw, resp in samples}
        return len(keyed) > 1

    def distinct_signatures(self) -> int:
        return len(self.seen_signatures)

    def distinct_sws(self) -> set[str]:
        out: set[str] = set()
        for sws in self.seen_sw_by_command.values():
            out |= sws
        return out


def _is_rare_sw(sw: str) -> bool:
    return any(pat.match(sw) for pat in _RARE_SW_PATTERNS)
