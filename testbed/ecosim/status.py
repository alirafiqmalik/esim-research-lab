"""Real SGP.22 ES9+/ES11 function-execution status envelope and reason codes.

Grounded in live captures from production SM-DP+/SM-DS during this project (see
testbed/profile-download/FINDINGS.md and testbed/es9-message-flow/). Before this
module, ecosim signalled every failure with a bare `raise ValueError` and
returned un-enveloped dicts. Real servers wrap every ES9+/ES11 response in a
`header.functionExecutionStatus` and return a structured `statusCodeData` on
failure.

`RspError` subclasses `ValueError` so existing `except ValueError` callers keep
working while gaining the real subject/reason codes and a Failed-envelope
renderer.
"""

from __future__ import annotations

from dataclasses import dataclass

STATUS_EXECUTED_SUCCESS = "Executed-Success"
STATUS_FAILED = "Failed"


@dataclass(frozen=True)
class ReasonCode:
    """One SGP.22 statusCodeData triple. `subject_code`/`reason_code` are the
    dotted identifiers; `message` is the human string a server returns."""

    subject_code: str
    reason_code: str
    subject_identifier: str
    message: str


# --- Reason codes observed live (2026-07-28) -------------------------------
# The exact triples returned by production servers this project probed.

# RedteaGO: the free profile pool was exhausted server-side.
POOL_EMPTY = ReasonCode("9.4", "10.1", "", "campaign resource pool is empty")
# BetterRoaming QR-G-5C-1LS: the profile is refused for this EID (consumed).
EID_REFUSED = ReasonCode("8.1.1", "3.8", "EID", "Refused")
# Re-downloading a code whose profile is still installed on the eUICC.
MATCHING_ID_REFUSED = ReasonCode("8.2.6", "3.8", "Matching ID", "Refused")

# --- Common SGP.22 codes (not all observed, but part of the real catalog) ---
# No pending order for the presented matchingId.
MATCHING_ID_UNKNOWN = ReasonCode("8.2.6", "3.8", "Matching ID", "Refused")
# eUICC advertises no CI public key the server can chain to (SGP.22 SS5.7.5).
CI_UNSUPPORTED = ReasonCode("8.8.4", "3.7", "GSMA CI Public Key", "Unknown")
# eUICC certificate / signature failed verification.
EUICC_VERIFICATION_FAILED = ReasonCode("8.1", "6.1", "eUICC", "Verification failed")
# Unknown transactionId (session not established or expired).
TRANSACTION_UNKNOWN = ReasonCode("8.10.1", "3.9", "Transaction ID", "Unknown")


def executed_success() -> dict:
    return {"status": STATUS_EXECUTED_SUCCESS}


def failed(reason: ReasonCode, subject_identifier: str | None = None) -> dict:
    """Build a Failed functionExecutionStatus. `subject_identifier` overrides the
    reason's default (e.g. the concrete ICCID for POOL_EMPTY)."""
    return {
        "status": STATUS_FAILED,
        "statusCodeData": {
            "subjectCode": reason.subject_code,
            "reasonCode": reason.reason_code,
            "subjectIdentifier": subject_identifier if subject_identifier is not None else reason.subject_identifier,
            "message": reason.message,
        },
    }


def envelope(function_status: dict, **fields: object) -> dict:
    """Wrap a response body in the real `header.functionExecutionStatus`, keeping
    the top-level fields alongside it exactly as the live wire does."""
    return {"header": {"functionExecutionStatus": function_status}, **fields}


def success_envelope(**fields: object) -> dict:
    return envelope(executed_success(), **fields)


class RspError(ValueError):
    """A structured ES9+/ES11 failure carrying a real SGP.22 reason code.

    Subclasses ValueError so callers that already `except ValueError` are
    unaffected. `to_failed_response` renders the exact Failed envelope a live
    server returns."""

    def __init__(self, reason: ReasonCode, subject_identifier: str | None = None,
                 detail: str | None = None) -> None:
        self.reason = reason
        self.subject_identifier = subject_identifier if subject_identifier is not None else reason.subject_identifier
        text = detail or f"{reason.subject_code}/{reason.reason_code} {self.subject_identifier} {reason.message}".strip()
        super().__init__(text)

    def to_failed_response(self, transaction_id: str | None = None) -> dict:
        body: dict = {} if transaction_id is None else {"transactionId": transaction_id}
        return envelope(failed(self.reason, self.subject_identifier), **body)
