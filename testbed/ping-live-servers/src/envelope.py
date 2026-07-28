"""GSMA RSP HTTP envelope: function paths, HTTP headers, and the `header` wrapper.

testbed/ecosim/ models ES9+/ES11 as bare Python dicts exchanged in-process --
it never puts anything on the wire, so it has no envelope. This module adds
back what a real HTTP client must send/parse (see notes/03-api-request-list.md
for the sourcing of these paths/field names), so the request-builder library
here produces wire-accurate bytes even though it validates against ecosim.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from .errors import MalformedResponseError

CONTENT_TYPE = "application/json"
ADMIN_PROTOCOL = "gsma/rsp/v2.2.0"
USER_AGENT = "esim-mitm-research-client/0.1 (offline-prepared, live-fire gated)"

# (interface, function) -> HTTP path. ES11 reuses the ES9+ message set/paths but
# is served from the SM-DS FQDN rather than the SM-DP+ FQDN (SGP.22 SS3.6); see
# notes/03-api-request-list.md for the confidence note on this path reuse.
FUNCTION_PATHS: dict[tuple[str, str], str] = {
    ("ES9+", "InitiateAuthentication"): "/gsma/rsp2/es9plus/initiateAuthentication",
    ("ES9+", "AuthenticateClient"): "/gsma/rsp2/es9plus/authenticateClient",
    ("ES9+", "GetBoundProfilePackage"): "/gsma/rsp2/es9plus/getBoundProfilePackage",
    ("ES9+", "HandleNotification"): "/gsma/rsp2/es9plus/handleNotification",
    ("ES9+", "CancelSession"): "/gsma/rsp2/es9plus/cancelSession",
    ("ES11", "InitiateAuthentication"): "/gsma/rsp2/es9plus/initiateAuthentication",
    ("ES11", "AuthenticateClient"): "/gsma/rsp2/es9plus/authenticateClient",
    # ecosim-only: the local SM-DS shim collapses ES11.InitiateAuthentication +
    # ES11.AuthenticateClient into one EID-keyed lookup (models.Es11DiscoveryRequest),
    # matching smds.SmDs.discover(eid). This path exists only on local_sim_server.py's
    # SM-DS shim -- never use it against a real provider, use ("ES11", "AuthenticateClient").
    ("ES11", "Discover"): "/gsma/rsp2/es9plus/discover",
}


def path_for(interface: str, function: str) -> str:
    try:
        return FUNCTION_PATHS[(interface, function)]
    except KeyError as exc:
        raise KeyError(f"no known HTTP path for {interface}.{function}") from exc


@dataclass
class FunctionHeader:
    function_requester_identifier: str
    function_call_identifier: str

    def to_wire(self) -> dict[str, str]:
        return {
            "functionRequesterIdentifier": self.function_requester_identifier,
            "functionCallIdentifier": self.function_call_identifier,
        }


def new_header(requester_identifier: str) -> FunctionHeader:
    call_id = f"FCI-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    return FunctionHeader(function_requester_identifier=requester_identifier, function_call_identifier=call_id)


def wrap_request(body: dict[str, object], header: FunctionHeader) -> dict[str, object]:
    return {"header": header.to_wire(), **body}


@dataclass
class ExecutionStatus:
    status: str
    subject_code: str | None = None
    reason_code: str | None = None
    message: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "Executed-Success"


def parse_response_header(obj: dict) -> ExecutionStatus:
    header = obj.get("header")
    if not isinstance(header, dict):
        raise MalformedResponseError("response missing 'header' object")
    status_obj = header.get("functionExecutionStatus")
    if not isinstance(status_obj, dict) or "status" not in status_obj:
        raise MalformedResponseError("response header missing functionExecutionStatus.status")
    status_code = status_obj.get("statusCodeData") or {}
    return ExecutionStatus(
        status=status_obj["status"],
        subject_code=status_code.get("subjectCode"),
        reason_code=status_code.get("reasonCode"),
        message=status_code.get("message"),
    )


def wrap_response(body: dict[str, object], ok: bool = True, reason: str | None = None) -> dict[str, object]:
    status: dict[str, object] = {"status": "Executed-Success" if ok else "Failed"}
    if not ok and reason:
        status["statusCodeData"] = {"subjectCode": "8.1", "reasonCode": "3.8", "message": reason}
    return {"header": {"functionExecutionStatus": status}, **body}
