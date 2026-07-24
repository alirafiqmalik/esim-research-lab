"""Local rogue SM-DS (SGP.22 ES11) HTTPS server for the eUICC/LPA under test.

Implements the two ES9+/ES11 endpoints OpenEUICC's ``discovery`` applet calls
(``LpacJni.es11Discovery`` -> ``es9p_initiate_authentication`` ->
``es11_authenticate_client``):

    POST /gsma/rsp2/es9plus/initiateAuthentication
        req  {"smdpAddress", "euiccChallenge"<b64>, "euiccInfo1"<b64>}
        resp {"header":{...}, "transactionId", "serverSigned1"<b64>,
              "serverSignature1"<b64>, "euiccCiPKIdToBeUsed"<b64>,
              "serverCertificate"<b64>}

    POST /gsma/rsp2/es9plus/authenticateClient   (ES11 form)
        req  {"transactionId", "authenticateServerResponse"<b64>}
        resp {"header":{...}, "eventEntries":[{"rspServerAddress", "eventId", ...}]}

(field names verified against ``lpac/euicc/es9p.c`` es9p_initiate_authentication_r
and es11_authenticate_client_r, and the real capture in
``.sessions/betterroaming-live-rsp-20260629/handshake_capture.txt``.)

The HTTP layer is thin. A :class:`ResponseSource` supplies the response bytes for
each request; the fuzzer plugs its mutated responses in through that seam. The
pure request/response builders (:func:`build_initiate_response`,
:func:`build_authenticate_response`, and the ``parse_*`` helpers) are what the
unit tests exercise — no socket required.

The server binds ``127.0.0.1`` by default and speaks HTTPS with a supplied cert.
See ``README.md`` for how the LPA is made to trust that cert (it is NOT the system
store — OpenEUICC pins RSP TLS to the GSMA CI keystore).
"""

from __future__ import annotations

import base64
import json
import ssl
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Protocol

INITIATE_PATH = "/gsma/rsp2/es9plus/initiateAuthentication"
AUTHENTICATE_PATH = "/gsma/rsp2/es9plus/authenticateClient"

_EXECUTED_SUCCESS = {"header": {"functionExecutionStatus": {"status": "Executed-Success"}}}


class ServerError(ValueError):
    """Raised when a request cannot be parsed into the expected ES11 shape."""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text)


# --------------------------------------------------------------------------- #
# Request / response data objects.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class InitiateAuthRequest:
    """A parsed ``initiateAuthentication`` request from the LPA."""

    smdp_address: str
    euicc_challenge: bytes
    euicc_info1: bytes


@dataclass(frozen=True)
class AuthenticateClientRequest:
    """A parsed ES11 ``authenticateClient`` request from the LPA."""

    transaction_id: str
    authenticate_server_response: bytes


@dataclass(frozen=True)
class InitiateAuthResponse:
    """The five signed constructs of an ``initiateAuthentication`` response.

    Each field is the raw TLV bytes (as they appear base64-decoded on the wire).
    ``to_json_bytes`` base64-encodes them into the exact JSON lpac parses. ``header``
    lets a mutation inject a Failed/garbage status.
    """

    transaction_id: str
    server_signed1: bytes
    server_signature1: bytes
    euicc_ci_pkid: bytes
    server_certificate: bytes
    header: dict = field(default_factory=lambda: dict(_EXECUTED_SUCCESS["header"]))

    def to_json_bytes(self) -> bytes:
        return json.dumps(
            {
                "header": self.header,
                "transactionId": self.transaction_id,
                "serverSigned1": _b64(self.server_signed1),
                "serverSignature1": _b64(self.server_signature1),
                "euiccCiPKIdToBeUsed": _b64(self.euicc_ci_pkid),
                "serverCertificate": _b64(self.server_certificate),
            }
        ).encode("utf-8")


@dataclass(frozen=True)
class EventRecord:
    """One ES11 event entry: a POINTER to an SM-DP+ with a pending event.

    Discovery returns pointers, never profiles. ``rsp_server_address`` is the only
    field lpac reads (``es11_authenticate_client_r``); the others round out the
    SGP.22 EventEntries shape and give the parser fuzzer more surface.
    """

    rsp_server_address: str
    event_id: str = "00000000"

    def to_dict(self) -> dict:
        return {"rspServerAddress": self.rsp_server_address, "eventId": self.event_id}


@dataclass(frozen=True)
class AuthenticateClientResponse:
    """The ES11 ``authenticateClient`` response: a signed event-record list."""

    event_entries: list[EventRecord]
    header: dict = field(default_factory=lambda: dict(_EXECUTED_SUCCESS["header"]))

    def to_json_bytes(self) -> bytes:
        return json.dumps(
            {
                "header": self.header,
                "eventEntries": [e.to_dict() for e in self.event_entries],
            }
        ).encode("utf-8")


# --------------------------------------------------------------------------- #
# Pure request parsers + response builders (unit-tested; no socket).
# --------------------------------------------------------------------------- #


def parse_initiate_request(body: bytes) -> InitiateAuthRequest:
    try:
        obj = json.loads(body)
        return InitiateAuthRequest(
            smdp_address=str(obj["smdpAddress"]),
            euicc_challenge=_unb64(obj["euiccChallenge"]),
            euicc_info1=_unb64(obj["euiccInfo1"]),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise ServerError(f"malformed initiateAuthentication request: {exc}") from exc


def parse_authenticate_request(body: bytes) -> AuthenticateClientRequest:
    try:
        obj = json.loads(body)
        return AuthenticateClientRequest(
            transaction_id=str(obj["transactionId"]),
            authenticate_server_response=_unb64(obj["authenticateServerResponse"]),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise ServerError(f"malformed authenticateClient request: {exc}") from exc


class ResponseSource(Protocol):
    """Supplies the raw response body for each ES11 endpoint.

    The fuzzer implements this to serve a mutated response per iteration. A source
    reads the parsed request (to echo the FRESH euiccChallenge / transactionId) and
    returns the JSON body bytes to send.
    """

    def initiate(self, request: InitiateAuthRequest) -> bytes: ...

    def authenticate(self, request: AuthenticateClientRequest) -> bytes: ...


# --------------------------------------------------------------------------- #
# HTTPS server.
# --------------------------------------------------------------------------- #


@dataclass
class RequestLog:
    """Captured requests, so the orchestrator can prove which challenge was echoed."""

    initiate: list[InitiateAuthRequest] = field(default_factory=list)
    authenticate: list[AuthenticateClientRequest] = field(default_factory=list)


class RogueSmdsServer:
    """A local HTTPS SM-DS bound to 127.0.0.1 serving ``source``'s responses.

    ``certfile``/``keyfile`` are the attacker TLS cert/key (PEM). This is the TLS
    identity the LPA must be made to accept — see README (OpenEUICC pins RSP TLS to
    the GSMA CI keystore, so use the built-in ``ignore_tls_certificate`` toggle).
    """

    def __init__(
        self,
        source: ResponseSource,
        certfile: str,
        keyfile: str,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self._source = source
        self._log = RequestLog()
        self._httpd = ThreadingHTTPServer((host, port), self._make_handler())
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self._httpd.socket = ctx.wrap_socket(self._httpd.socket, server_side=True)

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def request_log(self) -> RequestLog:
        return self._log

    def serve_forever(self) -> None:
        self._httpd.serve_forever()

    def shutdown(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        source = self._source
        log = self._log

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args) -> None:  # silence default stderr logging
                return

            def _read_body(self) -> bytes:
                length = int(self.headers.get("Content-Length", 0))
                return self.rfile.read(length)

            def _send(self, body: bytes) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:  # noqa: N802 (http.server API)
                body = self._read_body()
                try:
                    if self.path == INITIATE_PATH:
                        req = parse_initiate_request(body)
                        log.initiate.append(req)
                        self._send(source.initiate(req))
                    elif self.path == AUTHENTICATE_PATH:
                        req = parse_authenticate_request(body)
                        log.authenticate.append(req)
                        self._send(source.authenticate(req))
                    else:
                        self.send_error(404, "unknown ES11 endpoint")
                except ServerError as exc:
                    self.send_error(400, str(exc))

        return Handler
