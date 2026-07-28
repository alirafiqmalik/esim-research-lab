#!/usr/bin/env python3
"""Local-only HTTP shim: speaks the real ES9+/ES11 JSON wire shape, backed by
testbed/ecosim/'s in-process SM-DP+ / SM-DS objects.

This is the *only* thing Step 4 scripts are allowed to talk to by default. It
binds to 127.0.0.1 only (never 0.0.0.0), never opens an outbound connection,
and never touches a real provider. It exists purely so the request-builder
library in src/ can be validated over a real HTTP socket with real JSON
serialization -- not just in-process function calls -- while staying entirely
offline.

Usage as a library (preferred -- see scripts/run_es9plus_flow.py):

    server = start_smdp_server(eco.smdp, eco.pki.ci.certificate, eco.euicc.get_eid())
    ...
    server.shutdown()

Usage standalone (for manual poking with curl against 127.0.0.1 only):

    ./venv/bin/python testbed/ping-live-servers/scripts/local_sim_server.py --role smdp
    ./venv/bin/python testbed/ping-live-servers/scripts/local_sim_server.py --role smds

Standalone mode builds its own fresh ecosystem, so a standalone smdp server
and a standalone smds server (or a separate client script) do NOT share a PKI
identity unless you drive them from the same Python process -- see
run_es9plus_flow.py, which does that correctly in-process.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]
PING_LIVE_SERVERS = HERE.parent
for p in (str(REPO_ROOT), str(PING_LIVE_SERVERS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from src.envelope import wrap_response  # noqa: E402
from testbed.ecosim import codec  # noqa: E402


class _SmdpHandler(BaseHTTPRequestHandler):
    smdp = None  # type: ignore[assignment]
    ci_cert = None  # type: ignore[assignment]
    authenticated_eid = None  # type: ignore[assignment]

    def log_message(self, fmt: str, *args: object) -> None:  # quiet by default
        pass

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8"))

    def _respond(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:  # noqa: N802 (http.server naming convention)
        try:
            req = self._read_json()
            req.pop("header", None)
            if self.path == "/gsma/rsp2/es9plus/initiateAuthentication":
                resp = self.smdp.initiate_authentication(
                    codec.unb64(req["euiccChallenge"]), codec.unb64(req["euiccInfo1"]), req["smdpAddress"]
                )
                self._respond(200, wrap_response(resp))
            elif self.path == "/gsma/rsp2/es9plus/authenticateClient":
                resp = self.smdp.authenticate_client(req, self.ci_cert, authenticated_eid=self.authenticated_eid)
                self._respond(200, wrap_response(resp))
            elif self.path == "/gsma/rsp2/es9plus/getBoundProfilePackage":
                resp = self.smdp.get_bound_profile_package(req["transactionId"])
                self._respond(200, wrap_response(resp))
            elif self.path == "/gsma/rsp2/es9plus/handleNotification":
                self.smdp.handle_notification(
                    codec.unb64(req["notification"]), req["seq"], codec.unb64(req["euiccCertificate"])
                )
                self._respond(200, wrap_response({}))
            else:
                self._respond(404, wrap_response({}, ok=False, reason=f"unknown path {self.path}"))
        except (KeyError, ValueError) as exc:
            self._respond(200, wrap_response({}, ok=False, reason=str(exc)))


class _SmdsHandler(BaseHTTPRequestHandler):
    smds = None  # type: ignore[assignment]

    def log_message(self, fmt: str, *args: object) -> None:
        pass

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8"))

    def _respond(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:  # noqa: N802
        try:
            req = self._read_json()
            req.pop("header", None)
            if self.path == "/gsma/rsp2/es9plus/discover":
                records = self.smds.discover(req["eid"])
                entries = [{"eventId": r.event_id, "rspServerAddress": r.smdp_address} for r in records]
                self._respond(200, wrap_response({"eventEntries": entries}))
            else:
                self._respond(404, wrap_response({}, ok=False, reason=f"unknown path {self.path}"))
        except (KeyError, ValueError) as exc:
            self._respond(200, wrap_response({}, ok=False, reason=str(exc)))


def start_smdp_server(smdp, ci_cert, authenticated_eid: str, port: int = 0) -> HTTPServer:
    """Start the SM-DP+ shim in a background thread, bound to 127.0.0.1.
    port=0 lets the OS pick a free port; read it back via server.server_port."""
    handler = type("BoundSmdpHandler", (_SmdpHandler,), {
        "smdp": smdp, "ci_cert": ci_cert, "authenticated_eid": authenticated_eid,
    })
    httpd = HTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def start_smds_server(smds, port: int = 0) -> HTTPServer:
    handler = type("BoundSmdsHandler", (_SmdsHandler,), {"smds": smds})
    httpd = HTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def _standalone_main() -> None:
    from testbed.ecosim.orchestrator import build_ecosystem
    from testbed.ecosim.smds import SmDs

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=["smdp", "smds"], required=True)
    parser.add_argument("--port", type=int, default=None, help="default: 8443 (smdp) / 8444 (smds)")
    args = parser.parse_args()

    if args.role == "smdp":
        eco = build_ecosystem()
        eco.mno.order_profile("standalone-profile", "standalone-MNO", 0)
        port = args.port if args.port is not None else 8443
        httpd = start_smdp_server(eco.smdp, eco.pki.ci.certificate, eco.euicc.get_eid(), port=port)
        print(f"[local_sim_server] SM-DP+ shim on http://127.0.0.1:{httpd.server_port} (role=smdp)")
    else:
        smds = SmDs()
        smds.register_event("00000000000000000000000000000000", "demo-event", "smdp.ecosim.test")
        port = args.port if args.port is not None else 8444
        httpd = start_smds_server(smds, port=port)
        print(f"[local_sim_server] SM-DS shim on http://127.0.0.1:{httpd.server_port} (role=smds)")

    print("Ctrl-C to stop. This server binds to 127.0.0.1 only and makes no outbound connections.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    _standalone_main()
