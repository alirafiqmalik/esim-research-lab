#!/usr/bin/env python3
"""Ping every known SM-DP+ / SM-DS server with a live ES9+/ES11
InitiateAuthentication request and log the responses.

Two passes:
  1. Strict SSL (system trust store).
  2. Insecure SSL (no cert verification) for servers that failed pass 1
     with a cert-related error.  This matches how real LPAs work --
     they trust GSMA CI certs, not the OS bundle.

Requires:
    ESIM_MITM_ALLOW_LIVE_FIRE=1  (safety gate)
    --allow-live-fire            (second safety gate)

Run:
    ESIM_MITM_ALLOW_LIVE_FIRE=1 \
    ./venv/bin/python testbed/ping-live-servers/scripts/ping_live_servers.py \
        --allow-live-fire
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError

HERE = Path(__file__).resolve().parent
PING_LIVE_SERVERS = HERE.parent
REPO_ROOT = HERE.parents[2]
for p in (str(REPO_ROOT), str(PING_LIVE_SERVERS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from src.client import LiveFireNotAuthorizedError, RspHttpClient, TransportError
from src.envelope import parse_response_header, path_for
from src.errors import RspClientError
from src.models import InitiateAuthenticationRequest, InitiateAuthenticationResponse
from src.targets import provider_target
from testbed.ecosim import codec

PROVIDERS: list[dict] = [
    {"provider": "1GLOBAL", "host": "rsp.truphone.com", "type": "smdp", "confidence": "high"},
    {"provider": "Eastcom Peace", "host": "secsmsminiapp.eastcompeace.com", "type": "smdp", "confidence": "medium"},
    {"provider": "Giesecke+Devrient", "host": "cust-003.oberthur.rsp.gieseckedevrient.com", "type": "smdp", "confidence": "medium"},
    {"provider": "Giesecke+Devrient", "host": "prod.attesim.rsp.gieseckedevrient.com", "type": "smdp", "confidence": "medium"},
    {"provider": "Idemia", "host": "t-mobile.idemia.io", "type": "smdp", "confidence": "medium"},
    {"provider": "Idemia", "host": "rsp-3002.idemia.io", "type": "smdp", "confidence": "medium"},
    {"provider": "Idemia", "host": "rsp-3036.idemia.io", "type": "smdp", "confidence": "medium"},
    {"provider": "Idemia", "host": "rsp-4002.idemia.io", "type": "smdp", "confidence": "medium"},
    {"provider": "Idemia", "host": "rsp-4008.idemia.io", "type": "smdp", "confidence": "medium"},
    {"provider": "Idemia", "host": "celitech.idemia.io", "type": "smdp", "confidence": "medium"},
    {"provider": "Kigen", "host": "smdp-plus-0.eu.cd.rsp.kigen.com", "type": "smdp", "confidence": "medium"},
    {"provider": "Kigen", "host": "smdp-plus-1.eu.cd.rsp.kigen.com", "type": "smdp", "confidence": "medium"},
    {"provider": "Linksfield", "host": "rsp-0001.linksfield.net", "type": "smdp", "confidence": "medium"},
    {"provider": "Redtea Mobile", "host": "rsp-eu.redteamobile.com", "type": "smdp", "confidence": "high"},
    {"provider": "Valid", "host": "demo-consumer.validspereachdpplus.com", "type": "smdp", "confidence": "medium"},
    {"provider": "Thales", "host": "lpa.ds.gsma.com", "type": "smds", "confidence": "medium"},
    {"provider": "Thales", "host": "lpa.live.esimdiscovery.com", "type": "smds", "confidence": "high"},
    {"provider": "Thales", "host": "lpa.live.esimdiscovery.dev", "type": "smds", "confidence": "medium"},
]

SYNTHETIC_EUICC_CHALLENGE = bytes.fromhex("bf2e128010574eb8cd81ee86b4adb597421fdc457f")
SYNTHETIC_EUICC_INFO1 = bytes.fromhex(
    "bf20358203020200a9160414801fe1df177a074d89f0d52391836f5e5dde4348"
    "aa160414801fe1df177a074d89f0d52391836f5e5dde4348"
)


def ping_provider(provider: dict, insecure: bool = False) -> dict:
    host = provider["host"]
    pname = provider["provider"]
    ptype = provider["type"]

    log_entry: dict = {
        "provider": pname,
        "host": host,
        "type": ptype,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "confidence": provider["confidence"],
        "insecure": insecure,
    }

    req = InitiateAuthenticationRequest(
        euicc_challenge=SYNTHETIC_EUICC_CHALLENGE,
        euicc_info1=SYNTHETIC_EUICC_INFO1,
        smdp_address=host,
    )

    ssl_ctx = ssl._create_unverified_context() if insecure else None
    client = RspHttpClient(
        target=provider_target(pname, host),
        timeout_seconds=15.0,
        allow_live_fire=True,
        ssl_context=ssl_ctx,
    )

    try:
        if ptype == "smds":
            interface, function = "ES11", "InitiateAuthentication"
        else:
            interface, function = "ES9+", "InitiateAuthentication"

        path = path_for(interface, function)
        raw = client.call(interface, function, path, req.to_wire())

        log_entry["http_status"] = 200
        log_entry["response_body"] = raw

        header_ok = parse_response_header(raw).ok
        log_entry["function_status_ok"] = header_ok

        if header_ok:
            try:
                resp = InitiateAuthenticationResponse.from_wire(raw)
                log_entry["transaction_id"] = resp.transaction_id
                log_entry["server_certificate_len"] = len(resp.server_certificate)
                log_entry["status"] = "success"
            except RspClientError as exc:
                log_entry["status"] = "partial_parse_error"
                log_entry["error"] = str(exc)
        else:
            log_entry["status"] = "function_failed"

    except TransportError as exc:
        log_entry["status"] = "transport_error"
        log_entry["error"] = str(exc)
        inner = exc.__cause__
        if inner:
            log_entry["error_detail"] = str(inner)
            if isinstance(inner, URLError):
                log_entry["reason"] = str(inner.reason)
    except LiveFireNotAuthorizedError as exc:
        log_entry["status"] = "live_fire_not_authorized"
        log_entry["error"] = str(exc)
    except RspClientError as exc:
        log_entry["status"] = "client_error"
        log_entry["error"] = str(exc)
    except Exception as exc:
        log_entry["status"] = "unexpected_error"
        log_entry["error"] = str(exc)
        log_entry["traceback"] = traceback.format_exc()

    log_entry["elapsed_seconds"] = (
        datetime.now(timezone.utc).timestamp()
        - datetime.fromisoformat(log_entry["timestamp"]).timestamp()
    )
    return log_entry


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-live-fire", action="store_true", required=True)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--provider", default=None, help="filter by provider name")
    parser.add_argument("--output", default=None, help="log file path")
    args = parser.parse_args()

    if os.environ.get("ESIM_MITM_ALLOW_LIVE_FIRE") != "1":
        print("FATAL: ESIM_MITM_ALLOW_LIVE_FIRE=1 is required", file=sys.stderr)
        return 1

    targets = PROVIDERS
    if args.provider:
        targets = [p for p in PROVIDERS if args.provider.lower() in p["provider"].lower()]
        if not targets:
            print("No providers match filter: {!r}".format(args.provider), file=sys.stderr)
            return 1

    output_path = args.output or str(PING_LIVE_SERVERS / "logs" / "ping-{}.jsonl".format(datetime.now().strftime("%Y%m%d_%H%M%S")))
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    print("Pinging {} endpoints (pass 1: strict SSL)...".format(len(targets)))
    print("Log: {}".format(output_path))
    print()

    # --- Pass 1: strict SSL ---
    results: list[dict] = []
    cert_failures: list[dict] = []

    for provider in targets:
        host = provider["host"]
        pname = provider["provider"]
        label = "{} @ {}".format(pname, host)
        print("  [{}] ...".format(label), end=" ", flush=True)

        entry = ping_provider(provider, insecure=False)
        results.append(entry)

        status = entry.get("status", "unknown")
        if status == "success":
            print("OK")
        elif status == "function_failed":
            body = entry.get("response_body", {})
            es = body.get("header", {}).get("functionExecutionStatus", {})
            msg = es.get("statusCodeData", {}).get("message", "no reason")
            print("REJECTED ({})".format(msg))
        elif status == "transport_error":
            err = entry.get("error", "")
            reason = entry.get("reason", "")
            print("TRANSPORT: {}".format(reason[:80] if reason else err[:80]))
            if "CERT" in err or "certificate" in err.lower():
                cert_failures.append(provider)
        else:
            print("ERROR: {}".format(entry.get("error", "?")[:60]))

    # --- Pass 2: insecure SSL for cert failures ---
    if cert_failures:
        print("")
        print("--- Pass 2: insecure SSL for {} cert-failing endpoints ---".format(len(cert_failures)))
        print("")
        for provider in cert_failures:
            host = provider["host"]
            pname = provider["provider"]
            label = "{} @ {}".format(pname, host)
            print("  [{}] ...".format(label), end=" ", flush=True)
            entry = ping_provider(provider, insecure=True)
            results.append(entry)

            status = entry.get("status", "unknown")
            if status == "success":
                print("OK")
            elif status == "function_failed":
                body = entry.get("response_body", {})
                es = body.get("header", {}).get("functionExecutionStatus", {})
                msg = es.get("statusCodeData", {}).get("message", "no reason")
                print("REJECTED ({})".format(msg))
            elif status == "transport_error":
                err = entry.get("error", "")
                reason = entry.get("reason", "")
                print("TRANSPORT: {}".format(reason[:80] if reason else err[:80]))
            else:
                print("ERROR: {}".format(entry.get("error", "?")[:60]))

    # --- Write log ---
    with open(output_path, "w") as f:
        for entry in results:
            f.write(json.dumps(entry, default=str) + "\n")

    # --- Summary ---
    print("")
    print("=== SUMMARY ===")
    total_probes = len(results)
    pass_count = 1 + (1 if cert_failures else 0)
    print("  Total probes:     {} ({} endpoints x {} passes)".format(total_probes, len(targets), pass_count))
    success = [r for r in results if r.get("status") == "success"]
    rejected = [r for r in results if r.get("status") == "function_failed"]
    transport = [r for r in results if r.get("status") == "transport_error"]
    other = [r for r in results if r.get("status") not in ("success", "function_failed", "transport_error")]
    print("  Success:          {}".format(len(success)))
    print("  Rejected by host: {}".format(len(rejected)))
    print("  Transport errors: {}".format(len(transport)))
    print("  Other:            {}".format(len(other)))
    print("")

    if success:
        print("Responded to InitiateAuthentication:")
        for s in success:
            print("  [{}] {} @ {}".format(s["confidence"], s["provider"], s["host"]))
        print("")
    if rejected:
        print("Reached but rejected the request:")
        for r in rejected:
            body = r.get("response_body", {})
            es = body.get("header", {}).get("functionExecutionStatus", {})
            sd = es.get("statusCodeData", {})
            msg = sd.get("message", "no reason")
            print("  [{}] {} @ {}: {}".format(r["confidence"], r["provider"], r["host"], msg))
        print("")
    if transport:
        print("Transport errors (unreachable):")
        for t in transport:
            err_short = t.get("reason", t.get("error", "?"))[:80]
            print("  [{}] {} @ {}: {}".format(t["confidence"], t["provider"], t["host"], err_short))
        print("")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
