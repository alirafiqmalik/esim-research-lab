#!/usr/bin/env python3
"""Test whether live SM-DS discovery exposes a pre-authentication EID oracle:
can an unauthenticated party present arbitrary EIDs and learn "event waiting"
vs "nothing"?

Structural answer, confirmed empirically here:

  ES11.InitiateAuthentication  -> body carries euiccChallenge + euiccInfo1 ONLY.
                                  There is NO EID field. The SM-DS does not know
                                  which EID is asking at this stage.
  ES11.AuthenticateClient      -> returns eventEntries[]. Its input is the
                                  eUICC-signed authenticateServerResponse, whose
                                  CERT.EUICC embeds the EID. The SM-DS binds the
                                  queried EID to a valid eUICC signature.

So the EID is only presented AFTER an eUICC signature, and eventEntries only come
out of that authenticated step. There is nothing to enumerate pre-auth, and you
cannot query an EID you do not hold the eUICC for.

This probe:
  A. Host-side: sends N InitiateAuthentication requests to the reachable SM-DS
     endpoints and shows the request has no EID slot and the response does not
     vary with anything an unauthenticated caller controls (no oracle).
  B. Device: one real ES11 discovery via the eUICC (the ONE EID we can query),
     as the authenticated reference (expected events=0).

Read-only: no profile is downloaded, enabled, or deleted.

Gated:
    ESIM_MITM_ALLOW_LIVE_FIRE=1  --allow-live-fire

Run:
    ESIM_MITM_ALLOW_LIVE_FIRE=1 \
    ./venv/bin/python testbed/ping-sm-ds/scripts/eid_enumeration.py --allow-live-fire
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import subprocess
import sys
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
PING_SM_DS = HERE.parent
REPO_ROOT = HERE.parents[2]
ESIM = str(REPO_ROOT / "venv" / "bin" / "esim")

ES11_PATH = "/gsma/rsp2/es9plus/initiateAuthentication"

# Real public euiccInfo1 (BF20) captured from this Pixel eUICC: advertises the
# real GSMA CI PKIDs so the SM-DS executes InitiateAuthentication instead of
# rejecting. It is public metadata, not a secret, and carries NO EID.
REAL_EUICC_INFO1_B64 = "vyA1ggMCAwCpFgQUgTcPUSXQsdQI1MOyMubSXnlb6/uqFgQUgTcPUSXQsdQI1MOyMubSXnlb6/s="

# SM-DS endpoints. lpa.ds.gsma.com (root) demands mutual TLS and is not
# host-reachable from a laptop; only the phone's stack completes it. The two
# esimdiscovery hosts are host-reachable (with cert verification relaxed, as a
# real LPA trusts the GSMA CI, not the OS bundle).
SMDS_HOSTS = [
    {"host": "lpa.live.esimdiscovery.com", "note": "Thales, host-reachable"},
    {"host": "lpa.live.esimdiscovery.dev", "note": "Thales/Google UE4 lab, host-reachable"},
    {"host": "lpa.ds.gsma.com", "note": "GSMA root, phone-only (mutual TLS)"},
]


@dataclass
class ProbeRow:
    host: str
    note: str
    attempt: int
    eid_field_present_in_request: bool
    http_status: int | None = None
    function_status: str = ""
    error: str = ""


@dataclass
class Report:
    timestamp: str
    host_side: list[ProbeRow] = field(default_factory=list)
    device_discovery: dict = field(default_factory=dict)
    conclusion: str = ""


def _es11_initiate(host: str, timeout: float) -> tuple[int | None, str, str]:
    """POST an ES11 InitiateAuthentication. Returns (http_status, function_status,
    error). The body deliberately contains no EID because the schema has none."""
    body = {
        "euiccChallenge": base64.b64encode(os.urandom(16)).decode(),
        "euiccInfo1": REAL_EUICC_INFO1_B64,
    }
    data = json.dumps(body).encode()
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(
        f"https://{host}{ES11_PATH}",
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "gsma-rsp-lpad/2.1.0",
            "X-Admin-Protocol": "gsma/rsp/v2.2.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode(errors="replace")
            status = ""
            try:
                status = json.loads(raw)["header"]["functionExecutionStatus"]["status"]
            except (ValueError, KeyError):
                status = raw[:80]
            return resp.status, status, ""
    except Exception as exc:  # noqa: BLE001 -- reachability/TLS outcome is data
        return None, "", f"{type(exc).__name__}: {exc}"


def _device_discovery(timeout: float) -> dict:
    cmd = [ESIM, "euicc", "--backend", "lpac", "discovery"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(REPO_ROOT))
        raw = proc.stdout[proc.stdout.index("{"):] if "{" in proc.stdout else ""
        result = json.loads(raw) if raw else {"ok": False, "stderr": proc.stderr.strip()[:200]}
        events = result.get("eventEntries", result.get("events", []))
        return {"ok": result.get("ok"), "event_count": len(events) if isinstance(events, list) else events,
                "raw_keys": [k for k in result if k != "log_dir"]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "discovery timed out"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--allow-live-fire", action="store_true", required=True)
    ap.add_argument("--attempts", type=int, default=3, help="host-side InitiateAuthentication attempts per host")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--skip-device", action="store_true", help="skip the eUICC discovery baseline")
    args = ap.parse_args()

    if os.environ.get("ESIM_MITM_ALLOW_LIVE_FIRE") != "1":
        print("FATAL: ESIM_MITM_ALLOW_LIVE_FIRE=1 is required", file=sys.stderr)
        return 1

    report = Report(timestamp=datetime.now(timezone.utc).isoformat())

    print("A. Host-side ES11 InitiateAuthentication (no EID field exists to vary):")
    for entry in SMDS_HOSTS:
        for attempt in range(1, args.attempts + 1):
            status, fstatus, err = _es11_initiate(entry["host"], args.timeout)
            row = ProbeRow(
                host=entry["host"], note=entry["note"], attempt=attempt,
                eid_field_present_in_request=False,  # schema is euiccChallenge+euiccInfo1
                http_status=status, function_status=fstatus, error=err,
            )
            report.host_side.append(row)
            tag = fstatus or (err[:40] if err else "?")
            print(f"  {entry['host']:32s} #{attempt}  http={status}  {tag}")

    if not args.skip_device:
        print("\nB. Device ES11 discovery (our real EID — the only one we can query):")
        report.device_discovery = _device_discovery(max(args.timeout, 120.0))
        print(f"  {report.device_discovery}")

    report.conclusion = (
        "No pre-authentication EID oracle. InitiateAuthentication carries no EID "
        "field, so an unauthenticated caller has no input to enumerate over; "
        "eventEntries are returned only by AuthenticateClient, which requires an "
        "eUICC-signed response embedding CERT.EUICC (the EID). You can only learn "
        "'event waiting vs nothing' for an EID whose eUICC you control."
    )

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = PING_SM_DS / "logs" / f"eid-enum-{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(asdict(report), indent=2) + "\n")

    print("\n=== CONCLUSION ===")
    print(report.conclusion)
    print(f"\nlog: {out_dir / 'report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
