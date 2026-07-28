#!/usr/bin/env python3
"""Exercise and log every device <-> SM-DP+ (ES9+) message-flow procedure against
the live servers we hold consumer test profiles for (Truphone, Redtea).

The five ES9+ procedures:
    1. InitiateAuthentication      2. AuthenticateClient
    3. GetBoundProfilePackage      4. HandleNotification
    5. CancelSession

Procedures 1-4 are driven by a real profile download (`esim euicc download`),
which emits them in order; the parsed exchange is in the harness `rsp.json`.
Procedure 5 (CancelSession) is NOT reachable from the automated lpac path -- the
LPA only emits it on a user-declined confirmation or an SM-DP+ abort, neither of
which the headless download triggers. It is reported as not-captured, with a
pointer to where it is modeled (testbed/ecosim, ping-live-servers/src/models.py).

Per server: run `authenticate` (CI-trust + InitiateAuthentication), then a clean
`download` (delete any already-installed instance first so the download runs
fresh, which also restores it), then classify each captured procedure. Originals
are restored at the end.

Read/idempotent for Truphone (deletes then re-downloads the same fixed profile).
Redtea's free pool is exhausted, so its download fails at AuthenticateClient --
a valid captured outcome.

Gated:
    ESIM_MITM_ALLOW_LIVE_FIRE=1  --allow-live-fire  --i-understand-real-profile
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "profile-download" / "scripts"))
from download_lifecycle import Runner  # noqa: E402

ES9_FLOW = HERE.parent
REPO_ROOT = HERE.parents[2]

ES9_PROCEDURES = [
    "initiateAuthentication",
    "authenticateClient",
    "getBoundProfilePackage",
    "handleNotification",
    "cancelSession",
]

SERVERS = [
    {"provider": "1GLOBAL (Truphone)", "host": "rsp.truphone.com",
     "brand": "Speedtest", "lpa": "LPA:1$rsp.truphone.com$QRF-SPEEDTEST"},
    {"provider": "Redtea Mobile", "host": "rsp-eu.redteamobile.com",
     "brand": "RedteaGO", "lpa": "LPA:1$rsp-eu.redteamobile.com$5901981126831169"},
]

# Original profiles to guarantee restored at the end (iccid -> restore code).
RESTORE = {
    "8944476500015198679": "LPA:1$rsp.truphone.com$QRF-SPEEDTEST",
    "8944476500015257715": "LPA:1$rsp.truphone.com$QRF-BETTERROAMING-PMRDGIR2EARDEIT5",
}


@dataclass
class ServerCapture:
    provider: str
    host: str
    lpa: str
    ci_trusted: bool | None = None
    auth_stage: str = ""
    download_ok: bool = False
    downloaded_iccid: str | None = None
    procedures: dict = field(default_factory=dict)


def _index_of(profs: list[dict], iccid: str) -> int | None:
    for i, p in enumerate(profs):
        if p["iccid"] == iccid:
            return i + 1
    return None


_RE_STATUS = re.compile(r'"status"\s*:\s*"([^"]+)"')


def _scd_field(blob: str, name: str) -> str:
    m = re.search(r'"%s"\s*:\s*"([^"]*)"' % name, blob)
    return m.group(1) if m else ""


def parse_procedures(dl_result: dict) -> dict:
    """Pair each es9plus request URL with the next response body, extracting the
    function status and any reason code. Uses regex, not json.loads: the harness
    truncates large response bodies (~600 chars), so the cert/BPP blobs make the
    JSON incomplete, but `status` and `statusCodeData` sit at the front."""
    out: dict = {}
    current: str | None = None
    for item in dl_result.get("rsp", []) or []:
        kind, val = item.get("kind"), item.get("value", "")
        if kind == "request-url" and "es9plus/" in val:
            current = val.rsplit("es9plus/", 1)[-1]
            out.setdefault(current, {"seen": True, "status": "", "reason": ""})
        elif kind == "response-body" and current:
            m = _RE_STATUS.search(val)
            if m:
                out[current]["status"] = m.group(1)
            if '"statusCodeData"' in val:
                out[current]["reason"] = (
                    f"{_scd_field(val, 'subjectCode')}/{_scd_field(val, 'reasonCode')} "
                    f"{_scd_field(val, 'subjectIdentifier')} {_scd_field(val, 'message')}"
                ).strip()
            current = None
    return out


def capture_server(runner: Runner, server: dict) -> ServerCapture:
    cap = ServerCapture(provider=server["provider"], host=server["host"], lpa=server["lpa"])

    auth = runner.call("01-authenticate", ["authenticate", server["host"]])
    cap.ci_trusted = auth.get("ciTrusted")
    cap.auth_stage = auth.get("stage", "")

    # Clean slate: delete any installed instance of this brand so the download
    # runs the full chain fresh (and, for a fixed profile, restores it).
    for _ in range(5):
        profs = runner.list_profiles("02-preclean-list")
        match = next((p for p in profs
                      if server["brand"].lower() in f"{p.get('provider','')} {p.get('name','')}".lower()), None)
        if not match:
            break
        idx = _index_of(profs, match["iccid"])
        runner.call("02-preclean-del", ["delete", str(idx), "--yes", "--force"])

    before = runner.list_iccids("03-before-download")
    dl = runner.call("04-download", ["download", server["lpa"]])
    cap.download_ok = bool(dl.get("ok"))
    new = runner.list_iccids("05-after-download") - before
    cap.downloaded_iccid = sorted(new)[0] if new else None
    cap.procedures = parse_procedures(dl)
    return cap


def restore_originals(runner: Runner) -> list[str]:
    current = runner.list_iccids("restore-check")
    restored = []
    for iccid, code in RESTORE.items():
        if iccid not in current:
            runner.call(f"restore-{iccid[-4:]}", ["download", code])
            restored.append(iccid)
    return restored


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", default="lpac", choices=["lpac", "fw", "ui"])
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("--allow-live-fire", action="store_true")
    ap.add_argument("--i-understand-real-profile", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    gates_ok = (os.environ.get("ESIM_MITM_ALLOW_LIVE_FIRE") == "1"
                and args.allow_live_fire and args.i_understand_real_profile)
    if args.dry_run or not gates_ok:
        print("DRY RUN — would probe ES9+ flow against:")
        for s in SERVERS:
            print(f"  {s['provider']:20s} authenticate + download {s['lpa']}")
        if not gates_ok and not args.dry_run:
            print("\nGates: ESIM_MITM_ALLOW_LIVE_FIRE=1 --allow-live-fire --i-understand-real-profile")
        return 0

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = ES9_FLOW / "logs" / f"es9-flow-{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"ES9+ message-flow probe. Logs: {out_dir}\n")

    caps: list[ServerCapture] = []
    for server in SERVERS:
        print(f"  [{server['provider']}] authenticate + download ...", flush=True)
        runner = Runner(out_dir / server["host"], args.backend, args.timeout)
        cap = capture_server(runner, server)
        caps.append(cap)
        for proc in ES9_PROCEDURES:
            info = cap.procedures.get(proc)
            if info and info["status"]:
                tag = info["status"] + (f" ({info['reason']})" if info["reason"] else "")
            elif info:
                tag = "sent (HTTP 204 ack, no status body)"
            elif proc == "cancelSession":
                tag = "not captured (LPA emits only on decline/abort)"
            else:
                tag = "not reached"
            print(f"      {proc:24s} {tag}")

    meta = Runner(out_dir / "_restore", args.backend, args.timeout)
    restored = restore_originals(meta)
    if restored:
        print(f"\nRestored originals: {restored}")

    coverage = {
        "timestamp": ts,
        "servers": [asdict(c) for c in caps],
        "final_installed": sorted(meta.list_iccids("final")),
        "cancelSession_note": ("Not device-triggerable via lpac; LPA emits it only on user-declined "
                               "confirmation or SM-DP+ abort. Modeled in ecosim + ping-live-servers/src/models.py."),
    }
    (out_dir / "coverage.json").write_text(json.dumps(coverage, indent=2) + "\n")

    print("\n=== COVERAGE MATRIX (procedure x server) ===")
    header = "  {:24s}".format("procedure") + "".join(f"{c.host[:22]:24s}" for c in caps)
    print(header)
    for proc in ES9_PROCEDURES:
        row = f"  {proc:24s}"
        for c in caps:
            info = c.procedures.get(proc)
            if info and info["status"]:
                cell = info["status"]
            elif info:
                cell = "sent (204)"
            else:
                cell = "n/a" if proc == "cancelSession" else "-"
            row += f"{cell:24s}"
        print(row)
    print(f"\n  final installed: {coverage['final_installed']}")
    print(f"  full coverage: {out_dir / 'coverage.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
