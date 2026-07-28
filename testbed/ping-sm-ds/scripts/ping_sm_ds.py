#!/usr/bin/env python3
"""Ping the SM-DS (discovery) servers from the phone's real eUICC.

Two ES11 probes per SM-DS, both driven through the Pixel's OpenEUICC:

  authenticate  ES11 InitiateAuthentication + ES10b AuthenticateServer.
                Proves the SM-DS is reached and its cert chains to a CI the
                eUICC trusts (ciTrusted / stage=accepted).
  discovery     ES11 discovery lookup keyed by our EID. Returns eventEntries
                (eID/matchingId -> SM-DP+ routing). Empty is the expected
                outcome for an EID with no pending registered events.

No profile is downloaded or changed; discovery and authenticate are read-only
queries. Egress is the phone's network, so DNS/reachability differ from the host.

Requires (live queries to third-party production servers):
    ESIM_MITM_ALLOW_LIVE_FIRE=1
    --allow-live-fire

Run:
    ESIM_MITM_ALLOW_LIVE_FIRE=1 \
    ./venv/bin/python testbed/ping-sm-ds/scripts/ping_sm_ds.py --allow-live-fire
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
PING_SM_DS = HERE.parent
REPO_ROOT = HERE.parents[2]
ESIM = str(REPO_ROOT / "venv" / "bin" / "esim")

# The GSMA root SM-DS is the consumer bootstrap directory every production eUICC
# queries; our eUICC's ES10a GetEuiccConfiguredAddresses reports it as the root.
# The Thales esimdiscovery hosts are the other public SM-DS instances. The
# Truphone/Redtea profiles use direct SM-DP+ activation codes, so their discovery
# path is this shared root SM-DS, not a per-brand SM-DS.
TARGETS: list[dict] = [
    {"provider": "GSMA (root)", "host": "lpa.ds.gsma.com", "kind": "root-smds", "ci": "production"},
    {"provider": "Thales", "host": "lpa.live.esimdiscovery.com", "kind": "smds", "ci": "production"},
    {"provider": "Thales", "host": "lpa.live.esimdiscovery.dev", "kind": "smds-dev", "ci": "test"},
]


@dataclass
class SmDsResult:
    provider: str
    host: str
    kind: str
    ci: str
    timestamp: str
    auth_rc: int | None = None
    ci_trusted: bool | None = None
    auth_stage: str = ""
    auth_outcome: str = "unknown"
    discovery_ok: bool | None = None
    event_count: int | None = None
    events: list[dict] = field(default_factory=list)
    error: str = ""


def _run(op_args: list[str], timeout: float) -> tuple[dict, str]:
    cmd = [ESIM, "euicc", "--backend", "lpac", *op_args]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(REPO_ROOT))
    raw = proc.stdout[proc.stdout.index("{"):] if "{" in proc.stdout else ""
    result = json.loads(raw) if raw else {"ok": False, "stderr": proc.stderr.strip()[:400]}
    return result, result.get("log_dir", "")


def _capture(log_dir: str, dest: Path) -> None:
    if not log_dir or not Path(log_dir).exists():
        return
    dest.mkdir(parents=True, exist_ok=True)
    for fname in ("logcat.txt", "rsp.json"):
        src = Path(log_dir) / fname
        if src.exists():
            shutil.copy2(src, dest / fname)


def _classify_auth(res: dict) -> tuple[str, str]:
    stage = res.get("stage", "")
    if res.get("ok") and stage == "accepted":
        return "accepted", stage
    if stage == "initiateAuthentication_failed":
        return "initiate_failed", stage
    if res.get("ciTrusted") is False and stage:
        return "ci_untrusted", stage
    return stage or "unknown", stage


def probe(target: dict, out_dir: Path, timeout: float) -> SmDsResult:
    host = target["host"]
    r = SmDsResult(
        provider=target["provider"], host=host, kind=target["kind"], ci=target["ci"],
        timestamp=datetime.now().astimezone().isoformat(),
    )
    dest = out_dir / host

    try:
        auth, auth_log = _run(["authenticate", host], timeout)
        _capture(auth_log, dest / "authenticate")
        r.auth_rc = auth.get("authRc")
        r.ci_trusted = auth.get("ciTrusted")
        r.auth_stage = auth.get("stage", "")
        r.auth_outcome, _ = _classify_auth(auth)
    except subprocess.TimeoutExpired:
        r.auth_outcome = "timeout"
        r.error = f"authenticate exceeded {timeout:.0f}s"

    try:
        disc, disc_log = _run(["discovery", "--smds", host], timeout)
        _capture(disc_log, dest / "discovery")
        r.discovery_ok = bool(disc.get("ok"))
        r.events = disc.get("events", []) or []
        r.event_count = disc.get("count", len(r.events))
        if not r.discovery_ok and not r.error:
            r.error = str(disc.get("stderr") or disc.get("error") or "")[:200]
    except subprocess.TimeoutExpired:
        r.discovery_ok = False
        if not r.error:
            r.error = f"discovery exceeded {timeout:.0f}s"

    return r


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--allow-live-fire", action="store_true", required=True)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--host", default=None, help="probe only this SM-DS host")
    args = ap.parse_args()

    if os.environ.get("ESIM_MITM_ALLOW_LIVE_FIRE") != "1":
        print("FATAL: ESIM_MITM_ALLOW_LIVE_FIRE=1 is required", file=sys.stderr)
        return 1

    targets = [t for t in TARGETS if not args.host or t["host"] == args.host]
    if not targets:
        print(f"No SM-DS target matches {args.host!r}", file=sys.stderr)
        return 1

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = PING_SM_DS / "logs" / f"smds-{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl = out_dir / "results.jsonl"

    print(f"SM-DS probe — {len(targets)} servers (authenticate + ES11 discovery)")
    print(f"Logs: {out_dir}\n")

    results: list[SmDsResult] = []
    with open(jsonl, "w") as f:
        for t in targets:
            print(f"  [{t['provider']} @ {t['host']}] ...", end=" ", flush=True)
            r = probe(t, out_dir, args.timeout)
            results.append(r)
            f.write(json.dumps(asdict(r)) + "\n")
            f.flush()
            print(f"auth={r.auth_outcome} discovery={'ok' if r.discovery_ok else 'fail'} "
                  f"events={r.event_count}")

    _summarize(results, out_dir)
    return 0


def _summarize(results: list[SmDsResult], out_dir: Path) -> None:
    lines = ["=== SM-DS SUMMARY ===", f"  servers probed: {len(results)}", ""]
    for r in results:
        lines.append(f"  {r.provider} @ {r.host}  [{r.ci} CI, {r.kind}]")
        lines.append(f"      authenticate : {r.auth_outcome}"
                     + (f" (ciTrusted={r.ci_trusted}, stage={r.auth_stage})" if r.auth_stage else ""))
        disc = "ok" if r.discovery_ok else "fail"
        lines.append(f"      discovery    : {disc}, events={r.event_count}")
        if r.error:
            lines.append(f"      note         : {r.error}")
        lines.append("")
    report = "\n".join(lines)
    print()
    print(report)
    (out_dir / "summary.txt").write_text(report + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
