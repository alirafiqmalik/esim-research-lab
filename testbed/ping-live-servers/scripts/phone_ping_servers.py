#!/usr/bin/env python3
"""Ping SM-DP+/SM-DS servers with a *real* eUICC-authenticated request from the
phone, not a synthetic host-side POST.

Each target is probed with `esim euicc --backend lpac authenticate <fqdn>`, which
drives the Pixel's OpenEUICC through the real ES9+/ES11 handshake:

    ES10b GetEUICCChallenge  -> real euiccChallenge
    ES10b GetEUICCInfo1      -> real euiccInfo1 (real GSMA CI PKIDs)
    ES9+  InitiateAuthentication (over the phone's network + trust store)
    ES10b AuthenticateServer -> eUICC verifies the server's CERT.DPauth chain

A signed rejection is a valid outcome: it means the server was reached and the
eUICC evaluated its certificate. No profile is downloaded.

Runs serially -- one RSP session at a time on the single eUICC. The phone's own
network is the egress, so DNS/reachability differ from a host-side probe.

Requires (live fire to third-party production servers):
    ESIM_MITM_ALLOW_LIVE_FIRE=1
    --allow-live-fire

Run:
    ESIM_MITM_ALLOW_LIVE_FIRE=1 \
    ./venv/bin/python testbed/ping-live-servers/scripts/phone_ping_servers.py \
        --allow-live-fire
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
PING_LIVE_SERVERS = HERE.parent
REPO_ROOT = HERE.parents[2]

# Production SM-DP+/SM-DS the real eUICC can meaningfully evaluate. The dev/test
# endpoint lpa.live.esimdiscovery.dev is deliberately excluded: a production
# eUICC does not trust a test CI, so it would reject the server cert for a
# reason that says nothing about reachability.
TARGETS: list[dict] = [
    {"provider": "1GLOBAL", "host": "rsp.truphone.com", "type": "smdp"},
    {"provider": "Eastcom Peace", "host": "secsmsminiapp.eastcompeace.com", "type": "smdp"},
    {"provider": "Giesecke+Devrient", "host": "cust-003.oberthur.rsp.gieseckedevrient.com", "type": "smdp"},
    {"provider": "Giesecke+Devrient", "host": "prod.attesim.rsp.gieseckedevrient.com", "type": "smdp"},
    {"provider": "Idemia", "host": "t-mobile.idemia.io", "type": "smdp"},
    {"provider": "Idemia", "host": "rsp-3002.idemia.io", "type": "smdp"},
    {"provider": "Idemia", "host": "rsp-3036.idemia.io", "type": "smdp"},
    {"provider": "Idemia", "host": "rsp-4002.idemia.io", "type": "smdp"},
    {"provider": "Idemia", "host": "rsp-4008.idemia.io", "type": "smdp"},
    {"provider": "Idemia", "host": "celitech.idemia.io", "type": "smdp"},
    {"provider": "Kigen", "host": "smdp-plus-0.eu.cd.rsp.kigen.com", "type": "smdp"},
    {"provider": "Kigen", "host": "smdp-plus-1.eu.cd.rsp.kigen.com", "type": "smdp"},
    {"provider": "Linksfield", "host": "rsp-0001.linksfield.net", "type": "smdp"},
    {"provider": "Redtea Mobile", "host": "rsp-eu.redteamobile.com", "type": "smdp"},
    {"provider": "Valid", "host": "demo-consumer.validspereachdpplus.com", "type": "smdp"},
    {"provider": "Thales", "host": "lpa.ds.gsma.com", "type": "smds"},
    {"provider": "Thales", "host": "lpa.live.esimdiscovery.com", "type": "smds"},
]

# Plaintext ES9+ markers OpenEUICC's HttpInterfaceImpl logs. Kept narrow so the
# extracted transcript is the RSP exchange, not the whole logcat.
_RSP_LINE = re.compile(
    r"HttpInterfaceImpl|initiateAuthentication|authenticateClient|"
    r"serverSigned1|serverCertificate|transactionId|euiccChallenge|"
    r"functionExecutionStatus"
)


@dataclass
class ProbeResult:
    provider: str
    host: str
    type: str
    timestamp: str
    auth_rc: int | None = None
    ci_trusted: bool | None = None
    stage: str = ""
    ok: bool = False
    http_status: str = ""
    server_cert_subject: str = ""
    outcome: str = "unknown"
    error: str = ""
    log_dir: str = ""
    elapsed_seconds: float = 0.0


def _run_authenticate(host: str, backend: str, timeout: float) -> dict:
    cmd = [
        str(REPO_ROOT / "venv" / "bin" / "esim"),
        "euicc", "--backend", backend, "authenticate", host,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(REPO_ROOT))
    stdout = proc.stdout.strip()
    if not stdout:
        raise RuntimeError(f"harness produced no JSON (rc={proc.returncode}): {proc.stderr.strip()[:200]}")
    # The harness prints one JSON object; take the last brace-balanced blob.
    start = stdout.rfind("\n{")
    blob = stdout[start + 1:] if start != -1 else stdout
    return json.loads(blob)


def _extract_transcript(log_dir: Path, dest: Path) -> tuple[str, str]:
    """Copy the RSP-relevant plaintext lines out of the raw logcat. Returns
    (http_status, server_cert_subject) parsed from the response body."""
    logcat = log_dir / "logcat.txt"
    http_status = ""
    cert_subject = ""
    if not logcat.exists():
        return http_status, cert_subject

    kept: list[str] = []
    for line in logcat.read_text(errors="replace").splitlines():
        if _RSP_LINE.search(line):
            kept.append(line)
            if "functionExecutionStatus" in line:
                m = re.search(r'"status"\s*:\s*"([^"]+)"', line)
                if m:
                    http_status = m.group(1)
            if "serverCertificate" in line and not cert_subject:
                cert_subject = _decode_cert_subject(line)

    dest.write_text("\n".join(kept) + "\n" if kept else "(no RSP plaintext captured)\n")
    return http_status, cert_subject


def _decode_cert_subject(line: str) -> str:
    import base64

    m = re.search(r'"serverCertificate"\s*:\s*"([A-Za-z0-9+/=]+)"', line)
    if not m:
        return ""
    try:
        der = base64.b64decode(m.group(1))
    except (ValueError, TypeError):
        return ""
    # Cheap DER scan: pull printable CN-ish strings without an ASN.1 lib.
    strings = re.findall(rb"[ -~]{4,}", der)
    for s in reversed(strings):
        text = s.decode("ascii", "ignore")
        if "SM-DP" in text or "SM-DS" in text:
            return text
    return strings[-1].decode("ascii", "ignore") if strings else ""


def _classify(result: dict) -> tuple[str, str]:
    """Map the harness result to a coarse outcome label.

    Order matters: a failed InitiateAuthentication (the ES9+ HTTP call threw,
    no response body) leaves ciTrusted at its default False. That is a network
    failure, not a CI-distrust verdict -- so the stage is checked before
    ciTrusted, and ci_untrusted is only claimed when the eUICC actually
    evaluated the server cert."""
    stage = result.get("stage", "")
    ci = result.get("ciTrusted")
    if result.get("ok") and stage == "accepted":
        return "accepted", ""
    if stage == "initiateAuthentication_failed":
        return "initiate_failed", stage  # server not reached / no ES9+ response
    if ci is False and stage:
        return "ci_untrusted", stage  # reached, but eUICC rejected the cert chain
    if stage in ("rejected", "server-rejected"):
        return "server_rejected", stage
    if "error" in result:
        return "error", str(result.get("error", ""))
    return stage or "unknown", str(result.get("error", ""))


def probe(target: dict, out_logs: Path, backend: str, timeout: float) -> ProbeResult:
    started = datetime.now(timezone.utc)
    res = ProbeResult(
        provider=target["provider"],
        host=target["host"],
        type=target["type"],
        timestamp=started.isoformat(),
    )
    try:
        raw = _run_authenticate(target["host"], backend, timeout)
        res.auth_rc = raw.get("authRc")
        res.ci_trusted = raw.get("ciTrusted")
        res.stage = raw.get("stage", "")
        res.ok = bool(raw.get("ok"))
        res.log_dir = raw.get("log_dir", "")
        res.outcome, detail = _classify(raw)
        if detail:
            res.error = detail

        if res.log_dir:
            src = Path(res.log_dir)
            dest_dir = out_logs / target["host"]
            dest_dir.mkdir(parents=True, exist_ok=True)
            (dest_dir / "harness-result.json").write_text(json.dumps(raw, indent=2) + "\n")
            res.http_status, res.server_cert_subject = _extract_transcript(
                src, dest_dir / "es9plus-transcript.txt"
            )
    except subprocess.TimeoutExpired:
        res.outcome = "timeout"
        res.error = f"harness exceeded {timeout:.0f}s"
    except Exception as exc:  # noqa: BLE001 -- record and continue the sweep
        res.outcome = "harness_error"
        res.error = f"{type(exc).__name__}: {exc}"

    res.elapsed_seconds = (datetime.now(timezone.utc) - started).total_seconds()
    return res


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--allow-live-fire", action="store_true", required=True)
    parser.add_argument("--backend", default="lpac", choices=["lpac", "fw", "ui"])
    parser.add_argument("--timeout", type=float, default=150.0, help="per-server harness timeout")
    parser.add_argument("--provider", default=None, help="filter by provider substring")
    args = parser.parse_args()

    if os.environ.get("ESIM_MITM_ALLOW_LIVE_FIRE") != "1":
        print("FATAL: ESIM_MITM_ALLOW_LIVE_FIRE=1 is required", file=sys.stderr)
        return 1

    targets = TARGETS
    if args.provider:
        targets = [t for t in TARGETS if args.provider.lower() in t["provider"].lower()]
        if not targets:
            print(f"No targets match {args.provider!r}", file=sys.stderr)
            return 1

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_logs = PING_LIVE_SERVERS / "logs" / f"phone-authenticate-{ts}"
    out_logs.mkdir(parents=True, exist_ok=True)
    jsonl_path = out_logs / "results.jsonl"

    print(f"Phone-driven AuthenticateServer probe -- {len(targets)} production endpoints (serial)")
    print(f"Backend: {args.backend}   Logs: {out_logs}")
    print()

    results: list[ProbeResult] = []
    with open(jsonl_path, "w") as f:
        for target in targets:
            label = f"{target['provider']} @ {target['host']}"
            print(f"  [{label}] ...", end=" ", flush=True)
            res = probe(target, out_logs, args.backend, args.timeout)
            results.append(res)
            f.write(json.dumps(asdict(res)) + "\n")
            f.flush()

            tag = res.outcome.upper()
            extra = res.http_status or res.error[:60]
            print(f"{tag}" + (f" ({extra})" if extra else ""))

    _summarize(results, out_logs)
    return 0


def _summarize(results: list[ProbeResult], out_logs: Path) -> None:
    buckets: dict[str, list[ProbeResult]] = {}
    for r in results:
        buckets.setdefault(r.outcome, []).append(r)

    lines: list[str] = []
    lines.append("=== SUMMARY ===")
    lines.append(f"  Endpoints probed: {len(results)}")
    for outcome in sorted(buckets):
        lines.append(f"  {outcome:16s}: {len(buckets[outcome])}")
    lines.append("")

    accepted = buckets.get("accepted", [])
    if accepted:
        lines.append("eUICC accepted the server cert (valid authenticated request):")
        for r in accepted:
            subj = f" [{r.server_cert_subject}]" if r.server_cert_subject else ""
            lines.append(f"  {r.provider} @ {r.host} -> {r.http_status or 'reached'}{subj}")
        lines.append("")

    unreached = [r for r in results if r.outcome in ("initiate_failed", "timeout", "harness_error", "error")]
    if unreached:
        lines.append("Not reached / no eUICC evaluation:")
        for r in unreached:
            lines.append(f"  {r.provider} @ {r.host}: {r.outcome} ({r.error[:80]})")
        lines.append("")

    report = "\n".join(lines)
    print()
    print(report)
    (out_logs / "summary.txt").write_text(report + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
