#!/usr/bin/env python3
"""Trigger a profile download three ways for one activation string:

    a) harness   — esim euicc download 'LPA:1$...'   (lpac/fw backend)
    b) intent    — Android VIEW intent on the LPA: URI (on-device LPA handler)
    c) manual    — printed steps for typing the SM-DP+ address + matching code

All three converge on the same ES9+ flow; they differ only in how the activation
string reaches the LPA (see notes/02-delivery-methods.md).

SAFETY: methods (a) and (b) install a real profile via live RSP. They run ONLY
when all gates are present:

    ESIM_MITM_ALLOW_LIVE_FIRE=1  --allow-live-fire  --i-understand-real-profile

Without them, or with --dry-run, it prints the plan for all three and fires
nothing. Method (c) is always instructions only.

Run (dry run, safe):
    ./venv/bin/python testbed/profile-delivery/scripts/trigger_download.py \
        --lpa 'LPA:1$rsp.truphone.com$QRF-SPEEDTEST'
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
CATALOG_JSONL = REPO_ROOT / "testbed" / "profile-download" / "catalog" / "profiles.jsonl"
ESIM = str(REPO_ROOT / "venv" / "bin" / "esim")


@dataclass(frozen=True)
class Activation:
    lpa: str
    smdp: str
    matching_id: str


def parse_activation(lpa: str) -> Activation:
    if not lpa.startswith("LPA:1$"):
        raise ValueError(f"not an LPA:1$ string: {lpa!r}")
    parts = lpa.split("$")
    if len(parts) < 3 or not parts[1] or not parts[2]:
        raise ValueError(f"expected LPA:1$<smdp>$<matchingId>: {lpa!r}")
    return Activation(lpa=lpa, smdp=parts[1], matching_id=parts[2])


def resolve(lpa: str | None, brand: str | None) -> Activation:
    if lpa:
        return parse_activation(lpa)
    if brand:
        catalog = [json.loads(x) for x in CATALOG_JSONL.read_text().splitlines() if x.strip()]
        hits = [e for e in catalog if brand.lower() in e["brand"].lower()]
        if not hits:
            raise ValueError(f"no catalog brand matches {brand!r}")
        if len({e["full_lpa_string"] for e in hits}) > 1:
            raise ValueError(f"brand {brand!r} is ambiguous; use --lpa")
        return parse_activation(hits[0]["full_lpa_string"])
    raise ValueError("provide --lpa or --brand")


def harness_cmd(act: Activation, backend: str) -> list[str]:
    return [ESIM, "euicc", "--backend", backend, "download", act.lpa]


def intent_cmd(act: Activation, serial: str | None) -> list[str]:
    # Android routes an LPA: URI to the system eSIM handler via a VIEW intent.
    base = ["adb"] + (["-s", serial] if serial else [])
    return base + ["shell", "am", "start", "-a", "android.intent.action.VIEW", "-d", act.lpa]


def manual_steps(act: Activation) -> list[str]:
    return [
        "Open the LPA. Add/download profile, then manual entry (not scan).",
        f"SM-DP+ address field: {act.smdp}   (host only, no LPA: / 1$ / ://)",
        f"Activation/matching code field: {act.matching_id}",
        "Confirmation code: leave empty.",
        "Start the download.",
    ]


def print_plan(act: Activation, backend: str, serial: str | None) -> None:
    print(f"Activation: {act.lpa}")
    print(f"  SM-DP+: {act.smdp}   matchingId: {act.matching_id}\n")
    print("a) harness:")
    print("   " + " ".join(harness_cmd(act, backend)))
    print("\nb) Android VIEW intent (on-device LPA handler):")
    print("   " + " ".join(intent_cmd(act, serial)))
    print("   (framework path alternative: EuiccManager.downloadSubscription(DownloadableSubscription))")
    print("\nc) manual entry:")
    for i, step in enumerate(manual_steps(act), 1):
        print(f"   {i}. {step}")


def run(cmd: list[str], timeout: float) -> int:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    sys.stdout.write(proc.stdout)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
    return proc.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lpa")
    parser.add_argument("--brand")
    parser.add_argument("--method", choices=["harness", "intent", "manual"], help="which trigger to fire")
    parser.add_argument("--backend", default="lpac", choices=["lpac", "fw", "ui"])
    parser.add_argument("--serial", default=None, help="adb serial for the intent method")
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--allow-live-fire", action="store_true")
    parser.add_argument("--i-understand-real-profile", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        act = resolve(args.lpa, args.brand)
    except (ValueError, FileNotFoundError) as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 1

    gates_ok = (
        os.environ.get("ESIM_MITM_ALLOW_LIVE_FIRE") == "1"
        and args.allow_live_fire
        and args.i_understand_real_profile
    )

    if args.method == "manual":
        print(f"Manual entry for {act.lpa}:\n")
        for i, step in enumerate(manual_steps(act), 1):
            print(f"  {i}. {step}")
        return 0

    if args.dry_run or not args.method or not gates_ok:
        print("DRY RUN — no live actions.\n")
        print_plan(act, args.backend, args.serial)
        if args.method in ("harness", "intent") and not gates_ok and not args.dry_run:
            print("\nGates not set: ESIM_MITM_ALLOW_LIVE_FIRE=1 --allow-live-fire --i-understand-real-profile")
        return 0

    cmd = harness_cmd(act, args.backend) if args.method == "harness" else intent_cmd(act, args.serial)
    print(f"LIVE {args.method}: {' '.join(cmd)}\n")
    return run(cmd, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
