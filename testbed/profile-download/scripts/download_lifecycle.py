#!/usr/bin/env python3
"""Download / delete / re-download lifecycle for ONE test profile, with full
per-step logging.

Sequence:
    0. snapshot   list installed profiles (before)
    1. acquire    if --target-iccid given, use that installed profile as A;
                  else download(lpa) and detect the new iccid as A
    2. delete     delete profile A, verify it is gone
    3. redownload download(lpa) again, detect iccid B, verify installed
    4. snapshot   list installed profiles (after) + summary (A vs B)

Every harness call's JSON and its captured ES9+ RSP log dir are saved under
logs/<ts>-lifecycle-<label>/.

SAFETY: this fires live RSP downloads at a production SM-DP+ and installs/removes
a real profile on the phone. It runs ONLY when all three gates are present:

    ESIM_MITM_ALLOW_LIVE_FIRE=1        (env)
    --allow-live-fire                  (flag)
    --i-understand-real-profile        (flag)

Without all three it prints the ordered plan and exits (dry run). --dry-run
forces the plan-only path even if the gates are set.

Run (dry run, safe):
    ./venv/bin/python testbed/profile-download/scripts/download_lifecycle.py \
        --lpa 'LPA:1$rsp.truphone.com$QRF-SPEEDTEST'
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE_DOWNLOAD = HERE.parent
REPO_ROOT = HERE.parents[2]
CATALOG_JSONL = PROFILE_DOWNLOAD / "catalog" / "profiles.jsonl"
ESIM = str(REPO_ROOT / "venv" / "bin" / "esim")


class LifecycleError(RuntimeError):
    pass


def _catalog() -> list[dict]:
    return [json.loads(l) for l in CATALOG_JSONL.read_text().splitlines() if l.strip()]


def resolve_lpa(lpa: str | None, brand: str | None) -> tuple[str, str]:
    """Return (lpa_string, label). Either an explicit --lpa or a --brand lookup."""
    if lpa:
        label = lpa.split("$")[-1][:24]
        return lpa, label
    if brand:
        hits = [e for e in _catalog() if brand.lower() in e["brand"].lower()]
        if not hits:
            raise LifecycleError(f"no catalog brand matches {brand!r}")
        if len({e["full_lpa_string"] for e in hits}) > 1:
            opts = ", ".join(e["full_lpa_string"] for e in hits)
            raise LifecycleError(f"brand {brand!r} is ambiguous: {opts}; use --lpa")
        return hits[0]["full_lpa_string"], hits[0]["brand"]
    raise LifecycleError("provide --lpa or --brand")


class Runner:
    def __init__(self, out_dir: Path, backend: str, timeout: float) -> None:
        self._out = out_dir
        self._backend = backend
        self._timeout = timeout
        self._steps_log = out_dir / "steps.jsonl"
        self._n = 0
        out_dir.mkdir(parents=True, exist_ok=True)

    def call(self, step: str, op_args: list[str]) -> dict:
        self._n += 1
        cmd = [ESIM, "euicc", "--backend", self._backend, *op_args]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self._timeout, cwd=str(REPO_ROOT))
        raw = proc.stdout[proc.stdout.index("{"):] if "{" in proc.stdout else ""
        result = json.loads(raw) if raw else {"ok": False, "stderr": proc.stderr.strip()[:400]}

        record = {"step": step, "n": self._n, "cmd": op_args, "returncode": proc.returncode, "result": result}
        with open(self._steps_log, "a") as f:
            f.write(json.dumps(record) + "\n")

        log_dir = result.get("log_dir")
        if log_dir and Path(log_dir).exists():
            dest = self._out / f"{self._n:02d}-{step}"
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "result.json").write_text(json.dumps(result, indent=2) + "\n")
            # logcat.txt is the raw capture; rsp.json is the parsed ES9+ chain
            # (initiateAuthentication -> authenticateClient -> getBoundProfilePackage
            # -> handleNotification) and is the higher-value artifact for downloads.
            for fname in ("logcat.txt", "rsp.json"):
                src = Path(log_dir) / fname
                if src.exists():
                    shutil.copy2(src, dest / fname)
        return result

    def list_profiles(self, step: str) -> list[dict]:
        return self.call(step, ["list"]).get("profiles", [])

    def list_iccids(self, step: str) -> set[str]:
        return {p["iccid"] for p in self.list_profiles(step)}


def _plan(lpa: str, target_iccid: str | None) -> list[str]:
    steps = ["0. list (snapshot before)"]
    if target_iccid:
        steps.append(f"1. acquire: use installed profile A = {target_iccid}")
    else:
        steps.append(f"1. acquire: download {lpa}  -> detect new iccid A")
    steps += [
        "2. delete profile A (--yes), verify gone",
        f"3. redownload {lpa}  -> detect iccid B, verify installed",
        "4. list (snapshot after) + summary (A vs B)",
    ]
    return steps


def run_lifecycle(runner: Runner, lpa: str, target_iccid: str | None, force_delete: bool) -> dict:
    before = runner.list_iccids("00-snapshot-before")

    if target_iccid:
        if target_iccid not in before:
            raise LifecycleError(f"--target-iccid {target_iccid} is not installed")
        iccid_a = target_iccid
    else:
        runner.call("01-download-A", ["download", lpa])
        after_dl = runner.list_iccids("02-verify-A")
        new = after_dl - before
        if not new:
            raise LifecycleError("download did not add a profile (see logs)")
        iccid_a = sorted(new)[0]

    # The harness `delete` takes a 1-based LIST INDEX, not an ICCID
    # (_do_delete does int(target)-1). Resolve the index immediately before
    # deleting so it reflects the current list order.
    profs = runner.list_profiles("03a-index-lookup")
    idx = next((i + 1 for i, p in enumerate(profs) if p["iccid"] == iccid_a), None)
    if idx is None:
        raise LifecycleError(f"profile {iccid_a} not in list before delete")
    del_args = ["delete", str(idx), "--yes"] + (["--force"] if force_delete else [])
    runner.call("03-delete-A", del_args)
    after_del = runner.list_iccids("04-verify-deleted")
    if iccid_a in after_del:
        raise LifecycleError(f"profile {iccid_a} still present after delete")

    runner.call("05-redownload", ["download", lpa])
    after_re = runner.list_iccids("06-verify-B")
    new_b = after_re - after_del
    if not new_b:
        raise LifecycleError("re-download did not add a profile (see logs)")
    iccid_b = sorted(new_b)[0]

    return {
        "lpa": lpa,
        "iccid_A": iccid_a,
        "iccid_B": iccid_b,
        "same_iccid": iccid_a == iccid_b,
        "installed_before": sorted(before),
        "installed_after": sorted(after_re),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lpa", help="full LPA activation string")
    ap.add_argument("--brand", help="catalog brand to look up instead of --lpa")
    ap.add_argument("--target-iccid", help="ICCID of an already-installed matching profile to start from")
    ap.add_argument("--backend", default="lpac", choices=["lpac", "fw", "ui"])
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("--force", action="store_true", help="pass --force to delete (override guards)")
    ap.add_argument("--allow-live-fire", action="store_true")
    ap.add_argument("--i-understand-real-profile", action="store_true",
                    help="acknowledge this installs/removes a real profile via live RSP")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and exit")
    args = ap.parse_args()

    try:
        lpa, label = resolve_lpa(args.lpa, args.brand)
    except LifecycleError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 1

    gates_ok = (
        os.environ.get("ESIM_MITM_ALLOW_LIVE_FIRE") == "1"
        and args.allow_live_fire
        and args.i_understand_real_profile
    )
    if args.dry_run or not gates_ok:
        print("DRY RUN — no live actions. Planned sequence:")
        for line in _plan(lpa, args.target_iccid):
            print(f"  {line}")
        if not gates_ok and not args.dry_run:
            print("\nGates not all set. To execute, provide:")
            print("  ESIM_MITM_ALLOW_LIVE_FIRE=1  --allow-live-fire  --i-understand-real-profile")
        return 0

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = PROFILE_DOWNLOAD / "logs" / f"{ts}-lifecycle-{label}"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"LIVE lifecycle for {lpa}")
    print(f"Logs: {out_dir}\n")

    runner = Runner(out_dir, args.backend, args.timeout)
    try:
        summary = run_lifecycle(runner, lpa, args.target_iccid, args.force)
    except (LifecycleError, subprocess.TimeoutExpired) as exc:
        print(f"\nABORTED: {exc}", file=sys.stderr)
        (out_dir / "summary.json").write_text(json.dumps({"error": str(exc)}, indent=2) + "\n")
        return 2

    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("\n=== SUMMARY ===")
    print(f"  activation code : {summary['lpa']}")
    print(f"  profile A (pre-delete) : {summary['iccid_A']}")
    print(f"  profile B (re-download): {summary['iccid_B']}")
    print(f"  same ICCID on re-issue : {summary['same_iccid']}")
    print(f"  installed after        : {summary['installed_after']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
