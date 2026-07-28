#!/usr/bin/env python3
"""Full lifecycle for EVERY catalog code: download -> enable -> disable ->
delete -> re-download, with per-step logging and a summary table.

Handled quirks:
  - `delete` takes a 1-based LIST INDEX, not an ICCID (resolved per step).
  - `enable`/`disable` take an ICCID (they use _resolve_iccid).
  - These are fixed profiles: re-downloading a code returns the same ICCID, so a
    fresh download collides if that ICCID is already installed. On a collision
    (download adds no profile) the catalog profiles are purged and the download
    retried, so every code gets a clean instance to cycle.

Normalizes first: deletes all currently-installed catalog profiles so the batch
starts clean. Each code's cycle ends with the profile re-downloaded (installed).

Gated identically to download_lifecycle.py:
    ESIM_MITM_ALLOW_LIVE_FIRE=1  --allow-live-fire  --i-understand-real-profile

Run:
    ESIM_MITM_ALLOW_LIVE_FIRE=1 \
    ./venv/bin/python testbed/profile-download/scripts/batch_lifecycle.py \
        --allow-live-fire --i-understand-real-profile
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from download_lifecycle import Runner  # noqa: E402  (shared harness wrapper)

PROFILE_DOWNLOAD = HERE.parent
CATALOG_JSONL = PROFILE_DOWNLOAD / "catalog" / "profiles.jsonl"


@dataclass
class CodeResult:
    brand: str
    provider: str
    full_lpa_string: str
    iccid_a: str | None = None
    iccid_b: str | None = None
    same_iccid: bool | None = None
    download_ok: bool = False
    collided: bool = False
    enabled_state: str | None = None
    disabled_state: str | None = None
    deleted_ok: bool = False
    redownload_ok: bool = False
    rsp_ops: list[str] = field(default_factory=list)
    status: str = "unknown"
    error: str = ""


def load_catalog() -> list[dict]:
    return [json.loads(l) for l in CATALOG_JSONL.read_text().splitlines() if l.strip()]


def _matches_catalog(prof: dict, catalog: list[dict]) -> bool:
    hay = f"{prof.get('name','')} {prof.get('provider','')}".lower()
    return any(e["brand"].lower() in hay for e in catalog)


def _state_of(runner: Runner, iccid: str, step: str) -> str | None:
    for p in runner.list_profiles(step):
        if p["iccid"] == iccid:
            return p.get("state")
    return None


def _index_of(profs: list[dict], iccid: str) -> int | None:
    for i, p in enumerate(profs):
        if p["iccid"] == iccid:
            return i + 1
    return None


def _rsp_ops(result: dict) -> list[str]:
    ops: list[str] = []
    for item in result.get("rsp", []) or []:
        val = item.get("value", "")
        if item.get("kind") == "request-url" and "es9plus/" in val:
            ops.append(val.rsplit("es9plus/", 1)[-1])
    return ops


def _fail_reason(result: dict) -> str:
    """Extract 'subjectCode/reasonCode subjectIdentifier message' from the first
    Failed RSP response body (e.g. '8.1.1/3.8 EID Refused')."""
    for item in result.get("rsp", []) or []:
        if item.get("kind") == "response-body" and '"Failed"' in item.get("value", ""):
            try:
                sd = json.loads(item["value"])["header"]["functionExecutionStatus"]["statusCodeData"]
                return (f"{sd.get('subjectCode')}/{sd.get('reasonCode')} "
                        f"{sd.get('subjectIdentifier','')} {sd.get('message','')}").strip()
            except (ValueError, KeyError):
                return "Failed"
    return ""


def purge_catalog(runner: Runner, catalog: list[dict], step_prefix: str) -> list[str]:
    """Delete every installed catalog profile (by index, --force). Returns the
    ICCIDs removed."""
    removed: list[str] = []
    for _ in range(20):  # bounded; far more than any eUICC holds
        profs = runner.list_profiles(f"{step_prefix}-list")
        target = next((p for p in profs if _matches_catalog(p, catalog)), None)
        if not target:
            break
        idx = _index_of(profs, target["iccid"])
        runner.call(f"{step_prefix}-del", ["delete", str(idx), "--yes", "--force"])
        removed.append(target["iccid"])
    return removed


def cycle(runner: Runner, entry: dict, catalog: list[dict]) -> CodeResult:
    lpa = entry["full_lpa_string"]
    r = CodeResult(brand=entry["brand"], provider=entry["provider"], full_lpa_string=lpa)

    # Clean slate: purge catalog profiles first so this code's download can never
    # collide with an earlier code's re-downloaded (fixed) profile. With a clean
    # deck, a download that adds nothing is a genuine server rejection, and the
    # purge only ever touches catalog test profiles for THIS batch.
    r.collided = bool(purge_catalog(runner, catalog, "00-purge"))
    before = runner.list_iccids("00-before")
    dl = runner.call("01-download", ["download", lpa])
    r.download_ok = bool(dl.get("ok"))
    r.rsp_ops = _rsp_ops(dl)
    r.error = _fail_reason(dl)
    new = runner.list_iccids("02-after-download") - before
    if not new:
        r.status = "download_failed"
        return r

    r.iccid_a = sorted(new)[0]

    runner.call("03-enable", ["enable", r.iccid_a])
    r.enabled_state = _state_of(runner, r.iccid_a, "04-after-enable")
    runner.call("05-disable", ["disable", r.iccid_a])
    r.disabled_state = _state_of(runner, r.iccid_a, "06-after-disable")

    profs = runner.list_profiles("07-index")
    idx = _index_of(profs, r.iccid_a)
    if idx is None:
        r.status = "lost_before_delete"
        return r
    runner.call("08-delete", ["delete", str(idx), "--yes", "--force"])
    r.deleted_ok = r.iccid_a not in runner.list_iccids("09-after-delete")

    after_del = runner.list_iccids("09b-mark")
    rdl = runner.call("10-redownload", ["download", lpa])
    r.redownload_ok = bool(rdl.get("ok"))
    new_b = runner.list_iccids("11-after-redownload") - after_del
    r.iccid_b = sorted(new_b)[0] if new_b else None
    r.same_iccid = (r.iccid_a == r.iccid_b) if r.iccid_b else None

    ok = r.download_ok and r.deleted_ok and r.redownload_ok and r.disabled_state == "Disabled"
    r.status = "ok" if ok else "partial"
    return r


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", default="lpac", choices=["lpac", "fw", "ui"])
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("--allow-live-fire", action="store_true")
    ap.add_argument("--i-understand-real-profile", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    catalog = load_catalog()
    gates_ok = (
        os.environ.get("ESIM_MITM_ALLOW_LIVE_FIRE") == "1"
        and args.allow_live_fire
        and args.i_understand_real_profile
    )
    if args.dry_run or not gates_ok:
        print("DRY RUN — no live actions. Would cycle these codes:")
        for e in catalog:
            print(f"  download -> enable -> disable -> delete -> re-download : {e['full_lpa_string']}")
        if not gates_ok and not args.dry_run:
            print("\nGates not set: ESIM_MITM_ALLOW_LIVE_FIRE=1 --allow-live-fire --i-understand-real-profile")
        return 0

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    batch_dir = PROFILE_DOWNLOAD / "logs" / f"{ts}-batch"
    batch_dir.mkdir(parents=True, exist_ok=True)
    print(f"BATCH lifecycle over {len(catalog)} codes. Logs: {batch_dir}\n")

    meta = Runner(batch_dir / "00-meta", args.backend, args.timeout)
    initial = [p["iccid"] for p in meta.list_profiles("initial")]
    print(f"Initial installed: {initial}\n")

    results: list[CodeResult] = []
    for i, entry in enumerate(catalog, 1):
        label = f"{i:02d}-{entry['brand']}-{entry['activation_code'][:16]}"
        print(f"  [{i}/{len(catalog)}] {entry['brand']:14s} {entry['activation_code']} ...", end=" ", flush=True)
        runner = Runner(batch_dir / label, args.backend, args.timeout)
        res = cycle(runner, entry, catalog)
        results.append(res)
        extra = f"  reason={res.error}" if res.status != "ok" and res.error else ""
        print(f"{res.status.upper()}  (A={res.iccid_a} B={res.iccid_b} same={res.same_iccid} "
              f"en={res.enabled_state} dis={res.disabled_state}){extra}")

    # Restore any originally-installed profile the batch left uninstalled, using
    # the code observed to produce each ICCID this run.
    current = meta.list_iccids("zz-precheck")
    icc_to_lpa: dict[str, str] = {}
    for res in results:
        for icc in (res.iccid_b, res.iccid_a):
            if icc:
                icc_to_lpa.setdefault(icc, res.full_lpa_string)
    restored: list[str] = []
    for icc in initial:
        if icc not in current and icc in icc_to_lpa:
            meta.call(f"restore-{icc[-4:]}", ["download", icc_to_lpa[icc]])
            restored.append(icc)
    if restored:
        print(f"\nRestored {len(restored)} original profile(s): {restored}")

    summary = {
        "timestamp": ts,
        "initial_installed": initial,
        "restored": restored,
        "results": [asdict(r) for r in results],
        "final_installed": [p["iccid"] for p in meta.list_profiles("zz-final")],
    }
    (batch_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")

    print("\n=== SUMMARY ===")
    for r in results:
        reason = f"  [{r.error}]" if r.status != "ok" and r.error else ""
        print(f"  {r.status:16s} {r.brand:14s} {r.activation_line()}{reason}")
    print(f"\n  final installed: {summary['final_installed']}")
    print(f"  full summary: {batch_dir / 'summary.json'}")
    return 0


def _activation_line(r: CodeResult) -> str:
    return (f"A={r.iccid_a} B={r.iccid_b} same={r.same_iccid} "
            f"dl={r.download_ok} en={r.enabled_state} dis={r.disabled_state} "
            f"del={r.deleted_ok} redl={r.redownload_ok} ops={'/'.join(sorted(set(r.rsp_ops)))}")


CodeResult.activation_line = lambda self: _activation_line(self)  # type: ignore[attr-defined]


if __name__ == "__main__":
    raise SystemExit(main())
