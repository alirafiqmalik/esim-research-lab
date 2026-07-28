#!/usr/bin/env python3
"""Cross-reference the phone's installed eSIM profiles against the scoped
catalog. Read-only: runs `esim euicc list` and matches by brand/provider name.

Answers: is any installed profile one of our catalog test profiles, and do we
hold its activation code (QR) for a delete/re-download.

Run:
    ./venv/bin/python testbed/profile-download/scripts/check_installed.py
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE_DOWNLOAD = HERE.parent
REPO_ROOT = HERE.parents[2]
CATALOG_JSONL = PROFILE_DOWNLOAD / "catalog" / "profiles.jsonl"


@dataclass
class Candidate:
    brand: str
    full_lpa_string: str
    via: str  # "provider" (strong) or "name" (weak) — where the brand matched


@dataclass
class ProfileMatch:
    iccid: str
    installed_name: str
    installed_provider: str
    state: str
    candidates: list[Candidate]  # ranked, provider-matches first


def load_catalog() -> list[dict]:
    if not CATALOG_JSONL.exists():
        raise FileNotFoundError(f"catalog missing: {CATALOG_JSONL}; run build_catalog.py first")
    return [json.loads(line) for line in CATALOG_JSONL.read_text().splitlines() if line.strip()]


def list_installed(backend: str = "lpac") -> list[dict]:
    cmd = [str(REPO_ROOT / "venv" / "bin" / "esim"), "euicc", "--backend", backend, "list"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90, cwd=str(REPO_ROOT))
    if not proc.stdout.strip():
        raise RuntimeError(f"list produced no output (rc={proc.returncode}): {proc.stderr.strip()[:200]}")
    data = json.loads(proc.stdout[proc.stdout.index("{"):])
    return data.get("profiles", [])


def match(installed: list[dict], catalog: list[dict]) -> list[ProfileMatch]:
    """The installed *name* is often generic (both Truphone profiles report
    name 'BetterRoaming'); the *provider* is the real discriminator. So a brand
    that matches the provider is a strong hit, name-only is weak. The exact
    matchingID cannot be recovered from list output, so all candidate QRs are
    returned rather than one guessed answer."""
    out: list[ProfileMatch] = []
    for prof in installed:
        name = prof.get("name", "")
        provider = prof.get("provider", "")
        candidates: list[Candidate] = []
        for entry in catalog:
            brand = entry["brand"].lower()
            if brand in provider.lower():
                via = "provider"
            elif brand in name.lower():
                via = "name"
            else:
                continue
            candidates.append(Candidate(entry["brand"], entry["full_lpa_string"], via))
        candidates.sort(key=lambda c: 0 if c.via == "provider" else 1)
        if candidates:
            out.append(ProfileMatch(
                iccid=prof.get("iccid", ""),
                installed_name=name,
                installed_provider=provider,
                state=prof.get("state", ""),
                candidates=candidates,
            ))
    return out


def main() -> int:
    catalog = load_catalog()
    installed = list_installed()
    print(f"Installed profiles: {len(installed)}")
    for p in installed:
        print(f"  - {p.get('iccid')}  {p.get('provider')} / {p.get('name')}  [{p.get('state')}]")
    print()

    matches = match(installed, catalog)
    if not matches:
        print("No installed profile matches the scoped catalog.")
        return 0

    print("Installed profiles that ARE catalog test profiles (QR available):")
    for m in matches:
        strong = [c for c in m.candidates if c.via == "provider"]
        print(f"  - {m.iccid}  [{m.state}]  provider={m.installed_provider!r} name={m.installed_name!r}")
        for c in m.candidates:
            marker = "==>" if c.via == "provider" else "   "
            print(f"      {marker} [{c.via:8s}] {c.brand:14s} {c.full_lpa_string}")
        if len(strong) != 1:
            print(f"      NOTE: exact matchingID not recoverable from list output "
                  f"({len(strong)} provider-match, {len(m.candidates)} total candidates)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
