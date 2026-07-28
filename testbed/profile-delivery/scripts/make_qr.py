#!/usr/bin/env python3
"""Generate a QR image for a catalog code's LPA string, or any LPA string.

Local only: no device, no network. Encodes `LPA:1$<smdp>$<matchingId>` into a QR
a phone camera can scan to start a download.

Degrades gracefully. If `segno` or `qrcode` is installed it writes a PNG (and an
SVG for segno). If neither is present it writes a `.txt` with the payload and
render instructions instead of failing.

Run:
    ./venv/bin/python testbed/profile-delivery/scripts/make_qr.py --brand Speedtest
    ./venv/bin/python testbed/profile-delivery/scripts/make_qr.py --lpa 'LPA:1$rsp.truphone.com$QRF-SPEEDTEST'
    ./venv/bin/python testbed/profile-delivery/scripts/make_qr.py --all
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE_DELIVERY = HERE.parent
REPO_ROOT = HERE.parents[2]
CATALOG_JSONL = REPO_ROOT / "testbed" / "profile-download" / "catalog" / "profiles.jsonl"
OUT_DIR = PROFILE_DELIVERY / "qr"


@dataclass(frozen=True)
class QrJob:
    label: str
    payload: str


def load_catalog() -> list[dict]:
    if not CATALOG_JSONL.exists():
        raise FileNotFoundError(f"catalog missing: {CATALOG_JSONL}")
    return [json.loads(line) for line in CATALOG_JSONL.read_text().splitlines() if line.strip()]


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")[:48]


def validate_lpa(lpa: str) -> str:
    if not lpa.startswith("LPA:1$"):
        raise ValueError(f"not an LPA:1$ activation string: {lpa!r}")
    if len(lpa.split("$")) < 3:
        raise ValueError(f"expected LPA:1$<smdp>$<matchingId>: {lpa!r}")
    return lpa


def jobs_from_args(lpa: str | None, brand: str | None, want_all: bool) -> list[QrJob]:
    if lpa:
        return [QrJob(_slug(lpa.split("$")[-1]), validate_lpa(lpa))]
    catalog = load_catalog()
    if want_all:
        return [QrJob(_slug(f"{e['brand']}-{e['activation_code']}"), validate_lpa(e["full_lpa_string"]))
                for e in catalog]
    if brand:
        hits = [e for e in catalog if brand.lower() in e["brand"].lower()]
        if not hits:
            raise ValueError(f"no catalog brand matches {brand!r}")
        return [QrJob(_slug(f"{e['brand']}-{e['activation_code']}"), validate_lpa(e["full_lpa_string"]))
                for e in hits]
    raise ValueError("provide --lpa, --brand, or --all")


def render(job: QrJob, out_dir: Path) -> list[Path]:
    """Write the best QR artifact available. Returns the paths written."""
    written: list[Path] = []
    try:
        import segno  # type: ignore

        qr = segno.make(job.payload, error="m")
        png = out_dir / f"{job.label}.png"
        svg = out_dir / f"{job.label}.svg"
        qr.save(str(png), scale=8, border=2)
        qr.save(str(svg), scale=8, border=2)
        return [png, svg]
    except ImportError:
        pass
    try:
        import qrcode  # type: ignore

        img = qrcode.make(job.payload)
        png = out_dir / f"{job.label}.png"
        img.save(str(png))
        return [png]
    except ImportError:
        pass

    # No QR library: write the payload and instructions so nothing is lost.
    txt = out_dir / f"{job.label}.txt"
    txt.write_text(
        f"{job.payload}\n\n"
        "No QR library (segno/qrcode) in this venv. To render:\n"
        f"  ./venv/bin/pip install segno\n"
        f"  ./venv/bin/python -c \"import segno; segno.make({job.payload!r}).save('{job.label}.png', scale=8)\"\n"
        "Or paste the first line into any QR generator.\n"
    )
    written.append(txt)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lpa", help="an explicit LPA:1$... activation string")
    parser.add_argument("--brand", help="catalog brand substring")
    parser.add_argument("--all", action="store_true", help="every catalog code")
    args = parser.parse_args()

    try:
        jobs = jobs_from_args(args.lpa, args.brand, args.all)
    except (ValueError, FileNotFoundError) as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for job in jobs:
        paths = render(job, OUT_DIR)
        kinds = ", ".join(p.suffix.lstrip(".") for p in paths)
        print(f"  {job.label:40s} [{kinds}] {job.payload}")
    print(f"\nWrote {len(jobs)} QR artifact set(s) to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
