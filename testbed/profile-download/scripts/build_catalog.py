#!/usr/bin/env python3
"""Build the scoped test-profile catalog: brand/profile, SM-DP+ host,
activation code, full LPA string.

Scope: 1GLOBAL/Truphone (rsp.truphone.com) and Redtea (rsp-eu.redteamobile.com)
commercial test profiles that chain to a GSMA **Live** (production) CI, need no
signup, and are reusable (downloadable repeatedly, not EID-locked).

Data is curated from two cross-checked sources (see SOURCES) and validated here:
every full LPA string is reparsed and must reconstruct from its own components.

Repeatable: run it any time to regenerate catalog/profiles.jsonl and
catalog/profiles.md deterministically.

Run:
    ./venv/bin/python testbed/profile-download/scripts/build_catalog.py
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE_DOWNLOAD = HERE.parent
CATALOG_DIR = PROFILE_DOWNLOAD / "catalog"

SOURCES = [
    "https://euicc-manual.osmocom.org/docs/rsp/known-test-profile/",
    "docs/research/research-gsma-ts48-test-profile.md",
    "docs/research/research-other-free-esim-codes.md",
]


@dataclass(frozen=True)
class ProfileEntry:
    provider: str          # SM-DP+ operator (GSMA provider name)
    brand: str             # profile/brand as shown by the LPA
    smdp_host: str         # SM-DP+ FQDN
    activation_code: str   # the matchingId portion
    full_lpa_string: str   # LPA:1$host$matchingId
    reusable: bool         # downloadable repeatedly
    eid_locked: bool       # burned to one EID on first download
    ci: str                # certificate issuer class
    source: str            # provenance URL/path


def parse_lpa(lpa: str) -> tuple[str, str, str]:
    """Parse `LPA:1$<host>$<matchingId>[$<oid>][$<cc>]` into
    (version, host, matchingId). Raises ValueError on malformed input."""
    if not lpa.startswith("LPA:"):
        raise ValueError(f"missing LPA: scheme in {lpa!r}")
    body = lpa[len("LPA:"):]
    parts = body.split("$")
    if len(parts) < 3:
        raise ValueError(f"expected at least version$host$matchingId in {lpa!r}")
    version, host, matching_id = parts[0], parts[1], parts[2]
    if version != "1":
        raise ValueError(f"unsupported activation-code version {version!r} in {lpa!r}")
    if not host or not matching_id:
        raise ValueError(f"empty host or matchingId in {lpa!r}")
    return version, host, matching_id


def _entry(provider: str, brand: str, host: str, matching_id: str, source: str) -> ProfileEntry:
    lpa = f"LPA:1${host}${matching_id}"
    _, parsed_host, parsed_mid = parse_lpa(lpa)
    if parsed_host != host or parsed_mid != matching_id:
        raise ValueError(f"round-trip mismatch building {lpa!r}")
    return ProfileEntry(
        provider=provider,
        brand=brand,
        smdp_host=host,
        activation_code=matching_id,
        full_lpa_string=lpa,
        reusable=True,
        eid_locked=False,
        ci="GSMA Live (production)",
        source=source,
    )


OSMO = SOURCES[0]

CATALOG: list[ProfileEntry] = [
    _entry("1GLOBAL (Truphone)", "BetterRoaming", "rsp.truphone.com", "QR-G-5C-1LS-1W1Z9P7", OSMO),
    _entry("1GLOBAL (Truphone)", "BetterRoaming", "rsp.truphone.com", "QR-G-5C-KR-1PCDWP9", OSMO),
    _entry("1GLOBAL (Truphone)", "BetterRoaming", "rsp.truphone.com", "QRF-BETTERROAMING-PMRDGIR2EARDEIT5", OSMO),
    _entry("1GLOBAL (Truphone)", "Speedtest", "rsp.truphone.com", "QRF-SPEEDTEST", OSMO),
    _entry("Redtea Mobile", "RedteaGO", "rsp-eu.redteamobile.com", "5901981126831169", OSMO),
]


def write_jsonl(entries: list[ProfileEntry], path: Path) -> None:
    with open(path, "w") as f:
        for e in entries:
            f.write(json.dumps(asdict(e)) + "\n")


def write_markdown(entries: list[ProfileEntry], path: Path) -> None:
    lines = [
        "# Scoped Test-Profile Catalog",
        "",
        "Providers in scope: 1GLOBAL/Truphone, Redtea. All reusable, GSMA Live CI, no signup.",
        "",
        "| Brand / profile | SM-DP+ host | Activation code | Full LPA string | Reusable |",
        "|---|---|---|---|---|",
    ]
    for e in entries:
        lines.append(
            f"| {e.brand} ({e.provider}) | `{e.smdp_host}` | `{e.activation_code}` "
            f"| `{e.full_lpa_string}` | {'yes' if e.reusable else 'no'} |"
        )
    lines += ["", "## Sources", ""]
    lines += [f"- {s}" for s in SOURCES]
    path.write_text("\n".join(lines) + "\n")


def main() -> int:
    CATALOG_DIR.mkdir(parents=True, exist_ok=True)
    jsonl_path = CATALOG_DIR / "profiles.jsonl"
    md_path = CATALOG_DIR / "profiles.md"
    write_jsonl(CATALOG, jsonl_path)
    write_markdown(CATALOG, md_path)
    print(f"Wrote {len(CATALOG)} entries")
    print(f"  {jsonl_path}")
    print(f"  {md_path}")
    for e in CATALOG:
        print(f"  - {e.brand:14s} {e.full_lpa_string}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
