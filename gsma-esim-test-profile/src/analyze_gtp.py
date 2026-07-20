#!/usr/bin/env python3
"""Analyze the GSMA TS.48 Generic eUICC Test Profile (GTP) packages.

The package ships four SAIP 2.3 Unprotected Profile Packages (UPP), each as a
DER blob (`.rename2der`) plus its ASN.1 value-notation twin (`.txt`). This tool
summarizes each variant from the readable `.txt` and reports the DER size, so we
know exactly what we are (and are not) able to load onto the eUICC.

Run: python3 analyze_gtp.py
"""
from __future__ import annotations
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

PKG = Path(__file__).resolve().parents[1] / \
    "TS.48-v7.1-Generic-eUICC-Test-Profile-for-DevicTesting" / "TS48 V7.0 eSIM_GTP_SAIP2.3"
VARIANTS = ("BERTLV_SUCI", "BERTLV_SUCI_NoRAMRFM", "NoBERTLV", "NoBERTLV_NoRAMRFM")


@dataclass
class GtpSummary:
    variant: str
    der_bytes: int
    iccid: str | None = None
    profile_type: str | None = None
    saip_version: str | None = None
    pe_counts: dict[str, int] = field(default_factory=dict)
    imsi: str | None = None
    aka_ki: str | None = None
    aka_algo: str | None = None
    isd_key: str | None = None
    puks: list[str] = field(default_factory=list)
    has_rfm: bool = False


def _hex_field(txt: str, name: str) -> str | None:
    m = re.search(rf"{name}\s+'([0-9A-Fa-f]+)'H", txt)
    return m.group(1) if m else None


def _swap_nibbles(bcd: str) -> str:
    return "".join(bcd[i + 1] + bcd[i] for i in range(0, len(bcd) - 1, 2))


def analyze_variant(variant: str) -> GtpSummary:
    stem = f"TS48 V7.0 eSIM_GTP_SAIP2.3_{variant}"
    txt = (PKG / f"{stem}.txt").read_text(errors="replace")
    der = PKG / f"{stem}.rename2der"

    s = GtpSummary(variant=variant, der_bytes=der.stat().st_size if der.exists() else -1)
    s.iccid = _hex_field(txt, "iccid")  # header ICCID is stored human-readable (not swapped)
    pt = re.search(r'profileType\s+"([^"]+)"', txt)
    s.profile_type = pt.group(1) if pt else None
    ver = re.search(r"major-version\s+(\d+),\s+minor-version\s+(\d+)", txt)
    s.saip_version = f"{ver.group(1)}.{ver.group(2)}" if ver else None

    s.pe_counts = dict(Counter(
        m.group(1) for m in re.finditer(r"^value\d+ ProfileElement ::= ([A-Za-z-]+)", txt, re.M)))
    s.has_rfm = s.pe_counts.get("rfm", 0) > 0

    ef_imsi = re.search(r"ef-imsi\s*\{.*?fillFileContent\s*:\s*'([0-9A-Fa-f]+)'H", txt, re.S)
    if ef_imsi:
        raw = ef_imsi.group(1)
        s.imsi = _swap_nibbles(raw[2:])[1:] if len(raw) >= 4 else raw  # strip len + parity nibble
    aka = re.search(r"algorithmID\s+([A-Za-z0-9-]+),.*?key\s+'([0-9A-Fa-f]+)'H", txt, re.S)
    if aka:
        s.aka_algo, s.aka_ki = aka.group(1), aka.group(2)
    isd = re.search(r"keyType\s+'80'H,\s+keyData\s+'([0-9A-Fa-f]+)'H", txt)
    s.isd_key = isd.group(1) if isd else None
    s.puks = re.findall(r"pukValue\s+'([0-9A-Fa-f]+)'H", txt)
    return s


def main() -> None:
    print("GSMA TS.48 v7.1 Generic eUICC Test Profile — package analysis\n")
    for v in VARIANTS:
        s = analyze_variant(v)
        print(f"### {v}   ({s.der_bytes} B DER)")
        print(f"  profileType : {s.profile_type}")
        print(f"  SAIP        : v{s.saip_version}   ICCID {s.iccid}   IMSI {s.imsi}")
        print(f"  AKA         : algo={s.aka_algo} Ki={s.aka_ki}")
        print(f"  ISD SCP key : {s.isd_key}   PUKs={s.puks}")
        print(f"  RFM/RAM     : {'present' if s.has_rfm else 'ABSENT'}")
        print(f"  PEs         : {s.pe_counts}\n")


if __name__ == "__main__":
    main()
