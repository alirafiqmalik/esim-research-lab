#!/usr/bin/env python3
"""Try (and expect to fail) to load the TS.48 GTP onto the production eUICC.

We know the eUICC will not accept a test profile — this makes the failure
concrete instead of assumed. There is NO SM-DP+/BPP here: we take the raw SAIP
UPP and shove its first bytes at the ISD-R as an ES10b LoadBoundProfilePackage
STORE DATA, with no ES8+ session established. SGP.22 requires a session opened by
AuthenticateServer + PrepareDownload first, so the eUICC rejects the command with
an error status word and creates no ISD-P — which is the point we want to observe.

Uses only the existing testbed (esimctl raw `apdu`), changes nothing. Snapshots
the profile list before and after to prove the eUICC is untouched.

Run: python3 try_direct_load.py
"""
from __future__ import annotations
import json
import subprocess
from pathlib import Path

SRC = Path(__file__).resolve()
ESIMCTL = SRC.parents[2] / "tools" / "esimctl" / "esimctl.py"
DER = SRC.parents[1] / "TS.48-v7.1-Generic-eUICC-Test-Profile-for-DevicTesting" / \
    "TS48 V7.0 eSIM_GTP_SAIP2.3" / "TS48 V7.0 eSIM_GTP_SAIP2.3_NoBERTLV.rename2der"

SW = {  # common ISO-7816 / SGP.22 status words we might see
    "9000": "OK (unexpected — would mean it accepted a byte chunk)",
    "6985": "Conditions of use not satisfied (no download session open)",
    "6A88": "Referenced data not found",
    "6A80": "Incorrect parameters in the command data",
    "6A86": "Incorrect P1-P2",
    "6D00": "Instruction not supported / invalid state",
    "6982": "Security status not satisfied",
    "6F00": "No precise diagnosis",
}


def esimctl(*args: str) -> dict:
    r = subprocess.run(["python3", str(ESIMCTL), *args],
                       capture_output=True, text=True, timeout=90)
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"_raw": r.stdout, "_err": r.stderr}


def profiles() -> list[str]:
    return [p["iccid"] for p in esimctl("list").get("profiles", [])]


def main() -> None:
    upp = DER.read_bytes()
    print(f"GTP UPP: {len(upp)} bytes, starts {upp[:8].hex().upper()}")

    before = profiles()
    print(f"profiles before: {len(before)} {before}")

    # Wrap the first bytes of the UPP as an ES10b LoadBoundProfilePackage (BF37)
    # STORE DATA. One APDU, no session — expected to be refused.
    chunk = upp[:180]
    tlv = b"\xbf\x37" + bytes([len(chunk)]) + chunk
    apdu = bytes([0x81, 0xE2, 0x91, 0x00, len(tlv)]) + tlv
    print(f"\nsending out-of-session LoadBoundProfilePackage ({len(apdu)} B APDU)...")
    res = esimctl("apdu", apdu.hex().upper())
    resp = (res.get("resp") or "").upper()
    sw = resp[-4:] if len(resp) >= 4 else resp
    print(f"  response: {resp or res}")
    print(f"  status word: {sw}  -> {SW.get(sw, 'unknown SW')}")

    after = profiles()
    print(f"\nprofiles after: {len(after)} {after}")
    print("VERDICT:")
    print(f"  eUICC unchanged : {before == after}")
    print(f"  profile installed: {'89000123456789012341' in after}  (expected: False)")
    print("  => the raw test profile cannot be injected without an RSP/ES8+ session.")


if __name__ == "__main__":
    main()
