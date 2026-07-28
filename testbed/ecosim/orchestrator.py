"""Wires the ecosystem together and runs end-to-end download flows.

Owns the object graph so identities (PKI certs, EID, SM-DP+ address) are built
ONCE and reused across runs — they stay invariant, exactly as in reality — while
per-transaction values (challenge, transaction id, ephemeral keys, matchingId,
iccid) advance from a shared seeded RNG and therefore vary run to run. That split
is what the invariant/variable analysis keys off.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509

from .bus import Bus, Message
from .euicc import SoftwareEuicc
from .lpa import Lpa
from .mno import Mno
from .pki import PKI, build_pki, write_pki
from .smdp import SmDpPlus

DEFAULT_SEED = 0xE517


@dataclass
class Ecosystem:
    pki: PKI
    bus: Bus
    euicc: SoftwareEuicc
    smdp: SmDpPlus
    mno: Mno
    lpa: Lpa
    rng: random.Random


def build_ecosystem(seed: int = DEFAULT_SEED, pki_out: Path | None = None) -> Ecosystem:
    pki = build_pki()
    if pki_out is not None:
        write_pki(pki, pki_out)
    rng = random.Random(seed)
    bus = Bus.default()
    ci_cert = pki.ci.certificate
    euicc = SoftwareEuicc(pki, rng)
    smdp = SmDpPlus(pki, rng)
    mno = Mno(smdp, rng)
    lpa = Lpa(euicc, smdp, bus, ci_cert)
    return Ecosystem(pki=pki, bus=bus, euicc=euicc, smdp=smdp, mno=mno, lpa=lpa, rng=rng)


def run_flow(
    eco: Ecosystem,
    profile_name: str = "ecosim-profile",
    sp_name: str = "ecosim-MNO",
    profile_class: int = 0,
) -> tuple[dict, list[Message]]:
    """Order a profile at the MNO, then run the full LPA download. Returns
    (summary, messages-observed-this-run). The bus log is reset first so the
    returned list is exactly one run's traffic."""
    activation = eco.mno.order_profile(profile_name, sp_name, profile_class)
    eco.bus.reset_logs()
    summary = eco.lpa.download_profile(activation.encode())
    return summary, list(eco.bus.all_messages())


def _decode_preview(msg: Message) -> object:
    try:
        if msg.encoding == "json":
            return json.loads(msg.wire.decode("utf-8"))
        if msg.encoding == "text":
            return msg.wire.decode("utf-8", "replace")
    except (ValueError, UnicodeDecodeError):
        pass
    return msg.wire.hex()


def write_run_log(messages: list[Message], path: Path) -> None:
    """One JSON record per message: {channel, direction, kind, encoding, wire, preview}."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for msg in messages:
            record = {
                "channel": msg.channel,
                "direction": msg.direction,
                "kind": msg.kind,
                "encoding": msg.encoding,
                "wire": msg.hexwire(),
                "preview": _decode_preview(msg),
            }
            fh.write(json.dumps(record) + "\n")
