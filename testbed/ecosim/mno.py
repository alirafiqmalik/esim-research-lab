"""Simulated MNO (ES2+ operator side).

Places a profile order with the SM-DP+ and hands the subscriber an activation
code (what a real operator would print on a QR code or SMS). No PKI/crypto of
its own — ES2+ trusts the SM-DP+ implicitly in this simulation, matching the
real-world trust boundary (the MNO is the SM-DP+'s customer, not its verifier).
"""

from __future__ import annotations

import random

from .codec import ActivationCode
from .smdp import SmDpPlus


class Mno:
    """MNO role: orders profiles from an SM-DP+ and issues activation codes."""

    def __init__(self, smdp: SmDpPlus, rng: random.Random) -> None:
        self.smdp = smdp
        self.rng = rng

    def order_profile(
        self, profile_name: str, sp_name: str, profile_class: int = 0
    ) -> ActivationCode:
        iccid = self._generate_iccid()
        matching_id = self._generate_matching_id()
        self.smdp.register_order(matching_id, iccid, profile_name, sp_name, profile_class)
        return ActivationCode(smdp_address=self.smdp.address, matching_id=matching_id)

    def _generate_iccid(self) -> str:
        # 19 decimal digits, GSMA-style: an odd digit count is 'F'-padded to a
        # full nibble so the result is valid semi-octet BCD (bytes.fromhex-able).
        digits = "".join(str(self.rng.randrange(10)) for _ in range(19))
        return digits + "F"

    def _generate_matching_id(self) -> str:
        return self.rng.randbytes(8).hex()
