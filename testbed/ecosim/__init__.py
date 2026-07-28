"""Local eSIM ecosystem simulation testbed.

Models the GSMA SGP.22 Remote SIM Provisioning flow end-to-end with custom PKI,
so every channel can be observed in cleartext:

    MNO --ES2+--> SM-DP+ --C1/ES9+--> device --C2a--> LPA --C3/ES10--> eUICC (software)

No hardware or emulated card is involved. The eUICC is a software model of the
ISD-R. The crypto that is genuinely protected end-to-end (TLS on C1, the ECDSA
mutual authentication, the ES8+/SCP03t profile package) is implemented for real
with P-256 keys off the custom CI, so the *unprotected* framing/metadata that
remains the attack surface is exactly what the fuzzer targets.
"""

from __future__ import annotations

__all__ = ["__version__"]
__version__ = "0.1.0"
