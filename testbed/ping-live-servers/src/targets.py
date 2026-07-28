"""Request targets: where a script points its HTTP client.

LOCAL_SIM_SMDP / LOCAL_SIM_SMDS are the only targets any script uses by
default. `provider_target()` builds a Target for a real provider FQDN --
constructing one is harmless by itself (no I/O happens here); the actual
safety guard lives in `client.RspHttpClient`, which refuses to send anything
to a non-local target without an explicit, double-gated opt-in. That split
(safe-to-construct vs. gated-to-use) is intentional: it lets Step 4/5 scripts
take a `--target provider:<name>` CLI argument today without risk, ready for
the (separately gated) live phase to flip the opt-in later.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Target:
    name: str
    base_url: str
    is_local: bool


LOCAL_SIM_SMDP = Target(name="local-sim-smdp", base_url="http://127.0.0.1:8443", is_local=True)
LOCAL_SIM_SMDS = Target(name="local-sim-smds", base_url="http://127.0.0.1:8444", is_local=True)


def provider_target(name: str, host: str) -> Target:
    """Build a Target for a real provider FQDN. Never selected by default --
    every script's default target is local. See module docstring: this alone
    does not authorize sending anything; RspHttpClient enforces that."""
    return Target(name=name, base_url=f"https://{host}", is_local=False)
