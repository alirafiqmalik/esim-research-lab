# eSIM Testbed — Status Update

## Mission Objective

Build a **scriptable research testbed** to drive and observe the eSIM chip inside a rooted Google Pixel 7a. The goal is to reach **every eSIM command** the hardware allows and capture the full **RSP** (Remote SIM Provisioning — how carrier profiles get downloaded) traffic in plain text. This lets us study where the security boundary really sits.

The whole thing runs from the command line with **no AI agent in the loop**. One tool, `esimctl`, controls everything and logs each step automatically.

## Core Features Implemented

**Command tool (`esimctl`)** — one command line to run the eSIM. Every action starts logging before it runs, so nothing is missed.

- **Read the chip**: list profiles, read the **EID** (the chip's unique serial number), read chip info and CI trust keys.
- **Manage profiles**: download, enable, disable, delete, rename, and reset — with **hard safety guards** on anything destructive.
- **Raw access**: send any low-level command straight to the chip's main applet (**ISD-R**, the chip's command inbox).

**Deep eUICC access** — commands the standard tools never expose are now reachable.

- **Address control**: read and rewrite the **default SM-DP+ / SM-DS** (the carrier servers the chip trusts by default) — the most attack-relevant knob.
- **ECASD reachable**: we found and opened the chip's **identity vault** (ECASD), reading its key inventory. The private certificates stay locked, exactly as designed.
- **Notifications**: pull the chip-signed messages it would send back to a carrier server.

**Live RSP experiments** — real network round trips, not simulations.

- **CI-trust probe** (`authenticate`): point it at any carrier server and see if the chip **accepts or rejects** that server's identity. Real production servers pass; fake/test ones are refused.
- **Discovery** (`discovery`): asks the global **root SM-DS** (the carrier lookup directory) whether any profile is waiting for this chip.

**Two independent command paths** — we can reach the chip two different ways, which cross-checks results and survives if one path breaks.

**Full reproducibility** — one setup script rebuilds the entire testbed from scratch, and a **17-check self-test passes 100%**.

## Technical Blockers (if any)

**The stock carrier command path is locked to us.** We can reach Android's built-in eSIM command interface, but it rejects our tool with **`CALLER_NOT_ALLOWED`**. Only the phone's official default SIM app is allowed to use it, and unlocking that would mean replacing the default app.

**The chip enforces trust in hardware, not software.** Even with full root access, the chip itself refuses any carrier server whose identity isn't signed by a **real GSMA production key**. This is the expected security wall — root gets us to the door, but **the chip's crypto core holds**.

**One applet is simply absent.** The **ARA-M** access-rule component does not exist on this particular chip, so that avenue is a dead end here (not a bug).

## Next Steps

- **Run the foreign-certificate experiment**: use the new CI-trust probe against a real test-key server to capture the exact rejection.
- **Manipulate the trust addresses**: use the new address-write feature to steer the chip toward a chosen server and observe the result.
- **Optional**: explore making our tool the phone's default SIM app to unlock the second command path.
