# eSIM Research Framework — Design Spec

**Date:** 2026-06-03
**Device:** OnePlus Nord N30 5G (CPH2515), T-Mobile
**ADB serial:** 3ddf2893
**Scope:** No-root, ADB-over-USB + Wi-Fi proxy interception

---

## Goal

Build a standalone Python eSIM research framework (`esim/`) with a library API and CLI,
covering the full RSP observation and interaction surface available without root. The
`.claude/` directory provides dev infrastructure — skills, agents, rules, notes — that
Claude uses to build and extend the framework efficiently. The framework itself has no
dependency on Claude tooling.

---

## Project Structure

```
esim-research/
├── esim/                  # Python package (the deliverable)
│   ├── __init__.py
│   ├── device.py          # ADB device abstraction
│   ├── profiles.py        # Profile CRUD, enable/disable
│   ├── capture.py         # mitmproxy + logcat concurrent capture
│   ├── analysis.py        # Parse/filter captured RSP sessions
│   └── cli.py             # Click CLI wrapping the library
│
├── tools/                 # One-time setup shell scripts
│   ├── setup_hotspot.sh   # Configure PC Wi-Fi hotspot (hostapd + dnsmasq)
│   └── install_mitm_cert.sh  # Push mitmproxy CA cert install instructions
│
├── sessions/              # Captured session output (gitignored)
├── tests/
├── pyproject.toml
│
└── .claude/               # Dev infrastructure
    ├── skills/
    ├── agents/
    ├── rules/
    └── notes/
```

---

## Python Framework

### `Device`

Central class. Wraps all ADB primitives. Auto-detects device serial if one is connected.

```python
d = Device(serial=None)
d.get_eid()               # → str: eUICC identifier
d.list_subscriptions()    # → list[Subscription]: physical SIM + eSIM profiles
d.get_euicc_state()       # → dict: full dumpsys euicc_card_controller output
d.enable_profile(sub_id)  # → bool
d.disable_profile(sub_id) # → bool
d.set_data_sim(sub_id)    # → bool
d.bugreport(out_dir)      # → Path: saves bugreport.zip
```

`Subscription` fields: `sub_id`, `iccid`, `display_name`, `slot`, `state` (enabled/disabled), `is_esim`.

### `Capture`

Context manager. Runs mitmproxy and `adb logcat` concurrently. Detects TLS pinning.

```python
with Capture(device=d, port=8080, filters=["ES9+", "ES11"]) as cap:
    input("Trigger eSIM action on phone, then press Enter...")
session = cap.save("sessions/2026-06-03-discovery/")
```

On `__enter__`: snapshots eUICC state, spawns mitmproxy subprocess, spawns filtered logcat subprocess.
On `__exit__`: stops subprocesses, writes session directory.

TLS pinning detection: if zero HTTPS flows arrive from known LPA hosts within 30s, emits
`PinningDetected` warning and continues in logcat-only mode.

### `Analysis`

Loads a saved session directory and provides correlated views.

```python
s = Session.load("sessions/2026-06-03-discovery/")
s.es11_calls()     # → list of ES11 request/response dicts
s.es9_calls()      # → list of ES9+ exchanges
s.bpp_blobs()      # → list of Base64 BPP payloads (encrypted, for reference)
s.logcat_events()  # → list of timestamped log lines
s.timeline()       # → merged, millisecond-aligned view of network + logcat events
```

### CLI

Click commands map 1:1 to library calls. All output is plain text by default; `--json` for machine-readable.

```
esim eid
esim profiles list
esim profiles enable <sub_id>
esim profiles disable <sub_id>
esim data-sim set <sub_id>
esim capture start [--port 8080] [--filter ES9+,ES11]
esim session analyze <path>
esim bugreport [--out sessions/]
```

### Dependencies

- `adb` — system, must be on PATH
- `mitmproxy` — pip, for traffic capture
- `click` — pip, for CLI
- `pyserial` — not needed (ADB-only)

No heavy ML or parsing libraries required.

---

## Capture Pipeline

```
PC Wi-Fi hotspot (hostapd + dnsmasq)
    ↓  phone connects, Wi-Fi proxy set to PC_IP:8080
mitmproxy (port 8080) ←→ upstream internet
    ↓
Capture context manager
    ├── mitmproxy subprocess  → traffic.mitm
    └── adb logcat subprocess → logcat.txt

Session directory output:
    sessions/<timestamp>/
    ├── traffic.mitm       # mitmproxy native (open with mitmweb)
    ├── traffic.har        # HAR export for external tools
    ├── logcat.txt         # filtered logcat
    ├── euicc_state.json   # dumpsys snapshot at start + end
    └── metadata.json      # {serial, eid, subscriptions, timestamp, duration}
```

`Analysis.timeline()` aligns mitmproxy flows and logcat events on a shared millisecond
clock using metadata timestamps. Example: ES10b `prepareDownload` log at t+1.2s correlates
to ES9+ `getBoundProfilePackage` response at t+1.8s.

---

## `.claude/` Infrastructure

### Skills

| File | Purpose |
|---|---|
| `skills/adb-probe.md` | Probe device state, resolve sub IDs, verify ADB connectivity |
| `skills/run-capture.md` | Start a capture session with correct flags and pre-checks |
| `skills/scaffold-module.md` | Add a new `esim/` module with tests and CLI hook |
| `skills/analyze-session.md` | Load and summarize a saved session |

### Agents

| File | Purpose |
|---|---|
| `agents/impl-worker.md` | Writes/edits Python code in `esim/` |
| `agents/test-runner.md` | Runs pytest, reports failures to orchestrator |
| `agents/adb-monitor.md` | Streams logcat for a session, saves output |

### Rules

| File | Purpose |
|---|---|
| `rules/markdown-style.md` | Clean, human-dev tone — no AI boilerplate |
| `rules/orchestrator.md` | Main session = manager, max 2-3 subagents, fast context sharing |
| `rules/code-style.md` | Python conventions for this project |

### Notes

| File | Purpose |
|---|---|
| `notes/device-cph2515.md` | OnePlus Nord N30 quirks, verified ADB commands |
| `notes/tls-pinning-status.md` | Whether mitmproxy intercepts or not (updated per test) |
| `notes/rsp-observations.md` | Protocol-level findings accumulated across sessions |

---

## Device Context

- **OEM:** OnePlus (OxygenOS) — medium-low TLS pinning risk; mitmproxy interception likely to work
- **Carrier:** T-Mobile US — may use T-Mobile LPA variant; to be confirmed via logcat on first run
- **eSIM status:** Active profile already on device at project start
- **Physical SIM:** Slot 1, 5G — independent data path on the phone; not the PC's upstream. PC hotspot requires its own internet source (ethernet or second Wi-Fi adapter)
- **ADB:** Confirmed connected (serial 3ddf2893), USB Debugging enabled

---

## What This Framework Cannot Do

These limitations are hard constraints of the no-root retail build — not gaps in the design:

- Decrypt the ES8+ Bound Profile Package (keys inside eUICC secure element)
- Capture raw APDU bytes (scrubbed on `user` builds)
- Access `EuiccCardManager` API directly (system-privileged, platform-key signed apps only)
- Bypass TLS certificate pinning if enforced by the OEM LPA
- Trigger a new eSIM profile download from scratch via ADB (requires system LPA privileges)

---

## Success Criteria

- `esim eid` returns the device EID without error
- `esim profiles list` shows both physical SIM and eSIM subscriptions
- A full ES11 + ES9+ capture session produces a populated `traffic.mitm` and correlated `timeline()`
- `esim session analyze` parses and prints a human-readable summary of a saved session
- All `.claude/` infrastructure files are in place and functional
