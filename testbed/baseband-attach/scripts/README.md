# NAS + RRC capture/decode scripts

Turn the rooted-Pixel Shannon modem into a NAS/RRC analyzer. Two steps: capture on
the phone over ADB, decode on the host with SCAT + tshark.

## What you can analyze

- **NAS** — LTE EMM/ESM and 5G 5GMM/5GSM. Attach/Registration Request, Identity
  Request/Response (IMEISV / SUCI), Security Mode, ESM info, Attach/Registration Accept.
  Security-header type is decoded — that is how you read "type 0 = Plain, unprotected".
- **RRC** — LTE and NR: MIB, SIB1-24, RRCConnectionRequest/Setup/Reconfiguration,
  MeasurementReport, and (in NR coverage) NR-RRC / EN-DC SCG config.
- Lower layers on demand: pass `pdcp,rlc,mac,ip` as the layers argument.

## Prerequisites

- Rooted device with a Samsung Shannon/Exynos modem (Pixel 6/7/8 Tensor, Samsung Exynos).
- ADB + root. Host has `tshark` and `signalcat` (SCAT):
  `venv/bin/python3 -m pip install signalcat`
- Modem logging works from ADB once verbose vendor logging is on (the scripts set it).
  On builds where the prop is ignored, enable "Verbose Vendor Logging" in Developer
  options, or the modem-log toggle in the on-device diagnostics app, once.

## Capture

```bash
# airplane cycle -> re-attach (default)
./capture_nas_rrc.sh out/run1

# cold attach by re-enabling an eSIM profile (gives the full Identity exchange)
./capture_nas_rrc.sh out/run1 reenable 89311210000007826945
```

Writes `out/run1/cap.sdm`. Stops logging and cleans the device temp on exit.

## Decode

```bash
./decode_nas_rrc.sh out/run1/cap.sdm            # nas,rrc
./decode_nas_rrc.sh out/run1/cap.sdm nas,rrc,pdcp,rlc,mac
```

Produces next to the `.sdm`:
- `cap.pcap` — GSMTAP, open in Wireshark.
- `cap.summary.txt` — one line per frame.
- `cap.detail.txt` — full verbose decode.
- `cap.nas.txt` — NAS-only (EMM/ESM/5GMM).

And prints: control-plane message inventory, the unprotected (security-header type 0)
NAS lines, and an NR/EN-DC frame count.

## Notes

- Samsung modem = SCAT `-t sec` (SDM). Qualcomm would be `-t qc` (QMDL/DIAG) — not this
  device.
- Shannon logs NAS after deciphering, so a logged type-0 AFTER security is up is a decode
  artifact, not the on-air state. Type-0 on pre-security messages (Attach/Identity) is the
  real unprotected wire state.
- Raw `.sdm`/`.pcap` hold real subscriber traffic (IMEISV, TMSI, SMS). Keep them out of
  git; treat as sensitive.
