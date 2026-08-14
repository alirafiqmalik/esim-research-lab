# Non-root eSIM RSP capture

Capture what stock Android exposes during an eSIM download, on a phone you cannot root.
Runs on your computer, drives the phone over USB `adb`. No root, no app install.

## What you get

`adb` runs as the `shell` user, which holds `READ_LOGS`, so it reads system-wide and
radio logcat without root. During an eSIM add you can capture:

- LPA download flow — `EuiccService`, `EuiccController`, `EuiccConnector`, and OEM
  equivalents.
- SM-DP+ address and `matchingId` (when the LPA logs them).
- Download result and error codes — `EuiccManager` `OPERATION_*` / `ERROR_*`.
- Profile-install notification handling.
- Modem attach and registration after the new profile enables (radio buffer).
- Before/after subscription state (`dumpsys isub`, `telephony.registry`).

## What you do NOT get

The stock LPA pins RSP TLS to the GSMA CI and never logs the payloads. Without root you
cannot capture:

- ES9+ / ES8+ plaintext — `InitiateAuthentication`, `AuthenticateClient`,
  `GetBoundProfilePackage` bodies.
- The eUICC-signed `deviceInfo`, so no IMEI or TAC on the RSP wire.
- Raw ES10 APDUs to the eUICC.
- Decrypted TLS. A user-installed CA does not help — Android 7+ ignores user CAs for
  system traffic, and the LPA pins anyway.

That level needs the privileged `lpac`/OpenEUICC stack on a rooted device — the setup in
`../openeuicc/` and `../profile-download/`.

## Prerequisites

- `adb` on your computer.
- USB debugging enabled on the phone (Settings > Developer options), RSA prompt accepted.
- The eSIM activation QR or code ready to enter on the phone.

## Run

```bash
chmod +x capture_esim_rsp.sh
./capture_esim_rsp.sh                 # one device attached
./capture_esim_rsp.sh -s <SERIAL>     # if both phones are plugged in
./capture_esim_rsp.sh --bugreport     # also pull a full adb bugreport after
./capture_esim_rsp.sh --pull-logs     # harvest on-device SysDump / modem logs
```

## Relationship to `*#9900#` (Samsung SysDump)

`*#9900#` "Run dumpstate/logcat" invokes the same `dumpstate` as `adb bugreport`, so
`--bugreport` captures the identical bundle — all log buffers plus every `dumpsys`. The
one thing the dialer menu does that `adb` cannot without root is enable **modem logging**
(Sky/CP), which writes baseband `.sdm` files (the NAS/RRC attach layer). Toggle that in
SysDump, then run this script with `--pull-logs` to harvest `/sdcard/log` and any
`.sdm` / `dumpState*` files off the phone. Decode the `.sdm` with SCAT (`signalcat`), as
in `../baseband-attach/`. Neither path exposes RSP plaintext.

If the rooted phone is still plugged in, `adb devices` shows two — pass `-s` with the
target serial. The script prints the model and asks you to confirm before it captures.

The script snapshots state, starts logcat, then waits. Do the eSIM add on the phone, let
download and activation finish, then press ENTER. It stops, snapshots again, and writes:

- `logcat-full.txt` — full system + radio log for the window.
- `logcat-rsp.txt` — lines filtered to eSIM/RSP tags.
- `summary.txt` — extracted URLs, SM-DP+ candidates, `matchingId`, result codes.
- `state-before/`, `state-after/` — subscription and telephony snapshots.

## Optional: network metadata with PCAPdroid (no root)

PCAPdroid records traffic through the Android VPN API, no root. It cannot decrypt the
pinned RSP TLS, but it captures the SM-DP+ hostname (TLS SNI), IP, connection timing, and
byte volumes — enough to pair the LPA log flow with the on-wire exchange. The profile
package stays encrypted either way.

The script drives PCAPdroid through its adb control API (`--pcapdroid`): it starts the
capture before the window, stops it after, and pulls the `.pcap`. That needs a one-time
setup on the phone.

One-time setup (once per phone):

1. Open PCAPdroid. Start a capture manually once and accept the Android VPN consent.
2. In PCAPdroid settings, allow control from other apps (so the adb intent is not blocked
   every time). The first `--pcapdroid` run still shows a control-consent prompt — accept
   it and, if offered, "remember".
3. Set the PCAP export/download folder to internal storage (for example
   `Download/PCAPdroid`) so the file lands somewhere the script can pull.

Then run:

```bash
./capture_esim_rsp.sh -s <SERIAL> --pcapdroid
```

The pcap arrives in `pulled-logs/`. If none appears, PCAPdroid saved it outside the pulled
paths — check its export folder and adjust, or read it in the app. To narrow the capture,
set a target app in PCAPdroid; note the eSIM download runs from the telephony/phone
process, not a user app, so leave it unfiltered unless you know the UID.

`--pcapdroid` implies `--pull-logs`.

## Correlate the clocks

`state-before/device-clock.txt` and `host-clock.txt` record both clocks at start. Use the
offset to line up logcat timestamps with anything you capture on the host side.
