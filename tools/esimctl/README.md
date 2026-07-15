# esimctl — scriptable, auto-logging eSIM control

Drive the phone's eUICC from the command line, no LLM. Every op auto-starts full
`logcat` capture **before** it runs and, for RSP ops, attaches OpenEUICC's verbose
ES9+/APDU plaintext hook. Output is JSON; exit code 0 = ok. Compose ops in shell
or Python to run sequences.

## Requirements
- The rooted Pixel with our privileged **OpenEUICC** installed and `verbose_logging`
  enabled (already set). `frida-server` at `/data/local/tmp/frida-server` for `--capture-rsp`.
- Laptop: `adb`, Python 3. Run from anywhere; paths resolve to the repo.

## Ops (backend `lpac` — default, full plaintext)

| Command | Does | Verified |
|---|---|---|
| `esimctl list` | embedded profiles (from `dumpsys isub`) | ✓ |
| `esimctl eid` | eUICC EID (from OpenEUICC ES10c GetEID) | ✓ |
| `esimctl info` | EID + trusted CI key IDs + EUICCInfo1 | ✓ |
| `esimctl download 'LPA:1$smdp$mid'` | download a profile; captures the full ES9+ RSP plaintext | ✓ |
| `esimctl enable N` | enable profile #N | ✓ |
| `esimctl disable N` | disable profile #N | ✓ |
| `esimctl delete N` | delete profile #N (destructive) | mechanism ✓ |
| `esimctl cycle --code '…' --times 5` | download→delete loop, each fully logged | compound |

`N` is the 1-based row as shown by `list`.

## Examples

```bash
cd tools/esimctl
python3 esimctl.py list
python3 esimctl.py eid
python3 esimctl.py download 'LPA:1$rsp.truphone.com$QRF-SPEEDTEST'
python3 esimctl.py enable 2 && python3 esimctl.py disable 2

# a no-LLM automation script: cycle a code 10x, save each result
for i in $(seq 1 10); do
  python3 esimctl.py download 'LPA:1$rsp-eu.redteamobile.com$5901981126831169' \
    > runs/dl_$i.json
done
```

## Logging / output

Each invocation writes to `sessions/esimctl/<timestamp>-<op>/`:
- `logcat.txt` — full logcat captured across the op
- `rsp.json` — parsed ES9+ request/response bodies (download ops)
- `frida.txt` — raw Frida hook output (with `--capture-rsp`)
- `isub.txt` — raw subscription dump (read ops)

The JSON printed to stdout includes `log_dir` pointing at that directory.

## Design

- `esimctl.py` — CLI, per-op `Session` (starts logcat before the op), op dispatch, JSON out.
- `uidriver.py` — coordinate-free UI helper (find nodes by resource-id/text/class, tap
  centers, wait-for-element) so write ops survive layout shifts.
- Read ops use `dumpsys` + OpenEUICC's verbose enumeration. Write ops drive OpenEUICC's
  UI (download wizard, profile menu). RSP plaintext comes from `tools/frida/google_lpa_rsp.js`.

## Roadmap

1. **Robust non-UI backend (recommended next):** add an `am broadcast`-driven
   `EsimCtlReceiver` to our OpenEUICC build that calls `EuiccChannelManagerService`
   tasks (`launchProfileDownloadTask`/`Delete`/`Switch`) and `LocalProfileAssistant`
   reads directly, logging results to a `ESIMCTL` logcat tag. Removes UI-automation
   fragility. Requires one OpenEUICC rebuild (`:app:assembleDebugMagiskModuleDir`).
2. **`fw` backend (framework EuiccManager):** the same receiver can also call
   `android.telephony.euicc.EuiccManager` (download/delete/switch/getEid/getEuiccInfo)
   for framework-level behavior — result codes only (RSP bodies opaque via the stock LPA,
   as documented in `docs/google-lpa-vs-openeuicc-rsp.md`). `--backend fw` is stubbed
   until then.
