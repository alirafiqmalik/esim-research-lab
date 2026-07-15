# esimctl — scriptable, auto-logging eSIM control

Drive the phone's eUICC from the command line, no LLM. Every op auto-starts full
`logcat` capture **before** it runs; for `download` the OpenEUICC verbose ES9+/APDU
plaintext lands in that log. Output is JSON; exit code 0 = ok. Compose ops in
shell or Python to run sequences.

## Requirements
- Rooted Pixel with our privileged **OpenEUICC** build (includes `EsimCtlActivity`
  — see `openeuicc/`) and `verbose_logging` enabled (already set).
- **Device unlocked** — eUICC APDU access is keyguard-gated. `tools/keep_phone_awake.sh`
  keeps it awake; the SessionStart hook runs it automatically.
- Laptop: `adb`, Python 3.

## Backends
- **`lpac`** (default) — drives OpenEUICC's headless `EsimCtlActivity`, which runs
  the op through OpenEUICC's own lpac stack. Deterministic (no UI automation) and
  full plaintext. **Recommended.**
- **`fw`** — Android framework `EuiccManager` (download/delete/switch/eid/info) via
  the same activity. Result codes only (RSP bodies opaque through the stock LPA).
- **`ui`** — legacy OpenEUICC UI automation (uiautomator). Fallback only.

## Ops (verified end-to-end)

| Command | Does | lpac | fw |
|---|---|:--:|:--:|
| `esimctl list` | profiles (unmasked iccid, name, provider, state, class) | ✓ | — |
| `esimctl eid` | eUICC EID | ✓ | ✓ |
| `esimctl info` | EID + euiccInfo2 | ✓ | ✓ |
| `esimctl notifications` | pending eUICC notifications | ✓ | — |
| `esimctl download 'LPA:1$smdp$mid'` | download a profile; captures full ES9+ RSP plaintext | ✓ | ✓ |
| `esimctl enable N` | enable profile #N | ✓ | — |
| `esimctl disable N` | disable profile #N | ✓ | — |
| `esimctl delete N` | delete profile #N (destructive) | ✓ | — |
| `esimctl cycle --code '…' --times 5` | download→delete loop, each fully logged | ✓ | — |

`N` is the 1-based row from `list`; the tool resolves it to the full ICCID.

## Examples

```bash
cd tools/esimctl
python3 esimctl.py list
python3 esimctl.py eid
python3 esimctl.py download 'LPA:1$rsp.truphone.com$QRF-SPEEDTEST'
python3 esimctl.py enable 2 && python3 esimctl.py disable 2
python3 esimctl.py --backend fw eid

# no-LLM automation: cycle a code 10x, capture each RSP exchange
for i in $(seq 1 10); do
  python3 esimctl.py download 'LPA:1$rsp-eu.redteamobile.com$5901981126831169' > runs/$i.json
done
```

## Logging / output

Each invocation writes `sessions/esimctl/<timestamp>-<op>/`:
- `logcat.txt` — full logcat across the op
- `rsp.json` — parsed ES9+ request/response bodies (download)
- `isub.txt` — raw subscription dump (ui backend reads)

Stdout JSON includes `log_dir`.

## Design

- `esimctl.py` — CLI, per-op `Session` (starts logcat before the op), backend
  dispatch (`ACT_OPS` = activity, `OPS` = ui), JSON out.
- `uidriver.py` — coordinate-free UI helper for the `ui` fallback backend.
- `openeuicc/` — the `EsimCtlActivity.kt` source + integration/build steps. The
  activity logs `ESIMCTL: <id> RESULT {json}`; `esimctl` fires it via
  `am start` and reads the tagged result from logcat.

## Notes / limits
- The `download` op reports `ok:false` on a server-side failure (e.g. matchingId
  refused, pool empty) but still returns the captured RSP — that exchange is the
  deliverable.
- `fw` ops go through the default (stock) LPA, so their RSP bodies are opaque
  (see `docs/google-lpa-vs-openeuicc-rsp.md`).
