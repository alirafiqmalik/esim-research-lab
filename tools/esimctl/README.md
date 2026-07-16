# esimctl — scriptable, auto-logging eSIM control

Drive the phone's eUICC from the command line, no LLM. Every op auto-starts full
`logcat` capture **before** it runs; for `download` the OpenEUICC verbose ES9+/APDU
plaintext lands in that log. Output is JSON; exit code 0 = ok. Compose ops in
shell or Python to run sequences.

## Reproduce from scratch

```bash
bash tools/setup_testbed.sh
```

Clones/builds/installs the patched OpenEUICC, provisions frida-server, sets
the required datastore prefs, then runs `selftest.sh`. Idempotent — safe to
re-run. A first-time privileged install triggers one reboot; rerun the script
after the phone comes back up.

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
| `esimctl get-addresses` | ES10a: default SM-DP+ / root SM-DS addresses | ✓ | — |
| `esimctl set-dp-address FQDN` | ES10a: write the default SM-DP+ address (`""` clears) | ✓ | — |
| `esimctl get-rat` | ES10b: Rules Authorisation Table (raw BER-TLV) | ✓ | — |
| `esimctl apdu HEX` | raw ES10x C-APDU to the ISD-R; returns response hex | ✓ | — |
| `esimctl nickname N NAME` | ES10c: set a profile nickname (`""` clears) | ✓ | — |
| `esimctl remove-notification SEQ` | ES10b: delete a pending notification locally | ✓ | — |
| `esimctl handle-notification SEQ` | ES9+: send a pending notification to its SM-DP+ | ✓ | — |
| `esimctl reset --confirm-wipe` | ES10c: eUICCMemoryReset — **erases ALL profiles** | ✓ | — |

`N` is the 1-based row from `list`; the tool resolves it to the full ICCID.

The last eight reach commands lpac-jni does not bridge to Kotlin. `get-addresses`,
`set-dp-address`, `get-rat`, and `apdu` build the ES10x store-data C-APDU
(`81 E2 91 00 …`) and transmit it on lpac's **already-open** ISD-R logical channel
(the ISD-R is non-multiselectable — a second channel is refused with SW 6999).
`reset` is hard-guarded: it refuses without `--confirm-wipe` and, in the activity,
without `--es confirm RESET`.

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
