# esimctl — scriptable, auto-logging eSIM control

Drive the phone's eUICC from the command line, no LLM. Every op auto-starts full
`logcat` capture **before** it runs; for `download` the OpenEUICC verbose ES9+/APDU
plaintext lands in that log. Output is JSON; exit code 0 = ok. Compose ops in
shell or Python to run sequences.

## Reproduce from scratch

```bash
bash scripts/setup/setup_testbed.sh
```

Clones/builds/installs the patched OpenEUICC, provisions frida-server, sets
the required datastore prefs, then runs `selftest.sh`. Idempotent — safe to
re-run. A first-time privileged install triggers one reboot; rerun the script
after the phone comes back up.

## Requirements
- Rooted Pixel with our privileged **OpenEUICC** build (includes `EsimCtlActivity`
  — see `openeuicc/`) and `verbose_logging` enabled (already set).
- **Device unlocked** — eUICC APDU access is keyguard-gated. `scripts/device/keep_phone_awake.sh`
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
| `esim euicc list` | profiles (unmasked iccid, name, provider, state, class) | ✓ | — |
| `esim euicc eid` | eUICC EID | ✓ | ✓ |
| `esim euicc info` | EID + euiccInfo2 | ✓ | ✓ |
| `esim euicc notifications` | pending eUICC notifications | ✓ | — |
| `esim euicc download 'LPA:1$smdp$mid'` | download a profile; captures full ES9+ RSP plaintext | ✓ | ✓ |
| `esim euicc enable N` | enable profile #N | ✓ | — |
| `esim euicc disable N` | disable profile #N | ✓ | — |
| `esim euicc delete N` | delete profile #N (destructive) | ✓ | — |
| `esim euicc cycle --code '…' --times 5` | download→delete loop, each fully logged | ✓ | — |
| `esim euicc get-addresses` | ES10a: default SM-DP+ / root SM-DS addresses | ✓ | — |
| `esim euicc set-dp-address FQDN` | ES10a: write the default SM-DP+ address (`""` clears) | ✓ | — |
| `esim euicc get-rat` | ES10b: Rules Authorisation Table (raw BER-TLV) | ✓ | — |
| `esim euicc apdu HEX` | raw ES10x C-APDU to the ISD-R; returns response hex | ✓ | — |
| `esim euicc seq HEX... [RESET]...` | many APDUs on ONE ISD-R channel (state persists); `RESET` close+reopens the channel | ✓ | — |
| `esim euicc nickname N NAME` | ES10c: set a profile nickname (`""` clears) | ✓ | — |
| `esim euicc remove-notification SEQ` | ES10b: delete a pending notification locally | ✓ | — |
| `esim euicc handle-notification SEQ` | ES9+: send a pending notification to its SM-DP+ | ✓ | — |
| `esim euicc reset --confirm-wipe` | ES10c: eUICCMemoryReset — **erases ALL profiles** | ✓ | — |
| `esim euicc info1` | ES10b GetEUICCInfo1 (BF20) — version + CI PKID lists | ✓ | — |
| `esim euicc challenge` | ES10b GetEUICCChallenge (BF2E) — 16-byte SE nonce | ✓ | — |
| `esim euicc retrieve-notification SEQ` | ES10b RetrieveNotificationsList (BF2B) — signed blob | ✓ | — |
| `esim euicc apdu-aid AID HEX` | open a channel to ANY applet AID and transmit | ✓ | — |
| `esim euicc select-aid AID` | SELECT an applet, return its FCI (ECASD reachable) | ✓ | — |
| `esim euicc discovery [--smds D]` | ES11 SM-DS discovery — pending events for this EID | ✓ | — |
| `esim euicc authenticate SERVER` | standalone AuthenticateServer CI-trust probe | ✓ | — |
| `esim euicc card-<challenge\|info2\|smds\|default-smdp\|rat\|profiles>` | 2nd command path via framework IEuiccCardController (authz-gated) | ✓ | — |

`N` is the 1-based row from `list`; the tool resolves it to the full ICCID.

See `docs/reference/euicc-api.md` for the frontier ops (rows/verification). The
`discovery`/`authenticate` ops use a lpac JNI bridge (`openeuicc/es11-discovery.patch`).
ECASD AID = `A0000005591010FFFFFFFF8900000200`. The `card-*` ops reach the stock card
controller but return `RESULT_CALLER_NOT_ALLOWED` (gated on being the active LPA);
they need `hidden_api_policy 1` (set by `setup_testbed.sh`).

The last eight reach commands lpac-jni does not bridge to Kotlin. `get-addresses`,
`set-dp-address`, `get-rat`, and `apdu` build the ES10x store-data C-APDU
(`81 E2 91 00 …`) and transmit it on lpac's **already-open** ISD-R logical channel
(the ISD-R is non-multiselectable — a second channel is refused with SW 6999).
`reset` is hard-guarded: it refuses without `--confirm-wipe` and, in the activity,
without `--es confirm RESET`.

## Examples

```bash
python3 -m esim.cli euicc list
python3 -m esim.cli euicc eid
python3 -m esim.cli euicc download 'LPA:1$rsp.truphone.com$QRF-SPEEDTEST'
python3 -m esim.cli euicc enable 2 && python3 -m esim.cli euicc disable 2
python3 -m esim.cli euicc --backend fw eid

# no-LLM automation: cycle a code 10x, capture each RSP exchange
for i in $(seq 1 10); do
  python3 -m esim.cli euicc download 'LPA:1$rsp-eu.redteamobile.com$5901981126831169' > runs/$i.json
done
```

## Logging / output

Each invocation writes `.sessions/esimctl/<timestamp>-<op>/`:
- `logcat.txt` — full logcat across the op
- `rsp.json` — parsed ES9+ request/response bodies (download)
- `isub.txt` — raw subscription dump (ui backend reads)

Stdout JSON includes `log_dir`.

## Design

- `esim/euicc/` — CLI (`cli.py`), per-op `Session` (starts logcat before the op), backend
  dispatch (`ACT_OPS` = activity, `OPS` = ui), JSON out.
- `uidriver.py` — coordinate-free UI helper for the `ui` fallback backend.
- `openeuicc/` — the `EsimCtlActivity.kt` source + integration/build steps. The
  activity logs `ESIMCTL: <id> RESULT {json}`; `esim euicc` fires it via
  `am start` and reads the tagged result from logcat.

## Notes / limits
- The `download` op reports `ok:false` on a server-side failure (e.g. matchingId
  refused, pool empty) but still returns the captured RSP — that exchange is the
  deliverable.
- `fw` ops go through the default (stock) LPA, so their RSP bodies are opaque
  (see `docs/google-lpa-vs-openeuicc-rsp.md`).
