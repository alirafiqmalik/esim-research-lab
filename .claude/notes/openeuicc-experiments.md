---
name: openeuicc-experiments
description: Results of RSP experiments using the self-built privileged OpenEUICC on the rooted Pixel 7a — APDU/RSP capture, programmatic eUICC ops, MITM, and the test-server plan.
---

# OpenEUICC RSP Experiments (Pixel 7a, 2026-06-27)

Using our source-built privileged OpenEUICC (`im.angry.openeuicc`). See
[[device-pixel7a]]. All capture is observation of our own LPA — no MITM needed
for plaintext. Drive OpenEUICC **with the device unlocked** (keyguard gates
telephony/OMAPI APDU access).

## Built-in research toggles (DataStore `prefs`, dev options)

OpenEUICC ships the experiments as developer toggles — no code changes needed:

| key | effect |
|-----|--------|
| `verbose_logging` | logs raw APDUs (`OmapiApduInterface`/`TelephonyManagerApduInterface`) + ES9+ HTTP (`HttpInterfaceImpl`: `HTTP tx`, `HTTP response body`) |
| `ignore_tls_certificate` | swaps in `AllowAllTrustManager` — accepts any ES9+ TLS cert (enables mitmproxy) |
| `isdr_aid_list` | override the ISD-R AIDs tried |
| `es10x_mss`, `force_tpdu_mode` | low-level APDU tuning |
| `developer_options_enabled` | reveals the dev category in Settings |

Enable programmatically by writing the Preferences-DataStore protobuf to
`/data/data/im.angry.openeuicc/files/datastore/prefs.preferences_pb` (owner =
app uid 10317, context `privapp_data_file`), then force-stop + relaunch. Generator:
`tmp/mkprefs.py`. Or: Settings → tap version 7× → Developer options.

## Exp 1 — RSP/APDU plaintext logging  ✅

With `verbose_logging` on, the eUICC enumeration is captured in the clear:

- **ES10b GetEUICCInfo1** `81E2910003BF2200` → CI key IDs, eUICC spec v2.3, label `TS-PA-UP-0423`.
- **ES10c GetEID** `81E2910006BF3E035C015A` → `5A10` + 16 bytes.

ES9+/ES11 HTTP plaintext is logged the same way on a download/discovery
(`HttpInterfaceImpl: HTTP tx = ...` / `HTTP response body = ...`). This is the
clean version of what we chased with Frida on the Google LPA.

## Exp 2 — programmatic eUICC read  ✅

Read directly from the eUICC via OpenEUICC:

- **EID:** `89033023427100000000027143866816`
- **Trusted CI key ID:** `81370F5125D0B1D408D4C3B232E6D25E795BEBFB` (production GSMA CI)
- **eUICC label:** `TS-PA-UP-0423`, spec v2.3, MEP supported, **0 profiles**

OpenEUICC also exposes (UI + lpac): profile list, eUICC info, notifications,
slot mapping, enable/disable/delete, download. These are driveable via the
`LPA:`/`lpa:` VIEW intent into `DownloadWizardActivity` and the app's activities.

## Exp 3 — cooperating MITM (ready)

`ignore_tls_certificate` + `adb reverse tcp:PORT tcp:PORT` + set the SM-DP+ to a
mitmproxy reverse target lets us decrypt/modify ES9+ in our own build (legit —
we own the client). Pending a download trigger to exercise it.

## Test server / end-to-end RSP

- **osmo-smdpp** (Osmocom pySim) — self-hostable PoC SM-DP+, **SGP.26 test certs**.
- **sysmocom public test SM-DP+** `smdpp.test.rsp.sysmocom.de`, key ID
  `f54172bdf98a95d65cbeb88a38a1c11d800a85c3`, TS.48 test profiles, not EID-locked.

**Hard constraint:** both use **test-CI** certs. The Pixel eUICC trusts only the
**production CI** (`81370F...`), validated inside the secure element during ES8+
mutual auth — unbypassable. So a download from a test server to the Pixel will
proceed through ES9+ (capturable) but the eUICC rejects it at AuthenticateServer.
A successful end-to-end install needs an eUICC with SGP.26 test keys (e.g.
sysmoEUICC / Comprion test card, or a removable test eSIM). Without one, the
self-hosted server is still valuable for capturing/replaying the ES9+/ES11
exchange end-to-end up to the eUICC auth step.

## RSP executed end-to-end through the phone (2026-06-27) ✅ — definitive

Drove OpenEUICC's download wizard (manual entry, separate address/matchingID
fields to avoid `$`-escaping) against the sysmocom test SM-DP+, with
`verbose_logging` + `ignore_tls_certificate` on. The full RSP protocol executed
and was captured in plaintext. Artifacts: `sessions/openeuicc-rsp-20260627/`
(`full_logcat.txt`, `decoded_rsp.txt`).

Flow captured:
1. **ES10b GetEUICCChallenge** → `7C0836E3B8EFB81C9761F12DEC1705FD`
2. **ES10b GetEUICCInfo1** → SGP.22 v2.3, CI PK ID `81370F5125D0B1D408D4C3B232E6D25E795BEBFB` (production GSMA CI, both A9 verify + AA sign lists)
3. **ES9+ initiateAuthentication** (POST `/gsma/rsp2/es9plus/initiateAuthentication`):
   `{"smdpAddress":"smdpp.test.rsp.sysmocom.de","euiccChallenge":"fAg247jvuByXYfEt7BcF/Q==","euiccInfo1":"vyA1..."}`
   — TLS connected (HTTP 200) thanks to `ignore_tls_certificate`.
4. **SM-DP+ response: Failed**, SGP.22 `subjectCode 8.8.4 / reasonCode 3.7`:
   *"The SM-DP+ has no CERT.DPauth.SIG which chains to one of the eSIM CA Root CA
   Certificate with a Public Key supported by the eUICC."*
   UI: *"This eSIM profile is unsupported by your eSIM chip."*

**Conclusion (empirical):** the protocol runs correctly; the install is blocked
at the **CI-trust negotiation**, not by our setup. The production eUICC advertises
only the production CI (`81370F…`); the test server only holds test-CI (`f54172…`)
certs, so the server itself refuses at the first authentication step. The
`ignore_tls_certificate` toggle bypasses the **ES9+ TLS** layer only — it cannot
touch the **RSP CI trust** check (server-side here; eUICC-side AuthenticateServer
otherwise). This is the GSMA security model working as designed; no LPA change
bypasses it.

**To get a successful INSTALL through the phone you need matching CI**, one of:
- a real **production-CI** profile (a normal/free-trial carrier eSIM activation code), or
- an eUICC carrying **SGP.26 test CI** keys (removable test eSIM / sysmoEUICC) — the
  internal Pixel eUICC cannot be given test CI keys.

## LIVE production RSP handshake — SUCCESS (2026-06-29) ✅✅

Executed a real end-to-end GSMA RSP download on the **production** Pixel eUICC
using a free **BetterRoaming / Truphone (1GLOBAL)** bootstrap profile — production
CI, so the eUICC accepts it. The profile **actually installed**. Full ES9+
plaintext captured in `sessions/betterroaming-live-rsp-20260629/`
(`handshake_capture.txt`, `decoded_handshake.txt`).

Activation code (production, reusable, from osmocom euicc-manual "freely available
production profiles"): `LPA:1$rsp.truphone.com$QRF-BETTERROAMING-PMRDGIR2EARDEIT5`
(backups `QR-G-5C-1LS-1W1Z9P7`, `QR-G-5C-KR-1PCDWP9` — these two were spent →
`8.2.6/3.8 Matching ID Refused`).

Captured flow (SM-DP+ `rsp.truphone.com`, transactionId `000000001C85E05C`):
1. ES10b GetEUICCChallenge / GetEUICCInfo1 (eUICC)
2. **ES9+ initiateAuthentication → `Executed-Success`** — server returned
   `euiccCiPKIdToBeUsed = 81370F5125D0B1D408D4C3B232E6D25E795BEBFB` (the production
   CI the eUICC trusts). Contrast: sysmocom test SM-DP+ = instant `8.8.4/3.7`.
3. **ES10b AuthenticateServer (eUICC) → PASSED** — the secure element validated the
   production SM-DP+ certificate (this is the step no LPA toggle can fake).
4. ES9+ authenticateClient → (primary code) success → getBoundProfilePackage →
   **ES8+ LoadBoundProfilePackage → profile installed** ("BetterRoaming", slot #1).

**Definitive proof of the CI model:** same eUICC, same LPA, same toggles — a
**production-CI** server completes the full handshake and installs; a **test-CI**
server is refused at the first message. The certificate barrier is real and
CI-bound, exactly as documented; the way "around" it for a working install is a
**matching-CI profile** (production profile here; or a test-CI eUICC for test
servers), not an LPA/root bypass.

## RSP test matrix — 4 SM-DP+ operators, fully logged (2026-06-29)

Ran 4 activation codes one-by-one via OpenEUICC, continuous `logcat` started
BEFORE each download. Artifacts: `sessions/rsp-test-<label>-20260629/`
(`capture.txt` full log + `decoded.txt` ES9+ plaintext). No profiles deleted.

| Label | SM-DP+ | Outcome | CI | Installed |
|-------|--------|---------|----|-----------|
| redteago | rsp-eu.redteamobile.com | initiateAuth→Executed-Success; authClient→Failed `9.4/10.1` "campaign resource pool is empty" | **production** | no (free pool empty) |
| truphone-speedtest | rsp.truphone.com | full success → ES8+ load → **INSTALLED** ("Speedtest Travel" #2), txn `000000001C85ECB8`, CI `81370F…` | **production** | **yes** |
| sysmocom-ts48 | smdpp.test.rsp.sysmocom.de | initiateAuth→Failed `8.8.4/3.7` (no CERT.DPauth chaining to a supported CI) | **test** | no |
| google-aosp-ts48 | prod.smdp-plus.rsp.goog | initiateAuth→Failed `8.8.2/3.1` "Execution Failed" | **test** | no |

Conclusions (cross-validated across 4 independent operators):
- **production-CI ⇒ the eUICC `AuthenticateServer` passes** and the handshake
  proceeds; it installs when a profile is actually available (Truphone Speedtest
  installed; RedteaGO passed the crypto path but the free pool was empty — a
  server-side `9.4/10.1`, not a CI failure).
- **test-CI ⇒ refused at the first message** (`initiateAuthentication`), never
  reaching `authenticateClient`. Google returns generic `8.8.2/3.1`, sysmocom the
  explicit `8.8.4/3.7` — both are the production-vs-test CI mismatch.
- The GSMA TS.48 generic test profile and the AOSP/Google test server are both
  **test-CI only** → not installable on the production Pixel eUICC (need an SGP.26
  test eUICC). Research: `docs/research-gsma-ts48-test-profile.md`,
  `docs/research-aosp-esim-testing.md`, `docs/research-other-free-esim-codes.md`.

eUICC now holds 2 disabled profiles: #1 BetterRoaming, #2 Speedtest Travel.

## Sources
- osmo-smdpp: https://osmocom.org/projects/pysim/wiki/Osmo-smdpp
- sysmocom test SM-DP+: https://euicc-manual.osmocom.org/docs/rsp/known-test-profile/
- Android test profiles: https://source.android.com/docs/core/connect/esim-test-profiles
