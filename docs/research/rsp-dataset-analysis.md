# eSIM RSP Dataset — What We're Working With

Analysis of the fully-logged RSP dataset captured on the rooted Pixel 7a with our
self-built privileged OpenEUICC. Every capture below started logging *before* the
RSP procedure, so the ES9+/ES10 plaintext is complete.

## The hardware (our eUICC)

- Device: Pixel 7a (lynx), rooted, internal non-removable eUICC.
- EID: `89033023427100000000027143866816`.
- SGP.22 **v2.3**, MEP (multiple enabled profiles, 2 logical slots), ~809 KiB free.
- Trusted eSIM CA / CI public key: **`81370F5125D0B1D408D4C3B232E6D25E795BEBFB`**
  (production GSMA CI — DigiCert "RSP2 Root CI1"). This single value is the gate
  that decides which servers work.

## The profiles installed (both Truphone bootstrap)

| # | Name / Provider | ICCID | IMSI | Home PLMN | When enabled |
|---|-----------------|-------|------|-----------|--------------|
| 1 | BetterRoaming | `894447650…` | `234250004…` | 234/25 (Truphone, GB) | registers IN_SERVICE, LTE B66, **roams onto 311480 (Verizon US)** |
| 2 | Speedtest Travel | `894447650…` | `234250004…` | 234/25 (Truphone, GB) | same: IN_SERVICE LTE, **311480 Verizon** |

Both are Truphone-issued bootstrap profiles sharing one subscription identity
(same IMSI). Enabling either gives **real LTE attach** (voice+data IN_SERVICE) via
roaming on Verizon — not just a dead test profile. Data plan/voucher would be
needed for actual throughput, but the network registration is genuine.

## RSP protocol coverage captured

ES9+ (LPA ↔ SM-DP+, application layer, plaintext via verbose logging):

| Endpoint | Count | Notes |
|----------|-------|-------|
| initiateAuthentication | 10 | across 6 SM-DP+ operators |
| authenticateClient | 5 | reached only on production-CI servers |
| getBoundProfilePackage | 2 | the BPP fetch before ES8+ install |
| handleNotification | 2 | post-install notifications |

ES10b/ES10c (LPA ↔ eUICC, raw APDUs, plaintext hex):

- `BF2E` GetEUICCChallenge · `BF20` EUICCInfo1 · `BF22` EUICCInfo2 ·
  `BF3E` GetEID · `BF2D` GetProfilesInfo · `BF31` **EnableProfile** ·
  `BF32` **DisableProfile** · plus AuthenticateServer + notification/management cmds.

ES8+ (SM-DP+ → eUICC, end-to-end encrypted BPP): observed as
`es10b_load_bound_profile_package` — the bytes pass through but stay opaque
(decrypted only inside the secure element).

## SGP.22 outcomes observed (the full error taxonomy)

| Status | Count | Meaning | Trigger |
|--------|-------|---------|---------|
| Executed-Success | 10 | step OK | production-CI servers; all ES10 ops |
| `8.8.4 / 3.7` | 4 | "no CERT.DPauth chaining to a CI the eUICC supports" | sysmocom **test-CI** |
| `8.8.2 / 3.1` | 2 | "Execution Failed" (generic) | Google AOSP **test-CI** |
| `8.2.6 / 3.8` | 1 | "Matching ID Refused" | spent/invalid matching ID |
| `9.4 / 10.1` | 2 | "campaign resource pool is empty" | RedteaGO free pool exhausted |

## What this means — the picture

1. **The CI trust check is the master switch, confirmed across 6 operators.**
   production-CI server → eUICC `AuthenticateServer` passes → handshake proceeds /
   installs. test-CI server → refused at the *first* message. Same eUICC, same LPA,
   same toggles; only the CI changes the result.
2. **We have full read/observe/control of the RSP stack** except the two parts
   sealed in the secure element (the eUICC's private keys and ES8+ BPP plaintext):
   read EID/EUICCInfo/profiles, drive download/enable/disable, and capture every
   ES9+/ES10 message in plaintext.
3. **We have two genuinely live profiles** that attach to a real LTE network
   (Verizon, via Truphone roaming) — useful for exercising enable/disable, network
   registration, and post-install notification flows.
4. **Limits, restated:** test-CI profiles (GSMA TS.48, AOSP/Google, sysmocom)
   cannot install on this production eUICC; that needs an SGP.26 test eUICC. ES8+
   profile contents (the actual keys/applets) never appear in the clear.

## Session artifacts

| Session | Contents |
|---------|----------|
| `betterroaming-live-rsp-20260629/` | first successful production install + decoded ES9+ |
| `rsp-test-{truphone-speedtest,redteago,sysmocom-ts48,google-aosp-ts48}-20260629/` | 4-operator matrix, each `capture.txt` + `decoded.txt` |
| `profile-cycle-20260629/` | enable/analyze/disable cycle for both profiles + telephony registration |
| `openeuicc-rsp-20260627/` | first sysmocom test-CI rejection (`8.8.4/3.7`) |
| `pixel7a-20260627/`, `s24plus-20260604/` | earlier mitmproxy TLS captures |
