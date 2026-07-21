# eUICC API capability map — verified against the real setup

Verified 2026-07-15 on the actual testbed. Claims from the general capability
surface are marked ✓ (confirmed live), ◐ (present but not surfaced/works
differently here), or ✗ (not available on this setup).

## The real device / tooling

| | Value |
|---|---|
| Device | Google **Pixel 7a** (`lynx`) |
| OS | **Android 17**, SDK 37, `user` (release-keys) build |
| Arch | arm64-v8a |
| Modem/RIL | **Samsung S.LSI Vendor RIL** (NOT Qualcomm QMI) |
| Root | Magisk (`uid=0 … u:r:magisk:s0`) |
| eUICC | EID `89033023427100000000027143866816`, SGP.22 v2.3, MEP; ISD-R AID **`A0000005591010FFFFFFFF8900000100`**; trusted CI key `81370F…` (GSMA production) |
| Profiles / carriers | 2 Truphone profiles: **BetterRoaming**, **Speedtest Travel** (both Disabled; roam onto Verizon 311480 when enabled). **No physical SIM** (`ABSENT`). |
| LPA tooling | our privileged **OpenEUICC** build (`im.angry.openeuicc`, PRIVILEGED SYSTEM_EXT) with `EsimCtlActivity`; **lpac** embedded as `lpac-jni`; `esimctl` CLI driver. **No standalone lpac binary.** EasyEUICC not installed. |

## 1. Direct APDU to ISD-R (ES10x) — ✓ via OMAPI

- **Transport:** **OMAPI works** (the live channel; root/privileged bypasses the SE ARF/carrier-privilege gate). The **RIL / `iccOpenLogicalChannel`** path *exists* (`TelephonyManagerApduInterface`) but on this Pixel it returns **"APDU interface unavailable" for the ISD-R AID and falls back to OMAPI** — so on the Samsung-RIL Pixel 7a, OMAPI is the real transport, not RIL. ◐ vs the "OMAPI *or* RIL" claim.
- **ES10b** — ✓ GetEUICCChallenge (`BF2E`), GetEUICCInfo1/2 (`BF20`/`BF22`), PrepareDownload + LoadBoundProfilePackage + AuthenticateServer (exercised end-to-end by a real download/install).
- **ES10c** — ✓ EnableProfile, DisableProfile, DeleteProfile (all driven live via `esimctl`), GetProfilesInfo, GetEID (`BF3E`). `eUICCMemoryReset()` — **API present** (`LocalProfileAssistant.euiccMemoryReset`), not exercised (destructive).
- **ES10a** (GetEuiccConfiguredAddresses, SetDefaultDpAddress `BF3F`) — ✓ **now surfaced** in `esimctl` (2026-07-16) as `get-addresses` / `set-dp-address`, via the raw ISD-R path. Live: rootDs `lpa.ds.gsma.com`, defaultDp read/write/restore. (Was C-core-only when this map was first written.)
- GetEID — ✓ (live: `esim euicc eid`).

## 2. High-level EuiccManager — ✓

`android.telephony.euicc.EuiccManager` (`getEid`, `downloadSubscription`,
`switchToSubscription`, `deleteSubscription`) reachable via `esim euicc --backend fw`
(`fw eid` returns the EID live). Requires `WRITE_EMBEDDED_SUBSCRIPTIONS` +
`SECURE_ELEMENT_PRIVILEGED_OPERATION` — **granted** (confirmed live). Correction:
a **privileged priv-app + privapp-permissions whitelist** is sufficient; **full
platform signing is not required** (OpenEUICC is self-signed, installed privileged).
Framework calls route through the *default* (stock Google) LPA, so their RSP
message bodies are opaque — full plaintext only via the lpac path.

## 3. Internal framework APIs + open-source LPA — ✓ (OpenEUICC), ✗ (standalone lpac)

- **Binder services present:** `econtroller` (`IEuiccController`), `euicc_card_controller`
  (`IEuiccCardController`) — reflection-reachable. ◐ Wired as `esim euicc card-*` (2026-07-16):
  the binder transaction succeeds from OpenEUICC's process (hidden-API unblocked via root),
  but the stock card controller returns `-3 RESULT_CALLER_NOT_ALLOWED` — **authz-gated to
  the device's active LPA**, so reachable but not usable unless OpenEUICC is the default LPA.
- **OpenEUICC** — ✓ the working LPA; drives all reachable ES10x via OMAPI. **EasyEUICC** — ✗ not installed (removable-eSIM only anyway).
- **Standalone lpac** (`apdu_gbinder` / `apdu_qmi` / `apdu_at`) — ✗ on this device: Samsung RIL has no QMI; the gbinder HAL driver isn't built; there's no lpac Android binary. lpac only runs **embedded** (`lpac-jni`) with an **OMAPI-backed** APDU bridge. So "lpac with qmi/at/gbinder drivers" does not apply here.

## Boundary — ✓ confirmed (matches the modeling scope)

Root grants the full **local** profile lifecycle (enable/disable/delete/download),
EID read, and — at the lpac-C level — SM-DP+/SM-DS address get/set. It does **not**
grant the eUICC private keys or certificate forgery: the eUICC enforces the CI
trust check inside the secure element (test-CI SM-DP+ rejected with SGP.22
`8.8.4/3.7`; only production-CI profiles install), and ES8+/ES9+ crypto + ISD-P
provisioning hold. Adversary operates at the authorization/discovery layer, not
the trusted crypto core.

## Corrections to the general map, for this setup
1. Transport is **OMAPI**, not RIL — the telephony logical-channel path to ISD-R is unavailable on the Samsung-RIL Pixel 7a.
2. **Standalone lpac drivers (gbinder/qmi/at) don't apply** — lpac is embedded via OMAPI inside OpenEUICC.
3. **ES10a address get/set is now surfaced** in `esimctl` (`get-addresses` / `set-dp-address`, 2026-07-16) via the raw ISD-R path — was C-core-only when this map was first written.
4. EuiccManager needs a **privileged app**, not necessarily a **platform-signed** one.
