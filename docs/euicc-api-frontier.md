# eUICC API frontier — new surface beyond esimctl

Additional eUICC commands and indirect paths found by static analysis of the lpac
C core, the AOSP telephony binders, and the device, plus a few safe live probes.
Ranked by value. Companion to `docs/euicc-api-reference.md` (what we already ship)
and `.claude/notes/euicc-api-surface.md`.

Device: Pixel 7a (lynx), Android 17, Magisk root, OMAPI transport, production CI
`81370F5125D0B1D408D4C3B232E6D25E795BEBFB`.

## Implementation status (2026-07-16) — all rows now wired into esimctl

| Row | Capability | esimctl op | Verified result |
|---|---|---|---|
| 1 | IEuiccCardController | `card-challenge/info1/info2/smds/default-smdp/rat/profiles` | **Reachable, authz-gated.** Binder txn succeeds (hidden-API unblocked via root `hidden_api_policy 1`); stock card controller returns `-3 RESULT_CALLER_NOT_ALLOWED` — gated on caller being the active LPA. cardId = EID string. |
| 2 | GetEUICCInfo1 (BF20) | `info1` | ✅ version + CI PKID signing/verification lists |
| 3 | RetrieveNotificationsList (BF2B) | `retrieve-notification SEQ` | ✅ returns the signed PendingNotification for a seq (empty when queue empty) |
| 4 | AuthenticateServer (BF38) | `authenticate SERVER` | ✅ CI-trust probe. Prod CI (`lpa.ds.gsma.com`, `rsp.truphone.com`) → `ciTrusted:true stage:accepted`; foreign/test-CI → rejected at its stage |
| 5 | ES11 SM-DS discovery | `discovery [--smds]` | ✅ full round trip to `lpa.ds.gsma.com`, 0 pending events (correct), authServer passes (prod CI) |
| 6 | GetEUICCChallenge (BF2E) | `challenge` | ✅ 16-byte SE nonce |
| 7 | ECASD | `select-aid`/`apdu-aid <ECASD>` | ✅ selectable at `A0000005591010FFFFFFFF8900000200`; Card Recognition Data (66) + Key Info Template (E0) readable; certs (7F21) auth-protected (6A88) |
| 8 | ARA-M | `select-aid A00000015141434C00` | ✗ not present on this eUICC's OMAPI reader (NoSuchElement) |

Rows 4/5 use a lpac JNI bridge (`es11-discovery.patch`); the rest use the raw ISD-R
path or reflection. Detail below.

## Ranked new capabilities

| # | Capability | How to reach it | Exact APDU / method | eUICC command it grants | Status | Adversary value |
|---|---|---|---|---|---|---|
| 1 | **IEuiccCardController** — the framework's per-command card interface | Binder svc **169** `euicc_card_controller`; `IEuiccCardController.Stub.asInterface(ServiceManager.getService(...))` **from OpenEUICC's process** (holds `WRITE_EMBEDDED_SUBSCRIPTIONS`, confirmed granted) | `getEuiccChallenge`, `getEuiccInfo1/2`, `authenticateServer`, `prepareDownload`, `loadBoundProfilePackage`, `getRulesAuthTable`, `getSmdsAddress`, `getDefaultSmdpAddress`, `setDefaultSmdpAddress`, `retrieveNotification(seq)`, `listNotifications`, `removeNotificationFromList`, `disableProfile`, `switchToProfile`, `deleteProfile`, `resetMemory`, `getAllProfiles`, `getProfile` | The **entire ES10 command set**, each as a binder call, routed through the **stock Google card stack** — independent of our lpac stack | Source-only (perm held; needs a reflection call wired into OpenEUICC's process — `service call` as shell uid 2000 is rejected) | **Highest.** A complete second, independent command path. Cross-checks lpac; survives if the lpac path breaks; exercises the OEM card code directly |
| 2 | **GetEUICCInfo1** (BF20) | existing `esimctl apdu` | `81E2910003BF2000` | GetEUICCInfo1 — SGP.22 version + CI PKID lists (signing `A9`, verification `AA`) | **Verified live** → `BF20358203020300A9160414 81370F… AA160414 81370F… 9000` | Low/medium. Confirms which CIs the eUICC trusts, standalone (no download) |
| 3 | **RetrieveNotificationsList by seq** (BF2B) | existing `esimctl apdu` | `81E2910008 BF2B05 A003 8001 <seq>` (searchCriteria→seqNumber) | Pulls the **full eUICC-signed PendingNotification** (ProfileInstallationResult / signed notification blob), not just the metadata `list` gives | **Verified reachable** → `BF2B…9000` (empty for a churned seq during the concurrent test run) | **Medium/high.** Extract the signed notification the eUICC would send to the SM-DP+ → replay / offline analysis |
| 4 | **AuthenticateServer** (BF38) standalone | existing `esimctl apdu` (mid-session) | `81E29100 Lc BF38 …serverSigned1/sig/cert…` | ES10b AuthenticateServer — the step that runs the **CI trust check inside the SE** | Source-only (needs a live ES9+ initiateAuthentication first to get server challenge) | **High.** The exact point to feed a crafted/foreign-CI server cert and observe the `8.8.4/3.7` rejection — the core of the CI-trust experiment |
| 5 | **ES11 SM-DS discovery** (`es11_authenticate_client`) | lpac C core; not bridged | lpac `es11_authenticate_client` → root SM-DS `lpa.ds.gsma.com` | Query the root SM-DS for pending download events for this EID | Source-only (lpac C, no LpacJni binding; runs only inside download when no SM-DP+ given) | **High.** The discovery layer — an adversary who controls SM-DS responses steers the LPA to a chosen SM-DP+ |
| 6 | **GetEuiccData / Challenge** (BF2E), **PrepareDownload** (BF21), **LoadBoundProfilePackage** (BF37) | existing `esimctl apdu` (mid-session) | `81E2910003BF2E00` (data); BF21/BF37 need signed inputs | Standalone RSP-phase primitives | Source-only (only meaningful with valid session inputs) | Medium. Manual step-through of the download state machine |
| 7 | **ECASD** — eUICC cert / identity SD | OMAPI SELECT to ECASD AID, then GET DATA | SELECT `00A40400 <ECASD-AID>`; GET DATA for `CERT.EUICC.ECDSA` / EUM cert | eUICC certificate chain + EID attestation, bypassing ISD-R | Theoretical (needs a new logical channel to a different AID — our `apdu` op reuses the ISD-R channel; most eUICCs refuse external ECASD SELECT) | Medium. The device identity/attestation material |
| 8 | **ARA-M** — access-rule master | OMAPI SELECT `A00000015141434C00`, GET DATA `FF40` | SELECT `00A40400 09 A00000015141434C00`; `80CAFF4000` | Reads the SE access-control rules (which apps may open which applets) | Theoretical (needs a new-AID channel; root likely bypasses the gate) | Medium. Maps the OMAPI access policy that root bypasses |

## Two independent command paths (the big picture)
1. **lpac over OMAPI** (what esimctl uses) — full plaintext, our code, ISD-R channel reuse.
2. **IEuiccCardController binder** (row 1) — the same ES10 commands through the stock
   OEM card stack. OpenEUICC already holds the guarding permission. Wiring one
   reflection call into `EsimCtlActivity` would expose `getEuiccChallenge`,
   `authenticateServer`, `prepareDownload`, `loadBoundProfilePackage`,
   `getRulesAuthTable`, `getSmdsAddress`, and `retrieveNotification(seq)` as a second,
   cross-checkable backend.

## Reaching a different applet (ECASD / ARA-M)
The current `apdu` op transmits on lpac's already-open **ISD-R** channel, so it cannot
SELECT another applet. Rows 7-8 need a small esimctl op that opens a **fresh logical
channel to the target AID** (`ch.apduInterface.logicalChannelOpen(aid)` — allowed,
since the non-multiselectable limit is per-applet and applies only to a second ISD-R
channel). Not wired here (read-only exploration).

## lpac C-core functions with no LpacJni.kt binding
`es10a_*` (surfaced via raw APDU), `es10b_get_rat` (surfaced), `es10b_get_euicc_info`
(BF20, row 2), `es10b_get_euicc_challenge_and_info` (BF2E, row 6),
`es10b_prepare_download`, `es10b_authenticate_server`, `es10b_load_bound_profile_package`,
`es10b_retrieve_notifications_list` (BF2B, row 3), `es10b_cancel_session`,
`es10x_command` / `es10x_command_iter` (the generic transceiver our `apdu` op mirrors),
`es9p_*` / `es11_*` / `es8p_*` (network side, row 5). None add a command our raw-APDU
op cannot already send; they add typed parsing.
