# eUICC API Reference — what we can actually call on this testbed

Authoritative, source-verified map of every eUICC API layer reachable on the
rooted Pixel 7a testbed, with the exact command → APDU tag → exposure at each
layer. Verified against the lpac C source, the lpac-jni bridge, OpenEUICC's
Kotlin API, `esimctl`, and the live device. Companion to
`docs/euicc-api-capability-map.md` (higher-level narrative); this file is the
detailed lookup table so subagents stop guessing.

## Device / stack ground truth
- Pixel 7a (lynx), Android 17 `user` build, arm64, Samsung S.LSI RIL, Magisk root.
- eUICC: EID `89033023427100000000027143866816`, ISD-R AID
  `A0000005591010FFFFFFFF8900000100`, SGP.22 v2.3, MEP, production CI `81370F5125D0B1D408D4C3B232E6D25E795BEBFB`.
- Transport to the eUICC = **OMAPI** (root bypasses the SE access-rule gate). The
  telephony `iccOpenLogicalChannel` path exists but returns "unavailable" for the
  ISD-R AID on this Samsung RIL and falls back to OMAPI. **No QMI, no gbinder HAL
  driver, no standalone lpac binary.** lpac runs *embedded* over OMAPI inside our
  privileged OpenEUICC build.
- Embedded eUICC is on **slot 0** (`slot=0 port=0`). Physical **slot 1** has no
  eUICC — OpenEUICC logs `OMAPI APDU interface unavailable for physical slot 1`.
- Live-verified 2026-07-15 via `EsimCtlActivity`: raw OMAPI exchanges observed —
  GetEID `81E2910006BF3E035C015A` → `BF3E125A10 89033023…6816`; GetEUICCInfo2
  `81E2910003BF2200` → CI `81370F…` present in both signing (`AA`) and verification
  (`AB`) lists.

## The layer stack (lowest → highest)

```
raw APDU (ApduInterface/OMAPI)  →  lpac C core (libeuicc)  →  lpac-jni (LpacJni.kt)
   →  Kotlin LocalProfileAssistant  →  EuiccChannelManager tasks  →  esimctl (EsimCtlActivity)
framework:  EuiccManager  →  IEuiccController / IEuiccCardController binders
```

- **Raw APDU — `net.typeblog.lpac_jni.ApduInterface`**: `logicalChannelOpen(aid)`,
  `transmit(handle, tx)`, `logicalChannelClose`. Sends **arbitrary APDUs to any
  applet** — the maximal capability. Open a channel to the ISD-R AID and transmit
  any ES10x C-APDU (`81 E2 91 00 Lc <BER-TLV>`), including commands not surfaced
  higher up. Implemented by `OmapiApduInterface` (OMAPI) and
  `TelephonyManagerApduInterface` (RIL, unavailable here).
- **lpac C core (`libeuicc`)**: the full SGP.22 command set (below), talking to the
  eUICC through `ApduInterface` and to SM-DP+/SM-DS through `HttpInterface`.
- **lpac-jni (`LpacJni.kt`)**: JNI bridge exposing a **subset** of the C core.
- **`LocalProfileAssistant`** (Kotlin): the app-facing API.
- **`EuiccChannelManagerService`** tasks: `launchProfileDownloadTask`,
  `launchProfileDeleteTask`, `launchProfileSwitchTask`, `launchProfileRenameTask`;
  reads via `withEuiccChannel(slot, port, seId){ it.lpa … }`.
- **`esimctl`** (`EsimCtlActivity`, driven by `tools/esimctl/esimctl.py`): the
  scriptable surface.
- **framework `EuiccManager`** (`--backend fw`): routes through the *stock* LPA,
  so RSP bodies are opaque (result codes only).
- **binders**: `econtroller` = `IEuiccController` (service 166),
  `euicc_card_controller` = `IEuiccCardController` (169) — reflection / `service
  call` reachable; not currently wrapped.

## Command exposure matrix

Tags per lpac source / SGP.22. Exposure: **C** = lpac core, **J** = lpac-jni,
**K** = Kotlin LPA, **E** = esimctl, **F** = framework EuiccManager.
Raw APDU can reach **every** row regardless of the higher columns.

### ES10c — local profile management
| Command | Tag | C | J | K | E | F |
|---|---|:-:|:-:|:-:|:-:|:-:|
| GetEID | BF3E | ✓ | `es10cGetEid` | `eID` | `eid` | `getEid` |
| GetProfilesInfo | BF2D | ✓ | `es10cGetProfilesInfo` | `profiles` | `list` | — |
| EnableProfile | BF31 | ✓ | `es10cEnableProfile` | `enableProfile` | `enable` | `switchToSubscription` |
| DisableProfile | BF32 | ✓ | `es10cDisableProfile` | `disableProfile` | `disable` | — |
| DeleteProfile | BF33 | ✓ | `es10cDeleteProfile` | `deleteProfile` | `delete` | `deleteSubscription` |
| eUICCMemoryReset | BF34 | ✓ | `es10cEuiccMemoryReset` | `euiccMemoryReset` | `reset` (guarded) | — |
| SetNickname | BF29 | ✓ | `es10cSetNickname` | `setNickname` | `nickname` | — |

### ES10b — download engine + notifications + info
| Command | Tag | C | J | K | E | F |
|---|---|:-:|:-:|:-:|:-:|:-:|
| GetEUICCChallenge | BF2E | ✓ | (inside download) | — | — | — |
| GetEUICCInfo1 | BF20 | ✓ | — | — | — | — |
| GetEUICCInfo2 | BF22 | ✓ | `es10cexGetEuiccInfo2` | `euiccInfo2` | `info` | `getEuiccInfo` |
| PrepareDownload | BF21 | ✓ | (inside download) | — | — | — |
| AuthenticateServer | BF38 | ✓ | (inside download) | — | — | — |
| LoadBoundProfilePackage | BF37 | ✓ | (inside download) | via `downloadProfile` | `download` | `downloadSubscription` |
| ListNotification | BF28 | ✓ | `es10bListNotification` | `notifications` | `notifications` | — |
| RetrieveNotificationsList | BF2B | ✓ | (via list) | — | — | — |
| RemoveNotificationFromList | BF30 | ✓ | `es10bDeleteNotification` | `deleteNotification` | `remove-notification` | — |
| HandleNotification (ES9+) | — | ✓ | `handleNotification` | `handleNotification` | `handle-notification` | (auto) |
| GetRAT (Rules Auth Table) | BF43 | ✓ | **—** | **—** | `get-rat` (raw APDU) | — |
| CancelSession | BF41 | ✓ | `cancelSessions` | `close` | — | — |

### ES10a — address configuration  (surfaced via raw APDU, not lpac-jni)
| Command | Tag | C | J | K | E | F |
|---|---|:-:|:-:|:-:|:-:|:-:|
| GetEuiccConfiguredAddresses (default SM-DP+, root SM-DS) | BF3C | ✓ | **—** | **—** | `get-addresses` | — |
| SetDefaultDpAddress | BF3F | ✓ | **—** | **—** | `set-dp-address` | — |

Live-verified 2026-07-15: `get-addresses` → rootDsAddress `lpa.ds.gsma.com`,
defaultDpAddress empty; `set-dp-address testdp.example.com` → `BF3F038001009000`
(result 0), read back, restored to empty. Values from the raw ES10a response
`BF3C11 810F 6C70612E64732E67736D612E636F6D 9000`.

### ES9+/ES8+/ES11 — RSP transport (network, driven internally by `downloadProfile`)
`es9p_initiate_authentication`, `es9p_authenticate_client`,
`es9p_get_bound_profile_package`, `es9p_handle_notification`, `es9p_cancel_session`;
`es11_authenticate_client` (SM-DS discovery); `es8p_metadata_parse`. Not exposed as
standalone calls — they run as the phases of a download. Full plaintext is logged
via `HttpInterfaceImpl` (verbose) — this is the lpac path's key research advantage.

## Reaching the unexposed commands — DONE (all surfaced in esimctl)
As of 2026-07-15 every previously-unexposed command is wired into `esimctl` and
the `EsimCtlActivity` `lpac` backend. Two mechanisms:

- **Raw ES10x over the ISD-R** (ES10a addresses, GetRAT, arbitrary `apdu`): build
  the store-data C-APDU `81 E2 91 00 Lc <BER-TLV>` and transmit it. Forms:
  GetEID `81E2910006 BF3E03 5C015A`; GetEuiccConfiguredAddresses `81E2910003 BF3C00`;
  GetRAT `81E2910003 BF4300`; SetDefaultDpAddress `81E29100 Lc BF3F Lc 80 Lc <fqdn>`
  (empty `80 00` clears it).
- **Existing Kotlin LPA methods** (nickname, reset, remove/handle notification):
  call `it.lpa.setNickname / euiccMemoryReset / deleteNotification / handleNotification`
  inside `withEuiccChannel`.

**Non-obvious gotcha (this cost a debug cycle):** the ISD-R is a **non-multiselectable
applet**, and lpac keeps its one permitted logical channel open for the whole context
lifetime. Opening a *second* channel to the ISD-R AID fails with **SW 6999**
(`openLogicalChannel → NO_SUCH_ELEMENT_ERROR`). So the raw path does **not** call
`withLogicalChannel`; it reflects `OmapiApduInterface.channels`, takes the already-open
handle, and calls `transmit(handle, apdu)` on it. See `isdrExchange()` in
`EsimCtlActivity.kt`. OMAPI's `Channel.transmit` handles 61xx GET RESPONSE, so a single
transmit returns full data+SW; no manual chaining. No NDK/lpac rebuild was needed —
JNI extension (option 2) was unnecessary.

The ES10a address get/set is the one most relevant to the adversary model
(manipulating the default SM-DP+ / root SM-DS the eUICC hands to the LPA).

## Trust boundary (what root does NOT grant)
Root gives the full **local** lifecycle (enable/disable/delete/reset/nickname),
EID read, raw ES10x APDU, and — at the lpac-C level — SM-DP+/SM-DS address get/set.
It does **not** grant eUICC private keys, ES8+/ES9+ crypto material, or ISD-P
provisioning. The **CI trust check is enforced inside the secure element** during
ES10b AuthenticateServer: a test-CI SM-DP+ is rejected `8.8.4/3.7`; only a
production-CI server (matching the eUICC's `81370F…` CI) completes an install.
Adversary operates at the authorization/discovery layer; the crypto core holds.

## Invocation quick reference
- Local mgmt / read / download (full plaintext): `tools/esimctl/esimctl.py <op>`
  (`list eid info notifications download enable disable delete cycle`).
- Raw ES10x / previously-unbridged: `esimctl.py <get-addresses | set-dp-address FQDN |
  get-rat | apdu HEX | nickname N NAME | remove-notification SEQ | handle-notification SEQ |
  reset --confirm-wipe>`.
- Frontier (see `docs/euicc-api-frontier.md`): `esimctl.py <info1 | challenge |
  retrieve-notification SEQ | apdu-aid AID HEX | select-aid AID | discovery [--smds D] |
  authenticate SERVER>`. ECASD AID = `A0000005591010FFFFFFFF8900000200`.
- Second command path (framework IEuiccCardController, authz-gated to the active LPA):
  `esimctl.py <card-challenge | card-info2 | card-smds | card-default-smdp | card-rat |
  card-profiles>`.
- Framework path: `esimctl.py --backend fw <eid|info|download|delete|switch>`.
- Raw APDU evidence: any `esimctl` op's `sessions/esimctl/<ts>-<op>/logcat.txt`
  shows the `OmapiApduInterface: OMAPI APDU:` request/response hex.
- Binders: `service call econtroller <code> …` (IEuiccController) — reflection-level,
  unwrapped.
