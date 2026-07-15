# eUICC API surface — read before touching eSIM APIs

Full source-verified detail: `docs/euicc-api-reference.md` (command → APDU tag →
exposure matrix). This note is the fast index. Don't re-derive; verify against
the running device only when a fact here looks stale.

## The one thing to know
There are six layers. The **lowest one is complete**:
`ApduInterface` (`logicalChannelOpen(aid)` + `transmit(handle, tx)`, OpenEUICC's
`OmapiApduInterface`) sends **arbitrary APDUs to the ISD-R** — any ES10x command,
including ones not surfaced higher. Everything above it is a convenience subset.

```
raw APDU/OMAPI → lpac C core → lpac-jni (LpacJni.kt) → LocalProfileAssistant
   → EuiccChannelManager tasks → esimctl        |  framework: EuiccManager → binders
```

## Device facts (live-verified 2026-07-15)
- Pixel 7a (lynx), Android 17, Samsung S.LSI RIL, Magisk root. Transport = **OMAPI**
  (not RIL — `iccOpenLogicalChannel` returns unavailable for ISD-R here).
- Embedded eUICC = **slot 0 / port 0**. Physical slot 1 has no eUICC.
- EID `89033023427100000000027143866816`, ISD-R `A0000005591010FFFFFFFF8900000100`,
  SGP.22 v2.3, production CI `81370F5125D0B1D408D4C3B232E6D25E795BEBFB`.

## What's exposed where (short form)
- **Scriptable now (`tools/esimctl/esimctl.py`)**: `list eid info notifications
  download enable disable delete cycle`. `--backend fw` for
  `eid info download delete switch` (stock LPA, opaque RSP).
- **In Kotlin LPA but not esimctl**: `euiccMemoryReset`, `setNickname`,
  `deleteNotification`, `handleNotification`. (add a case to `EsimCtlActivity.runLpac`.)
- **In lpac C core, NOT bridged to Kotlin** (need raw APDU or a JNI add):
  - ES10a `GetEuiccConfiguredAddresses` (BF3C) / `SetDefaultDpAddress` (BF3F) —
    the default SM-DP+ / root SM-DS the eUICC hands the LPA. **Most relevant to the
    adversary model.** C funcs exist: `es10a_get_euicc_configured_addresses`,
    `es10a_set_default_dp_address`.
  - ES10b `GetRAT` (BF43) — Rules Authorisation Table.
- **ES9+/ES8+/ES11**: run only as internal phases of `downloadProfile`; full
  plaintext is logged (verbose) — the lpac path's research advantage over the fw path.

## Trust boundary (don't waste cycles trying to cross it)
Root grants full **local** lifecycle + EID + raw ES10x + (C-level) address get/set.
It does **not** grant eUICC keys, ES8+/ES9+ crypto, or ISD-P provisioning. The
**CI trust check lives in the secure element** (ES10b AuthenticateServer): test-CI
SM-DP+ → rejected `8.8.4/3.7`; only production-CI (`81370F…`) installs. Confirmed
on hardware. Related: [[rsp-tls-pins-to-gsma-ci]].

## Binders (unwrapped, reflection/`service call` reachable)
`econtroller` = `IEuiccController` (svc 166), `euicc_card_controller` =
`IEuiccCardController` (svc 169).
