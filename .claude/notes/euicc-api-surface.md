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
- **Newly surfaced 2026-07-15** (previously unbridged — all live-verified):
  - `get-addresses` / `set-dp-address FQDN` — ES10a BF3C / BF3F, the default
    SM-DP+ + root SM-DS. **Most relevant to the adversary model.** rootDs =
    `lpa.ds.gsma.com`; set/read/restore proven.
  - `get-rat` — ES10b BF43 Rules Authorisation Table.
  - `apdu HEX` — raw ES10x C-APDU to the ISD-R (universal escape hatch).
  - `nickname N NAME`, `remove-notification SEQ`, `handle-notification SEQ` — Kotlin
    LPA methods.
  - `reset --confirm-wipe` — eUICCMemoryReset; **hard-guarded, wipes ALL profiles**.
- **How the raw path works (non-obvious)**: the ISD-R is **non-multiselectable** and
  lpac holds its one logical channel open, so a 2nd `openLogicalChannel` fails with
  **SW 6999**. `isdrExchange()` reflects `OmapiApduInterface.channels`, reuses the
  open handle, and `transmit`s on it. No NDK/lpac rebuild needed.
- **ES9+/ES8+/ES11**: run only as internal phases of `downloadProfile`; full
  plaintext is logged (verbose) — the lpac path's research advantage over the fw path.

## Trust boundary (don't waste cycles trying to cross it)
Root grants full **local** lifecycle + EID + raw ES10x + address get/set (now scriptable).
It does **not** grant eUICC keys, ES8+/ES9+ crypto, or ISD-P provisioning. The
**CI trust check lives in the secure element** (ES10b AuthenticateServer): test-CI
SM-DP+ → rejected `8.8.4/3.7`; only production-CI (`81370F…`) installs. Confirmed
on hardware. Related: [[rsp-tls-pins-to-gsma-ci]].

## Binders (unwrapped, reflection/`service call` reachable)
`econtroller` = `IEuiccController` (svc 166), `euicc_card_controller` =
`IEuiccCardController` (svc 169). The latter exposes the **entire ES10 command set**
as binder calls through the stock card; OpenEUICC holds its guard perm
(`WRITE_EMBEDDED_SUBSCRIPTIONS`). See `docs/euicc-api-frontier.md`.

## Frontier — new surface beyond esimctl
`docs/euicc-api-frontier.md`: ranked new commands/paths. Verified live: GetEUICCInfo1
(BF20 `81E2910003BF2000`), RetrieveNotificationsList by seq (BF2B, pulls the signed
notification). Highest-value untapped: the IEuiccCardController binder (2nd command
path via the OEM card) and standalone AuthenticateServer (BF38, the CI-trust step).
