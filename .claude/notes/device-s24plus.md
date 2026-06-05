---
name: device-s24plus
description: Samsung Galaxy S24+ (SM-S926U1) — verified ADB commands, eSIM profile inventory, RSP infrastructure findings
---

# Device: Samsung Galaxy S24+ (SM-S926U1)

- ADB serial: R5CX804NGAT
- OEM: Samsung, One UI (Android 14)
- Carrier context: unlocked, multiple eSIM profiles stored
- TLS pinning: untested — run capture session to determine

## eUICC status

`Euicc enabled=true`. Active embedded subscriptions: [1, 7, 8].

## Profile inventory (as of 2026-06-04)

| sub_id | Name | ICCID prefix | profileClass | State | Notes |
|--------|------|--------------|--------------|-------|-------|
| 1 | AT&T | 890138062 | PROVISIONING (1) | disabled | Bootstrap V1.0 — pre-loaded OEM profile |
| 7 | Liberty | 890179010 | OPERATIONAL (2) | disabled | Plan data expired |
| 8 | eSIM Go | 894442271 | OPERATIONAL (2) | disabled | Plan data expired |
| 2 | Mint | 890124036 | — | physical SIM slot 1 | Active, has service |

Historical SIM records also in DB (sub_ids 3-6: Nomad, 1GLOBAL, Ufone×2) from previously inserted physical SIMs.

## Samsung LPA

- Component: `com.samsung.euicc.service.EuiccServiceImpl`
- `euicc_card_controller` service exists (`mBestComponent=null`) — Samsung's LPA does NOT register with AOSP euicc_card_controller, so `esim eid` will fail
- EID: not accessible via ADB without root on Samsung. Read it from Settings → About phone → Status → EID

## RSP infrastructure

- SM-DS: `rsp.truphone.com` (primary discovery server — **mitmproxy capture target**)
- SM-DP+ servers observed:
  - `sm-v4-099-a-gtm.pr.go-esim.com` (eSIM Go download, 2025-12-18)
  - `rsp-3104.idemia.io` (Liberty download via Idemia, 2025-12-22)
- Push notification token for SM-DS discovery registered (QueryDsWorker scheduled)

## Verified ADB commands

- `dumpsys isub` → works; shows all subscriptions including embedded ones
- `dumpsys econtroller` → works; dumps Samsung LPA state, profile cache, psshdb, RSP addresses
- `esim profiles list` → returns all 8 subscription records correctly
- `esim eid` → raises ADBError (Samsung LPA not registered with AOSP service)

## Logcat tags for eSIM activity

Monitor these tags during capture:
- `EuiccConnector`
- `EuiccManager`
- `EuiccController`
- `com.samsung.euicc`

## Parser notes

`SubscriptionInfoInternal` format is identical to CPH2515 (Android 13+). Samsung One UI adds extra fields (`serviceCapabilities`, `transferStatus`, `satelliteEntitlement*`) which the parser ignores safely.

The `displayName` field can contain spaces (e.g., "eSIM Go"). The field-map parser in `_parse_isub_block()` handles this correctly by using `\s+\w+=` as field boundaries.
