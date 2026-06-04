---
name: device-cph2515
description: OnePlus Nord N30 5G (CPH2515) T-Mobile — verified ADB commands, OxygenOS output format quirks, dumpsys parsing notes
---

# Device: OnePlus Nord N30 5G (CPH2515)

- ADB serial: 3ddf2893
- OEM: OnePlus, OxygenOS (Android 13)
- Carrier: T-Mobile US
- TLS pinning: untested — see tls-pinning-status.md after first capture

## eUICC status

**No embedded eSIM hardware.** `dumpsys isub` shows `Euicc enabled=false` and `Embedded subscriptions: []`.

- `dumpsys euicc_card_controller` — exits 0 but prints `Can't find service: euicc_card_controller`
- `com.qualcomm.qti.lpa` is installed but there is no eUICC chip to drive
- `esim eid` raises `ADBError: eUICC hardware not present or disabled (Euicc enabled=false)`

When a removable eUICC SIM (SIM-form-factor eUICC) is inserted and activated, `Euicc enabled` becomes `true` and `euicc_card_controller` starts responding. At that point `esim eid` will work.

## Verified ADB commands

- `dumpsys isub` → works; uses `SubscriptionInfoInternal` format (space-separated key=value, wrapped in `[...]`)
- `dumpsys phone` → works; uses `SubscriptionInfo {comma-separated}` format (legacy, not used on Android 13)
- `dumpsys euicc_card_controller` → exits 0 with "Can't find service" (no eUICC hardware active)
- `esim profiles list` → returns 1 physical SIM (T-Mobile, sub_id=1, slot=0, isEmbedded=0)

## Parser notes

`dumpsys isub` (Android 13) emits `SubscriptionInfoInternal:` records in three sections:
1. "Active subscriptions:" 
2. "All subscriptions:"
3. "SubscriptionDatabaseManager: All subscriptions:"

All three sections repeat the same records. `_parse_subscriptions_isub()` deduplicates by `sub_id`.

The `SubscriptionInfoInternal` format: `[SubscriptionInfoInternal: key=value key=value ...]`
- Fields are space-separated
- Boolean fields use `0`/`1` (not `true`/`false`)
- `isEmbedded=0` for physical SIM, `isEmbedded=1` for embedded eSIM
- `isRemovableEmbedded=1` for SIM-form-factor eUICC
