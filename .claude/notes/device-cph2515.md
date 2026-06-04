---
name: device-cph2515
description: OnePlus Nord N30 5G (CPH2515) T-Mobile — verified ADB commands, OxygenOS output format quirks, dumpsys parsing notes
---

# Device: OnePlus Nord N30 5G (CPH2515)

- ADB serial: 3ddf2893
- OEM: OnePlus, OxygenOS (Android 13)
- Carrier: T-Mobile US
- TLS pinning: untested — see tls-pinning-status.md after first capture

## Verified ADB commands

Populate this section as commands are tested against the real device.
Format: command → output note or parsing adjustment needed.

## Parser notes

If `_parse_subscriptions()` in `esim/device.py` returns empty on the real device,
run `adb shell dumpsys phone | grep -i subscriptioninfo` and compare the output
format to the regex in `_SUB_PATTERN`. Adjust the regex and update this note.
