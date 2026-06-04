---
name: adb-probe
description: Verify ADB connectivity and collect device baseline state (EID, subscriptions, eUICC dump) before starting a research session
---

# ADB Probe

Use at the start of any session to verify the device is connected and collect baseline state.

## Steps

1. Verify device connected:
   ```bash
   adb devices
   ```
   Expected: one device listed, not "unauthorized" or "offline".

2. Get EID:
   ```bash
   esim eid
   ```

3. List subscriptions — note the sub_id for the eSIM profile:
   ```bash
   esim profiles list
   ```

4. Dump eUICC state:
   ```bash
   adb shell dumpsys euicc_card_controller > sessions/euicc_state_$(date +%Y%m%d).txt
   ```

5. Update `.claude/notes/device-cph2515.md` with any new command output or parser findings.
