---
name: run-capture
description: Start a mitmproxy + logcat capture session with correct pre-checks and flags
---

# Run Capture

## Pre-checks

1. Hotspot is active: `nmcli connection show esim-hotspot | grep "GENERAL.STATE"`
2. Phone is connected to hotspot (check phone Wi-Fi settings).
3. Phone proxy is set to `<PC_IP>:8080`.
4. mitmproxy CA cert is installed on the phone.
5. ADB device is connected: `adb devices`.

## Start capture

```bash
esim capture start --port 8080
```

Trigger eSIM activity on the phone. Press Ctrl-C to stop.

## After capture

```bash
esim session analyze sessions/<timestamp>/
```

Check `.claude/notes/tls-pinning-status.md` and update based on whether flows appeared.
