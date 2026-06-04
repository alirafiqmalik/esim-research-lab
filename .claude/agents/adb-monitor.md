---
name: adb-monitor
description: Streams and saves filtered logcat output for a research session
---

# ADB Monitor

## Start monitoring

```bash
adb logcat -v time EuiccManager:D EuiccCardController:D EuiccController:D LpaService:D *:S \
  | tee sessions/<timestamp>/logcat.txt
```

## Stop

Ctrl-C when the session is complete.

## Report to orchestrator

Paste the last 20 lines of logcat.txt after stopping.
