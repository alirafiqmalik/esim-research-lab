#!/usr/bin/env bash
# Keep the connected Android phone awake and unlocked while we work.
# Usage:
#   scripts/device/keep_phone_awake.sh        # keep awake (idempotent)
#   scripts/device/keep_phone_awake.sh off    # restore sane defaults
#
# We never touch the lock credential. We only keep the screen on so the
# keyguard does not re-engage after the user unlocks once.

set -u

SLEEP_TIMEOUT_MAX=2147483647
SLEEP_TIMEOUT_DEFAULT=30000

# Find the first device in "device" state. Empty if none connected.
serial="$(adb devices 2>/dev/null | awk '$2 == "device" { print $1; exit }')"

if [ -z "${serial}" ]; then
  echo "keep_phone_awake: no Android device connected (adb shows none in 'device' state)."
  echo "keep_phone_awake: nothing to do. Plug in the phone over USB and re-run."
  exit 0
fi

echo "keep_phone_awake: using device ${serial}"

mode="${1:-on}"

if [ "${mode}" = "off" ]; then
  adb -s "${serial}" shell svc power stayon false
  adb -s "${serial}" shell settings put system screen_off_timeout "${SLEEP_TIMEOUT_DEFAULT}"
  adb -s "${serial}" shell settings put secure sleep_timeout "${SLEEP_TIMEOUT_DEFAULT}"
  adb -s "${serial}" shell settings put global stay_on_while_plugged_in 0
  echo "keep_phone_awake: restored defaults (stayon false, screen_off_timeout ${SLEEP_TIMEOUT_DEFAULT} ms, sleep_timeout ${SLEEP_TIMEOUT_DEFAULT} ms, stay_on_while_plugged_in 0)."
  exit 0
fi

# Keep awake while USB-powered.
# Three independent timers can sleep the screen; we disable all three:
#   - system screen_off_timeout : the normal "Screen timeout" -> set to max
#   - secure sleep_timeout      : attentive/adaptive sleep -> -1 disables it
#                                 (this is the one that forces ~30s sleep even
#                                  when screen_off_timeout is high)
#   - global stay_on_while_plugged_in : bitmask 1=AC 2=USB 4=wireless -> 15 = all
adb -s "${serial}" shell svc power stayon true
adb -s "${serial}" shell settings put global stay_on_while_plugged_in 15
adb -s "${serial}" shell settings put system screen_off_timeout "${SLEEP_TIMEOUT_MAX}"
adb -s "${serial}" shell settings put secure sleep_timeout -1
adb -s "${serial}" shell input keyevent KEYCODE_WAKEUP

wakefulness="$(adb -s "${serial}" shell dumpsys power 2>/dev/null | grep -m1 'mWakefulness=' | tr -d '\r' | sed 's/^[[:space:]]*//')"
keyguard_line="$(adb -s "${serial}" shell dumpsys window 2>/dev/null | grep -m1 -E 'isKeyguardShowing|mDreamingLockscreen' | tr -d '\r' | sed 's/^[[:space:]]*//')"

echo "keep_phone_awake: power  -> ${wakefulness:-unknown}"
echo "keep_phone_awake: keyguard -> ${keyguard_line:-unknown}"

if printf '%s' "${keyguard_line}" | grep -qE 'isKeyguardShowing=true|mDreamingLockscreen=true'; then
  echo "keep_phone_awake: NOTE the lock screen is showing. Unlock the phone once by hand."
  echo "keep_phone_awake: we do not bypass the PIN. Once unlocked, stayon keeps it open."
fi

exit 0
