# Keep phone awake

Keeps the connected Pixel 7a awake so the keyguard does not re-engage during a
research session. It never touches the PIN. Unlock the phone once by hand.

## Keep awake

```bash
tools/keep_phone_awake.sh
```

Sets `svc power stayon true`, raises `screen_off_timeout` to its max, and sends
`KEYCODE_WAKEUP`. It prints the current power and keyguard state. If the lock
screen still shows, unlock the phone once. With no device connected it prints a
note and exits 0.

## Stop (restore defaults)

```bash
tools/keep_phone_awake.sh off
```

Sets `svc power stayon false` and `screen_off_timeout` back to 30000 ms.

## Usage

Run this script manually before a capture or testbed session, or wire it into
your own startup hook, to keep the device awake and the keyguard clear.
