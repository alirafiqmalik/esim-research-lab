---
name: tls-pinning-status
description: Whether mitmproxy successfully intercepts LPA HTTPS traffic on this device — updated after each capture attempt
---

# TLS Pinning Status

**Device:** OnePlus Nord N30 5G (CPH2515)
**Last tested:** not yet

## Status

Untested.

Run `esim capture start` with mitmproxy active and trigger eSIM activity on the phone.
If no HTTPS flows appear in `traffic.mitm` within 30s of triggering eSIM activity,
`Capture` will emit `PinningDetected`.

Update this file after each test with: date, what was triggered, result (flows captured / pinning detected).
