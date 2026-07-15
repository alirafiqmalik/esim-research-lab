---
name: tls-pinning-status
description: Whether mitmproxy successfully intercepts LPA HTTPS traffic per device/endpoint — updated after each capture attempt
---

# TLS Pinning Status

## Pixel 7a (rooted) — tested 2026-06-27

| Endpoint | Through proxy? | Decrypts with system CA? | Notes |
|----------|----------------|--------------------------|-------|
| `www.gstatic.com` (carrier logos) | yes | **yes** | LPA UI asset fetch — proves system cert works |
| `lpa.ds.gsma.com` (root SM-DS, ES9+/ES11) | yes | **no** | Pins to GSMA CI roots (SGP.22). `CertPathValidatorException: Trust anchor not found` |
| `*.googleapis.com`, `accounts.google.com` | yes | **no** | Google first-party cert pinning |

Triggered SM-DS discovery via `am start -a
android.telephony.euicc.action.PROVISION_EMBEDDED_SUBSCRIPTION`. The LPA hit the
root SM-DS at `lpa.ds.gsma.com /gsma/rsp2/es9plus/initiateAuthentication` through
the proxy, then rejected mitmproxy's cert.

### Why RSP can't be MITM'd with a CA cert

GSMA SGP.22 authenticates the SM-DP+/SM-DS server certificate against the **GSMA
CI (Certificate Issuer) root certificates** that the LPA carries itself. It does
not consult the Android system trust store for RSP TLS. Adding a CA to the system
store — even with root — does not help. Protocol property, not a device limit.

### Paths to RSP plaintext (rooted device)

1. **Frida unpinning** (recommended) — hook `com.google.android.euicc`'s
   TrustManager (RSP uses `com.android.okhttp`) to skip CI validation, then
   mitmproxy (`--ssl-insecure` upstream) decrypts. Needs frida-server pushed;
   SELinux Enforcing so attach via root/ptrace.
2. **GSMA test CI** — SM-DP+/SM-DS test infra with certs chaining to GSMA TEST CI
   roots + an eUICC carrying matching test CI. Not possible on a retail eUICC.

ES8+ BPP plaintext stays out of reach regardless — those keys live in the eUICC
secure element. Frida buys ES9+/ES11 transport visibility only.

## OnePlus Nord N30 5G (CPH2515)

No embedded eUICC hardware — not applicable.

## Samsung Galaxy S24+ (SM-S926U1)

Untested. Samsung uses a proprietary LPA; expect the same GSMA CI pinning for RSP.
