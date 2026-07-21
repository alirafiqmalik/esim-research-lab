# Using the TS.48 v7.1 Generic Test Profile with our eUICC

Short version: **our production eUICC will not take this test profile**, and we
proved it two ways. This doc says what the profile is, why it is rejected, what we
tried, and the one path that *would* work.

## What the profile actually is

- **TS.48 GTP = a SAIP v2.3 *Unprotected* Profile Package (UPP).** It is raw profile
  content, not an installable download.
- It ships in **4 variants**, all the same identity: `BERTLV_SUCI`,
  `BERTLV_SUCI_NoRAMRFM`, `NoBERTLV`, `NoBERTLV_NoRAMRFM`.
- The variants differ on **two axes only**: BER-TLV file encoding on/off, and
  **RAM/RFM** (remote-management applets) present/absent.

Identity + secrets (all **well-known, published** test values):

- **ICCID** `89000123456789012341`, **IMSI** `001010123456789` (test PLMN 001/01).
- **AKA**: `usim-test-algorithm`, **Ki** `000102…0E0F`, OPc all-zero.
- **ISD/OTA SCP keys** (KIC/KID/KIK) `000102…0E0F`; **PUKs** `11111111` / `22222222`.
- Apps: **USIM + ISIM + CSIM** — a full multi-app test SIM.

## Why our eUICC rejects it (two independent walls)

An **UPP is not a Bound Profile Package (BPP).** To install any profile, SGP.22
requires an **SM-DP+** to personalise the UPP, encrypt/MAC it into a BPP (ES8+), and
bind it to the eUICC over a session the eUICC's ISD-R authenticates.

- **Wall 1 — CI trust (the RSP path).** TS.48 says the GTP is *"pre-loaded on a
  Certified eUICC during manufacturing, or downloaded from a certified SM-DP+"*,
  onto an eUICC *"configured following the eUICC test specification"* (**SGP.26**).
  A test SM-DP+ uses the **test CI**; our eUICC trusts only the **production CI**
  (`81370F…`), so `AuthenticateServer` fails with SGP.22 **`8.8.4` / `3.7`** before a
  single profile byte is sent.
- **Wall 2 — no unprotected install (the direct path).** There is no way to push
  raw profile content into a consumer eUICC without that ES8+ session.

## What we tried (and saw)

- **Direct-load attempt** (`try_direct_load.py`): wrapped the UPP's first bytes in an
  ES10b `LoadBoundProfilePackage` and sent it to the ISD-R with **no session**.
  → **SW `6985` "Conditions of use not satisfied."** eUICC **unchanged** (still 2
  profiles), nothing installed. This is Wall 2, made concrete.
- **RSP attempt**: pointing `esim euicc download`/`authenticate` at any test SM-DP+ that
  hosts the GTP hits Wall 1 — the same **`8.8.4/3.7`** rejection this testbed has
  already reproduced against test-CI servers. The profile content never matters,
  because the handshake dies first.

## Update — Google's production SM-DP+ path (tried live, 2026-07-19)

Google hosts the TS.48 profiles OTA on a **production** SM-DP+
(`prod.smdp-plus.rsp.goog`, per the AOSP eSIM-test-profiles page), with real
activation codes e.g. `1$prod.smdp-plus.rsp.goog$3TD6-8L82-HUE1-LVN6`
(SAIP2.1_NoBERTLV). We tried it on our production eUICC and got **further than any
test-CI path, but it still fails** — the wall just moves to the other end:

1. **TLS wall first.** lpac doesn't bundle Google's SM-DP+ TLS CA →
   `SSLHandshakeException: Trust anchor … not found`. Bypassable with OpenEUICC's
   **`ignore_tls_certificate`** datastore pref (dev option). Reverted afterward.
2. **After the bypass we reach the real RSP layer** (HTTP 200). The server then
   **refuses our eUICC at `initiateAuthentication`** with SGP.22
   **`8.8.2 / 3.1` "Execution Failed"** — *before* the matchingId/profile is ever
   evaluated (so all four codes fail identically).
3. **Why:** at that step the server sees `euiccInfo1`, whose CI-PKID list contains
   **only the production CI** (`81370F…`), no test CI. Google's TS.48 SM-DP+ only
   serves eUICCs that trust the **GSMA test CI (SGP.26)** — the precondition the AOSP
   docs state ("a device with a test certificate issued by a GSMA CI").

**Net:** the CI-trust wall is **bidirectional**. A test-CI SM-DP+ is rejected by our
eUICC (`8.8.4/3.7`, eUICC-side); a production-CI SM-DP+ that requires a test eUICC
rejects us (`8.8.2/3.1`, server-side). A retail production eUICC gets the GTP by
**neither** path. The AOSP claim that these "work on a Pixel 7a" holds only for
**test/engineering eUICCs**, not the retail production eUICC in this device.

## The one path that would actually work

You need an eUICC that **trusts the test CI** — i.e. a **test eUICC** (SGP.26
configured), which we cannot make from a production Pixel eUICC. Given one:

1. Run a **test SM-DP+** that serves the GTP — the reference tool is Osmocom
   **`osmo-smdpp`** (pysim), which ships the SGP.26 test certs and serves a SAIP UPP.
2. Feed it one of these UPP `.rename2der` files.
3. Point `esim euicc download 'LPA:1$<smdpp-host>$<matchingId>'` at it over an
   `adb reverse` tunnel; `AuthenticateServer` now passes, the BPP installs.

Alternatively, obtain a GTP **pre-loaded test eUICC** (chip vendor) and skip RSP.

**Do not modify our eUICC or testbed to chase this** — the wall is in the secure
element and is the correct security behaviour. The GTP is only useful here as a
*reference* (its files, keys, and structure), not as an installable profile.

## Files in `src/`

- `analyze_gtp.py` — parses all 4 UPP variants, prints identity/keys/PE structure.
- `try_direct_load.py` — the safe, testbed-only injection attempt above (SW `6985`).
