# BetterRoaming eSIM Activation

Goal: trigger a real production-CI RSP download (ES9+/ES8+) on the Pixel 7a using a
commercial activation code that chains to the production GSMA CI our eUICC trusts.

## TL;DR

A ready-to-use production activation string is available now. No signup, no payment,
no app needed for the download/handshake itself.

```
LPA:1$rsp.truphone.com$QRF-BETTERROAMING-PMRDGIR2EARDEIT5
```

Two more verified BetterRoaming codes on the same SM-DP+:

```
LPA:1$rsp.truphone.com$QR-G-5C-1LS-1W1Z9P7
LPA:1$rsp.truphone.com$QR-G-5C-KR-1PCDWP9
```

The osmocom eUICC manual lists these under "freely available eSIM profiles for
production networks" and states they "can be freely downloaded any number of times to
any number of eUICCs" using GSMA Live CI certificates. So they are not one-time-use and
not EID-locked. Source: https://euicc-manual.osmocom.org/docs/rsp/known-test-profile/

## SM-DP+ and CI identity

- SM-DP+ hostname: `rsp.truphone.com`
- Operator: Truphone, now rebranded **1GLOBAL** (acquired). BetterRoaming is operated by
  TP GLOBAL OPERATIONS LIMITED.
- The Android app package name is `com.truphone.betterroaming` — direct confirmation that
  BetterRoaming rides on Truphone/1GLOBAL RSP infrastructure.
- CI: production GSMA Live CI. This is what we need. The profile chains to the production
  certificate issuer, so our eUICC (which trusts `81370F5...795BEBFB` and rejects SGP.26
  test CI) should accept it and run a genuine ES9+/ES8+ handshake.

Sources:
- https://play.google.com/store/apps/details?id=com.truphone.betterroaming
- https://docs.connect.1global.com/docs/recipes/new-esim/

## Activation string format

Standard SGP.22 LPA Activation Code:

```
LPA:1$<smdp-address>$<matchingID>
```

- `<smdp-address>` = `rsp.truphone.com`
- `<matchingID>` = the per-profile token, e.g. `QRF-BETTERROAMING-PMRDGIR2EARDEIT5`
- No confirmation code is present in these strings (no trailing `$<code>`).
- A QR code for BetterRoaming simply encodes this exact `LPA:1$...` text. Scanning it and
  pasting the raw string are equivalent.

## How to get a code

You do not need to obtain a fresh code — the three above are documented, reusable
production codes. If you want a fresh one anyway:

- Free path: BetterRoaming offers a free "bootstrap" eSIM (free install, advertised free
  7-day trial). Scan the QR on https://www.betterroaming.com/ or install via the app.
  Installing the profile is free. Buying a *data plan* requires payment (card, Apple Pay,
  Google Pay, PayPal) or a voucher code redeemed after install via the welcome SMS link.
- The free profile install itself is the RSP event we care about. Provisioning paid data
  on top of it is a separate step and not needed to test the handshake.

Sources:
- https://www.betterroaming.com/support/how-do-i-get-a-betterroaming-esim-with-a-qr-code/
- https://www.betterroaming.com/esim-installation/

## Redeem / test on Android

Normal flow (any LPA, including OpenEUICC — the BetterRoaming app is NOT required):

1. Settings → Network & internet → SIMs → Download a SIM instead? / Add eSIM.
2. Choose "Enter it manually" (or "Need help?" → enter code) instead of scanning.
3. Paste the full `LPA:1$rsp.truphone.com$QRF-BETTERROAMING-PMRDGIR2EARDEIT5`.
4. The device resolves `rsp.truphone.com`, runs mutual auth, downloads and installs.

For this project: enter the same string into the OpenEUICC download wizard. Because the
profile uses the production CI, the eUICC will not throw the `8.8.4 / 3.7` rejection seen
with the sysmocom test SM-DP+.

## Gotchas

- These are provisioning/bootstrap profiles. They install and complete the RSP handshake,
  but without a purchased plan or voucher they carry no usable data allowance. Fine for
  testing the download/handshake; not for live traffic.
- Activating actual data needs the app or the welcome-SMS voucher flow, and may be region
  restricted (160+ countries, but plan availability varies).
- MCC/MNC: rides on Truphone/1GLOBAL multi-IMSI infrastructure; not a single fixed
  PLMN — varies by roaming network.
- Reusable per osmocom (not EID-locked, multi-download). If `rsp.truphone.com` later
  retires a specific `matchingID`, try the next code in the list.
- For MITM: the LPA pins/validates the SM-DP+ TLS chain and the GSMA cert chain inside
  ES9+. A transparent proxy on `rsp.truphone.com:443` will see TLS but the SGP.22
  application-layer ECDSA signatures still validate against the production CI keys, which
  you cannot forge. Plan the intercept accordingly.
