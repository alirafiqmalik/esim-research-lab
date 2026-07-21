# Repeatable eSIM Issuer for RSP Protocol Testing

**Goal:** Find a source of eSIM activation codes that supports an indefinite download → delete → re-download cycle on a production-CI eUICC (Pixel 7a, GSMA Live CI only).

---

## Top Recommendation

**Use the free reusable BetterRoaming / RedteaGO production-CI codes** — they already exist, they are publicly documented, and they support unlimited download/delete cycles at zero cost. Two additional BetterRoaming codes beyond the three we already hold are listed in the osmocom euicc-manual. No paid plan beats this for the RSP handshake use case.

If you need codes you *control* (to vary matching IDs, test edge cases, etc.), the **1GLOBAL Connect API** is the only commercially viable path to minting new codes on demand — but it is enterprise-only and pricing requires a sales call.

---

## Ranked Option Table

| Option | Per-cycle cost | Re-download after delete | EID-locked | Notes |
|---|---|---|---|---|
| BetterRoaming / Speedtest free codes (Truphone SM-DP+) | $0 | Yes — unlimited | No | 5 codes total; bootstrap profiles, no real data |
| RedteaGO free code | $0 | Yes — unlimited | No | 1 code; bootstrap/no-data |
| Ubigi paid plan | ~$6 one-time | Yes — up to 5 times | Same device | Up to 5 reinstall cycles per purchase |
| BNESIM | varies (~$5–15) | Yes — same device, unlimited re-installs via app | Same device | Only if deleted from phone settings, not from BNESIM app |
| Nomad (Blue plan) | varies | Up to 3 installs total | Same device | QR code is one-time; reinstall requires original QR saved |
| GigSky | varies | Up to 2 re-downloads via app | Same device | Soft limit of 2 |
| Airalo | varies (~$5+) | Maybe once via app recovery | EID-locked | Not designed for cycling |
| Holafly | varies | No — needs new QR | EID-locked | Must contact support for new code |
| Yesim | varies | No — one-time use | EID-locked | Once deleted, must contact support |
| Firsty | Free (ads) / €0.99 replacement | €0.99 per re-issue | One device | Ad-based free tier; locked to one device |
| 1GLOBAL Connect API | Enterprise pricing | Unlimited (new code per order) | No | B2B only; same rsp.truphone.com SM-DP+ |

---

## Free Reusable Production-CI Codes

All five codes below hit production GSMA CI servers and can be downloaded indefinitely to any compatible eUICC. They carry no real data plan — they are bootstrap/zero-data profiles used by the provider's LPA app. That is fine for RSP handshake testing.

```
# Already confirmed working
LPA:1$rsp.truphone.com$QRF-BETTERROAMING-PMRDGIR2EARDEIT5
LPA:1$rsp.truphone.com$QRF-SPEEDTEST
LPA:1$rsp-eu.redteamobile.com$5901981126831169

# Additional BetterRoaming codes (production CI, reusable — from osmocom euicc-manual)
LPA:1$rsp.truphone.com$QR-G-5C-1LS-1W1Z9P7
LPA:1$rsp.truphone.com$QR-G-5C-KR-1PCDWP9
```

SM-DP+ hosts:
- `rsp.truphone.com` — operated by 1GLOBAL (formerly Truphone); GSMA Live CI
- `rsp-eu.redteamobile.com` — operated by RedteaMobile; GSMA Live CI

These are the only publicly documented, freely available, production-CI reusable codes known as of mid-2026.

---

## Developer / API Paths

### 1GLOBAL Connect API
- URL: `docs.connect.1global.com`
- SM-DP+ used: `rsp.truphone.com` (same server as the free BetterRoaming codes)
- Capability: place an order via REST API → receive a new ICCID, matching ID, and LPA URL → install on device → repeat
- Each new order mints a fresh activation code. No EID-lock between orders.
- Access: enterprise/B2B only. Requires a sales engagement. No self-serve developer tier. Pricing is not published.
- Verdict: the right path if you need code control at scale, but not accessible to an individual researcher without a business relationship.

### Transatel Developer API
- URL: `developers.transatel.com`
- Capability: "release" an eSIM profile from inventory stock → receive activation code + QR code
- Transatel is an NTT subsidiary; serves MNOs, MVNOs, and OEMs.
- Access: B2B only. No self-serve tier. Pricing requires contact.
- Verdict: same capability as 1GLOBAL but a different operator; not reachable without a business account.

### RedteaMobile Partner API
- PDF: `static.redteago.com/nobel_front_src/RedteaGO_API_Guide.pdf`
- Capability: white-label eSIM store + API for resellers; can generate activation codes
- Access: B2B reseller program. Not open to individuals.
- Verdict: not accessible for a one-person RSP research setup.

### Kigen (ARM) RSP Sandbox
- Offers SAS-SM certified SM-DP+ hosted on AWS
- Open API v3 specs published
- Access: enterprise customers and OEM partners only
- Pricing: contact ARM/Kigen
- Verdict: too heavyweight and expensive for this use case.

### No Open Developer Tier Exists
No SM-DP+ vendor — Thales, IDEMIA, G+D, Kigen, 1GLOBAL, RedteaMobile, Transatel — offers a self-serve developer sandbox on production CI. The sysmocom SGP.26 test SM-DP+ (`smdpp.test.rsp.sysmocom.de`) is free and publicly accessible but uses test CI, which the Pixel 7a's production eUICC rejects.

---

## eSIM.me Reprogrammable Card

The eSIM.me Card (V2) stores up to 15 eSIM profiles. You can delete a profile and load a new one into the freed slot. Reprogramming cycles have no documented limit.

**Not relevant for this project.** We test the Pixel 7a's internal (soldered) eUICC, not a removable physical card. The eSIM.me card has its own separate EID. Installing and deleting profiles on it exercises that card's eUICC, not the phone's. Additionally, Android 11+ has a bug where disabling the eSIM.me card slot permanently marks it as disabled in the OS (only fixable with root).

---

## Per-Provider Details

### Ubigi
- Owner: Transatel (NTT)
- SM-DP+: not publicly disclosed; likely Transatel's own server
- Re-download policy: **up to 5 reinstalls** after device-side deletion, via Ubigi app → Settings → "Re-install my Ubigi eSIM"
- EID behaviour: reinstall appears to target the same device (EID match likely enforced)
- Cost: cheapest plan is $6/month (5 GB, USA); some 3 GB plans from $7
- Verdict for RSP testing: 5 cycles per $6 purchase. Functional but not infinite. Useful if you need a specific network profile and can tolerate the 5-cycle cap.

### BNESIM
- Re-download policy: if you delete the profile from **phone settings** (not from the BNESIM app), you can reinstall via the BNESIM app, same device, at no extra cost. The number of reinstalls is not capped in their documentation.
- If you delete from the BNESIM app itself, the profile is permanently erased — no recovery.
- QR codes are one-time use; reinstall is handled app-side.
- EID: same-device only
- Verdict: potentially unlimited cycles on one device — but the distinction between "phone settings delete" vs "app delete" is fragile for automated testing. The reinstall goes through BNESIM's proprietary app flow, not a raw LPA string, so it may not exercise the standard SGP.22 download handshake cleanly.

### Nomad
- Re-download policy: original QR code can be used to reinstall on the **same device** after deletion. QR codes are single-use per-device — a second device cannot use the same QR.
- Blue plan: up to 3 total installs
- Amber plan: transfer across devices allowed
- Thailand unlimited plans: no reinstall after delete
- Verdict: limited cycles (≤ 3), single-device. Not suitable for repeated cycling.

### Airalo
- Re-download policy: mostly one-time use. App may offer a single "recovery" attempt. No systematic re-download.
- EID-locked to first device.
- Verdict: not suitable.

---

## Sources

- [Known Test Profiles — osmocom euicc-manual](https://euicc-manual.osmocom.org/docs/rsp/known-test-profile/)
- [SM-DP+ — osmocom euicc-manual](https://euicc-manual.osmocom.org/docs/rsp/sm-dp-plus/)
- [1GLOBAL Connect API — eSIM Lifecycle](https://docs.connect.1global.com/docs/recipes/esim-lifecycle/)
- [1GLOBAL Connect API — Getting a New eSIM](https://docs.connect.1global.com/docs/recipes/new-esim/)
- [Transatel Developer Portal — SIM Management Overview](https://developers.transatel.com/docs/sim-management-overview/)
- [Ubigi — What happens if I erase my eSIM](https://cellulardata.ubigi.com/help-center/faq/esim-data-plan/deletion-of-esim-profile/)
- [Ubigi — Reinstall on Android after deletion](https://cellulardata.ubigi.com/help-center/faq/ubigi-esim-service/ubigi-esim-profile-retrieval-after-deletion-on-android-device/)
- [Ubigi — USA 5GB plan ($6/month)](https://cellulardata.ubigi.com/rates-and-coverage/usa-data-plans/usa-5gb/)
- [BNESIM — Can I delete/reinstall an eSIM](https://www.bnesim.com/help/can-i-delete-reinstall-an-esim/)
- [Nomad — Can I delete and re-install my Nomad eSIM](https://www.nomadesim.com/help-center/en/articles/9886371-can-i-delete-and-re-install-my-nomad-esim)
- [Nomad — Can my eSIM QR code be reused](https://www.nomadesim.com/blog/can-esim-qr-code-be-reused)
- [Airalo — Can I reinstall an eSIM](https://www.airalo.com/help/using-managing-esims/ZSEEHBT5HW6F/can-i-reinstall-an-esim/54MPGHA4TCY1)
- [Firsty — How to restore a deleted eSIM](https://www.firsty.app/help/account/help-with-deleted-esim)
- [Yesim — Reusing eSIM possibilities and limitations](https://help.yesim.tech/can-an-esim-be-re-used/)
- [eSIM.me FAQ](https://esim.me/FAQ)
- [BetterRoaming — How to get an eSIM with a QR code](https://www.betterroaming.com/support/how-do-i-get-a-betterroaming-esim-with-a-qr-code/)
- [sysmocom SGP.26 test SM-DP+](https://test.rsp.sysmocom.de/)
- [RedteaGO API Guide (PDF)](https://static.redteago.com/nobel_front_src/RedteaGO_API_Guide.pdf)
- [eSIM Access API — docs](https://docs.esimaccess.com/)
