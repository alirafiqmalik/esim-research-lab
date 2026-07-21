# GSMA TS.48 Generic eUICC Test Profile

## Bottom line first

We cannot download a TS.48 profile onto our production Pixel 7a eUICC. Every
public server that serves a real TS.48 profile chains to a **GSMA test CI
(SGP.26)**, not a production CI. Our eUICC trusts only the production CI key
`81370F5125D0B1D408D4C3B232E6D25E795BEBFB`. A TS.48 download will fail the same
way sysmocom already failed: SGP.22 `subjectCode 8.8.4 / reasonCode 3.7` at the
first RSP message.

The user hint (`://gsma.com`, `1$://gsma.com$TEST-PROFILE-1`) is wrong.
`gsma.com` is not an SM-DP+ host. No such activation code exists.

## What TS.48 actually is

TS.48 is **profile content plus a spec**, not a server.

- It defines a generic, non-MNO test profile for device certification (GCF,
  PTCRB) and 3GPP RF/protocol testing.
- It fixes a static, non-unique ICCID and known K/OPc test key material.
- The GSMA publishes the *structure*, not a hosted download. The repo
  `GSMATerminals/Generic-eUICC-Test-Profile-for-Device-Testing-Public` holds the
  spec `.docx`, the `eSIM_GTP_Profile_Structure.xlsx`, ASN.1 references, and the
  SAIP package. No `.der`, no ICCID values, no server, nothing runnable.
- To get an installable TS.48 profile you need an SM-DP+ that has it loaded and
  will sign the download.

So TS.48 is the *what*. The SM-DP+ + its CI is the *who can install it*.

## Who serves a real TS.48 profile (and which CI)

| Server | Host | CI | Installs on our Pixel? |
|--------|------|-----|------------------------|
| sysmocom | `smdpp.test.rsp.sysmocom.de` | GSMA SGP.26 **test** CI | No — needs SGP.26 test eUICC |
| Infineon | `testsmdpplus.infineon.com` | GSMA SGP.26 **test** CI | No — needs SGP.26 test eUICC |
| Android/Google | `prod.smdp-plus.rsp.goog` | GSMA **test** CI (non-standard key) | No — needs test certificate eUICC |

All three explicitly require a test-CI eUICC. sysmocom states it plainly: "You
can only download the eSIM profiles using an eUICC that itself contains a SGP.26
test key/certificate." Android says the device "must have a test certificate
issued by a GSMA CI."

There is **no GSMA-operated or production-CI SM-DP+ that serves TS.48**. The
GSMA does not run a public download server at all.

## Production-CI servers exist — but they do NOT serve TS.48

The osmocom "Known Test Profiles" page lists profiles that chain to **GSMA live
CIs** and so install on any production eUICC (including ours). These are
free *test-network* profiles, not TS.48 generic test profiles:

| Service | Activation code | Host | CI |
|---------|-----------------|------|-----|
| BetterRoaming | `LPA:1$rsp.truphone.com$QRF-BETTERROAMING-PMRDGIR2EARDEIT5` | rsp.truphone.com | production |
| Speedtest | `LPA:1$rsp.truphone.com$QRF-SPEEDTEST` | rsp.truphone.com | production |
| RedteaGO | `LPA:1$rsp-eu.redteamobile.com$5901981126831169` | rsp-eu.redteamobile.com | production |

These match our earlier finding: a Truphone (production-CI) SM-DP+ completed the
full handshake and installed. But these are commercial test-network profiles,
not the TS.48 GTP profile. If the goal is "a profile that installs on the
Pixel," use these. If the goal is "the TS.48 generic profile specifically," it
cannot be done on a production eUICC.

## Concrete activation strings

### TS.48 — TEST CI only (will hit 8.8.4 / 3.7 on our Pixel)

sysmocom hosts 50+ TS.48 variants. Activation code form:
`LPA:1$smdpp.test.rsp.sysmocom.de$<matchingID>`

- `LPA:1$smdpp.test.rsp.sysmocom.de$TS48v1_A`
- `LPA:1$smdpp.test.rsp.sysmocom.de$TS48v1_B`
- `LPA:1$smdpp.test.rsp.sysmocom.de$TS48v2_SAIP2.1_BERTLV`
- `LPA:1$smdpp.test.rsp.sysmocom.de$TS48v7.0_SAIP2.3_BERTLV_SUCI`

The full, current list with QR codes is on `https://test.rsp.sysmocom.de/`.
Tag: **test CI**. Requires an SGP.26 test eUICC (e.g. sysmoEUICC1-C2T).

Android/Google TS.48, also **test CI**:
`1$prod.smdp-plus.rsp.goog$052X-UFXS-CQIY-PNGL` (example matching ID).

### Production CI — installs on our Pixel (NOT TS.48)

- `LPA:1$rsp.truphone.com$QRF-SPEEDTEST`
- `LPA:1$rsp.truphone.com$QRF-BETTERROAMING-PMRDGIR2EARDEIT5`
- `LPA:1$rsp-eu.redteamobile.com$5901981126831169`

Tag: **production CI**. These succeed on a normal production eUICC.

## Android redemption (manual entry, OpenEUICC)

1. Open the LPA. Choose add/download profile, then manual entry (not scan).
2. SM-DP+ address field: the host only, e.g. `smdpp.test.rsp.sysmocom.de` or
   `rsp.truphone.com`. No `LPA:`, no `1$`, no `://`.
3. Activation/Matching code field: the matching ID only, e.g. `TS48v1_A` or
   `QRF-SPEEDTEST`.
4. Leave confirmation code empty (none of these use one).
5. Start the download.

Equivalent single-string form for a QR: `LPA:1$<host>$<matchingID>`.

## What we CAN run on the production Pixel

- **A real successful download:** use the production-CI Truphone/RedteaGO codes
  above. These install. (Not TS.48, but a genuine end-to-end RSP success against
  a production CI — same path that already worked for us.)
- **A reproducible CI-mismatch failure with a TS.48 profile:** point the LPA at
  `smdpp.test.rsp.sysmocom.de` with `TS48v1_A`. It reaches the SM-DP+, then the
  eUICC rejects the test-CI certificate at the first RSP message with
  `8.8.4 / 3.7`. Useful as a controlled negative case for the MITM work.

To download an actual TS.48 profile, we would need a separate **SGP.26 test
eUICC** (sysmoEUICC1-C2T or equivalent). Our internal Pixel eUICC cannot do it.

## Sources

- [GSMA TS.48 working group page](https://www.gsma.com/get-involved/working-groups/gsma_resources/ts-48-generic-euicc-test-profile-for-device-testing/)
- [GSMA TS.48 v1.0 PDF](https://www.gsma.com/newsroom/wp-content/uploads/TS.48-v1.0.pdf)
- [GSMATerminals Generic-eUICC-Test-Profile-for-Device-Testing-Public](https://github.com/GSMATerminals/Generic-eUICC-Test-Profile-for-Device-Testing-Public)
- [osmocom Known Test Profiles](https://euicc-manual.osmocom.org/docs/rsp/known-test-profile/)
- [sysmocom SGP.26 test SM-DP+](https://test.rsp.sysmocom.de/)
- [Android Downloadable test profiles](https://source.android.com/docs/core/connect/esim-test-profiles)
- [osmo-smdpp docs](https://downloads.osmocom.org/docs/pysim/master/html/osmo-smdpp.html)
