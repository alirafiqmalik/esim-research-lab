# AOSP / Google eSIM Test Infrastructure

Research on the Google-hosted eSIM test SM-DP+, AOSP downloadable test profiles, on-device
EuiccService testing, and whether any of it produces a successful RSP download on our
production Pixel 7a eUICC.

## Bottom line

No AOSP/Google path yields a successful RSP download on our production Pixel eUICC.

Google's test SM-DP+ (`prod.smdp-plus.rsp.goog`) serves the TS.48 generic test profiles, but
its server certificate chain is signed by a **GSMA test CI**. Our eUICC trusts only the
production GSMA CI (`81370F5125D0B1D408D4C3B232E6D25E795BEBFB`). The download fails during
mutual authentication for the same reason a test-CI SM-DP+ fails today: the eUICC cannot
verify the SM-DP+ certificate chain. This is the same SGP.22 refusal class we already
observed (`8.8.4` / `3.7` family, "certificate/CI not trusted").

The closest runnable test on our device is simply attempting one of the activation codes
below. Expected outcome: authentication-stage failure, not an install.

## Q1 — Does Google operate a public eSIM test SM-DP+?

Yes.

- Hostname: `prod.smdp-plus.rsp.goog`
- Publicly reachable, no special credentials.
- No download counters and no profile policy rules — "no limits" on downloads or eligible
  devices, per the AOSP docs.
- CI class: **test-CI**. The docs state plainly: "The device downloading the test profiles
  must have a test certificate issued by a GSMA CI." The SM-DP+ end of the RSP handshake is
  correspondingly signed by the GSMA test CI (SGP.26 v1.4 Annex D test certificates).

Because it is test-CI, it will NOT install on our production Pixel eUICC. It needs a separate
test eUICC whose root of trust includes the GSMA test CI.

## Q2 — AOSP "downloadable test profiles" mechanism

Source: https://source.android.com/docs/core/connect/esim-test-profiles

Mechanism:

- Google runs an SM-DP+ at `prod.smdp-plus.rsp.goog` that hosts the GSMA TS.48 generic eUICC
  test profiles ("Generic eUICC Test Profile for Device Testing").
- The device fetches a profile the normal RSP way: scan the QR / enter the activation code,
  the LPA runs ES9+/ES10b against the server, the profile downloads and installs.
- Four profiles, with activation codes (format `1$<host>$<matchingID>`, prefix `LPA:` optional):

  | Profile | Activation code |
  |---|---|
  | SAIP2.1_BERTLV_v2 | `LPA:1$prod.smdp-plus.rsp.goog$052X-UFXS-CQIY-PNGL` |
  | SAIP2.1_NoBERTLV  | `LPA:1$prod.smdp-plus.rsp.goog$3TD6-8L82-HUE1-LVN6` |
  | SAIP2.3_BERTLV    | `LPA:1$prod.smdp-plus.rsp.goog$15YQ-Q0XO-9BN6-KSX2` |
  | SAIP2.3_NoBERTLV  | `LPA:1$prod.smdp-plus.rsp.goog$9RS2-4AT0-MPKU-HKUO` |

- Installs on a normal production eUICC? **No.** Requires a test-CI eUICC. The "no limits"
  language refers to the absence of download/policy rules, not to CI trust — CI trust is the
  hard gate and it is test-CI.
- Build requirements: none stated for the LPA/Android side. The gate is the eUICC's trusted
  CI set, which is fixed in the chip's eUICC OS, not in the Android build. A userdebug/eng
  Android image does not change which CI the eUICC trusts.

Reference standards: GSMA TS.48 (generic test profile content), SGP.26 v1.4 Annex D (test
certificate definitions).

## Q3 — Loopback / EuiccService test mode

There is no AOSP "loopback SM-DP+" that runs on-device and bypasses the network or the CI.

What AOSP actually provides for on-device testing is **CTS test coverage of the eUICC API
surface**:

- Path: `platform/cts/tests/tests/telephony/current/src/android/telephony/euicc/cts`.
- These verify the EuiccManager / EuiccService API contract (the framework can discover and
  bind the LPA, intents resolve, etc.). They do not perform a real RSP download against a
  live SM-DP+ and do not mint a profile.
- They validate plumbing, not provisioning, so passing them tells you nothing about whether a
  real profile install would succeed.

The "loopback testing" wording in the AOSP eSIM pages refers to using the TS.48 generic test
profile + test SM-DP+ as the closed test loop for radio/conformance testing (system
simulator world), not a device-only software loopback. It still requires a test-CI eUICC.

Can it run on our rooted production Pixel? The CTS API tests can run on any build. The real
download loop cannot succeed, because the test profiles need a test-CI eUICC. No userdebug
build, CTS harness, or developer flag changes the eUICC's trusted-CI set.

## Q4 — Rooted-device-specific leverage

Root and adb let us *trigger* the Euicc APIs but do not relax CI trust:

- `adb shell cmd phone` and the `EuiccManager`/`downloadSubscription` path can kick off a
  download with any activation code, including the goog test codes. The handshake still
  reaches the eUICC, which still rejects a test-CI server certificate.
- Carrier config (`CarrierConfigManager`) and test-mode props affect carrier-app behavior,
  UI, and policy enforcement on the Android side — not the eUICC's certificate verification.
- The trusted CI list lives inside the eUICC OS (the secure element), not in Android. Root on
  the application processor does not reach it. There is no documented prop, carrier-config
  key, or `cmd` that adds a CI or disables CI verification on a production eUICC.

So root is useful for driving and instrumenting the attempt (logcat, repeatable triggers via
adb), but it cannot make the goog test profile install.

What root *does* let us do usefully: run our privileged OpenEUICC LPA, issue the goog
activation code programmatically, and capture the exact ES9+/ES10b failure for the writeup —
confirming the CI-trust boundary end to end.

## Q5 — Exact runnable test and expected outcome

There is no success path on the production Pixel eUICC. The closest runnable test:

1. In our OpenEUICC LPA (or via the Euicc API), enter:
   `LPA:1$prod.smdp-plus.rsp.goog$3TD6-8L82-HUE1-LVN6`
2. The LPA resolves `prod.smdp-plus.rsp.goog`, runs ES9+ `InitiateAuthentication` /
   `AuthenticateClient` and ES10b on the eUICC.
3. Expected outcome: failure at the authentication stage. The eUICC cannot validate the
   server's test-CI certificate chain against its production-only trust anchor. This is the
   same refusal family as our existing test-CI SM-DP+ result, not a successful install.

To actually exercise a successful Google/AOSP test download you need a **test-CI eUICC**
(e.g. a sysmoEUICC or vendor test eUICC provisioned with the GSMA test CI root). On such an
eUICC the codes above install with no download/policy limits — that is the intended, working
configuration.

CI class summary:

- Google test SM-DP+ `prod.smdp-plus.rsp.goog`: **test-CI** → separate test eUICC required.
- Production-CI SM-DP+ (e.g. Truphone): installs on our Pixel — but that is a real carrier
  profile, not a Google/AOSP test profile.

Build/flag requirements: none on the Android side change the result. The decisive factor is
the eUICC's trusted CI set, which is fixed in hardware/eUICC-OS.

## Sources

- Implement eSIM (overview): https://source.android.com/docs/core/connect/esim-overview
- Downloadable test profiles: https://source.android.com/docs/core/connect/esim-test-profiles
- eUICC APIs: https://source.android.com/docs/core/connect/esim-euicc-api
- Handle eUICC API errors: https://source.android.com/docs/core/connect/esim-error-handling
- GSMA TS.48 Generic eUICC Test Profile: https://www.gsma.com/get-involved/working-groups/gsma_resources/ts-48-generic-euicc-test-profile-for-device-testing/
- GSMA TS.48 public repo: https://github.com/GSMATerminals/Generic-eUICC-Test-Profile-for-Device-Testing-Public
- AOSP CTS telephony euicc tests: platform/cts/tests/tests/telephony/current/src/android/telephony/euicc/cts
