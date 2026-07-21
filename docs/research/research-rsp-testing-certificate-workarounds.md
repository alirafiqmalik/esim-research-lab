# eSIM RSP Testing: The CI-Trust Problem and Workarounds

## Executive summary

Your conclusion is correct. The LPA TLS bypass does not touch the RSP CI-trust check. A production eUICC trusts only production GSMA CI keys. A test SM-DP+ holds only SGP.26 test-CI certs. The mismatch is detected and cryptographically enforced.

The check runs on two sides:

- Server side: the SM-DP+ at `initiateAuthentication` reads `euiccCiPKIdListForVerification` from the eUICC's `EUICCInfo1`. If it holds no `CERT.DPauth.SIG` chaining to a CI the eUICC trusts, it aborts. This is the `8.8.4 / 3.7` error you hit.
- eUICC side: ES10b `AuthenticateServer` validates the SM-DP+ certificate chain against the CI public keys stored in the secure element. This is the hard anchor. It cannot be bypassed with root or a patched LPA.

You cannot add a test CI key to the Pixel's production eUICC. CI root public keys are provisioned by the eUICC manufacturer (EUM) before issuance and protected inside the secure element. No end-user, root, or LPA mechanism adds one.

Recommended path: buy a removable SGP.26 test eUICC (sysmoEUICC1-C2T, EUR 95.20). Run it two ways. On the rooted Pixel use OpenEUICC/EasyEUICC. On the laptop use lpac with a PCSC USB reader. Point either at the sysmocom test SM-DP+ or your own osmo-smdpp. This gives a full, successful, end-to-end RSP install you control. A fully software eUICC that trusts SGP.26 keys does not exist as a usable project today.

## Q1: Where CI trust is enforced

The RSP trust anchor is the eSIM CA (the CI). Its public key is stored on the eUICC before issuance. Every SM-DP+, SM-DS, and EUM certificate must chain to a CI root the eUICC trusts.

Mutual authentication (SGP.22 ES9+/ES10b, the "Common Mutual Authentication" procedure) enforces this at two points:

1. SM-DP+ `initiateAuthentication` (server side). The LPA sends `euiccInfo1`, which contains `euiccCiPKIdListForVerification` (CI key IDs the eUICC will accept for verifying the server) and `euiccCiPKIdListForSigning` (CI key IDs under which the eUICC can sign). The SM-DP+ must pick a `CERT.DPauth.SIG` that chains to a CI in the verification list. If it has none, it returns subjectCode `8.8.4` / reasonCode `3.7` — exactly your observation. The failure is server-side because the sysmocom server is honest and refuses to proceed.

2. eUICC `ES10b.AuthenticateServer` (card side). The eUICC verifies the server certificate chain (`CERT.DPauth.SIG` up to the CI root) using the CI public key held inside the secure element. A dishonest or patched server that skipped step 1 would still fail here. This is the cryptographic enforcement that root and LPA changes cannot reach.

The team's read is confirmed by the osmocom euicc-manual and sysmocom's own SM-DP+ notes: "You can only download the eSIM profiles using an eUICC that itself contains a SGP.26 test key/certificate." Production eUICC plus test SM-DP+ is impossible by design.

Your eUICC's single supported CI key `81370F5125D0B1D408D4C3B232E6D25E795BEBFB` is the GSMA production "RSP2 Root CI1" run by DigiCert (expires 2052). The sysmocom server's `f54172bdf98a95d65cbeb88a38a1c11d800a85c3` is an SGP.26 v1.x test CI. No overlap, so no trust.

## Q2: Can a CI public key be added to an existing eUICC?

Not by you, and not on this device.

- CI root public keys are loaded by the EUM (eUICC manufacturer) during production and live in the secure element. SGP.22 states identities rely on a single root of trust, the eSIM CA, whose public key is "stored pre-issuance on the eUICC."
- SGP.22 v3 added `euiccCiUpdateSupport` and multi-CI handling. This governs which CI keys the eUICC advertises and how a v3 eUICC negotiates among several pre-loaded CIs. It does not give an open API to inject an arbitrary new root CA public key. Any such update is gated by EUM/GSMA-controlled, signed provisioning data. Those keys are not available to end users.
- SGP.32 (IoT) adds the eIM (eSIM IoT remote Manager) and IoT Profile Assistant. It changes who triggers downloads. It does not change the CI trust anchor model. Profiles and servers still chain to a GSMA CI.
- The only known way anyone has altered eUICC-internal trust material is exploitation (see Q6), not a supported feature.

Conclusion: adding a test CI to the Pixel's production eUICC is not possible without the EUM's keys, which you do not have. Treat the production eUICC's CI list as fixed.

## Q3: Test eUICC options that trust SGP.26

Removable, card-form-factor test eUICCs exist and are the standard tool. They ship with SGP.26 test-CI certificates, so they trust test SM-DP+ servers (sysmocom, Infineon) and your own osmo-smdpp.

| Product | Form factor | Certs | EIN prefix | Price | Notes |
|---|---|---|---|---|---|
| sysmoEUICC1-C2T | 2FF/3FF/4FF seamless cut | SGP.26 v2.x test CI | 89049044 | EUR 95.20 incl VAT | Best documented; reviews confirm EasyEUICC + lpac work |
| COMPRION Consumer Test eUICC | card | SGP.26 v1.x test CI | 89049032 | contact vendor | Older v1.x test CI |
| Infineon test (via test SM-DP+) | varies | test CI | — | — | `testsmdpplus.infineon.com`, login required |

Production-CI removable cards (sysmoEUICC1-C2G "9eSIM", ESTKme) exist too, but they trust only production CI, so they behave like your Pixel for this purpose. They are useful only for downloading real carrier profiles, not for test SM-DP+ work.

Tooling support:

- The sysmoEUICC1-C2T works in a USB CCID PC/SC reader with lpac on the laptop. No phone required.
- It also works on the rooted Pixel through OpenEUICC (privileged) or EasyEUICC (ARA-M / carrier-privilege allowlisted), since the card itself carries the test certs.
- 5ber, eSIM.me, and Estonia/IoT cards are general-purpose removable eUICCs. They generally carry production CI, not SGP.26 test CI, so they do not solve the test-server problem. Verify the CI key ID before buying if you want test support; assume production unless stated otherwise.

Cost/effort winner: sysmoEUICC1-C2T. One EUR 95 card unlocks both the phone and the laptop path.

## Q4: Software / emulated eUICC

There is no mature, drop-in software eUICC that implements SGP.22 with the SGP.26 test keys end to end.

Pieces that exist:

- jCardSim — open-source Java Card Runtime Environment simulator (Java Card 2.2.1/2.2.2). It can run Java Card applets on a PC and expose them over a virtual reader. It is the natural host for an ISD-R/eUICC applet, but it does not ship an SGP.22 eUICC applet.
- OpenRSP — open-source RSP implementation effort for eSIM profile management. Server-leaning, not a packaged software eUICC.
- rlpa-server — remote LPA server from the lpac group. Transport plumbing, not an eUICC.
- The hard missing piece is a complete, open SGP.22 eUICC applet (ISD-R, ECASD, profile package handling, ES8+/ES10 command set) seeded with SGP.26 test keys. No public project provides this in usable form. Vendors keep their eUICC OS proprietary.

Practical implication: a fully software, no-hardware RSP loop is not realistic today. The closest "no phone" setup is still hardware: a real test eUICC in a PC/SC reader driven by lpac, talking to osmo-smdpp. That is cheap, documented, and fully under your control.

## Q5: Self-hosting an SM-DP+ that a production eUICC trusts

Not possible for a research setup.

- A production eUICC accepts only servers whose certs chain to a production GSMA CI (for the Pixel, DigiCert RSP2 Root CI1).
- To get such certs you must be a GSMA SAS-SM accredited SM-DP+ operator and obtain DPtls/DPauth/DPpb certificates signed by the GSMA CI. osmo-smdpp's own docs state this plainly: without GSMA-CI-signed certs you cannot use it with a production eUICC.
- The GSMA CI private keys are held by the CI operators (DigiCert, Cybertrust, WISeKey) under SAS audit. They are not public and not obtainable for testing. The trust-anchor model is deliberately one-way: the eUICC trusts the root, the root signs only accredited parties.
- There is no public or research path to a production-CI-signed test SM-DP+. The supported research path is the inverse: use a test eUICC and a test-CI SM-DP+.

So the production CI key is confirmed unavailable, and the design intends it to be.

## Q6: Patching the eUICC vs patching the LPA

What root + a patched LPA CAN do:

- See and log ES9+/ES11 transport (HTTPS to SM-DP+/SM-DS). You already do this.
- Bypass the LPA's TLS validation (OpenEUICC `ignore_tls_certificate` / AllowAllTrustManager). Gets HTTP 200, nothing more.
- Bypass the LPA-side CI check. The OpenEUICC-SGP.26 fork (`laf0rge/OpenEUICC-SGP.26`) is "extended to accept GSMA SGP.26 test root certificate." This only stops the LPA from rejecting the chain. It still needs a test eUICC, because the eUICC re-checks.
- Use a custom ISD-R AID, and inspect/modify what the LPA sends the server (including the CI list in `euiccInfo1`). But the eUICC signs `euiccInfo1`-derived material during AuthenticateServer; you cannot make the card honor a CI it does not hold by editing the LPA's view.

What they CANNOT do:

- Change eUICC-internal certificate validation in `ES10b.AuthenticateServer`.
- Add or replace CI root public keys in the secure element.
- Touch ES8+ / BPP decryption keys or the eUICC's private keys.

Bypassing eUICC-side validation via attacks (research, not a method for you):

- Security Explorations (Adam Gowdiak) broke a Kigen eUICC via a Java Card VM type-confusion bug. With physical access and known OTA keys (the TS.48 generic test profile's well-known static keys), they loaded a malicious applet, escaped the VM, and extracted the eUICC's private ECC GSMA identity key and plaintext MNO profiles (K/OPc/AMF). Kigen paid a USD 30,000 bounty. Harald Welte's analysis traces the root cause to Java Card permitting off-card bytecode verification, plus shared hardware holding many operators' load keys. Mitigation in TS.48 v7 randomizes the test key material.
- This is key extraction and applet injection on a vulnerable card, not a clean way to add a CI to a healthy production eUICC. It needs physical access, a vulnerable EUM OS, and known keys. It is the wrong tool for building a test bench. Treat it as background on why the trust model is fragile, not as a workaround.

## Q7: Recommended setups, ranked

| Rank | Setup | What you get | Cost | Effort | Notes |
|---|---|---|---|---|---|
| 1 | sysmoEUICC1-C2T + lpac + PCSC reader + osmo-smdpp (laptop) | Full RSP loop you control, successful install, plus you author/sign profiles | ~EUR 95 card + ~EUR 15 reader | Low | Best for protocol study; no phone needed |
| 2 | sysmoEUICC1-C2T in rooted Pixel via OpenEUICC/EasyEUICC + sysmocom test SM-DP+ | Successful install on the real phone you target | ~EUR 95 | Low | Closest to your phone MITM scenario |
| 3 | Pixel internal (production) eUICC + free/cheap production-CI carrier profile | A real successful download on the production eUICC | EUR 0–10 | Low | Studies a real chain end to end, but you do not control the server |
| 4 | Software eUICC | — | — | — | Not viable today (Q4) |

### Setup 1 commands (laptop, fully self-hosted)

Reader and lpac:

```bash
sudo apt install pcscd
sudo systemctl enable --now pcscd.socket
# download lpac-linux-x86_64.zip from github.com/estkme-group/lpac/releases
export LPAC_APDU=pcsc
export LPAC_HTTP=curl
./lpac chip info          # reads EID, default SM-DP+, SM-DS
./lpac profile list
```

osmo-smdpp (proof-of-concept SM-DP+, ships SGP.26 test certs):

```bash
# from pysim repo; serves test certs from ./smdpp-data/certs
./osmo-smdpp.py                 # built-in TLS on :443, host testsmdpplus1.example.com
# or behind your own TLS proxy:
./osmo-smdpp.py -p 8000 --nossl
```

Point the LPA at it. The test certs bind to `testsmdpplus1.example.com`, so add that hostname to your DNS/hosts file pointing at the server. Then download:

```bash
./lpac profile download -s testsmdpplus1.example.com -m "<matchingID>"
./lpac profile enable <ICCID>
```

### Setup 2 (rooted Pixel)

Use the sysmocom hosted test SM-DP+ instead of self-hosting. Activation via the OpenEUICC/EasyEUICC GUI:

- SM-DP+: `smdpp.test.rsp.sysmocom.de`
- Use a TS.48 test profile matching ID (see the osmocom known-test-profile page for current matching IDs).
- The card's SGP.26 certs satisfy AuthenticateServer, so the install completes.

This is the setup that mirrors your phone MITM research most directly: a real phone, a real LPA, a real SM-DP+ handshake, and a profile that actually installs — because the eUICC and server share a CI.

## Sources

- SGP.22 RSP Technical Specification v2.3 (PDF): https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2021/07/SGP.22-v2.3.pdf
- SGP.22 v2.2.2 (PDF): https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2020/06/SGP.22-v2.2.2.pdf
- SGP.32 eSIM IoT Technical Specification v1.1 (PDF): https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2024/04/SGP.32-v1.1.0.pdf
- GSMA eSIM Certificates / Root CI: https://www.gsma.com/solutions-and-impact/technologies/esim/gsma-root-ci/
- osmocom euicc-manual, Certificate Issuers (CI key IDs, production + SGP.26): https://euicc-manual.osmocom.org/docs/pki/ci/
- osmocom euicc-manual, Known eUICC Cards: https://euicc-manual.osmocom.org/docs/lpa/known-card/
- osmocom euicc-manual, Known Test Profiles: https://euicc-manual.osmocom.org/docs/rsp/known-test-profile/
- osmocom euicc-manual, SM-DP+: https://euicc-manual.osmocom.org/docs/rsp/sm-dp-plus/
- osmo-smdpp manual (setup, cert requirements): https://downloads.osmocom.org/docs/pysim/master/html/osmo-smdpp.html
- osmo-smdpp wiki: https://osmocom.org/projects/pysim/wiki/Osmo-smdpp
- sysmocom test SM-DP+ (key ID f54172...): https://test.rsp.sysmocom.de/
- sysmoEUICC1-C2T product page (EUR 95.20): https://shop.sysmocom.de/eUICC-for-consumer-eSIM-RSP-with-SGP.26-Test-Certificates/sysmoEUICC1-C2T
- EasyEUICC announcement (Osmocom Discourse): https://discourse.osmocom.org/t/easyeuicc-download-sgp-26-test-esims-via-an-android-gui-program/286
- OpenEUICC (upstream mirror): https://github.com/estkme-group/openeuicc
- OpenEUICC-SGP.26 fork (accepts test root cert): https://gitea.angry.im/laf0rge/OpenEUICC-SGP.26
- lpac repo and releases: https://github.com/estkme-group/lpac
- lpac USAGE.md: https://github.com/estkme-group/lpac/blob/main/docs/USAGE.md
- Soprani.ca lpac + PCSC walkthrough: https://wiki.soprani.ca/eSIM%20Adapter/lpac
- Harald Welte, eSIM/eUICC/Java Card security analysis: https://laforge.gnumonks.org/blog/20250709-gsma-esim-euicc-security/
- Security Explorations, eSIM security (Kigen): https://security-explorations.com/esim-security.html
- The Hacker News, Kigen eUICC vulnerability: https://thehackernews.com/2025/07/esim-vulnerability-in-kigens-euicc.html
- jCardSim: https://jcardsim.org/
- Mode51, AuthenticateClient deep dive: https://medium.com/@mode51/esim-rsp-sm-dp-common-mutual-authentication-part-5-authenticateclient-ba411bd1b9a0
- Infineon, eSIM mutual authentication: https://community.infineon.com/t5/Blogs/eSIM-Security-A-Deep-Dive-into-Mutual-Authentication/ba-p/826519
- Harald Welte, "Open Source for eSIM integration" (ELCE 2025 slides): https://static.sched.com/hosted_files/osseu2025/b4/elce2025-open_source_for_esim_integration.pdf
