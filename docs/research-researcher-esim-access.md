# Researcher Access to Production-CI SM-DP+ for RSP Testing

**Goal:** Identify paths for a PhD researcher to gain repeatable production-CI eSIM profile downloads beyond the free reusable codes and 1GLOBAL Connect API already documented in `research-repeatable-esim-issuer.md`.

**Test rig:** Rooted Pixel 7a, retail eUICC trusting only GSMA Live CI (`81370F…`, DigiCert RSP2 Root CI1). SGP.26 test-CI servers are rejected by the hardware.

---

## Ranked Recommendation Table

| # | Path | Eligibility | Cost per cycle | Repeatable | Prod-CI | Friction |
|---|------|-------------|---------------|------------|---------|----------|
| 1 | Free reusable codes (prior report) | Anyone | $0 | Yes — unlimited | ✓ | None — already have them |
| 2 | **Telnyx eSIM API** | Self-serve account | ~$0.70/code + $2/mo | Yes — new code per cycle | ✓ (commercial) | Low — sign up, add credit, call API |
| 3 | **eSIM Go API** | Reseller account, $100 test credit | ~$1–5/code (volume-based) | Yes — new code per cycle | ✓ (travel eSIM) | Medium — reseller onboarding |
| 4 | **COMPRION eSIM Test Profile Service** | Any company or lab | Credits (200 min to open account) | Yes — delete frees slot for another device | ✓ (GSMA live certs) | Medium — credit purchase, portal |
| 5 | GSMA Academic Membership | University / research institution | ~£15,000–£30,000/yr (estimated) | N/A — membership only | N/A | High — institutional; no SM-DP+ access granted |
| 6 | freeesim.edu.pl / freeesim.org | .edu / .ac / .edu.pl email | $0 | No — re-apply each semester | ✓ (prod networks) | Low — email verification |
| 7 | SM-DP+ vendor academic programs (Thales, IDEMIA, G+D, Kigen) | Not available | N/A | N/A | N/A | Not offered |

---

## 1. GSMA Academic / Research Programs

GSMA does offer an **Academic Membership** tier described as "for research institutions working on mobile technology related projects." A **Sector Membership** exists for commercial entities needing limited access.

**What it grants:**

- Participation in GSMA Working Groups, including the RSP/eSIM groups that author SGP.21/SGP.22
- Access to pre-release specification drafts and meeting documents via the Member Gateway
- Networking with MNOs, SM-DP+ vendors, and CI operators

**What it does NOT grant:**

- SM-DP+ access or production CI credentials
- Any right to operate an SM-DP+ or download profiles
- Getting production CI certificates requires a separate, expensive path: SAS-SM security audit of your SM-DP+ infrastructure, GSMA compliance process, and PKI certificate purchase — all designed for commercial operators, not individual researchers

**Cost:** Not publicly disclosed. GSMA fees scale with revenue for operator and industry members. Academic and sector member contributions are negotiated. Third-party resellers list GSMA memberships starting around £15,000/year for small companies; academic rates may differ. Contact: gsma.com/membership.

**GSMA Foundry:** Focused on 5G healthcare and enterprise applications, not RSP/eSIM research. Partners are large institutions (hospital systems, MNOs). No eSIM researcher access path found.

**Verdict:** Academic membership earns a seat at the standards table. It does not open SM-DP+ access. Worth pursuing for a multi-year research program that aims to influence SGP.22 or SGP.32; not useful for immediate production-CI profile downloads.

**Contact:** membership@gsma.com — [GSMA Academic/Sector membership page](https://www.gsma.com/membership/membership-types/sector-members/)

---

## 2. SM-DP+ and eUICC Vendor Research Programs

### Kigen (ARM)

ARM Academic Access provides institutional access to Arm processor IP and design tools under a simple institutional agreement. The program does not include Kigen eUICC OS, SM-DP+ software, or SAS-SM services. Kigen's SM-DP+ Cloud is targeted at MNOs and OEM partners; no academic tier exists.

**Verdict:** Not applicable. ARM Academic Access covers silicon/tools, not RSP infrastructure.

### Thales, IDEMIA, Giesecke+Devrient (G+D)

All three dominate the GSMA eSIM enablement rankings. None publish an academic research program, eval sandbox, or developer tier for their SM-DP+ platforms. All engagement is enterprise B2B, typically requiring MNO sponsorship, NDAs, and commercial contracts.

**Verdict:** No path for an individual PhD researcher without a commercial partner.

### Workz Group

Five-time GSMA-certified for full eSIM lifecycle management. Operates an eSIM Cloud platform for MVNOs and OEMs. No academic program found. All access is through partnerships (Monogoto uses Workz eSIM Cloud, for example).

### Valid, IDEX Biometrics

No academic or research programs found for either vendor.

### COMPRION eSIM Test Profile Service

COMPRION offers a credit-based eSIM Test Profile Service that runs on **GSMA live certificates** (production CI). Designed for device manufacturers, conformance labs, and OEM production QA — but commercially available to any company.

- **CI:** Production (GSMA live certificates confirmed)
- **Profiles:** Unique ICCID per profile; compatible with commercial eUICCs
- **Re-download:** Deleting a profile on one device frees it for another device to download — not unlimited same-device cycling
- **Pricing:** Credits; 200 credits minimum to open an account; per-download cost not public (request a price list from comprion.com)
- **Eligibility:** Commercial account required; no academic tier published
- **Good for:** Getting a fresh production-CI profile for each test cycle, if you can absorb the per-credit cost

**Verdict:** Viable if the per-credit cost is low (request quote). Profiles work on the Pixel 7a eUICC. Not free. Re-download model is "delete on device A, download on device B" rather than same-device repeat — check with vendor whether same-device re-download is possible.

**Contact/URL:** [COMPRION eSIM Test Profile Service](https://www.comprion.com/products-solutions/products-solutions-a-z/esim-test-profile-service/)

### 1GLOBAL / Truphone

Already covered in the prior report. No academic tier. B2B API only.

### RedteaGO

B2B reseller program. No academic tier. Free reusable code already documented.

---

## 3. Programmatic Code Issuance — Self-Serve APIs

### Telnyx eSIM API ⭐ Best Self-Serve Option

Telnyx is a CPaaS provider that offers a self-serve eSIM API. The API issues production-CI eSIM profiles (Telnyx is a commercial MVNO-enabler operating under GSMA compliance).

- **Sign-up:** Self-serve at telnyx.com — no sales call required
- **API:** `POST /v2/sim_cards/esims` purchases an eSIM. Response includes the ICCID. Retrieve the LPA activation code via `GET /v2/sim_cards/{uuid}`.
- **Pricing:** ~$0.70 per eSIM purchased; $2/month per activated SIM; $0.20/month per inactive SIM
- **CI:** Commercial production GSMA CI (specific SM-DP+ address not publicly documented)
- **Cycling:** Each test cycle = purchase a new eSIM code ($0.70). No EID-lock between purchases. Previous code can be abandoned after profile is deleted on-device.
- **Data plan:** IoT-focused but eSIM API also covers consumer eSIMs; no mandatory data plan required per eSIM
- **Eligibility:** Any self-serve account — a PhD researcher qualifies immediately

**Verdict:** Most accessible path to controlled, programmatic, production-CI activation code generation. At $0.70/cycle, 100 test cycles costs $70. No academic discount but open to individuals. API is documented at [developers.telnyx.com](https://developers.telnyx.com/api/wireless/purchase-e-sim).

### eSIM Go API

eSIM Go is a travel eSIM aggregation platform with a reseller API. Production CI (commercial travel eSIMs on GSMA Live CI). $100 test credit available for new partners. Prepaid wallet model. Prices are volume-based (per-eSIM wholesale pricing, not published; requires a reseller account).

- **Friction:** Higher than Telnyx — reseller onboarding, not just a developer account
- **API docs:** [docs.esim-go.com](https://docs.esim-go.com/)
- **Cycling:** Same approach as Telnyx: purchase a new activation code per test cycle

**Verdict:** Viable but more friction than Telnyx. More suitable if you want a variety of underlying MNO profiles from different providers.

### emnify

emnify is an IoT CPaaS. They offer a 60-day free trial using their developer eSIM (SGP.22-compliant, backed by 10T Tech SM-DP+). The platform is designed for IoT deployments, but their consumer eSIM product (SGP.22) is compatible with consumer eUICCs.

- **Free trial:** 60-day or until prepaid balance runs out; no credit card to start
- **CI:** Production CI (commercial SGP.22-compliant service)
- **Re-download after delete:** Their IoT eIM platform supports profile download/delete/enable/disable operations via API across the same EID. Whether the same applies to their consumer eSIM product is not documented publicly.
- **Friction:** Sign up at portal.emnify.com; free to start
- **URL:** [emnify developer eSIM](https://www.emnify.com/blog/emnify-developer-esim)

**Verdict:** Worth testing during the 60-day trial period. If the consumer eSIM supports delete + re-download on the same EID via API, this is the cheapest path (free for 60 days). Unclear whether it beats the free reusable codes for pure handshake testing.

### Monogoto

IoT connectivity platform using Workz eSIM Cloud. Activation codes are issued by the team (not fully automated self-serve). No public pricing. More friction than Telnyx.

### floLIVE, Onomondo, 1NCE

All IoT/M2M focused, primarily SGP.02 or SGP.32 profiles. Not consumer SGP.22 compatible with a Pixel 7a retail eUICC.

---

## 4. Academic Testbeds and Published Research Methods

### Aalto University — "Security Analysis of the Consumer Remote SIM Provisioning Protocol"

**Authors:** Ahmed, Peltonen, Sethi, Aura  
**Published:** ACM Transactions on Privacy and Security, Vol. 27 Issue 3, August 2024  
**arXiv:** [arxiv.org/abs/2211.15323](https://arxiv.org/abs/2211.15323)  
**GSMA briefing:** [gsma.com/security-analysis-of-the-consumer-remote-sim-provisioning-protocol](https://www.gsma.com/solutions-and-impact/technologies/esim/security-analysis-of-the-consumer-remote-sim-provisioning-protocol/)

**Methodology:** Formal security analysis using applied pi calculus and ProVerif tool. This is a **protocol-level analysis**, not an empirical testbed with real profile downloads. The researchers did not need repeated production-CI downloads — they modeled the RSP protocol mathematically.

**Takeaway:** If your research goal is formal security analysis, you do not need production-CI access at all. If your goal is empirical protocol observation (e.g., packet capture, timing analysis), this paper provides no guidance on SM-DP+ access.

### USENIX Security 2025 — "eSIMplicity or eSIMplification?"

**Authors:** Motallebighomi, Veara, Bitsikas, Ranganathan  
**Conference:** 34th USENIX Security Symposium, 2025  
**PDF (mirror):** [aanjhan.com/assets/sec25-motallebighomi.pdf](https://aanjhan.com/assets/sec25-motallebighomi.pdf)

**Methodology:** Used a **private LTE testbed (Amarisoft-based)** and **commercial SM-DP+ infrastructure** — specifically travel eSIM providers including one using `consumer.rsp.world` as the SM-DP+ address. The researchers purchased commercial travel eSIMs from multiple providers and observed device behavior during profile disablement and deletion. They did not need an academic SM-DP+ relationship — they bought consumer eSIMs as any user would.

**Testbed approach:** Amarisoft LTE base station + commercial eSIM purchases. No special SM-DP+ access arrangement documented.

**Takeaway:** USENIX-level security research on SGP.22 was done using ordinary commercial eSIM purchases, not any academic SM-DP+ arrangement. This validates the approach of using cheap commercial eSIM purchases (e.g., Telnyx at $0.70/cycle) rather than seeking an academic program.

### No Academic Testbed Found

No published paper or consortium was found that documents a dedicated university eSIM testbed providing repeatable production-CI profile downloads under an academic arrangement. All empirical RSP research found used commercial purchases or free reusable codes.

---

## 5. MVNO and IoT Providers with Re-Provisionable eSIMs

### freeesim.edu.pl (Academic Connectivity Initiative)

A Warsaw-based non-profit initiative providing free eSIM profiles for academics.

- **Eligibility:** Students, researchers, and faculty with a `.edu`, `.ac`, or `.edu.pl` email; developers can apply via a Research Sandbox program
- **What you get:** 2.5 GB of 5G data, production networks (T-Mobile/AT&T USA, SoftBank Japan, Telstra Australia)
- **CI:** Production (commercial MNO networks)
- **Re-download:** Profiles expire after 7 days or when data runs out. Reapplication allowed once per academic semester.
- **API:** Documented (`GET /api/v1/provision_esim`) — research sandbox users may get API access
- **Cost:** Free
- **Verdict:** Not suitable for unlimited cycling (semester-rate limit). Useful for occasional controlled testing or validating a specific RSP sequence once per semester. The Research Sandbox API path is worth exploring — contact the Academic Connectivity Initiative to ask if the rate limit can be lifted for protocol research with no data consumption.
- **URL:** [freeesim.edu.pl](https://freeesim.edu.pl/) (redirects to esimfree.org)

### COMPRION (repeated from §2)

Already listed. Credit-based, production CI, "delete frees for another device" model.

### IoT Providers — Not Applicable

1NCE, Onomondo, and similar IoT providers use SGP.02 (M2M) profiles pushed by the operator. These require a network-side trigger to download a profile and are not compatible with consumer eUICC SGP.22 flow. The Pixel 7a's retail eUICC cannot receive M2M profiles.

---

## 6. Per-Path Summary: Eligibility, Cost, Repeatability, and Friction

| Path | PhD researcher qualifies? | Cost | Truly repeatable (no EID-lock, no cap) | Prod-CI | Signup friction |
|------|--------------------------|------|----------------------------------------|---------|-----------------|
| Telnyx eSIM API | Yes — self-serve | ~$0.70/cycle | Yes — new code each cycle, no EID-lock | ✓ | Low: sign up, top up balance |
| eSIM Go API | Yes — reseller account | ~$1–5/code | Yes — new code per cycle | ✓ | Medium: reseller onboarding |
| emnify (60-day trial) | Yes — free trial | Free (trial) | Unclear for consumer SGP.22 | ✓ | Low: portal.emnify.com |
| COMPRION eSIM Test Profiles | Yes, but needs company account | Credits | Delete → re-download on different device only | ✓ | Medium: credit purchase |
| freeesim.edu.pl Research Sandbox | Yes — .edu email | Free | No — semester rate limit | ✓ | Low: email verification |
| GSMA Academic Membership | University institution | £15k+/yr estimated | N/A — no SM-DP+ access | N/A | High: institutional |
| Thales / IDEMIA / G+D / Kigen | No academic program | N/A | N/A | N/A | Not available |

---

## Most Realistic Path

**For pure RSP handshake cycling with no code-control need:** the free reusable BetterRoaming and RedteaGO codes (prior report) remain unbeaten. Zero cost, unlimited cycles, production CI. Any academic program adds cost and friction without benefit here.

**For controlled code generation** (varying ICCIDs, testing specific matching IDs, injecting errors, testing RSP over different SM-DP+ endpoints): **Telnyx eSIM API** is the most accessible path. Self-serve signup, $0.70 per activation code, production CI, no minimum order. Each test cycle = purchase a new code. 100 cycles = $70. No NDA, no sales call, no academic letter needed.

**For academic credibility / standards engagement:** pursue GSMA Academic Membership if the institution can absorb the cost. It will not give SM-DP+ access but will grant access to RSP working group documents and contacts at SM-DP+ vendors who might offer informal sandbox access after relationship-building.

**Application links:**
- Telnyx: [telnyx.com](https://telnyx.com) → Mission Control Portal → SIMs & eSIMs → Developer docs: [developers.telnyx.com/api/wireless/purchase-e-sim](https://developers.telnyx.com/api/wireless/purchase-e-sim)
- eSIM Go: [esimgo.com/product/solutions/api/](https://esimgo.com/product/solutions/api/)
- emnify free trial: [portal.emnify.com](https://portal.emnify.com)
- freeesim Research Sandbox: [freeesim.edu.pl](https://freeesim.edu.pl/)
- COMPRION: [comprion.com/esim-test-profile-service](https://www.comprion.com/products-solutions/products-solutions-a-z/esim-test-profile-service/)
- GSMA membership: [gsma.com/get-involved/gsma-membership/become-a-gsma-member/](https://www.gsma.com/get-involved/gsma-membership/become-a-gsma-member/)

---

## Sources

- [GSMA — Academic/Sector Members](https://www.gsma.com/membership/membership-types/sector-members/)
- [GSMA — Membership Categories & Contributions](https://www.gsma.com/get-involved/gsma-membership/membership-categories-contributions/)
- [GSMA — GSMA Foundry Partners](https://www.gsma.com/get-involved/gsma-foundry/gsma-foundry-partners/)
- [GSMA — eSIM Certificates / CI](https://www.gsma.com/solutions-and-impact/technologies/esim/gsma-root-ci/)
- [GSMA — RSP Technical Onboarding (SM-DP+ compliance)](https://www.gsma.com/solutions-and-impact/technologies/esim/root-ds-technical-onboarding-support/)
- [GSMA — eSA Price List 2024](https://www.gsma.com/solutions-and-impact/industry-services/wp-content/uploads/2024/05/GSMA-eSA-Price-List-2024.pdf)
- [GSMA — Security Analysis of the Consumer RSP Protocol (Aalto, Black Hat Europe 2024)](https://www.gsma.com/solutions-and-impact/technologies/esim/security-analysis-of-the-consumer-remote-sim-provisioning-protocol/)
- [Ahmed et al. — Security Analysis of the Consumer Remote SIM Provisioning Protocol (ACM TOPS 2024)](https://dl.acm.org/doi/full/10.1145/3663761)
- [Ahmed et al. — arXiv preprint 2022](https://arxiv.org/abs/2211.15323)
- [Aalto University research portal listing](https://research.aalto.fi/en/publications/security-analysis-of-the-consumer-remote-sim-provisioning-protoco)
- [Motallebighomi et al. — eSIMplicity or eSIMplification? USENIX Security 25](https://www.usenix.org/conference/usenixsecurity25/presentation/motallebighomi)
- [USENIX 2025 paper PDF](https://www.usenix.org/system/files/usenixsecurity25-motallebighomi.pdf)
- [Telnyx — Purchase eSIMs API](https://developers.telnyx.com/api/wireless/purchase-e-sim)
- [Telnyx — SIMs & eSIMs Developer Docs](https://developers.telnyx.com/docs/iot-sim/get-started)
- [Telnyx — Global SIMs FAQs](https://support.telnyx.com/en/articles/3270136-telnyx-global-sims-faqs)
- [Telnyx — Manual eSIM activation guide](https://support.telnyx.com/en/articles/10067533-manual-esim-activation-guide)
- [eSIM Go API](https://esimgo.com/product/solutions/api/)
- [eSIM Go Developer Docs](https://docs.esim-go.com/guides/getting_started/)
- [emnify — Developer eSIM launch announcement](https://www.emnify.com/blog/emnify-developer-esim)
- [emnify — Consumer eSIM Global (docs)](https://docs.emnify.com/services/consumer-esim-global)
- [emnify — Activation code how-to](https://docs.emnify.com/how-tos/consumer-esim/activation-code-activation)
- [Monogoto — eSIM docs](https://docs.monogoto.io/getting-started/sim-cards/esim)
- [COMPRION — eSIM Test Profile Service](https://www.comprion.com/products-solutions/products-solutions-a-z/esim-test-profile-service/)
- [COMPRION — eSIM Test Profile Service Credits](https://www.comprion.com/shop/esim-test-profile-service-credits.html)
- [COMPRION — FAQ](https://www.comprion.com/esim-test-profile-service-faq/)
- [Fime — SM-DP+ Simulator (SGP.26 test CI only)](https://www.fime.com/shop/product/sm-dp-simulator-4951)
- [ARM Academic Access program](https://www.arm.ecs.soton.ac.uk/projects/arm-academic-access/)
- [Kigen — GSMA SAS-SM accreditation](https://kigen.com/resources/news/first-gsma-sas-sm-for-eim/)
- [freeesim.edu.pl — Academic Connectivity Initiative](https://freeesim.edu.pl/)
- [osmocom euicc-manual — Known Test Profiles](https://euicc-manual.osmocom.org/docs/rsp/known-test-profile/)
- [osmocom euicc-manual — SM-DP+](https://euicc-manual.osmocom.org/docs/rsp/sm-dp-plus/)
- [Counterpoint Research — Thales, G+D, IDEMIA lead eSIM rankings 2025](https://counterpointresearch.com/en/insights/gd-thales-idemia-deemed-pacesetters-in-2025-esim-enablement-rankings)
- [1GLOBAL — Consumer RSP overview](https://www.1global.com/consumer-remote-sim-provisioning)
