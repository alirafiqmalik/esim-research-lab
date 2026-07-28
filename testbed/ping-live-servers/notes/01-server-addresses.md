# Step 1 — SM-DP+ / SM-DS Server Addresses

Publicly-documented SM-DP+ and SM-DS FQDNs for the 13 GSMA RSP providers in
scope. All research is from public sources: vendor documentation, GSMA
materials, the osmocom euicc-manual, certificate-transparency logs (crt.sh /
certspotter), module-manufacturer manuals (Quectel), reseller pages, and
GitHub issue threads from device/firmware developers logging real connection
attempts. No live request was sent to any SM-DP+ or SM-DS host to produce
this document — every address below was found by reading someone else's
already-published page, log, or certificate record.

Confidence levels:
- **high** — the vendor's own docs/product page explicitly names the FQDN.
- **medium** — corroborated by a second-party technical source (osmocom, a
  GSMA doc, a working activation code, a module manufacturer's manual, or
  multiple independent GitHub reports), but not the vendor's own docs.
- **low** — a single unconfirmed mention (one forum/blog post, one aggregator
  listing, or a CT-log hostname with no corroborating use).
- **not found** — no address exists in any source checked. Recorded honestly
  rather than guessed, per the research brief.

Machine-readable form: `analysis/server-addresses.jsonl` (13 lines, one per
provider).

## Coverage summary

| Provider | SM-DP+ | SM-DS | Best confidence |
|---|---|---|---|
| 1GLOBAL | `rsp.truphone.com` | not found | high |
| Eastcom Peace | `secsmsminiapp.eastcompeace.com` (+1 low-confidence candidate) | not found | medium |
| Giesecke+Devrient (G+D) | 2 carrier-instance hosts (`*.rsp.gieseckedevrient.com`) | not found | medium |
| Idemia | 7 carrier-instance hosts (`*.idemia.io`) | not found (GSMA Discovery integrated into SM-DP+ platform, no branded SM-DS FQDN) | medium |
| Invigo | not found | not found | — |
| Kigen | 2 hosts (`smdp-plus-{0,1}.eu.cd.rsp.kigen.com`) | not found | medium |
| Linksfield | `rsp-0001.linksfield.net` (+3 low-confidence candidates, roles unconfirmed) | not found | medium |
| Redtea Mobile | `rsp-eu.redteamobile.com` | not found | high |
| Teal Communications | not found (only B2B integration-API hosts, not confirmed device-facing) | not found | low |
| Thales | not found (SM-DP+ is white-labelled per-MNO) | `lpa.ds.gsma.com`, `lpa.live.esimdiscovery.com`, `lpa.live.esimdiscovery.dev` | high |
| Valid | `demo-consumer.validspereachdpplus.com` (+5 low-confidence candidates) | not found | medium |
| Watchdata | not found | not found | — |
| Workz | not found | not found | — |

4 of 13 providers have a medium-or-better-confidence SM-DP+ address; 1
(Thales) has medium/high-confidence SM-DS addresses (as the GSMA Root SM-DS
operator, not a Thales-branded SM-DS). 4 providers (Invigo, Watchdata, Workz,
and Teal Communications for the device-facing FQDN) have nothing publicly
documented at all — recorded honestly as not found.

---

## 1GLOBAL

### SM-DP+ / SM-DS addresses

| host | type | confidence | source_url |
|---|---|---|---|
| rsp.truphone.com | SM-DP+ | high | https://docs.connect.1global.com/docs/recipes/new-esim/ |
| (none found) | SM-DS | not found | — |

1GLOBAL was formerly Truphone; `rsp.truphone.com` is confirmed as the SM-DP+ URL returned
by 1GLOBAL's own Connect API documentation (repo seed context corroborates this).

## Eastcom Peace (Eastcompeace Technology Co., Ltd.)

### SM-DP+ / SM-DS addresses

| host | type | confidence | source_url |
|---|---|---|---|
| secsmsminiapp.eastcompeace.com | SM-DP+ (example/live) | medium | https://python.quectel.com/doc/Application_guide/en/network-comm/esim/index.html |
| ecprsp.eastcompeace.com | SM-DP+ (candidate, unverified) | low | search-engine index snippet only (title "loading... - Eastcompeace"); page was not fetched to avoid a live request to a possible production RSP host |
| (none found) | SM-DS | not found | — |

`secsmsminiapp.eastcompeace.com` appears as the SM-DP+ host in a worked LPA activation-code
example (`LPA:1$secsmsminiapp.eastcompeace.com$09533D4E06D041E396E4F4D8E427FF5B`) in
Quectel's official QuecPython developer documentation — a second-party vendor (module
manufacturer) technical source, not Eastcompeace's own docs, hence "medium." Eastcompeace
holds GSMA SAS-SM certification for SM-DP+, SM-DP, and SM-SR (first Chinese vendor to do
so, per their own press release) but no company developer portal with FQDNs was found.
Source: https://www.eastcompeace.com/en/751.html

## Giesecke+Devrient (G+D)

### SM-DP+ / SM-DS addresses

| host | type | confidence | source_url |
|---|---|---|---|
| cust-003.oberthur.rsp.gieseckedevrient.com | SM-DP+ (carrier instance — T-Mobile/US Mobile) | medium | https://blog.yesim.tech/sm-dp-address/ |
| prod.attesim.rsp.gieseckedevrient.com | SM-DP+ (carrier instance — AT&T) | medium | https://blog.yesim.tech/sm-dp-address/ |
| (none found) | SM-DS | not found | — |

Both hostnames share the pattern `*.rsp.gieseckedevrient.com`, corroborated by the same
third-party technical blog listing multiple independent carrier examples on G+D's
infrastructure (T-Mobile, AT&T, US Mobile), which is consistent with G+D's own public
statements that it operates SM-DP+ services (branded "eSIM Device Enablement Service" /
eDES) for MNOs such as Orange Belgium and Telefónica. No G+D-branded developer-portal page
naming the FQDN directly was found (hence "medium," not "high").
Sources: https://blog.yesim.tech/sm-dp-address/ ;
https://www.gi-de.com/en/group/press/press-releases/g-d-mobile-security-simplifies-connectivity-management-for-enterprises-with-the-esim-device-enablement-service

## Idemia

### SM-DP+ / SM-DS addresses

| host | type | confidence | source_url |
|---|---|---|---|
| t-mobile.idemia.io | SM-DP+ (carrier instance — Mint Mobile) | medium | https://github.com/PenumbraOS/sdk/issues/3 |
| rsp-3002.idemia.io | SM-DP+ (carrier instance) | medium | https://github.com/espressif/arduino-esp32/issues/10026 |
| rsp-3036.idemia.io | SM-DP+ (carrier instance) | medium | https://github.com/espressif/arduino-esp32/issues/10026 |
| rsp-4002.idemia.io | SM-DP+ (carrier instance — RedPocket "GSMA" profile) | medium | https://help.redpocket.com/ios-esim-manual-installation-instructions ; https://github.com/espressif/arduino-esp32/issues/10026 |
| rsp-4008.idemia.io | SM-DP+ (carrier instance) | medium | https://github.com/espressif/arduino-esp32/issues/10026 |
| vfgb.idemia.io | SM-DP+ (carrier instance — Vodafone GB, inferred from "vfgb") | low | https://github.com/espressif/arduino-esp32/issues/10026 |
| celitech.idemia.io | SM-DP+ (carrier/reseller instance — Celitech) | medium | https://github.com/PenumbraOS/sdk/issues/3 ; https://github.com/espressif/arduino-esp32/issues/10026 |
| (none found) | SM-DS | not found | IDEMIA states it has "integrated the GSMA eSIM Discovery service into its SM-DP+ platform" rather than operating its own branded SM-DS FQDN — https://www.idemia.com/insights/what-right-esim-activation-method-consumer-device-connectivity |

All confirmed hostnames share the `*.idemia.io` domain pattern, cross-corroborated by two
independent GitHub issue threads (device/firmware developers logging real TLS-connection
tests against these hosts) and one carrier help-center page (RedPocket, naming
`rsp-4002.idemia.io` directly for its "GSMA" eSIM profile). `*.idemia.io` is consistent
with IDEMIA's own statements that it runs a "Smart Connect" SM-DP+ platform for MNOs
(T-Mobile/Mint Mobile, Vodafone, RedPocket, etc.) hosted on Microsoft Azure. Confidence is
"medium" throughout since no IDEMIA-branded page explicitly lists these FQDNs; the pattern
and per-carrier subdomain naming are corroborated by independent third parties rather than
IDEMIA's own docs.

## Invigo

### SM-DP+ / SM-DS addresses

| host | type | confidence | source_url |
|---|---|---|---|
| (none found) | SM-DP+ | not found | — |
| (none found) | SM-DS | not found | — |

Extensive searching (vendor site, GitHub, carrier help pages, MTN/Ooredoo support pages,
osmocom manual, forum/blog activation-code examples) turned up no publicly documented
Invigo SM-DP+ or SM-DS FQDN. Invigo's own site confirms it operates SM-DP+/SM-DS nodes as
part of its "eSIM Manager" product and holds GSMA SAS-SM accreditation (renewed), but does
not publish the FQDN(s). No third-party carrier or developer source naming an Invigo
hostname was found either. Recorded honestly as "not found" rather than guessed.
Sources: https://invigo.com/esim-manager/ ;
https://invigo.com/invigos-esim-manager-solution-reinforced-with-the-renewal-of-the-gsma-sas-sm-accreditation/

## Kigen

### SM-DP+ / SM-DS addresses

| host | type | confidence | source_url |
|---|---|---|---|
| `smdp-plus-0.eu.cd.rsp.kigen.com` | SM-DP+ | medium | https://github.com/espressif/arduino-esp32/issues/10026 |
| `smdp-plus-1.eu.cd.rsp.kigen.com` | SM-DP+ | medium | https://github.com/espressif/arduino-esp32/issues/10026 |
| (none found) | SM-DS | not found | — |

Notes:
- Both hostnames appear in a third-party GitHub issue (ESP32 TLS-handshake bug report) as real hosts the
  reporter's device attempted to connect to; not a Kigen-authored source, hence "medium" not "high". The
  `.eu.cd.` label suggests an EU region, "consumer" (cd) instance; no other regional variants (e.g. `.na.`,
  `.ap.`) were found in public sources.
- Kigen's own marketing/glossary pages (kigen.com) describe SM-DP+/SM-DS conceptually but do not publish any
  FQDN. This matches prior repo research (`docs/research/research-repeatable-esim-issuer.md`): no public
  self-serve developer sandbox, SAS-SM certified SM-DP+ hosted on AWS for enterprise/OEM partners only.
- crt.sh lookups for `kigen.com` and common guesses (`smdp.kigen.com`, `rsp.kigen.com`, `sas.kigen.com`,
  `esim.kigen.com`, `dp.kigen.com`) returned either no certificate or server errors — consistent with no
  broadly-public dedicated cert for a consumer-facing FQDN under those names.
- No SM-DS hostname for Kigen was found anywhere in public sources. Recorded honestly as "not found".

## Linksfield

### SM-DP+ / SM-DS addresses

| host | type | confidence | source_url |
|---|---|---|---|
| `rsp-0001.linksfield.net` | SM-DP+ | medium | https://shop.maaltalk.com/qr-code-galaxy |
| `dppo.linksfield.net` | SM-DP+ (portal, unconfirmed as protocol FQDN) | low | https://dppo.linksfield.net/ (page title "LINKSFIELD SM DP+", found via Google search snippet — page body not retrievable in this session, likely JS SPA) |
| `lpa.linksfield.net` | unclear (LPA-related) | low | crt.sh certificate-transparency lookup for `%.linksfield.net` |
| `rsp-0004-ui.linksfield.net` | unclear (RSP UI, likely operator console) | low | crt.sh certificate-transparency lookup for `%.linksfield.net` |
| (none found) | SM-DS | not found | — |

Notes:
- `rsp-0001.linksfield.net` is corroborated by a real, third-party-published activation code:
  `LPA:1$rsp-0001.linksfield.net$QDDPY-TCC0J-XKJJT-L0IVK` on a reseller's public help page (Maaltalk), plus its
  presence in crt.sh's certificate list for `linksfield.net`. Two independent corroborating sources → "medium"
  confidence per the task's rubric.
- `dppo.linksfield.net` was NOT found in the crt.sh subdomain enumeration (Oct 2025 scan via c99.nl scanner:
  https://subdomainfinder.c99.nl/scans/2025-10-06/linksfield.net), only via a Google search result title. Its
  exact role (management portal vs. device-facing SM-DP+ FQDN) could not be confirmed since the page did not
  render in this session — recorded as "low" confidence and flagged as possibly a portal, not the wire FQDN.
- `rsp-0004-ui.linksfield.net` (the `-ui` suffix) looks like an operator-facing web console rather than a
  device-facing SM-DP+ FQDN; included for completeness at low confidence.
- No SM-DS hostname found for Linksfield.
- Linksfield's public marketing page (https://www.linksfield.net/what-we-do/esim/) confirms they operate
  SGP.21/SGP.22-compliant RSP/eSIM services and offer customized LPA/IPA integration, but the page content
  could not be retrieved verbatim in this session (returned empty to the fetch tool, likely JS-rendered).

## Redtea Mobile (RedteaGO)

### SM-DP+ / SM-DS addresses

| host | type | confidence | source_url |
|---|---|---|---|
| `rsp-eu.redteamobile.com` | SM-DP+ | high | https://euicc-manual.osmocom.org/docs/rsp/known-test-profile/ (corroborates repo's already-verified working activation code `LPA:1$rsp-eu.redteamobile.com$5901981126831169`) |
| (other regional, e.g. non-EU) | SM-DP+ | not found | — |
| (none found) | SM-DS | not found | — |

Notes:
- No other regional (non-EU) SM-DP+ FQDN for Redtea/RedteaGO was found. crt.sh for `redteamobile.com` shows
  only `alliance.`, `talentsphere.`, `www.` subdomains with dedicated certs — `rsp-eu` is covered by the
  wildcard `*.redteamobile.com` cert and doesn't appear as its own leaf certificate, so absence from crt.sh
  leaf-cert listing is expected and not evidence against it.
- The RedteaGO Partner "API Guide" PDF (https://static.redteago.com/nobel_front_src/RedteaGO_API_Guide.pdf)
  was reviewed in full: it documents a *commission/referral partner* API (`rousseau.redtea.dev` /
  `rousseau.redtea.io`, `/api/v1/query/areaPackages`) for resellers, not the RSP/SM-DP+ protocol. It contains
  no SM-DP+ FQDN and no rate-limit/timeout/retry information.
- RedteaGO FAQ (https://esim.redteago.com/faq-redteago-esim) tells end users they receive their SM-DP+
  address by email at purchase time (i.e., issued per-order, not a single fixed public FQDN for all
  customers) — consistent with `rsp-eu.redteamobile.com` being (at least) the EU-region address.

## Teal Communications

### SM-DP+ / SM-DS addresses

| host | type | confidence | source_url |
|---|---|---|---|
| `integrationapi.teal.global` | Teal B2B integration/management API (NOT confirmed as device-facing SM-DP+ FQDN) | low | https://simetry.freshdesk.com/support/solutions/articles/154000222061-teal-api-reference-troubleshooting-guide |
| `api.teal.global` | related infrastructure (role unconfirmed) | low | crt.sh certificate-transparency lookup for `%.teal.global` |
| `admin.teal.global` | related infrastructure (role unconfirmed) | low | crt.sh certificate-transparency lookup for `%.teal.global` |
| (none found) | SM-DP+ (device-facing FQDN) | not found | — |
| (none found) | SM-DS | not found | — |

Notes:
- Teal's own marketing pages (tealcom.io) confirm they operate a GSMA SAS-SM certified, cloud-native SM-DP+
  called "PLUS+" and a Credentialing-as-a-Service model, but publish no FQDN
  (https://tealcom.io/consumer-esim/, https://tealcom.io/mobile-network-operators-platform/).
  https://tealcom.io/openeim/ describes their SGP.32 eIM product "OpenEIM" — also no FQDN published.
  Confirmed real company: Teal Communications, founded 2018, Bellevue/Seattle WA, first US-HQ company with
  GSMA SAS-SM SMDP+ certification (multiple press sources, e.g.
  https://www.iotforall.com/news/press-teal-communications-launches-global-esim).
- `integrationapi.teal.global` was confirmed to belong to Teal Communications via the support contact
  `support@tealcommunications.com` cited in the third-party (Simetry/Freshdesk) troubleshooting guide, and its
  described purpose ("manage eSIMs, monitor usage, and automate SIM lifecycle events") — this reads as a
  partner/B2B lifecycle-management API (akin to an ES2+-style integration), not necessarily the literal
  device-facing SM-DP+ FQDN a phone's LPA would dial during profile download. Recorded at "low" confidence and
  flagged accordingly, per instructions not to guess.
- crt.sh for `teal.global` returned `*.teal.global`, `api.teal.global`, `admin.teal.global`,
  `www.api.teal.global`, `www.admin.teal.global` — no host with `smdp`/`rsp`/`lpa` in the name was found.
- No dedicated SM-DP+ or SM-DS device-facing FQDN for Teal Communications was found in any public source
  checked. Recorded honestly as "not found" rather than guessing that `integrationapi.teal.global` is it.

## Thales

### SM-DP+ / SM-DS addresses

| host | type | confidence | source_url |
|---|---|---|---|
| `lpa.ds.gsma.com` | SM-DS (GSMA Root SM-DS, platform operated by Thales) | medium | https://euicc-manual.osmocom.org/docs/rsp/sm-ds/ (corroborated by https://www.thalesgroup.com/en/markets/digital-identity-and-security/mobile/gsma-esim-discovery-service ) |
| `lpa.live.esimdiscovery.com` | SM-DS (Thales eSIM Discovery, Android production) | high | https://euicc-manual.osmocom.org/docs/rsp/sm-ds/ (Thales's own product page confirms Thales operates the Android eSIM Discovery Service: https://www.thalesgroup.com/en/markets/digital-identity-and-security/mobile/esim-discovery-service ) |
| `lpa.live.esimdiscovery.dev` | SM-DS (Thales eSIM Discovery, Android staging) | medium | https://euicc-manual.osmocom.org/docs/rsp/sm-ds/ |
| `lpads.vzw.otgeuicc.com` | SM-DS (Verizon Wireless-specific instance, Thales key) | medium | https://euicc-manual.osmocom.org/docs/rsp/sm-ds/ |
| (none found) | SM-DP+ | not found | — |

Thales does not operate a single public "Thales SM-DP+" FQDN — Thales's SM-DP+ product is
deployed per-MNO/per-customer (white-labelled to the operator's own domain, e.g. carrier-branded
FQDNs), so no generic Thales-branded SM-DP+ hostname is publicly documented. `lpa.ds.gsma.com` is
formally a **GSMA**-owned FQDN; Thales is the appointed platform operator per GSMA's own
statements. Thales's own marketing pages (thalesgroup.com) return a bot-detection/JS-required
wall to automated fetches, so several Thales pages that likely discuss the Discovery Service FAQ
in more depth could not be read; findings here rely on osmocom's manual and search-indexed
snippets of Thales's pages, not full page content.

All four addresses above are attributed to Thales because osmocom's manual lists them under
the same TLS key ID (`81370f5125d0b1d408d4c3b232e6d25e795bebfb`). See "Shared/non-provider-specific
SM-DS discovery services" below for the important caveat that these are shared platforms, not
Thales-exclusive infrastructure, and for a fifth, differently-keyed discovery host
(`prod.smds.rsp.goog`) that must NOT be attributed to Thales.

### Shared/non-provider-specific SM-DS discovery services

Unlike SM-DP+ (one operator's infrastructure serves that operator's profiles), the small set of
publicly known SM-DS hosts are **shared discovery platforms that many operators' SM-DP+ instances
register events with** — there is no one-SM-DS-per-provider mapping to fill in for the other 12
providers in this catalog, and the blank "SM-DS: not found" cells for those providers should be
read as "no provider-specific SM-DS exists to find," not as a research gap.

All publicly documented SM-DS hosts found in this research, source
`https://euicc-manual.osmocom.org/docs/rsp/sm-ds/` (fetched and verified directly in this
session):

| host | operator (by TLS key) | role |
|---|---|---|
| `lpa.ds.gsma.com` | Thales | GSMA root/commercial SM-DS |
| `lpa.live.esimdiscovery.com` | Thales | Android production discovery |
| `lpa.live.esimdiscovery.dev` | Thales | Android staging discovery |
| `lpads.vzw.otgeuicc.com` | Thales | Verizon Wireless-specific instance |
| `prod.smds.rsp.goog` | Google (Stork) | Google's own SM-DS, separate key — **not Thales, not GSMA root** |

**Caveat:** an SM-DS holds discoverable profile records for a particular eUICC; it is not
inherently the same service as, or hostname as, any given provider's SM-DP+. A provider not
listed above (i.e. all 12 providers other than Thales) may still have its SM-DP+ register events
with one of these shared SM-DS hosts, or with an undocumented one of its own — that registration
relationship is not publicly observable without either the provider's own documentation or a live
discovery query, neither of which is available offline. Do not fill any other provider's blank
SM-DS cell with `lpa.ds.gsma.com` (or any host above) without a specific source establishing that
provider actually registers events there.

## Valid

### SM-DP+ / SM-DS addresses

| host | type | confidence | source_url |
|---|---|---|---|
| `demo-consumer.validspereachdpplus.com` | SM-DP+ (demo/example) | medium | https://esimqr.com/rsp-provider ; corroborated by Quectel's official EC25/EG21-G eSIM AT Commands Manual, which uses `LPA:1$demo-consumer.validspereachdpplus.com$...` as a real worked example including a live `smdpAddress` field in an ES9+ InitiateAuthentication response — https://forums.quectel.com/uploads/short-url/A4rEKqqtf17nlInpzz8jIhF06GN.pdf |
| `bait.validspereachdpplus.com` | SM-DP+ | low | https://esimqr.com/rsp-provider (single aggregator source, not independently corroborated) |
| `bics.validspereachdpplus.com` | SM-DP+ | low | https://esimqr.com/rsp-provider |
| `firsty.validereachdpplus.com` | SM-DP+ | low | https://esimqr.com/rsp-provider |
| `mobileuc.validereachdpplus.com` | SM-DP+ | low | https://esimqr.com/rsp-provider |
| `viettelvietnam.validspereachdpplus.com` | SM-DP+ | low | https://esimqr.com/rsp-provider |
| `validereachdpplus.com` (base domain) | SM-DP+ infrastructure domain | medium | WHOIS registrant contact is `darren.boyaram@valid.com` — https://website.informer.com/validereachdpplus.com — corroborating that Valid (valid.com) owns this domain, independent of the esimqr.com listing |
| (none found) | SM-DS | not found | — |

Valid runs its RSP infrastructure on two separate, non-`valid.com` domains
(`validspereachdpplus.com` and `validereachdpplus.com`) rather than under its corporate domain.
Certificate-transparency search of `valid.com` itself (via certspotter) turned up no `smdp`/`rsp`
subdomains, consistent with this. Only the `demo-consumer.validspereachdpplus.com` entry has
second-party technical corroboration (Quectel's module manual); the other five hostnames come
from a single unverified third-party aggregator (esimqr.com) and are recorded at low confidence.

## Watchdata

### SM-DP+ / SM-DS addresses

| host | type | confidence | source_url |
|---|---|---|---|
| (none found) | SM-DP+ | not found | — |
| (none found) | SM-DS | not found | — |

Extensive search (vendor product/press pages, osmocom manual, certificate-transparency logs
for `watchdata.com` and `watchdata.com.cn` via certspotter, GitHub/forum activation-code searches)
turned up no publicly documented SM-DP+ or SM-DS FQDN for Watchdata. CT logs for `watchdata.com`
and `watchdata.com.cn` show only corporate/portal subdomains (`bpm.watchdata.com`,
`arkclaw.watchdata.com`, `up.watchdata.com.cn`, etc.) — none resembling `smdp`/`rsp`/`lpa` naming.
Watchdata's own pages confirm it operates a GSMA SAS-SM-certified eSIM management platform and an
SGP.32 eIM (Paris site) but do not publish the platform's FQDN.

## Workz

### SM-DP+ / SM-DS addresses

| host | type | confidence | source_url |
|---|---|---|---|
| (none found) | SM-DP+ | not found | — |
| (none found) | SM-DS | not found | — |

No SM-DP+ or SM-DS FQDN found in Workz's public product pages, technical data sheets, the
osmocom manual, esimqr.com's aggregator list, or certificate-transparency logs for `workz.com`
(via certspotter). CT logs for `workz.com` show only corporate/marketing subdomains and one
SGP.32-suggestive host, `eim-dev.workz.com` (eIM = eSIM IoT remote manager, a different RSP role
than SM-DP+/SM-DS), which is not itself an SM-DP+ or SM-DS address and is noted only as a data
point, not recorded as a found address.
