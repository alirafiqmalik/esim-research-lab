# Other Free Production-CI eSIM Activation Codes

Goal: find free, no-signup activation codes signed by a production GSMA CI, downloadable
to our production eUICC to exercise the RSP protocol. Excludes BetterRoaming/Truphone,
GSMA TS.48, and Google/AOSP (covered by other agents).

Device recap: rooted Pixel 7a, internal eUICC, EID
`89033023427100000000027143866816`, OpenEUICC LPA. The eUICC trusts only production
GSMA CI `81370F5125D0B1D408D4C3B232E6D25E795BEBFB`. Production-CI codes install fully.
Our prior success: `LPA:1$rsp.truphone.com$QRF-BETTERROAMING-PMRDGIR2EARDEIT5`.

## Ranked candidates

Most useful first. "Reusable" means downloadable any number of times to any EID.

| Rank | Activation string | SM-DP+ host | CI vendor | Reusable? | Signup? |
|---|---|---|---|---|---|
| 1 | `LPA:1$rsp-eu.redteamobile.com$5901981126831169` | rsp-eu.redteamobile.com | RedteaGO (production GSMA Live CI; vendor not publicly disclosed) | Reusable, not EID-locked | None |
| 2 | `LPA:1$rsp.truphone.com$QRF-SPEEDTEST` | rsp.truphone.com | Speedtest profile on Truphone SM-DP+ (production CI) | Reusable | None |
| 3 | GigSky free 100MB tier | (in confirmation page after order) | Production commercial CI | One-time per order, EID-locked | Free account, no card |
| 4 | Nomad / Gohub / Eskimo / Firsty free tier | (in order email/dashboard) | Production commercial CI | One-time per order, EID-locked | Free account, no card |

## 1. Codes from the osmocom euicc-manual (no signup, reusable)

The osmocom "Known Test Profiles" page lists production GSMA Live CI profiles that anyone
can download repeatedly to any eUICC. These need no account and no payment.

Excluding the BetterRoaming/Truphone entries, the page yields:

- **RedteaGO** — `LPA:1$rsp-eu.redteamobile.com$5901981126831169`
  - Different SM-DP+ operator from Truphone. This is the prime new candidate.
  - SM-DP+ host: `rsp-eu.redteamobile.com` (Redtea Mobile's RSP platform).
  - Reusable, not EID-locked. Downloadable any number of times to any eUICC.
  - CI vendor: the page classifies it as "GSMA Live CI" (production). The exact CI vendor
    (Idemia / G+D / Kigen / Thales) is not stated publicly. Read the SM-DP+ certificate
    chain during the RSP exchange to identify the issuer.

- **Speedtest** — `LPA:1$rsp.truphone.com$QRF-SPEEDTEST`
  - Same SM-DP+ host as the excluded Truphone codes, but a different profile/operator.
  - Reusable, production CI. Useful as a second profile on the Truphone host, less useful
    if the goal is a different SM-DP+ implementation.

You will not know the K/OPc material, so these profiles only attach on the real
commercial MNO behind them. That does not matter for RSP-protocol testing — the download
and install succeed against the production CI.

### Other hosts seen but with no reusable code

The lpac `USAGE.md` notification sample data references two more production SM-DP+ hosts,
but with no published reusable matchingID:

- `rsp-eu.redteamobile.com` (same as above).
- `cust-005-v4-prod-atl2.gdsb.net` — the `gdsb.net` domain is Giesecke+Devrient (G+D).
  This confirms a G+D production SM-DP+ exists and signs under a Live CI, but no free
  reusable activation code is published. Obtaining one needs a profile order from a
  G+D-backed operator.

## 2. Free-trial commercial eSIMs that expose a raw activation code

These are production commercial providers. Each profile installs against a production CI,
so our eUICC accepts it. The catch: codes are one-time and EID-locked, and you must create
a free account to receive the SM-DP+ host plus matchingID. None published a static code.

All of these let you install manually (enter SM-DP+ address + activation code), so the app
is not required once you have the strings — copy them from the confirmation email or
dashboard into OpenEUICC.

- **GigSky** — free 100MB tier, no credit card. Create a GigSky account (email). The
  web-purchase flow shows "Enter Details Manually" with the SM-DP+ Address and Activation
  Code. Copy both into OpenEUICC. The SM-DP+ host reveals the CI vendor.
- **Nomad** — free tier (up to ~1GB / 3 days in some regions). Free account. SM-DP+
  address and activation code appear in the order confirmation and dashboard.
- **Gohub** — free 300MB / 1 day across Asian destinations, no card. Free account.
- **Eskimo, Firsty, SimLocal** — free base tiers, no card per 2026 trial roundups. Free
  account. Confirm each exposes a manual SM-DP+ + code (most do).

Airalo discontinued its open free trial in 2025; no public free tier as of 2026.

### Steps for the minimal-signup providers

1. Create a free account with email (no card).
2. Claim the free plan.
3. Open the install instructions and choose manual / "Enter Details Manually".
4. Copy the SM-DP+ Address and Activation Code.
5. Build `LPA:1$<host>$<activation-code>` and enter it in OpenEUICC.

The main session or human performs the signup. This report only maps the path.

## 3. One-time / EID-locked vs reusable

- Reusable, not EID-locked: the osmocom RedteaGO and Speedtest codes. Best for repeat
  testing — download, delete, download again, any number of times.
- One-time, EID-locked: every commercial free-trial code (GigSky, Nomad, Gohub, Eskimo,
  Firsty). The SM-DP+ binds the matchingID to your EID on first download and burns it.
  Good for a single end-to-end run per order; not for repeated downloads.

## Recommendation

Try first, verbatim, no signup, reusable, production CI:

1. `LPA:1$rsp-eu.redteamobile.com$5901981126831169` (RedteaGO — different SM-DP+ operator,
   the highest-value new target).
2. `LPA:1$rsp.truphone.com$QRF-SPEEDTEST` (different profile, Truphone host).

Need a free signup (no card), one-time EID-locked, but a genuinely different SM-DP+
implementation and CI vendor: GigSky, then Nomad. Use these when you want to fingerprint a
non-Truphone, non-Redtea production SM-DP+. Read the SM-DP+ certificate chain during the
exchange to record the CI vendor for each.

## Sources

- [osmocom euicc-manual — Known Test Profiles](https://euicc-manual.osmocom.org/docs/rsp/known-test-profile/)
- [lpac USAGE.md](https://github.com/estkme-group/lpac/blob/main/docs/USAGE.md)
- [Redtea Mobile — RSP / SM-DP+ platform](https://www.redteamobile.com/technology-rsp/)
- [GigSky — free offering](https://www.gigsky.com/free-offering)
- [GigSky — install with activation code (manual)](https://support.gigsky.com/hc/en-us/articles/13093309836178-GigSky-eSIM-web-purchase-Installing-and-activating-with-an-Activation-code)
- [Nomad — what is an SM-DP+ address (manual install)](https://www.nomadesim.com/blog/what-is-sm-dp-address)
- [Gohub — best free eSIM trials 2026](https://gohub.com/blog/best-free-esim-trials-no-credit-card)
- [Security Explorations — eSIM security (production RSP servers, IDEMIA/Thales)](https://security-explorations.com/esim-security.html)
- [osmocom euicc-manual — EUMs](https://euicc-manual.osmocom.org/docs/pki/eum/)
