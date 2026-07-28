# Round 4 (final) — spec-grounded facts (SGP.22 v3.1)

## Q13 — EID-binding norm: D1/D2 confused-deputy is UNIVERSAL to Activation-Code deployments, not an edge case
Table 6a (ES2+.DownloadOrder/ConfirmOrder input data), per use-case:
```
                   Default SM-DP+   Activation Code   SM-DS
DownloadOrder eid:      O                 O             O
ConfirmOrder  eid:     C(2)               O            C(2)
```
For **Activation Code** (the dominant consumer flow: buy online/in-store, scan a QR code on whatever device),
`eid` is Optional at BOTH DownloadOrder and ConfirmOrder. EID is only conditionally-mandatory for the
Default-SM-DP+ and SM-DS use cases specifically (structural need for SOME routing key), not because GSMA
treats EID-pinning as the security default generally. Narrative confirms this is deliberate: "The EID is
optional and MAY not be known at this stage" (§5.3.1); Annex F Figure 41 diagrams EID-known and EID-unknown
as two CO-EQUAL, parallel, spec-drawn branches ("Bind MatchingID-ICCID-EID" vs "Bind MatchingID-ICCID"), not
a degraded path. §3.1.3.1 step 3's EID check is explicitly conditional ("If this order is already linked to
an EID, verify..."). When it wasn't bound (the Activation-Code-optional path): **no EID check exists anywhere
in the download claim procedure.** No SHOULD/recommendation language anywhere urges EID-pinning even for AC flows.
**VERDICT: D1/D2's confused-deputy exposure is REAL-GAP: UNIVERSAL for Activation-Code deployments** (the
single most common consumer flow) — not a misconfiguration or unusual edge case, but the natural, spec-permitted
consequence of a field GSMA made Optional for this exact use case. Upgrades severity framing from "contingent
on deployment choice" to "structural to the dominant real-world flow."

## Q14 — D3 profileMetadata gap: GSMA-acknowledged risk category, undocumented severity asymmetry
§3.1.3.2 step 12 (after BPP download, LPAd reconciles the two metadata copies):
- **SHALL** (mandatory, mandatory-abort-on-failure): verify Profile Policy Rules + Enterprise Configuration
  haven't changed between consent-time and BPP-time copies; on mismatch, SHALL CancelSession
  (`pprNotAllowed`/`metadataMismatch`).
- **SHOULD/MAY** (recommended-to-check, fully discretionary response): verify "other" elements -- **Profile
  Name, Icon, etc. -- the exact user-facing branding fields consent decisions actually hinge on.** A
  conformant LPA MAY skip this check entirely for ProfileName/ServiceProviderName/Icon and remain compliant.
There IS a named `CancelSessionReason.metadataMismatch` and a dedicated procedure step -- this is NOT an
unremarked ASN.1 consequence; GSMA anticipated metadata divergence generally. But NO annex/note anywhere
(checked full Annex list A-Q; no security/threat annex exists in SGP.22) explains or justifies WHY policy
fields get SHALL-level protection while the exact fields a user reads to judge "is this really my carrier?"
get only SHOULD/MAY. Also unaddressed: consent happens at AuthenticateClient response time, BEFORE step 12's
reconciliation ever runs against the BPP copy -- the user may have already consented off the since-superseded
first copy regardless of what step 12 later finds.
**VERDICT: D3 is a HYBRID finding.** Report as: "GSMA-acknowledged risk category (named cancel reason +
dedicated procedure step) with an intentionally partial, undocumented-as-such mitigation gap specifically on
the consumer-trust-relevant display fields" -- neither "novel undiscovered gap" nor "already fully addressed."

## Testbed gap surfaced by Q14
Our lpa.py implements NO step-12-style reconciliation at all (neither the SHALL-level PPR/EnterpriseConfig
check nor the SHOULD-level display-field check) -- our D3 test demonstrates the WORST-CASE-conformant LPA
behavior (skip the SHOULD check entirely, which is spec-legal) rather than a maximally-conformant one that
still does the mandatory PPR check. This doesn't invalidate the D3 REAL-GAP (profileName/SPN/icon divergence
is legally unchecked either way per Q14), but is worth one report caveat: our test doesn't yet demonstrate
that a maximally-conformant LPA (SHALL-level PPR check active) would still catch a PPR/EnterpriseConfig swap
even while missing a ProfileName swap. Documented as backlog; not implemented given remaining time.

## Session close
Spec-verifier signed off after this round ("four genuinely productive rounds... good luck closing out the
report"). No round 5 planned unless a new question surfaces during report compilation.
