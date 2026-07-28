# Round 3 — spec-grounded facts (SGP.22 v3.1)

## Q9 — PrepareDownload/EUICCSigned2 signature chain + key-generation timing · §5.7.5, §3.1.3.2
Real signature chain: euiccSignature1 (covers euiccSigned1) -> smdpSignature2 (covers smdpSigned2 ‖
euiccSignature1) -> euiccSignature2 (covers euiccSigned2 ‖ smdpSignature2). Each step transitively binds to
every prior one (anti-mix-and-match/replay across the multi-round handshake). Real ordering: PrepareDownload's
own smdpSignature2 verification (DPpb role) SHALL succeed BEFORE the eUICC generates/exposes its ECDH keypair.
Verifier's own test for our model: raw key GENERATION early is cosmetic (no attacker-controlled inputs); early
TRUST COMMITMENT (deriving/using the shared session key) gated only on the DPauth check while skipping an
independent DPpb check would be a real fidelity gap (collapses two intentionally-separate trust boundaries).

**Reconciled against our code (lead review):** our model generates euicc_otsk during authenticate_server
(DPauth-gated) and transmits euiccOtpk to the SM-DP+ at that same step (cosmetic, matches spec's practice of
disclosing euiccCertificate/euiccSigned1 during AuthenticateClient too). But the actual cryptographic
commitment -- protocol.session_key() derivation and AEAD seal/open of the profile -- only happens in
get_bound_profile_package (SM-DP+) / install_bound_profile_package (eUICC), and the LPA's sequence
(lpa.download_profile) calls euicc.verify_smdp_signature2 (DPpb-role, added this session per Q5/D8 fixes)
BEFORE ever calling _get_bound_profile_package. So the trust-boundary-collapse failure mode the verifier
warned about does NOT apply to our current code: DPauth and DPpb are checked independently, and the DPpb
check gates the only step that actually USES the shared secret. Recorded as CONFORMANT/info -- no new fix needed.

## Q10 — EID: format, check-digit, and unauthenticated local exposure · §4.3.1, §5.7.20, SGP.29 §7-9
EID = 32 decimal digits (EIN + ESIN + 2 mod-97 check digits, ISO-7812-style). **EID is never a field in
EUICCInfo1/2** (checked directly, neither ASN.1 structure has it). Two places it appears:
1. `ES10c.GetEID` -> `GetEuiccDataResponse ::= [62] SEQUENCE { eidValue [APPLICATION 26] Octet16 }` --
   RAW, UNSIGNED, UNENCRYPTED local APDU response. Zero cryptographic protection at this hop.
2. `CERT.EUICC.SIG.subject.serialNumber` -- only trustworthy once a relying party (the SM-DP+/SM-DS per
   §3.0.1 step 16, NOT explicitly the LPAd) validates the full chain to CI.
No SHALL-clause requires the LPA/SM-DP+ to validate the mod-97 check digit before using an EID operationally
(it's an input-error detector, not a security control). REAL-GAP: a local MITM on the LPA<->eUICC bus (this
project's exact threat model) can read OR SPOOF the plaintext GetEID response with zero built-in protection --
device impersonation/enumeration against anything trusting an LPA-reported EID without independently
cross-checking the CERT.EUICC.SIG-embedded copy (which requires a full RSP session, not just GetEID).

## Q11 — Notification/HandleNotification confidentiality: signed-only, validates our model · §2.5.6, §5.6.4, §2.6.6
Confirmed: BF37/BF27 (ProfileInstallationResult) is plaintext-but-signed at the RSP application layer, BY
DESIGN, not omission. Local ES10b hop (eUICC->LPA) has NO transport protection defined at all (unconditionally
plaintext-readable). Network ES9+ hop (LPA->SM-DP+) gets confidentiality ONLY from mandatory TLS (§2.6.6, TLS
1.2+) layered on top -- if that TLS is absent/broken, the same "readable but not forgeable" property holds.
**This directly validates our Q5 fix**: representing BF37/BF27 as plaintext-but-signed (not encrypted) is
faithful to spec, not a simplification needing further work.

## Q12 — CRL stapling: mandatory-to-implement but conditionally-used; real deployed gap · §5.7.13, §2.7, Annex M
Declaring CRL-stapling SUPPORT (`crlStaplingV3Support` bit) is mandatory for v3.1 conformance (eUICC/LPA/
SM-DP+/SM-DS all). Actual per-session CHECKING only fires if the peer asserts `crlStaplingV3Used` (a runtime
flag) AND supplies a valid crlList. v3.1-conformant eUICCs are explicitly required to stay interoperable with
pre-v3.0 servers with NO CRL-stapling concept at all (Annex M lowestSvn=v2.1.0). The eUICC has no independent
network path to fetch CRLs -- structurally dependent on a peer "stapling" (pushing) revocation data.
VERDICT: "no revocation checking" is a REAL, currently-deployed gap (not a universal v3.1 requirement gap) --
most realistic framed as (a) a pre-v3.0 entity, or (b) an active capability-bit-stripping/crlList-suppression
downgrade attack against a v3.1 entity (the eUICC can't tell genuine unavailability from deliberate withholding).
NOT MODELED in our testbed (no CRL/capability-bit machinery at all) -- documented as a backlog item, not
implemented this session given the time budget.

## Actions taken as a result (lead)
- Q9: reviewed our actual code against the verifier's own criterion; confirmed CONFORMANT (DPauth and DPpb
  checks are independently gated; the DPpb check -- verify_smdp_signature2, already added for Q5/D8 -- runs
  before the only step that uses the shared secret). No fix needed; recorded as a clarifying finding.
- Q10: NEW real gap, not yet modeled. Adding ES10c.GetEID to dispatch_apdu (plaintext, unsigned, matching
  spec exactly) and a C2b/C3 spoofing test, since it's a small, self-contained, high-value addition.
- Q11: validates the Q5 fix; no action needed.
- Q12: documented as backlog (CRL/capability-bit downgrade modeling out of scope for the remaining window).
