# Round 2 — spec-grounded facts (SGP.22 v3.1)

## D4 — SM-DP+ address/identity binding · §3.0.1 steps 8/10, §4.5.2.1.0.4-5
serverAddress lives INSIDE serverSigned1 (tamper-evident once signed) but is self-asserted by whichever
server answers. OID binding via subjectAltName.registeredID is CONDITIONAL (only checked "if its OID was
provided earlier"). No serverAddressMismatch/serverOidMismatch reason code shipped in the final
CancelSessionReason enum (only in changelog, dropped from normative v3.1). eUICC itself never checks
serverAddress at all. REAL-GAP: because the AC (D1) has zero integrity, an attacker who controls the AC/QR
can point the LPAd at a DIFFERENT but still validly CI-issued SM-DP+; every downstream check passes because
LPAd compares the attacker's dialed address against that same attacker's self-reported address. Only anchor
is ordinary TLS hostname validation against CERT.DP.TLS for the FQDN actually dialed — useless if that FQDN
was itself attacker-supplied via the AC. => "rogue-but-CI-valid SM-DP+ substitution via AC tampering" is real
attack surface, not a modeling artifact.

## D5 — ProfileInstallationResult IS SIGNED · §2.5.6 (pp.51-52)
```
ProfileInstallationResult ::= [55] SEQUENCE { -- BF37
  profileInstallationResultData [39] ProfileInstallationResultData,  -- BF27
  euiccSignPIR EuiccSign }                                            -- 5F37, signed with SK.EUICC.SIG
ProfileInstallationResultData ::= [39] SEQUENCE {
  transactionId [0], notificationMetadata [47] NotificationMetadata, smdpOid OID, finalResult [2] CHOICE }
NotificationMetadata ::= [47] SEQUENCE { seqNumber [0] INTEGER, profileManagementOperation [1], notificationAddress, iccid OPTIONAL }
```
**seqNumber and finalResult are INSIDE the signed envelope.** Nothing here is unsigned (unlike euiccCiPKIdToBeUsed
or consent-time profileMetadata). VERDICT (verifier, explicit): our current UNSIGNED ProfileInstallResult with a
mutable seq/status is modeling something materially WEAKER than the real spec. Round-0 findings
"C3 BF37/81 empty/truncate/type_confusion accepted" MUST be reclassified TESTBED-ARTIFACT, and the fix is to
require euiccSignPIR verification before any seqNumber/finalResult is trusted.

## D6 — top-level "serverOtpk" at InitiateAuthentication time DOES NOT EXIST IN REAL PROTOCOL · §6.6.2.1, §5.5.1
`InitiateAuthenticationOkEs9` has NO key-agreement public key field. Real ECDH sequencing: InitiateAuthentication/
AuthenticateServer/AuthenticateClient = signature-only auth, NO ECDH. eUICC's ECDH keypair (`otSK.EUICC.KA`/
`euiccOtpk`) is generated during PrepareDownload (EUICCSigned2). The SM-DP+'s ECDH pubkey (`smdpOtpk`) first
appears in `InitialiseSecureChannelRequest` (ES8+, tag BF23) — the FIRST COMMAND INSIDE THE BPP, delivered via
ES10b.LoadBoundProfilePackage, authenticated by its own signature `smdpSign` (distinct from serverSignature1
and smdpSignature2). eUICC SHALL verify smdpSign via PK.DPpb.SIG before trusting smdpOtpk (invalidSignature).
VERDICT: our testbed's top-level `serverOtpk` field at InitiateAuthentication time (and its associated round-0
findings "C1 serverOtpk bitflip/type_confusion accepted") is a MODELING ARTIFACT — that message doesn't exist
at that point in the real protocol. Full remodel (PrepareDownload + InitialiseSecureChannel with its own
smdpSign) is a real architectural change; documented as a known limitation, deferred unless time remains.
Round-0 serverOtpk findings RECLASSIFIED ARTIFACT.

## D7 — euiccCiPKIdToBeUsed: confirmed mechanism + real downgrade concern · §5.7.13, §5.6.1 Table36 Note6
Confirmed: empty/omitted -> eUICC SHALL return ciPKUnknown (both values omitted -> ciPKUnknown too); ID naming
an unsupported CI -> ciPKUnknown. euiccCiPKIdToBeUsed selects which of the eUICC's OWN signing-credential sets
to use (curve/cert variant), not which CI verifies the server. It is UNSIGNED at the local ES10b hop; SM-DP+
only catches tampering RETROACTIVELY at AuthenticateClient (chain check against the value). REAL fuzz direction:
a local MITM (LPA/baseband boundary, this project's threat model) can swap the CI-key-ID to force the eUICC to
sign with a different-but-still-supported credential (e.g. different curve per §4.6.1 curve table: P-256 /
BrainpoolP256r1 / FRP256V1) before the SM-DP+'s retroactive check fires.

## D8 — Certificate role separation is spec-mandated and must be checked · §2.4a.1.0, §4.5.2.1.0.2-5, §4.5.2.2, §5.7.13
Role carried via `certificatePolicies` OID (id-rspRole-{ci,ciSubCa,eum,euicc,dp-auth,dp-pb,dp-tls,...}), NOT
just keyUsage. DPauth and DPpb are cryptographically DISTINCT keypairs/certs for the same SM-DP+ (different
subject/serialNumber/policy-OID/pubkey/signature/SKI) — deliberately non-interchangeable. §5.7.13 explicit SHALL:
"Verify that the RSP Server Certificate is either a CERT.DPauth.SIG or a CERT.DSauth.SIG... Otherwise SHALL
return invalidOid." §4.5.2.2: certificate-profile restrictions "SHALL be verified" for all non-TLS chains (TLS
chains get a softer MAY). VERDICT: a conformant eUICC MUST reject a validly-CI-signed-but-wrong-role cert
(e.g. an EUM cert presented in the DPauth slot) with invalidOid, even though it chains correctly. Our testbed's
`authenticate_server` currently only calls `verify_chain(server_cert, ci_cert)` with NO role check — since
pki.eum is ALSO issued directly by pki.ci, an EUM cert would pass our chain check today. This is a TESTBED GAP
(not yet a real-vs-artifact fuzz outcome) that must be fixed before testing D8, or any "wrong-role cert accepted"
result is a TESTBED-ARTIFACT by construction, not a finding about real eUICCs (which are spec-mandated to check).

## Actions taken as a result (lead)
- FIX-Q5: sign ProfileInstallationResult (euiccSignPIR over profileInstallationResultData incl. seqNumber+finalResult);
  add verification before trusting it. Round-0 BF37/81-mutation findings reclassified ARTIFACT with rationale.
- FIX-Q8: add lightweight certificate-role tagging (CN-based, since our PKI doesn't encode real GSMA policy OIDs)
  and enforce role check in authenticate_server (must present a dp_auth-role cert) before testing D8, so a
  "wrong-role accepted" result cannot occur as an artifact of our sim skipping a check the spec mandates.
- FIX-Q6: documented as known architectural limitation (full PrepareDownload/InitialiseSecureChannel remodel is
  out of scope for the remaining window); round-0 serverOtpk findings reclassified ARTIFACT.
- New round-2 test backlog: D4 (rogue-but-CI-valid SM-DP+ substitution), D7 (CI-key-id downgrade), D8 (cert-role
  confusion, post-fix).
