# Step 3 — ES9+ / ES11 API Request Catalog

Scope: every request an LPA/device is entitled to send to an SM-DP+ (ES9+) or
SM-DS (ES11) server under SGP.22. Grounded in two sources:

1. `testbed/ecosim/` — this repo's local SGP.22 simulation (`codec.py`,
   `smdp.py`, `smds.py`, `lpa.py`). Read directly; not web-sourced.
2. Public secondary sources for the real HTTP wire shape ecosim does not model
   (ecosim represents ES9+/ES11 as JSON dicts exchanged in-process — it does not
   run an HTTP server or use the GSMA JSON field names as the ASN.1-derived
   single-blob fields real deployments use). Sources: osmocom `pySim.esim.es9p`
   module (GitHub `osmocom/pysim`, `pySim/esim/es9p.py`), osmocom
   euicc-manual SM-DP+/SM-DS pages, GSMA SGP.22 spec PDFs (section numbers
   below are the ones already cited elsewhere in this repo's `ecosim` code
   comments, e.g. `codec.py`, `smdp.py`, `euicc.py` — reused here, not
   re-derived).

Every ES9+/ES11 HTTP call in reality carries a `header` object
(`functionRequesterIdentifier`, `functionCallIdentifier`) on the request and
`header.functionExecutionStatus.status` (`Executed-Success` / `Failed`) on the
response, plus HTTP headers `Content-Type: application/json` and
(commonly, per public LPA implementations) `User-Agent`/`X-Admin-Protocol`
identifying the RSP version. ecosim does not model this envelope — it passes
bare function-parameter dicts. `src/envelope.py` (Step 4) adds the envelope
back for the request-builder library so the wire shape matches reality.

## ES9+ (LPA <-> SM-DP+)

| # | Function | HTTP method + path | Required inputs | Response (key fields) | ecosim analog |
|---|---|---|---|---|---|
| 1 | InitiateAuthentication | `POST /gsma/rsp2/es9plus/initiateAuthentication` | `euiccChallenge` (b64), `euiccInfo1` (b64 TLV), `smdpAddress` (string) | `transactionId`, `serverSigned1`, `serverSignature1`, `euiccCiPKIdToBeUsed`, `serverCertificate` | `smdp.SmDpPlus.initiate_authentication` |
| 2 | AuthenticateClient | `POST /gsma/rsp2/es9plus/authenticateClient` | Real: `transactionId`, `authenticateServerResponse` (single b64 ASN.1 blob). ecosim simplification: `transactionId`, `euiccSigned1`, `euiccSignature1`, `euiccCertificate`, `eumCertificate`, `euiccOtpk` as separate b64 fields | `transactionId`, `profileMetadata`, `smdpSigned2`, `smdpSignature2`, `smdpCertificate` (ecosim: `smdpPbCertificate`) | `smdp.SmDpPlus.authenticate_client` |
| 3 | GetBoundProfilePackage | `POST /gsma/rsp2/es9plus/getBoundProfilePackage` | Real: `transactionId`, `prepareDownloadResponse`. ecosim simplification: `transactionId` only (no separate PrepareDownload step) | Real: `transactionId`, `boundProfilePackage` (single b64 ASN.1 blob). ecosim: `transactionId`, `serverOtpk`, `sealedProfile`, `metadataPreview` (decomposed) | `smdp.SmDpPlus.get_bound_profile_package` |
| 4 | HandleNotification | `POST /gsma/rsp2/es9plus/handleNotification` | Real: `pendingNotification` (single b64 blob: `ProfileInstallationResult` or `OtherSignedNotification`). ecosim: `notification`, `seq`, `euiccCertificate` (decomposed) | HTTP 204 / empty body | `smdp.SmDpPlus.handle_notification` |
| 5 | CancelSession | `POST /gsma/rsp2/es9plus/cancelSession` | `transactionId`, `cancelSessionResponse` (b64, carries a reason code) | HTTP 204 / empty body | **not modeled in ecosim** — included here for catalog completeness; `scripts/` Step 4 builds the request shape but there is no local target to validate the response against |

## ES11 (LPA <-> SM-DS, discovery)

SGP.22 has the SM-DS reuse the ES9+ message set for the authentication
handshake (same two functions, same JSON shapes) — this repo's own research
(`docs/research/research-repeatable-esim-issuer.md`, citing
`euicc-manual.osmocom.org`) documents the same `/gsma/rsp2/es9plus/...` path
prefix pattern; treat the SM-DS-hosted path as **inferred by analogy, medium
confidence**, not independently confirmed per-provider.

| # | Function | HTTP method + path | Required inputs | Response (key fields) | ecosim analog |
|---|---|---|---|---|---|
| 6 | ES11.InitiateAuthentication | `POST /gsma/rsp2/es9plus/initiateAuthentication` (on the SM-DS FQDN) | Same shape as ES9+ #1, but `smdpAddress` is omitted/irrelevant (talking to the SM-DS itself) | Same shape as ES9+ #1 | **not modeled** — ecosim's `smds.py` skips straight to discovery (see module docstring: discovery is unauthenticated by design in the real protocol too, at this pre-auth stage) |
| 7 | ES11.AuthenticateClient (discovery) | `POST /gsma/rsp2/es9plus/authenticateClient` (on the SM-DS FQDN) | Same envelope shape as ES9+ #2 | `eventEntries`: list of `{eventId (b64), rspServerAddress (FQDN string)}` | `smds.SmDs.discover(eid) -> list[EventRecord(event_id, smdp_address)]` — ecosim collapses functions #6+#7 into one `discover(eid)` call taking the EID directly, deliberately, to test whether the pre-auth EID-keyed lookup is an enumeration primitive (see `smds.py` docstring) |

## ES12 (SM-DP+ <-> SM-DS, RegisterEvent) — out of scope for a device/LPA client

`ES12.RegisterEvent` is server-to-server (the SM-DP+ tells the SM-DS a profile
is waiting for an EID); a device never calls it. Listed only because ecosim
models it (`smds.SmDs.register_event`, called by the SM-DP+ side) and because
it explains how SM-DS state in #7 gets populated. Not carried into Step 4/5
scripts — those only build requests a device is entitled to send.

## Usage conditions (safe cadence)

General pattern that holds across all functions above:

- `transactionId` is single-use, minted fresh by `InitiateAuthentication`.
  SGP.22 SS3.1.3 (Common Mutual Authentication Procedure) ties every
  subsequent ES9+ call in a download session to that one `transactionId` —
  a compliant client does not retry a failed step by reusing an old
  `transactionId`; it starts over from `InitiateAuthentication`, which is
  itself a new, chargeable-to-rate-limit request.
- `HandleNotification` delivery (function #4) is retried by the LPA only for
  as long as the eUICC still lists the notification as pending
  (`ES10b.ListNotification` / removal on ack, SGP.22 SS5.7.15) — cadence is
  event-driven (per pending notification), not a fixed poll interval.
- SGP.22 does not define a numeric HTTP rate limit, timeout value, or retry
  count for any ES9+/ES11 function. Those are operator/deployment policy.

## Catalog size

7 functions cataloged across 2 interfaces (5 ES9+, 2 ES11) that a device/LPA
may call, plus 1 server-to-server function (ES12.RegisterEvent) noted for
context only. Machine-readable form: `analysis/api-catalog.jsonl` (8 lines,
one per function including ES12).
