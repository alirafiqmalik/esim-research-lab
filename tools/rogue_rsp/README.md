# Rogue SM-DS (ES11) fuzzer

A local HTTPS SM-DS that serves crafted/fuzzed SGP.22 **ES11** discovery responses
to the eUICC/LPA under test. It probes two gates:

1. The eUICC's `AuthenticateServer` CI-trust check against a rogue SM-DS cert.
2. OpenEUICC's ES11 discovery / event-record parsing.

Build, unit tests, and this TLS plan only. No live device run until the safety
review + the TLS-trust step below are done.

## Files

- `smds_server.py` — HTTPS server for the two ES11 endpoints the LPA calls.
- `rsp_certs.py` — attacker ECDSA P-256 key + SGP.22 server cert + challenge-bound
  `serverSigned1` signing.
- `es11_fuzz.py` — the response fuzzer (three mutation classes).
- `run_smds_fuzz.py` — orchestrator (dry-run now; live is gated).
- `tests/` — mock unit tests, no device, no real network.

## ES11 message structure

Verified against `lpac/euicc/es9p.c` (`es9p_initiate_authentication_r`,
`es11_authenticate_client_r`) and the real capture in
`.sessions/betterroaming-live-rsp-20260629/handshake_capture.txt`.

`POST /gsma/rsp2/es9plus/initiateAuthentication`

```
req  {"smdpAddress", "euiccChallenge"<b64>, "euiccInfo1"<b64>}
resp {"header":{"functionExecutionStatus":{"status":"Executed-Success"}},
      "transactionId", "serverSigned1"<b64>, "serverSignature1"<b64>,
      "euiccCiPKIdToBeUsed"<b64>, "serverCertificate"<b64>}
```

`POST /gsma/rsp2/es9plus/authenticateClient` (ES11 form)

```
req  {"transactionId", "authenticateServerResponse"<b64>}
resp {"header":{...}, "eventEntries":[{"rspServerAddress", "eventId"}, ...]}
```

Base64-decoded TLV shapes (from the capture):

- `serverSigned1`     `30 { 80 <txid>  81 <euiccChallenge>  83 <serverAddress>  84 <serverChallenge> }`
- `serverSignature1`  `5F 37 40 <64-byte ECDSA r||s>`
- `euiccCiPKIdToBeUsed` `04 14 <20-byte CI SKI>`
- `serverCertificate` X.509 DER (`30 82 ..`)

lpac reads only `rspServerAddress` from each event entry
(`es11_authenticate_client_r`).

## Fuzz mutation classes

- `ci_trust` — well-formed, crypto-valid, challenge-bound, but the cert does not
  chain to a GSMA CI (`ci_untrusted_ci_signed`, `ci_self_signed`) or
  `euiccCiPKIdToBeUsed` is forged to the production CI (`ci_forged_pkid`).
  Expected: eUICC REJECT at the CI-trust gate. **ACCEPT = CI-trust bypass =
  CRITICAL.**
- `parser` — malformed ASN.1/BER in `serverSigned1` / `serverCertificate` (over-
  and under-declared lengths, truncation, unexpected private-class tag, 64-deep
  nesting, 8 KiB field), plus event-list attacks (5000 records, wrong JSON types,
  64 KiB address). Expected: clean LPA parser reject. Crash / hang / anomaly =
  candidate app bug.
- `binding` — valid untrusted-CI response with a stale challenge or a mismatched
  transactionId. Expected: eUICC REJECT at the binding check.

## TLS-trust plan

**OpenEUICC pins RSP TLS to the GSMA CI keystore — NOT the system store.**

`HttpInterfaceImpl.usePublicKeyIds` builds a PKIX `TrustManager` from
`keyIdToKeystore(pkids)` (`RootCertificates.kt`), a keystore holding only the GSMA
CI roots (RSP2 Root CI1 + OISITE), and always at least RSP2 Root CI1. So:

- The mitmproxy / research CA that `setup_capture_pixel7a.sh` installs into the
  conscrypt APEX store does **nothing** for OpenEUICC RSP TLS. That store is not
  consulted on this path.
- Frida unpinning (`scripts/frida/`) would work but is not needed here.

**Least-invasive path (recommended): the built-in developer toggle.**

`HttpInterfaceImpl.getSocketFactory` swaps in `AllowAllTrustManager()` when the
`ignore_tls_certificate` preference is set (`PreferenceKeys.IGNORE_TLS_CERTIFICATE`,
surfaced as the `pref_developer_ignore_tls_certificate` checkbox). We build
OpenEUICC ourselves, so enable that developer setting on the test build. The LPA
then accepts the rogue server's self-signed TLS cert (for `127.0.0.1`, generated
by `run_smds_fuzz.write_tls_cert`). No Frida, no CA install, no code change.

- Recommendation: **enable `ignore_tls_certificate`**. It is a shipped toggle, not
  a patch.
- This bypasses only TLS (the transport wall). It does NOT touch the eUICC's
  in-SE `AuthenticateServer` CI-trust check — which is the gate under test and
  must still REJECT the rogue cert.

### What the live phase needs (before `--live`)

1. Human safety review of this module.
2. Enable `ignore_tls_certificate` on the OpenEUICC test build.
3. Reach `127.0.0.1:PORT` from the device — either run the server on-device via
   the same host, or `adb reverse tcp:PORT tcp:PORT` so the phone's `127.0.0.1`
   maps to the host server.

## Running

```
# unit tests (no device, no network)
cd tools/rogue_rsp && python3 -m pytest -q

# offline dry-run: build every mutation's response body for review
python3 tools/rogue_rsp/run_smds_fuzz.py --session-dir .sessions/rogue-smds-dryrun

# live (GATED — refused without the safety-review flag)
python3 tools/rogue_rsp/run_smds_fuzz.py --live --i-have-safety-review
```

Planned live discovery command per iteration:

```
esim euicc discovery --smds 127.0.0.1:PORT
```

## Safety

- Discovery returns event-record **pointers**, not profiles. It installs nothing.
- This module never proceeds past discovery to a download/install. No eUICC writes.
- The eUICC CI-trust gate must REJECT the rogue SM-DS cert. If it ACCEPTS, the
  orchestrator stops and flags CRITICAL.
- Parser fuzzing is app-level. An OpenEUICC crash is recoverable, no card damage.
- The live phase must snapshot `esim euicc list` before/after and preserve
  profile #1.
