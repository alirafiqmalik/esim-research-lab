# IMEI / deviceInfo Threat Model

Scope: what the IMEI leak in `ctxParams1.deviceInfo` actually exposes, and whether
a fake SM-DP+ or a network MITM can harvest it. Grounded in this session's live
captures on a rooted Pixel 7a (OpenEUICC + `lpac`) and the repo's TLS-pinning and
RSP-flow notes.

## What the session proved

- The full 15-digit IMEI rides inside `ctxParams1.deviceInfo` (SGP.22 §5.7.13).
- `deviceInfo` has two fields: `tac [80]` (4 bytes, device model) and `imei [82]`
  (8 bytes, the whole IMEI, BCD-swapped). Both were populated when supplied.
- The IMEI is signed by the eUICC (integrity) but not encrypted at the application
  layer. It sat in cleartext in `lpac`'s HTTP tx body, before TLS.
- No SM-DP+ tested (Truphone/1GLOBAL, Redtea) validated it. A junk TAC installed
  fine. A "blacklisted" IMEI installed fine.
- A rejected download still transmits it. The eUICC-signed blob is POSTed before
  the server refuses, so the IMEI leaks even when no profile is delivered.
- `lpac` omits `imei` by default and sends the placeholder TAC `35290611`. The real
  IMEI leaks only when the LPA populates the field.

## The ordering that governs everything

SGP.22 §3.1.3 (Common Mutual Authentication) fixes the sequence. `deviceInfo` is
built and signed only after the server proves itself:

```
1. InitiateAuthentication   LPA -> server   euiccChallenge + euiccInfo1   (no IMEI)
2. AuthenticateServer (ES10b)  eUICC verifies CERT.DPauth chains to a GSMA CI root
                               -- gate. Fails here => no deviceInfo is ever built.
3. eUICC signs euiccSigned1(ctxParams1.deviceInfo)   <- IMEI first exists here
4. AuthenticateClient       LPA -> server   POSTs that signed blob (carries IMEI)
```

The eUICC never produces the IMEI-bearing blob until step 2 passes. This single
fact answers Q2 and shapes Q3.

## Q1 — Why the leak matters against an honest SM-DP+

The IMEI is unnecessary for the protocol and permanent for the device. That
combination is the problem.

- Authentication is EID- and certificate-based. The IMEI authenticates nothing.
  The session proved it: an invalid IMEI still installs. The field carries no
  security value, so its only effect is disclosure.
- The IMEI is a lifelong hardware identifier. The EID identifies the eUICC and the
  IMSI identifies the subscription. The IMEI identifies the physical handset across
  every profile, carrier, and SIM it ever holds.
- The SM-DP+ now holds a binding: `IMEI <-> EID <-> matchingId/profile <-> subscription`.
  That links the hardware to a named subscriber account.

Concrete exposure, no compromise required:

- Cross-profile linkage. A user who rotates eSIMs for privacy is defeated. The IMEI
  is constant across all of them, so the backend sees one device behind every
  profile.
- Cross-carrier correlation. One SM-DP+ vendor serves many carriers (the
  server-addresses note shows many MVNOs on shared `idemia.io` and
  `gieseckedevrient.com` instances). That vendor sees the same IMEI download for
  carrier A and carrier B and links both subscriptions to one handset.
- Breach. A leaked SM-DP+ database exposes `IMEI + EID + profile + timestamp` —
  a device-tracking and stolen-device-correlation dataset.
- Data sharing and lawful intercept. The IMEI is a standard intercept selector.
  Handing it to the RSP backend widens who can map a device to its subscriptions
  and provisioning times.

Gradation matters. `tac` (device model) is mandatory in `DeviceInfo` and leaks
always. `imei` (the unique handset) is optional. The model is a fingerprint; the
full IMEI is an identity.

Proven vs inferred: we proved `lpac` omits `imei` unless supplied. We did not test
what the stock Google LPA sends. Commercial LPAs are expected to populate the real
`tac` always and may include the real `imei` per operator policy. The Q1 analysis
applies wherever the LPA populates the field.

## Q2 — Can a fake / unauthenticated SM-DP+ harvest the IMEI?

No, not a naive one. The eUICC verifies `CERT.DPauth` against the GSMA CI roots at
`AuthenticateServer` (step 2) before it signs `deviceInfo` (step 3). A server that
cannot present a valid CI-chained certificate is rejected there. In our harness
that is `authRc -3` (`authenticateServer_rejected`) — the flow stops before the
IMEI exists.

What an attacker would actually need: a valid `CERT.DPauth` that chains to a GSMA
CI root — an accredited SM-DP+ certificate (or a stolen/compromised one). That is
the real bar, and it is high. Standing up a TLS server with a WebPKI certificate is
not enough; the eUICC ignores WebPKI for this check and demands a GSMA CI chain.

What any server does get before that gate, from `InitiateAuthentication` (step 1):

- `euiccChallenge` — a random nonce. Not identifying.
- `euiccInfo1` — the eUICC's supported GSMA CI public-key identifiers (PKIDs) and
  version/capability data. This fingerprints the eUICC make and CI trust set. It
  does not contain the EID or the IMEI.
- `smdpAddress` — the address the LPA dialed, i.e. the attacker's own host.

The `matchingId` is attacker-chosen input to the download, not a device secret, so
it is not a leak.

So a fake endpoint learns the eUICC's CI/capability fingerprint, never the IMEI —
unless it holds an accredited SM-DP+ certificate.

## Q3 — Can a network MITM intercept the IMEI?

This splits by attacker position and by LPA.

Passive off-path attacker. No. `deviceInfo` travels inside TLS. The application
layer signs it but does not encrypt it, so TLS confidentiality is the only barrier
— and against a passive listener it holds. The attacker sees ciphertext.

Active MITM as a relay. This is the real risk, and it does not need a CERT.DPauth.
The attacker sits between the LPA and the genuine SM-DP+ and relays the RSP
messages. The eUICC's step-2 check validates the real server's certificate, which
the relay forwards unchanged, so the check passes. The attacker only has to break
the TLS transport to read the relayed `AuthenticateClient` body. Because
`deviceInfo` is signed-but-not-encrypted, the full IMEI is readable there in the
clear. The relay does not impersonate the SM-DP+ at the RSP layer; it forwards to
the real one and reads in passing.

Whether the TLS transport can be broken depends on the LPA:

| LPA | RSP TLS trust | System-CA MITM result |
|---|---|---|
| Google LPA (`com.google.android.euicc`) | pins to GSMA CI at the transport | rejected — `Trust anchor not found` (tls-pinning note) |
| OpenEUICC / `lpac` (`HttpInterfaceImpl`) | Android system trust store | terminable with a device-trusted CA |

The tls-pinning note recorded the Google LPA rejecting a system-CA mitmproxy cert
at `lpa.ds.gsma.com`. That LPA pins the transport, so a rogue system CA does not
help; defeating it needs Frida unpinning of its TrustManager. Our IMEI experiments
and the phone-authenticate probe ran through `lpac`, which uses the phone's own
trust store. On a rooted phone a system-installed CA (or any CA the device trusts)
lets an active MITM terminate `lpac`'s TLS and read the IMEI.

Two limits hold in every case:

- The IMEI blob is eUICC-signed. A MITM can read it but cannot forge a different
  device's signed IMEI without the eUICC key.
- The ES8+ bound profile package stays encrypted to the eUICC secure element. TLS
  interception exposes ES9+ transport data (including `deviceInfo`), never the
  profile keys.

## Spoofing the deviceInfo IMEI

The field is caller-controlled, so it spoofs trivially. That does not weaken RSP.

- The value comes from the LPA, not the eUICC. On OpenEUICC the `download` op reads
  `--es imei` verbatim into `ProfileDownloadInput`; our `--imei` flag sets it to any
  string. The eUICC signs whatever it receives — SGP.22 §5.7.13 has it neither check
  nor use `deviceInfo`.
- We sent a placeholder, a junk-TAC synthetic IMEI, and a valid-TAC IMEI. All three
  installed the same profile. No SM-DP+ validated the value.
- Spoofable is not insecure. The download is secured by mutual certificate
  authentication (eUICC certificate + `CERT.DPauth`, both chaining to a GSMA CI) and
  the profile is encrypted to the secure element. The IMEI is metadata. Spoofing it
  cannot fetch an unauthorized profile, impersonate another eUICC, or decrypt a
  profile.
- The weakness sits with whoever trusts the field. A party that gates on `deviceInfo`
  (device eligibility, fraud scoring, blocklist enforcement at download) trusts an
  unauthenticated value. One flag defeats that check. No SM-DP+ tested did this.
- For the user, spoofing is a privacy defense, not an attack. Substituting or omitting
  the IMEI withholds the real one from the operator. The honest default sends the real
  IMEI and pays the exposure; the spoof is the mitigation.

The cellular IMEI the modem reports at attach is a separate identifier with a separate
threat model — see `cellular-imei-spoofing-and-cloning.md`.

## Summary

| Question | Answer |
|---|---|
| Honest SM-DP+ — does the leak matter? | Yes. Permanent hardware ID, no protocol need, enables cross-profile/cross-carrier linkage, breach and intercept exposure. |
| Fake / unauthenticated SM-DP+? | Cannot get the IMEI. Rejected at AuthenticateServer before `deviceInfo` exists. Needs an accredited GSMA-CI SM-DP+ certificate. Learns only the eUICC CI/capability fingerprint pre-auth. |
| Passive network MITM? | No. TLS confidentiality holds. |
| Active MITM relay, Google LPA? | Blocked by transport pinning. Needs Frida unpinning. |
| Active MITM relay, OpenEUICC/`lpac`? | Yes. System-trust-store TLS is terminable with a device-trusted CA; `deviceInfo` is signed but not encrypted, so the full IMEI is readable. |

The sharp result: the IMEI has no cryptographic value (unvalidated, forgeable) yet
full privacy cost (permanent, unique, leaked on success and on rejection). The
honest user who sends a real IMEI pays that cost; an attacker forging one pays
nothing.
