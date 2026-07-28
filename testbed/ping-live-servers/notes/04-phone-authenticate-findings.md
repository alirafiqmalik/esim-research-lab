# Phone-Driven AuthenticateServer Probe — Findings

Date: 2026-07-28
Device: Pixel 7a (rooted), OpenEUICC privileged, `lpac` backend
EID: 89033023427100000000027143866816
Runner: `scripts/phone_ping_servers.py`
Log set: `logs/phone-authenticate-20260728_011705/`

## What ran

Each server got one `esim euicc --backend lpac authenticate <fqdn>`. That drives
the real eUICC through:

```
ES10b GetEUICCChallenge   -> real euiccChallenge
ES10b GetEUICCInfo1       -> real euiccInfo1 (real GSMA CI PKIDs)
ES9+  InitiateAuthentication (phone network + phone trust store)
ES10b AuthenticateServer  -> eUICC verifies CERT.DPauth chain to a trusted CI
```

No profile downloaded. Serial run, one RSP session at a time.

## Result: 13 accepted, 4 unreachable

Every reachable server returned `functionExecutionStatus: Executed-Success` and a
real `serverCertificate`, and the eUICC accepted the chain (`ciTrusted: true`,
`stage: accepted`).

| Provider | Host | Type | Outcome |
|---|---|---|---|
| 1GLOBAL | rsp.truphone.com | SM-DP+ | accepted |
| Eastcom Peace | secsmsminiapp.eastcompeace.com | SM-DP+ | accepted |
| Idemia | t-mobile.idemia.io | SM-DP+ | accepted |
| Idemia | rsp-3002.idemia.io | SM-DP+ | accepted |
| Idemia | rsp-3036.idemia.io | SM-DP+ | accepted |
| Idemia | rsp-4002.idemia.io | SM-DP+ | accepted |
| Idemia | rsp-4008.idemia.io | SM-DP+ | accepted |
| Idemia | celitech.idemia.io | SM-DP+ | accepted |
| Linksfield | rsp-0001.linksfield.net | SM-DP+ | accepted |
| Redtea Mobile | rsp-eu.redteamobile.com | SM-DP+ | accepted |
| Valid | demo-consumer.validspereachdpplus.com | SM-DP+ | accepted |
| Thales | lpa.ds.gsma.com | SM-DS | accepted |
| Thales | lpa.live.esimdiscovery.com | SM-DS | accepted |
| Giesecke+Devrient | cust-003.oberthur.rsp.gieseckedevrient.com | SM-DP+ | unreachable |
| Giesecke+Devrient | prod.attesim.rsp.gieseckedevrient.com | SM-DP+ | unreachable |
| Kigen | smdp-plus-0.eu.cd.rsp.kigen.com | SM-DP+ | unreachable |
| Kigen | smdp-plus-1.eu.cd.rsp.kigen.com | SM-DP+ | unreachable |

## The 4 unreachable are network, not CI distrust

Each shows `authRc: -2`, `stage: initiateAuthentication_failed`, `ciTrusted: false`.
The transcript proves the cause: the phone sent the ES9+ POST, then
`HttpInterfaceImpl.transmit` threw before any response body arrived.

```
D/HttpInterfaceImpl: transmit(url = https://.../es9plus/initiateAuthentication)
D/HttpInterfaceImpl: HTTP tx = {"smdpAddress":...,"euiccChallenge":...,"euiccInfo1":...}
W/System.err:    at net.typeblog.lpac_jni.impl.HttpInterfaceImpl.transmit(HttpInterfaceImpl.kt:61)
```

`ciTrusted: false` here is the untouched default — the eUICC never evaluated a
cert. The two G+D hosts do not resolve; the two Kigen hosts time out. Same real
cause seen earlier from the host probe. Do not read these as CI-trust failures.

Corroboration: the 13 accepted hosts each logged exactly one `HTTP response body`;
the 4 unreachable logged zero.

## Why this beats the host probe

`ping_live_servers.py` posts a synthetic challenge and synthetic euiccInfo1 from
the laptop, so servers reject it (`Invalid`, `Unsupported`, `None of the proposed
Public Key Identifiers is supported`). This probe sends the phone's real eUICC
identity over the phone's own network, so the request is genuine and the eUICC
verifies the server cert. `Executed-Success` here is a real authenticated exchange.

## Limits

- `accepted` means the server was reached and the eUICC trusts its cert. It does
  not mean a profile is available — that needs a matching activation code.
- Egress is the phone's network. DNS and reachability differ from the laptop.
- Test/dev endpoints (for example `lpa.live.esimdiscovery.dev`) are excluded. A
  production eUICC does not trust a test CI, so a rejection there says nothing
  about reachability.

## Artifacts

- `logs/phone-authenticate-20260728_011705/results.jsonl` — one row per server
- `logs/phone-authenticate-20260728_011705/summary.txt` — the summary
- `logs/phone-authenticate-20260728_011705/<host>/es9plus-transcript.txt` — the
  ES9+ plaintext (challenge, euiccInfo1, serverSigned1, serverCertificate)
- `logs/phone-authenticate-20260728_011705/<host>/harness-result.json` — raw
  harness output
