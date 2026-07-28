# SM-DS Probe Findings

Date: 2026-07-28
Device: Pixel 7a, OpenEUICC lpac backend, EID 89033023427100000000027143866816
Runner: `scripts/ping_sm_ds.py`
Log set: `logs/smds-20260728_053710/`

## Result: all 3 SM-DS reached, all trusted, no pending events

| Provider | Host | authenticate | discovery | events |
|---|---|---|---|---|
| GSMA (root) | `lpa.ds.gsma.com` | accepted (ciTrusted=true) | ok | 0 |
| Thales | `lpa.live.esimdiscovery.com` | accepted (ciTrusted=true) | ok | 0 |
| Thales | `lpa.live.esimdiscovery.dev` | accepted (ciTrusted=true) | ok | 0 |

## What the probes show

- `events=0` everywhere: no download events are registered against this EID at
  any SM-DS. Expected — nothing has bound a profile to this EID via discovery.
  A non-empty result would list `eventEntries` mapping the EID to an SM-DP+.
- Every SM-DS cert chains to production GSMA RSP2 Root CI1, so the eUICC accepts
  all three (`ciTrusted=true`).

## ES11 discovery is a full handshake, not a bare lookup

The captured logcat shows discovery running two HTTPS calls to the SM-DS:

```
POST https://lpa.ds.gsma.com/gsma/rsp2/es9plus/initiateAuthentication
     {smdpAddress, euiccChallenge, euiccInfo1}
POST https://lpa.ds.gsma.com/gsma/rsp2/es9plus/authenticateClient
     {transactionId, authenticateServerResponse}
-> response carries eventEntries
```

So discovery authenticates both directions (server cert to the eUICC, then the
eUICC's `authenticateServerResponse` — GEMALTO EUM cert chain — to the SM-DS)
before returning the event list.

## Correction to the earlier assumption

`lpa.live.esimdiscovery.dev` was previously assumed to be a test-CI host and
excluded from the SM-DP+ sweep. Its AuthenticateServer certificate actually
chains to the production CI:

```
subject = C=US, L=Virginia, O=Thales, OU=ODC US, CN=Google SMDS UE4 LAB
issuer  = O=GSM Association, CN=GSM Association - RSP2 Root CI1
```

The production eUICC trusts it, so it is a valid production-CI SM-DS for probing.

## Artifacts

- `logs/smds-20260728_053710/results.jsonl` — one row per SM-DS
- `logs/smds-20260728_053710/summary.txt`
- `logs/smds-20260728_053710/<host>/{authenticate,discovery}/logcat.txt` — ES11
  plaintext (challenge, euiccInfo1, authenticateServerResponse, eventEntries)
