# SM-DS EID Enumeration — Finding

Date: 2026-07-28
Probe: `scripts/eid_enumeration.py`
Log: `logs/eid-enum-20260728_131108/report.json`

## Question

Can an unauthenticated party present arbitrary EIDs to a live SM-DS and learn
"event waiting" vs "nothing" — an enumeration oracle?

## Answer: no pre-authentication EID oracle

The ES11 message flow forbids it by construction:

- `InitiateAuthentication` body = `euiccChallenge` + `euiccInfo1`. **No EID
  field.** The SM-DS does not know which EID is asking at this stage, so there is
  no input for an unauthenticated caller to enumerate over.
- `eventEntries[]` come only from `AuthenticateClient`, whose input is the
  eUICC-signed `authenticateServerResponse`. The EID rides inside `CERT.EUICC`,
  which the eUICC signs. The SM-DS binds the queried EID to a valid eUICC
  signature.

You can only learn the event state for an EID whose eUICC you control.

## Evidence

Host-side `InitiateAuthentication` (synthetic challenge, real public
`euiccInfo1`, no EID) to three SM-DS, 3 attempts each:

| Host | HTTP | Function status |
|---|---|---|
| lpa.live.esimdiscovery.com | 200 | Failed |
| lpa.live.esimdiscovery.dev | 200 | Failed |
| lpa.ds.gsma.com (root) | 200 | Failed |

Every attempt returns the same function-level `Failed` — no variation, and no
field carried an EID. A synthetic host-side request cannot advance past
InitiateAuthentication because the next step needs an eUICC signature.

Authenticated reference — the one EID we can query, via the real eUICC:

```
esim euicc discovery  ->  ok=True, event_count=0
```

The eUICC-driven flow completes and returns `events=0` (nothing registered to
this EID), while no synthetic path can query any other EID.

## Relevance to MITM

Discovery is not an open enumeration primitive on the live network. An attacker
cannot sweep EIDs against the SM-DS without the corresponding eUICC key material.
The event lookup is only meaningful to the legitimate eUICC holder.
