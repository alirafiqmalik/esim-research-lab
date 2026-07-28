# SM-DS Server Addresses

## How SM-DS works in eSIM discovery

- Handshake: on power-up a new eSIM device starts a discovery bootstrap keyed by
  its eUICC identifier (EID).
- Querying the directory: the device reaches the root SM-DS, or a specific SM-DS
  named in the profile configuration.
- Routing to SM-DP+: the SM-DS maps the EID / matching ID to the correct
  operator SM-DP+ and returns `eventEntries` that point the device there to
  download the profile.

On this device, ES10a GetEuiccConfiguredAddresses reports the configured root:

```
rootDsAddress = lpa.ds.gsma.com   (TLV BF3C: 6c70612e64732e67736d612e636f6d)
```

No default SM-DP+ address is set, so discovery falls back to the GSMA root SM-DS.

## Addresses

| Provider | Host | Kind | CI | Source |
|---|---|---|---|---|
| GSMA | `lpa.ds.gsma.com` | Root SM-DS (consumer bootstrap) | production | eUICC ES10a; osmocom |
| Thales | `lpa.live.esimdiscovery.com` | SM-DS | production | osmocom known-test-profile |
| Thales | `lpa.live.esimdiscovery.dev` | SM-DS (Google UE4 lab) | production CI (see note) | osmocom |

Note on `.dev`: despite the `.dev` label, its AuthenticateServer certificate
chains to the **production** GSMA RSP2 Root CI1 (subject `Google SMDS UE4 LAB,
O=Thales`), so a production eUICC trusts it. It is not a test-CI host.

## Relation to the Truphone / Redtea profiles

The 1GLOBAL/Truphone (BetterRoaming, Speedtest) and Redtea (RedteaGO) profiles
install via direct SM-DP+ activation codes (`LPA:1$<smdp>$<matchingId>`), so they
do not use a per-brand SM-DS. Their discovery path is the shared GSMA root SM-DS
above. No Truphone- or Redtea-specific SM-DS host is published.

## Probes available

- `esim euicc discovery --smds <host>` — ES11 discovery (InitiateAuthentication +
  AuthenticateClient against the SM-DS), returns `eventEntries`.
- `esim euicc authenticate <host>` — CI-trust probe (InitiateAuthentication +
  ES10b AuthenticateServer).
- `esim euicc get-addresses` — ES10a, reads the eUICC's configured root SM-DS.

## Sources

- Device ES10a GetEuiccConfiguredAddresses (2026-07-28)
- https://euicc-manual.osmocom.org/docs/rsp/known-test-profile/
- `testbed/ping-live-servers/notes/04-phone-authenticate-findings.md`
