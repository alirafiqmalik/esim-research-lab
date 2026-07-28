# ecosim — local eSIM ecosystem simulation testbed

A self-contained software model of the GSMA SGP.22 Remote SIM Provisioning flow.
No hardware, no emulated card. Everything runs in one Python process against a
custom PKI, so every channel is observable in cleartext.

```
MNO --ES2+--> SM-DP+ --C1/ES9+--> device --C2a--> LPA --C3/ES10--> eUICC (software)
                                    `--C2b (modem APDU transport)--'
```

## Channels

| Channel | Interface | Transport | Protected? |
|---------|-----------|-----------|------------|
| C1  | ES9+  | JSON over "HTTPS" | TLS + signed blobs |
| C2a | LPA activation-code entry | text | none |
| C2b | modem APDU transport | APDU | none |
| C3  | ES10 (ISD-R) | BER-TLV APDU | none at transport |

The signed/encrypted parts (ECDSA authentication, ES8+/SCP03t profile package)
use real P-256 keys off the custom CI. They are genuinely protected. Everything
outside that envelope — framing, metadata, ids, challenges — is the attack surface.

## Modules

- `pki.py` — custom CI → EUM → eUICC and CI → SM-DP+ cert chains (P-256).
- `crypto.py` — ECDSA sign/verify, ECDH session key, AES-GCM profile sealing.
- `protocol.py` — shared signed-blob layouts + session-key derivation (the linchpin both sides import).
- `tlv.py` — BER-TLV encode/decode for the ES10 layer.
- `codec.py` — ES9+/ES2+ JSON builders, activation code, ES10 APDU builders.
- `bus.py` — the four channels with tap / record / mutate hooks.
- `euicc.py` — software eUICC (ISD-R model): challenge, info1, AuthenticateServer, install.
- `smdp.py` — SM-DP+: InitiateAuthentication, AuthenticateClient, GetBoundProfilePackage.
- `mno.py` — MNO harness: order a profile, emit an activation code.
- `lpa.py` — LPA: drives the whole flow, routing every message through the bus.
- `verifier.py` — structure verifier: checks each message against SGP.22 command structure.
- `analyze.py` — classifies fields as invariant vs variable across runs.
- `fuzz.py` — mutates only variable fields, per channel, through the bus hook.
- `orchestrator.py` — builds the object graph, runs one flow, writes run logs.
- `testing/run_e2e.py` — the driver: verify-loop → classify → fuzz.

## Run

```
./venv/bin/python -m testbed.ecosim.testing.run_e2e
```

Outputs land in `logs/`:

- `clean-run-*.jsonl` — one verified end-to-end run each (one JSON record per message).
- `field-classification.txt` / `.jsonl` — invariant vs variable field report.
- `fuzz-results.jsonl` — per-mutation outcome (accepted / verifier-violation / exception).

## Method

1. Build the ecosystem once. Identities (certs, EID, SM-DP+ address) stay fixed.
2. Run the flow; the verifier gates each run against the real command structure.
   Only conforming runs are banked. That is the agentic verify-loop.
3. Diff banked runs. Fields identical every run are invariant (tags, OIDs, cert
   bytes, placeholders, structure). Fields that change are variable (challenges,
   transaction ids, ephemeral keys, iccid, matchingId).
4. Fuzz only the variable fields, per channel. Record what the stack rejects and
   what it accepts unchecked.
