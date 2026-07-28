# scripts/ — ES9+/ES11 request-builder scripts

Everything here defaults to the local ecosim-backed sim. Nothing in this
directory has ever sent a request to a real SM-DP+ or SM-DS host.

## What's here

- `local_sim_server.py` — local-only HTTP shim (binds `127.0.0.1` only) that
  speaks the real ES9+/ES11 JSON wire shape, backed by
  `testbed/ecosim/`'s in-process `SmDpPlus`/`SmDs` objects. Used
  programmatically by the two flow scripts below; can also run standalone.
- `run_es9plus_flow.py` — drives `InitiateAuthentication` ->
  `AuthenticateClient` -> `GetBoundProfilePackage` -> `HandleNotification`
  through the `src/` request-builder library, over a real local HTTP socket.
- `run_es11_discovery.py` — drives an SM-DS discovery lookup the same way.

## Local-only validation

Run either flow script with no arguments and it:

1. builds a fresh `ecosim` ecosystem (fresh PKI, one registered order),
2. starts `local_sim_server.py` in a background thread bound to
   `127.0.0.1` on an OS-assigned port,
3. builds each request with the `src/models.py` dataclasses, serializes it
   with the real GSMA JSON envelope (`src/envelope.py`), and POSTs it over an
   actual `http://127.0.0.1:<port>/...` socket using `src/client.py`,
4. parses the JSON response back into typed dataclasses and feeds it into
   `ecosim`'s own eUICC object (real ECDSA/AEAD, same code path as
   `testbed/ecosim/lpa.py`) so the round trip is cryptographically checked,
   not just shape-checked,
5. shuts the shim down and prints a summary.

Both scripts exit 0 and print `OK` on success. Verified by running them:

```
./venv/bin/python testbed/ping-live-servers/scripts/run_es9plus_flow.py
./venv/bin/python testbed/ping-live-servers/scripts/run_es11_discovery.py
```

`local_sim_server.py` can also run standalone (`--role smdp` /
`--role smds`) for manual poking with `curl` against `127.0.0.1` — but a
standalone server and a separately-run client process do not share a PKI
identity (ecosim generates fresh keys per process), so only the two flow
scripts above (which build the server and client in the same process) can
complete a full authenticated round trip. Standalone mode is for inspecting
the wire shape, not for the cryptographic flow.

## Live execution is gated — by design, not by accident

Every script defaults to `--target local`. `--target provider` exists as a
documented, inert code path: it requires `--provider-host <fqdn>`,
`--allow-live-fire`, **and** the environment variable
`ESIM_MITM_ALLOW_LIVE_FIRE=1` to all be present before `src/client.py`'s
`RspHttpClient` will even construct successfully against a non-local target
— and even then, these scripts print a refusal message and exit 2 rather
than dispatching a real request, because live execution is a decision the
orchestrating session makes separately, later, and neither gate is set
anywhere in this repo.

`src/targets.provider_target(name, host)` can build a `Target` for a real
FQDN (harmless — it does no I/O), but `RspHttpClient.__post_init__` refuses
to use it without both gates. See `src/client.py` for the exact check.

## Directory map

```
src/
  errors.py     — exception types (raise, never return None)
  envelope.py   — GSMA header wrapper + HTTP paths (notes/03-api-request-list.md)
  models.py     — typed request/response dataclasses per ES9+/ES11 function
  targets.py    — Target dataclass; LOCAL_SIM_SMDP/SMDS + provider_target()
  client.py     — RspHttpClient: the only thing that does network I/O, gated
scripts/
  local_sim_server.py   — local-only HTTP shim over ecosim
  run_es9plus_flow.py   — full ES9+ download flow, validated
  run_es11_discovery.py — ES11 discovery lookup, validated
```
