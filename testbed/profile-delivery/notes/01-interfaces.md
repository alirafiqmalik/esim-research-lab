# SM-DP+ Interfaces: ES9+, ES2+, ES8+

Three interfaces move a profile from an operator to the eUICC. Only one is
reachable from the phone. The other two are server-to-server or ride inside the
first.

ecosim states the channel map directly (`testbed/ecosim/__init__.py`):

```
MNO --ES2+--> SM-DP+ --C1/ES9+--> device --C2a--> LPA --C3/ES10--> eUICC
```

## ES9+ — device LPA to SM-DP+

The encrypted download channel. This is the one the LPA drives, over TLS, to the
SM-DP+ FQDN. Five functions, one download session, tied together by a single
`transactionId` minted at step 1.

| # | Function | Wire endpoint |
|---|---|---|
| 1 | InitiateAuthentication | `POST /gsma/rsp2/es9plus/initiateAuthentication` |
| 2 | AuthenticateClient | `POST /gsma/rsp2/es9plus/authenticateClient` |
| 3 | GetBoundProfilePackage | `POST /gsma/rsp2/es9plus/getBoundProfilePackage` |
| 4 | HandleNotification | `POST /gsma/rsp2/es9plus/handleNotification` |
| 5 | CancelSession | `POST /gsma/rsp2/es9plus/cancelSession` |

We drive this whole chain from the phone. A single `esim euicc download` run
captured all four active steps in cleartext — see
`testbed/profile-download/logs/20260728_041930-lifecycle-QRF-SPEEDTEST/05-05-redownload/rsp.json`:
`initiateAuthentication -> authenticateClient -> getBoundProfilePackage ->
handleNotification`, each `Executed-Success`.

Device-reachable: **yes**. Full function catalog:
`testbed/ping-live-servers/notes/03-api-request-list.md`.

## ES2+ — MNO/MVNO backend to SM-DP+

The ordering channel. The operator's business system tells the SM-DP+ to prepare
a profile and hand back an activation token. This is what mints the
`matchingId` our catalog codes carry.

ecosim models the operator side (`testbed/ecosim/mno.py`):

```python
def order_profile(self, profile_name, sp_name, profile_class=0) -> ActivationCode:
    iccid = self._generate_iccid()
    matching_id = self._generate_matching_id()
    self.smdp.register_order(matching_id, iccid, profile_name, sp_name, profile_class)
    return ActivationCode(smdp_address=self.smdp.address, matching_id=matching_id)
```

The returned `ActivationCode(smdp_address, matching_id)` is exactly the
`LPA:1$<smdp>$<matchingId>` shape in `testbed/profile-download/catalog/profiles.jsonl`.
The SM-DP+ side stores it in an order registry (`testbed/ecosim/smdp.py`:
"Owns the order registry (what ES2+ registered with the operator)"). Real ES2+
functions include DownloadOrder, ConfirmOrder, and ReleaseProfile; ecosim
collapses these into one `order_profile` / `register_order` pair.

Device-reachable: **no**. ES2+ needs operator credentials against the SM-DP+
admin API. The phone never speaks it. It explains where our activation codes
come from.

## ES8+ — SM-DP+ to eUICC, tunneled

The secure channel carrying the profile itself. ES8+ is not a separate HTTP
call. The SM-DP+ seals the profile under an SCP03t session key, wraps it in the
BoundProfilePackage, and the BPP travels inside the ES9+ GetBoundProfilePackage
response (step 3 above). The LPA passes the BPP to the eUICC, which unwraps the
ES8+ segments internally.

ecosim implements this sealing for real (`testbed/ecosim/protocol.py`:
"ES8+/SCP03t profile sealing"; `testbed/ecosim/crypto.py`:
"ES8+/SCP03t session-key derivation"). `smdp.get_bound_profile_package` seals the
profile under the ES8+ session key.

Device-reachable: **only as the payload of ES9+ step 3**. We already captured the
BPP bytes in the rsp.json cited above. The plaintext profile inside is protected
by the eUICC's keys; the LPA sees only the sealed package.

## Summary

| Interface | Endpoints / functions | Who talks | Device-reachable? | Where we exercise or model it |
|---|---|---|---|---|
| ES9+ | 5 `/gsma/rsp2/es9plus/...` functions | LPA ↔ SM-DP+ | Yes | live: profile-download rsp.json; model: `ecosim/smdp.py` |
| ES2+ | DownloadOrder / ConfirmOrder / ReleaseProfile (ecosim: `order_profile`) | MNO/MVNO ↔ SM-DP+ | No (operator credentials) | model only: `ecosim/mno.py` + `smdp.register_order` |
| ES8+ | SCP03t-sealed profile inside the BPP | SM-DP+ → eUICC | Only inside ES9+ step 3 | live: BPP bytes captured; model: `ecosim/protocol.py` + `crypto.py` |
