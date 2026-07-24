"""ES11 discovery-response fuzzer for the rogue SM-DS.

Given a live ``initiateAuthentication`` / ``authenticateClient`` request (so it can
echo the FRESH euiccChallenge and transactionId), each mutation produces a response
body that SHOULD be rejected — either by the eUICC's ``AuthenticateServer`` CI-trust
gate or by the LPA's ES11 parser. Every mutation is labelled and carries its
expected outcome.

Three mutation classes:

- ci_trust  — the response is well-formed and crypto-valid (signature verifies,
  challenge echoed), but the certificate does not chain to a trusted GSMA CI, or
  ``euiccCiPKIdToBeUsed`` is forged. Expected: eUICC REJECT at the CI-trust gate.
  An ACCEPT is a CI-trust BYPASS — CRITICAL.
- parser    — malformed ASN.1/BER in serverSigned1, serverCertificate, or the
  event-record list, plus oversized/deeply-nested/huge-list inputs. Expected: the
  LPA parser rejects cleanly. A crash / hang / anomaly is a candidate app bug.
- binding   — a valid untrusted-CI response whose challenge is stale or whose
  transactionId is mismatched. Expected: eUICC REJECT at the binding check.

A mutation targets one of the two endpoints. Parser mutations that hit the event
list target ``authenticate``; everything else targets ``initiate``. The default
``authenticate`` response for non-event mutations is a single benign pointer, so a
device never lacks a downstream event to (not) act on.

Nothing here sends anything. It builds response bytes.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

import ber
import rsp_certs
from smds_server import (
    AuthenticateClientRequest,
    AuthenticateClientResponse,
    EventRecord,
    InitiateAuthRequest,
    InitiateAuthResponse,
    ResponseSource,
)

CI_TRUST = "ci_trust"
PARSER = "parser"
BINDING = "binding"

INITIATE = "initiate"
AUTHENTICATE = "authenticate"

# A fixed stale challenge for the binding attack (never equals a fresh 16-byte one).
_STALE_CHALLENGE = bytes.fromhex("DEADBEEF" * 4)
_SERVER_CHALLENGE = bytes(range(0x40, 0x50))
_ROGUE_ADDRESS = "rogue-smds.local"
_BENIGN_EVENT = EventRecord("rsp-pointer.example.com")


class FuzzError(ValueError):
    """Raised when a mutation cannot be constructed."""


@dataclass(frozen=True)
class Es11Mutation:
    """One labelled ES11 response mutation.

    ``endpoint`` is which request triggers the mutated body. ``build`` takes the
    live parsed request and returns the raw JSON body bytes to serve. ``build`` may
    return deliberately malformed bytes (parser class). ``expected_reject`` is True
    for every mutation: the safe outcome is a reject.
    """

    label: str
    category: str
    endpoint: str
    description: str
    build: Callable[[object], bytes]
    expected_reject: bool = True


# --------------------------------------------------------------------------- #
# Baseline well-formed (but untrusted) response builders.
# --------------------------------------------------------------------------- #


def build_valid_untrusted_response(
    request: InitiateAuthRequest, identity: rsp_certs.AttackerIdentity
) -> InitiateAuthResponse:
    """A crypto-valid response bound to the FRESH challenge, untrusted CI.

    Challenge echoed, signature verifies against the attacker key, cert present but
    not chained to a GSMA CI. This is the CI-trust probe: the eUICC must get past
    the binding + signature checks and REJECT purely on CI-trust.
    """
    txid = "A1B2C3D4"
    server_signed1 = rsp_certs.build_server_signed1(
        transaction_id=bytes.fromhex(txid),
        euicc_challenge=request.euicc_challenge,
        server_address=_ROGUE_ADDRESS,
        server_challenge=_SERVER_CHALLENGE,
    )
    signature = rsp_certs.sign_server_signed1(identity.private_key, server_signed1)
    return InitiateAuthResponse(
        transaction_id=txid,
        server_signed1=server_signed1,
        server_signature1=signature,
        euicc_ci_pkid=identity.ci_pkid,
        server_certificate=identity.server_certificate_tlv(),
    )


def _benign_authenticate(_request: object) -> bytes:
    return AuthenticateClientResponse([_BENIGN_EVENT]).to_json_bytes()


# --------------------------------------------------------------------------- #
# ci_trust mutations.
# --------------------------------------------------------------------------- #


def _ci_trust_mutations() -> list[Es11Mutation]:
    def make(identity_factory: Callable[[], rsp_certs.AttackerIdentity]):
        def build(request: object) -> bytes:
            assert isinstance(request, InitiateAuthRequest)
            return build_valid_untrusted_response(
                request, identity_factory()
            ).to_json_bytes()

        return build

    return [
        Es11Mutation(
            "ci_untrusted_ci_signed", CI_TRUST, INITIATE,
            "cert chains to a synthetic untrusted CI; euiccCiPKIdToBeUsed = that CI",
            make(rsp_certs.build_untrusted_ci_identity),
        ),
        Es11Mutation(
            "ci_self_signed", CI_TRUST, INITIATE,
            "cert self-signed, no CI in the chain",
            make(rsp_certs.build_self_signed_identity),
        ),
        Es11Mutation(
            "ci_forged_pkid", CI_TRUST, INITIATE,
            "euiccCiPKIdToBeUsed forged to the production GSMA CI; cert not signed by it",
            make(rsp_certs.build_forged_ci_pkid_identity),
        ),
    ]


# --------------------------------------------------------------------------- #
# binding mutations.
# --------------------------------------------------------------------------- #


def _binding_mutations() -> list[Es11Mutation]:
    def stale_challenge(request: object) -> bytes:
        assert isinstance(request, InitiateAuthRequest)
        identity = rsp_certs.build_untrusted_ci_identity()
        server_signed1 = rsp_certs.build_server_signed1(
            transaction_id=bytes.fromhex("A1B2C3D4"),
            euicc_challenge=_STALE_CHALLENGE,  # NOT the fresh request challenge
            server_address=_ROGUE_ADDRESS,
            server_challenge=_SERVER_CHALLENGE,
        )
        signature = rsp_certs.sign_server_signed1(identity.private_key, server_signed1)
        return InitiateAuthResponse(
            transaction_id="A1B2C3D4",
            server_signed1=server_signed1,
            server_signature1=signature,
            euicc_ci_pkid=identity.ci_pkid,
            server_certificate=identity.server_certificate_tlv(),
        ).to_json_bytes()

    def mismatched_txid(request: object) -> bytes:
        assert isinstance(request, InitiateAuthRequest)
        identity = rsp_certs.build_untrusted_ci_identity()
        # serverSigned1 carries one txid; the JSON transactionId carries another.
        server_signed1 = rsp_certs.build_server_signed1(
            transaction_id=bytes.fromhex("11111111"),
            euicc_challenge=request.euicc_challenge,
            server_address=_ROGUE_ADDRESS,
            server_challenge=_SERVER_CHALLENGE,
        )
        signature = rsp_certs.sign_server_signed1(identity.private_key, server_signed1)
        return InitiateAuthResponse(
            transaction_id="99999999",
            server_signed1=server_signed1,
            server_signature1=signature,
            euicc_ci_pkid=identity.ci_pkid,
            server_certificate=identity.server_certificate_tlv(),
        ).to_json_bytes()

    return [
        Es11Mutation(
            "binding_stale_challenge", BINDING, INITIATE,
            "serverSigned1 echoes a stale challenge, not the fresh euiccChallenge",
            stale_challenge,
        ),
        Es11Mutation(
            "binding_mismatched_txid", BINDING, INITIATE,
            "transactionId in serverSigned1 mismatches the JSON transactionId",
            mismatched_txid,
        ),
    ]


# --------------------------------------------------------------------------- #
# parser / ASN.1 mutations.
# --------------------------------------------------------------------------- #


def _bump_first_length(data: bytes, delta: int) -> bytes:
    """Adjust the first TLV's declared length by ``delta``, value bytes untouched."""
    ba = bytearray(data)
    tag_end = 1
    if (ba[0] & 0x1F) == 0x1F:
        tag_end = 2
        while ba[tag_end - 1] & 0x80:
            tag_end += 1
    len_byte = ba[tag_end]
    if len_byte & 0x80:
        n = len_byte & 0x7F
        current = int.from_bytes(ba[tag_end + 1 : tag_end + 1 + n], "big")
        new = max(0, current + delta)
        ba[tag_end + 1 : tag_end + 1 + n] = new.to_bytes(n, "big")
    else:
        ba[tag_end] = max(0, min(0x7F, len_byte + delta))
    return bytes(ba)


def _mutate_signed1(request: object, transform: Callable[[bytes], bytes]) -> bytes:
    """Build a valid response, then replace serverSigned1 with transform(signed1)."""
    assert isinstance(request, InitiateAuthRequest)
    identity = rsp_certs.build_untrusted_ci_identity()
    base = build_valid_untrusted_response(request, identity)
    return InitiateAuthResponse(
        transaction_id=base.transaction_id,
        server_signed1=transform(base.server_signed1),
        server_signature1=base.server_signature1,
        euicc_ci_pkid=base.euicc_ci_pkid,
        server_certificate=base.server_certificate,
    ).to_json_bytes()


def _mutate_cert(request: object, transform: Callable[[bytes], bytes]) -> bytes:
    assert isinstance(request, InitiateAuthRequest)
    identity = rsp_certs.build_untrusted_ci_identity()
    base = build_valid_untrusted_response(request, identity)
    return InitiateAuthResponse(
        transaction_id=base.transaction_id,
        server_signed1=base.server_signed1,
        server_signature1=base.server_signature1,
        euicc_ci_pkid=base.euicc_ci_pkid,
        server_certificate=transform(base.server_certificate),
    ).to_json_bytes()


def _deep_nesting(depth: int) -> bytes:
    inner = ber.tlv(0x81, bytes(range(4)))
    for _ in range(depth):
        inner = ber.tlv(0x30, inner)
    return inner


def _parser_mutations() -> list[Es11Mutation]:
    muts: list[Es11Mutation] = []

    muts.append(Es11Mutation(
        "parser_signed1_len_overdeclared", PARSER, INITIATE,
        "serverSigned1 outer length over-declared by 16 bytes (overruns buffer)",
        lambda r: _mutate_signed1(r, lambda s: _bump_first_length(s, +0x10)),
    ))
    muts.append(Es11Mutation(
        "parser_signed1_len_underdeclared", PARSER, INITIATE,
        "serverSigned1 outer length under-declared by 8 bytes (trailing garbage)",
        lambda r: _mutate_signed1(r, lambda s: _bump_first_length(s, -0x08)),
    ))
    muts.append(Es11Mutation(
        "parser_signed1_truncated", PARSER, INITIATE,
        "serverSigned1 truncated by 12 bytes",
        lambda r: _mutate_signed1(r, lambda s: s[:-12]),
    ))
    muts.append(Es11Mutation(
        "parser_signed1_unexpected_tag", PARSER, INITIATE,
        "unexpected private-class tag (0xDF7F) prepended inside serverSigned1",
        lambda r: _mutate_signed1(
            r, lambda s: ber.tlv(0x30, ber.tlv(0xDF7F, b"\x00\x01\x02") + ber.first(s, 0x30).value)
        ),
    ))
    muts.append(Es11Mutation(
        "parser_signed1_deep_nesting", PARSER, INITIATE,
        "serverSigned1 replaced with 64-deep nested SEQUENCEs (parser recursion)",
        lambda r: _mutate_signed1(r, lambda _s: _deep_nesting(64)),
    ))
    muts.append(Es11Mutation(
        "parser_signed1_oversized_field", PARSER, INITIATE,
        "euiccChallenge field inside serverSigned1 inflated to 8 KiB",
        lambda r: _mutate_signed1(
            r, lambda _s: ber.tlv(0x30, ber.tlv(0x80, b"\x00" * 4) + ber.tlv(0x81, b"\xAA" * 8192))
        ),
    ))
    muts.append(Es11Mutation(
        "parser_cert_truncated", PARSER, INITIATE,
        "serverCertificate DER truncated by 32 bytes",
        lambda r: _mutate_cert(r, lambda c: c[:-32]),
    ))
    muts.append(Es11Mutation(
        "parser_cert_len_overdeclared", PARSER, INITIATE,
        "serverCertificate outer length over-declared by 64 bytes",
        lambda r: _mutate_cert(r, lambda c: _bump_first_length(c, +0x40)),
    ))

    # event-record parser attacks on the ES11 authenticateClient response.
    def huge_event_list(_request: object) -> bytes:
        events = [EventRecord(f"smdp-{i}.example.com", f"{i:08X}") for i in range(5000)]
        return AuthenticateClientResponse(events).to_json_bytes()

    def malformed_event_json(_request: object) -> bytes:
        # eventEntries present but each entry missing rspServerAddress (lpac errors).
        body = {
            "header": {"functionExecutionStatus": {"status": "Executed-Success"}},
            "eventEntries": [{"eventId": "00000000"}, {"rspServerAddress": 12345}],
        }
        return json.dumps(body).encode("utf-8")

    def oversized_event_address(_request: object) -> bytes:
        events = [EventRecord("A" * 65536)]
        return AuthenticateClientResponse(events).to_json_bytes()

    muts.append(Es11Mutation(
        "parser_event_huge_list", PARSER, AUTHENTICATE,
        "eventEntries with 5000 records (list-size / allocation stress)",
        huge_event_list,
    ))
    muts.append(Es11Mutation(
        "parser_event_wrong_types", PARSER, AUTHENTICATE,
        "eventEntries records missing rspServerAddress / wrong JSON types",
        malformed_event_json,
    ))
    muts.append(Es11Mutation(
        "parser_event_oversized_address", PARSER, AUTHENTICATE,
        "single event with a 64 KiB rspServerAddress string",
        oversized_event_address,
    ))
    return muts


# --------------------------------------------------------------------------- #
# Public API.
# --------------------------------------------------------------------------- #


def all_mutations() -> list[Es11Mutation]:
    """Every labelled mutation across the three classes."""
    muts = _ci_trust_mutations() + _binding_mutations() + _parser_mutations()
    labels = [m.label for m in muts]
    if len(labels) != len(set(labels)):
        raise FuzzError("duplicate mutation labels")
    return muts


CATEGORIES = (CI_TRUST, BINDING, PARSER)


class Es11FuzzSource(ResponseSource):
    """A :class:`ResponseSource` that serves one selected mutation's response.

    The orchestrator sets :attr:`current` per iteration. The endpoint the mutation
    does NOT target gets a benign well-formed response, so the flow reaches the
    targeted step. Discovery stays non-destructive: the authenticate response is
    only ever event POINTERS, and the orchestrator never proceeds past discovery.
    """

    def __init__(self, mutation: Es11Mutation) -> None:
        self.current = mutation

    def initiate(self, request: InitiateAuthRequest) -> bytes:
        if self.current.endpoint == INITIATE:
            return self.current.build(request)
        return build_valid_untrusted_response(
            request, rsp_certs.build_untrusted_ci_identity()
        ).to_json_bytes()

    def authenticate(self, request: AuthenticateClientRequest) -> bytes:
        if self.current.endpoint == AUTHENTICATE:
            return self.current.build(request)
        return _benign_authenticate(request)
