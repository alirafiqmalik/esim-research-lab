"""es11_fuzz: every mutation is labelled, locatable, and correctly classed."""

from __future__ import annotations

import base64
import json

import es11_fuzz
import rsp_certs
from es11_fuzz import (
    AUTHENTICATE,
    CATEGORIES,
    CI_TRUST,
    INITIATE,
    Es11FuzzSource,
    all_mutations,
)
from smds_server import AuthenticateClientRequest, InitiateAuthRequest

_FRESH_CHALLENGE = bytes.fromhex("0AE5502D276DA170928AB33246923A35")


def _initiate_req() -> InitiateAuthRequest:
    return InitiateAuthRequest("127.0.0.1", _FRESH_CHALLENGE, b"\xBF\x20\x00")


def _authenticate_req() -> AuthenticateClientRequest:
    return AuthenticateClientRequest("A1B2C3D4", b"\xBF\x38\x00")


def test_all_mutations_labelled_and_unique():
    muts = all_mutations()
    labels = [m.label for m in muts]
    assert len(labels) == len(set(labels))
    assert all(m.label and m.description for m in muts)
    assert all(m.category in CATEGORIES for m in muts)
    assert all(m.endpoint in (INITIATE, AUTHENTICATE) for m in muts)


def test_every_class_is_represented():
    cats = {m.category for m in all_mutations()}
    assert cats == set(CATEGORIES)


def test_each_mutation_builds_response_bytes():
    for m in all_mutations():
        req = _initiate_req() if m.endpoint == INITIATE else _authenticate_req()
        body = m.build(req)
        assert isinstance(body, bytes) and len(body) > 0


def test_ci_trust_mutations_carry_untrusted_pkid_and_echo_challenge():
    for m in all_mutations():
        if m.category != CI_TRUST:
            continue
        body = m.build(_initiate_req())
        obj = json.loads(body)
        # crypto-valid + challenge-bound so it reaches the CI-trust gate
        signed1 = base64.b64decode(obj["serverSigned1"])
        assert _FRESH_CHALLENGE in signed1
        pkid = base64.b64decode(obj["euiccCiPKIdToBeUsed"])
        # forged mutation advertises the prod CI; the others advertise a synthetic CI.
        if m.label == "ci_forged_pkid":
            assert pkid == rsp_certs.PROD_GSMA_CI_PKID
        else:
            assert pkid != rsp_certs.PROD_GSMA_CI_PKID


def test_ci_trust_signature_verifies_against_served_cert():
    from cryptography import x509

    body = next(m for m in all_mutations() if m.label == "ci_untrusted_ci_signed").build(
        _initiate_req()
    )
    obj = json.loads(body)
    cert = x509.load_der_x509_certificate(base64.b64decode(obj["serverCertificate"]))
    signed1 = base64.b64decode(obj["serverSigned1"])
    # serverSignature1 wire form is the raw 5F37 TLV
    import ber

    sig_tlv = base64.b64decode(obj["serverSignature1"])
    assert ber.first(sig_tlv, rsp_certs.TAG_SERVER_SIGNATURE1).tag == 0x5F37
    assert rsp_certs.verify_server_signature1(cert.public_key(), signed1, sig_tlv)


def test_binding_stale_challenge_does_not_echo_fresh():
    body = next(m for m in all_mutations() if m.label == "binding_stale_challenge").build(
        _initiate_req()
    )
    signed1 = base64.b64decode(json.loads(body)["serverSigned1"])
    assert _FRESH_CHALLENGE not in signed1


def test_parser_mutations_are_structurally_locatable():
    # Each parser mutation returns bytes we can at least locate the framing of.
    for m in all_mutations():
        if m.category != es11_fuzz.PARSER:
            continue
        req = _initiate_req() if m.endpoint == INITIATE else _authenticate_req()
        body = m.build(req)
        assert len(body) > 0
        # authenticate-endpoint parser mutations are JSON with eventEntries
        if m.endpoint == AUTHENTICATE:
            assert b"eventEntries" in body


def test_parser_huge_event_list_is_large():
    body = next(m for m in all_mutations() if m.label == "parser_event_huge_list").build(
        _authenticate_req()
    )
    assert json.loads(body)["eventEntries"].__len__() == 5000


def test_fuzz_source_serves_selected_mutation_and_benign_other_endpoint():
    mutation = next(m for m in all_mutations() if m.endpoint == INITIATE)
    source = Es11FuzzSource(mutation)
    initiate_body = source.initiate(_initiate_req())
    # a fresh keypair is minted per build, so bodies differ byte-for-byte; assert
    # the source routed the request to the mutation (valid initiate JSON shape)
    obj = json.loads(initiate_body)
    assert "serverSigned1" in obj and "serverCertificate" in obj
    # the non-targeted endpoint returns a benign pointer-only response
    auth_body = source.authenticate(_authenticate_req())
    assert b"rspServerAddress" in auth_body
    assert b"boundProfilePackage" not in auth_body
