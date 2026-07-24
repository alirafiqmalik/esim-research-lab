"""smds_server: request parsing + response building echo the fresh challenge."""

from __future__ import annotations

import base64
import json

import rsp_certs
from smds_server import (
    AUTHENTICATE_PATH,
    INITIATE_PATH,
    AuthenticateClientResponse,
    EventRecord,
    InitiateAuthResponse,
    ServerError,
    parse_authenticate_request,
    parse_initiate_request,
)


def _mk_initiate_body(challenge: bytes) -> bytes:
    return json.dumps(
        {
            "smdpAddress": "127.0.0.1",
            "euiccChallenge": base64.b64encode(challenge).decode(),
            "euiccInfo1": base64.b64encode(b"\xBF\x20\x00").decode(),
        }
    ).encode()


def test_parse_initiate_extracts_fresh_challenge():
    challenge = bytes.fromhex("0AE5502D276DA170928AB33246923A35")
    req = parse_initiate_request(_mk_initiate_body(challenge))
    assert req.euicc_challenge == challenge
    assert req.smdp_address == "127.0.0.1"


def test_parse_initiate_rejects_garbage():
    try:
        parse_initiate_request(b"not json")
        raise AssertionError("expected ServerError")
    except ServerError:
        pass


def test_initiate_response_echoes_challenge_into_server_signed1():
    challenge = bytes.fromhex("0AE5502D276DA170928AB33246923A35")
    identity = rsp_certs.build_untrusted_ci_identity()
    signed1 = rsp_certs.build_server_signed1(
        transaction_id=bytes.fromhex("A1B2C3D4"),
        euicc_challenge=challenge,
        server_address="rogue.local",
        server_challenge=bytes(16),
    )
    resp = InitiateAuthResponse(
        transaction_id="A1B2C3D4",
        server_signed1=signed1,
        server_signature1=rsp_certs.sign_server_signed1(identity.private_key, signed1),
        euicc_ci_pkid=identity.ci_pkid,
        server_certificate=identity.server_certificate_tlv(),
    )
    obj = json.loads(resp.to_json_bytes())
    # The wire serverSigned1 must contain the exact fresh challenge bytes.
    wire_signed1 = base64.b64decode(obj["serverSigned1"])
    assert challenge in wire_signed1
    assert obj["header"]["functionExecutionStatus"]["status"] == "Executed-Success"


def test_authenticate_response_carries_event_pointers_only():
    resp = AuthenticateClientResponse([EventRecord("smdp.example.com")])
    obj = json.loads(resp.to_json_bytes())
    assert obj["eventEntries"][0]["rspServerAddress"] == "smdp.example.com"
    # No profile bytes anywhere — discovery returns pointers.
    assert "boundProfilePackage" not in resp.to_json_bytes().decode()


def test_parse_authenticate_request_roundtrip():
    body = json.dumps(
        {"transactionId": "A1B2C3D4", "authenticateServerResponse": base64.b64encode(b"\xBF\x38\x00").decode()}
    ).encode()
    req = parse_authenticate_request(body)
    assert req.transaction_id == "A1B2C3D4"
    assert req.authenticate_server_response == b"\xBF\x38\x00"


def test_endpoint_paths_match_lpac():
    assert INITIATE_PATH == "/gsma/rsp2/es9plus/initiateAuthentication"
    assert AUTHENTICATE_PATH == "/gsma/rsp2/es9plus/authenticateClient"
