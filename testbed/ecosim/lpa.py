"""LPA (Local Profile Assistant): drives the end-to-end profile download flow.

Every hop of the flow — C2a activation code, C3 ES10 APDUs (mirrored onto C2b),
and C1 ES9+ JSON — goes through ``bus.send`` so an installed fuzz mutator can
rewrite the wire in flight. Downstream code always re-derives its inputs from
the *returned* message, never from the value it built locally, so a mutation
actually reaches the component that verifies it.
"""

from __future__ import annotations

from typing import Protocol

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from . import codec, tlv
from .bus import C1, C2A, C2B, C3, Bus, Message
from .codec import ActivationCode
from .pki import certificate_registered_oid

# --- inner tags for the AuthenticateServer.resp APDU we invent here ---------
# codec.py only defines the top-level ES10 tags; the fields nested under
# TAG_AUTHENTICATE_SERVER are local to this LPA<->eUICC encoding and are only
# consumed by this module and by verifier.py (which checks the top tag only).
_TAG_AS_EUICC_SIGNED1 = 0x80
_TAG_AS_EUICC_SIGNATURE1 = 0x81
_TAG_AS_EUICC_CERT = 0x82
_TAG_AS_EUM_CERT = 0x83
_TAG_AS_EUICC_OTPK = 0x84


class _EuiccLike(Protocol):
    def get_euicc_challenge(self) -> bytes: ...
    def get_euicc_info1(self, ci_pkid: bytes) -> bytes: ...
    def dispatch_apdu(self, command_wire: bytes, ci_pkid: bytes | None = ...) -> bytes: ...
    def authenticate_server(
        self,
        transaction_id: bytes,
        server_signed1: bytes,
        server_signature1: bytes,
        server_cert_der: bytes,
        ci_cert: x509.Certificate,
        ctx_params1: bytes = ...,
    ) -> dict: ...
    def verify_smdp_signature2(
        self, smdp_signed2: bytes, smdp_signature2: bytes,
        smdp_pb_cert_der: bytes, ci_cert: x509.Certificate,
    ) -> None: ...
    def install_bound_profile_package(self, bpp: dict) -> bytes: ...
    def get_eid(self) -> str: ...


class _SmDpLike(Protocol):
    def initiate_authentication(
        self, euicc_challenge: bytes, euicc_info1: bytes, smdp_address: str
    ) -> dict: ...
    def authenticate_client(
        self, req: dict, ci_cert: x509.Certificate, authenticated_eid: str | None = ...,
    ) -> dict: ...
    def get_bound_profile_package(self, transaction_id_hex: str) -> dict: ...
    def handle_notification(self, notification: bytes, seq: int, euicc_cert_der: bytes) -> None: ...


def _encode_authenticate_server_resp(result: dict) -> bytes:
    return tlv.encode_constructed(codec.TAG_AUTHENTICATE_SERVER, [
        tlv.encode(_TAG_AS_EUICC_SIGNED1, result["euiccSigned1"]),
        tlv.encode(_TAG_AS_EUICC_SIGNATURE1, result["euiccSignature1"]),
        tlv.encode(_TAG_AS_EUICC_CERT, result["euiccCertificate"]),
        tlv.encode(_TAG_AS_EUM_CERT, result["eumCertificate"]),
        tlv.encode(_TAG_AS_EUICC_OTPK, result["euiccOtpk"]),
    ])


def _decode_authenticate_server_resp(wire: bytes) -> dict:
    top = tlv.find(tlv.walk(wire), codec.TAG_AUTHENTICATE_SERVER)
    if top is None:
        raise ValueError("AuthenticateServer.resp: missing top-level tag")

    def _child(tag: int, label: str) -> bytes:
        node = tlv.find(top.children, tag)
        if node is None:
            raise ValueError(f"AuthenticateServer.resp: missing {label} (tag {tag:#x})")
        return node.value

    return {
        "euiccSigned1": _child(_TAG_AS_EUICC_SIGNED1, "euiccSigned1"),
        "euiccSignature1": _child(_TAG_AS_EUICC_SIGNATURE1, "euiccSignature1"),
        "euiccCertificate": _child(_TAG_AS_EUICC_CERT, "euiccCertificate"),
        "eumCertificate": _child(_TAG_AS_EUM_CERT, "eumCertificate"),
        "euiccOtpk": _child(_TAG_AS_EUICC_OTPK, "euiccOtpk"),
    }


def _decode_iccid(raw: bytes) -> str:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return raw.hex()
    return text if text.isprintable() else raw.hex()


class Lpa:
    def __init__(self, euicc: _EuiccLike, smdp: _SmDpLike, bus: Bus, ci_cert: x509.Certificate) -> None:
        self.euicc = euicc
        self.smdp = smdp
        self.bus = bus
        self.ci_cert = ci_cert

    def download_profile(self, activation_code: str) -> dict:
        ac = self._send_activation_code(activation_code)
        euicc_challenge = self._get_euicc_challenge()
        euicc_info1_wire = self._get_euicc_info1()
        init_resp = self._initiate_authentication(euicc_challenge, euicc_info1_wire, ac.smdp_address)
        self._verify_oid_pin(ac, init_resp["serverCertificate"])
        auth_fields = self._authenticate_server(init_resp, ac.matching_id)
        auth_client_resp = self._authenticate_client(init_resp["transactionId"], auth_fields)
        self.euicc.verify_smdp_signature2(
            codec.unb64(auth_client_resp["smdpSigned2"]),
            codec.unb64(auth_client_resp["smdpSignature2"]),
            codec.unb64(auth_client_resp["smdpPbCertificate"]),
            self.ci_cert,
        )
        bpp_resp = self._get_bound_profile_package(auth_client_resp["transactionId"])
        install_wire = self._install_profile(bpp_resp["boundProfilePackage"])
        self._handle_notification(install_wire, auth_fields["euiccCertificate"])
        iccid, profile_name = self._parse_metadata_preview(bpp_resp["boundProfilePackage"]["metadataPreview"])
        return {
            "installed": True,
            "iccid": iccid,
            "profileName": profile_name,
            "eid": self.euicc.get_eid(),
        }

    def _verify_oid_pin(self, ac: ActivationCode, server_certificate_b64: str) -> None:
        """SGP.22 SS3.0.1 step 10: 'If the SM-XX is an SM-DP+ and if its OID was
        provided earlier, verify the OID.' Conditional -- only enforced when the
        activation code actually carried an OID; most consumer ACs don't (SS4.1
        makes it optional), so this is narrow protection, not a general fix for
        D4-style SM-DP+ substitution. If the AC itself is attacker-controlled the
        attacker can rewrite the OID field too -- this only helps when the OID
        reaches the LPA through a channel the AC-tampering attacker doesn't control."""
        if not ac.oid:
            return
        server_cert = x509.load_der_x509_certificate(codec.unb64(server_certificate_b64))
        cert_oid = certificate_registered_oid(server_cert)
        if cert_oid != ac.oid:
            raise ValueError(
                f"serverOidMismatch: activation code pinned OID {ac.oid!r}, "
                f"server certificate carries {cert_oid!r}"
            )

    # --- C2a --------------------------------------------------------------
    def _send_activation_code(self, activation_code: str) -> ActivationCode:
        sent = self.bus.send(Message(
            channel=C2A, direction="device->lpa", kind="ActivationCode",
            wire=activation_code.encode("utf-8"), encoding="text",
        ))
        return ActivationCode.parse(sent.wire.decode("utf-8"))

    # --- C3 / C2b -----------------------------------------------------------
    def _send_c3(self, kind: str, wire: bytes) -> Message:
        return self.bus.send(Message(
            channel=C3, direction="euicc->lpa", kind=kind, wire=wire, encoding="apdu",
        ))

    def _es10_get(self, kind: str, command_wire: bytes) -> bytes:
        """Send a no-input ES10 command across the modem APDU transport (C2b) into
        the eUICC's real command parser (dispatch_apdu), then carry the response
        back over C2b (transport) and C3 (ES10 logical). Every leg is bus-routed,
        so a C2b or C3 mutator can rewrite either the command the card parses or
        the response the LPA parses -- the on-device / rooted-baseband boundary
        this project targets. A malformed command surfaces as an eUICC status word."""
        cmd = self.bus.send(Message(
            channel=C2B, direction="lpa->modem", kind=f"{kind}.cmd",
            wire=command_wire, encoding="apdu",
        ))
        resp_wire = self.euicc.dispatch_apdu(cmd.wire, self._ci_public_key_id())
        r2b = self.bus.send(Message(
            channel=C2B, direction="modem->lpa", kind=f"{kind}.resp",
            wire=resp_wire, encoding="apdu",
        ))
        sent = self._send_c3(kind, r2b.wire)
        return sent.wire

    def _ci_public_key_id(self) -> bytes:
        spki = self.ci_cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashes.Hash(hashes.SHA1())
        digest.update(spki)
        return digest.finalize()

    def _get_euicc_challenge(self) -> bytes:
        wire = self._es10_get("GetEUICCChallenge.resp", codec.apdu_get_euicc_challenge())
        top = tlv.find(tlv.walk(wire), codec.TAG_GET_EUICC_CHALLENGE)
        if top is None:
            raise ValueError("GetEUICCChallenge.resp: missing top-level tag")
        inner = tlv.find(top.children, 0x80)
        if inner is None:
            raise ValueError("GetEUICCChallenge.resp: missing challenge value (tag 0x80)")
        return inner.value

    def _get_euicc_info1(self) -> bytes:
        return self._es10_get("GetEUICCInfo1.resp", codec.apdu_get_euicc_info1())

    def get_eid(self) -> str:
        """ES10c.GetEID, standalone (not part of the download flow): plaintext,
        unsigned per SGP.22 SS5.7.20 -- a local MITM can read or spoof it freely."""
        wire = self._es10_get("GetEID.resp", codec.apdu_get_eid())
        return codec.parse_eid_response(wire)

    def enable_profile(self, iccid: str) -> None:
        self._es10_get("EnableProfile.resp", codec.apdu_enable_profile(bytes.fromhex(iccid)))

    def disable_profile(self, iccid: str) -> None:
        self._es10_get("DisableProfile.resp", codec.apdu_disable_profile(bytes.fromhex(iccid)))

    def delete_profile(self, iccid: str) -> None:
        self._es10_get("DeleteProfile.resp", codec.apdu_delete_profile(bytes.fromhex(iccid)))

    def memory_reset(self) -> None:
        self._es10_get("EuiccMemoryReset.resp", codec.apdu_memory_reset())

    def discover(self, smds) -> list[dict[str, str]]:
        """SM-DS discovery (SGP.22 SS3.6). A device can only query its OWN
        eUICC-attested EID: real ES11 binds the discovered EID to the eUICC
        signature in AuthenticateClient, so there is no way to ask for another
        device's EID. Returns the eventEntries list (empty when nothing is
        registered). See testbed/ping-sm-ds/notes/03-eid-enumeration.md."""
        return smds.discover(self.get_eid())

    def _authenticate_server(self, init_resp: dict, matching_id: str) -> dict:
        transaction_id = bytes.fromhex(init_resp["transactionId"])
        server_signed1 = codec.unb64(init_resp["serverSigned1"])
        server_signature1 = codec.unb64(init_resp["serverSignature1"])
        server_cert_der = codec.unb64(init_resp["serverCertificate"])
        ctx_params1 = codec.ctx_params1(matching_id)
        result = self.euicc.authenticate_server(
            transaction_id, server_signed1, server_signature1, server_cert_der, self.ci_cert,
            ctx_params1,
        )
        sent = self._send_c3("AuthenticateServer.resp", _encode_authenticate_server_resp(result))
        return _decode_authenticate_server_resp(sent.wire)

    def _install_profile(self, bpp: dict) -> bytes:
        wire = self.euicc.install_bound_profile_package(bpp)
        sent = self._send_c3("ProfileInstallResult", wire)
        return sent.wire

    # --- C1 -----------------------------------------------------------------
    def _send_c1(self, kind: str, direction: str, obj: dict) -> dict:
        sent = self.bus.send(Message(
            channel=C1, direction=direction, kind=kind,
            wire=codec.to_json_wire(obj), encoding="json",
        ))
        return codec.from_json_wire(sent.wire)

    def _initiate_authentication(self, euicc_challenge: bytes, euicc_info1_wire: bytes, smdp_address: str) -> dict:
        req = {
            "func": "InitiateAuthentication",
            "euiccChallenge": codec.b64(euicc_challenge),
            "euiccInfo1": codec.b64(euicc_info1_wire),
            "smdpAddress": smdp_address,
        }
        req_used = self._send_c1("InitiateAuthentication.req", "lpa->smdp", req)
        # Consume the (possibly mutated) request so a C1 mutator actually reaches the
        # SM-DP+ -- earlier this call used the pre-mutation locals and silently ignored
        # any tampering of euiccChallenge / euiccInfo1 / smdpAddress.
        resp = self.smdp.initiate_authentication(
            codec.unb64(req_used["euiccChallenge"]),
            codec.unb64(req_used["euiccInfo1"]),
            req_used["smdpAddress"],
        )
        return self._send_c1("InitiateAuthentication.resp", "smdp->lpa", resp)

    def _authenticate_client(self, transaction_id_hex: str, auth_fields: dict) -> dict:
        req = {
            "func": "AuthenticateClient",
            "transactionId": transaction_id_hex,
            "euiccSigned1": codec.b64(auth_fields["euiccSigned1"]),
            "euiccSignature1": codec.b64(auth_fields["euiccSignature1"]),
            "euiccCertificate": codec.b64(auth_fields["euiccCertificate"]),
            "eumCertificate": codec.b64(auth_fields["eumCertificate"]),
            "euiccOtpk": codec.b64(auth_fields["euiccOtpk"]),
        }
        req_used = self._send_c1("AuthenticateClient.req", "lpa->smdp", req)
        # authenticated_eid models the out-of-band/cert-embedded EID a real
        # deployment would bind an EID-bound order to; see smdp.py's
        # authenticate_client docstring for the caveat that this isn't yet
        # carried on the wire in our PKI model. A no-op for unbound orders.
        resp = self.smdp.authenticate_client(req_used, self.ci_cert, authenticated_eid=self.euicc.get_eid())
        return self._send_c1("AuthenticateClient.resp", "smdp->lpa", resp)

    def _get_bound_profile_package(self, transaction_id_hex: str) -> dict:
        req = {"func": "GetBoundProfilePackage", "transactionId": transaction_id_hex}
        req_used = self._send_c1("GetBoundProfilePackage.req", "lpa->smdp", req)
        bpp = self.smdp.get_bound_profile_package(req_used["transactionId"])
        envelope = {"transactionId": req_used["transactionId"], "boundProfilePackage": bpp}
        return self._send_c1("GetBoundProfilePackage.resp", "smdp->lpa", envelope)

    def _handle_notification(self, install_result_wire: bytes, euicc_cert_der: bytes) -> None:
        # The LPA is a blind relay here (SGP.22 SS2.5.6): it reads the claimed seq to
        # build the envelope, but trusting seq/finalResult is the SM-DP+'s job, via
        # euiccSignPIR verification -- see SmDpPlus.handle_notification.
        _transaction_id, seq, _ok, _sig = codec.parse_profile_installation_result(install_result_wire)
        req = {
            "func": "HandleNotification",
            "notification": codec.b64(install_result_wire),
            "seq": seq,
            "euiccCertificate": codec.b64(euicc_cert_der),
        }
        req_used = self._send_c1("HandleNotification.req", "lpa->smdp", req)
        self.smdp.handle_notification(
            codec.unb64(req_used["notification"]),
            req_used["seq"],
            codec.unb64(req_used["euiccCertificate"]),
        )

    # --- misc -----------------------------------------------------------------
    def _parse_metadata_preview(self, metadata_preview_b64: str) -> tuple[str, str]:
        wire = codec.unb64(metadata_preview_b64)
        top = tlv.find(tlv.walk(wire), codec.TAG_STORE_METADATA)
        if top is None:
            raise ValueError("metadataPreview: missing top-level tag")
        iccid_node = tlv.find(top.children, codec.TAG_ICCID)
        name_node = tlv.find(top.children, codec.TAG_PROFILE_NAME)
        if iccid_node is None or name_node is None:
            raise ValueError("metadataPreview: missing ICCID or profile name field")
        return _decode_iccid(iccid_node.value), name_node.value.decode("utf-8")
