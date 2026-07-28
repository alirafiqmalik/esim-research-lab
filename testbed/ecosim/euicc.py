"""Software model of the eUICC (ISD-R) side of the SGP.22 profile-download flow.

Holds every piece of state a real eUICC chip would hold across the handshake:
the stored eUICC challenge, the per-transaction ephemeral keypair/peer point,
the installed-profile list, and the notification sequence counter. Nothing here
is global -- it all lives on the ``SoftwareEuicc`` instance so multiple
simulated cards can run side by side in the same process.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec

from . import codec, crypto, protocol, tlv
from .pki import PKI, eid_from_certificate, require_role, verify_chain


def _read_len_fields(data: bytes) -> list[bytes]:
    """Inverse of protocol.concat_len: split a 2-byte-length-prefixed blob."""
    fields: list[bytes] = []
    i = 0
    n = len(data)
    while i < n:
        if i + 2 > n:
            raise ValueError("truncated length prefix")
        length = int.from_bytes(data[i:i + 2], "big")
        i += 2
        if i + length > n:
            raise ValueError("field overruns buffer")
        fields.append(data[i:i + length])
        i += length
    return fields


class EuiccApduError(ValueError):
    """A card-level rejection of an ES10 command, carrying an ISO 7816 status word."""

    def __init__(self, sw: int, message: str) -> None:
        super().__init__(f"SW={sw:04X}: {message}")
        self.sw = sw


@dataclass
class InstalledProfile:
    iccid: str
    name: str
    enabled: bool = False
    ppr_no_delete: bool = False  # Profile Policy Rule set by the profile owner at install time


class SoftwareEuicc:
    """In-memory eUICC: challenge/authenticate/install flow, ES10 side."""

    def __init__(self, pki: PKI, rng: random.Random) -> None:
        self._pki = pki
        self._rng = rng
        # EID comes from the eUICC certificate (SGP.22 SS4.3.1: it lives in
        # subject.serialNumber), the same copy that leaks over C1 in
        # AuthenticateClient.req -- so GetEID and the cert always agree.
        self._eid: str = eid_from_certificate(pki.euicc.certificate)
        self._challenge: bytes | None = None
        self._installed: list[InstalledProfile] = []
        self._notification_seq: int = 0
        # Per-transaction context, populated by authenticate_server().
        self._euicc_otsk: ec.EllipticCurvePrivateKey | None = None
        self._server_otpk: ec.EllipticCurvePublicKey | None = None

    def get_eid(self) -> str:
        return self._eid

    def get_euicc_challenge(self) -> bytes:
        self._challenge = bytes(self._rng.getrandbits(8) for _ in range(16))
        return codec.euicc_challenge_response(self._challenge)

    def get_euicc_info1(self, ci_pkid: bytes) -> bytes:
        return codec.euicc_info1(svn=b"\x02\x02\x00", ci_pkid=ci_pkid)

    def dispatch_apdu(self, command_wire: bytes, ci_pkid: bytes | None = None) -> bytes:
        """Parse a raw ES10 command APDU and route it, the way a real ISD-R applet
        decodes the incoming BER-TLV before acting. Malformed or unsupported
        commands raise EuiccApduError carrying a status word, mirroring a real
        chip's error SW instead of crashing. This is the parser surface a C3/C2b
        command fuzzer exercises (as opposed to the response-side typed methods)."""
        try:
            nodes = tlv.walk(command_wire)
        except tlv.TLVError as exc:
            raise EuiccApduError(0x6A80, f"unparsable command TLV: {exc}") from exc
        if not nodes:
            raise EuiccApduError(0x6700, "empty command")
        if len(nodes) != 1:
            raise EuiccApduError(0x6A80, f"expected a single command TLV, got {len(nodes)}")
        cmd = nodes[0]
        if cmd.tag == codec.TAG_GET_EUICC_CHALLENGE:
            return self.get_euicc_challenge()
        if cmd.tag == codec.TAG_GET_EUICC_INFO1:
            return self.get_euicc_info1(ci_pkid if ci_pkid is not None else self._pki.ci_public_key_id())
        if cmd.tag == codec.TAG_GET_EID:
            # SGP.22 SS5.7.20: GetEID is plaintext and unsigned even in the real
            # protocol -- there is no cryptographic protection to model here, this
            # response is exactly as exposed on a real local ES10c bus.
            return codec.eid_response(self._eid)
        if cmd.tag in (codec.TAG_ENABLE_PROFILE, codec.TAG_DISABLE_PROFILE, codec.TAG_DELETE_PROFILE):
            return self._lifecycle_command(cmd)
        if cmd.tag == codec.TAG_MEMORY_RESET:
            # SGP.22 SS5.7.19: deletes "regardless of ... any Profile Policy Rules" --
            # deliberately bypasses the ppr_no_delete check DeleteProfile respects below.
            self._installed.clear()
            return codec.lifecycle_result(codec.TAG_MEMORY_RESET, True)
        raise EuiccApduError(0x6A88, f"unsupported/unknown ES10 command tag {cmd.tag:#x}")

    def _lifecycle_command(self, cmd: tlv.TLV) -> bytes:
        """Post-install profile management: purely local, ICCID-keyed, no
        additional authorization beyond ES10c/APDU access -- modeled this way
        pending spec confirmation of whether SGP.22 requires anything more."""
        iccid_node = tlv.find(cmd.children, codec.TAG_ICCID)
        if iccid_node is None:
            raise EuiccApduError(0x6A80, "lifecycle command missing ICCID")
        iccid = iccid_node.value.hex()
        profile = next((p for p in self._installed if p.iccid == iccid), None)
        if profile is None:
            raise EuiccApduError(0x6A88, f"no installed profile with iccid {iccid}")
        if cmd.tag == codec.TAG_ENABLE_PROFILE:
            for p in self._installed:
                p.enabled = False  # SGP.22: at most one profile enabled at a time
            profile.enabled = True
        elif cmd.tag == codec.TAG_DISABLE_PROFILE:
            profile.enabled = False
        elif cmd.tag == codec.TAG_DELETE_PROFILE:
            if profile.enabled:
                raise EuiccApduError(0x6985, "cannot delete the currently enabled profile")
            if profile.ppr_no_delete:
                raise EuiccApduError(0x6985, "disallowedByPolicy: Profile Policy Rules forbid deletion")
            self._installed.remove(profile)
        return codec.lifecycle_result(cmd.tag, True)

    def authenticate_server(
        self,
        transaction_id: bytes,
        server_signed1: bytes,
        server_signature1: bytes,
        server_cert_der: bytes,
        ci_cert: x509.Certificate,
        ctx_params1: bytes = b"",
    ) -> dict[str, bytes]:
        if self._challenge is None:
            raise ValueError("no eUICC challenge outstanding")

        fields = _read_len_fields(server_signed1)
        if len(fields) != 4:
            raise ValueError(f"serverSigned1: expected 4 fields, got {len(fields)}")
        _tx_id_field, euicc_challenge_field, _smdp_address_field, server_otpk_field = fields

        if euicc_challenge_field != self._challenge:
            raise ValueError("serverSigned1 euiccChallenge does not match stored challenge")

        server_cert = x509.load_der_x509_certificate(server_cert_der)
        if not verify_chain(server_cert, ci_cert):
            raise ValueError("server certificate does not chain to the given CI certificate")
        # SGP.22 SS5.7.13: "Verify that the RSP Server Certificate is either a
        # CERT.DPauth.SIG or a CERT.DSauth.SIG ... Otherwise return invalidOid" --
        # a cert that chains fine but was issued for a different role (e.g. an EUM
        # cert) must still be rejected. We only model the DP-auth role here.
        require_role(server_cert, "dp_auth")
        if not crypto.verify(server_cert.public_key(), server_signature1, server_signed1):
            raise ValueError("serverSignature1 verification failed")

        server_otpk = protocol.load_point(server_otpk_field)
        self._server_otpk = server_otpk

        otsk = crypto.ephemeral_keypair()
        self._euicc_otsk = otsk
        euicc_otpk_bytes = protocol.point_bytes(otsk)

        euicc_info1 = self.get_euicc_info1(self._pki.ci_public_key_id())
        # SGP.22 SS5.7.13: the eUICC "SHALL neither check the values provided in
        # ctxParams1 ... nor correlate them" -- it signs whatever the LPA supplied.
        # That unchecked signing is precisely the confused-deputy surface we test;
        # the SM-DP+ order lookup is the only backstop.
        euicc_signed1 = protocol.euicc_signed1(
            transaction_id, self._challenge, euicc_otpk_bytes, euicc_info1, ctx_params1
        )
        euicc_signature1 = crypto.sign(self._pki.euicc.private_key, euicc_signed1)

        return {
            "euiccSigned1": euicc_signed1,
            "euiccSignature1": euicc_signature1,
            "euiccCertificate": self._pki.euicc.cert_der(),
            "eumCertificate": self._pki.eum.cert_der(),
            "euiccOtpk": euicc_otpk_bytes,
            "ctxParams1": ctx_params1,
        }

    def verify_smdp_signature2(
        self,
        smdp_signed2: bytes,
        smdp_signature2: bytes,
        smdp_pb_cert_der: bytes,
        ci_cert: x509.Certificate,
    ) -> None:
        """SGP.22 SS5.7.5-shaped PrepareDownload check: verify the SM-DP+'s
        profile-binding signature (SK.DPpb.SIG, distinct from the DPauth key used
        in AuthenticateServer) over smdpSigned2 before trusting the binding, and
        confirm the bppEuiccOtpk it names is actually this eUICC's own ephemeral
        key -- i.e. this profile package was bound to THIS session, not replayed
        or redirected from another. Raises ValueError on any failure."""
        if self._euicc_otsk is None:
            raise ValueError("no active transaction: authenticate_server was not completed")

        smdp_pb_cert = x509.load_der_x509_certificate(smdp_pb_cert_der)
        if not verify_chain(smdp_pb_cert, ci_cert):
            raise ValueError("SM-DP+ profile-binding certificate does not chain to the given CI")
        require_role(smdp_pb_cert, "dp_pb")
        if not crypto.verify(smdp_pb_cert.public_key(), smdp_signature2, smdp_signed2):
            raise ValueError("smdpSignature2 verification failed")

        fields = _read_len_fields(smdp_signed2)
        if len(fields) != 3:
            raise ValueError(f"smdpSigned2: expected 3 fields, got {len(fields)}")
        _tx_id_field, _cc_required_field, bpp_euicc_otpk_field = fields
        if bpp_euicc_otpk_field != protocol.point_bytes(self._euicc_otsk):
            raise ValueError("smdpSigned2 bppEuiccOtpk does not match this eUICC's ephemeral key")

    def install_bound_profile_package(self, bpp: dict) -> bytes:
        if self._euicc_otsk is None:
            raise ValueError("no active transaction: authenticate_server was not completed")

        transaction_id_bytes = bytes.fromhex(bpp["transactionId"])
        server_otpk = protocol.load_point(codec.unb64(bpp["serverOtpk"]))
        session_key = protocol.session_key(self._euicc_otsk, server_otpk, transaction_id_bytes)

        sealed = codec.unb64(bpp["sealedProfile"])
        try:
            plaintext = protocol.open_profile(session_key, sealed, aad=transaction_id_bytes)
        except InvalidTag as exc:
            raise ValueError("bound profile package failed AEAD integrity check") from exc

        parts = plaintext.split(b"||", 1)
        if len(parts) != 2:
            raise ValueError("sealed profile payload missing store-metadata separator")
        metadata_wire, _profile_body = parts

        nodes = tlv.walk(metadata_wire)
        metadata = tlv.find(nodes, codec.TAG_STORE_METADATA)
        if metadata is None:
            raise ValueError("sealed profile payload missing StoreMetadata TLV")
        iccid_tlv = tlv.find(metadata.children, codec.TAG_ICCID)
        name_tlv = tlv.find(metadata.children, codec.TAG_PROFILE_NAME)
        if iccid_tlv is None or name_tlv is None:
            raise ValueError("StoreMetadata missing ICCID or profile name")

        iccid = iccid_tlv.value.hex()  # ICCID travels as BCD semi-octets, not ASCII
        profile_name = name_tlv.value.decode("utf-8")
        self._installed.append(InstalledProfile(iccid=iccid, name=profile_name))
        self._notification_seq += 1

        self._euicc_otsk = None
        self._server_otpk = None
        self._challenge = None

        # SGP.22 SS2.5.6: ProfileInstallationResult SHALL carry euiccSignPIR, an
        # eUICC signature (SK.EUICC.SIG) over profileInstallationResultData -- the
        # sequence number and final result are inside that signed envelope, not left
        # bare the way an earlier version of this model had them.
        pir_data = codec.profile_installation_result_data(
            transaction_id_bytes, self._notification_seq, ok=True
        )
        signature = crypto.sign(self._pki.euicc.private_key, pir_data)
        return codec.profile_installation_result(pir_data, signature)
