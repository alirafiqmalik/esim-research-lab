"""Simulated SM-DP+ (SGP.22 ES9+/ES8+ server side).

Owns the order registry (what ES2+ registered with the operator) and the
per-transaction state needed to carry a download from InitiateAuthentication
through GetBoundProfilePackage. Everything here mirrors the byte-for-byte
layouts in `protocol.py` so the eUICC side can verify what this class signs.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from . import codec, crypto, protocol
from .pki import PKI, require_role, verify_chain


@dataclass
class Order:
    matching_id: str
    iccid: str
    profile_name: str
    sp_name: str
    profile_class: int
    # Optional ES2+ EID-binding practice (SGP.22 order-binding via the eid
    # parameter): when set, only the eUICC holding this EID may consume the
    # order. None reproduces the (default, more common) matchingId-only
    # ordering flow with no per-device binding.
    eid: str | None = None


@dataclass
class _Transaction:
    server_otsk: ec.EllipticCurvePrivateKey
    euicc_challenge: bytes
    euicc_otpk: bytes | None = None
    order: Order | None = None


class SmDpPlus:
    """SM-DP+ role: authenticates the eUICC and hands it a bound profile package."""

    def __init__(self, pki: PKI, rng: random.Random, address: str = "smdp.ecosim.test") -> None:
        self.pki = pki
        self.rng = rng
        self.address = address
        self._orders: dict[str, Order] = {}
        self._transactions: dict[str, _Transaction] = {}
        self._notifications: list[tuple[int, bytes]] = []

    def register_order(
        self,
        matching_id: str,
        iccid: str,
        profile_name: str,
        sp_name: str,
        profile_class: int,
        eid: str | None = None,
    ) -> None:
        self._orders[matching_id] = Order(
            matching_id=matching_id,
            iccid=iccid,
            profile_name=profile_name,
            sp_name=sp_name,
            profile_class=profile_class,
            eid=eid,
        )

    def initiate_authentication(
        self, euicc_challenge: bytes, euicc_info1: bytes, smdp_address: str
    ) -> dict:
        """ES9+ InitiateAuthentication: sign ServerSigned1 with the DPauth key."""
        transaction_id = self.rng.randbytes(16)
        transaction_id_hex = transaction_id.hex()

        server_otsk = crypto.ephemeral_keypair()
        server_otpk = protocol.point_bytes(server_otsk)

        server_signed1 = protocol.server_signed1(
            transaction_id, euicc_challenge, smdp_address.encode("utf-8"), server_otpk
        )
        server_signature1 = crypto.sign(self.pki.dp_auth.private_key, server_signed1)

        self._transactions[transaction_id_hex] = _Transaction(
            server_otsk=server_otsk, euicc_challenge=euicc_challenge
        )

        return {
            "transactionId": transaction_id_hex,
            "serverSigned1": codec.b64(server_signed1),
            "serverSignature1": codec.b64(server_signature1),
            "serverCertificate": codec.b64(self.pki.dp_auth.cert_der()),
            "euiccCiPKIdToBeUsed": codec.b64(self.pki.ci_public_key_id()),
            "serverOtpk": codec.b64(server_otpk),
        }

    def authenticate_client(
        self, req: dict, ci_cert: x509.Certificate, authenticated_eid: str | None = None,
    ) -> dict:
        """ES9+ AuthenticateClient: verify the eUICC's cert chain + signature.

        ``authenticated_eid`` stands in for whatever out-of-band/cert-embedded
        EID a real deployment would bind an order to (our pki.py certs don't
        carry a per-device EID -- there is one shared eUICC keypair -- so this
        is threaded in directly by the caller rather than parsed off the wire;
        see campaign D1-D2-eid-binding-contrast for the honest caveat). Callers
        that omit it reproduce the default matchingId-only order lookup.

        Raises ValueError if the transaction is unknown or any verification fails.
        """
        transaction_id_hex = req["transactionId"]
        tx = self._transactions.get(transaction_id_hex)
        if tx is None:
            raise ValueError(f"unknown transactionId {transaction_id_hex!r}")

        euicc_cert = x509.load_der_x509_certificate(codec.unb64(req["euiccCertificate"]))
        eum_cert = x509.load_der_x509_certificate(codec.unb64(req["eumCertificate"]))

        if not (verify_chain(euicc_cert, eum_cert) and verify_chain(eum_cert, ci_cert)):
            raise ValueError("eUICC certificate chain does not verify to the given CI")
        require_role(euicc_cert, "euicc")
        require_role(eum_cert, "eum")

        euicc_signed1 = codec.unb64(req["euiccSigned1"])
        euicc_signature1 = codec.unb64(req["euiccSignature1"])
        if not crypto.verify(euicc_cert.public_key(), euicc_signature1, euicc_signed1):
            raise ValueError("euiccSignature1 does not verify over euiccSigned1")

        tx.euicc_otpk = codec.unb64(req["euiccOtpk"])

        if not self._orders:
            raise ValueError("no registered order for this SM-DP+")
        # SGP.22 SS3.1.3 step 3: the SM-DP+ binds the session to the pending order
        # named by the eUICC-attested matchingId. This is the sole backstop against
        # a matchingId the LPA/eUICC hop may have tampered (the eUICC never checks it).
        order = self._select_order(euicc_signed1, authenticated_eid)
        tx.order = order

        profile_metadata = codec.store_metadata(
            bytes.fromhex(order.iccid), order.profile_name, order.sp_name, order.profile_class
        )
        transaction_id = bytes.fromhex(transaction_id_hex)
        # SmdpSigned2 per SGP.22 SS5.7.5 = {transactionId, ccRequiredFlag, bppEuiccOtpk};
        # profileMetadata is deliberately NOT covered (the plaintext-consent gap, SS4.4).
        cc_required_flag = b"\x00"
        smdp_signed2 = protocol.concat_len(transaction_id, cc_required_flag, tx.euicc_otpk)
        smdp_signature2 = crypto.sign(self.pki.dp_pb.private_key, smdp_signed2)

        return {
            "transactionId": transaction_id_hex,
            "profileMetadata": codec.b64(profile_metadata),
            "smdpSigned2": codec.b64(smdp_signed2),
            "smdpSignature2": codec.b64(smdp_signature2),
            "smdpPbCertificate": codec.b64(self.pki.dp_pb.cert_der()),
        }

    def _select_order(self, euicc_signed1: bytes, authenticated_eid: str | None = None) -> Order:
        """Recover the eUICC-attested matchingId from euiccSigned1 and look up its order.

        euiccSigned1 = concat_len(transactionId, euiccChallenge, euiccOtpk, euiccInfo1,
        ctxParams1). A conformant SM-DP+ serves only the order matching the id; an
        unknown id is rejected (there is no "serve any order" fallback in reality).

        If the order carries an `eid` (an EID-bound ES2+ order), it may only be
        consumed by the eUICC that authenticated as that EID -- this is the
        contrast case to the default matchingId-only lookup above: it closes
        the matchingId confused-deputy surface (D1/D2) for any order an
        operator chose to bind, at the cost of requiring EID to be known and
        supplied at order time."""
        fields = protocol.read_len_fields(euicc_signed1)
        ctx = fields[4] if len(fields) >= 5 else b""
        if not ctx:
            raise ValueError("AuthenticateClient: euiccSigned1 carries no ctxParams1/matchingId")
        matching_id = codec.parse_matching_id(ctx)
        order = self._orders.get(matching_id)
        if order is None:
            raise ValueError(f"no pending order for matchingId {matching_id!r}")
        if order.eid is not None and order.eid != authenticated_eid:
            raise ValueError(
                f"eidMismatch: order for matchingId {matching_id!r} is bound to eid "
                f"{order.eid!r}, but the authenticating eUICC reports eid {authenticated_eid!r}"
            )
        return order

    def get_bound_profile_package(
        self, transaction_id_hex: str, profile_body: bytes = b"PROFILE"
    ) -> dict:
        """ES9+ GetBoundProfilePackage: seal the profile under the ES8+ session key."""
        tx = self._transactions.get(transaction_id_hex)
        if tx is None:
            raise ValueError(f"unknown transactionId {transaction_id_hex!r}")
        if tx.euicc_otpk is None or tx.order is None:
            raise ValueError("transaction has not completed AuthenticateClient yet")

        transaction_id = bytes.fromhex(transaction_id_hex)
        session_key = protocol.session_key(
            tx.server_otsk, protocol.load_point(tx.euicc_otpk), transaction_id
        )

        order = tx.order
        store_metadata_wire = codec.store_metadata(
            bytes.fromhex(order.iccid), order.profile_name, order.sp_name, order.profile_class
        )
        sealed = protocol.seal_profile(
            session_key, store_metadata_wire + b"||" + profile_body, aad=transaction_id
        )

        return {
            "transactionId": transaction_id_hex,
            "serverOtpk": codec.b64(protocol.point_bytes(tx.server_otsk)),
            "sealedProfile": codec.b64(sealed),
            "metadataPreview": codec.b64(store_metadata_wire),
        }

    def handle_notification(self, notification: bytes, seq: int, euicc_cert_der: bytes) -> None:
        """ES9+ HandleNotification: verify euiccSignPIR before trusting anything in it.

        SGP.22 SS2.5.6 mandates ProfileInstallationResult carries a mandatory eUICC
        signature over profileInstallationResultData (seqNumber and finalResult
        included) -- the SM-DP+ is the party expected to check it. A caller-supplied
        `seq` int is accepted only for the message envelope; the verified value from
        the signature is what's actually recorded, and any mismatch or forged claim
        raises rather than being silently trusted.
        """
        euicc_cert = x509.load_der_x509_certificate(euicc_cert_der)
        _transaction_id, verified_seq, ok = codec.verify_profile_installation_result(
            notification, euicc_cert.public_key()
        )
        if verified_seq != seq:
            raise ValueError(
                f"HandleNotification: claimed seq {seq} does not match signed seq {verified_seq}"
            )
        self._notifications.append((verified_seq, notification, ok))
