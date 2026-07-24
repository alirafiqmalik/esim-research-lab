"""Obtain and parse a real ES10b.AuthenticateServer (BF38) command as the fuzz seed.

The fuzzer needs one REAL, valid AuthenticateServer command to mutate. That seed
is produced by running the existing ``authenticate SERVER`` op against a
production SM-DP+ (e.g. ``rsp.truphone.com``) and reading the exact BF38 APDU
constructs back out of the verbose session log.

    esim euicc authenticate rsp.truphone.com
    # -> writes .sessions/esimctl/<ts>-authenticate/logcat.txt with the
    #    OmapiApduInterface "OMAPI APDU:" lines carrying the block-chained BF38.

On the wire the BF38 command does not fit one STORE DATA APDU, so lpac block-
chains it: ``81 E2 11 00 ...`` (P1=0x11, more) through ``81 E2 91 0C ...``
(P1=0x91, last block). :func:`reassemble_blocks` concatenates the block bodies
back into the single BF38 TLV, and :func:`parse_bf38_tlv` splits that into the
four signed/certificate constructs plus the contextual params.

SGP.22 v2.x §5.7.13 / rsp.asn ``AuthenticateServerRequest``::

    BF38 SEQUENCE {
        serverSigned1        SEQUENCE (tag 30) { transactionId[80], euiccChallenge[81],
                                                 serverAddress[83], serverChallenge[84] }
        serverSignature1     [APPLICATION 55] OCTET STRING (tag 5F37, 64-byte ECDSA)
        euiccCiPKIdToBeUsed  SubjectKeyIdentifier (tag 04, 20-byte CI SKI)
        serverCertificate    Certificate (tag 30, X.509 DER)
        ctxParams1           CHOICE (tag A0)
    }

The actual capture happens in the gated run phase. This module is built and unit
tested here against a synthetic BF38 (:func:`build_synthetic_command`); it never
touches a device.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import ber

# BF38 component tags, in the order rsp.asn defines them.
TAG_BF38 = 0xBF38
TAG_SERVER_SIGNED1 = 0x30  # SEQUENCE
TAG_SERVER_SIGNATURE1 = 0x5F37  # [APPLICATION 55] OCTET STRING
TAG_EUICC_CI_PKID = 0x04  # OCTET STRING (SubjectKeyIdentifier)
TAG_SERVER_CERTIFICATE = 0x30  # X.509 Certificate SEQUENCE
TAG_CTX_PARAMS1 = 0xA0  # CHOICE [0]

# Inner ServerSigned1 tags.
TAG_TRANSACTION_ID = 0x80
TAG_EUICC_CHALLENGE = 0x81
TAG_SERVER_ADDRESS = 0x83
TAG_SERVER_CHALLENGE = 0x84

INS_STORE_DATA = 0xE2
P1_LAST_BLOCK = 0x80  # bit 8 of STORE DATA P1 marks the final block

_APDU_LINE = re.compile(r"OMAPI APDU:\s*([0-9A-Fa-f]{8,})\s*$")


class SeedError(ValueError):
    """Raised when a seed cannot be parsed into a well-formed BF38 command."""


@dataclass(frozen=True)
class AuthCommand:
    """The five constructs of one AuthenticateServer (BF38) command.

    Each field is the FULL TLV (tag + length + value), so reassembly is a plain
    concatenation and a mutation only has to replace one field.
    """

    server_signed1: bytes
    server_signature1: bytes
    euicc_ci_pkid: bytes
    server_certificate: bytes
    ctx_params1: bytes

    def to_command_tlv(self) -> bytes:
        """The single BF38 TLV (tag + length + value)."""
        body = (
            self.server_signed1
            + self.server_signature1
            + self.euicc_ci_pkid
            + self.server_certificate
            + self.ctx_params1
        )
        return ber.tlv(TAG_BF38, body)

    def to_store_data_apdu(self) -> str:
        """Logical store-data APDU form for the safety layer to classify.

        Returns ``81 E2 91 00 <Lc> <BF38 TLV>``. This is the pre-chaining LOGICAL
        command: on the wire the transport block-chains the BF38 TLV across many
        <=255-byte STORE DATA blocks (see :func:`iter_blocks`). ``safety.classify``
        reads only the INS (E2) and the leading BER-TLV tag (BF38) to reach its
        verdict, so this single-APDU projection classifies identically to the real
        first block. Lc is capped at 0xFF purely as a non-zero placeholder; the
        real per-block Lc is set during chaining.
        """
        tlv_bytes = self.to_command_tlv()
        lc = len(tlv_bytes) if len(tlv_bytes) <= 0xFF else 0xFF
        header = bytes([0x81, INS_STORE_DATA, 0x91, 0x00, lc])
        return (header + tlv_bytes).hex().upper()

    @property
    def server_signature1_value(self) -> bytes:
        """The raw ECDSA signature bytes (tag/len stripped)."""
        return ber.first(self.server_signature1, TAG_SERVER_SIGNATURE1).value

    @property
    def euicc_ci_pkid_value(self) -> bytes:
        """The 20-byte CI SubjectKeyIdentifier (tag/len stripped)."""
        return ber.first(self.euicc_ci_pkid, TAG_EUICC_CI_PKID).value

    @property
    def euicc_challenge(self) -> bytes:
        """The euiccChallenge inside serverSigned1 (binds the command to a nonce)."""
        signed = ber.first(self.server_signed1, TAG_SERVER_SIGNED1).value
        return ber.first(signed, TAG_EUICC_CHALLENGE).value

    @property
    def transaction_id(self) -> bytes:
        """The transactionId inside serverSigned1."""
        signed = ber.first(self.server_signed1, TAG_SERVER_SIGNED1).value
        return ber.first(signed, TAG_TRANSACTION_ID).value


def parse_bf38_tlv(data: bytes) -> AuthCommand:
    """Split a full BF38 TLV into its five constructs.

    ``data`` is the BF38 TLV (starting with tag ``BF38``). Raises SeedError if the
    tag is wrong, a component is missing, or a component tag does not match the
    rsp.asn order.
    """
    fields = ber.walk(data)
    if not fields or fields[0].tag != TAG_BF38:
        raise SeedError("payload does not start with a BF38 tag")
    body = fields[0].value
    components = ber.walk(body)
    if len(components) < 5:
        raise SeedError(
            f"BF38 body has {len(components)} components, expected 5 "
            "(serverSigned1, serverSignature1, euiccCiPKIdToBeUsed, "
            "serverCertificate, ctxParams1)"
        )

    expected = [
        (TAG_SERVER_SIGNED1, "serverSigned1"),
        (TAG_SERVER_SIGNATURE1, "serverSignature1"),
        (TAG_EUICC_CI_PKID, "euiccCiPKIdToBeUsed"),
        (TAG_SERVER_CERTIFICATE, "serverCertificate"),
        (TAG_CTX_PARAMS1, "ctxParams1"),
    ]
    for index, (tag, name) in enumerate(expected):
        if components[index].tag != tag:
            raise SeedError(
                f"component {index} ({name}) has tag "
                f"0x{components[index].tag:X}, expected 0x{tag:X}"
            )

    return AuthCommand(
        server_signed1=components[0].raw,
        server_signature1=components[1].raw,
        euicc_ci_pkid=components[2].raw,
        server_certificate=components[3].raw,
        ctx_params1=components[4].raw,
    )


def reassemble_blocks(apdus: list[bytes]) -> bytes:
    """Concatenate block-chained STORE DATA bodies into the single BF38 TLV.

    ``apdus`` is the ordered list of ``81 E2 P1 P2 Lc <body>`` blocks. Every block
    must be a STORE DATA (INS 0xE2). The BF38 tag opens the first block's body;
    collection stops at the block whose P1 has the last-block bit (0x80) set.
    """
    if not apdus:
        raise SeedError("no APDU blocks to reassemble")

    body = bytearray()
    saw_last = False
    for index, apdu in enumerate(apdus):
        if len(apdu) < 5:
            raise SeedError(f"block {index} shorter than a 5-byte header")
        if apdu[1] != INS_STORE_DATA:
            raise SeedError(f"block {index} is not a STORE DATA (INS 0x{apdu[1]:02X})")
        p1 = apdu[2]
        body += apdu[5:]
        if p1 & P1_LAST_BLOCK:
            saw_last = True
            break
    if not saw_last:
        raise SeedError("no final block (P1 bit 0x80) found in the chain")
    return bytes(body)


def _extract_block_chain(apdu_hexes: list[str]) -> list[bytes]:
    """From all logged STORE DATA APDUs, return the BF38 block chain.

    Finds the first STORE DATA whose body begins with the BF38 tag, then collects
    forward through the last-block marker.
    """
    started = False
    chain: list[bytes] = []
    for hexstr in apdu_hexes:
        try:
            apdu = bytes.fromhex(hexstr)
        except ValueError:
            continue
        if len(apdu) < 5 or apdu[1] != INS_STORE_DATA:
            continue
        body = apdu[5:]
        if not started:
            if body[:2] == bytes([0xBF, 0x38]):
                started = True
                chain.append(apdu)
                if apdu[2] & P1_LAST_BLOCK:
                    break
            continue
        chain.append(apdu)
        if apdu[2] & P1_LAST_BLOCK:
            break
    if not chain:
        raise SeedError("no BF38 block chain found in the log APDUs")
    return chain


def load_seed(path: str | Path) -> AuthCommand:
    """Parse a captured BF38 AuthenticateServer command into an AuthCommand.

    ``path`` is either the ``logcat.txt`` verbose session log written under
    ``.sessions/esimctl/<ts>-authenticate/`` or a plain text file with one
    ``OMAPI APDU:`` line per block. Reassembles the block chain and parses it.
    """
    text = Path(path).read_text(errors="replace")
    apdu_hexes = [m.group(1) for m in (_APDU_LINE.search(line) for line in text.splitlines()) if m]
    if not apdu_hexes:
        raise SeedError(f"no 'OMAPI APDU:' lines in {path}")
    chain = _extract_block_chain(apdu_hexes)
    return parse_bf38_tlv(reassemble_blocks(chain))


def build_synthetic_command() -> AuthCommand:
    """A structurally valid synthetic BF38 for unit tests and generator self-checks.

    Not cryptographically valid (the signature and certificate are filler) but
    shaped exactly like a real AuthenticateServerRequest: a real seed swaps in the
    captured bytes with the same TLV skeleton.
    """
    server_signed1 = ber.tlv(
        TAG_SERVER_SIGNED1,
        ber.tlv(TAG_TRANSACTION_ID, bytes(range(0x10)))
        + ber.tlv(TAG_EUICC_CHALLENGE, bytes(range(0x20, 0x30)))
        + ber.tlv(TAG_SERVER_ADDRESS, b"rsp.truphone.com")
        + ber.tlv(TAG_SERVER_CHALLENGE, bytes(range(0x40, 0x50))),
    )
    server_signature1 = ber.tlv(TAG_SERVER_SIGNATURE1, bytes(range(64)))
    euicc_ci_pkid = ber.tlv(
        TAG_EUICC_CI_PKID,
        bytes.fromhex("81370F5125D0B1D408D4C3B232E6D25E795BEBFB"),
    )
    # A minimal but shape-faithful X.509: outer SEQUENCE holding tbsCertificate,
    # signatureAlgorithm, and a signatureValue BIT STRING (the CI signature the
    # cert-attack class corrupts).
    tbs = ber.tlv(0x30, bytes(range(0x30, 0x60)))
    sig_alg = ber.tlv(0x30, bytes.fromhex("06082A8648CE3D040302"))
    sig_value = ber.tlv(0x03, b"\x00" + bytes(range(0x70, 0xB0)))
    server_certificate = ber.tlv(TAG_SERVER_CERTIFICATE, tbs + sig_alg + sig_value)
    ctx_params1 = ber.tlv(TAG_CTX_PARAMS1, ber.tlv(0x30, ber.tlv(0x81, b"\x00")))
    return AuthCommand(
        server_signed1=server_signed1,
        server_signature1=server_signature1,
        euicc_ci_pkid=euicc_ci_pkid,
        server_certificate=server_certificate,
        ctx_params1=ctx_params1,
    )
