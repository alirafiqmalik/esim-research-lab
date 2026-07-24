"""Malleable-framing / structural / replay fuzzer for ES10b.AuthenticateServer (BF38).

The certificate/signature fuzzer (``authsrv_fuzz``) attacks the CRYPTO gate. This
module attacks the PARSER that runs before, or independently of, that gate: the
BER-TLV framing, the LPA-supplied unsigned ``ctxParams1``, the length encodings,
and the STORE DATA block-chaining. None of these bytes are covered by
ServerSignature1, so the eUICC must parse them to reach the signature check. A
crash, hang, over-large error, unexpected acceptance, or card-state change while
parsing this malleable envelope is an SE-side parser bug.

Design, per ``testing-handbook-skills``:

- ``fuzzing-dictionary``: the SGP.22 sub-TLV tags (matchingId ``80``, deviceInfo
  ``30``, tac ``80``, deviceCapabilities ``A1``, imei ``82``, ctxParams ``A0``)
  are the domain tokens the structural mutators splice, reorder, and duplicate,
  instead of blind byte flips that would never build a parseable BF38.
- ``fuzzing-obstacles``: the obstacle here is the eUICC's own signature/CI check.
  We do NOT bypass it; we keep the signed blobs and the CI-PKID VALUE intact so a
  mutation reaches the parser and (for most classes) the CI-known stage the eUICC
  checks first, exposing framing handling deeper in the pipeline. The mutated
  dimension is the BER length/framing itself (short/long/indefinite/non-minimal/
  over/under-declared) — the classic length-framing obstacle, inverted into an
  attack surface.

Every mutation stays a BF38-tagged STORE DATA logical command: the outer tag is
never changed, so ``safety.classify`` still returns ALLOWED/BF38. The generator
re-verifies this before returning any mutation. Nothing here sends anything.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

import ber
from authsrv_seed import (
    TAG_BF38,
    TAG_EUICC_CI_PKID,
    AuthCommand,
)
from safety import Classification, classify

# --------------------------------------------------------------------------- #
# SGP.22 ctxParams1 / deviceInfo tags (the fuzzing dictionary tokens).
# --------------------------------------------------------------------------- #
TAG_CTX_PARAMS1 = 0xA0  # ctxParamsForCommonAuthentication [0]
TAG_MATCHING_ID = 0x80  # matchingId [0] UTF8String
TAG_DEVICE_INFO = 0x30  # DeviceInfo SEQUENCE
TAG_TAC = 0x80  # tac Octet4
TAG_DEVICE_CAPS = 0xA1  # deviceCapabilities
TAG_IMEI = 0x82  # imei Octet8 OPTIONAL

BF38_TAG_BYTES = b"\xbf\x38"

# Mutation class labels.
CLASS_CTX = "ctxParams1"
CLASS_OUTER = "outer_framing"
CLASS_CI_PKID = "ci_pkid_framing"
CLASS_CERT = "cert_wrapper"
CLASS_BLOCKS = "block_chaining"
CLASS_REPLAY = "replay"
CLASS_COMBO = "combinatorial"  # inner structural perturbation × outer length form

CLASSES = (CLASS_CTX, CLASS_OUTER, CLASS_CI_PKID, CLASS_CERT, CLASS_BLOCKS, CLASS_REPLAY, CLASS_COMBO)

# Block-chaining wire constants (mirror run_authsrv chaining).
INS_STORE_DATA = 0xE2
P1_INTERMEDIATE = 0x11
P1_LAST = 0x91
P1_LAST_BIT = 0x80


class FramingMutationError(ValueError):
    """Raised when a generated mutation fails its own BF38/ALLOWED self-check."""


@dataclass(frozen=True)
class FramingMutation:
    """One malleable-framing mutation of an AuthenticateServer command.

    ``command_tlv`` is the LOGICAL reassembled BF38 command (possibly malformed in
    its framing but always opening with the BF38 tag). ``blocks`` is set only for
    the block-chaining class, where the wire split is itself the mutation and does
    NOT necessarily reassemble to ``command_tlv``; when ``None`` the runner applies
    the standard chunking, which reassembles byte-for-byte.

    ``keeps_ci_pkid_valid`` records whether the 20-byte CI SubjectKeyIdentifier
    VALUE is left intact so the mutation still passes the CI-known stage.
    """

    label: str
    mutation_class: str
    perturbs: str
    command_tlv: bytes
    blocks: tuple[str, ...] | None = None
    keeps_ci_pkid_valid: bool = True
    expected_reject: bool = True

    @property
    def apdu_hex(self) -> str:
        """Single-APDU logical projection for the safety guard to classify.

        Lc is capped at 0xFF as a non-zero placeholder; ``safety.classify`` reads
        only INS (E2) and the leading BF38 tag, never Lc-vs-body length, so a long
        or malformed body still classifies on its BF38 tag exactly as the first
        wire block would.
        """
        tlv = self.command_tlv
        lc = len(tlv) if len(tlv) <= 0xFF else 0xFF
        header = bytes([0x81, INS_STORE_DATA, 0x91, 0x00, lc])
        return (header + tlv).hex().upper()


# --------------------------------------------------------------------------- #
# BER length-form encoders (the length/framing obstacle, inverted).
# --------------------------------------------------------------------------- #


def _len_long(n: int, k: int) -> bytes:
    """Long-form length declaring ``n`` in exactly ``k`` bytes (non-minimal if k is
    larger than needed)."""
    if k < 1 or k > 4:
        raise FramingMutationError(f"unsupported long-form byte count {k}")
    if n >= (1 << (8 * k)):
        raise FramingMutationError(f"length {n} does not fit in {k} bytes")
    return bytes([0x80 | k]) + n.to_bytes(k, "big")


def _tlv_len_form(tag_bytes: bytes, value: bytes, form: str, delta: int = 0) -> bytes:
    """Encode ``tag_bytes`` + a length in ``form`` + ``value``.

    Forms: ``minimal`` (DER), ``long1``..``long4`` (fixed non-minimal length
    widths), ``indefinite`` (0x80, no valid terminator), ``over``/``under``
    (declared length off by ``delta``), ``truncated`` (declared full length but
    ``delta`` value bytes chopped off the end).
    """
    n = len(value)
    if form == "minimal":
        return tag_bytes + ber.encode_len(n) + value
    if form.startswith("long"):
        return tag_bytes + _len_long(n, int(form[4:])) + value
    if form == "indefinite":
        return tag_bytes + b"\x80" + value
    if form == "over":
        return tag_bytes + ber.encode_len(n + delta) + value
    if form == "under":
        return tag_bytes + ber.encode_len(max(0, n - delta)) + value
    if form == "truncated":
        return tag_bytes + ber.encode_len(n) + value[: max(0, n - delta)]
    raise FramingMutationError(f"unknown length form {form!r}")


# --------------------------------------------------------------------------- #
# Component assembly.
# --------------------------------------------------------------------------- #


def _body(
    seed: AuthCommand,
    *,
    ctx: bytes | None = None,
    ci_pkid: bytes | None = None,
    cert: bytes | None = None,
) -> bytes:
    """Concatenate the five BF38 components, overriding the named ones."""
    return (
        seed.server_signed1
        + seed.server_signature1
        + (ci_pkid if ci_pkid is not None else seed.euicc_ci_pkid)
        + (cert if cert is not None else seed.server_certificate)
        + (ctx if ctx is not None else seed.ctx_params1)
    )


def _wrap_bf38(body: bytes, form: str = "minimal", delta: int = 0) -> bytes:
    return _tlv_len_form(BF38_TAG_BYTES, body, form, delta)


# --------------------------------------------------------------------------- #
# Canonical ctxParams1 (LPA-supplied, unsigned) — the base for ctx mutations.
# --------------------------------------------------------------------------- #

_CANON_TAC = bytes.fromhex("35290611")
_CANON_DEVCAP = ber.tlv(0x80, bytes.fromhex("0A0000")) + ber.tlv(0x81, bytes.fromhex("0A0000"))
_CANON_IMEI = bytes.fromhex("3589012345678900")
_CANON_MATCHING_ID = b"QRF-SPEEDTEST"


def _device_info(
    tac: bytes = _CANON_TAC,
    devcap: bytes = _CANON_DEVCAP,
    imei: bytes = _CANON_IMEI,
    *,
    order: tuple[str, ...] = ("tac", "devcap", "imei"),
    include: tuple[str, ...] = ("tac", "devcap", "imei"),
    extra: bytes = b"",
    form: str = "minimal",
    delta: int = 0,
) -> bytes:
    parts = {
        "tac": ber.tlv(TAG_TAC, tac),
        "devcap": ber.tlv(TAG_DEVICE_CAPS, devcap),
        "imei": ber.tlv(TAG_IMEI, imei),
    }
    inner = b"".join(parts[name] for name in order if name in include) + extra
    return _tlv_len_form(bytes([TAG_DEVICE_INFO]), inner, form, delta)


def _ctx(matching_id: bytes = _CANON_MATCHING_ID, device_info: bytes | None = None) -> bytes:
    dev = device_info if device_info is not None else _device_info()
    inner = ber.tlv(TAG_MATCHING_ID, matching_id) + dev
    return ber.tlv(TAG_CTX_PARAMS1, inner)


# --------------------------------------------------------------------------- #
# Class 1 — ctxParams1 (top priority: LPA-supplied, unsigned).
# --------------------------------------------------------------------------- #


def ctx_params_mutations(seed: AuthCommand) -> list[FramingMutation]:
    out: list[FramingMutation] = []

    def add(label: str, perturbs: str, ctx: bytes) -> None:
        out.append(FramingMutation(
            label=label, mutation_class=CLASS_CTX, perturbs=perturbs,
            command_tlv=_wrap_bf38(_body(seed, ctx=ctx)),
            keeps_ci_pkid_valid=True,
        ))

    # matchingId value-space (size × fill), each a full ctx with canonical devInfo.
    sizes = (0, 1, 2, 15, 16, 127, 128, 255, 256, 512, 1024, 4096)
    for size in sizes:
        add(f"ctx_matchingid_len_{size}_zero", f"matchingId {size}B 0x00", _ctx(b"\x00" * size))
    for size in (1, 16, 255):
        add(f"ctx_matchingid_len_{size}_ff", f"matchingId {size}B 0xFF non-UTF8", _ctx(b"\xff" * size))
        add(f"ctx_matchingid_len_{size}_ascii", f"matchingId {size}B ASCII", _ctx(b"A" * size))
    add("ctx_matchingid_embedded_nul", "matchingId with embedded NUL", _ctx(b"QRF\x00INJECT"))
    add("ctx_matchingid_embedded_tlv", "matchingId carrying BF38 TLV bytes",
        _ctx(BF38_TAG_BYTES + b"\x82\x04\x00" + b"\xa0\x80"))
    add("ctx_matchingid_high_utf8", "matchingId invalid UTF-8 continuation bytes",
        _ctx(bytes([0xC0, 0x80, 0xE0, 0x80, 0xF5, 0xFF])))

    # deviceInfo sub-TLV framing.
    add("ctx_devinfo_missing_tac", "deviceInfo without tac",
        _ctx(device_info=_device_info(include=("devcap", "imei"))))
    add("ctx_devinfo_missing_imei", "deviceInfo without imei (imei is OPTIONAL)",
        _ctx(device_info=_device_info(include=("tac", "devcap"))))
    add("ctx_devinfo_missing_devcap", "deviceInfo without deviceCapabilities",
        _ctx(device_info=_device_info(include=("tac", "imei"))))
    add("ctx_devinfo_only_tac", "deviceInfo with tac only", _ctx(device_info=_device_info(include=("tac",))))
    add("ctx_devinfo_empty", "deviceInfo empty SEQUENCE", _ctx(device_info=ber.tlv(TAG_DEVICE_INFO, b"")))
    add("ctx_devinfo_dup_tac", "deviceInfo with duplicated tac",
        _ctx(device_info=_device_info(extra=ber.tlv(TAG_TAC, _CANON_TAC))))
    add("ctx_devinfo_dup_imei", "deviceInfo with duplicated imei",
        _ctx(device_info=_device_info(extra=ber.tlv(TAG_IMEI, _CANON_IMEI))))
    add("ctx_devinfo_reorder_imei_first", "deviceInfo tac/imei reordered",
        _ctx(device_info=_device_info(order=("imei", "tac", "devcap"))))
    add("ctx_devinfo_reorder_devcap_first", "deviceInfo devcap first",
        _ctx(device_info=_device_info(order=("devcap", "tac", "imei"))))
    add("ctx_devinfo_over_declared", "deviceInfo length over-declared by 16",
        _ctx(device_info=_device_info(form="over", delta=16)))
    add("ctx_devinfo_under_declared", "deviceInfo length under-declared by 4",
        _ctx(device_info=_device_info(form="under", delta=4)))
    add("ctx_devinfo_truncated", "deviceInfo declared full but truncated by 3",
        _ctx(device_info=_device_info(form="truncated", delta=3)))
    add("ctx_devinfo_indefinite_len", "deviceInfo indefinite length (0x80)",
        _ctx(device_info=_device_info(form="indefinite")))
    add("ctx_devinfo_longform_len", "deviceInfo non-minimal long-form length",
        _ctx(device_info=_device_info(form="long3")))
    add("ctx_devinfo_oversized_tac", "tac 100 bytes (spec Octet4)",
        _ctx(device_info=_device_info(tac=b"\x11" * 100)))
    add("ctx_devinfo_oversized_imei", "imei 64 bytes (spec Octet8)",
        _ctx(device_info=_device_info(imei=b"\x22" * 64)))
    add("ctx_devinfo_zero_tac", "tac zero length", _ctx(device_info=_device_info(tac=b"")))
    add("ctx_devinfo_unexpected_tag", "deviceInfo with unknown 9F70 sub-TLV",
        _ctx(device_info=_device_info(extra=ber.tlv(0x9F70, bytes(20)))))
    add("ctx_devinfo_deep_nest", "deviceInfo wrapped in extra nesting",
        _ctx(device_info=ber.tlv(TAG_DEVICE_INFO,
                                 ber.tlv(0x30, ber.tlv(0x30, _device_info())))))

    # matchingId × deviceInfo cross product (a representative slice for volume).
    for mid_label, mid in (("empty", b""), ("big", b"Z" * 300)):
        for dev_label, dev in (
            ("noimei", _device_info(include=("tac", "devcap"))),
            ("reorder", _device_info(order=("imei", "tac", "devcap"))),
            ("overdecl", _device_info(form="over", delta=8)),
        ):
            add(f"ctx_cross_{mid_label}_{dev_label}",
                f"matchingId {mid_label} × deviceInfo {dev_label}",
                _ctx(mid, device_info=dev))

    # ctxParams1 outer wrapper framing.
    for form, delta in (("over", 16), ("under", 4), ("long3", 0), ("indefinite", 0), ("truncated", 4)):
        inner = ber.tlv(TAG_MATCHING_ID, _CANON_MATCHING_ID) + _device_info()
        ctx = _tlv_len_form(bytes([TAG_CTX_PARAMS1]), inner, form, delta)
        add(f"ctx_outer_{form}", f"ctxParams1 A0 length {form}", ctx)
    add("ctx_missing_entirely", "ctxParams1 empty A0 wrapper",
        ber.tlv(TAG_CTX_PARAMS1, b""))

    return out


# --------------------------------------------------------------------------- #
# Class 2 — outer / store-data TLV framing.
# --------------------------------------------------------------------------- #


def outer_framing_mutations(seed: AuthCommand) -> list[FramingMutation]:
    out: list[FramingMutation] = []
    body = _body(seed)

    def add(label: str, perturbs: str, command_tlv: bytes) -> None:
        out.append(FramingMutation(
            label=label, mutation_class=CLASS_OUTER, perturbs=perturbs,
            command_tlv=command_tlv, keeps_ci_pkid_valid=True,
        ))

    # Length encodings on the outer BF38.
    add("outer_len_long1", "BF38 length long-form 81", _wrap_bf38(body, "long1")
        if len(body) < 0x100 else _wrap_bf38(body, "long2"))
    add("outer_len_long2", "BF38 length long-form 82", _wrap_bf38(body, "long2"))
    add("outer_len_long3", "BF38 length long-form 83 (non-minimal)", _wrap_bf38(body, "long3"))
    add("outer_len_long4", "BF38 length long-form 84 (non-minimal)", _wrap_bf38(body, "long4"))
    add("outer_len_indefinite", "BF38 indefinite length 0x80", _wrap_bf38(body, "indefinite"))
    add("outer_len_over_1", "BF38 length over-declared by 1", _wrap_bf38(body, "over", 1))
    add("outer_len_over_16", "BF38 length over-declared by 16", _wrap_bf38(body, "over", 16))
    add("outer_len_over_256", "BF38 length over-declared by 256", _wrap_bf38(body, "over", 256))
    add("outer_len_under_1", "BF38 length under-declared by 1", _wrap_bf38(body, "under", 1))
    add("outer_len_under_16", "BF38 length under-declared by 16", _wrap_bf38(body, "under", 16))
    add("outer_len_truncated_8", "BF38 declared full but truncated by 8", _wrap_bf38(body, "truncated", 8))

    # Duplicate each top-level sub-TLV.
    components = ber.walk(body)
    names = ["serverSigned1", "serverSignature1", "euiccCiPKIdToBeUsed", "serverCertificate", "ctxParams1"]
    for idx, field in enumerate(components):
        dup_body = body + field.raw
        add(f"outer_dup_{names[idx]}", f"duplicate {names[idx]} sub-TLV", _wrap_bf38(dup_body))

    # Reorder: reverse full order, and swap adjacent pairs.
    add("outer_reorder_reverse", "all five sub-TLVs reversed",
        _wrap_bf38(b"".join(f.raw for f in reversed(components))))
    for i in range(len(components) - 1):
        swapped = list(components)
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        add(f"outer_reorder_swap_{i}_{i+1}", f"swap {names[i]} and {names[i+1]}",
            _wrap_bf38(b"".join(f.raw for f in swapped)))

    # Trailing garbage after the last valid TLV.
    for tag, garbage in (("1b", b"\xff"), ("16b", b"\xAB" * 16), ("tlv", ber.tlv(0x9F70, bytes(8)))):
        add(f"outer_trailing_{tag}", f"trailing garbage ({tag}) after last TLV",
            _wrap_bf38(body + garbage))

    # Truncate the body at each sub-TLV boundary.
    offset = 0
    for idx, field in enumerate(components[:-1]):
        offset += len(field.raw)
        add(f"outer_truncate_after_{names[idx]}", f"body truncated after {names[idx]}",
            _wrap_bf38(body[:offset]))

    return out


# --------------------------------------------------------------------------- #
# Class 3 — euiccCiPKIdToBeUsed framing (VALUE kept valid).
# --------------------------------------------------------------------------- #


def ci_pkid_framing_mutations(seed: AuthCommand) -> list[FramingMutation]:
    out: list[FramingMutation] = []
    value = seed.euicc_ci_pkid_value  # the intact 20-byte prod CI SKI

    def add(label: str, perturbs: str, ci_pkid: bytes) -> None:
        out.append(FramingMutation(
            label=label, mutation_class=CLASS_CI_PKID, perturbs=perturbs,
            command_tlv=_wrap_bf38(_body(seed, ci_pkid=ci_pkid)),
            keeps_ci_pkid_valid=True,
        ))

    add("cipkid_len_plus_1", "CI-PKID length +1 (value intact)",
        _tlv_len_form(bytes([TAG_EUICC_CI_PKID]), value, "over", 1))
    add("cipkid_len_minus_1", "CI-PKID length -1 (value intact)",
        _tlv_len_form(bytes([TAG_EUICC_CI_PKID]), value, "under", 1))
    add("cipkid_len_long1", "CI-PKID length long-form 81 14",
        _tlv_len_form(bytes([TAG_EUICC_CI_PKID]), value, "long1"))
    add("cipkid_len_long2", "CI-PKID length non-minimal 82 0014",
        _tlv_len_form(bytes([TAG_EUICC_CI_PKID]), value, "long2"))
    add("cipkid_len_indefinite", "CI-PKID indefinite length",
        _tlv_len_form(bytes([TAG_EUICC_CI_PKID]), value, "indefinite"))
    add("cipkid_trailing_1", "CI-PKID with 1 extra trailing byte in value",
        ber.tlv(TAG_EUICC_CI_PKID, value + b"\xff"))
    add("cipkid_trailing_4", "CI-PKID with 4 extra trailing bytes in value",
        ber.tlv(TAG_EUICC_CI_PKID, value + b"\xde\xad\xbe\xef"))
    add("cipkid_wrong_tag_03", "CI-PKID tag changed 04->03 (value intact)",
        ber.tlv(0x03, value))
    add("cipkid_wrong_tag_05", "CI-PKID tag changed 04->05 (value intact)",
        ber.tlv(0x05, value))
    add("cipkid_wrong_tag_9f70", "CI-PKID tag changed 04->9F70 (value intact)",
        ber.tlv(0x9F70, value))
    add("cipkid_duplicated", "CI-PKID TLV duplicated",
        ber.tlv(TAG_EUICC_CI_PKID, value) + ber.tlv(TAG_EUICC_CI_PKID, value))
    add("cipkid_zero_len", "CI-PKID zero-length wrapper (value moved to trailing)",
        ber.tlv(TAG_EUICC_CI_PKID, b"") + value)
    return out


# --------------------------------------------------------------------------- #
# Class 4 — serverCertificate wrapper (cert body kept).
# --------------------------------------------------------------------------- #


def cert_wrapper_mutations(seed: AuthCommand) -> list[FramingMutation]:
    out: list[FramingMutation] = []
    cert = seed.server_certificate
    cert_field = ber.walk(cert)[0]
    cert_body = cert_field.value

    def add(label: str, perturbs: str, cert_tlv: bytes) -> None:
        out.append(FramingMutation(
            label=label, mutation_class=CLASS_CERT, perturbs=perturbs,
            command_tlv=_wrap_bf38(_body(seed, cert=cert_tlv)),
            keeps_ci_pkid_valid=True,
        ))

    add("cert_len_over_16", "serverCertificate outer length over-declared by 16",
        _tlv_len_form(bytes([0x30]), cert_body, "over", 16))
    add("cert_len_over_256", "serverCertificate outer length over-declared by 256",
        _tlv_len_form(bytes([0x30]), cert_body, "over", 256))
    add("cert_len_under_8", "serverCertificate outer length under-declared by 8",
        _tlv_len_form(bytes([0x30]), cert_body, "under", 8))
    add("cert_len_long4", "serverCertificate non-minimal long-form length",
        _tlv_len_form(bytes([0x30]), cert_body, "long4"))
    add("cert_len_indefinite", "serverCertificate indefinite length",
        _tlv_len_form(bytes([0x30]), cert_body, "indefinite"))
    add("cert_extra_nesting", "serverCertificate body wrapped in an extra SEQUENCE",
        ber.tlv(0x30, ber.tlv(0x30, cert_body)))
    add("cert_trailing_bytes", "serverCertificate with trailing bytes inside outer",
        ber.tlv(0x30, cert_body + b"\xAB\xCD"))
    add("cert_trailing_after_outer", "trailing bytes after serverCertificate TLV",
        cert + b"\x00\x00")
    add("cert_truncated_body", "serverCertificate declared full but body truncated by 16",
        _tlv_len_form(bytes([0x30]), cert_body, "truncated", 16))
    return out


# --------------------------------------------------------------------------- #
# Class 5 — block-chaining boundaries (wire split IS the mutation).
# --------------------------------------------------------------------------- #


def _chain(tlv: bytes, chunk: int) -> list[str]:
    blocks: list[str] = []
    total = len(tlv)
    offset = 0
    index = 0
    while offset < total:
        piece = tlv[offset : offset + chunk]
        last = offset + len(piece) >= total
        p1 = P1_LAST if last else P1_INTERMEDIATE
        blocks.append((bytes([0x81, INS_STORE_DATA, p1, index & 0xFF, len(piece)]) + piece).hex().upper())
        offset += len(piece)
        index += 1
    return blocks


def block_chaining_mutations(seed: AuthCommand) -> list[FramingMutation]:
    out: list[FramingMutation] = []
    tlv = _wrap_bf38(_body(seed))

    def add(label: str, perturbs: str, blocks: list[str]) -> None:
        out.append(FramingMutation(
            label=label, mutation_class=CLASS_BLOCKS, perturbs=perturbs,
            command_tlv=tlv, blocks=tuple(blocks), keeps_ci_pkid_valid=True,
        ))

    add("blocks_1byte", "split into 1-byte STORE DATA blocks", _chain(tlv, 1))
    add("blocks_oversized", "single-shot 255-byte blocks", _chain(tlv, 0xFF))
    add("blocks_2byte", "2-byte blocks (split mid-tag on BF38)", _chain(tlv, 2))

    base = _chain(tlv, 0x3F)

    # Wrong more-data bits: last block loses the 0x80 last-block marker.
    no_last = list(base)
    apdu = bytes.fromhex(no_last[-1])
    no_last[-1] = (bytes([apdu[0], apdu[1], P1_INTERMEDIATE, apdu[3], apdu[4]]) + apdu[5:]).hex().upper()
    add("blocks_no_final_marker", "final block P1 lacks last-block bit", no_last)

    # An intermediate block already carries the last-block bit.
    early_last = list(base)
    if len(early_last) > 1:
        apdu = bytes.fromhex(early_last[0])
        early_last[0] = (bytes([apdu[0], apdu[1], P1_LAST, apdu[3], apdu[4]]) + apdu[5:]).hex().upper()
        add("blocks_early_last_bit", "first block carries the last-block bit", early_last)

    # Extra empty final block after the real last block.
    empty_tail = list(base)
    empty_tail[-1] = _revert_last_to_intermediate(empty_tail[-1])
    empty_tail.append(bytes([0x81, INS_STORE_DATA, P1_LAST, len(empty_tail) & 0xFF, 0x00]).hex().upper())
    add("blocks_extra_empty_final", "extra empty last block appended", empty_tail)

    # Missing final block: drop the last block entirely (no 0x80 anywhere).
    if len(base) > 1:
        add("blocks_missing_final", "last block dropped (chain never terminates)", base[:-1])

    # Overlapping: duplicate a middle block.
    if len(base) > 2:
        overlap = base[:1] + base[1:2] + base[1:]
        add("blocks_overlapping", "a middle block duplicated (overlap)", overlap)

    # Wrong P2 indices: all zero.
    zeroed = [(bytes.fromhex(b)[:3] + b"\x00" + bytes.fromhex(b)[4:]).hex().upper() for b in base]
    add("blocks_p2_all_zero", "every block P2 index set to 0", zeroed)

    return out


def _revert_last_to_intermediate(block_hex: str) -> str:
    apdu = bytes.fromhex(block_hex)
    return (bytes([apdu[0], apdu[1], P1_INTERMEDIATE, apdu[3], apdu[4]]) + apdu[5:]).hex().upper()


# --------------------------------------------------------------------------- #
# Class 6 — replay + framing perturbations.
# --------------------------------------------------------------------------- #


def replay_mutations(seed: AuthCommand) -> list[FramingMutation]:
    out: list[FramingMutation] = []
    intact = _wrap_bf38(_body(seed))

    # Control: the intact seed replayed verbatim. expected_reject=False — a fresh,
    # correctly-signed replay MAY be accepted (challenge-bound); it is the baseline
    # against which the framing perturbations are compared, not itself a bypass.
    out.append(FramingMutation(
        label="replay_intact_control", mutation_class=CLASS_REPLAY,
        perturbs="verbatim captured seed (control)", command_tlv=intact,
        keeps_ci_pkid_valid=True, expected_reject=False,
    ))

    body = _body(seed)
    components = ber.walk(body)
    out.append(FramingMutation(
        label="replay_longform_outer", mutation_class=CLASS_REPLAY,
        perturbs="seed + outer long-form length only",
        command_tlv=_wrap_bf38(body, "long3"), keeps_ci_pkid_valid=True,
    ))
    out.append(FramingMutation(
        label="replay_reordered_body", mutation_class=CLASS_REPLAY,
        perturbs="seed + reordered top-level sub-TLVs",
        command_tlv=_wrap_bf38(b"".join(f.raw for f in reversed(components))),
        keeps_ci_pkid_valid=True,
    ))
    out.append(FramingMutation(
        label="replay_trailing_garbage", mutation_class=CLASS_REPLAY,
        perturbs="seed + trailing garbage",
        command_tlv=_wrap_bf38(body + b"\xDE\xAD"), keeps_ci_pkid_valid=True,
    ))
    return out


# --------------------------------------------------------------------------- #
# Combinatorial — inner structural perturbation × outer length form.
# --------------------------------------------------------------------------- #

# Outer length forms applied to every perturbed body. A length-framing handler bug
# may only surface when the declared length disagrees with a body that is ALSO
# internally malformed, so the cross product is not redundant with the flat classes.
_OUTER_FORMS: tuple[tuple[str, str, int], ...] = (
    ("min", "minimal", 0),
    ("long2", "long2", 0),
    ("long3", "long3", 0),
    ("long4", "long4", 0),
    ("indef", "indefinite", 0),
    ("over1", "over", 1),
    ("over16", "over", 16),
    ("over256", "over", 256),
    ("under1", "under", 1),
    ("under16", "under", 16),
    ("trunc8", "truncated", 8),
)


def _perturbed_bodies(seed: AuthCommand) -> list[tuple[str, bytes]]:
    """Representative internally-perturbed BF38 bodies (tag+len+value concatenations)."""
    bodies: list[tuple[str, bytes]] = []
    bodies.append(("canonical", _body(seed)))
    # ctxParams1 perturbations.
    bodies.append(("ctx_mid_empty", _body(seed, ctx=_ctx(b""))))
    bodies.append(("ctx_mid_4k", _body(seed, ctx=_ctx(b"\x00" * 4096))))
    bodies.append(("ctx_mid_nul", _body(seed, ctx=_ctx(b"QRF\x00INJ"))))
    bodies.append(("ctx_mid_tlvbytes", _body(seed, ctx=_ctx(BF38_TAG_BYTES + b"\x82\x04\x00"))))
    bodies.append(("ctx_dev_no_tac", _body(seed, ctx=_ctx(device_info=_device_info(include=("devcap", "imei"))))))
    bodies.append(("ctx_dev_dup_imei", _body(seed, ctx=_ctx(device_info=_device_info(extra=ber.tlv(TAG_IMEI, _CANON_IMEI))))))
    bodies.append(("ctx_dev_reorder", _body(seed, ctx=_ctx(device_info=_device_info(order=("imei", "tac", "devcap"))))))
    bodies.append(("ctx_dev_overdecl", _body(seed, ctx=_ctx(device_info=_device_info(form="over", delta=16)))))
    bodies.append(("ctx_dev_deepnest", _body(seed, ctx=_ctx(device_info=ber.tlv(TAG_DEVICE_INFO, ber.tlv(0x30, ber.tlv(0x30, _device_info())))))))
    bodies.append(("ctx_dev_badtag", _body(seed, ctx=_ctx(device_info=_device_info(extra=ber.tlv(0x9F70, bytes(12)))))))
    # euiccCiPKIdToBeUsed wrapper perturbations (VALUE intact).
    value = seed.euicc_ci_pkid_value
    bodies.append(("cipkid_len1", _body(seed, ci_pkid=_tlv_len_form(bytes([TAG_EUICC_CI_PKID]), value, "over", 1))))
    bodies.append(("cipkid_long2", _body(seed, ci_pkid=_tlv_len_form(bytes([TAG_EUICC_CI_PKID]), value, "long2"))))
    bodies.append(("cipkid_badtag", _body(seed, ci_pkid=ber.tlv(0x03, value))))
    # serverCertificate wrapper perturbations (body intact).
    cert_body = ber.walk(seed.server_certificate)[0].value
    bodies.append(("cert_over16", _body(seed, cert=_tlv_len_form(bytes([0x30]), cert_body, "over", 16))))
    bodies.append(("cert_nested", _body(seed, cert=ber.tlv(0x30, ber.tlv(0x30, cert_body)))))
    bodies.append(("cert_indef", _body(seed, cert=_tlv_len_form(bytes([0x30]), cert_body, "indefinite"))))
    bodies.append(("cert_under8", _body(seed, cert=_tlv_len_form(bytes([0x30]), cert_body, "under", 8))))
    bodies.append(("cipkid_trailing", _body(seed, ci_pkid=ber.tlv(TAG_EUICC_CI_PKID, value + b"\xff\xff"))))
    bodies.append(("cipkid_indef", _body(seed, ci_pkid=_tlv_len_form(bytes([TAG_EUICC_CI_PKID]), value, "indefinite"))))
    bodies.append(("cipkid_dup", _body(seed, ci_pkid=ber.tlv(TAG_EUICC_CI_PKID, value) + ber.tlv(TAG_EUICC_CI_PKID, value))))
    # matchingId size × fill grid, each as a full body.
    for size in (0, 1, 16, 127, 128, 255, 256, 1024, 4096):
        for fill_label, fill in (("00", b"\x00"), ("ff", b"\xff")):
            if size == 0 and fill_label == "ff":
                continue
            bodies.append((f"ctx_mid_{size}_{fill_label}", _body(seed, ctx=_ctx(fill * size))))
    # Duplicated / reordered top-level structure.
    comps = ber.walk(_body(seed))
    names = ["signed1", "sig1", "cipkid", "cert", "ctx"]
    for idx, field in enumerate(comps):
        bodies.append((f"dup_{names[idx]}", _body(seed) + field.raw))
    for i in range(len(comps) - 1):
        swapped = list(comps)
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        bodies.append((f"swap_{i}_{i+1}", b"".join(f.raw for f in swapped)))
    bodies.append(("reversed", b"".join(f.raw for f in reversed(comps))))
    return bodies


def combinatorial_mutations(seed: AuthCommand) -> list[FramingMutation]:
    """Cross every perturbed body with every outer length form.

    Keeps ``keeps_ci_pkid_valid`` True: no body here alters the CI-PKID VALUE (the
    ci_pkid entries fuzz only its wrapper). The outer tag is always BF38.
    """
    out: list[FramingMutation] = []
    for body_label, body in _perturbed_bodies(seed):
        for form_label, form, delta in _OUTER_FORMS:
            # long-form widths that cannot hold this length are skipped.
            try:
                command_tlv = _wrap_bf38(body, form, delta)
            except FramingMutationError:
                continue
            out.append(FramingMutation(
                label=f"combo_{body_label}__{form_label}",
                mutation_class=CLASS_COMBO,
                perturbs=f"body={body_label} × outer-length={form_label}",
                command_tlv=command_tlv, keeps_ci_pkid_valid=True,
            ))
    return out


# --------------------------------------------------------------------------- #
# Top-level generator with self-check.
# --------------------------------------------------------------------------- #


def _self_check(mutation: FramingMutation) -> None:
    """Every mutation's LOGICAL command must classify ALLOWED as BF38, and every
    explicit wire block must NOT classify BLOCKED. A failure is a generator bug."""
    verdict = classify(mutation.apdu_hex)
    if verdict.classification is not Classification.ALLOWED or verdict.tag != TAG_BF38:
        raise FramingMutationError(
            f"mutation {mutation.label!r} logical command is not ALLOWED/BF38: "
            f"{verdict.classification.value} tag={verdict.tag}"
        )
    if mutation.blocks is not None:
        for block in mutation.blocks:
            if classify(block).classification is Classification.BLOCKED:
                raise FramingMutationError(
                    f"mutation {mutation.label!r} emits a BLOCKED wire block: {block}"
                )


def generate_mutations(seed: AuthCommand) -> list[FramingMutation]:
    """All framing/structural/replay mutations, deduplicated and self-checked.

    Each returned mutation is a BF38-tagged STORE DATA logical command (never a
    different INS/tag, never a destructive APDU). Raises FramingMutationError if
    any mutation fails its BF38/ALLOWED self-check.
    """
    mutations: list[FramingMutation] = []
    mutations += ctx_params_mutations(seed)
    mutations += outer_framing_mutations(seed)
    mutations += ci_pkid_framing_mutations(seed)
    mutations += cert_wrapper_mutations(seed)
    mutations += block_chaining_mutations(seed)
    mutations += replay_mutations(seed)
    mutations += combinatorial_mutations(seed)

    seen: set[tuple[bytes, tuple[str, ...] | None]] = set()
    unique: list[FramingMutation] = []
    for mutation in mutations:
        key = (mutation.command_tlv, mutation.blocks)
        if key in seen:
            continue
        seen.add(key)
        _self_check(mutation)
        unique.append(mutation)
    return unique


def counts_by_class(mutations: list[FramingMutation]) -> dict[str, int]:
    out: dict[str, int] = {name: 0 for name in CLASSES}
    for mutation in mutations:
        out[mutation.mutation_class] += 1
    return out
