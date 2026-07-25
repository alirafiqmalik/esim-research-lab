"""Deep/big SE-parser fuzzer for the eUICC: oversized fields, deep TLV nesting,
huge values, massive block-chains, and length-lies at scale.

The framing fuzzer (``authsrv_framing_fuzz``) attacks the SHAPE of the
AuthenticateServer envelope with small perturbations. This module attacks the
SE parser's MEMORY and RECURSION handling with inputs the transport previously
could not deliver: matchingId at 256 KB, TLV nested 32768 levels deep, single
fields at 256 KB, and commands split into thousands of STORE DATA blocks. These
are the classic buffer-overflow / stack-exhaustion / reassembly-DoS vectors.

Delivery is the on-device file transport (``seq_transport.LargeSeqTransport`` /
the ``esim euicc seq`` auto-route), so the binder intent-extra and logcat-line
caps no longer bound the input size.

Design, per ``testing-handbook-skills``:

- ``harness-writing``: the target is a closed SE, so the "harness" is the pair
  (mutation generator, on-device transport). Each mutation is a NARROW, typed
  input for one parser (BF38 or one allowlisted READ tag), never a blind byte
  blast at an unknown INS. The generator is deterministic: the same seed builds
  the same set, so any crash is reproducible from its label.
- ``fuzzing-obstacles``: the SE's own CI/signature check is the obstacle. As in
  the framing campaign we do NOT bypass it; we keep the cheap-to-pass parts (the
  20-byte CI-PKID VALUE) intact so the oversized/deep bytes reach the length- and
  recursion-handling code that runs BEFORE the crypto gate. Deep-nesting / length
  framing IS the attack surface here (SGP.22 does not bound ctxParams1 depth or
  size on the wire).
- ``fuzzing-dictionary``: the SGP.22 sub-TLV tags (matchingId ``80``, deviceInfo
  ``30``, ctxParams ``A0``, tac/imei) and the allowlisted READ tags are the
  domain tokens the size/depth mutators wrap, so every input is a parseable
  command header carrying a pathological body.

SAFETY: every mutation is a STORE DATA whose OUTER tag classifies ALLOWED through
``safety.classify`` — BF38 (verify-only) or an allowlisted ES10x READ tag. The
oversized/deep VALUE bytes are DATA inside an allowed command, never a command of
their own. The generator re-verifies this (and that no wire block classifies
BLOCKED) before returning any mutation. Nothing here sends anything.
"""

from __future__ import annotations

from dataclasses import dataclass

import ber
from authsrv_framing_fuzz import (
    BF38_TAG_BYTES,
    TAG_CTX_PARAMS1,
    TAG_DEVICE_CAPS,
    TAG_DEVICE_INFO,
    TAG_IMEI,
    TAG_MATCHING_ID,
    TAG_TAC,
    _body,
    _ctx,
    _device_info,
    _tlv_len_form,
    _wrap_bf38,
)
from authsrv_seed import TAG_BF38, AuthCommand
from safety import ALLOWLIST_TAGS, Classification, classify

# --------------------------------------------------------------------------- #
# Mutation-class labels.
# --------------------------------------------------------------------------- #
CLASS_OVERSIZED_CTX = "oversized_ctxParams1"
CLASS_DEEP_NESTING = "deep_nesting"
CLASS_HUGE_FIELD = "huge_field"
CLASS_MASSIVE_CHAIN = "massive_chain"
CLASS_READ_DEEPBIG = "read_deepbig"
CLASS_LENGTH_LIE = "length_lie"

CLASSES = (
    CLASS_OVERSIZED_CTX,
    CLASS_DEEP_NESTING,
    CLASS_HUGE_FIELD,
    CLASS_MASSIVE_CHAIN,
    CLASS_READ_DEEPBIG,
    CLASS_LENGTH_LIE,
)

# --------------------------------------------------------------------------- #
# Size / depth grids (the campaign's stress dimensions).
# --------------------------------------------------------------------------- #
OVERSIZED_CTX_SIZES = (1024, 4096, 16384, 65536, 262144)  # matchingId 1 KB..256 KB
DEEP_DEPTHS = (8, 32, 128, 512, 2048, 8192, 32768)  # TLV nesting levels
HUGE_FIELD_SIZES = (16384, 32768, 65536, 131072, 262144)  # single field 16 KB..256 KB
MASSIVE_CHAIN_TARGETS = (1024, 4096, 16384)  # STORE DATA block counts

# Allowlisted ES10x READ tags the deep/oversized READ class targets. Each is
# read-only in ``safety.ALLOWLIST_TAGS``; BF2D carries a structured search-criteria
# body (the lenient ES10x parser under pathological size/depth), BF2E/BF3E/BF2B
# take a (normally empty) body we overfill.
READ_TAGS = (0xBF2D, 0xBF2E, 0xBF3E, 0xBF2B)

# STORE DATA wire constants (mirror run_authsrv / authsrv_framing_fuzz chaining).
INS_STORE_DATA = 0xE2
P1_INTERMEDIATE = 0x11
P1_LAST = 0x91

# A generic constructed tag for the recursion vector (SEQUENCE).
TAG_NEST = 0x30


class DeepBigMutationError(ValueError):
    """Raised when a generated mutation fails its own ALLOWED self-check."""


@dataclass(frozen=True)
class DeepBigMutation:
    """One deep/big mutation of an ALLOWED eUICC command.

    ``command_tlv`` is the LOGICAL command TLV whose leading tag is BF38 or an
    allowlisted READ tag. ``blocks`` is set only for the massive-chain class,
    where the wire split (thousands of STORE DATA blocks) IS the mutation; when
    ``None`` the runner applies the standard chunking, which reassembles the
    command byte-for-byte.

    ``depth`` / ``size`` record the stress dimension reached (0 when N/A).
    ``keeps_ci_pkid_valid`` marks BF38 mutations that leave the CI SKI VALUE
    intact so the input reaches the parser past the CI-known stage.
    """

    label: str
    mutation_class: str
    target: str
    target_tag: int
    perturbs: str
    command_tlv: bytes
    blocks: tuple[str, ...] | None = None
    depth: int = 0
    size: int = 0
    keeps_ci_pkid_valid: bool = True
    expected_reject: bool = True

    @property
    def apdu_hex(self) -> str:
        """Single-APDU logical projection for the safety guard to classify.

        Lc is capped at 0xFF as a non-zero placeholder; ``safety.classify`` reads
        only INS (E2) and the leading BER-TLV tag, never Lc-vs-body length, so an
        oversized body still classifies on its outer tag exactly as the first wire
        block would.
        """
        tlv = self.command_tlv
        lc = len(tlv) if len(tlv) <= 0xFF else 0xFF
        header = bytes([0x81, INS_STORE_DATA, 0x91, 0x00, lc])
        return (header + tlv).hex().upper()


# --------------------------------------------------------------------------- #
# Low-level builders.
# --------------------------------------------------------------------------- #


def _read_tag_bytes(tag: int) -> bytes:
    return bytes(((tag >> 8) & 0xFF, tag & 0xFF)) if tag > 0xFF else bytes((tag,))


def _read_command(tag: int, value: bytes) -> bytes:
    """A raw ES10x READ command TLV: two-byte tag + BER length + value."""
    return _read_tag_bytes(tag) + ber.encode_len(len(value)) + value


def build_nested_tlv(depth: int, *, tag: int = TAG_NEST, innermost: bytes = b"") -> bytes:
    """Build a TLV nested ``depth`` levels deep in O(depth) time and memory.

    Naive repeated wrapping is O(depth^2) (each wrap copies the growing value); at
    depth 32768 that is unusable. This computes each level's content length
    bottom-up, then emits the headers outermost-first followed by the innermost
    value once. The result is a single well-formed BER-TLV whose recursion depth is
    exactly ``depth`` — the stack-exhaustion vector for a recursive-descent parser.
    """
    if depth < 1:
        raise DeepBigMutationError(f"nesting depth must be >= 1, got {depth}")
    tag_bytes = _read_tag_bytes(tag)

    # content_lengths[k] is the value length wrapped by level k (innermost first).
    content_lengths: list[int] = []
    cur = len(innermost)
    for _ in range(depth):
        content_lengths.append(cur)
        header_len = len(tag_bytes) + len(ber.encode_len(cur))
        cur = header_len + cur

    buf = bytearray()
    for length in reversed(content_lengths):  # outermost header first
        buf += tag_bytes + ber.encode_len(length)
    buf += innermost
    return bytes(buf)


def _ctx_with_mid_tlv(mid_tlv: bytes) -> bytes:
    """A ctxParams1 (A0) whose matchingId TLV is supplied verbatim (canonical devInfo)."""
    inner = mid_tlv + _device_info()
    return ber.tlv(TAG_CTX_PARAMS1, inner)


def chunk_command(tlv: bytes, chunk_size: int) -> list[str]:
    """Re-split any command TLV into block-chained STORE DATA APDUs.

    Intermediate blocks are ``81 E2 11 <idx> <Lc> <chunk>``; the final block is
    ``81 E2 91 <idx> <Lc> <chunk>``. The first block's body opens with the command
    tag, so it classifies on that tag; intermediate blocks are mid-body splits
    (classify UNKNOWN, never BLOCKED). ``authsrv_seed.reassemble_blocks`` over the
    result reproduces ``tlv`` byte-for-byte.
    """
    if not 1 <= chunk_size <= 0xFF:
        raise DeepBigMutationError(f"chunk_size {chunk_size} out of 1..255 range")
    if not tlv:
        raise DeepBigMutationError("cannot chunk an empty command")

    blocks: list[str] = []
    total = len(tlv)
    offset = 0
    index = 0
    while offset < total:
        chunk = tlv[offset : offset + chunk_size]
        last = offset + len(chunk) >= total
        p1 = P1_LAST if last else P1_INTERMEDIATE
        header = bytes([0x81, INS_STORE_DATA, p1, index & 0xFF, len(chunk)])
        blocks.append((header + chunk).hex().upper())
        offset += len(chunk)
        index += 1
    return blocks


# --------------------------------------------------------------------------- #
# Class 1 — oversized ctxParams1 (LPA-supplied, unsigned; CI-PKID kept valid).
# --------------------------------------------------------------------------- #


def oversized_ctx_mutations(seed: AuthCommand) -> list[DeepBigMutation]:
    out: list[DeepBigMutation] = []

    def add(label: str, perturbs: str, ctx: bytes, size: int) -> None:
        out.append(DeepBigMutation(
            label=label, mutation_class=CLASS_OVERSIZED_CTX, target="BF38",
            target_tag=TAG_BF38, perturbs=perturbs,
            command_tlv=_wrap_bf38(_body(seed, ctx=ctx)),
            size=size, keeps_ci_pkid_valid=True,
        ))

    # matchingId at 1 KB..256 KB, two fills (0x00 valid-ish, 0xFF non-UTF8).
    for size in OVERSIZED_CTX_SIZES:
        add(f"oversized_mid_{size}_zero", f"matchingId {size}B 0x00",
            _ctx(b"\x00" * size), size)
        add(f"oversized_mid_{size}_ff", f"matchingId {size}B 0xFF non-UTF8",
            _ctx(b"\xff" * size), size)

    # deviceInfo with huge tac / imei / deviceCapabilities (all spec-bounded fields).
    for size in (4096, 16384, 65536):
        add(f"oversized_tac_{size}", f"deviceInfo tac {size}B (spec Octet4)",
            _ctx(device_info=_device_info(tac=b"\x11" * size)), size)
        add(f"oversized_imei_{size}", f"deviceInfo imei {size}B (spec Octet8)",
            _ctx(device_info=_device_info(imei=b"\x22" * size)), size)
        add(f"oversized_devcap_{size}", f"deviceInfo deviceCapabilities {size}B",
            _ctx(device_info=_device_info(devcap=b"\x33" * size)), size)

    return out


# --------------------------------------------------------------------------- #
# Class 2 — deep TLV nesting (recursion / stack-exhaustion vector).
# --------------------------------------------------------------------------- #


def deep_nesting_mutations(seed: AuthCommand) -> list[DeepBigMutation]:
    out: list[DeepBigMutation] = []

    for depth in DEEP_DEPTHS:
        nest = build_nested_tlv(depth)

        # (a) nested inside ctxParams1 (A0 wraps the deep nest as its whole value).
        ctx = ber.tlv(TAG_CTX_PARAMS1, nest)
        out.append(DeepBigMutation(
            label=f"deepnest_ctx_{depth}", mutation_class=CLASS_DEEP_NESTING,
            target="BF38", target_tag=TAG_BF38,
            perturbs=f"ctxParams1 carrying a {depth}-level nested TLV",
            command_tlv=_wrap_bf38(_body(seed, ctx=ctx)),
            depth=depth, size=len(nest), keeps_ci_pkid_valid=True,
        ))

        # (b) nested directly in the outer BF38 wrapper; CI-PKID kept present so
        # the parser reaches the CI-known stage, deep nest trails it.
        body = seed.euicc_ci_pkid + nest
        out.append(DeepBigMutation(
            label=f"deepnest_outer_{depth}", mutation_class=CLASS_DEEP_NESTING,
            target="BF38", target_tag=TAG_BF38,
            perturbs=f"BF38 body = CI-PKID + a {depth}-level nested TLV",
            command_tlv=_wrap_bf38(body),
            depth=depth, size=len(nest), keeps_ci_pkid_valid=True,
        ))

        # (c) as a READ-command body (BF2D search-criteria), the lenient ES10x parser.
        out.append(DeepBigMutation(
            label=f"deepnest_read_bf2d_{depth}", mutation_class=CLASS_DEEP_NESTING,
            target="BF2D", target_tag=0xBF2D,
            perturbs=f"BF2D body = a {depth}-level nested TLV",
            command_tlv=_read_command(0xBF2D, nest),
            depth=depth, size=len(nest), keeps_ci_pkid_valid=False,
        ))

    return out


# --------------------------------------------------------------------------- #
# Class 3 — huge single field (buffer-sizing vector).
# --------------------------------------------------------------------------- #


def huge_field_mutations(seed: AuthCommand) -> list[DeepBigMutation]:
    out: list[DeepBigMutation] = []

    for size in HUGE_FIELD_SIZES:
        # (a) a single huge matchingId VALUE; ber.encode_len auto-selects long-form.
        ctx = _ctx(b"\x5A" * size)
        out.append(DeepBigMutation(
            label=f"huge_matchingid_{size}", mutation_class=CLASS_HUGE_FIELD,
            target="BF38", target_tag=TAG_BF38,
            perturbs=f"single matchingId field {size}B",
            command_tlv=_wrap_bf38(_body(seed, ctx=ctx)),
            size=size, keeps_ci_pkid_valid=True,
        ))

        # (b) explicit long-form length (84 xxxxxxxx) declaring the huge size with a
        # MATCHING huge body — the length field itself is the multi-byte stressor.
        mid_tlv = _tlv_len_form(bytes([TAG_MATCHING_ID]), b"\x5A" * size, "long4")
        out.append(DeepBigMutation(
            label=f"huge_matchingid_long4_{size}", mutation_class=CLASS_HUGE_FIELD,
            target="BF38", target_tag=TAG_BF38,
            perturbs=f"matchingId {size}B with 84-form long length",
            command_tlv=_wrap_bf38(_body(seed, ctx=_ctx_with_mid_tlv(mid_tlv))),
            size=size, keeps_ci_pkid_valid=True,
        ))

    return out


# --------------------------------------------------------------------------- #
# Class 4 — massive block-chains (reassembly state-machine stress).
# --------------------------------------------------------------------------- #


def _padded_bf38(seed: AuthCommand, target_bytes: int) -> bytes:
    """A BF38 command TLV whose length is at least ``target_bytes`` (matchingId pad)."""
    command = _wrap_bf38(_body(seed, ctx=_ctx(b"\x00" * target_bytes)))
    return command


def massive_chain_mutations(seed: AuthCommand) -> list[DeepBigMutation]:
    out: list[DeepBigMutation] = []

    for target in MASSIVE_CHAIN_TARGETS:
        # Pad a BF38 command to ~target bytes, then split at 1 byte/block so the
        # chain carries ~target STORE DATA blocks. The reassembly state machine must
        # hold and re-concatenate thousands of blocks; every block stays ALLOWED
        # (first block = BF38, rest = mid-body splits).
        command = _padded_bf38(seed, target)
        blocks = chunk_command(command, 1)
        out.append(DeepBigMutation(
            label=f"massive_chain_{target}", mutation_class=CLASS_MASSIVE_CHAIN,
            target="BF38", target_tag=TAG_BF38,
            perturbs=f"BF38 split into {len(blocks)} single-byte STORE DATA blocks",
            command_tlv=command, blocks=tuple(blocks),
            size=len(command), keeps_ci_pkid_valid=True,
        ))

    return out


# --------------------------------------------------------------------------- #
# Class 5 — deep / oversized bodies to allowlisted READ commands.
# --------------------------------------------------------------------------- #


def read_deepbig_mutations(seed: AuthCommand) -> list[DeepBigMutation]:
    out: list[DeepBigMutation] = []

    def add(tag: int, label: str, perturbs: str, value: bytes, *, depth: int = 0) -> None:
        out.append(DeepBigMutation(
            label=label, mutation_class=CLASS_READ_DEEPBIG,
            target=f"{tag:04X}", target_tag=tag, perturbs=perturbs,
            command_tlv=_read_command(tag, value),
            depth=depth, size=len(value), keeps_ci_pkid_valid=False,
        ))

    for tag in READ_TAGS:
        name = ALLOWLIST_TAGS.get(tag, f"{tag:04X}")
        # Oversized flat body at 16 KB / 64 KB / 256 KB.
        for size in (16384, 65536, 262144):
            add(tag, f"read_{tag:04X}_oversized_{size}",
                f"{name} body {size}B flat 0x00", b"\x00" * size)
        # Oversized nested search-criteria: an A0 whose value is a huge blob.
        add(tag, f"read_{tag:04X}_a0_oversized",
            f"{name} A0 search-criteria 64KB value",
            ber.tlv(0xA0, b"\x11" * 65536))
        # Deep nesting (recursion) as the READ body.
        for depth in (128, 2048, 8192):
            add(tag, f"read_{tag:04X}_deepnest_{depth}",
                f"{name} body nested {depth} levels",
                build_nested_tlv(depth), depth=depth)

    return out


# --------------------------------------------------------------------------- #
# Class 6 — length-lie at scale (long-form length vs actual big body).
# --------------------------------------------------------------------------- #

# (label, form, delta) applied to the outer BF38 over a large body. ``over``/
# ``under`` declare the length off by ``delta`` bytes; ``truncated`` declares the
# full length but chops ``delta`` value bytes; ``long3``/``long4`` are non-minimal
# multi-byte length encodings of the true (large) length.
_LENGTH_LIE_FORMS: tuple[tuple[str, str, int], ...] = (
    ("long3", "long3", 0),
    ("long4", "long4", 0),
    ("over_4k", "over", 4096),
    ("over_64k", "over", 65536),
    ("under_4k", "under", 4096),
    ("truncated_4k", "truncated", 4096),
)


def length_lie_mutations(seed: AuthCommand) -> list[DeepBigMutation]:
    out: list[DeepBigMutation] = []
    # A large but structurally sound body so the length lie is the only defect.
    body = _body(seed, ctx=_ctx(b"\x00" * 16384))

    for label, form, delta in _LENGTH_LIE_FORMS:
        try:
            command_tlv = _wrap_bf38(body, form, delta)
        except Exception:  # noqa: BLE001 — length width too small for this size; skip
            continue
        out.append(DeepBigMutation(
            label=f"length_lie_{label}", mutation_class=CLASS_LENGTH_LIE,
            target="BF38", target_tag=TAG_BF38,
            perturbs=f"BF38 outer length {label} over a {len(body)}B body",
            command_tlv=command_tlv, size=len(body), keeps_ci_pkid_valid=True,
        ))

    return out


# --------------------------------------------------------------------------- #
# Top-level generator with self-check.
# --------------------------------------------------------------------------- #

# Outer tags a mutation is allowed to carry: BF38 plus the READ tags it targets.
# Every one is ALLOWED in ``safety.ALLOWLIST_TAGS``; the self-check enforces it.
_ALLOWED_TARGET_TAGS = frozenset({TAG_BF38, *READ_TAGS})


def _self_check(mutation: DeepBigMutation) -> None:
    """Every mutation's LOGICAL command must classify ALLOWED on its outer tag, and
    every explicit wire block must NOT classify BLOCKED. A failure is a generator bug
    that must never reach the card."""
    if mutation.target_tag not in _ALLOWED_TARGET_TAGS:
        raise DeepBigMutationError(
            f"mutation {mutation.label!r} targets non-allowlisted tag 0x{mutation.target_tag:04X}"
        )
    if mutation.target_tag not in ALLOWLIST_TAGS:
        raise DeepBigMutationError(
            f"mutation {mutation.label!r} outer tag 0x{mutation.target_tag:04X} not in safety allowlist"
        )
    verdict = classify(mutation.apdu_hex)
    if verdict.classification is not Classification.ALLOWED or verdict.tag != mutation.target_tag:
        raise DeepBigMutationError(
            f"mutation {mutation.label!r} logical command is not ALLOWED/0x{mutation.target_tag:04X}: "
            f"{verdict.classification.value} tag={verdict.tag}"
        )
    if mutation.blocks is not None:
        for block in mutation.blocks:
            if classify(block).classification is Classification.BLOCKED:
                raise DeepBigMutationError(
                    f"mutation {mutation.label!r} emits a BLOCKED wire block: {block[:32]}..."
                )


def generate_mutations(seed: AuthCommand) -> list[DeepBigMutation]:
    """All deep/big mutations, deduplicated and self-checked.

    Each returned mutation is a STORE DATA whose outer tag is BF38 or an
    allowlisted READ tag (never a destructive APDU). Raises DeepBigMutationError if
    any mutation fails its ALLOWED self-check.
    """
    mutations: list[DeepBigMutation] = []
    mutations += oversized_ctx_mutations(seed)
    mutations += deep_nesting_mutations(seed)
    mutations += huge_field_mutations(seed)
    mutations += massive_chain_mutations(seed)
    mutations += read_deepbig_mutations(seed)
    mutations += length_lie_mutations(seed)

    seen: set[tuple[bytes, tuple[str, ...] | None]] = set()
    unique: list[DeepBigMutation] = []
    for mutation in mutations:
        key = (mutation.command_tlv, mutation.blocks)
        if key in seen:
            continue
        seen.add(key)
        _self_check(mutation)
        unique.append(mutation)
    return unique


def counts_by_class(mutations: list[DeepBigMutation]) -> dict[str, int]:
    out: dict[str, int] = {name: 0 for name in CLASSES}
    for mutation in mutations:
        out[mutation.mutation_class] += 1
    return out


def max_depth_reached(mutations: list[DeepBigMutation]) -> int:
    return max((m.depth for m in mutations), default=0)


def max_size_reached(mutations: list[DeepBigMutation]) -> int:
    return max((m.size for m in mutations), default=0)


def max_blocks_reached(mutations: list[DeepBigMutation]) -> int:
    return max((len(m.blocks) for m in mutations if m.blocks is not None), default=0)
