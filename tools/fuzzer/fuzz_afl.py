"""AFL-style, coverage-guided mutation with atheris.

## The coverage caveat, stated plainly

The eUICC is a black box behind an opaque APDU pipe. There is **no in-process
coverage of the secure element**: atheris cannot see a single branch inside the
card. So atheris here guides on the coverage of *this project's Python* — the
safety classifier and the APDU builders — which is real but is not the target's
coverage.

The signal that actually matters for the target is a **proxy**: the diversity of
status words (live) and safety classifications (dry-run) recorded by the engine.
Each distinct SW or classification class is one observed behaviour of the card.
See ``engine.FuzzEngine.summary``.

This harness mutates seed bytes into candidate APDUs and feeds every candidate
through the safety layer. In dry-run nothing is sent; the proxy signal is the
classifier's verdict distribution.

Run it directly under libFuzzer/atheris::

    tools/fuzzer/.venv/bin/python tools/fuzzer/fuzz_afl.py tools/fuzzer/seeds/

Or through the single entrypoint::

    tools/fuzzer/.venv/bin/python tools/fuzzer/run_fuzz.py --mode afl
"""

from __future__ import annotations

import atexit
import logging
import sys

try:
    import atheris
    _HAVE_ATHERIS = True
except ImportError:
    atheris = None  # type: ignore[assignment]
    _HAVE_ATHERIS = False

if _HAVE_ATHERIS:
    with atheris.instrument_imports():
        from engine import FuzzEngine
        from safety import classify
else:
    from engine import FuzzEngine
    from safety import classify

log = logging.getLogger("fuzzer.afl")

# One store-data prefix used to frame mutated bodies into valid commands.
_STORE_DATA_PREFIX = bytes([0x81, 0xE2, 0x91, 0x00])


def build_candidate(data: bytes) -> str | None:
    """Turn fuzzer bytes into a candidate APDU hex string.

    Two shapes, selected by the first byte:
    - a raw 4-byte header (exercises prefix and write-instruction branches)
    - a well-framed store-data command carrying a mutated BER-TLV
    Returns None when there are too few bytes to build anything.
    """
    if len(data) < 5:
        return None

    selector = data[0] & 1
    rest = data[1:]

    if selector == 0:
        return rest[:4].hex().upper()

    tag = rest[:2]
    value = rest[2:18]
    tlv = tag + bytes([len(value)]) + value
    apdu = _STORE_DATA_PREFIX + bytes([len(tlv)]) + tlv
    return apdu.hex().upper()


def make_target(engine: FuzzEngine):
    """Build the atheris ``TestOneInput`` closure bound to an engine."""

    def test_one_input(data: bytes) -> None:
        apdu_hex = build_candidate(data)
        if apdu_hex is None:
            return
        # classify is instrumented; atheris guides on its branch coverage.
        classify(apdu_hex)
        # The engine gates and records the proxy SW/classification signal. It
        # swallows SafetyError internally, so no expected exception escapes.
        engine.consider(apdu_hex)

    return test_one_input


def main(argv: list[str]) -> None:
    """Entry point for direct atheris execution."""
    if not _HAVE_ATHERIS:
        raise RuntimeError(
            "atheris is not installed in this venv; install it to run the AFL mode"
        )

    logging.basicConfig(level=logging.INFO)
    engine = FuzzEngine(live=False)
    atexit.register(lambda: log.info("afl mode diversity: %s", engine.summary()))

    atheris.Setup(argv, make_target(engine))
    atheris.Fuzz()


if __name__ == "__main__":
    main(sys.argv)
