"""Same-channel sequence transport to the eUICC ISD-R via the project CLI.

The stateful fuzzer never talks to the card directly. It shells out to:

    python3 -m esim.cli euicc seq HEX1 HEX2 ... RESET ...

run with cwd set to the repo root. Every APDU in the list runs on ONE persistent
ISD-R logical channel, so transient card state persists across them. A literal
``RESET`` token close+reopens the channel (re-SELECT ISD-R, clears transient
state only; it is NEVER eUICCMemoryReset).

The CLI prints one JSON object on stdout::

    {"op": "seq", "backend": "lpac", "results": [
        {"apdu": "80CA00...", "resp": "...9000", "ok": true},
        {"apdu": "RESET", "resp": "", "ok": true, "reset": true},
        ...
    ]}

This adapter parses the ``results`` array into a list of :class:`SeqStepResult`.

The ``euicc seq`` subcommand runs against a live device. This adapter only builds
the command string; it is unit tested with ``subprocess.run`` mocked and must
never be pointed at a device by a test.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

_CLI_MODULE = "esim.cli"
_TIMEOUT_SECONDS = 60
_PER_STEP_SECONDS = 0.5  # extra headroom per token for large sequences
_RESET_TOKEN = "RESET"


class SeqTransportError(Exception):
    """Raised when the CLI call fails or returns output the adapter cannot parse."""


@dataclass(frozen=True)
class SeqStepResult:
    """One element result from a same-channel sequence.

    ``apdu`` is the input token (an APDU hex, or the literal ``RESET``). ``sw`` is
    the trailing two bytes of ``resp`` (empty for a RESET step). ``reset`` marks a
    non-destructive channel reset step.
    """

    apdu: str
    resp_hex: str
    sw: str
    ok: bool
    reset: bool
    raw: dict[str, object]

    @property
    def is_reset(self) -> bool:
        return self.reset


class SeqTransport:
    """Send same-channel APDU sequences to the eUICC ISD-R via the project CLI."""

    def __init__(self, repo_root: Path, python_executable: str | None = None) -> None:
        self._repo_root = repo_root
        self._python = python_executable or sys.executable

    def send_sequence(self, seq: list[str]) -> list[SeqStepResult]:
        """Send one same-channel sequence and return per-step results.

        ``seq`` is a list of APDU hex strings and/or the literal ``RESET`` token.
        RESET tokens pass through to the CLI untouched. Raises SeqTransportError
        on a non-zero exit, malformed JSON, or a missing ``results`` array.

        This adapter does NOT classify APDUs. Guarding is the caller's job via
        ``seq_safety.guard_sequence`` and must run BEFORE this method.
        """
        if not seq:
            raise SeqTransportError("empty sequence")

        tokens = [self._normalize(tok) for tok in seq]
        cmd = [self._python, "-m", _CLI_MODULE, "euicc", "seq", *tokens]
        # The CLI transparently switches to on-device file delivery for large/many-block
        # sequences (bypassing the intent-extra and logcat-line limits), but those run
        # many more card round trips — scale the host-side subprocess timeout with length.
        timeout = self._timeout(len(tokens))
        try:
            proc = subprocess.run(
                cmd,
                cwd=self._repo_root,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise SeqTransportError(
                f"CLI timed out after {timeout}s: {cmd}"
            ) from exc

        if proc.returncode != 0:
            raise SeqTransportError(
                f"CLI exited {proc.returncode}: "
                f"{proc.stderr.strip() or proc.stdout.strip()}"
            )

        return self._parse(proc.stdout, tokens)

    @staticmethod
    def _timeout(n_tokens: int) -> int:
        return max(_TIMEOUT_SECONDS, int(n_tokens * _PER_STEP_SECONDS))

    @staticmethod
    def _normalize(token: str) -> str:
        if token.strip().upper() == _RESET_TOKEN:
            return _RESET_TOKEN
        return token.strip().replace(" ", "")

    @staticmethod
    def _parse(stdout: str, tokens: list[str]) -> list[SeqStepResult]:
        text = stdout.strip()
        if not text:
            raise SeqTransportError(f"empty CLI output for sequence {tokens}")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SeqTransportError(f"CLI output is not JSON: {text!r}") from exc
        if not isinstance(data, dict):
            raise SeqTransportError(f"CLI JSON is not an object: {text!r}")
        if "error" in data:
            raise SeqTransportError(f"CLI reported error: {data['error']!r}")

        results = data.get("results")
        if not isinstance(results, list):
            raise SeqTransportError(f"CLI JSON missing 'results' array: {text!r}")

        parsed: list[SeqStepResult] = []
        for element in results:
            if not isinstance(element, dict):
                raise SeqTransportError(f"result element is not an object: {element!r}")
            parsed.append(SeqTransport._parse_element(element))
        return parsed

    @staticmethod
    def _parse_element(element: dict[str, object]) -> SeqStepResult:
        for key in ("apdu", "resp", "ok"):
            if key not in element:
                raise SeqTransportError(f"result element missing {key!r}: {element!r}")
        resp_hex = str(element["resp"])
        reset = bool(element.get("reset", False))
        sw = str(element["sw"]) if "sw" in element else resp_hex[-4:]
        return SeqStepResult(
            apdu=str(element["apdu"]),
            resp_hex=resp_hex,
            sw=sw,
            ok=bool(element["ok"]),
            reset=reset,
            raw=element,
        )


class LargeSeqTransport(SeqTransport):
    """Same interface as :class:`SeqTransport`, for oversized / many-block sequences.

    Delivery of large sequences is handled by the CLI itself: `esim euicc seq` stages
    the tokens in an on-device file (``--es apdus_file``) once they exceed the inline
    intent-extra bound, and reads the results back from a device-side ``--es
    results_file`` — bypassing the binder intent-extra limit (in) and the ~4KB logcat
    line cap (out). This subclass is a semantic marker plus a longer per-token timeout
    budget for sequences with thousands of card round trips; the guarding contract is
    unchanged (``seq_safety.guard_sequence`` MUST run BEFORE send_sequence).
    """

    _PER_STEP_SECONDS_LARGE = 1.0

    @classmethod
    def _timeout(cls, n_tokens: int) -> int:
        return max(_TIMEOUT_SECONDS, int(n_tokens * cls._PER_STEP_SECONDS_LARGE))
