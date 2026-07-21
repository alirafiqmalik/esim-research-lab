"""Transport adapter to the eUICC ISD-R through the project CLI.

The fuzzer never talks to the card directly. It shells out to the post-migration
CLI:

    python3 -m esim.cli euicc apdu <HEX>

run with cwd set to the repo root. The CLI prints a JSON object on stdout::

    {"resp": "...9000", "sw": "9000", "ok": true, ...}

This adapter parses that into an :class:`ApduResult`.

The ``euicc apdu`` subcommand lands in migration Phase 3 and does not exist in
this worktree yet. This adapter only references the command string; it is unit
tested with ``subprocess.run`` mocked and must never be pointed at a device by a
test.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

_CLI_MODULE = "esim.cli"
_TIMEOUT_SECONDS = 30


class TransportError(Exception):
    """Raised when the CLI call fails or returns output the adapter cannot parse."""


@dataclass(frozen=True)
class ApduResult:
    """One APDU exchange result parsed from the CLI JSON."""

    resp_hex: str
    sw: str
    ok: bool
    raw: dict[str, object]


class EuiccTransport:
    """Send APDUs to the eUICC ISD-R via the project CLI subprocess."""

    def __init__(self, repo_root: Path, python_executable: str | None = None) -> None:
        self._repo_root = repo_root
        self._python = python_executable or sys.executable

    def send(self, apdu_hex: str) -> ApduResult:
        """Send one hex APDU and return the parsed result.

        Raises TransportError on a non-zero exit, malformed JSON, or missing keys.
        """
        cleaned = apdu_hex.strip().replace(" ", "")
        cmd = [self._python, "-m", _CLI_MODULE, "euicc", "apdu", cleaned]
        try:
            proc = subprocess.run(
                cmd,
                cwd=self._repo_root,
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise TransportError(f"CLI timed out after {_TIMEOUT_SECONDS}s: {cmd}") from exc

        if proc.returncode != 0:
            raise TransportError(
                f"CLI exited {proc.returncode}: {proc.stderr.strip() or proc.stdout.strip()}"
            )

        return self._parse(proc.stdout, apdu_hex)

    @staticmethod
    def _parse(stdout: str, apdu_hex: str) -> ApduResult:
        text = stdout.strip()
        if not text:
            raise TransportError(f"empty CLI output for APDU {apdu_hex}")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise TransportError(f"CLI output is not JSON: {text!r}") from exc
        if not isinstance(data, dict):
            raise TransportError(f"CLI JSON is not an object: {text!r}")

        for key in ("resp", "sw", "ok"):
            if key not in data:
                raise TransportError(f"CLI JSON missing {key!r}: {text!r}")

        return ApduResult(
            resp_hex=str(data["resp"]),
            sw=str(data["sw"]),
            ok=bool(data["ok"]),
            raw=data,
        )
