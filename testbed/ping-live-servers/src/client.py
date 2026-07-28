"""HTTP client for ES9+/ES11 requests, with a hard live-fire safety guard.

Default target is always the local ecosim-backed shim server
(targets.LOCAL_SIM_SMDP / LOCAL_SIM_SMDS). Any target whose `is_local` is
False requires BOTH:

  1. the caller passing allow_live_fire=True, and
  2. the environment variable ESIM_MITM_ALLOW_LIVE_FIRE=1 being set.

Both gates must be true together so a single flipped flag (a stray CLI
default, e.g.) can never alone send a live request. Neither gate is set
anywhere in this repo or in any script's default arguments -- live execution
is a decision the orchestrating session makes separately, later.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .envelope import ADMIN_PROTOCOL, CONTENT_TYPE, USER_AGENT, FunctionHeader, wrap_request
from .errors import LiveFireNotAuthorizedError, MalformedResponseError, TransportError
from .targets import Target

LIVE_FIRE_ENV_VAR = "ESIM_MITM_ALLOW_LIVE_FIRE"


@dataclass
class RspHttpClient:
    target: Target
    requester_identifier: str = "esim-mitm-research"
    timeout_seconds: float = 15.0
    allow_live_fire: bool = False
    ssl_context: ssl.SSLContext | None = None

    def __post_init__(self) -> None:
        if not self.target.is_local and not self._live_fire_authorized():
            raise LiveFireNotAuthorizedError(
                f"target {self.target.base_url!r} is not the local sim; live-fire requires "
                f"allow_live_fire=True AND ${LIVE_FIRE_ENV_VAR}=1. Neither is set in this "
                f"research phase -- live execution is gated by the orchestrating session."
            )

    def _live_fire_authorized(self) -> bool:
        return self.allow_live_fire and os.environ.get(LIVE_FIRE_ENV_VAR) == "1"

    def call(self, interface: str, function: str, path: str, body: dict[str, object]) -> dict[str, object]:
        """POST `body` (already wire-shaped, e.g. via a models.*Request.to_wire())
        to `path` on this client's target, wrapped in the GSMA function header.
        Returns the parsed JSON response body. Raises TransportError on any
        connection/HTTP failure, MalformedResponseError if the response is not
        valid JSON."""
        header = FunctionHeader(self.requester_identifier, f"{function}-{id(body)}")
        envelope = wrap_request(body, header)
        data = json.dumps(envelope).encode("utf-8")
        url = self.target.base_url.rstrip("/") + path
        request = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "Content-Type": CONTENT_TYPE,
                "Accept": CONTENT_TYPE,
                "User-Agent": USER_AGENT,
                "X-Admin-Protocol": ADMIN_PROTOCOL,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds, context=self.ssl_context) as resp:
                raw = resp.read()
        except urllib.error.URLError as exc:
            raise TransportError(f"{interface}.{function} request to {url} failed: {exc}") from exc
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise MalformedResponseError(f"{interface}.{function} response was not valid JSON") from exc
