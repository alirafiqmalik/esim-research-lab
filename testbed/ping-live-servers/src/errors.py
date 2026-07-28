"""Exceptions for the ES9+/ES11 request-builder library.

Repo style: raise on error, never return None to signal failure.
"""

from __future__ import annotations


class RspClientError(Exception):
    """Base class for every error this library raises."""


class MalformedResponseError(RspClientError):
    """A server (or local sim) response is missing a required field, or is malformed."""


class LiveFireNotAuthorizedError(RspClientError):
    """Raised when a script targets a non-local (real-provider) host without both
    required opt-ins present. See client.py -- this is the hard safety guard."""


class TransportError(RspClientError):
    """The HTTP request itself failed: connection, timeout, or transport-level error."""
