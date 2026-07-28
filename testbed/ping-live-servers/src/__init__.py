"""Reusable ES9+/ES11 request-builder library for the ping-live-servers testbed.

Everything here is transport-agnostic and safe to import: building a request
or a real-provider Target never sends anything. Only `client.RspHttpClient`
performs I/O, and it refuses non-local targets without an explicit,
double-gated opt-in (see `client.py`).
"""

from __future__ import annotations
