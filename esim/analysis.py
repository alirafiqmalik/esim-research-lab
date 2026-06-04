import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RSPCall:
    timestamp_ms: float
    method: str
    url: str
    request_body: dict
    response_body: dict
    interface: str  # "ES11" | "ES9+"


@dataclass
class LogEvent:
    timestamp_ms: float
    tag: str
    message: str


class Session:
    def __init__(self, session_dir: Path):
        self._dir = Path(session_dir)
        self._metadata = json.loads((self._dir / "metadata.json").read_text())
        self._logcat_raw = (self._dir / "logcat.txt").read_text()
        self._flows = self._load_flows()
        self._rsp_calls_cache: list[RSPCall] | None = None

    @classmethod
    def load(cls, path: "str | Path") -> "Session":
        return cls(path)

    def _load_flows(self) -> list:
        mitm_path = self._dir / "traffic.mitm"
        if not mitm_path.exists() or mitm_path.stat().st_size == 0:
            return []
        try:
            from mitmproxy.io import FlowReader
            from mitmproxy.http import HTTPFlow
            flows = []
            with open(mitm_path, "rb") as f:
                reader = FlowReader(f)
                for flow in reader.stream():
                    if isinstance(flow, HTTPFlow):
                        flows.append(flow)
            return flows
        except Exception:
            return []

    def es11_calls(self) -> list:
        return [c for c in self._parse_rsp_calls() if c.interface == "ES11"]

    def es9_calls(self) -> list:
        return [c for c in self._parse_rsp_calls() if c.interface == "ES9+"]

    def bpp_blobs(self) -> list:
        return [
            c.response_body["boundProfilePackage"]
            for c in self.es9_calls()
            if "getBoundProfilePackage" in c.method
            and "boundProfilePackage" in c.response_body
        ]

    def logcat_events(self) -> list:
        events = []
        for line in self._logcat_raw.splitlines():
            event = _parse_logcat_line(line)
            if event:
                events.append(event)
        return events

    def timeline(self) -> list:
        items = []
        for call in self._parse_rsp_calls():
            items.append({
                "t_ms": call.timestamp_ms,
                "type": "network",
                "interface": call.interface,
                "method": call.method,
            })
        for event in self.logcat_events():
            items.append({
                "t_ms": event.timestamp_ms,
                "type": "logcat",
                "tag": event.tag,
                "message": event.message,
            })
        return sorted(items, key=lambda x: x["t_ms"])

    def _parse_rsp_calls(self) -> list[RSPCall]:
        if self._rsp_calls_cache is None:
            self._rsp_calls_cache = self._build_rsp_calls()
        return self._rsp_calls_cache

    def _build_rsp_calls(self) -> list[RSPCall]:
        calls = []
        for flow in self._flows:
            url = flow.request.pretty_url
            interface = _detect_interface(url)
            if not interface:
                continue
            method = url.rstrip("/").split("/")[-1]
            try:
                req_body = json.loads(flow.request.text or "{}")
            except Exception:
                req_body = {}
            try:
                resp_body = json.loads(
                    flow.response.text if flow.response else "{}"
                )
            except Exception:
                resp_body = {}
            calls.append(RSPCall(
                timestamp_ms=flow.request.timestamp_start * 1000,
                method=method,
                url=url,
                request_body=req_body,
                response_body=resp_body,
                interface=interface,
            ))
        return calls


_LOGCAT_RE = re.compile(
    r"(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\d+\s+\d+\s+\w\s+(\S+?):\s*(.*)"
)


def _detect_interface(url: str) -> "str | None":
    lower = url.lower()
    if "/es11/" in lower:
        return "ES11"
    if "/es9plus/" in lower or "/es9+/" in lower:
        return "ES9+"
    return None


def _parse_logcat_line(line: str) -> "LogEvent | None":
    m = _LOGCAT_RE.match(line)
    if not m:
        return None
    try:
        ts = m.group(1)  # "MM-DD HH:MM:SS.fff"
        time_part = ts[6:]  # "HH:MM:SS.fff"
        h, rest = time_part.split(":", 1)
        mins, rest = rest.split(":", 1)
        secs, ms = rest.split(".", 1)
        t_ms = (int(h) * 3600 + int(mins) * 60 + int(secs)) * 1000 + int(ms)
    except (ValueError, IndexError):
        t_ms = 0.0
    return LogEvent(timestamp_ms=t_ms, tag=m.group(2), message=m.group(3))
