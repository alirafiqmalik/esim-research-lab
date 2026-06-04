import dataclasses
import json
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from esim.device import Device

LPA_LOG_TAGS = [
    "EuiccManager", "EuiccCardController", "EuiccController",
    "LpaService", "SM-DS",
]


class PinningDetected(Warning):
    pass


@dataclass
class CaptureSession:
    session_dir: Path
    metadata: dict = field(default_factory=dict)


class Capture:
    def __init__(self, device: Device, port: int = 8080,
                 filters: list[str] | None = None,
                 sessions_root: "Path | str" = "sessions"):
        self.device = device
        self.port = port
        self.filters = filters or ["ES9+", "ES11"]
        self._sessions_root = Path(sessions_root)
        self._mitm_proc: subprocess.Popen | None = None
        self._logcat_proc: subprocess.Popen | None = None
        self._logcat_lines: list[str] = []
        self._session_dir: Path | None = None
        self._start_time: datetime | None = None
        self._euicc_state_start = None

    def __enter__(self) -> "Capture":
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-T%H%M%S")
        self._session_dir = self._sessions_root / ts
        self._session_dir.mkdir(parents=True, exist_ok=True)
        self._start_time = datetime.now(timezone.utc)
        self._euicc_state_start = self.device.get_euicc_state()

        mitm_out = self._session_dir / "traffic.mitm"
        self._mitm_proc = subprocess.Popen(
            ["mitmdump", "-w", str(mitm_out),
             "--listen-port", str(self.port), "--quiet"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        adb_cmd = (self.device._adb_prefix + ["logcat", "-v", "time"] +
                   [f"{tag}:D" for tag in LPA_LOG_TAGS] + ["*:S"])
        self._logcat_proc = subprocess.Popen(
            adb_cmd, stdout=subprocess.PIPE, text=True,
        )
        self._logcat_thread = threading.Thread(
            target=self._collect_logcat, daemon=True,
        )
        self._logcat_thread.start()
        return self

    def _collect_logcat(self) -> None:
        assert self._logcat_proc and self._logcat_proc.stdout
        for line in self._logcat_proc.stdout:
            self._logcat_lines.append(line.rstrip())

    def __exit__(self, *_) -> None:
        if self._mitm_proc:
            self._mitm_proc.terminate()
            self._mitm_proc.wait(timeout=5)
        if self._logcat_proc:
            self._logcat_proc.terminate()
            self._logcat_proc.wait(timeout=5)

    def save(self, out_dir: "Path | str | None" = None) -> CaptureSession:
        assert self._session_dir and self._start_time
        target = Path(out_dir) if out_dir else self._session_dir
        target.mkdir(parents=True, exist_ok=True)

        (target / "logcat.txt").write_text("\n".join(self._logcat_lines))
        (target / "euicc_state.json").write_text(json.dumps({
            "start": self._state_to_dict(self._euicc_state_start),
            "end": self._state_to_dict(self.device.get_euicc_state()),
        }, indent=2))

        meta = {
            "serial": self.device.serial,
            "eid": self._safe_eid(),
            "subscriptions": [vars(s) for s in self.device.list_subscriptions()],
            "started_at": self._start_time.isoformat(),
            "duration_s": (datetime.now(timezone.utc) - self._start_time).total_seconds(),
        }
        (target / "metadata.json").write_text(json.dumps(meta, indent=2))

        mitm_src = self._session_dir / "traffic.mitm"
        mitm_dst = target / "traffic.mitm"
        if mitm_src.exists() and mitm_src != mitm_dst:
            mitm_src.rename(mitm_dst)

        # HAR export deferred — open traffic.mitm with `mitmweb -r traffic.mitm`
        # or use Session._load_flows() via the Analysis API.

        return CaptureSession(session_dir=target, metadata=meta)

    @staticmethod
    def _state_to_dict(state) -> dict:
        """Convert an EuiccState (or similar) to a JSON-safe dict."""
        if state is None:
            return {}
        if dataclasses.is_dataclass(state) and not isinstance(state, type):
            return dataclasses.asdict(state)
        # Fallback: pull only string/number attributes to avoid mock internals
        try:
            return {k: v for k, v in vars(state).items()
                    if isinstance(v, (str, int, float, bool, type(None)))}
        except TypeError:
            return {}

    def _safe_eid(self) -> str:
        try:
            return self.device.get_eid()
        except Exception:
            return ""
