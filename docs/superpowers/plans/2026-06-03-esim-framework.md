# eSIM Research Framework — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone Python eSIM research library + CLI (`esim/`) with `.claude/` dev infrastructure for autonomous, multi-agent research sessions on an unrooted Android device via ADB.

**Architecture:** `.claude/` rules/skills/agents/notes govern how Claude builds and extends the framework. `esim/` is a standalone Python package: `Device` wraps ADB calls, `Capture` runs mitmproxy + logcat concurrently, `Analysis` parses saved sessions. `tools/` holds one-time PC hotspot setup scripts. All Python code is test-driven with mocked ADB subprocess calls.

**Tech Stack:** Python 3.12+, Click 8+, mitmproxy 10+, pytest 8+, unittest.mock, ADB (system), hostapd + NetworkManager (Linux hotspot)

---

### Task 1: Project scaffold

**Files:**
- Create: `pyproject.toml`
- Create: `esim/__init__.py`
- Create: `tests/__init__.py`
- Create: `.gitignore`

- [ ] **Step 1: Write pyproject.toml**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "esim"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "click>=8.0",
    "mitmproxy>=10.0",
]

[project.scripts]
esim = "esim.cli:main"

[project.optional-dependencies]
dev = ["pytest>=8.0", "pytest-mock>=3.0"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Create directory structure and package stubs**

```bash
mkdir -p esim tests tools sessions .claude/{skills,agents,rules,notes} docs/superpowers/{specs,plans}
touch sessions/.gitkeep tools/.gitkeep
```

`esim/__init__.py`: (empty — populated progressively as modules are created)

`tests/__init__.py`: (empty file)

- [ ] **Step 3: Write .gitignore**

```gitignore
__pycache__/
*.py[cod]
*.egg-info/
dist/
.eggs/
sessions/
*.mitm
*.har
bugreport*.zip
.env
```

- [ ] **Step 4: Install in editable mode**

```bash
pip install -e ".[dev]"
```

Expected: no errors; `esim` command registered but will error until cli.py exists.

- [ ] **Step 5: Verify pytest baseline**

```bash
pytest -v
```

Expected: "no tests ran" or "collected 0 items".

- [ ] **Step 6: Commit**

```bash
git init
git add pyproject.toml esim/__init__.py tests/__init__.py .gitignore
git commit -m "feat: project scaffold"
```

---

### Task 2: .claude/ rules

**Files:**
- Create: `.claude/rules/markdown-style.md`
- Create: `.claude/rules/orchestrator.md`
- Create: `.claude/rules/code-style.md`

- [ ] **Step 1: Write markdown-style.md**

```markdown
# Markdown Style

All Markdown files must read like they were written by a senior developer who values
their reader's time. Apply to every .md file in this project.

## Banned phrases

Never use: "delve", "leverage", "robust", "seamless", "cutting-edge", "streamline",
"empower", "it's worth noting", "in order to", "as mentioned above", "please note",
"rest assured", "comprehensive", "holistic", "end-to-end", "moving forward",
"going forward", "at the end of the day", "I hope this helps".

## Rules

- Active voice. "Run the command" — not "The command should be run."
- Short sentences. If a sentence needs a comma to hold two thoughts, split it.
- Headers are noun phrases or imperative verbs — not questions.
- One idea per bullet. Bullets are not paragraphs.
- Code blocks for anything that runs in a terminal or goes into a file.
- No setup sentences: "In this section we will explore..."
- No summary sentences: "As you can see above..."
- No hedge padding: "generally speaking", "in most cases", "typically".
- Say the specific thing, not the general thing with qualifiers.

## Length

Cut until it hurts, then cut once more.
```

- [ ] **Step 2: Write orchestrator.md**

```markdown
# Orchestrator Rule

The main Claude Code session is the orchestrator. It plans, delegates, and synthesizes.
It does not write implementation code or run long-blocking tasks directly.

## Subagent limits

- Maximum 2-3 subagents running concurrently.
- Each subagent gets one scoped, actionable task — not a vague directive.
- A task is scoped enough if a subagent can complete it without asking clarifying questions.

## Context sharing

When two subagents need awareness of each other's output, the orchestrator extracts a
compact context block (key facts, decisions, current state) and passes it to each.
Never make subagents read each other's full transcript.

## Clean-slate subagents

Spin up a subagent with no conversation history when:
- Brainstorming or generating options (avoids anchoring on prior decisions)
- The current approach is stuck (fresh perspective, no sunk-cost bias)
- Critical review of work done in this session (avoids confirmation bias)

## Task handoff format

When dispatching a subagent, always include:
1. What to build or do (specific, not vague)
2. Which files to touch
3. What done looks like (acceptance criteria)
4. Compact context from any dependent prior work
```

- [ ] **Step 3: Write code-style.md**

```markdown
# Python Code Style

- Python 3.12+. Use `list[str]`, `dict[str, int]`, `str | None` — not `List`, `Dict`, `Optional`.
- Type hints on every public function signature. Not on local variables unless ambiguous.
- Dataclasses for data objects. No plain dicts returned from the public API.
- Raise exceptions on error. Never return `None` to signal failure.
- No `print()` in library code. Return values, raise exceptions.
- No global state. All state lives on class instances.
- Comments only when the WHY is non-obvious — never to describe what the code does.
- `subprocess.run(..., capture_output=True, text=True, timeout=30)` for ADB calls.
- Tests mock `subprocess.run` via `unittest.mock.patch` — never hit real ADB in unit tests.
```

- [ ] **Step 4: Commit**

```bash
git add .claude/rules/
git commit -m "chore: add .claude/ rules (markdown, orchestrator, code style)"
```

---

### Task 3: .claude/ skills, agents, and notes

**Files:**
- Create: `.claude/skills/adb-probe.md`
- Create: `.claude/skills/run-capture.md`
- Create: `.claude/skills/scaffold-module.md`
- Create: `.claude/skills/analyze-session.md`
- Create: `.claude/agents/impl-worker.md`
- Create: `.claude/agents/test-runner.md`
- Create: `.claude/agents/adb-monitor.md`
- Create: `.claude/notes/device-cph2515.md`
- Create: `.claude/notes/tls-pinning-status.md`
- Create: `.claude/notes/rsp-observations.md`

- [ ] **Step 1: Write skill files**

`.claude/skills/adb-probe.md`:
```markdown
---
name: adb-probe
description: Verify ADB connectivity and collect device baseline state (EID, subscriptions, eUICC dump) before starting a research session
---

# ADB Probe

Use at the start of any session to verify the device is connected and collect baseline state.

## Steps

1. Verify device connected:
   ```bash
   adb devices
   ```
   Expected: one device listed, not "unauthorized" or "offline".

2. Get EID:
   ```bash
   esim eid
   ```

3. List subscriptions — note the sub_id for the eSIM profile:
   ```bash
   esim profiles list
   ```

4. Dump eUICC state:
   ```bash
   adb shell dumpsys euicc_card_controller > sessions/euicc_state_$(date +%Y%m%d).txt
   ```

5. Update `.claude/notes/device-cph2515.md` with any new command output or parser findings.
```

`.claude/skills/run-capture.md`:
```markdown
---
name: run-capture
description: Start a mitmproxy + logcat capture session with correct pre-checks and flags
---

# Run Capture

## Pre-checks

1. Hotspot is active: `nmcli connection show esim-hotspot | grep "GENERAL.STATE"`
2. Phone is connected to hotspot (check phone Wi-Fi settings).
3. Phone proxy is set to `<PC_IP>:8080`.
4. mitmproxy CA cert is installed on the phone.
5. ADB device is connected: `adb devices`.

## Start capture

```bash
esim capture start --port 8080
```

Trigger eSIM activity on the phone. Press Ctrl-C to stop.

## After capture

```bash
esim session analyze sessions/<timestamp>/
```

Check `.claude/notes/tls-pinning-status.md` and update based on whether flows appeared.
```

`.claude/skills/scaffold-module.md`:
```markdown
---
name: scaffold-module
description: Add a new esim/ module with tests and CLI hook following project conventions
---

# Scaffold Module

## Steps

1. Create `esim/<name>.py` with a class or functions.
2. Create `tests/test_<name>.py` with at least one test per public function.
3. Export the new class/function from `esim/__init__.py` if it belongs in the public API.
4. Add a CLI command in `esim/cli.py` if user-facing.
5. Run `pytest tests/test_<name>.py -v` — all tests must pass.
6. Commit: `git commit -m "feat: add <name> module"`.
```

`.claude/skills/analyze-session.md`:
```markdown
---
name: analyze-session
description: Load and summarize a saved capture session — ES11/ES9+ call counts, BPP blobs, logcat events
---

# Analyze Session

```bash
esim session analyze sessions/<timestamp>/
```

For a deeper look using the Python API:

```python
from esim.analysis import Session

s = Session.load("sessions/<timestamp>/")
print(s.timeline())
for call in s.es9_calls():
    print(call.method, call.url)
    print("Request:", call.request_body)
    print("Response:", call.response_body)
```

Update `.claude/notes/rsp-observations.md` with any new protocol findings.
```

- [ ] **Step 2: Write agent files**

`.claude/agents/impl-worker.md`:
```markdown
---
name: impl-worker
description: Writes or edits Python code in esim/ — receives a scoped task with specific files and acceptance criteria from the orchestrator
---

# Implementation Worker

Receives from orchestrator:
- Which file(s) to create or modify (exact paths)
- The specific function/class to implement
- Acceptance criteria (which tests must pass)
- Compact context from dependent prior work

## Behavior

- TDD: write the failing test first, then implement.
- Run `pytest tests/` after each function is complete.
- Follow `.claude/rules/code-style.md`.
- Do not touch files outside the specified scope.
- Report back: "Done — tests pass" or "Blocked — [specific issue]".
```

`.claude/agents/test-runner.md`:
```markdown
---
name: test-runner
description: Runs pytest and reports failures back to the orchestrator with exact error output
---

# Test Runner

## Standard run

```bash
pytest tests/ -v --tb=short 2>&1
```

## On failure

Report the exact failing test name and traceback to the orchestrator. Do not attempt fixes.

## On pass

Report: "All N tests pass."
```

`.claude/agents/adb-monitor.md`:
```markdown
---
name: adb-monitor
description: Streams and saves filtered logcat output for a research session
---

# ADB Monitor

## Start monitoring

```bash
adb logcat -v time EuiccManager:D EuiccCardController:D EuiccController:D LpaService:D *:S \
  | tee sessions/<timestamp>/logcat.txt
```

## Stop

Ctrl-C when the session is complete.

## Report to orchestrator

Paste the last 20 lines of logcat.txt after stopping.
```

- [ ] **Step 3: Write note files**

`.claude/notes/device-cph2515.md`:
```markdown
---
name: device-cph2515
description: OnePlus Nord N30 5G (CPH2515) T-Mobile — verified ADB commands, OxygenOS output format quirks, dumpsys parsing notes
---

# Device: OnePlus Nord N30 5G (CPH2515)

- ADB serial: 3ddf2893
- OEM: OnePlus, OxygenOS (Android 13)
- Carrier: T-Mobile US
- TLS pinning: untested — see tls-pinning-status.md after first capture

## Verified ADB commands

Populate this section as commands are tested against the real device.
Format: command → output note or parsing adjustment needed.

## Parser notes

If `_parse_subscriptions()` in `esim/device.py` returns empty on the real device,
run `adb shell dumpsys phone | grep -i subscriptioninfo` and compare the output
format to the regex in `_SUB_PATTERN`. Adjust the regex and update this note.
```

`.claude/notes/tls-pinning-status.md`:
```markdown
---
name: tls-pinning-status
description: Whether mitmproxy successfully intercepts LPA HTTPS traffic on this device — updated after each capture attempt
---

# TLS Pinning Status

**Device:** OnePlus Nord N30 5G (CPH2515)
**Last tested:** not yet

## Status

Untested.

Run `esim capture start` with mitmproxy active and trigger eSIM activity on the phone.
If no HTTPS flows appear in `traffic.mitm` within 30s, `Capture` will emit `PinningDetected`.

Update this file after each test with: date, what was triggered, result (flows captured / pinning detected).
```

`.claude/notes/rsp-observations.md`:
```markdown
---
name: rsp-observations
description: Protocol-level RSP findings from capture sessions — ES11, ES9+, BPP observations accumulated over time
---

# RSP Protocol Observations

Populated from `esim session analyze` output after each capture session.

## Format

Date | Session path | ES11 calls | ES9+ calls | Notes
```

- [ ] **Step 4: Commit**

```bash
git add .claude/
git commit -m "chore: add .claude/ skills, agents, notes"
```

---

### Task 4: Device class

**Files:**
- Create: `esim/device.py`
- Create: `tests/test_device.py`

- [ ] **Step 1: Write failing tests**

`tests/test_device.py`:
```python
from unittest.mock import patch, MagicMock
import pytest
from esim.device import Device, Subscription, ADBError

DUMPSYS_EUICC = """
EuiccController:
  EID: 89049032004008882600000000000000
  Installed profiles: 1
"""

DUMPSYS_PHONE = """
Phone {id=0}:
  mSubscriptions:
    SubscriptionInfo {id=1, iccId=89012703278015354865, simSlotIndex=0, displayName=T-Mobile, isEmbedded=false}
    SubscriptionInfo {id=2, iccId=89049032004008882600, simSlotIndex=-1, displayName=eSIM, isEmbedded=true}
"""


def make_result(stdout="", returncode=0):
    r = MagicMock()
    r.stdout = stdout
    r.stderr = ""
    r.returncode = returncode
    return r


@patch("subprocess.run")
def test_get_eid(mock_run):
    mock_run.return_value = make_result(DUMPSYS_EUICC)
    assert Device().get_eid() == "89049032004008882600000000000000"
    mock_run.assert_called_once_with(
        ["adb", "shell", "dumpsys", "euicc_card_controller"],
        capture_output=True, text=True, timeout=30,
    )


@patch("subprocess.run")
def test_get_eid_not_found(mock_run):
    mock_run.return_value = make_result("no eid here")
    with pytest.raises(ADBError, match="EID not found"):
        Device().get_eid()


@patch("subprocess.run")
def test_list_subscriptions(mock_run):
    mock_run.return_value = make_result(DUMPSYS_PHONE)
    subs = Device().list_subscriptions()
    assert len(subs) == 2
    phys = next(s for s in subs if not s.is_esim)
    esim = next(s for s in subs if s.is_esim)
    assert phys.sub_id == 1
    assert phys.slot == 0
    assert phys.iccid == "89012703278015354865"
    assert esim.sub_id == 2
    assert esim.slot == -1
    assert esim.is_esim is True


@patch("subprocess.run")
def test_enable_profile(mock_run):
    mock_run.return_value = make_result("")
    assert Device().enable_profile(2) is True
    mock_run.assert_called_once_with(
        ["adb", "shell", "service", "call", "phone", "193", "i32", "2", "i32", "1"],
        capture_output=True, text=True, timeout=30,
    )


@patch("subprocess.run")
def test_disable_profile(mock_run):
    mock_run.return_value = make_result("")
    assert Device().disable_profile(2) is True
    mock_run.assert_called_once_with(
        ["adb", "shell", "service", "call", "phone", "193", "i32", "2", "i32", "0"],
        capture_output=True, text=True, timeout=30,
    )


@patch("subprocess.run")
def test_set_data_sim(mock_run):
    mock_run.return_value = make_result("")
    assert Device().set_data_sim(1) is True
    mock_run.assert_called_once_with(
        ["adb", "shell", "settings", "put", "global", "multi_sim_data_call", "1"],
        capture_output=True, text=True, timeout=30,
    )


@patch("subprocess.run")
def test_adb_error_on_nonzero(mock_run):
    mock_run.return_value = make_result("error: no devices", returncode=1)
    with pytest.raises(ADBError):
        Device().get_eid()


@patch("subprocess.run")
def test_serial_prepended(mock_run):
    mock_run.return_value = make_result(DUMPSYS_EUICC)
    Device(serial="abc123").get_eid()
    args = mock_run.call_args[0][0]
    assert args[:3] == ["adb", "-s", "abc123"]
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
pytest tests/test_device.py -v
```

Expected: `ImportError` or `ModuleNotFoundError` (device.py doesn't exist yet).

- [ ] **Step 3: Implement esim/device.py**

```python
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Subscription:
    sub_id: int
    iccid: str
    display_name: str
    slot: int
    is_esim: bool


class ADBError(Exception):
    pass


class Device:
    def __init__(self, serial: str | None = None):
        self.serial = serial
        self._adb_prefix = ["adb"] + (["-s", serial] if serial else [])

    def _run(self, *args: str) -> str:
        result = subprocess.run(
            self._adb_prefix + list(args),
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            raise ADBError(result.stderr.strip() or result.stdout.strip())
        return result.stdout

    def get_eid(self) -> str:
        output = self._run("shell", "dumpsys", "euicc_card_controller")
        match = re.search(r"EID[:\s]+([0-9A-Fa-f]{32})", output)
        if not match:
            raise ADBError("EID not found in euicc_card_controller output")
        return match.group(1).upper()

    def list_subscriptions(self) -> list[Subscription]:
        output = self._run("shell", "dumpsys", "phone")
        return _parse_subscriptions(output)

    def get_euicc_state(self) -> dict[str, str]:
        output = self._run("shell", "dumpsys", "euicc_card_controller")
        return {"raw": output}

    def enable_profile(self, sub_id: int) -> bool:
        self._run("shell", "service", "call", "phone", "193",
                  "i32", str(sub_id), "i32", "1")
        return True

    def disable_profile(self, sub_id: int) -> bool:
        self._run("shell", "service", "call", "phone", "193",
                  "i32", str(sub_id), "i32", "0")
        return True

    def set_data_sim(self, sub_id: int) -> bool:
        self._run("shell", "settings", "put", "global",
                  "multi_sim_data_call", str(sub_id))
        return True

    def bugreport(self, out_dir: Path) -> Path:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / "bugreport.zip"
        self._run("bugreport", str(path))
        return path


_SUB_PATTERN = re.compile(r"SubscriptionInfo\s*\{([^}]+)\}", re.DOTALL)
_FIELD = re.compile(r"(\w+)=([^,\s}]+)")


def _parse_subscriptions(output: str) -> list[Subscription]:
    subs = []
    for m in _SUB_PATTERN.finditer(output):
        fields = dict(_FIELD.findall(m.group(1)))
        try:
            subs.append(Subscription(
                sub_id=int(fields.get("id", fields.get("subId", -1))),
                iccid=fields.get("iccId", fields.get("iccid", "")),
                display_name=fields.get("displayName", ""),
                slot=int(fields.get("simSlotIndex", -1)),
                is_esim=fields.get("isEmbedded", "false").lower() == "true",
            ))
        except ValueError:
            continue
    return subs
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
pytest tests/test_device.py -v
```

Expected: 8 tests pass.

- [ ] **Step 5: Commit**

```bash
git add esim/device.py tests/test_device.py
git commit -m "feat: Device class with ADB primitives"
```

---

### Task 5: Capture class

**Files:**
- Create: `esim/capture.py`
- Create: `tests/test_capture.py`

- [ ] **Step 1: Write failing tests**

`tests/test_capture.py`:
```python
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from esim.capture import Capture, CaptureSession
from esim.device import Device, Subscription


def make_device():
    d = MagicMock(spec=Device)
    d.serial = "3ddf2893"
    d._adb_prefix = ["adb", "-s", "3ddf2893"]
    d.get_eid.return_value = "89049032004008882600000000000000"
    d.get_euicc_state.return_value = {"raw": "state_data"}
    d.list_subscriptions.return_value = [
        Subscription(1, "89012703278015354865", "T-Mobile", 0, False),
        Subscription(2, "89049032004008882600", "eSIM", -1, True),
    ]
    return d


@patch("subprocess.Popen")
def test_capture_starts_mitmdump(mock_popen, tmp_path):
    mock_proc = MagicMock()
    mock_proc.stdout = iter([])
    mock_popen.return_value = mock_proc

    d = make_device()
    with Capture(device=d, port=8081, sessions_root=tmp_path) as cap:
        pass

    calls = [c.args[0] for c in mock_popen.call_args_list]
    mitm_call = next(c for c in calls if "mitmdump" in c)
    assert "--listen-port" in mitm_call
    assert "8081" in mitm_call


@patch("subprocess.Popen")
def test_capture_save_writes_required_files(mock_popen, tmp_path):
    mock_proc = MagicMock()
    mock_proc.stdout = iter(["log line 1\n", "log line 2\n"])
    mock_popen.return_value = mock_proc

    d = make_device()
    with Capture(device=d, port=8080, sessions_root=tmp_path) as cap:
        cap._logcat_lines = ["log line 1", "log line 2"]
        session_dir = cap._session_dir
        (session_dir / "traffic.mitm").write_bytes(b"data")

    session = cap.save(session_dir)

    assert (session_dir / "logcat.txt").read_text() == "log line 1\nlog line 2"
    assert (session_dir / "traffic.mitm").exists()
    assert (session_dir / "euicc_state.json").exists()
    meta = json.loads((session_dir / "metadata.json").read_text())
    assert meta["serial"] == "3ddf2893"
    assert meta["eid"] == "89049032004008882600000000000000"
    assert len(meta["subscriptions"]) == 2
    assert isinstance(session, CaptureSession)


@patch("subprocess.Popen")
def test_capture_exit_terminates_processes(mock_popen, tmp_path):
    mock_proc = MagicMock()
    mock_proc.stdout = iter([])
    mock_popen.return_value = mock_proc

    d = make_device()
    with Capture(device=d, sessions_root=tmp_path) as cap:
        pass

    assert mock_proc.terminate.called
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
pytest tests/test_capture.py -v
```

Expected: `ImportError` (capture.py doesn't exist).

- [ ] **Step 3: Implement esim/capture.py**

```python
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
        self._euicc_state_start: dict | None = None

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
            "start": self._euicc_state_start,
            "end": self.device.get_euicc_state(),
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

    def _safe_eid(self) -> str:
        try:
            return self.device.get_eid()
        except Exception:
            return ""
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
pytest tests/test_capture.py -v
```

Expected: 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add esim/capture.py tests/test_capture.py
git commit -m "feat: Capture class with concurrent mitmproxy + logcat"
```

---

### Task 6: Analysis class

**Files:**
- Create: `esim/analysis.py`
- Create: `tests/test_analysis.py`

- [ ] **Step 1: Write failing tests**

`tests/test_analysis.py`:
```python
import json
from pathlib import Path
import pytest
from esim.analysis import Session, RSPCall, LogEvent, _detect_interface, _parse_logcat_line


def write_session(tmp_path: Path, logcat: str = "", mitm: bool = False) -> Path:
    meta = {
        "serial": "3ddf2893",
        "eid": "89049032004008882600000000000000",
        "subscriptions": [],
        "started_at": "2026-06-03T14:23:01+00:00",
        "duration_s": 45.2,
    }
    (tmp_path / "metadata.json").write_text(json.dumps(meta))
    (tmp_path / "logcat.txt").write_text(logcat)
    (tmp_path / "euicc_state.json").write_text(json.dumps({"start": {}, "end": {}}))
    if not mitm:
        (tmp_path / "traffic.mitm").write_bytes(b"")
    return tmp_path


def test_session_load(tmp_path):
    write_session(tmp_path)
    s = Session.load(tmp_path)
    assert s._metadata["eid"] == "89049032004008882600000000000000"


def test_detect_interface_es11():
    assert _detect_interface("https://smdsc.t-mobile.com/gsma/rsp2/es11/initiateAuthentication") == "ES11"


def test_detect_interface_es9plus():
    assert _detect_interface("https://smdp.example.com/gsma/rsp2/es9plus/getBoundProfilePackage") == "ES9+"


def test_detect_interface_unknown():
    assert _detect_interface("https://example.com/other") is None


def test_parse_logcat_line_valid():
    line = "06-03 14:23:01.123  1234  5678 D EuiccManager: prepareDownload called"
    event = _parse_logcat_line(line)
    assert event is not None
    assert event.tag == "EuiccManager"
    assert "prepareDownload" in event.message


def test_parse_logcat_line_invalid():
    assert _parse_logcat_line("not a log line") is None


def test_logcat_events_empty(tmp_path):
    write_session(tmp_path, logcat="")
    s = Session.load(tmp_path)
    assert s.logcat_events() == []


def test_logcat_events_parsed(tmp_path):
    logcat = "06-03 14:23:01.123  1234  5678 D EuiccManager: prepareDownload called"
    write_session(tmp_path, logcat=logcat)
    s = Session.load(tmp_path)
    events = s.logcat_events()
    assert len(events) == 1
    assert isinstance(events[0], LogEvent)


def test_es11_and_es9_empty_without_mitm(tmp_path):
    write_session(tmp_path)
    s = Session.load(tmp_path)
    assert s.es11_calls() == []
    assert s.es9_calls() == []
    assert s.bpp_blobs() == []


def test_timeline_merges_and_sorts(tmp_path):
    logcat = "06-03 14:23:01.123  1234  5678 D EuiccManager: step one"
    write_session(tmp_path, logcat=logcat)
    s = Session.load(tmp_path)
    tl = s.timeline()
    assert all("t_ms" in item for item in tl)
    assert tl == sorted(tl, key=lambda x: x["t_ms"])
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
pytest tests/test_analysis.py -v
```

Expected: `ImportError` (analysis.py doesn't exist).

- [ ] **Step 3: Implement esim/analysis.py**

```python
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

    def es11_calls(self) -> list[RSPCall]:
        return [c for c in self._parse_rsp_calls() if c.interface == "ES11"]

    def es9_calls(self) -> list[RSPCall]:
        return [c for c in self._parse_rsp_calls() if c.interface == "ES9+"]

    def bpp_blobs(self) -> list[str]:
        return [
            c.response_body["boundProfilePackage"]
            for c in self.es9_calls()
            if "getBoundProfilePackage" in c.method
            and "boundProfilePackage" in c.response_body
        ]

    def logcat_events(self) -> list[LogEvent]:
        events = []
        for line in self._logcat_raw.splitlines():
            event = _parse_logcat_line(line)
            if event:
                events.append(event)
        return events

    def timeline(self) -> list[dict]:
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


def _detect_interface(url: str) -> str | None:
    lower = url.lower()
    if "/es11/" in lower:
        return "ES11"
    if "/es9plus/" in lower or "/es9+/" in lower:
        return "ES9+"
    return None


def _parse_logcat_line(line: str) -> LogEvent | None:
    m = _LOGCAT_RE.match(line)
    if not m:
        return None
    try:
        from datetime import datetime
        dt = datetime.strptime(m.group(1), "%m-%d %H:%M:%S.%f")
        t_ms = (dt.hour * 3600 + dt.minute * 60 + dt.second) * 1000 + dt.microsecond / 1000
    except ValueError:
        t_ms = 0.0
    return LogEvent(timestamp_ms=t_ms, tag=m.group(2), message=m.group(3))
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
pytest tests/test_analysis.py -v
```

Expected: 11 tests pass.

- [ ] **Step 5: Commit**

```bash
git add esim/analysis.py tests/test_analysis.py
git commit -m "feat: Analysis/Session class for parsing capture sessions"
```

---

### Task 7: CLI

**Files:**
- Create: `esim/cli.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write failing tests**

`tests/test_cli.py`:
```python
from unittest.mock import MagicMock, patch
from click.testing import CliRunner
from esim.cli import main
from esim.device import Subscription, ADBError


def make_device_mock(eid="89049032004008882600000000000000"):
    d = MagicMock()
    d.get_eid.return_value = eid
    d.list_subscriptions.return_value = [
        Subscription(1, "89012703278015354865", "T-Mobile", 0, False),
        Subscription(2, "89049032004008882600", "eSIM", -1, True),
    ]
    d.enable_profile.return_value = True
    d.disable_profile.return_value = True
    d.set_data_sim.return_value = True
    return d


@patch("esim.cli.Device")
def test_eid_command(mock_device_cls):
    mock_device_cls.return_value = make_device_mock()
    result = CliRunner().invoke(main, ["eid"])
    assert result.exit_code == 0
    assert "89049032004008882600000000000000" in result.output


@patch("esim.cli.Device")
def test_eid_adb_error(mock_device_cls):
    d = MagicMock()
    d.get_eid.side_effect = ADBError("no device")
    mock_device_cls.return_value = d
    result = CliRunner().invoke(main, ["eid"])
    assert result.exit_code != 0
    assert "no device" in result.output


@patch("esim.cli.Device")
def test_profiles_list(mock_device_cls):
    mock_device_cls.return_value = make_device_mock()
    result = CliRunner().invoke(main, ["profiles", "list"])
    assert result.exit_code == 0
    assert "T-Mobile" in result.output
    assert "eSIM" in result.output


@patch("esim.cli.Device")
def test_profiles_enable(mock_device_cls):
    d = make_device_mock()
    mock_device_cls.return_value = d
    result = CliRunner().invoke(main, ["profiles", "enable", "2"])
    assert result.exit_code == 0
    d.enable_profile.assert_called_once_with(2)


@patch("esim.cli.Device")
def test_profiles_disable(mock_device_cls):
    d = make_device_mock()
    mock_device_cls.return_value = d
    result = CliRunner().invoke(main, ["profiles", "disable", "2"])
    assert result.exit_code == 0
    d.disable_profile.assert_called_once_with(2)


@patch("esim.cli.Device")
def test_data_sim_set(mock_device_cls):
    d = make_device_mock()
    mock_device_cls.return_value = d
    result = CliRunner().invoke(main, ["data-sim", "1"])
    assert result.exit_code == 0
    d.set_data_sim.assert_called_once_with(1)


def test_analyze_command(tmp_path):
    import json
    meta = {"serial": "x", "eid": "1" * 32, "subscriptions": [],
            "started_at": "2026-06-03T00:00:00+00:00", "duration_s": 10}
    (tmp_path / "metadata.json").write_text(json.dumps(meta))
    (tmp_path / "logcat.txt").write_text("")
    (tmp_path / "euicc_state.json").write_text(json.dumps({"start": {}, "end": {}}))
    (tmp_path / "traffic.mitm").write_bytes(b"")
    result = CliRunner().invoke(main, ["analyze", str(tmp_path)])
    assert result.exit_code == 0
    assert "ES11" in result.output
    assert "ES9+" in result.output
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
pytest tests/test_cli.py -v
```

Expected: `ImportError` (cli.py doesn't exist).

- [ ] **Step 3: Implement esim/cli.py**

```python
import time
from pathlib import Path

import click

from esim.analysis import Session
from esim.capture import Capture
from esim.device import ADBError, Device


@click.group()
@click.option("--serial", "-s", default=None, help="ADB device serial")
@click.pass_context
def main(ctx, serial: str | None) -> None:
    ctx.ensure_object(dict)
    ctx.obj["serial"] = serial


def _device(ctx: click.Context) -> Device:
    return Device(serial=ctx.obj.get("serial"))


@main.command()
@click.pass_context
def eid(ctx) -> None:
    """Print the eUICC identifier."""
    try:
        click.echo(_device(ctx).get_eid())
    except ADBError as e:
        raise click.ClickException(str(e))


@main.group()
def profiles() -> None:
    """Manage eSIM profiles."""


@profiles.command("list")
@click.pass_context
def profiles_list(ctx) -> None:
    """List all subscriptions."""
    try:
        subs = _device(ctx).list_subscriptions()
        click.echo(f"{'NAME':<20} {'ICCID':<22} {'SLOT':>5} {'ESIM':>6}")
        for s in subs:
            click.echo(
                f"{s.display_name:<20} {s.iccid:<22} {s.slot:>5} "
                f"{'yes' if s.is_esim else 'no':>6}"
            )
    except ADBError as e:
        raise click.ClickException(str(e))


@profiles.command("enable")
@click.argument("sub_id", type=int)
@click.pass_context
def profiles_enable(ctx, sub_id: int) -> None:
    """Enable an eSIM profile."""
    try:
        _device(ctx).enable_profile(sub_id)
        click.echo(f"Profile {sub_id} enabled.")
    except ADBError as e:
        raise click.ClickException(str(e))


@profiles.command("disable")
@click.argument("sub_id", type=int)
@click.pass_context
def profiles_disable(ctx, sub_id: int) -> None:
    """Disable an eSIM profile."""
    try:
        _device(ctx).disable_profile(sub_id)
        click.echo(f"Profile {sub_id} disabled.")
    except ADBError as e:
        raise click.ClickException(str(e))


@main.command("data-sim")
@click.argument("sub_id", type=int)
@click.pass_context
def data_sim(ctx, sub_id: int) -> None:
    """Set the default data SIM."""
    try:
        _device(ctx).set_data_sim(sub_id)
        click.echo(f"Data SIM set to subscription {sub_id}.")
    except ADBError as e:
        raise click.ClickException(str(e))


@main.command()
@click.option("--port", default=8080, show_default=True)
@click.option("--filter", "filters", multiple=True, default=["ES9+", "ES11"])
@click.option("--out", "out_dir", default=None, type=click.Path())
@click.pass_context
def capture(ctx, port: int, filters: tuple, out_dir: str | None) -> None:
    """Start a capture session. Ctrl-C to stop."""
    d = _device(ctx)
    try:
        with Capture(device=d, port=port, filters=list(filters)) as cap:
            click.echo(f"Capturing on :{port} — Ctrl-C to stop.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        session = cap.save(Path(out_dir) if out_dir else None)
        click.echo(f"Session saved: {session.session_dir}")
    except ADBError as e:
        raise click.ClickException(str(e))


@main.command()
@click.argument("session_path", type=click.Path(exists=True))
def analyze(session_path: str) -> None:
    """Analyze a saved capture session."""
    s = Session.load(session_path)
    click.echo(f"ES11 calls:    {len(s.es11_calls())}")
    click.echo(f"ES9+ calls:    {len(s.es9_calls())}")
    click.echo(f"BPP blobs:     {len(s.bpp_blobs())}")
    click.echo(f"Logcat events: {len(s.logcat_events())}")
    for c in s.es11_calls():
        click.echo(f"  ES11  {c.method}")
    for c in s.es9_calls():
        click.echo(f"  ES9+  {c.method}")


@main.command()
@click.option("--out", "out_dir", default="sessions", show_default=True, type=click.Path())
@click.pass_context
def bugreport(ctx, out_dir: str) -> None:
    """Capture a telephony bugreport."""
    try:
        path = _device(ctx).bugreport(Path(out_dir))
        click.echo(f"Saved: {path}")
    except ADBError as e:
        raise click.ClickException(str(e))
```

- [ ] **Step 4: Run all tests**

```bash
pytest tests/ -v
```

Expected: all tests pass (device + capture + analysis + cli).

- [ ] **Step 5: Commit**

```bash
git add esim/cli.py tests/test_cli.py
git commit -m "feat: Click CLI wrapping Device, Capture, Analysis"
```

---

### Task 8: Setup scripts

**Files:**
- Create: `tools/setup_hotspot.sh`
- Create: `tools/install_mitm_cert.sh`

- [ ] **Step 1: Write setup_hotspot.sh**

```bash
#!/usr/bin/env bash
# Sets up a Wi-Fi hotspot using NetworkManager. Requires a Wi-Fi adapter in AP mode.
set -euo pipefail

SSID="${1:-esim-research}"
PASSWORD="${2:-esimresearch}"
IFACE="${3:-wlan0}"

if ! iw list 2>/dev/null | grep -q "AP"; then
    echo "Error: no Wi-Fi adapter supports AP mode."
    echo "Check: iw list | grep -A5 'Supported interface modes'"
    exit 1
fi

nmcli connection delete "esim-hotspot" 2>/dev/null || true

nmcli connection add \
    type wifi ifname "$IFACE" con-name "esim-hotspot" autoconnect no ssid "$SSID" \
    -- wifi-sec.key-mgmt wpa-psk wifi-sec.psk "$PASSWORD" \
    802-11-wireless.mode ap 802-11-wireless.band bg \
    ipv4.method shared

nmcli connection up "esim-hotspot"

PC_IP=$(ip -4 addr show "$IFACE" | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
echo "Hotspot '$SSID' active on $IFACE (password: $PASSWORD)"
echo "Set phone Wi-Fi proxy → Manual → Host: $PC_IP  Port: 8080"
```

- [ ] **Step 2: Write install_mitm_cert.sh**

```bash
#!/usr/bin/env bash
# Prints step-by-step CA cert install instructions for the connected Android device.
set -euo pipefail

PORT="${1:-8080}"
IFACE="${2:-wlan0}"
PC_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1 || echo "<PC_IP>")

cat <<EOF
=== mitmproxy CA Certificate — Installation Steps ===

1. Run the hotspot:        ./tools/setup_hotspot.sh
2. Start mitmproxy:        mitmdump --listen-port $PORT
3. Connect phone to the 'esim-research' Wi-Fi network.
4. On phone: Settings → Wi-Fi → long-press network → Modify
   Proxy: Manual  Host: $PC_IP  Port: $PORT
5. On phone browser: http://mitm.it → download Android cert
6. Settings → Security → Encryption & credentials →
   Install a certificate → CA certificate → select downloaded file

Note: Android 7+ does not trust user CA certs for apps targeting API 24+.
If ES9+/ES11 flows do not appear in mitmproxy after triggering eSIM activity,
the LPA is enforcing TLS pinning. Update .claude/notes/tls-pinning-status.md.
EOF
```

- [ ] **Step 3: Make scripts executable and commit**

```bash
chmod +x tools/setup_hotspot.sh tools/install_mitm_cert.sh
git add tools/
git commit -m "feat: PC hotspot and mitmproxy CA cert setup scripts"
```

---

### Task 9: Integration smoke test

Run against the real device (ADB serial 3ddf2893). These are manual verification steps, not automated tests.

- [ ] **Step 1: Verify ADB connection**

```bash
adb -s 3ddf2893 devices
```

Expected: `3ddf2893  device`

- [ ] **Step 2: Get EID**

```bash
esim -s 3ddf2893 eid
```

Expected: a 32-character hex string.
If ADBError "EID not found": run `adb -s 3ddf2893 shell dumpsys euicc_card_controller | grep -i eid`
and update the regex in `device.py:get_eid()` to match the actual format. Commit the fix.

- [ ] **Step 3: List subscriptions**

```bash
esim -s 3ddf2893 profiles list
```

Expected: two rows — physical SIM (slot 0) and eSIM (slot -1).
If empty: run `adb -s 3ddf2893 shell dumpsys phone | grep -i subscriptioninfo`
and update `_parse_subscriptions()` regex to match OxygenOS format. Commit the fix.
Update `.claude/notes/device-cph2515.md` with the actual output format.

- [ ] **Step 4: Run full test suite**

```bash
pytest tests/ -v
```

Expected: all tests pass (no regressions from any parser fixes in steps 2-3).

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "fix: integration-verified parser adjustments for CPH2515"
```
