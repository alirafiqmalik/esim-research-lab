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
