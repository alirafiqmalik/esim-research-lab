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
