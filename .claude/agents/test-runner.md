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
