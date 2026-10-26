# Repository guide

## Placement

| Directory | Responsibility | Entry point |
| --- | --- | --- |
| `esim/` | Importable code and the installed `esim` command | [CLI](../esim/cli.py) |
| `tests/` | Offline tests for the core package | `python -m pytest -q` |
| `testbed/` | Device experiments and software simulation | [Experiment catalog](../testbed/README.md) |
| `tools/` | Standalone research harnesses | [Tool catalog](../tools/README.md) |
| `scripts/` | Setup and operational helpers | [Script catalog](../scripts/README.md) |
| `assets/` | Reference profile material used by experiments | [Asset guide](../assets/README.md) |
| `docs/` | Reference maps, research, reports, and diagrams | [Documentation index](README.md) |

The package stays at `esim/` to preserve existing imports and checkout-relative
asset lookup. The distribution name is `esim-research-lab`; the command and
Python import remain `esim`. Use an editable installation for this research checkout.

## Diagram organization

All shared diagram assets now live under `docs/diagrams/`:

- `rsp-download.*` moved from `docs/msd/`.
- `templates/template.*` moved from `scripts/msd/`.
- Capture-derived RSP diagrams keep their existing filenames.

Rendering programs stay in `scripts/msd/`. Experiment-specific diagrams remain
next to the experiment that explains them. Historical plans may show old paths.

## Local output

Use `.sessions/` for new device captures and intermediate figures. Use `tmp/`
for disposable output. Both are ignored, along with virtual environments and
Python caches. Existing experiment logs remain with their supporting notes.
An ignore rule does not remove files already tracked by Git.

## Experiment structure

Give each experiment a README with its purpose, prerequisites, commands,
expected artifacts, and limitations. Use `scripts/`, `notes/`, and `analysis/`
inside an experiment when those divisions help readers. Keep observed results
separate from proposed procedures and historical plans.
