# Contributing

## Local setup

Use Python 3.12 or newer in a virtual environment, then run:

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
```

These tests exercise the core package without a phone. Standalone tools and
experiments document their additional dependencies and checks locally.

## Changes

- Put reusable Python code in `esim/` and core tests in `tests/`.
- Keep experiment code, procedure notes, and findings together in `testbed/`.
- Keep standalone harnesses in `tools/` and operational helpers in `scripts/`.
- Keep diagram sources beside rendered images in `docs/diagrams/`.
- Update the relevant index when adding an experiment or tool.
- Use short Conventional Commits subjects such as `docs(readme): clarify setup`.

See the [repository guide](docs/repository-guide.md) for the full layout.

## Reproducible reports

Include the command, software versions, expected result, and observed result.
For device experiments, record the phone model, Android build, LPA, and required
privileges. Distinguish measured behavior from inference and simulator behavior.
Use synthetic examples or redact subscriber identifiers and account data.

Run only the relevant offline checks for documentation changes. Device tests
must follow the procedure and constraints in the experiment's README.

## Diagrams

Render a maintained Graphviz source with:

```bash
bash scripts/msd/render.sh docs/diagrams/rsp-download.dot
```

Review both the source and the image. Diagram content must follow the underlying
code, capture, or documented procedure. See the [catalog](docs/diagrams/README.md).
