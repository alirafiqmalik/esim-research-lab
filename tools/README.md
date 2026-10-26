# Research tools

These harnesses have their own dependencies and tests. They are not installed
as part of the core `esim` command.

| Tool | Purpose | Guide |
| --- | --- | --- |
| `fuzzer/` | APDU generation, mutation campaigns, and live-send gates | [APDU fuzzer](fuzzer/README.md) |
| `rogue_rsp/` | Local SM-DS response experiments and ES11 fuzzing | [SM-DS harness](rogue_rsp/README.md) |

Follow each guide's dry-run workflow and device constraints before a live run.
For the software ecosystem model, see [ecosim](../testbed/ecosim/README.md).
