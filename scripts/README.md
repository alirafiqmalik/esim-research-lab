# Script catalog

Run helpers from the repository root unless their guide says otherwise.
Read setup scripts before running them: they can change host networking or
device configuration.

| Directory | Purpose | Entry point |
| --- | --- | --- |
| `setup/` | Testbed, hotspot, and Pixel 7a capture setup | [Testbed script](setup/setup_testbed.sh) |
| `device/` | Device trust setup and keep-awake helpers | [Guide](device/README.md) |
| `frida/` | LPA observation and runtime instrumentation | [Guide](frida/README.md) |
| `msd/` | Capture-log parsing and Graphviz rendering | [Guide](msd/README.md) |

Diagram templates and rendered examples live in the
[diagram catalog](../docs/diagrams/README.md).
