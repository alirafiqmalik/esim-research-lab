# Experiment catalog

Start with an experiment's own prerequisites and procedure. These workflows
span physical devices, remote services, and local simulation.

| Experiment | Focus | Environment |
| --- | --- | --- |
| [ecosim](ecosim/README.md) | Software RSP ecosystem, channel inspection, and mutations | Local Python model |
| [OpenEUICC](openeuicc/README.md) | Instrumented LPA setup and eUICC access | Android device |
| [ES9+ message flow](es9-message-flow/README.md) | Provisioning sequence and message analysis | Captures / device |
| [Profile download](profile-download/README.md) | Download procedures and observed results | Android device |
| [Profile delivery](profile-delivery/README.md) | Delivery interfaces and methods | Device / services |
| [Live server probes](ping-live-servers/scripts/README.md) | RSP endpoint behavior | Remote services |
| [SM-DS probes](ping-sm-ds/README.md) | ES11 discovery behavior | Remote services |
| [Baseband attach](baseband-attach/README.md) | NAS/RRC capture and decode | Rooted Pixel 7a |

The root `pytest` suite covers `esim/`. Experiment suites and hardware checks
have separate entry points. See [evaluation reports](../docs/README.md#testbed)
for dated testbed observations.
