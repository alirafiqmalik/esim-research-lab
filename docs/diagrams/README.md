# Diagram catalog

Shared RSP diagrams keep editable Graphviz `.dot` sources beside their `.svg`
and `.png` outputs. Open an SVG for a scalable view.

| Diagram | Source | Preview |
| --- | --- | --- |
| RSP download procedure | [DOT](rsp-download.dot) | [SVG](rsp-download.svg) |
| Truphone provisioning | [DOT](rsp-truphone-success.dot) | [SVG](rsp-truphone-success.svg) |
| Sysmocom test-CI rejection | [DOT](rsp-sysmocom-testci-fail.dot) | [SVG](rsp-sysmocom-testci-fail.svg) |
| RedteaGO via OpenEUICC | [DOT](rsp-redteago.dot) | [SVG](rsp-redteago.svg) |
| RedteaGO via Google LPA | [DOT](rsp-google-lpa-redteago.dot) | [SVG](rsp-google-lpa-redteago.svg) |
| Reusable sequence template | [DOT](templates/template.dot) | [SVG](templates/template.svg) |

## Render

Install Graphviz, then run from the repository root:

```bash
bash scripts/msd/render.sh docs/diagrams/rsp-download.dot
```

For a new diagram, copy `templates/template.dot` and follow the source's actor
and message conventions. For capture-derived diagrams, use the
[log parser and renderer](../../scripts/msd/README.md).

## Experiment diagrams

- [ES9+ download sequence](../../testbed/es9-message-flow/es9plus-download-sequence.svg)
- [ES11 discovery sequence](../../testbed/ping-sm-ds/es11-discovery-sequence.svg)
- [LTE attach sequence source](../../testbed/baseband-attach/lte-attach-sequence.mmd)
