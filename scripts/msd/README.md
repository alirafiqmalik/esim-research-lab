# RSP log → message sequence diagram (MSD) pipeline

Converts an OpenEUICC/lpac capture log into a Graphviz-DOT message sequence
diagram of the eSIM RSP procedure. The sequence is derived strictly from the log
(which ES9+ functions fired and each one's SGP.22 status), so the diagram matches
the capture. Crypto, checks, and message structures use symbolic/math notation,
not English.

## Use

```bash
# parse + render SVG+PNG
scripts/msd/render_msd.sh <capture.log> <out-basename> ["Title"]

# just the DOT (or verify parse first)
python3 scripts/msd/rsp_to_msd.py <capture.log> -o out.dot --title "..."
python3 scripts/msd/rsp_to_msd.py <capture.log> --check   # prints parsed sequence
```

Input: any log containing `HttpInterfaceImpl` ES9+ lines (`transmit(url=…/es9plus/<fn>)`,
`HTTP tx = …`, `transmit responseCode = …`, `HTTP response body = …`). Our captures
live under `.sessions/*/capture.txt`.

Reusable templates live in [docs/diagrams/templates/](../../docs/diagrams/templates/).

## Actors / notation

Lifelines: `eUICC | LPA | SM-DP+`. eUICC self-loops are the ES10b in-element
computations/checks (`AuthenticateServer`, `PrepareDownload`,
`LoadBoundProfilePackage`). Examples: `eC ∈ {0,1}¹²⁸` (challenge nonce),
`σ_DP = Sig_{SK.DPauth}(srvSigned1)`, `Vrfy_{PK.DPauth}(σ_DP, srvSigned1)`,
`pkId_CI* ∈ trusted ∧ CERT.DPauth ↗ CI`, `ECKA(otPK.DP.KA, otSK.eUICC.KA) → SCP03t`.

Failure paths render dashed/red and stop at the aborting message (e.g. test-CI
`✗ Failed (8.8.4 / 3.7)` at `initiateAuthentication`).

## Examples (rendered)

- `docs/diagrams/rsp-truphone-success.{dot,svg,png}` — production-CI full download
- `docs/diagrams/rsp-sysmocom-testci-fail.{dot,svg,png}` — test-CI rejection

## Auto-rendering

`rsp_to_msd.py` is the parser/renderer that turns a capture into a diagram. To
auto-render on new captures, run `render_msd.sh` against new
`.sessions/*/capture.txt` from your own hook or cron; not installed here.
