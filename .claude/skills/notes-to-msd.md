---
name: notes-to-msd
description: Turn procedure notes/steps into a correctness-checked message sequence diagram in Graphviz DOT, using mathematical notation over English. Use when asked to diagram a protocol/procedure/handshake.
---

# Notes → Message Sequence Diagram (Graphviz DOT)

Convert a written procedure (protocol steps, a handshake, an algorithm exchange)
into a message sequence diagram in DOT. The diagram MUST match the notes exactly
and MUST favour symbols/equations over prose.

Tooling (already set up):
- Template:  `tools/msd/template.dot`
- Render:    `tools/msd/render.sh <file.dot>`  → `.svg` + `.png` (also syntax-validates)
- Verify:    `tools/msd/analyze.sh <file.dot>` → ordered message list + actor list
- A `PostToolUse` hook auto-renders any `.dot` you Write/Edit (so a render failure
  surfaces immediately).
- Worked example: `docs/msd/rsp-download.dot` (the SGP.22 RSP handshake).

## Workflow

1. **Extract the procedure.** From the notes, list in order: the actors
   (participants), and each step as `⟨sender, receiver, message⟩`. Note any
   in-actor computation/check that gates the next message.
2. **Write the DOT.** Copy `tools/msd/template.dot`. Set the title, one
   `role="actor"` header box per participant (fix order with the invisible
   `A -> B -> C` edge), and add one lifeline-waypoint row per time step.
3. **One message edge per step**, carrying `kind="msg"`, `seq="<n>"` (1,2,3,…),
   and a `label` in math notation (below). Solid arrow = request/forward,
   dashed arrow = response/return.
4. **Render:** `bash tools/msd/render.sh <file.dot>`. Fix any syntax error it
   reports before continuing.
5. **Verify correctness (required):** run `bash tools/msd/analyze.sh <file.dot>`
   and check the extracted list against the notes — see the checklist.

## DOT conventions

- Actors are columns; time flows top→bottom. Header nodes: `role="actor"`.
- Message edge: `kind="msg"`, `seq="<int>"`, `label="<math>"`,
  `style=solid` (request) or `style=dashed` (response).
- Lifelines + row ordering: `kind="life"` (dashed vertical chain + invisible
  left→right ordering per row). Add one `{ rank=same; A_n B_n C_n }` row per step.
- Keep one message per `seq`. Multi-line labels use `\n`. Keep labels short so
  cross-column arrows don't overrun a lifeline.

## Use mathematical notation, not English

Describe computations, checks, and message structure with symbols:

| Concept | Notation |
|---------|----------|
| random sample | `x ←$ {0,1}ⁿ` |
| sign / verify | `σ = Sign_sk(m)` · `Vrfy_pk(σ) ≟ 1` |
| hash, MAC, enc | `H(m)` · `MAC_k(m)` · `Enc_k(m)` / `Dec_k(c)` |
| key agreement | `K = KDF(g^{ab})` · `ECKA-DH` |
| structure / tuple | `S = ⟨a, b, c⟩` · concat `a ‖ b` |
| set / logic | `∈ ∉ ⊆` · `∧ ∨ ¬` · `∀ ∃` |
| guard / branch | `[cond] …` ; failure `✗ <code>` |

Reserve English for the operation name only (e.g. `ES9+.InitiateAuthentication`);
express its payload and any check as symbols. Map error/branch outcomes to their
real codes when the notes have them (e.g. SGP.22 `✗ 8.8.4/3.7`).

## Correctness checklist (do not skip)

After `analyze.sh`, confirm against the source notes:
- **Count** — message count equals the number of steps in the notes.
- **Order** — `seq` order equals the notes' order.
- **Endpoints** — every sender→receiver matches the notes (no swapped actors).
- **Completeness** — no note step is missing; no message exists that isn't in the notes.
- **Computations** — each check/derivation in the notes appears as math on the
  relevant edge (not dropped, not vaguely worded).
- **Fidelity** — concrete values from the notes (challenges, key IDs, codes) are
  carried verbatim where they aid traceability.

If any check fails, edit the DOT and re-run render + analyze until all pass.
