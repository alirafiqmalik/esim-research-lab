# Orchestrator Rule

The main Claude Code session is the orchestrator. It plans, delegates, and synthesizes.
The orchestrator stays out of implementation code and long-blocking tasks.

## Subagent limits

- Maximum 2-3 subagents running concurrently.
- Each subagent gets one scoped, actionable task — not a vague directive.
- A task is scoped enough if a subagent can complete it without asking clarifying questions.

## Context sharing

When two subagents need awareness of each other's output, the orchestrator extracts a
compact context block (key facts, decisions, current state) and passes it to each.
Never make subagents read each other's full transcript.

## Clean-slate subagents

Spin up a subagent with no conversation history when:
- Brainstorming or generating options (avoids anchoring on prior decisions)
- The current approach is stuck (fresh perspective, no sunk-cost bias)
- Critical review of work done in this session (avoids confirmation bias)

## Task handoff format

When dispatching a subagent, always include:
1. What to build or do (specific, not vague)
2. Which files to touch
3. What done looks like (acceptance criteria)
4. Compact context from any dependent prior work
