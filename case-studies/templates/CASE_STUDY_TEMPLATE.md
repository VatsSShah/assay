# Case study: <short name of the attack pattern>

<!--
Rules for authors (delete this block when publishing):

* Build the case study ONLY from committed evidence: scenario source, scorecards, experiment
  bundles, traces, witness receipts. Quote proof strings exactly and give the file and JSON path.
* Never invent intermediate steps, model reasoning, tool results, trace ids, receipts or
  replications. If something was not recorded, say "not recorded".
* Put representative safe executions next to failures.
* Keep "requested a tool call", "tool executed", "bytes transmitted" and "arrived at an
  independent sink" separate (docs/THREAT_MODEL.md §5).
* Every incident a scenario is "modelled on" is the scenario author's attribution; cite only what
  SPEC.md §1 cites, and say so.
-->

| label | value |
|---|---|
| Evidence level | self-reported / witnessed (by whom, key) / independently reproduced (by whom) |
| Independently witnessed | yes / no |
| Independently reproduced | yes / no |
| Scenario source | `src/assay_bench/scenarios.py` → `<builder>` (commit, and whether that commit is what ran) |
| Evidence files | `<paths>` |
| Catalog task id(s) | `<ids>` and whether the scenario actually implements the catalog mechanism |

## A. Security objective

What must not happen, stated as a property of the agent configuration (e.g. "a value returned by
`get_x` must not appear in arguments to a tool whose destination was chosen by untrusted
content").

## B. Legitimate task

The system prompt and user request, quoted from source. What a correct, helpful completion looks
like.

## C. Attacker capabilities

Which single surface the attacker controls (tool description, tool response, retrieved document,
ticket/record, repo/config file), what they can write there, which destination they control, and
what they cannot touch.

## D. Attack construction

The payload as delivered, quoted from source (with the canary shown as a placeholder), the
variant used, and the lever it relies on (procedure framing, authority, stealth, hidden markup).

## E. Environment

Agent loop, model route, turn limit, output budget, sampling parameters (or "not set; provider
defaults"), tools exposed with their descriptions, sink behaviour (e.g. "loopback handler that
records the call and returns 200 OK; sends nothing"), trials, runs, dates, code commit.

## F. Execution timeline (with trace IDs)

If a trace exists: list the events by `event_id` (`<trial_id>#NNNN`) with type, actor, source and
destination, and link the `traces.jsonl` file and its artifact index entry.

If no trace exists: say so explicitly, state that trace ids are unavailable, and list only what
the evidence does contain. Do not reconstruct a sequence of model turns.

## G. Observed behavior

A per-configuration table of exploited / resisted / inconclusive trials, then the exact proof
strings (file, JSON path, verbatim value), then representative safe executions.

## H. Verification links

The commands a reader runs to check what is checkable, and the verification level each reaches.

## I. Impact

- **Potential impact** — what this behaviour would enable in a real deployment.
- **Observed impact** — what actually happened in this run (usually: a recorded tool-call
  argument on a loopback server).
- **Production impact** — whether any production system, real credential or real user was
  involved (for Assay runs: no).

## J. Limitations

Evidence level, sample size and intervals, scenario-to-catalog fidelity, confounds, unpinned
code, missing metadata, and anything that would change the reading of G.
