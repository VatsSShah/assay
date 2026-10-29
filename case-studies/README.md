# Case studies

Worked examples of individual attack patterns, built **only** from committed evidence: the
scenario source in [`src/assay_bench/scenarios.py`](../src/assay_bench/scenarios.py), the
outcome counts and `canary.observed` proof strings in the real-model scorecards under
[`demo/arsenal/spectrum/`](../demo/arsenal/spectrum/), and the oracle. Proof strings are quoted
verbatim with their file and JSON path so each one can be recomputed.

| case study | evidence level | independently witnessed | independently reproduced | status |
|---|---|---|---|---|
| [Documented-procedure injection through a retrieved runbook](documented-procedure-injection.md) | self-reported | no | no | evidenced: eight configurations, task id M3 plus 14 task ids that reuse the scenario |
| [Credential forwarding requested by poisoned MCP tool responses](mcp-tool-response-poisoning.md) | self-reported | no | no | evidenced: bespoke scenarios M7, M1, M23, M24; five firing proofs from three configurations, safe executions from five |
| [Tool-description manipulation](tool-description-manipulation.md) | none for real models | no | no | **not yet evidenced** — no real-model scenario poisons tool descriptions; mechanism only |

## Read these first

- **No trace was captured** for any committed real-model run, so no case study has trace IDs.
  Each says so and lists what the [`assay/trace/1`](../docs/THREAT_MODEL.md#5-the-five-way-outcome-distinction)
  format records for new runs made with `assay experiment run`. No intermediate step has been
  reconstructed.
- **"Exploited" means the model requested a tool call carrying the planted canary.** The sink
  tools are loopback handlers that return `200 OK`; nothing was transmitted and nothing was
  observed by an independent party.
- **Safe executions are shown beside failures.** A configuration that resisted a scenario is part
  of the result.
- **Incident attributions** ("modelled on GeminiJack / EchoLeak / ForcedLeak / …") come from the
  scenario source. They are not among the works cited in SPEC.md §1 and were not re-verified for
  these case studies.

## Writing a new one

Copy [`templates/CASE_STUDY_TEMPLATE.md`](templates/CASE_STUDY_TEMPLATE.md). Sections A–J are
required. A case study built from an experiment bundle should link the bundle, its
`artifact_index.json`, the trace events by `event_id`, and any witness receipts, and run
`assay verify-artifacts` on the bundle before publishing.
