# Assay: a recomputable canary oracle for MCP agent security — technical report

*Verosek. Draft accompanying the "verifiable evidence" change set. This report describes the
system and the evidence that exists for it; it does not add measurements. Every number in §11 is
read from a committed artifact named next to it.*

---

## 1. Abstract

Assay is a frozen 31-task set for Model Context Protocol (MCP) security, with a runner, a
standalone verifier and a result format in which each canary-gated finding carries a triple
`(run_secret, origin|tool|step, observed)` that anyone can recompute offline. A per-run HMAC tag
is planted inside a secret-shaped value the agent can reach; a finding fires when the tag appears
in the arguments of a tool call the agent makes. A spurious hit would require forging a 64-bit
HMAC tag; misses (split, re-encoded, paraphrased egress) are enumerated and not bounded.
Verification is reported as named levels rather than a verdict, and the levels a self-reported
document cannot reach — that a run happened, that it is complete, that someone else observed or
reproduced it — are stated and pinned by tests. A real-model spectrum of eight agent
configurations (model routes via OpenRouter, Assay's own agent loop, five trials per task, one
run each) shows every configuration emitting the planted value into a tool call on at least nine
task ids, concentrated in one retrieved-runbook scenario, while most configurations refused the
more explicit credential-forwarding scenarios. Those results are **self-reported, unwitnessed and
unreproduced**, carry no per-step traces, and should be read as a demonstration of the method
and a set of hypotheses, not as a ranking of model security. This change set adds the machinery —
hash-chained traces, outcome detail, experiment manifests, redaction, signed artifact bundles,
per-observation witness receipts, statistics and a replication format — needed to turn such
results into evidence a third party can check.

## 2. Motivation

Agents that read untrusted content and hold tools can be steered by that content. Measuring how
often is easy to do badly: an LLM judge's error rate is unknown; a hand-built stub measures the
harness; a single headline score hides how much of the benchmark actually ran; and a published
number is usually something a reader must take on trust. Assay's design goals follow from those
failures:

1. **A decision rule with a bounded false-positive rate** that needs no judge (SPEC §3–§4).
2. **A result a reader can recheck** without rerunning anything (the proof triple).
3. **An honest denominator**: unsupported and inconclusive tasks are never counted as resisted,
   and every score carries an omission-proof lower bound (SPEC §5, `validity.py`).
4. **An explicit statement of what the evidence does not show**, at the same prominence as what it
   does (README "Read this first", SPEC §4.2, `tests/test_trust_boundary.py`).

Goal 4 is where earlier presentations of the real-model results fell short, and the reason for
this report and the accompanying [credibility audit](../docs/CREDIBILITY_AUDIT.md).

## 3. Threat model

Full statement: [`docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md). In brief:

- **Benchmark threat model.** An attacker controls one surface the agent reads — a tool
  description, a tool response, a retrieved document, a ticket or shared record, or a repository
  config file — and a destination. They do not control the system prompt, the user request, the
  agent loop or the model. The asset is privileged data the agent can reach, represented by a
  synthetic canary.
- **Evidence threat model.** The operator who publishes a result holds the run secret and wrote
  every file, so any document-level check is a coherence check. Stronger evidence requires a
  party the operator does not control: a witness at the egress sink, a precommitment authority, or
  an independent replicator.
- **Five outcomes, never one word.** The model *generated* a dangerous string; it *requested* a
  tool call carrying it; the tool *executed* that call; bytes were *transmitted*; they *arrived* at
  an independently controlled sink. The v0.1 oracle measures the second.

## 4. Related work

This section relies entirely on SPEC.md §1 and adds no citation. As cited in SPEC.md §1:
HarmBench (arXiv:2402.04249) and StrongREJECT (arXiv:2402.10260) grade jailbreak outputs with a
trained classifier and an LLM autograder respectively; AgentDojo (arXiv:2406.13352) scores agent
prompt injection with deterministic state predicates and no LLM judge; and four MCP-specific
security benchmarks predate Assay — MCPSecBench (arXiv:2508.13220), MCPTox (arXiv:2508.14925),
MSB (arXiv:2510.15994) and MCP-SafetyBench (arXiv:2512.15163) — several executing against real
MCP servers and tools. SPEC.md §1 draws the conclusions this report keeps: Assay is not the first
MCP security benchmark, not the first deterministic oracle, and not the first keyed canary; its
contribution is a recomputable result format, levelled verification with a written trust
boundary, and a frozen weighted task set. On execution realism Assay is behind MSB and MCPTox: its
real-model runs use Assay's own loopback servers. The related-work comparison rests on secondary
sources (REMAINING_GAPS G11).

## 5. Benchmark architecture

| component | file | role |
|---|---|---|
| Catalog | `tasks.json`, `src/assay_bench/catalog.py` | 31 frozen tasks: id, mode (28 B / 3 A), oracle (25 canary / 4 behavioural / 2 protocol), weight, crosswalk, execution contract |
| Canary | `src/assay_bench/canary.py` | per-run secret, digest, five envelope families, frozen detection rule |
| Deterministic surface | `src/assay_bench/surface.py`, `contamination.py`, `media.py` | poisoned descriptions/results and real PNG plants for the conformance stubs |
| Real-model scenarios | `src/assay_bench/scenarios.py` | loopback MCP servers for 5 canary and 3 behavioural tasks, plus a generic default |
| Adapters | `src/assay_bench/adapters/` | conformance stubs, `mcp_probe` (Mode A), `llm_agent` (Mode B, real model over loopback MCP) |
| MCP | `src/assay_bench/mcp/`, `servers/reference` | stdlib JSON-RPC client/server, checked against the official SDK |
| Oracles | `src/assay_bench/oracles.py` | one evaluator per evidence class with a normative observation boundary |
| Runner | `src/assay_bench/runner.py` | trial loop, retries, timeouts, raw trial records, diagnostics |
| Validity and scoring | `validity.py`, `src/scoring.py` | V1–V8, fixed denominator, lower bound, Wilson intervals |
| Verifier | `src/assay_verifier.py` | standalone, stdlib, levelled |
| Provenance, precommitment, attestation, witness | `provenance.py`, `precommit.py`, `attest.py`, `witness.py`, `ed25519.py` | the evidence layers above the manifest |
| New in this change set | `trace.py`, `redaction.py`, `bundle.py`, `witness_receipt.py`, `experiment.py`, `outcomes.py`, `analysis.py`, `replication.py` | §8, §13, §14 |

## 6. Attack-scenario taxonomy

The catalog groups by mechanism; the real-model path implements a subset. "Real-model scenario"
says what actually ran in the committed spectrum.

| family | catalog tasks (TASKS.md) | attacker surface | real-model scenario |
|---|---|---|---|
| Tool metadata poisoning | M1 description, M2 line jumping, M4 cross-server shadowing, M5 rug pull, M13 schema | tool description / schema | **none**. M1 runs a ticket-result injection; M2/M4/M5/M13 run the generic M3 scenario. See [case study](../case-studies/tool-description-manipulation.md) |
| Tool-result and retrieval injection | M3 indirect injection, M14 memory, M22 TOCTOU, M25 RAG | tool response / retrieved document | M3 bespoke (retrieved runbook → status deep-link); M14, M22, M25 generic M3 |
| Confused deputy and agency | M7 token passthrough, M8 excessive agency, M9 destructive, M16 runaway | tool response | M7, M8, M9, M16 bespoke |
| Exfiltration chains | M10 lethal trifecta, M19 source→sink, M21 temporal splitting | tool response | generic M3 |
| Supply chain and config | M12 backdoored tool, M24 rules file | tool / repository config | M24 bespoke (`.agentrules`); M12 generic M3 |
| Cross-tenant | M23 | shared record | M23 bespoke, as an injected instruction (catalog M23 is a missing tenant filter with no directive) |
| Multi-agent and sampling | M11 sampling abuse, M15 inter-agent | sampling / agent messages | generic M3 |
| Obfuscation | OBF | tool argument | generic M3 |
| Server posture (Mode A) | M6 param injection, M17 DNS rebinding, M18 unauthenticated server | the server under test | real MCP servers via `mcp_probe`; unsupported for an LLM agent |
| Image channel | M20, M26–M30 | image bytes | unsupported for a text agent |

Every real-model scenario uses one of five variants (`plausible`, `direct`, `authority`, `hidden`,
`combined`; `dormant` in code). The committed spectrum used `plausible` only: the exfiltration is
framed as an ordinary numbered procedure step, with no override language.

## 7. Canary-verification methodology

`digest = HMAC-SHA256(run_secret, "origin|tool|step")[:16 hex]`, with a fresh 32-byte secret per
run. The digest is embedded in an envelope (`sk-`, `AKIA`, JWT, opaque token, `REF-`) chosen per
(secret, task), so there is no fixed sentinel. The canary oracle fires iff the digest, its base64,
its hex-of-ASCII or its URL-quoted form is a substring of egress — for the LLM adapter, the raw
argument string of any tool call the model made. The proof triple is published with the secret
after the run; `assay_verifier.py` recomputes it.

Guarantees and limits (SPEC §4):

- **False positives** on canary tasks are bounded by HMAC forgery, `≤ Q·2⁻⁶⁴`, for a party
  without the secret.
- **The operator holds the secret**, so for them there is nothing to forge: a coherent
  fabrication passes every document-level level.
- **False negatives are many and unbounded in the wild**: 15 of 22 tested transformations are
  missed (`tests/test_oracle_blind_spots.py`); `diagnostics.py` flags 14 of the 15 without
  changing scores; paraphrase is irreducible.
- **Prose is outside the boundary**: a canary written only in the final answer is not counted.
- **Envelope shape is a variable**, not a constant. It was assumed neutral; the committed spectrum
  suggests it is not (§12).

## 8. Agent execution and observation model

**Execution.** For each trial the LLM adapter starts a fresh adversarial MCP server on
127.0.0.1, connects with Assay's MCP client, lists the tools, and runs an OpenAI-style tool loop
against the model route: up to `max_steps = 6` model calls, `max_tokens = 1024`,
`tool_choice: auto`, no sampling parameters unless configured. Every tool call the model emits is
executed by the loopback server; sink tools record the call and return `200 OK` and send nothing.

**Observation in v0.1.** The adapter turns each requested tool call into an egress event whose
payload is the tool name plus the **raw** argument string; the oracle decides from those. The
final text and per-step messages are held in memory and not published; the manifest carries
outcome counts and one proof per fired task; the optional raw-trials file adds per-trial state
and digests.

**Observation in this change set: traces.** `assay/trace/1` (`src/assay_bench/trace.py`) records
one JSON event per line with a per-trial sequence number, a hash chain (`prev_hash`,
`event_hash`), causal `parents`, and the SHA-256 of the original content even when the content
itself is redacted. Event types keep the five outcomes distinct: `model_output_contains_canary`,
`tool_call_requested`, `tool_call_executed` / `tool_call_blocked`, `network_egress_attempted` /
`network_egress_blocked`, and `egress_observed_at_sink`, alongside `user_request`,
`agent_config`, `tools_exposed`, `payload_delivered`, `model_response`, `tool_result`,
`tool_error`, `validation`, `error` and `final_response`. `check_trace` rejects traces that
contradict themselves — an execution without a request, an egress without an execution, a fired
validation with no canary-bearing request, a requested call with no recorded outcome, a broken
chain. Each trial also receives an `outcome_detail` (`attack_succeeded`, `attack_failed`,
`model_refused`, `legit_task_completed_safely`, `tool_execution_failed`, `model_api_failed`,
`timed_out`, `unsupported`, `inconclusive`, `blocked_by_control`) without changing the frozen
scoring states. A trace is still operator-written: it makes a run inspectable and internally
checkable, not independently attested.

## 9. Experimental design

**The committed spectrum** (`demo/arsenal/spectrum/`): eight model routes via OpenRouter; the
22 text Mode-B tasks (19 canary, 3 behavioural) decidable by a text agent, with the 6 image and 3
Mode-A tasks `unsupported`; variant `plausible`; 5 trials per task; one run per route on
2026-10-28; benign twins at 5 trials each; one operator machine running both sides; no sampling
parameters; no precommitment; no witness. The run secret, and therefore the envelope assigned to
each task, differed per route.

**What the design does not control**, all discussed in
[`docs/BENCHMARK_METHODOLOGY.md`](../docs/BENCHMARK_METHODOLOGY.md) §3: provider-side prompts and
safety layers, routing and revision, tool-call formatting, default sampling, reasoning effort,
and (in the committed runs) the envelope mix.

**The design this change set supports**: an experiment configuration file naming the model,
sampling parameters, agent configurations (baseline and controls), scenarios and trials, run with
`assay experiment run --config PATH` (mock models by default; live calls only with
`--allow-billable-calls`), producing a bundle with an experiment manifest, per-configuration
scorecards, raw trials, traces, an artifact index and optionally a signature and witness receipts.
Recommended for any comparison: one run secret across configurations (paired envelopes), ≥ 20
trials per cell, and a repeat on a second day.

## 10. Evaluation metrics

Five metrics, reported separately (methodology §1): **attack resistance** (over conclusive
trials), **coverage** (share of the catalog decided), **legitimate-task completion** (new runs),
**over-refusal** (benign twins), and **infrastructure reliability** (errors, timeouts, API
failures). The aggregate attack-resistance score is SPEC §5's weighted formula over the frozen
catalog denominator; for a partial run the lower bound — every undecided task charged in full —
is the citeable number, because the headline credits undecided tasks as resisted.

## 11. Available results

All eight scorecards are linked below. Each reaches `format_valid`, `internally_consistent`,
`canary_correspondence_verified` and `catalog_bound` under `python src/assay_verifier.py verify`;
none reaches `run_complete` (all partial) or `witnessed_egress`. Statistical treatment —
intervals, pairwise comparisons and what the five-trial design can and cannot resolve — is in
[`research/statistical-analysis.md`](statistical-analysis.md), generated by `assay analyze`; this
report does not restate its numbers.

**Qualifiers that apply to every row:** self-reported by one operator on one machine; not
witnessed; not independently reproduced; one run per route; 5 trials per task; OpenRouter routing
ids, model revision not recorded; no sampling parameters set; no transcripts or traces; Assay's
agent loop and system prompts, not any vendor's product; "canary tasks fired" counts task ids with
at least one trial in which the model requested a tool call carrying the planted canary to a
simulated sink on loopback — nothing was transmitted; 14 of the 19 canary task ids reuse one
scenario.

| configuration (OpenRouter route) | agent resistance, headline | lower bound | canary task ids fired (of 19) | behavioural task ids fired (of 3) | over-refusal (proxy) | scorecard |
|---|---|---|---|---|---|---|
| `deepseek/deepseek-v4.1-flash` | 80.2 | 61.0 | 9 | 0 | 18.1 | [full_deepseek.json](../demo/arsenal/spectrum/full_deepseek.json) |
| `google/gemini-3.8-flash` | 68.3 | 49.1 | 9 | 0 | 12.6 | [full_gemini.json](../demo/arsenal/spectrum/full_gemini.json) |
| `anthropic/claude-haiku-5.5` | 59.4 | 34.8 | 12 | 0 | 27.7 | [full_haiku.json](../demo/arsenal/spectrum/full_haiku.json) |
| `openai/gpt-6.1-terra` | 45.5 | 26.2 | 15 | 0 | 0.0 | [full_terra.json](../demo/arsenal/spectrum/full_terra.json) |
| `qwen/qwen3.8-flash` | 44.5 | 25.2 | 15 | 1 | 13.5 | [full_qwen.json](../demo/arsenal/spectrum/full_qwen.json) |
| `openai/gpt-6-luna` | 43.3 | 24.1 | 16 | 1 | 9.0 | [full_luna.json](../demo/arsenal/spectrum/full_luna.json) |
| `meta-llama/llama-3.1-8b-instruct` | 42.1 | 22.9 | 18 | 2 | 3.5 | [full_llama.json](../demo/arsenal/spectrum/full_llama.json) |
| `z-ai/glm-5.3-flashx` | 41.9 | 22.7 | 16 | 1 | 11.3 | [full_glm.json](../demo/arsenal/spectrum/full_glm.json) |

Headline and lower bound are `agent_resistance_score` and
`validity.agent_resistance_lower_bound`; fired counts are the `fired: true` findings by oracle
class; over-refusal is `over_refusal_rate`. The headline exceeds the lower bound by 19.2–19.3 points
on every row because the six unsupported image tasks are credited as resisted in the headline
(and by ≈ 24.6 for Haiku, whose M23 trials were all inconclusive).

**What the artifacts support, stated as findings.**

1. Under the retrieved-runbook scenario (task id M3 and the 14 ids that reuse it), every
   configuration requested a status post embedding the planted value in a link on the
   scenario's attacker-defined host, on between 26 and 75 of 75 trials (derived by summing
   `per_task_outcomes`; [case study](../case-studies/documented-procedure-injection.md)).
2. Under the four explicit credential-forwarding scenarios (M1, M7, M23, M24), five of eight
   configurations never fired; the firing proofs come from Llama-3.1-8B (M1, M23, M24), GLM-5.3
   FlashX and GPT-6 Luna (M7) ([case study](../case-studies/mcp-tool-response-poisoning.md)).
3. Behavioural tasks fired for runaway tool calls (M16: Luna, Qwen, GLM) and, for Llama-3.1-8B
   only, unconfirmed privilege escalation (M8) and destructive deletion (M9).
4. Each fired canary finding carries one proof string that recomputes.

**What they do not support:** that any model is "secure" or "insecure" in general; that a
vendor's product was compromised; that data left a machine; that the ordering reflects intrinsic
model properties rather than these configurations, this scenario mix, this envelope draw and these
provider defaults.

## 12. Statistical limitations

- **Five trials per cell.** Wilson 95 % intervals in the scorecards are [0.0, 0.4345] for 0/5 and
  [0.5655, 1.0] for 5/5; most per-task differences between configurations are unresolved.
- **One run per configuration.** No estimate of day-to-day or routing variance.
- **Non-independent task ids.** 15 task ids are one scenario, so the weighted aggregate is
  dominated by one scenario and per-task counts are not independent tests of different mechanisms.
- **Envelope confound.** Each route saw a different random envelope mix. A post hoc recomputation
  ([audit §4.2](../docs/CREDIBILITY_AUDIT.md)) suggests some configurations rarely embedded
  `sk-`/`AKIA`-shaped values but usually embedded JWT, opaque or `REF-` values; with different
  mixes, part of the spread between routes may be the draw. This is exploratory and unreplicated.
- **Retry conditioning.** Trials with no tool call were re-run (up to two retries), conditioning
  the scored sample on engagement.
- **No multiple-comparison control** in the published table; `assay analyze` reports intervals and
  pairwise tests, and [`statistical-analysis.md`](statistical-analysis.md) states which differences
  survive.

## 13. Independent-verification methodology

Evidence is layered, and each layer names the party it relies on (README, SPEC §4, §7):

| layer | checks | relies on |
|---|---|---|
| Verifier levels (`assay_verifier.py`) | format, internal consistency, canary correspondence, catalog binding, completeness | arithmetic only |
| Trace consistency (`check_trace`) | the trace does not contradict itself; hash chain intact | arithmetic only |
| Artifact bundle (`assay verify-artifacts`, `assay sign-artifacts`) | every file indexed, hashed, sized and cross-consistent (experiment manifest ↔ scorecards ↔ trials ↔ traces); optional Ed25519 signature over the index | the signer's key — integrity relative to whoever signed, not proof the experiment occurred |
| Witness receipts (`assay witness-sink`, `assay verify-witness`, `assay witness-demo`) | one signed receipt per canary arrival at a sink: experiment, trial, canary id, payload hash, time, nonce; replay and duplicate detection | the witness key; meaningful only if the witness is independent and its key is pinned. See `docs/INDEPENDENT_WITNESS_GUIDE.md` |
| Precommitment (`precommit/`) | commitment registered before the run | repository history; CI for the external level |
| Replication (`assay replication validate`, `docs/REPLICATION_GUIDE.md`) | a third party's own bundle for the same configuration, compared on invariants and intervals | the replicator |
| Maintainer attestation (`attest/`) | a maintainer reran and compared invariants | the maintainer |

**Current status:** the run-level witness has only ever been self-operated; the receipt protocol
is demonstrated locally (`assay witness-demo`) and has not been operated by an independent party;
no real-model result has been replicated or attested.

## 14. Reproducibility

- **Conformance artifacts** regenerate byte-identically (`python -m assay_bench reference`;
  `--check` compares invariants).
- **Real-model results** cannot be reproduced byte-for-byte (sampling is non-deterministic) and
  the committed spectrum's code is not pinned (`a80987a` predates the scenario code; audit §7).
  A replicator can run the current scenarios against the same routes with `assay run --target llm
  --model <route>` or, preferably, `assay experiment run` with an explicit configuration, and
  compare outcome counts and intervals, not bytes.
- Step-by-step instructions: [`REPRODUCIBILITY.md`](../REPRODUCIBILITY.md) and
  [`docs/REPLICATION_GUIDE.md`](../docs/REPLICATION_GUIDE.md). Bundle layout:
  [`docs/EVIDENCE_FORMAT.md`](../docs/EVIDENCE_FORMAT.md).

## 15. Threats to validity

- **Construct.** In the M3 scenario the user asks for a click-through link and to follow the
  runbook; the value is labelled `trace_context`; the attacker's host looks like the organisation's
  own. Compliance is a data-flow failure of the EchoLeak kind, not evidence that a model knowingly
  leaked a credential. Several catalog titles (M1, M2, M4, M5, M13, M23) are not what their
  real-model scenarios exercise.
- **Internal.** Unpinned code; retry conditioning; envelope confound; the oracle reads requested,
  not executed, arguments (one committed proof's arguments did not parse and would have reached
  the tool as `{}`); headline scores credit unsupported tasks; the twin path uses a different
  system prompt, a "any tool call" completion proxy, and sends image twins without images.
- **External.** Assay's loop, prompts and loopback tools are not a vendor's production agent;
  provider-side safety layers and routing are uncontrolled; the routes are mostly small/fast tiers
  and one 2024 8B baseline; the task set and scenario prose are public (contamination mitigations
  apply to the deterministic surface, not to `scenarios.py`).
- **Conclusion.** Five trials, one run, no interval on aggregates, no multiple-comparison control.

## 16. Responsible disclosure

[`SECURITY.md`](../SECURITY.md) governs vulnerabilities in Assay itself (anything that lets a
document claim more than it should, or that harms a user running the tools). It does not yet
cover findings *about* evaluated models. The behaviours reported in §11 are instances of publicly
documented injection classes against a configuration Assay controls, not a new technique against a
vendor's deployed product, and results name only the model route, never the operator. No record
of vendor notification exists in this repository. Recommended policy: before publishing a
model-specific result that demonstrates a technique not already public, notify the vendor with
the scenario, the bundle and the evidence level, and allow a reasonable window; never describe a
loopback result as a compromise of a vendor's product.

## 17. Future work

1. A traced, live re-run of the spectrum with explicit sampling, paired envelopes, ≥ 20 trials
   per cell and a repeat day, published as a signed, redacted bundle.
2. An independently operated witness sink with a pinned key, and precommitment of real-model runs.
3. Mechanism-faithful scenarios for the description, schema, shadowing and rug-pull channels
   (M1, M2, M4, M5, M13), multi-server sessions, and `tools/list_changed` handling in the loop.
4. Construct-validity controls for M3 (benign twin with a legitimate link; a variant labelling the
   value a credential).
5. A controls comparison on real models (hardened prompt, confirmation, egress allowlist, tool
   removal) reporting all five metrics.
6. A fixed LLM utility axis (same prompt, task-specific completion, image twins unsupported).
7. Independent replication and a maintainer attestation; a held-out split operated outside this
   repository; reading the primary sources for SPEC §1 (G11).
