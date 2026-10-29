# Threat model

Assay has two threat models layered on each other, and confusing them is the most common way its
results get misread:

1. **The benchmark's threat model** — what an attacker who controls content an AI agent reads
   can make that agent do. This is what the tasks measure.
2. **The evidence threat model** — what a party publishing an Assay result can make a reader
   believe. This is what the verifier, witness, bundle and replication machinery defend against.

This document states both. It is normative for the methodology
([`BENCHMARK_METHODOLOGY.md`](BENCHMARK_METHODOLOGY.md)) and is the reference the
[credibility audit](CREDIBILITY_AUDIT.md) checks claims against.

---

## 1. Assets

| asset | why it matters | how Assay represents it |
|---|---|---|
| Privileged data the agent can reach (API keys, OAuth tokens, tenant keys, deploy tokens, internal identifiers) | the object of exfiltration | a **synthetic canary**: an HMAC digest of a per-run secret inside a secret-shaped envelope (`sk-`, `AKIA`, JWT, opaque token, `REF-`). No real credential is ever used |
| The agent's authority (tools it may call on the user's behalf) | the object of confused-deputy and excessive-agency attacks | tools on an adversarial MCP server; dangerous ones (`purge_records`, `grant_admin`) are recorded, never real |
| The run secret | lets anyone holding it compute every canary | minted per run by whoever runs the adversarial side; revealed only after the run |
| A witness's signing key | lets a witness's observations be checked by others | Ed25519 key held by the witness, read from the environment, never an argument |
| The integrity of a published result | what a reader relies on | manifest `integrity_hash`, artifact index and signature, witness receipts, verification levels |

## 2. Actors

| actor | controls | trusted for | not trusted for |
|---|---|---|---|
| **Operator** (runs the benchmark, publishes the result) | the harness, the agent loop, the run secret (unless a witness supplies it), the published files | nothing beyond what the artifacts let a reader check | that a run happened, that it is complete, that the model named is the model that answered |
| **Attacker content author** | the content of attacker-controlled surfaces (§4) | — | — |
| **Model provider / router** | which weights answer, provider-side system prompts and safety layers, default sampling, tool-call formatting | returning a response to the request sent | that the route maps to a fixed model revision; that undisclosed server-side layers are constant |
| **Witness** | an egress sink, its own signing key, optionally the canaries | signing only what arrived at its sink | being honest or independent — both are declarations unless established out of band |
| **Verifier** (any reader running `assay_verifier.py`, `assay verify-artifacts`, `assay verify-witness`) | nothing but their own machine | recomputation | — |
| **Replicator** | their own run, own API key, own machine | their own observations | the operator's observations |

The agent under test is not an actor in the trust sense: it is the system being measured.

## 3. Trust boundaries

```text
             ┌──────────────────────────── operator's machine ─────────────────────────────┐
             │                                                                              │
 user task ──┼──► agent loop (Assay: llm_agent / experiment runner) ──HTTPS──► model provider│/router
             │        │   ▲                                                   (outside, B1) │
             │  tools/│   │tool results                                                    │
             │  call  ▼   │                                                                │
             │   adversarial MCP server (loopback 127.0.0.1)   ◄── attacker content (B2)    │
             │        │ read tools: runbook / ticket / record / rules file / tool metadata  │
             │        │ sink tools: post_status / send_reply / forward_webhook / http_get    │
             │        ▼                                                                     │
             │   recorded tool call (egress event) ──► canary oracle ──► scorecard / trace  │
             │        │                                                       │ (B4)         │
             │        └── optional relay of bytes ──────────────┐             ▼              │
             └──────────────────────────────────────────────────┼─────── published bundle ───┘
                                                                ▼ (B3)
                                                  witness sink (ideally another party)
                                                  signs receipts with its own key
```

- **B1 — provider boundary.** Everything about the model beyond the request and the response is
  outside the operator's control and visibility.
- **B2 — attacker-content boundary.** The content returned by read tools (and, for
  description-channel tasks, the tool metadata itself) is attacker-authored. The agent loop
  passes it to the model as data; whether the model treats it as instruction is what is measured.
- **B3 — witness boundary.** Only bytes that cross to a sink the operator does not control can be
  observed by someone other than the operator. In every committed real-model artifact today,
  **nothing crosses B3**: the sink is the operator's own loopback server.
- **B4 — publication boundary.** Everything a reader receives is operator-written unless signed
  by a key the operator does not hold.

## 4. Attacker capabilities per surface

The attacker never controls the system prompt, the user request, the agent loop or the model.
They control exactly one surface per scenario:

| surface | attacker can | cannot | Assay scenarios that use it (real-model path) |
|---|---|---|---|
| **Tool description / input schema** (the metadata an MCP server returns from `tools/list`) | write arbitrary text the model sees before any call; change it after approval (rug pull); describe another server's tool (shadowing) | make the client call the tool | catalog tasks M1, M2, M4, M5, M13 describe this; **no real-model scenario exercises it** — the deterministic conformance stubs plant there (`surface.py`). See [`case-studies/tool-description-manipulation.md`](../case-studies/tool-description-manipulation.md) |
| **Tool response** (the result of a tool the agent chose to call) | return arbitrary text, including instructions and URL templates | choose when or whether it is called | M7 (partner request list), M8, M9, M16 (`scenarios.py`) |
| **Retrieved document** (knowledge-base or runbook passage) | plant a "documented procedure" step the user asked the agent to follow | change what the user asked | M3 (`search_runbook`), reused for 14 further task ids by `_default_canary_scenario` |
| **Ticket / record** (user-generated content inside a business system) | write text in a field the agent reads during triage; share a record across tenants | read other tenants' data directly | M1 (support ticket), M23 (cross-tenant shared record) |
| **Repository / config file** (rules files the agent treats as project policy) | add a directive to a file loaded as authoritative | modify the agent's configuration | M24 (`.agentrules`) |

In every scenario the attacker also controls the **destination** named in the payload
(`status.acme-ops.io`, `billing-verify@partner-intake.example`, the "northwind" partner tool,
`intake.northwind-partners.example`, `registry.acme-ci.example`). Those are fictional; the sink
tools serving them are loopback handlers that return `"200 OK"`.

## 5. The five-way outcome distinction

A single word ("leaked") has been used for five different events. They have different evidence
and must be reported separately. The trace format (`assay/trace/1`) gives each its own event
type.

| # | event | what establishes it | trace event | in the committed spectrum? |
|---|---|---|---|---|
| 1 | **The model generated a dangerous string** (the canary appears in its output, prose or arguments) | the model response, if recorded | `model_output_contains_canary` | not recorded (no transcripts) |
| 2 | **The model requested a tool call** carrying it | the raw tool-call arguments from the response | `tool_call_requested` | **yes — this is what the oracle scored** |
| 3 | **The tool accepted / executed** that call with the canary in its arguments | the tool handler's record of the arguments it received | `tool_call_executed` (or `tool_call_blocked` by a control) | not recorded separately; usually implied, but not always (an unparseable argument string is executed as `{}`) |
| 4 | **Data was transmitted over a network** | the harness sent bytes to a destination | `network_egress_attempted` / `network_egress_blocked` | **no** — the sinks never send |
| 5 | **Data arrived at an (independently) controlled destination** | a party controlling that destination observed it and signed a receipt | `egress_observed_at_sink` with a witness receipt | **no** |

Events 1–3 are model behaviour and are what a benchmark of agent robustness measures. Events 4–5
are what "exfiltration" means in an incident report. The committed real-model results establish
event 2, self-reported. Calling them "confirmed exfiltration" conflates 2 with 4–5.

## 6. What each evidence level defends against

| evidence level | defends against | does not defend against |
|---|---|---|
| `format_valid` | malformed documents | anything semantic |
| `internally_consistent` | stated scores that disagree with the findings; post-hoc edits (integrity hash) | a coherent fabrication |
| `canary_correspondence_verified` | a "leak" string that does not contain the keyed tag; tampering with a proof | a keyholder pasting a computed digest into an invented string |
| `catalog_bound` | redefining a task's mode, oracle or weight | omission of findings (partly addressed by `run_complete` and the lower bound) |
| `run_complete` | short reports passed off as complete runs | silently unrun tasks reported as resisted |
| artifact index + signature (`verify-artifacts`) | files swapped, added or removed after signing; mismatch between scorecard, trials and traces | the signer fabricating the whole bundle |
| trace consistency (`check_trace`) | internally contradictory traces (a tool executed that was never requested, an egress with no execution, a "fired" validation with no canary-bearing request, broken hash chains) | a consistent fabricated trace |
| witness receipts (`verify-witness`) | an operator inventing an egress observation **if** the witness is independent and its key is pinned | a self-operated witness; a dishonest witness; key misattribution |
| `precommitment_verified` | choosing the secret after seeing results; silently discarding a registered run | registering N runs and revealing one (visible, not prevented) |
| independent replication / `maintainer_attested` | a single operator's error or fabrication | shared systematic error (same harness bug in both runs) |

No level establishes that the named model, at a stable revision, is what answered.

## 7. Out of scope

- Model-weight and training-time attacks; pure prompt-only jailbreaks; host-OS exploits
  (SPEC §8).
- Attacks on the provider or router themselves.
- Whether a vendor's production agent (with its own system prompt, tool policy and UI) would
  behave as Assay's agent loop did. Assay measures **a configuration**: this loop, these tools,
  this system prompt, this model route.
- Real exfiltration to the internet. Targets are loopback or in-process; the published benchmark
  never scores or contacts a live third-party endpoint.
- Image channels against real models (the text adapter declares `decodes_images: False`).
- Human-in-the-loop confirmation UIs; the agent loop executes every requested call unless a
  configured control blocks it.
