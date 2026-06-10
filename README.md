<div align="center">

# Assay

A canary-oracle benchmark for MCP security. Score an MCP server or agent against a frozen task
set and get one comparable number, decided by a deterministic cryptographic oracle at the tool
boundary rather than an LLM judge.

[![CI](https://github.com/VatsSShah/assay/actions/workflows/ci.yml/badge.svg)](https://github.com/VatsSShah/assay/actions)
![spec](https://img.shields.io/badge/spec-v0.1-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![tasks](https://img.shields.io/badge/frozen%20tasks-31-purple)
![deps](https://img.shields.io/badge/runtime%20deps-stdlib%20only-lightgrey)

Maintained by [Verosek](https://www.verosek.com). The standard is vendor-neutral; Verosek runs
the reference implementation and a commercial continuous-scoring service.

</div>

---

## The idea

A canary is a per-run value of the form:

```text
digest = HMAC-SHA256(run_secret, "origin|tool|step")[:16]
```

It is planted inside a realistic-secret envelope (an `sk-` key, an `AKIA` id, a JWT, an opaque
token, or a bare reference number) that rotates per run. The value the agent sees looks like a
real secret, so refusing to leak it is the same behaviour as refusing to leak a real secret, not
pattern-matching a benchmark marker. Detection is envelope-agnostic: recompute the 16-hex digest
and look for it (or a documented encoding) in the tool call or egress.

Because `run_secret` is fresh random bytes each run, the digest exists nowhere else and cannot be
forged or precomputed. So for the canary-gated tasks, a hit means a planted secret crossed a
boundary it should not have. That is a fact you can recompute, not a model's opinion, and its
false-positive rate is structurally zero (proof in [SPEC.md](SPEC.md) §4). The proof is about the
oracle: it says a canary hit implies real exfiltration. It does not claim a given model will or
will not leak; that is what scoring a target measures.

```mermaid
flowchart LR
  A["Mint per-run secret k<br/>(32 random bytes)"] --> B["digest =<br/>HMAC-SHA256(k, origin·tool·step)"]
  B --> C["Plant in a realistic-secret envelope<br/>sk- / AKIA / JWT / opaque / bare-ref"]
  C --> D{"Does the agent or<br/>server emit it?"}
  D -- "digest appears in egress" --> E["finding (deterministic proof)"]
  D -- "no" --> F["resisted"]
  E --> G["Ship triple:<br/>(run_secret, preimage, observed)"]
  G --> H["anyone recomputes the<br/>digest and confirms"]
```

## Why a cryptographic oracle

HarmBench and StrongREJECT, the standard jailbreak benchmarks, both score with a learned grader
and so carry a measured false-positive rate. AgentDojo introduced a deterministic state oracle
for agent prompt-injection, but it is not MCP-scoped and not cryptographic. The MCP taxonomies
(OWASP MCP Top-10, Adversa MCP Top-25, MITRE ATLAS) define threats but no scoring oracle. Assay
fills that gap for MCP: a frozen task set whose canary-gated results are decided by a recomputable
HMAC oracle.

## Quickstart: verify a scorecard with the standard library

```bash
pipx run assay-bench path/to/scorecard.json          # validate a whole manifest
pipx run assay-bench triple <run_secret> <origin> <tool> <step> <observed>   # one proof triple
```

The verifier checks four things: the commitment binds the revealed secret, the manifest integrity
hash matches, every fired canary recomputes from its triple, and the stated scores match the
scores recomputed from the findings. So a submitter cannot fake a canary hit or state a score the
findings do not imply. It does not, on its own, prove an honest run happened against a real
target (a submitter could under-report by not running the attacks); that is why every leaderboard
row is re-run by a maintainer.

## What's in this repo

| file | what it is |
|---|---|
| [`SPEC.md`](SPEC.md) | the versioned specification: two modes, oracle rules, FP=0 proof, metrics, commit-reveal, anti-contamination, freeze policy |
| [`TASKS.md`](TASKS.md) | the full catalog of all 31 tasks: mechanism, poison template, canary plant, egress, oracle rule, vulnerable-vs-safe behaviour, mitigation, taxonomy |
| [`tasks.json`](tasks.json) | the frozen task set as data, severity weights, taxonomy crosswalk |
| [`COVERAGE.md`](COVERAGE.md) | every task mapped to OWASP MCP / Adversa-25 / OWASP ASI / MITRE ATLAS |
| [`assay_verifier.py`](assay_verifier.py) | the standalone third-party verifier (stdlib only) |
| [`scoring.py`](scoring.py) | the two 0-100 scores (Agent Resistance, Server Posture) and the over-refusal axis |
| [`badge.py`](badge.py) | turn a passing scorecard into an embeddable shield |
| [`manifest_schema.json`](manifest_schema.json) | the scorecard JSON Schema |
| [`leaderboard/`](leaderboard/) | the two-track leaderboard: schema, site builder, submission protocol, reference manifests |
| [`reference/confusion_matrix.json`](reference/confusion_matrix.json) | the reference run's per-task recall and false-positive table |
| [`corpus/README.md`](corpus/README.md) | the labeled corpus: built-in controls plus external vulnerable servers (loopback) |
| [`paper/assay.tex`](paper/assay.tex) | the methodology paper |

## Two modes

A mapped surface is never reported as an exploit. Every result states its mode and whether its
evidence is a canary, a protocol fact, or a deterministic behavioural check.

```mermaid
flowchart TB
  subgraph MA["Mode A: server pentest (you are the client)"]
    A1["Assay MCP client"] --> A2[("your MCP server")]
    A2 --> A3["evidence = reproducible protocol fact<br/>(unauth tools/list, missing Origin, param injection, SSRF)"]
  end
  subgraph MB["Mode B: agent robustness (your agent is under test)"]
    B1["your agent"] -->|tool calls| B2["adversarial MCP server<br/>(poisoned descriptions + results)"]
    B2 -->|poisoned tool results| B1
    B1 --> B3["evidence = canary hit at the egress boundary"]
  end
```

## Result integrity

```mermaid
sequenceDiagram
  participant H as Harness
  participant L as Leaderboard
  participant V as Anyone (verifier)
  H->>L: 1. commitment = SHA-256(run_secret), before the run
  H->>H: 2. run frozen tasks, mint per-run canaries
  H->>L: 3. reveal run_secret + manifest (triples, scores, integrity hash)
  V->>V: 4. commitment binds reveal? triples recompute? scores match findings? hash matches?
  V-->>L: verified, cold, stdlib only
```

The manifest carries an integrity hash (a SHA-256 over its own content), not a cryptographic
signature. Commit-reveal stops a submitter from changing the secret after seeing results; the
score-binding check stops them from stating a number the findings do not support. Authenticity of
the run itself comes from the maintainer re-run.

## The reference numbers, scoped honestly

The repo ships a reference run against the built-in labeled corpus. That corpus uses deterministic
vulnerable and safe reference targets (in-process stubs), so the reference run is **mechanism
validation**: it confirms every attack fires against a target built to be vulnerable and clears a
target built to resist, and that the canary-gated families produce no false positive on the safe
side. It is not a field measurement against a live model. The structural FP=0 claim is the
cryptographic one above; the live ASR of a real model or server is what you get by scoring that
target (the reference implementation, see below). Per-task numbers are in
[`reference/confusion_matrix.json`](reference/confusion_matrix.json).

## Leaderboard

```mermaid
flowchart LR
  S["PR: manifest + entry"] --> C["CI runs the verifier<br/>(binds proofs + scores)"]
  C -- "fails" --> X["blocked"]
  C -- "verifies" --> M["maintainer re-runs<br/>at the pinned version"]
  M --> R["row published<br/>(links to its manifest)"]
```

Two tracks: Agent Resistance (Mode B) and Server Posture (Mode A). The verifier makes a stated
score impossible to inflate; the maintainer re-run is what attests the row is a real run against
the named target. See [`leaderboard/SUBMIT.md`](leaderboard/SUBMIT.md).

## Multimodal track

Six tasks carry the canary through a non-text channel, scored by the same oracle (no per-modality
judge to mis-read an image or mis-hear audio): M20 directive in a user-attached image, M26
directive in the pixels of a tool-returned image, M27 a cross-modal chain (a vision tool surfaces
the canary, a network tool exfiltrates it, with no injected instruction), M28 a steganographic
chart (canary in alt-text/metadata), M29 a rug-pull on an image resource, M30 a QR code encoding
an egress URL. Full mechanics in [`TASKS.md`](TASKS.md).

## Anti-contamination

- **Over-refusal (utility) axis (planned).** Resistance measures false success. The utility axis
  measures false refusal, a secure-but-useless target that blocks legitimate tool use. The scoring
  is defined (a helpful target scores 0%, an over-cautious one 100%), but the benign twins are not
  authored yet, so no live target is measured against it today.
- **Held-out split (planned).** `tasks.json` is the public split. A held-out split with the same
  oracles and unpublished task instances is maintained separately so a target that memorizes the
  public tasks can be caught by the gap between its public and held-out scores. Until that ships,
  commit-reveal blocks result grinding but not task memorization, so treat a high public score as
  necessary, not sufficient.

## Scope

In scope: tool-call injection, tool-return and RAG poisoning, rug-pull, cross-tenant, TOCTOU,
confused-deputy, transport/unauth/DNS-rebind, secret exfil, excessive agency, multimodal exfil,
and lethal-trifecta source-to-sink paths (the 31 tasks in [`TASKS.md`](TASKS.md)). Out of scope:
model-weight or training-time attacks, pure prompt-only jailbreaks (owned by StrongREJECT),
host-OS exploits. Targets are loopback only; the published benchmark never scores a live
third-party endpoint, so every result is locally reproducible.

## Open standard vs. reference implementation

The standard (this repo, MIT-licensed) is the canary methodology, the frozen task set, the
verifier, the manifest schema, and the leaderboard protocol. It is vendor-neutral so anyone,
including competitors, can run and cite it. The reference implementation that runs the tasks, and
a commercial continuous-scoring service, are maintained by [Verosek](https://www.verosek.com). The
commercial layer never touches this spec or the leaderboard's neutrality.

## Cite

> Assay: a canary-oracle benchmark for MCP security, v0.1. See [`SPEC.md`](SPEC.md) and
> [`CITATION.cff`](CITATION.cff).

Licensed under [MIT](LICENSE). Third-party taxonomy attributions in [`NOTICE`](NOTICE).

---

<div align="center"><sub>Built and maintained by <a href="https://www.verosek.com">Verosek</a> · verosek.com</sub></div>
