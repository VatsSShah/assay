# Assay corpus, ground truth (positives + negatives)

A benchmark needs labeled targets, not just attacks. Assay ships a **built-in labeled
corpus** and integrates **third-party vulnerable servers**, both run on **loopback only**,
so any result is reproducible locally and the published benchmark never targets a live
third-party endpoint.

## Built-in labeled corpus (runnable now, no key, no network)

Every frozen task is paired with two targets:

- a **vulnerable** target that the attack's mechanism should beat (a labeled **positive**),
- a **hardened control** that resists it (a labeled **negative**).

`python -m benchmarks.assay reference` runs all 31 tasks against both and emits the
confusion matrix (`runs/reference/confusion_matrix.json`). This is what proves the two
claims that make Assay a benchmark and not a demo:

- **Recall**, every attack fires against its vulnerable target.
- **FP = 0**, canary-gated families raise **zero** findings against the hardened control
  (latest reference run: **0/625**, Wilson 95% ≤ 0.62%). A control that ever trips is a
  *harness bug to fix before release*, not a finding.

## Third-party vulnerable servers (external positives, loopback)

To balance the self-authored controls, Assay's Mode-A track points at independently
published vulnerable MCP servers. These are **not bundled** (they carry their own licenses)
- they are fetched and run locally:

| Repo | What it is | Use |
|---|---|---|
| `harishsg993010/damn-vulnerable-MCP-server` (DVMCP) | the canonical "damn-vulnerable" MCP challenge set | external Mode-A positives |
| `appsecco/vulnerable-mcp-servers-lab` | a lab of intentionally-vulnerable MCP servers | external Mode-A positives |
| `IntegSec/VulnerableMCP` | an index/database of MCP vulnerabilities | mapping reference |

> **Integration (loopback only).** Clone the target, run it bound to `127.0.0.1`, and point
> the reference implementation's Mode-A client at it. Confirm each repo's license before
> redistributing any of its content; Assay references them by URL and does not vendor their
> code. Exact challenge counts/categories are read from each repo at integration time rather
> than asserted here, so this file never drifts from upstream.

## Why both halves matter

Self-authored controls alone could be dismissed as a vendor strawman; third-party DVMCP
positives alone wouldn't prove FP=0. Together they give a confusion matrix that proves
**recall** (catches the planted vulns) *and* **specificity** (clears the hardened controls)
- the evidence a skeptic asks for.
