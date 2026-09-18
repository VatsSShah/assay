# Assay leaderboard

Every row links to a manifest whose canary triples anyone can recompute. The build re-verifies each one and refuses to publish a row whose stated score disagrees with its own findings, or whose document was altered after sealing.

**Read the Levels column, not the score alone.** Verification is a coherence property of a document, not evidence that a run happened:

| code | level | what it establishes |
|------|-------|---------------------|
| `F` | format_valid | the document satisfies the manifest schema |
| `I` | internally_consistent | commitment binds the reveal, integrity hash matches, scores equal what the findings imply |
| `C` | canary_correspondence_verified | every fired canary's triple recomputes under the revealed secret |
| `B` | catalog_bound | every finding is a frozen task, with the catalog's own mode, oracle and weight |
| `R` | run_complete | all 31 frozen tasks reported, no errors or timeouts |

**Precommit** and **Attested** are separate artifacts, not verifier output. `Precommit` records whether a commitment was registered before the run and how that ordering was established (see [`../precommit/`](../precommit/)). `Attested` records whether a maintainer independently reran the target (see [`../attest/`](../attest/)). A dash means *not established*, never *assumed*.

A submitter who holds the run secret can synthesise a passing canary without running anything; that is why `C` is not an attestation and why the Attested column exists. See [SUBMIT.md](SUBMIT.md).

**Complete vs partial.** A row is ranked only if it is a *complete* run: every task in the frozen catalog for its track reported, every task conclusive, no unsupported tasks, no errors or timeouts, and at least the minimum trial count. Partial runs are listed in their own table with no rank and no headline score, showing instead the lower bound that charges every unreported, unsupported or inconclusive task at full weight. Scores use the **frozen catalog's** weight total as the denominator, never the reported findings', so a task cannot take its weight out of the denominator by being left out. The rules are in `assay_bench/validity.py`.

## Conformance rows (built-in deterministic stubs)

These validate the harness, not a product. They are tabled separately so a stub's 100.0 is never mistaken for a measurement of a real system.

### Agent Resistance (Mode B) - conformance

| # | Target | Score | Assay | Levels | Precommit | Attested | Submitter | Manifest | Notes |
|---|--------|-------|-------|--------|-----------|----------|-----------|----------|-------|
| 1 | Conformance target: hardened (built-in, deterministic) | **100.0** | v0.1 | `FICBR` | - | - | Assay reference | [manifest](manifests/reference_hardened.json) | Harness specificity check. A stub built to refuse; nothing may fire. Not a product measurement. |
| 2 | Conformance target: mixed (built-in, deterministic) | **71.7** | v0.1 | `FICBR` | - | - | Assay reference | [manifest](manifests/reference_mixed.json) | Harness discrimination check. Susceptible only on a published task subset, so a per-task evaluator can be told apart from a global flag. Not a product measurement. |
| 3 | Conformance target: vulnerable (built-in, deterministic) | **0.0** | v0.1 | `FICBR` | - | - | Assay reference | [manifest](manifests/reference_vulnerable.json) | Harness recall check. A stub built to comply; every attack must fire. Not a product measurement. |

### Server Posture (Mode A) - conformance

| # | Target | Score | Assay | Levels | Precommit | Attested | Submitter | Manifest | Notes |
|---|--------|-------|-------|--------|-----------|----------|-----------|----------|-------|
| 1 | Conformance target: hardened (built-in, deterministic) | **100.0** | v0.1 | `FICBR` | - | - | Assay reference | [manifest](manifests/reference_hardened.json) | Mode-A view of the same run. Harness specificity check. A stub built to refuse; nothing may fire. Not a product measurement. |
| 2 | Conformance target: mixed (built-in, deterministic) | **81.0** | v0.1 | `FICBR` | - | - | Assay reference | [manifest](manifests/reference_mixed.json) | Mode-A view of the same run. Harness discrimination check. Susceptible only on a published task subset, so a per-task evaluator can be told apart from a global flag. Not a product measurement. |
| 3 | Conformance target: vulnerable (built-in, deterministic) | **0.0** | v0.1 | `FICBR` | - | - | Assay reference | [manifest](manifests/reference_vulnerable.json) | Mode-A view of the same run. Harness recall check. A stub built to comply; every attack must fire. Not a product measurement. |

## Measurement rows (real targets)

### Agent Resistance (Mode B) - measurement

_No measurement rows yet._

### Server Posture (Mode A) - measurement

_No measurement rows yet._
