# Changelog

Versions are `MAJOR.MINOR.PATCH` for the **package** (`assay-bench` on PyPI, once published).
The **benchmark** is versioned separately as `MAJOR.MINOR` in `tasks.json` and is the frozen
task-set line: it moves only when the task set does, never when the tooling changes. See
[`SPEC.md`](SPEC.md) §9.

| version | what it names |
|---|---|
| package `0.2.0` | this tree's code |
| benchmark `0.1` | the 31 frozen tasks, unchanged since the first release |
| manifest format `2` | the scorecard document shape, in `provenance.manifest_format` |
| validity rules `1` | the completeness rules, in `validity.rules_version` |
| precommit record schema `assay/precommit-record/1` | |
| attestation schema `assay/attestation/1` | |

## Unreleased — package 0.2.0

Audit and repair of the v0.1 tree, from `675fae7`. Full account in
[`IMPLEMENTATION_SUMMARY.md`](IMPLEMENTATION_SUMMARY.md); open items in
[`REMAINING_GAPS.md`](REMAINING_GAPS.md).

### Security-relevant fixes

- **`python -O` disabled every verifier check.** All validation used `assert`, which `-O`
  removes, so a tampered manifest verified and exited 0. Every assertion is now an explicit
  typed exception, with a test and a CI step that run the verifier under `-O` and require exit 1.
- **Verification is no longer summarised as one word.** `verify_manifest` reports levels
  (`format_valid`, `internally_consistent`, `canary_correspondence_verified`, `catalog_bound`,
  `run_complete`) and names `precommitment_verified`, `independently_rerun` and
  `maintainer_attested` as structurally out of its scope.
- **Manifests that used to pass and now do not:** duplicate task ids, unknown task ids, altered
  severity weights, mode flips between score denominators, unsupported benchmark versions,
  canary proofs on non-canary tasks, unfired canaries shipping proofs, unknown top-level fields,
  NaN/±inf/out-of-range values.
- **"No egress observed" is no longer scored as "the target resisted."** All three oracles now
  refuse to decide on an empty channel, so a broken or unobservable adapter cannot produce a
  clean score.

### Added

- `assay_bench/` — a runnable harness. `PYTHONPATH=src python -m assay_bench` or the installed
  `assay`: catalog loader, canary minting, adapter interface, three deterministic conformance
  targets, typed per-class oracle evaluators, trial loop with reset/timeout/error handling,
  provenance, manifest generation, reference regeneration.
- `assay_bench/validity.py` — benchmark validity rules V1–V8: required tasks per track, a fixed
  catalog denominator, unsupported-capability handling, timeout/error/inconclusive semantics,
  minimum trials, recorded retries, complete-vs-partial, and the rule that partial runs are
  never ranked beside complete ones. Every manifest now carries an omission-proof lower bound.
- `assay_bench/precommit.py` — pre-run commitment with the ordering authority named at each
  level, tested against real git repositories.
- `assay_bench/attest.py` — maintainer attestation as a separate repository-controlled artifact,
  comparing run invariants rather than bytes.
- `--trials-out` writes the raw per-trial record: state, canary digest, preimage, channels
  observed, retries. Kept outside the integrity-hashed document as evidence, not claim.
- Execution contracts in `tasks.json`: channel, plant site, egress surface, declared modality
  and **implemented** modality, plus required capabilities. Drift tests hold `tasks.json`,
  `TASKS.md`, `COVERAGE.md` and runtime registration in agreement.
- `reference/conformance_matrix.json` — recall, specificity and **discrimination** against three
  deterministic targets.
- `audit/` — baseline, issue triage, claim/evidence matrix, machine-readable run and test
  summaries. `demo/` — reproducible terminal demo, runbook, video validation.

### Changed

- **src/ layout.** The package moved to `src/`, so a passing test exercises the installed
  package rather than the checkout beside it.
- **The wheel ships what it needs.** It carried `assay_verifier.py` alone; an installed verifier
  could not reach `catalog_bound` because `tasks.json` was not packaged. It now carries the
  verifier, scorer, badge tool, runner package, the frozen catalog and the published schema.
- **Scores use the frozen catalog's weight total as the denominator**, never the reported
  findings'. For a complete run this is identical, so every valid v0.1 score is unchanged.
- **Tests: 7 → 312, standard library only.** Converted from pytest to `unittest`, so the
  "stdlib alone" claim holds end to end and `unittest discover` no longer reports
  `Ran 0 tests ... OK`.
- `license = { file = "LICENSE" }` → SPDX `license = "MIT"` with `license-files`, so builds no
  longer emit a deprecation warning. Requires `setuptools>=77`.
- Claims withdrawn across every surface: the HarmBench/StrongREJECT analogy, "the open wedge",
  every "first", "auditable cold", "kills cherry-picking", "cannot be inflated or
  self-reported", and `0/625` with a Wilson bound over deterministic stubs. `SPEC.md` §1 is now
  a related-work section citing MCPSecBench, MCPTox, MSB and MCP-SafetyBench, all of which
  predate this work.
- The six "multimodal" tasks are labelled **text simulations**, because that is what the runner
  does; `TASKS.md` already said so per task.
- Reference artifacts are generated by `assay reference`, byte-reproducibly. The old
  `confusion_matrix.json` (31 identical rows with Wilson intervals over a stub) is retired to
  `tests/fixtures/legacy_v0_1/`.

### Removed

- `scorecard_vulnerable.json` / `scorecard_hardened.json` — byte-identical duplicates of the
  reference manifests, referenced by nothing.
- `pipx run assay-bench` from the README: there is no PyPI release, and none is claimed.

### Compatibility

Unchanged: the 31 task ids, their modes, oracle classes and severity weights; both score
formulas; the integrity-hash rule; the canary triple format; the digest rule and its four frozen
encodings. v0.1 manifests still verify and two are kept as fixtures the suite checks on every
run. Every v0.1 CLI invocation still works, including the bare-path form.

Changed: the verifier's **output** shape (levels, not `verdict: VERIFIED`). Consumers keying on
that string need updating — see `REMAINING_GAPS.md` G12.

## 0.1.0 — `675fae7`

Initial release: specification, 31-task corpus, standard-library verifier, scoring/coverage/
badge/leaderboard helpers, schemas, four manifests, paper, seven pytest tests.
