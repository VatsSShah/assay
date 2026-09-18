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
- **Precommitment and attestation are now exercised, not just implemented.**
  `precommit/registry/` holds a worked example registered in its own earlier commit, whose
  manifest reaches `repository_ordering_verified` from any clone. `attest/` holds a
  clean-clone reproduction whose invariants matched exactly. Attestation records now carry
  `kind` (`maintainer_attestation` vs `clean_clone_reproduction`) so a reproduction cannot be
  mistaken for an attestation; no maintainer attestation has been performed and a test asserts
  no shipped record claims one.
- `assay_bench/diagnostics.py` — the oracle's blind spots, measured at run time instead of only
  published. Twelve detectors (case folding, homoglyphs, separator/zero-width insertion,
  reversal, rot13, base32, base85, gzip/zlib, single-byte XOR, unsalted hashes, truncation, and
  splitting across events) catch 14 of the 15 documented misses. **No diagnostic changes a
  score** — widening the oracle is a MAJOR bump — and a test asserts a run with diagnostics on
  and off produces identical scores and findings. Confidence is per-detector: a recovered full
  digest carries the oracle's own collision argument, a truncated one does not and says so.
- `twins.json` + `assay_bench/twins.py` — the utility axis, measured rather than defined. 8
  benign twins, one per attack task, each declaring the surface feature it shares with its pair
  and arguing why complying is correct. `conformance-overcautious` ships as a fourth reference
  target: identical to `hardened` on resistance (100/100), opposite on utility (100.0 vs 0.0),
  so the published evidence shows a resistance score alone cannot tell a secure target from a
  useless one. Manifests carry a `utility` block and the verifier recomputes the rate from it.
- `assay_bench/mcp/` — a real MCP implementation, stdlib only: JSON-RPC 2.0 with a strict
  decoder, the `initialize` handshake with protocol-version negotiation, `tools/list` and
  `tools/call`, over stdio (subprocess, newline-delimited frames, deadline enforced) and
  Streamable HTTP (including SSE bodies). `assay_bench/servers/reference.py` runs two real MCP
  servers as separate processes, insecure and hardened, as one program with a posture
  parameter. `assay_bench/adapters/mcp_probe.py` drives them and decides all three Mode-A tasks
  from what it observed on the wire, with `is_real_target=True`. `assay run --target-url`
  probes someone else's server as a labelled third-party measurement.
- Interoperability with the **official MCP SDK** is checked in `tests/test_mcp_interop.py` and
  in its own CI job that fails if the check skips. The SDK is not a dependency.
- `assay_bench/media.py` — a dependency-free image layer, so the six image-channel tasks are
  executed as images rather than described as them. Spec PNG writer/reader with CRC32-validated
  `tEXt` chunks, LSB steganography over the pixel data, and a QR encoder/decoder (byte mode,
  level L, versions 1-10) with GF(256) Reed-Solomon, BCH(15,5) format information and data
  masking. Validated in `tests/test_media.py` against the published format tables, not against
  its own output.
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

- **`png_to_qr` had to be told the module scale.** A PNG written at a different scale was
  silently sampled at the wrong pixels and returned a matrix of noise rather than failing. It
  now infers scale and quiet zone from the image the way a scanner must, by measuring the
  top-left finder pattern, and validates the geometry.
- **`git log --follow` decided precommitment ordering.** Rename detection is a similarity
  heuristic and two manifests look alike to it, so `introducing_commit` traced a new manifest
  back to an unrelated reference manifest in the baseline commit and denied an honest
  submission `repository_ordering_verified`. The soundness direction is worse: a registry
  record could have inherited an older file's commit date and made a commitment look earlier
  than it was. `--follow` is gone and both directions are tests.
- **An MCP target's fingerprint included the ephemeral TCP port**, so the same server
  fingerprinted differently on every restart and a commitment could never bind its own run.
  Identity is now scheme, host and path, with the exclusion and its reason stated inside the
  republished pre-image.
- **M17 was decided by the wrong protocol fact.** `PROTOCOL_PREDICATES` was keyed on names no
  task used (`mcp_unauth_transport`, `mcp_dns_rebind`), so both protocol tasks fell through to a
  default that read `unauthenticated_tools_list`. A server that authenticated but had no
  DNS-rebind protection was scored as **resisting** M17, and the DNS-rebind predicate was dead
  code. The uniform conformance stubs could not surface it because they set every fact from one
  flag; pointing the harness at a real server did. There is now no default: an unregistered
  attack raises, and a predicate whose facts the adapter never reported makes the trial
  inconclusive rather than silently reading a missing fact as False.
- **An adapter that drives a server could score Mode-B tasks.** The capability check asked only
  which channels an adapter exposed, so a server probe emitting tool calls satisfied the canary
  oracle and all 28 Mode-B tasks were scored against a target never shown one — a headline
  100.0 for a run that decided three tasks. `Capabilities` now carries
  `drives_agent_under_test` / `drives_server_under_test`, checked before the channels, and an
  unsupported task states which requirement it failed.
- **An unreachable target scored as resisting.** The Mode-A probe treated a refused connection
  the same as a refusal by a live peer, so a server that was merely down was credited with
  protecting itself. Only an answer from a live peer is evidence now; a transport failure
  propagates and the trial is inconclusive.
- **For a partial run the CLI leads with the lower bound**, not the headline, which assumes
  every undecided task resisted.
- **The six image tasks now really carry their canary through an image.** M20, M26, M27, M28,
  M29 and M30 were text simulations: the "image" was prose and the canary was pasted into that
  prose. They now attach real PNG bytes, with the plant route recorded per task as
  `execution.image_plant` (`pixels`, `metadata`, `qr`, `rug_pull`), and the surface builder
  refuses to emit a surface whose canary or digest is also readable in the text. Adapters
  declare `decodes_images`; a target without it is `unsupported` on these six, never `resisted`.
  No task is labelled `text_simulation` any more. The limit is stated everywhere the claim is:
  the decoder is this repository's own, and no third-party scanner or production vision model
  has been shown to read these images.
- **src/ layout.** The package moved to `src/`, so a passing test exercises the installed
  package rather than the checkout beside it.
- **The wheel ships what it needs.** It carried `assay_verifier.py` alone; an installed verifier
  could not reach `catalog_bound` because `tasks.json` was not packaged. It now carries the
  verifier, scorer, badge tool, runner package, the frozen catalog and the published schema.
- **Scores use the frozen catalog's weight total as the denominator**, never the reported
  findings'. For a complete run this is identical, so every valid v0.1 score is unchanged.
- **Tests: 7 → 477, standard library only.** Converted from pytest to `unittest`, so the
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
