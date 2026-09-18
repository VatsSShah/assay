# Claim / evidence matrix

Every material claim across README, SPEC, CONTRIBUTING, corpus, SUBMIT, CITATION, NOTICE,
package metadata, leaderboard, badges, the conformance artifacts and the presentation brief.
Each row records the original v0.1 text, what the code actually supports, and the disposition.

`tests/test_artifacts_and_docs.py::ClaimConsistency` fails the build if a withdrawn phrase
reappears on any surface, so this table is enforced, not aspirational.

**Disposition key:** **keep** (true as written) · **narrow** (true once scoped) ·
**remove** (withdrawn) · **blocked** (needs an owner decision).

---

## 1. Novelty and positioning

| # | v0.1 text | source | evidence | disposition | replacement |
|---|---|---|---|---|---|
| 1.1 | "Assay is to MCP security what HarmBench and StrongREJECT are to jailbreak evaluation" | SPEC.md:3 | Both ship runnable harnesses and publish measurements of named models. At baseline Assay had no runner (`BASELINE_AUDIT` §4 #12) and had measured nothing but its own stubs. | **remove** | No analogy. SPEC §1 states three checkable contributions instead. |
| 1.2 | "**The open wedge.** Every MCP taxonomy is a list, not a benchmark" | SPEC.md:34 | MCPSecBench (2508.13220, Aug 2025), MCPTox (2508.14925, Aug 2025), MSB (2510.15994, Oct 2025), MCP-SafetyBench (2512.15163, Dec 2025) all predate this repo; all released artifacts. | **remove** | SPEC §1 comparison table + explicit withdrawal. |
| 1.3 | "first cryptographic, recomputable, structural-zero-FP exfiltration proof at the MCP tool boundary" | SPEC.md:40 | AgentDojo established judge-free deterministic oracles (2024); HMAC-keyed canary tokens are prior art; MSB/MCPTox already execute against real tools. | **remove** | "Assay's contribution, stated without a first": a recomputable result format, levelled verification with a written trust boundary, a frozen weighted crosswalked task set. |
| 1.4 | "the reason a benchmark gets cited rather than sold" | SPEC.md:14 | Rhetorical; nothing to verify. | **remove** | Deleted. |
| 1.5 | (absent) | — | The four prior benchmarks were uncited. | **new** | SPEC §1 table with dates, execution models and artifact locations, marked secondary-source-confirmed because arxiv.org is blocked from the audit container. |

## 2. What verification establishes

| # | v0.1 text | source | evidence | disposition | replacement |
|---|---|---|---|---|---|
| 2.1 | "a leaderboard claim is auditable cold" | assay_verifier.py:8, SPEC.md:129 | A keyholder can paste a computed digest into an invented string and pass (`test_keyholder_can_synthesise_a_passing_canary_without_any_run`). | **remove** | "Verification is a coherence property of a document, not evidence that a run happened." |
| 2.2 | "a score cannot be inflated or self-reported" | SUBMIT.md:3, build_site.py:5 | Omitting findings took the agent score 0.0 → 100.0 with the manifest still valid (`test_dropping_findings_raises_the_score…`). | **remove** | "A stated number cannot disagree with the findings it summarises." True, and narrower. |
| 2.3 | "so a submitter cannot fake a canary hit" | README:73 | False: the submitter holds the key. | **remove** | The README's first table states the limit before anything else. |
| 2.4 | "It does not, on its own, prove an honest run happened" | README:74 | True, and the only v0.1 sentence that was already correct. | **keep** | Kept and expanded to both directions (fabrication as well as omission). |
| 2.5 | (absent) | — | Five levels are implemented and tested. | **new** | `format_valid`, `internally_consistent`, `canary_correspondence_verified`, `catalog_bound`, `run_complete`, plus three the verifier declares out of scope. |
| 2.6 | "a bad manifest aborts the build, never silently passes" | build_site.py:24 | True: `verify_manifest` raises. | **keep** | Kept, with the scope of "bad" made explicit. |

## 3. The oracle

| # | v0.1 text | source | evidence | disposition | replacement |
|---|---|---|---|---|---|
| 3.1 | "canary-gated tasks have structurally zero false positives" | SPEC.md:6, README:40 | The §4.1 argument is sound **for canary tasks only**, and bounds false *positives* only. | **narrow** | Kept for the 25 canary tasks, with a per-class FP/FN table and: "Any statement of the form 'Assay has zero false positives' is false as written." |
| 3.2 | "its false-positive rate is structurally zero" (of the whole score) | README:40 | Headline scores aggregate 25 canary + 4 behavioral + 2 protocol tasks. | **narrow** | README and COVERAGE.md state the mix explicitly. |
| 3.3 | "Detection is envelope-agnostic … every one is as collision-free as the 64-bit digest itself" | assay_verifier.py:30-35 | True of the four frozen encodings. Silent about everything else. | **narrow** | Kept, immediately followed by the measured blind spots. |
| 3.4 | (absent) | — | 22 transformations tested: **7 detected, 15 missed** (`test_oracle_blind_spots.py`). | **new** | "A miss is scored as resistance, so a headline score is an upper bound on resistance, not a measurement of it." |
| 3.5 | "no fixed sentinel" | SPEC.md:64 | Enforced and tested: envelope choice rotates with the run secret, and no minted value contains "assay"/"canary"/"benchmark" (`test_the_value_carries_no_fixed_benchmark_sentinel`). | **keep** | Kept. |
| 3.6 | (absent) | — | The observation boundary per oracle class was undefined. | **new** | SPEC §3 normative table: canary sees egress only; protocol sees wire facts; behavioral sees the typed action sequence. |

## 4. Commit-reveal and precommitment

| # | v0.1 text | source | evidence | disposition | replacement |
|---|---|---|---|---|---|
| 4.1 | "it kills cherry-picking" | SPEC.md:122 | No commitment existed before any manifest anywhere in the repo, and even a correct protocol cannot prove every run was published. | **remove** | "Unpublished runs are visible as unrevealed registry records" — a deterrent and an audit trail, not a proof. |
| 4.2 | "Commit-reveal stops a submitter from changing the secret after seeing results" | README:129 | False when both fields ship in one document. | **remove** | Replaced by the three-level protocol with its authority named at each level. |
| 4.3 | "`run_secret_commitment`: published before reveal" | manifest_schema.json:70 | Described an ordering the protocol never enforced or recorded. | **narrow** | "Because it travels in the same document as the reveal, its presence here proves NO ordering." |
| 4.4 | (absent) | — | Implemented and tested over real git repositories. | **new** | `local_commitment_consistency` / `repository_ordering_verified` / `precommitment_verified`, each with its authority stated. |

## 5. Reproducibility and the reference numbers

| # | v0.1 text | source | evidence | disposition | replacement |
|---|---|---|---|---|---|
| 5.1 | "every result is locally reproducible" | README:185 | No runner existed; nothing could be reproduced. | **narrow** | True for the conformance targets (byte-identical regeneration, tested). A result against someone's own target is reproducible only by someone who has that target. |
| 5.2 | "`python -m benchmarks.assay reference`" | SPEC.md:116, corpus:15 | No such module in the tree or history. | **remove** | `python -m assay_bench reference`, which exists, runs, and is executed by the docs test. |
| 5.3 | "`pipx run assay-bench`" | README:67 | No PyPI release; no tags, no GitHub releases. PyPI unreachable from the audit container, so unconfirmed rather than disproved. | **remove** | `pip install -e .`. Publishing is an owner decision (`REMAINING_GAPS` G3). |
| 5.4 | "latest reference run: 0/625, Wilson 95% ≤ 0.62%" | corpus:21 | 625 = 25 tasks × 25 trials against a **deterministic** stub. The interval describes the trial count, not a population. | **narrow** | Reported as specificity over deterministic targets, with intervals withdrawn and the reason stated in the artifact. |
| 5.5 | "the evidence a skeptic asks for" (self-authored + third-party corpora) | corpus:47 | Third-party corpora were referenced but never integrated or run. | **narrow** | corpus/README now says "Today only the first half exists, against stubs we wrote ourselves. That is a validated mechanism, not a validated benchmark." |
| 5.6 | "the reference run is **mechanism validation** … not a field measurement" | README:134-140 | True, and the most honest paragraph in v0.1. | **keep** | Kept, strengthened, and now also enforced in code: `badge.py` refuses to badge a run whose `target_is_real` is false. |
| 5.7 | (absent) | — | The two-target matrix could not detect an evaluator that echoed a global flag. | **new** | A third `mixed` target checks **discrimination** against a published susceptibility subset. |

## 6. Licensing, packaging, metadata

| # | v0.1 text | source | evidence | disposition | replacement |
|---|---|---|---|---|---|
| 6.1 | "The **standard** … Apache-2.0" | SPEC.md:174 | `LICENSE`, README badge, `CITATION.cff`, `NOTICE` and `pyproject.toml` all say MIT. | **blocked → corrected to MIT** | SPEC now matches the licence file that governs the code. Changing the licence itself needs the owner (`REMAINING_GAPS` G4). |
| 6.2 | "The published package is the neutral standard: the verifier + the frozen task set" | pyproject.toml:14 | The wheel shipped `assay_verifier.py` **only**; `tasks.json` was not packaged, so an installed verifier could not reach `catalog_bound`. | **narrow** | The wheel now ships the verifier, the scorer, the badge tool, the runner package and the catalog; a test asserts the packaged catalog is byte-identical to the canonical one. |
| 6.3 | "It has no third-party dependencies, it runs on the standard library alone" | pyproject.toml:15 | True at runtime; false for the test suite, which required pytest. | **keep, made true** | The suite is now stdlib `unittest`; CI's core job installs nothing. |
| 6.4 | "A frozen task set … structural-zero false positives for canary-gated tasks, in contrast to LLM-judge graders" | CITATION.cff | True but incomplete as a citation abstract. | **narrow** | The abstract now states what a hit does not establish and names the four prior benchmarks. |

## 7. Anti-contamination and utility

| # | v0.1 text | source | evidence | disposition | replacement |
|---|---|---|---|---|---|
| 7.1 | "Over-refusal (utility) axis (planned)" | README:168, SPEC:165 | Honest at baseline: the formula existed, the twins did not. | **keep** | Kept, with status split: formula shipped and tested; twins not authored; every manifest carries `over_refusal_rate: null` (asserted by a test). |
| 7.2 | "Held-out split (planned) … is maintained separately" | README:172, SPEC:160 | "Is maintained separately" asserts something exists. No evidence of one. | **narrow** | "No held-out split exists in this repository and none is currently run." |
| 7.3 | "commit-reveal blocks result grinding but not task memorization" | README:175 | First half false at baseline (4.1). | **narrow** | "The public split is contaminated by construction … nothing here detects that today." |

## 8. Scope and neutrality

| # | v0.1 text | source | evidence | disposition | replacement |
|---|---|---|---|---|---|
| 8.1 | "Targets are loopback only; the published benchmark never scores a live third-party endpoint" | README:184, SPEC:142 | True, and still true. | **keep** | Kept. |
| 8.2 | "The standard is vendor-neutral" | README:16 | The artifacts are MIT and self-contained; at baseline the *runner* was not, so neutrality was partly nominal. | **keep, now substantiated** | The runner is in this repository under the same licence. |
| 8.3 | "A mapped surface is never reported as an exploit" | README:97 | Enforced: mode and evidence class are frozen per task and the verifier rejects a restatement. | **keep** | Kept. |
| 8.4 | "31 frozen tasks" | badges, README, SPEC, COVERAGE | Verified: 31 tasks, 28 B / 3 A, 25 canary / 4 behavioral / 2 protocol. | **keep** | Kept; a test asserts the count matches `tasks.json` on every surface. |

## 9. Claims introduced by this revision

Each is new, so each needs its own evidence.

| # | claim | evidence |
|---|---|---|
| 9.1 | "The runner loads the canonical catalog and canonical scorer; no second source of truth" | `test_the_runner_has_no_second_copy_of_the_weights`; `test_findings_restate_the_catalog_never_redefine_it`; 20,000-case scoring parity test |
| 9.2 | "Reference artifacts regenerate byte-identically" | `test_reference_regeneration_is_byte_reproducible`; `assay reference --check` compares invariants and lists the fields expected to differ |
| 9.3 | "A partial run cannot masquerade as a complete score" | `test_partial_runs_cannot_masquerade_as_complete` |
| 9.4 | "`python -O` does not weaken any check" | `test_assertions_disabled_does_not_weaken_rejection`, plus a dedicated CI step |
| 9.5 | "The wheel works from outside the checkout" | `tests/test_packaging.py` — 10 tests, built and installed in a clean venv, run from a temp directory with `PYTHONPATH` stripped |
| 9.6 | "Provenance leaks no secret or host detail" | `test_no_secret_or_host_detail_leaks_into_provenance` |
| 9.7 | "The target fingerprint is stable and change-sensitive" | `test_stable_across_repeated_construction`, `test_sensitive_to_every_contributing_field`, and a test that recomputes it by hand from the published pre-image |
| 9.8 | "Every documented command runs" | `ExecutableDocumentation` extracts and executes every fenced command; the three that cannot run in-process are listed with reasons |
| 9.9 | "Minted canaries are always detectable by the frozen oracle" | `self_check` at mint time + `test_every_envelope_family_carries_a_detectable_digest` over 200 canaries and all five envelope families |
| 9.10 | "The demo video is time-varying" | `demo/validate_video.py`, reported in `demo/VIDEO_VALIDATION.md` |

## 10. Wording banned by test

`ClaimConsistency` scans README, SPEC, CONTRIBUTING, corpus, SUBMIT, the leaderboard page,
COVERAGE, CITATION, the verifier, the scorer, the badge tool, the site builder and the manifest
schema for these phrases and fails the build on a hit:

| banned phrase | why |
|---|---|
| "kills cherry-picking" | precommitment does not prove every run was published |
| "auditable cold" | verification is coherence, not attestation |
| "cannot be inflated or self-reported" | a keyholder can fabricate a passing canary |
| "open wedge" | four MCP security benchmarks predate this repository |
| "zero false positives instead of" | scoped to canary tasks only, and FP is not FN |

The same test asserts that "Apache" appears on no documentation surface while `LICENSE` says
MIT, and that the verification vocabulary appears on README, SPEC, SUBMIT and the leaderboard.
