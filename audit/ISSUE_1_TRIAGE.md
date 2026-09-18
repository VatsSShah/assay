# Triage of GitHub Issue #1, assertion by assertion

Issue: *"The 'first MCP security benchmark' positioning is false — four uncited prior benchmarks
exist — and the cryptographic verifiability claims fail under your own threat model"*, opened
2026-08-17 by `helloparthshah`, no comments, still open.

Issue #1 is a single document making roughly twenty independently testable assertions. Each is
triaged separately below against the code at `675fae7d…` and, where repaired, against the code
on this branch. Classification is from executed evidence or a primary source, never from the
issue's wording.

**Headline result: 16 of 20 assertions are `reproducible_open`, 2 are `partially_fixed`, 1 is
`not_reproducible` as literally stated, and 1 is `blocked_needs_decision`.** The issue is
substantially correct. The audit additionally found six defects the issue did not raise,
listed in §F, including one (`python -O`) more severe than anything the issue reported.

Legend for **Now**: ✅ fixed on this branch · ◐ partly addressed, residue documented ·
⛔ deliberately not fixed (it is a real limit, now stated as one) · ⏸ blocked on an owner decision.

---

## A. Novelty and related work

### A1 — "Every MCP taxonomy is a list, not a benchmark" / "the open wedge"

**Classification: `reproducible_open`. Severity: high (scholarly). Now: ✅ withdrawn.**

The claim appeared verbatim at `SPEC.md:34`. It is false. Four MCP-specific security benchmarks
were published before this repository, verified from their published records:

| work | arXiv | first published | execution model | artifacts |
|---|---|---|---|---|
| MCPSecBench | 2508.13220 | 17 Aug 2025 | real MCP clients/servers + GUI harness; Claude, OpenAI, Cursor hosts; 17 attack types over 4 surfaces | code at `AIS2Lab/MCPSecBench` |
| MCPTox | 2508.14925 (AAAI-40) | Aug 2025 | **45 live real-world MCP servers**, 353 tools, 1312 cases, 20 agent settings | benchmark released |
| MSB (MCP Security Bench) | 2510.15994 | 14 Oct 2025 | **real tools executed over MCP, explicitly not simulation**; 405 tools, 2,000 instances | code released |
| MCP-SafetyBench | 2512.15163 (ICLR 2026) | Dec 2025 | real MCP servers, multi-turn, 5 domains, 20 attack types | code at `xjzzzzzzzz/MCPSafety` |

All four predate this repository (`CITATION.cff` gave `date-released: 2026-06-10`).

*Method note:* `arxiv.org` is blocked by this container's egress proxy, so the records were
retrieved via web search rather than by fetching the papers, and the linked repositories were
not cloned (this session's GitHub access is scoped to `VatsSShah/assay`). Titles, identifiers,
dates, scale figures and artifact URLs are therefore secondary-source-confirmed and are cited
as such in `SPEC.md` §1. Nothing here claims Assay reproduced any of their numbers.

**Action taken:** SPEC.md §1 replaced with a comparison table and an explicit withdrawal.
`tests/…::ClaimConsistency` fails the build if "open wedge" reappears on any surface.

### A2 — "Assay is to MCP security what HarmBench and StrongREJECT are to jailbreak evaluation"

**Classification: `reproducible_open`. Severity: medium. Now: ✅ removed.**

The analogy was at `SPEC.md:3`. HarmBench and StrongREJECT ship runnable harnesses and publish
measurements of named models; at baseline Assay had **no runner at all** (§D1) and had measured
nothing but its own stubs. Removed rather than softened.

### A3 — "first cryptographic, recomputable, structural-zero-FP exfiltration proof at the MCP tool boundary"

**Classification: `reproducible_open`. Severity: medium. Now: ✅ withdrawn.**

The issue calls this "novelty by qualifier-stacking", and the characterisation holds:

- *deterministic oracle* — AgentDojo (arXiv:2406.13352, NeurIPS 2024) established judge-free
  deterministic scoring for agent prompt injection;
- *cryptographic canary* — keyed canary/honeytoken exfiltration detection is long-standing
  practice, including HMAC-keyed per-placement tokens used to attribute agent scraping. The
  primitive is inherited;
- *not simulation* — MSB and MCPTox execute against real tools and real servers. Assay executes
  only against its own in-process stubs, which is strictly less real.

**Action taken:** every "first" removed. SPEC.md §1 now states three checkable contributions
(a recomputable result format, levelled verification with a written trust boundary, a frozen
weighted crosswalked task set) with no priority claim, and says plainly that the positioning is
"a result format and verifier for MCP security evidence, with a task set attached".

### A4 — "The omission is hard to read as accidental"

**Classification: `not_reproducible` (as a factual claim about intent).**

This is an inference about motive, not a testable property of the artifact. The audit can
confirm the omission (A1) and cannot adjudicate why. Recorded, not actioned; the remedy the
issue asks for — a real related-work section — was implemented regardless.

---

## B. What the verifier proves

### B1 — A keyholder can fabricate a passing manifest with no run

**Classification: `reproducible_open`. Severity: critical. Now: ⛔ irreducible; stated everywhere.**

Reproduced at baseline. Compute `HMAC(run_secret, "origin|tool|step")[:16]`, paste it into an
invented `observed`, seal the document: baseline `verify_manifest` returned
`verdict: "VERIFIED"` for a manifest whose `target.kind` was literally `"never-ran"`.

This cannot be fixed by any check on the document — `observed` is submitter-supplied text and
the submitter holds the key. What changed:

- the verifier no longer emits a single word. It reports **levels**, and a fabrication of two
  tasks now stops at `catalog_bound`, failing `run_complete` with
  `"29 task(s) in the frozen catalog are not reported"`;
- a fabrication covering all 31 tasks still reaches every level, and that is asserted as a
  **passing test**: `tests/test_trust_boundary.py::test_a_full_catalog_fabrication_also_reaches_run_complete`;
- the limit is stated in the verifier docstring, README's first table, SPEC §4.2, SUBMIT.md and
  the leaderboard page, all using the same vocabulary.

The issue's proposed fix ("rewrite the docstring … to state precisely what verification proves")
was adopted in full.

### B2 — Findings can be omitted, and omission improves the score

**Classification: `reproducible_open`. Severity: critical. Now: ◐ half fixed.**

Reproduced: dropping every fired finding from `reference_vulnerable.json` took the agent score
from **0.0 to 100.0** while the manifest stayed internally consistent, because the score is
recomputed from whatever findings are present.

**Fixed half:** a partial run can no longer masquerade as a complete benchmark score. The
verifier counts reported findings against the frozen catalog and withholds `run_complete`, and a
submitter's own `scope.completion: "complete"` cannot override that count
(`test_partial_runs_cannot_masquerade_as_complete`).

**Unfixed half:** a submitter who never ran an attack and reports it as `fired: false` is
indistinguishable from one who ran it and was resisted. No document check can separate those.
Documented in SPEC §4.2 and pinned by
`test_dropping_findings_raises_the_score_and_stays_internally_consistent`.

### B3 — "a leaderboard claim is auditable cold" / "a score cannot be inflated or self-reported"

**Classification: `reproducible_open`. Severity: high. Now: ✅ both withdrawn.**

Both were false as stated, for the reasons in B1/B2. "Auditable cold" was at
`assay_verifier.py:8` and `SPEC.md:129`; "cannot be inflated or self-reported" at
`SUBMIT.md:3` and `leaderboard/build_site.py:5`. Replaced with the precise property: *the build
recomputes each score from its findings, so a stated number cannot disagree with the findings it
summarises* — which is true, and is not the same claim. `ClaimConsistency` now fails the build
if either phrase returns.

### B4 — Additional tampering the issue did not test

All probed at baseline and after. Full matrix in `BASELINE_AUDIT.md` §5.

| attack | baseline | now |
|---|---|---|
| duplicate task IDs | **accepted** (counted twice) | ✅ rejected: `duplicate finding for task id 'M1'` |
| unknown task ID | **accepted** | ✅ rejected: `not a task in the frozen catalog` |
| altered severity weight | **accepted** | ✅ rejected: `severity weights are frozen` |
| mode flip B→A (moves a task between denominators) | **accepted** | ✅ rejected: `the frozen catalog says 'B'` |
| unsupported benchmark version (`99.0`) | **accepted** | ✅ rejected with an explanation of why no result is comparable |
| canary proof grafted onto a `behavioral` task | **accepted**, ignored | ✅ rejected: `must not carry a canary proof` |
| unfired canary shipping a proof | accepted | ✅ rejected |
| unknown top-level field | accepted | ✅ rejected (`additionalProperties:false` now enforced in code) |
| NaN / ±inf / out-of-range ASR | rejected, **wrong message** | ✅ rejected with the correct message |
| malformed hex secret | raw `ValueError` traceback | ✅ typed error, exit 1 |
| missing required field | raw `KeyError` traceback | ✅ typed error, exit 3 |
| relabelled evidence_type | rejected | ✅ still rejected |
| tampered `observed` | rejected | ✅ still rejected |

### B5 — Verification-level vocabulary

**Classification: `reproducible_open` (the issue asked for precision; none existed). Now: ✅.**

Implemented: `format_valid`, `internally_consistent`, `canary_correspondence_verified`,
`catalog_bound`, `run_complete`, plus `precommitment_verified`, `independently_rerun` and
`maintainer_attested` which the verifier reports as structurally out of its scope. `assay levels`
prints the vocabulary. The same words are used in the CLI output, schema descriptions, README,
SPEC, SUBMIT, CONTRIBUTING, the leaderboard page and the badge suffix; a test asserts the
vocabulary appears on each surface.

---

## C. Commitment timing

### C1 — Commit-reveal in one document proves no ordering

**Classification: `reproducible_open`. Severity: high. Now: ✅ protocol implemented.**

Confirmed by inspection and by search: no commitment existed anywhere before the manifest — not
in an earlier commit (there was only one commit), not in a tag, a release, an issue, a registry
file, or CI. `run_secret_commitment` and `run_secret_reveal` were adjacent fields in the same
JSON, and both reference manifests shared **the same secret**, which is itself incompatible with
"a per-run secret minted before each run".

**Implemented** (`assay_bench/precommit.py`, `precommit/README.md`): a registry record created
before the run, binding commitment, benchmark version, task-set digest, target fingerprint,
trial plan, run id and nonce, sealed by a `record_digest`. Verification names its authority at
each level: `local_commitment_consistency` (arithmetic, offline, **no ordering**),
`repository_ordering_verified` (git ancestry + committer date, forgeable by whoever owns the
history), `precommitment_verified` (a forge witness, which only CI can supply). Timestamps
inside the record are never consulted.

`tests/test_precommit.py` builds throwaway git repositories rather than mocking, covering: valid
earlier commitment; **same-commit** commitment and reveal (the v0.1 situation — reported as
carrying no evidence); late commitment; clock inversion with ancestry intact; uncommitted
record; squash rewrite; missing record; wrong target; wrong trial plan; commitment reuse;
idempotent rebinding; duplicate registrations.

### C2 — "it kills cherry-picking"

**Classification: `reproducible_open`. Severity: medium. Now: ✅ withdrawn, not merely weakened.**

Even with the protocol above, a submitter may register N commitments, run N times and reveal
one. All N records remain visible and `assay precommit-list` flags unrevealed ones — a deterrent
and an audit trail, not a proof. The permitted wording is now *"unpublished runs are visible as
unrevealed registry records"*. `ClaimConsistency` fails the build if "kills cherry-picking"
returns.

---

## D. Runnable harness

### D1 — `python -m benchmarks.assay reference` does not exist

**Classification: `reproducible_open`. Severity: critical. Now: ✅ a real runner ships.**

Confirmed absent from the tree, from `pyproject.toml`, from CI, and from all of history. Two
documents instructed readers to run it (`SPEC.md:116`, `corpus/README.md:15`).

**Implemented:** `assay_bench/`, invoked as `python -m assay_bench` or the installed `assay`.
It has the pieces the brief enumerates: typed catalog loader with strict validation
(`catalog.py`), canary minting with a per-run secret lifecycle and five rotating envelope
families (`canary.py`), an adapter interface declaring capabilities including `is_real_target`
(`adapters/__init__.py`), deterministic conformance targets (`adapters/conformance.py`), typed
per-class oracle evaluators with a normative observation boundary (`oracles.py`), a trial loop
with reset, timeout, error and interrupted-run handling (`runner.py`), provenance with a
precisely specified target fingerprint (`provenance.py`), manifest generation and integrity
hashing (`manifest.py`), and reference regeneration (`cli.py`).

The runner loads the **canonical** `tasks.json` and the **canonical** `scoring.py`; a test
asserts no weight literal appears in `runner.py`, and 20,000 randomised cases assert the
verifier's inlined formula matches the canonical scorer exactly.

The docs now name the command that exists. The old one is gone, and a test imports every
`python -m …` module mentioned in any doc.

### D2 — "every result is locally reproducible"

**Classification: `partially_fixed`.** True now for the conformance targets, which anyone can
regenerate byte-for-byte from a clean clone. It was never true in general and is not now: a
result against someone's own target is reproducible only by someone who has that target. README
and SPEC §8 say exactly that.

### D3 — "the closed Verosek reference implementation"

**Classification: `partially_fixed`.** The harness is now open and in this repository, so the
trust chain no longer routes through closed tooling for the conformance path. What remains true
is that **no real MCP adapter exists** — see `REMAINING_GAPS.md` G1. `corpus/README.md` now has
a section headed "Real MCP targets (NOT shipped)" instead of implying they were integrated.

---

## E. Narrower assertions

### E1 — `pipx run assay-bench` presumes a PyPI release that does not exist

**Classification: `reproducible_open`. Severity: low. Now: ✅ command replaced.**

Could not be checked directly: PyPI is unreachable from this container (503 through the egress
proxy; `pip download` finds no distributions). Supporting evidence that no release exists: the
repository has **no tags and no GitHub releases**, and `pyproject.toml` was never at a published
version. Per the brief's instruction not to claim a publication succeeded without checking the
public index, **no package was published and none is claimed**. The README now documents
`pip install -e .`, which works and is tested. Publishing is listed in `REMAINING_GAPS.md` as an
owner decision.

### E2 — Headline scores mix oracle classes under an FP=0 banner

**Classification: `reproducible_open`. Severity: medium. Now: ✅ scoped.**

Confirmed: both scores are weighted over all tasks of a mode — 25 canary, 4 behavioral, 2
protocol — while adjacent prose said "structurally zero false positives". SPEC §3 now carries a
per-class table with separate FP and FN columns and states: *"Any statement of the form 'Assay
has zero false positives' is false as written."* README and COVERAGE.md say the same.

### E3 — Substring matching trades judge false positives for unmeasured false negatives

**Classification: `reproducible_open`. Severity: medium. Now: ✅ measured and published.**

`tests/test_oracle_blind_spots.py` enumerates 22 egress transformations: **7 detected, 15
missed**. Misses include splitting across two requests, truncation, base32/base85/rot13,
uppercase, gzip+base64, XOR, SHA-256, full-width homoglyphs, zero-width joiners, and prose
paraphrase.

Deliberately **not** fixed: widening the encoding set changes the oracle and is a MAJOR bump
(SPEC §9), and the issue's own reasoning rules out an LLM judge, which would forfeit the
determinism. Instead the consequence is stated: a miss scores as resistance, so **a headline
score is an upper bound on resistance, not a measurement of it.**

### E4 — The confusion matrix reports Wilson intervals on deterministic stubs

**Classification: `reproducible_open`. Severity: medium. Now: ✅ reframed and regenerated.**

Confirmed: all 31 rows of `reference/confusion_matrix.json` were byte-identical — `asr 1.0`,
25/25 hits, `fp 0.0`, 0/25 — with Wilson intervals on every cell, and no generator existed to
produce the file. It also used a third vocabulary (`oracle: "cryptographic"`, `mode: "agent"`)
matching neither `tasks.json` nor the manifests.

Replaced by `reference/conformance_matrix.json`, generated by
`python -m assay_bench reference`, which:

- is named for what it is (mechanism conformance, not a confusion matrix over a population);
- carries a `what_this_is` field stating it is not a measurement of any real system;
- carries `why_there_are_no_confidence_intervals` and **omits the intervals**;
- adds a third target, `mixed`, susceptible on a published subset, so **discrimination** is
  checked — the property that distinguishes a real per-task evaluator from one echoing a global
  flag. The old two-target matrix could not have detected that failure.

The old file is preserved at `tests/fixtures/legacy_v0_1/confusion_matrix.json` as evidence.

### E5 — SPEC says Apache-2.0 while LICENSE says MIT

**Classification: `reproducible_open` → `blocked_needs_decision`. Severity: medium. Now: ⏸ documented.**

Confirmed at `SPEC.md:174`. Every other surface said MIT: `LICENSE`, the README badge,
`CITATION.cff`, `NOTICE`, and `pyproject.toml` (`license = { file = "LICENSE" }`).

**Action taken:** the single outlier in SPEC.md was corrected to MIT, so the documentation now
matches the licence file that actually governs the code. **This does not change the licence** —
it removes a contradiction in favour of the one authoritative artifact. If the owner intended
Apache-2.0 for the specification, that is a deliberate change to `LICENSE` plus every other
surface, and it needs the owner. Recorded in `REMAINING_GAPS.md` G4.

### E6 — "What survives is execution quality more than contribution"

**Classification: opinion; recorded, not classified.** The audit's own position is in SPEC §1:
three checkable contributions, no priority claim, and an explicit statement that this is smaller
than "a benchmark".

---

## F. Defects the audit found that Issue #1 did not raise

| # | defect | severity | status |
|---|---|---|---|
| F1 | **`python -O` disabled every check.** All validation used `assert`; under `-O` a tampered manifest verified and exited **0** | **critical** | ✅ every `assert` replaced with explicit exceptions in `assay_verifier.py` and `scoring.py`; a test runs the CLI under `-O` against a tampered manifest and requires exit 1 |
| F2 | **Float drift between the two scorers.** `scoring._resistance` computed `(w*hits)/trials` while the verifier computed `w*(hits/trials)`, differing by 0.1 on real inputs — within the tolerance, so it would have surfaced as an unexplained mismatch, not a clean failure | medium | ✅ ordering pinned; 20,000-case parity test |
| F3 | **`scorecard_*.json` were byte-identical duplicates** of the reference manifests, referenced by nothing | low | ✅ removed |
| F4 | **Both reference manifests shared one run secret and one timestamp**, contradicting "a per-run secret minted per run" | medium | ✅ regenerated by the runner; the fixed reference secret is now published and explained as a conformance-fixture choice |
| F5 | **`unittest discover` reported `Ran 0 tests … OK`** — a green result that executed nothing, while the real suite needed an uninstallable dependency | medium | ✅ suite converted to stdlib `unittest`; CONTRIBUTING documents the trap; CI runs `-s tests -t .` |
| F6 | **The Mode-A leaderboard table was always empty** — both entries declared `track: "agent"` although both manifests carried Mode-A findings and a `server_posture_score` | low | ✅ Mode-A entries added; conformance and measurement rows tabled separately |

---

## G. Proposed response to Issue #1

Drafted in `audit/ISSUE_1_RESPONSE.md`. **Not posted, and the issue is not closed.** Two of its
threads — scholarly priority and licensing intent — are the owner's to settle, and the response
concedes the substance of the issue on the record.
