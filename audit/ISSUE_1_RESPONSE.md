# Proposed response to Issue #1 — DRAFT, NOT POSTED

> **Do not post this without owner review.** Two of the threads — scholarly priority and
> licensing intent — are the owner's to settle, and the draft concedes the substance of the issue
> on the record. The issue should also not be closed automatically; several items are documented
> limits rather than fixes, and the reporter may reasonably want to see them stay open.

---

Thank you for this. It is a careful, specific read, and most of it is correct. We have treated it
as an audit brief rather than a comment thread: every assertion was reproduced or disproved
against the code, and the evidence is in [`audit/ISSUE_1_TRIAGE.md`](audit/ISSUE_1_TRIAGE.md),
one row per testable claim.

Summary: **16 of your 20 independently testable assertions reproduced, 2 were partly right, 1 was
not reproducible as literally stated, and 1 is blocked on a decision only the repository owner can
make.** The audit also found six defects you did not raise, one of which is worse than anything in
your list.

## 1. Novelty and related work — you are right, and the framing is withdrawn

MCPSecBench (arXiv:2508.13220, Aug 2025), MCPTox (arXiv:2508.14925, Aug 2025, AAAI-40), MSB
(arXiv:2510.15994, Oct 2025) and MCP-SafetyBench (arXiv:2512.15163, Dec 2025, ICLR 2026) all
predate this repository and all released artifacts. MCPTox runs against 45 live real-world MCP
servers; MSB executes real tools over MCP rather than simulating them.

Withdrawn: the HarmBench/StrongREJECT analogy, "the open wedge", and every "first" — including the
qualifier-stacked one. Your characterisation of that construction was accurate; each modifier did
exist to exclude one piece of prior art, and the conjunction's only distinctive element was the
third-party verifiability that items 2 and 3 showed it did not deliver.

[`SPEC.md`](SPEC.md) §1 is now a related-work section with dates, execution models and artifact
locations, and it states plainly that on execution realism Assay is **behind** those suites,
since it ships only deterministic in-process targets. The paper was revised to match.

One caveat we would rather disclose than paper over: arxiv.org is blocked from the environment the
audit ran in, so the four works were confirmed from their published records rather than by reading
the papers, and their repositories were not cloned. That is enough to establish that the wedge
framing was false; it is not enough for the task-by-task mechanism comparison you asked for. That
remains open as G11 in [`REMAINING_GAPS.md`](REMAINING_GAPS.md).

We do not accept one part of §1: the inference about intent. We can confirm the omission; we
cannot adjudicate why it happened, and neither can the artifact. The remedy you asked for was
implemented regardless.

## 2. What the verifier proves — reproduced, and it is worse in one direction than you wrote

Both directions reproduce. We built a manifest whose `target.kind` was literally `"never-ran"`,
with a digest computed and pasted into an invented `observed`, and the v0.1 verifier returned
`verdict: "VERIFIED"`.

Your sharper point — that the docstring admitted under-reporting but not fabrication — was the
right diagnosis. The fix is the one you proposed, applied to every surface rather than the
docstring alone. The verifier no longer emits a verdict; it reports levels
(`format_valid`, `internally_consistent`, `canary_correspondence_verified`, `catalog_bound`,
`run_complete`) and names `precommitment_verified`, `independently_rerun` and
`maintainer_attested` as structurally out of its scope.

"Auditable cold" and "a score cannot be inflated or self-reported" are withdrawn. The replacement
is the narrower true statement: *a stated number cannot disagree with the findings it summarises.*

The limits are now **passing tests** in `tests/test_trust_boundary.py` — every test there asserts
that an attack succeeds — so no future change can quietly reclaim a guarantee without one failing.
One half of the omission problem is now closed: a partial run cannot present itself as a complete
benchmark score, because the verifier counts findings against the frozen catalog and a submitter's
own `completion` claim cannot override it. The other half is irreducible and is documented as such.

While testing this we found seven further manifests the v0.1 verifier accepted that it should not
have: duplicate task ids, unknown task ids, altered severity weights, mode flips between score
denominators, unsupported benchmark versions, canary proofs grafted onto behavioral tasks, and
unknown top-level fields. All are rejected now.

## 3. Commitment timing — reproduced; a protocol is implemented, and the claim is still withdrawn

Confirmed: no commitment existed anywhere before any manifest — not in an earlier commit, a tag, a
release, an issue, a registry, or CI. Both reference manifests also shared a single run secret,
which is by itself incompatible with "a per-run secret minted before each run".

Implemented roughly as you suggested, with the authority named at each level:
`local_commitment_consistency` (arithmetic, offline, no ordering — this is all v0.1 had);
`repository_ordering_verified` (the registry record's introducing commit is a strict ancestor of
the manifest's, forgeable by whoever owns the history); `precommitment_verified` (witnessed by the
forge's push record, which only CI can supply). Timestamps inside a submitter-written record are
never consulted. `tests/test_precommit.py` builds real throwaway git repositories and covers
same-commit, late, inverted-clock, uncommitted, rewritten, reused and duplicate cases.

**"Kills cherry-picking" is withdrawn anyway.** Even the top level shows one commitment predated
one result; a submitter may register N and reveal one. All N stay visible and unrevealed records
are flagged — a deterrent and an audit trail, not a proof. The phrase is now banned by a test.

## 4. Runnable harness — the harness is open and in the repository

`python -m assay_bench` mints canaries, stands up the adversarial surface, drives a target through
an adapter interface, evaluates all three oracle classes, repeats trials, scores, and emits a
schema-valid manifest. The reference artifacts are generated by it, byte-reproducibly.

Two honest qualifications:

1. **There is still no real MCP adapter.** Nothing here has been scored against a real server,
   agent or model. The seam exists, declares an `is_real_target` capability, and is surfaced in
   provenance, in the verifier's output, in the leaderboard and by `badge.py` (which refuses to
   badge a stub run). What plugs into it is not written. `corpus/README.md` now has a section
   headed "Real MCP targets (NOT shipped)" instead of implying integration.
2. **`pipx run assay-bench` was removed, not fixed.** PyPI is unreachable from the audit
   environment, and the repository has no tags or releases, so we could not confirm publication
   and did not claim it. The README documents `pip install -e .`, which works and is tested.
   Publishing is an owner decision (G3).

You were also right about the third-party corpora: they were referenced but never integrated or
run, and that section now says so.

## 5. The narrower items

- **Mixed oracle classes under an FP=0 banner** — reproduced. SPEC §3 now carries a per-class
  table with separate FP and FN columns and states: *"Any statement of the form 'Assay has zero
  false positives' is false as written."*
- **Unmeasured false negatives** — reproduced, and now measured rather than argued:
  `tests/test_oracle_blind_spots.py` tests 22 egress transformations, **7 detected, 15 missed**,
  including split, truncated, base32/base85/rot13, gzip, XOR, hashed, homoglyph and paraphrased
  exfiltration. Deliberately not "fixed": widening the encoding set redefines the oracle (a MAJOR
  bump), and — as your own reasoning implies — an LLM judge would forfeit the determinism. The
  consequence is stated instead: **a miss scores as resistance, so a headline score is an upper
  bound on resistance, not a measurement of it.**
- **Wilson intervals on deterministic stubs** — reproduced. All 31 rows were byte-identical, and
  no generator existed. Replaced by `reference/conformance_matrix.json`, which reports recall,
  specificity and **discrimination**, omits the intervals, and carries a field explaining why. The
  `0/625, Wilson ≤0.62%` framing is withdrawn; it was 25 identical trials against a stub we wrote.
  The discrimination row is new and addresses something none of us raised: with only a compliant
  and a refusing target, a harness that merely echoed a global flag would have looked identical.
- **MIT vs Apache** — reproduced. SPEC was the lone outlier against `LICENSE`, the README badge,
  `CITATION.cff`, `NOTICE` and `pyproject.toml`, and was corrected to MIT so the docs match the
  file that governs the code. That is not a licence change; if Apache-2.0 was intended for the
  spec, only the owner can make that call (G4). A test now fails the build if the contradiction
  returns in either direction.

## 6. Things you did not raise

Worth recording, since one is more severe than anything in the issue:

- **`python -O` disabled every check.** All validation used `assert`, which `-O` removes, so a
  tampered manifest verified and exited **0**. Every assertion is now an explicit typed exception,
  and both a test and a CI step run the verifier under `-O` and require exit 1.
- **Float drift between the two scoring implementations**, differing by 0.1 on real inputs —
  inside the tolerance, so it would have surfaced as an unexplained mismatch rather than a clean
  failure. Now pinned by a 20,000-case parity test.
- `scorecard_*.json` were byte-identical duplicates referenced by nothing; both reference
  manifests shared one run secret and one timestamp; `unittest discover` reported
  `Ran 0 tests … OK` while the real suite needed an uninstallable dependency; and the Mode-A
  leaderboard table was always empty.

## 7. On your closing assessment

You wrote that what survives is "execution quality more than contribution", and suggested the
HMAC-canary mechanism might be a paper section or a PR into an existing benchmark. We do not think
that is unfair, and the repositioning reflects it. `SPEC.md` §1 now claims three things, with no
priority attached: a recomputable result format, levelled verification with a written and tested
trust boundary, and a frozen weighted crosswalked task set. It says explicitly that this is
smaller than "a benchmark".

The suite is 503 tests, all standard library. The claims are enforced: five withdrawn phrases are
banned by a test across thirteen surfaces, and every fenced command in the documentation is
executed by another.

Your last line — *"no reader should treat an Assay score as evidence about any system, and the
documentation actively suggests otherwise"* — was correct about the documentation. We have tried
to make the first half true by construction and the second half false. We would welcome your read
on whether it landed.

We are leaving this issue open rather than closing it on our own say-so.
