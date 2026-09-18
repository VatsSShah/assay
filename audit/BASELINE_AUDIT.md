# Phase 0 — Forensic baseline

Everything below was executed against the repository **before any file was modified**, in the
clean container described under *Environment*. Commands, exit codes and outputs are reproduced
as observed. Where a command could not be run, the reason is stated rather than the result
being guessed.

## 1. Repository state at audit time

| item | value |
|---|---|
| Remote | `https://github.com/VatsSShah/assay` |
| Branch audited | `claude/vibrant-allen-eem19b` (identical tree to `main`) |
| HEAD SHA | `675fae7d2d3c6ae9fb97ce3d761492dfb7e35a37` |
| Comparison to the SHA named in the audit brief | **identical** — the brief named `675fae7d…`, and HEAD was already that commit |
| Commits in history | 1 (`675fae7 Assay v0.1: canary-oracle MCP security benchmark`) |
| `git status --short` | empty (clean tree) |
| Tags | none |
| GitHub releases | none |
| Open PRs / closed PRs | 0 / 0 |
| Open issues | 1 (#1, opened 2026-08-17 by `helloparthshah`, no comments, no events) |
| Closed issues | 0 |

Because the repository had exactly one commit, there was no post-baseline history to inspect:
every file in the tree was introduced by that commit.

### Environment

| item | value |
|---|---|
| Python | 3.11.15 (CPython), Linux x86_64 |
| pip | 24.0 |
| Available third-party packages | `setuptools 68.1.2`, `wheel 0.42.0` (no `pytest`, no `build`) |
| PyPI reachability | **none** — `pip download pytest` fails with `no matching distribution`; `https://pypi.org/...` returns 503 through the egress proxy |
| arxiv.org reachability | **blocked** by the egress proxy (`EGRESS_BLOCKED`) |
| Web search | available, and used for the literature check in `ISSUE_1_TRIAGE.md` §A |

Two consequences follow, and both are recorded honestly rather than worked around:

1. **The declared test suite could not be run as shipped.** `tests/test_verifier.py` imported
   `pytest`, which is not installed and cannot be installed. This is a property of the audit
   environment, but it also exposed a design problem — see §4.
2. **Publication of `assay-bench` to PyPI could not be checked directly.** Absence of a GitHub
   release/tag is recorded as supporting evidence, and the claim is treated as unverified
   rather than as disproved. See `ISSUE_1_TRIAGE.md` §E1.

## 2. Tracked tree (31 files) and entry-point map

```
.github/PULL_REQUEST_TEMPLATE.md      NOTICE                     leaderboard/entries.json
.github/workflows/ci.yml              README.md                  leaderboard/index.md
.gitignore                            SPEC.md                    leaderboard/manifests/reference_hardened.json
CITATION.cff                          TASKS.md                   leaderboard/manifests/reference_vulnerable.json
CONTRIBUTING.md                       assay_verifier.py          leaderboard/manifests/scorecard_hardened.json
COVERAGE.md                           badge.py                   leaderboard/manifests/scorecard_vulnerable.json
LICENSE                               corpus/README.md           leaderboard/schema.json
manifest_schema.json                  coverage.py                paper/assay.tex
pyproject.toml                        reference/confusion_matrix.json
scoring.py                            tasks.json                 tests/test_verifier.py
leaderboard/SUBMIT.md                 leaderboard/build_site.py
```

**Package/entry-point map at baseline.** `pyproject.toml` declared
`py-modules = ["assay_verifier"]` only, with `assay` and `assay-bench` both pointing at
`assay_verifier:cli`. So the wheel shipped **one module**: the verifier. `scoring.py`,
`badge.py`, `coverage.py` and `leaderboard/build_site.py` were repo-only tools, and
`tasks.json` was not packaged at all — an installed `assay` had no access to the frozen
catalog.

**Searches performed before concluding a capability was absent** (per the brief's instruction
not to infer absence from a missing path): `git ls-files`, `git log --all`, `git grep` across
all history for `benchmarks`, `runner`, `harness`, `adapter`, `mint`; inspection of
`pyproject.toml` entry points, `.github/workflows/ci.yml`, `.gitignore`, and every docs file.
No runner existed under any name, in any commit, in any packaging surface.

## 3. Frozen task set as found

`tasks.json`: `benchmark=Assay`, `version=0.1`, `split=public`, `n_tasks=31`, weights
`{critical: 1.0, high: 0.7, medium: 0.4, low: 0.2}`.

| dimension | counts |
|---|---|
| Mode | B: 28, A: 3 |
| Oracle | canary: 25, behavioral: 4, protocol: 2 |
| Weights in use | 0.7 × 18, 0.4 × 8, 1.0 × 5 |
| IDs | `M1…M25`, `OBF`, `M26…M30` |

This matches the brief's baseline exactly.

## 4. Every documented executable command, and its observed result

Commands were extracted from `README.md`, `SPEC.md`, `CONTRIBUTING.md`, `corpus/README.md`,
`leaderboard/SUBMIT.md`, `.github/PULL_REQUEST_TEMPLATE.md` and `.github/workflows/ci.yml`.

| # | command | source | exit | observed |
|---|---|---|---|---|
| 1 | `python assay_verifier.py leaderboard/manifests/reference_vulnerable.json` | CONTRIBUTING, CI | 0 | `VERIFIED`, 25/25 canaries confirmed |
| 2 | `python assay_verifier.py leaderboard/manifests/reference_hardened.json` | CI | 0 | `VERIFIED`, 0/0 canaries |
| 3 | `python assay_verifier.py leaderboard/manifests/scorecard_vulnerable.json` | (untracked by docs) | 0 | `VERIFIED` — byte-identical to #1 |
| 4 | `python assay_verifier.py leaderboard/manifests/scorecard_hardened.json` | (untracked by docs) | 0 | `VERIFIED` — byte-identical to #2 |
| 5 | `python coverage.py` | CONTRIBUTING, CI | 0 | `wrote COVERAGE.md: 31 tasks` |
| 6 | `python leaderboard/build_site.py` | CONTRIBUTING, CI | 0 | `wrote index.md, 2 entries verified` |
| 7 | `git diff --exit-code` after #5 and #6 | CI | 0 | **no diff** — generated files were current |
| 8 | `python badge.py leaderboard/manifests/reference_hardened.json` | (module docstring) | 0 | shields.io endpoint, `100.0 on Assay v0.1` |
| 9 | `python -m pytest tests/ -q` | CONTRIBUTING, CI, PR template | **1** | `No module named pytest` — **cannot run in this environment** |
| 10 | `python -m unittest discover` | (diagnostic) | **0** | `Ran 0 tests ... OK` — **a green result that executed nothing** |
| 11 | `python -m unittest discover -s tests` | (diagnostic) | 1 | `Ran 1 test … FAILED (errors=1)` — the import of `pytest` fails |
| 12 | `python -m benchmarks.assay reference` | **SPEC.md:116, corpus/README.md:15** | — | **no such module anywhere in the tree or history** |
| 13 | `pipx run assay-bench <scorecard>` | README:67 | — | not executable here; no PyPI reachability at baseline, and no GitHub release/tag exists. **Later checked** (2026-09-18, from an environment that does reach PyPI): `assay-bench` returns 404 — unregistered — so the command could never have worked. The line was removed, not deferred. `assay` returns 200 and is an unrelated project by another author. See `REMAINING_GAPS.md` G3. |

Items **9, 10, 12 and 13** are the executable defects found at baseline. Item 10 is the
diagnostic trap the brief anticipated: run from the repository root, `unittest` discovery
starts in the current directory, finds no tests, and reports success. Anyone treating that as
evidence of test coverage would be reading a false green.

### Package build and clean-venv install at baseline

| step | result |
|---|---|
| `setuptools.build_meta.build_wheel` with system setuptools | **fails**: `AttributeError: install_layout` (distro-patched setuptools 68.1.2) |
| same, inside a fresh `python -m venv` (upstream setuptools 79.0.1 from ensurepip) | succeeds |
| wheel contents | `assay_verifier.py` only — **no `tasks.json`, no scoring module** |
| clean-venv install + `assay --help` | runs, prints the verifier's usage string |

So at baseline an installed wheel could verify a manifest's internal arithmetic but could not
check any finding against the frozen catalog, because the catalog was not shipped.

## 5. Verifier behaviour at baseline: an adversarial probe matrix

Each probe constructs a manifest, restates the scores so they match the (mutated) findings,
recomputes the integrity hash, and submits it. "ACCEPTED" means `verify_manifest` returned
`verdict: VERIFIED`.

| # | probe | baseline result |
|---|---|---|
| A | **Keyholder fabricates a manifest with no run and no target**: compute `HMAC(secret, preimage)`, paste it into an invented `observed`, ship 2 of 31 tasks, state a score of 83.3 | **ACCEPTED** |
| B | **Omission**: drop every fired finding, keep one clean task. Score goes 0.0 → 100.0 | **ACCEPTED** |
| C | **Duplicate task IDs**: append a copy of `M1` | **ACCEPTED** (counted twice: 26 canary findings) |
| D | **Unknown task ID + altered weight**: rename `M1` to `NOT-A-TASK`, set weight 0.01 | **ACCEPTED** |
| E | **Mode flip**: move a task from the Mode-B denominator to Mode-A | **ACCEPTED** |
| F | **Unknown benchmark version**: declare `version: 99.0` | **ACCEPTED** |
| G | **NaN ASR** | rejected, but with the wrong message (`a fired canary cannot have asr 0` — because `nan > 0` is false) |
| H | **ASR = −5.0** | rejected, same misleading message |
| I | **Canary proof attached to a `behavioral` task** | **ACCEPTED** (the extra proof is ignored) |
| J | **Non-hex `run_secret_reveal`** | rejected with an unhandled `ValueError` traceback, exit 1 |
| K | **Missing required field (`track`)** | rejected with an unhandled `KeyError` traceback |
| L | **`python -O` against a tampered manifest** | **ACCEPTED, exit 0** |

**Probe L is the most serious finding of the baseline.** `assay_verifier.verify_manifest`
performed every check with `assert`. Python's `-O` flag removes assertions, so under `-O` the
verifier accepted a manifest whose canary did not recompute and exited 0. The same applied to
`scoring.py`, which used `assert` for all of its input validation.

Probes A and B are the two limits Issue #1 §2 alleges; both reproduce exactly. Probes C–F and I
are additional gaps the issue did not raise.

## 6. Reference artifacts as found

| artifact | observation |
|---|---|
| `leaderboard/manifests/reference_vulnerable.json` | 31 findings, all fired, agent 0.0 / server 0.0 |
| `leaderboard/manifests/reference_hardened.json` | 31 findings, none fired, agent 100.0 / server 100.0 |
| `scorecard_vulnerable.json` / `scorecard_hardened.json` | **byte-identical duplicates** of the two above (same SHA-256), referenced by nothing |
| run secret | **the same `run_secret_reveal` and commitment in all four files** — two supposedly separate runs shared one secret |
| `generated_at` | identical timestamp across all four |
| `reference/confusion_matrix.json` | 31 rows, **every row identical**: `asr 1.0`, `25/25 hits`, `fp 0.0`, `0/25`, with Wilson intervals on every cell |
| vocabulary drift | the matrix says `oracle: "cryptographic"` and `mode: "agent"/"server"`, while `tasks.json` says `oracle: "canary"` and `mode: "B"/"A"` |
| generator | **none** — no code in the tree could produce any of these files |
| `entries.json` | both entries declared `track: "agent"`, so the Mode-A leaderboard table rendered empty despite both manifests carrying Mode-A findings and a `server_posture_score` |

The uniform confusion matrix is consistent with a deterministic stub, as the brief and Issue #1
both suspected: a Wilson interval over 25 identical outcomes describes the trial count, not a
population.

## 7. Claims requiring evidence (inventory)

Collected verbatim at baseline; each is carried into `CLAIM_EVIDENCE_MATRIX.md` with a
disposition.

| # | claim | source |
|---|---|---|
| 1 | "Assay is to MCP security what HarmBench and StrongREJECT are to jailbreak evaluation" | SPEC.md:3 |
| 2 | "**The open wedge.** Every MCP taxonomy is a list, not a benchmark" | SPEC.md:34 |
| 3 | "first cryptographic, recomputable, structural-zero-FP exfiltration proof at the MCP tool boundary" | SPEC.md:40 |
| 4 | "a leaderboard claim is auditable cold" | SPEC.md:129 |
| 5 | "it kills cherry-picking" | SPEC.md:122 |
| 6 | "a score cannot be inflated or self-reported" | SUBMIT.md:3, build_site.py:5 |
| 7 | "canary-gated tasks have **structurally zero false positives**" | SPEC.md:6, README:40 |
| 8 | "every result is locally reproducible" | README:185 |
| 9 | "`python -m benchmarks.assay reference` runs all 31 tasks" | SPEC.md:116, corpus/README.md:15 |
| 10 | "`pipx run assay-bench`" | README:67 |
| 11 | "The **standard** … Apache-2.0" | SPEC.md:174 (contradicts `LICENSE`, README badge, `CITATION.cff`, `NOTICE`, all MIT) |
| 12 | "latest reference run: **0/625**, Wilson 95% ≤ 0.62%" | corpus/README.md:21 |
| 13 | "FP = 0 … proves the two claims that make Assay a benchmark and not a demo" | corpus/README.md:16 |
| 14 | "Over-refusal axis (planned)" / "Held-out split (planned)" | README:168–176, SPEC.md:156–169 |
| 15 | "Detection is envelope-agnostic … as collision-free as the 64-bit digest itself" | assay_verifier.py:30–35 |

## 8. Baseline verdict

The repository as audited was **internally coherent and externally overstated**. The
verifier, scorer, task set and generated documents were consistent with each other, and the
four documented verification commands all passed. What did not hold up was everything that
required an artifact outside the document: there was no runner, no packaged catalog, no
commitment ordering, no attestation, no generator for the reference artifacts, no runnable
test suite in a dependency-free environment, and no defence against a submitter who holds the
run secret — while the prose claimed auditability, reproducibility, and priority.

Nothing in this file was edited after the fact to match the repairs that follow. The probe
matrix in §5 was re-run against the repaired verifier and the results are recorded in
`ISSUE_1_TRIAGE.md`.
