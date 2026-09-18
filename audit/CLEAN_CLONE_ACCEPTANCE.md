# Clean-clone acceptance

Every gate below was executed against a **fresh clone**, not the working tree. Commands, exit
codes and counts are as observed. Where a gate cannot pass, it says so and points at the
corresponding entry in [`REMAINING_GAPS.md`](../REMAINING_GAPS.md) rather than being weakened.

Run against commit `9871a18`. Reproduce with:

```bash
git clone https://github.com/VatsSShah/assay /tmp/assay && cd /tmp/assay
python -m unittest discover -s tests -t .
```

## Environment

| item | value |
|---|---|
| Python | 3.11.15 (CPython), Linux x86_64 |
| Third-party packages installed | **none** for the core suite |
| Network | not used by the core suite. PyPI IS reachable from this container and was queried (see G3); arxiv.org and every paper mirror remain blocked (see G11) |
| Clone | `git clone --no-hardlinks` of this repository into a temporary directory |

The core suite deliberately installs nothing. Building a wheel needs `setuptools>=77`, which a
`python -m venv` supplies from `ensurepip` with no network.

---

## Gate results

| # | Gate | Result |
|---|---|---|
| 1 | Baseline and issue triage exist with evidence for every assertion in Issue #1 | **pass** — `audit/BASELINE_AUDIT.md`, `audit/ISSUE_1_TRIAGE.md` (20 assertions, one row each) |
| 2 | Every open issue classified against current code | **pass** — one open issue (#1); 16 `reproducible_open`, 2 `partially_fixed`, 1 `not_reproducible`, 1 `blocked_needs_decision` |
| 3 | All supported tests pass, with the exact count reported | **pass** — **558 run, 0 failures, 0 errors, 3 skipped** |
| 4 | Wheel builds, installs in a clean venv, CLIs run from outside the checkout | **pass** — 18 packaging tests; `twine check --strict` PASSED on wheel and sdist; both console scripts driven from a temp directory with `PYTHONPATH` stripped, including a Mode-A run against a real MCP server. A bug found by this gate: `packages` was a hand-kept list and the wheel silently omitted `assay_bench.mcp` and `assay_bench.servers`. Fixed; wheel contents are now derived from the source tree by test |
| 5 | Every shipped canonical manifest verifies | **pass** — 5 shipped manifests verify (4 conformance references reach all five levels; the precommitted real-server run verifies and correctly withholds `run_complete`); 2 v0.1 fixtures still verify |
| 6 | Safe/vulnerable conformance runs generate artifacts through documented commands | **pass** — `assay reference` regenerates byte-identically; `--check` compares invariants |
| 7 | Generated artifacts and docs clean under `git diff --exit-code` | **pass** |
| 8 | Controlled tampering rejected with a stable non-zero exit | **pass** — exit 1, and still exit 1 under `python -O` |
| 9 | Partial runs cannot masquerade as complete | **pass** — a 2-of-31 run reports an apparent 92.5 and a **lower bound of 0.0**; `--require run_complete` exits 1 |
| 10 | Precommitment temporally enforced and tested, or claims removed | **pass** — three levels with named authorities, 26 tests over real git repos, and now a **worked example in this repository's own history**: `precommit-verify` reaches `repository_ordering_verified` from the clone. "Kills cherry-picking" withdrawn and banned by test |
| 11 | Attestation status distinct from internal verification | **pass** — `attest/`, its own leaderboard column, never emitted by the verifier. The one shipped record is a `clean_clone_reproduction`, not an attestation, and says so in its own `scope` field; a test forbids any shipped record claiming a maintainer rerun that did not happen |
| 12 | All executable documentation snippets tested | **pass** — every fenced command extracted and run; 5 excused with stated reasons |
| 13 | License text consistent or blocked on an owner decision | **pass with a flag** — SPEC's Apache outlier corrected to match `LICENSE`; changing the licence itself needs the owner (G4) |
| 14 | Literature and novelty claims backed by primary sources | **partial** — four prior benchmarks confirmed from published records. Re-checked: arxiv.org, ar5iv, alphaXiv, Semantic Scholar, Papers-with-Code, HuggingFace and OpenReview are all blocked by this container's egress proxy, so the papers were not read. Search summaries carry more detail and were deliberately NOT used to strengthen the claims (G11) |
| 15 | Claim wording consistent across code, schema, docs, paper, leaderboard, deck brief, demo | **pass** — 5 banned phrases enforced across 13 surfaces |
| 16 | Demo video genuinely time-varying, inspected, reproducible, accurately labelled | **pass** — see below |
| 17 | No secrets, credentials or private data committed | **pass** — see below |
| 18 | `git status` shows only intentional changes | **pass** |

---

## Gate 3 — test suite, from the clone

```
$ python -m unittest discover -s tests -t .
Ran 558 tests in 17.1s
OK (skipped=3)
```

The three skips are the recording-binary checks; the video is not committed (gate 17) and they
say so. Per module:

| module | tests |
|---|---|
| `test_verifier.py` | 67 |
| `test_artifacts_and_docs.py` | 37 |
| `test_source_of_truth.py` | 32 |
| `test_twins.py` | 31 |
| `test_mcp.py` | 30 |
| `test_diagnostics.py` | 29 |
| `test_task_matrix.py` | 29 |
| `test_runner.py` | 28 |
| `test_media.py` | 27 |
| `test_catalog_and_scoring.py` | 26 |
| `test_precommit.py` | 26 |
| `test_mcp_probe.py` | 24 |
| `test_contamination.py` | 23 |
| `test_provenance_and_attest.py` | 22 |
| `test_demo.py` | 18 |
| `test_packaging.py` | 18 |
| `test_canary.py` | 16 |
| `test_trust_boundary.py` | 9 |
| `test_mcp_interop.py` | 7 |
| `test_oracle_blind_spots.py` | 4 |

Total: 503.

`python -m unittest discover` with no arguments still reports `Ran 0 tests ... OK` from the
repository root, because discovery starts in the current directory. That is a property of
`unittest`, not of this suite; CONTRIBUTING documents it and CI always passes `-s tests -t .`.

## Gate 4 — distribution

Built and installed from the clean clone, then driven from `/tmp` with `PYTHONPATH` unset:

```
build_wheel rc 0
build_sdist rc 0
$ /tmp/cc_venv/bin/assay --version
assay-bench 0.2.0
$ /tmp/cc_venv/bin/assay run --target vulnerable --trials 5 --out /tmp/cc.json
wrote /tmp/cc.json: 31/31 tasks, agent=0.0 server=0.0 completion=complete real_target=False
$ /tmp/cc_venv/bin/assay verify /tmp/cc.json --require run_complete
exit 0
$ /tmp/cc_venv/bin/python -c "from assay_bench.catalog import load_catalog; ..."
installed catalog: 31 tasks, digest e8a6e47520e38b0e
```

The wheel carries `assay_verifier.py`, `scoring.py`, `badge.py`, the whole `assay_bench`
package including `mcp/` and `servers/`, and `data/tasks.json`, `data/manifest_schema.json` and
`data/twins.json`. `twine check --strict` PASSES on both the wheel and the sdist.

**A bug this gate found.** `packages` in `pyproject.toml` was a hand-kept literal list, so the
wheel silently omitted `assay_bench.mcp` and `assay_bench.servers`: an installed copy could not
run against a real MCP server at all while the source checkout could, and nothing failed,
because the suite runs against `src/` on `PYTHONPATH`. Packages are discovered now, and three
tests derive the expected wheel contents from the source tree rather than from a list — every
subpackage, every module, and an end-to-end check that the installed package can stand up a
reference MCP server and fingerprint it.

Console scripts `assay` and `assay-bench` both resolve. Driven from `/tmp` with `PYTHONPATH`
unset: `--help`, `--version`, `levels`, a full `run`, `verify --require run_complete`, the
legacy bare-path form, `triple`, and a Mode-A run against a real MCP server over a loopback
socket all behave.

The sdist unpacks and **its own suite passes standalone**: 285 tests, 12 skipped as
checkout-only (git history and the recording are deliberately absent from a distribution).

No deprecation warning is emitted — a test asserts the build output stays clean, which is what
the SPDX `license` string fixed.

## Gate 6 — reference artifacts

```
$ python -m assay_bench reference           # regenerate
$ git diff --exit-code                      # 0
$ python -m assay_bench reference --check
{ "ok": true, "problems": [] }
```

Byte-identical across regenerations, because the fixtures use a published fixed run secret and
frozen timestamps — both deliberate and both explained in the code. `--check` compares *run
invariants* and lists the fields expected to differ for a real run (secret, digests, integrity
hash, timestamps, run id, environment).

Conformance holds on all three properties: recall (every one of 31 tasks fires on the compliant
target), specificity (nothing fires on the refusing one, 0 canary false positives), and
discrimination (the mixed target fires on exactly its published subset).

## Gate 8 — tamper rejection

```
$ python src/assay_verifier.py verify /tmp/tampered.json
assay: canary finding M1 does not recompute: the digest is absent from the observed egress
       under the revealed secret
exit 1

$ python -O src/assay_verifier.py verify /tmp/tampered.json
exit 1
```

The second line is the one that matters. At baseline every check used `assert`, so `-O` removed
them all and the same tampered file verified with **exit 0**.

## Gate 9 — partial runs

```
$ PYTHONPATH=src python -m assay_bench run --target vulnerable --trials 5 \
      --task M1 --task M2 --out partial.json
$ python src/assay_verifier.py verify partial.json --require run_complete
exit 1

completion : partial
score      : 92.5      <- what reporting 2 of 31 tasks looks like
lower bound: 0.0       <- what it is worth
explanation: partial: 26 required task(s) not reported
```

The two numbers are the point. Cherry-picking two tasks produces a flattering headline and a
lower bound of zero, and only the lower bound is citable for a partial run.

Four independent mechanisms, each tested:

1. the verifier counts reported findings against the frozen catalog, so a submitter's own
   `completion: "complete"` cannot override it;
2. scores use the catalog's weight total as the denominator, never the reported findings';
3. every manifest carries a lower bound charging unreported, unsupported and inconclusive tasks
   at full weight — **omission can never raise it**;
4. the leaderboard tables partial runs separately with no rank, and `badge.py` refuses them.

An adapter that cannot evaluate a task yields `unsupported`, not `resisted`. A trial that errors,
times out, or leaves the oracle unable to decide yields `inconclusive`, not `resisted` — a bug
the per-task matrix caught, where an adapter observing *nothing* had scored a clean 100.

## Gate 16 — demo and video

Three consecutive runs from reset, environment stripped (`env -i`, no proxy variables), pacing
off:

| run | exit | duration |
|---|---|---|
| 1 | 0 | 0.489 s |
| 2 | 0 | 0.483 s |
| 3 | 0 | 0.501 s |

File hashes differ between runs — each mints a fresh secret — while **run invariants are
byte-identical** across all three, which is the property that matters and the one attestation
compares.

The recording: 1920×1080, VP8/WebM, 10 fps, 21.6 s, 216 frames. Of 31 sampled frames, **31 are
distinct, 0 adjacent pairs are identical, and the longest frozen run is 0**. Six frames were
opened and read, not merely hashed. Full report in [`demo/VIDEO_VALIDATION.md`](../demo/VIDEO_VALIDATION.md).

**The demo is a conformance and verifier demonstration, not a real MCP target run.** No MCP
server, agent or model is involved. Every frame's footer says so, and the closing summary repeats
it.

## Gate 17 — nothing sensitive committed

- The only secret the tooling produces is the run secret. A test asserts it never appears in
  provenance, and another that it never appears in a raw-trial log. The committed fixtures use a
  **published, fixed** secret on purpose — they are mechanism validation, not results.
- `precommit/registry/` holds exactly one record: the worked example, registered in its own
  earlier commit. Its run secret is **not** committed — the record carries only the SHA-256
  commitment, and a test checks the secret never appears in it. A stray record from a CLI smoke
  test was caught and removed during this audit; CLI tests now write to a temporary registry.
- The canary GUID in `tasks.json` is a deliberate published identifier, not a secret. A test
  asserts it has not spread beyond the three places it belongs.
- **The recorded video and its frames are not committed.** This is a public repository and a
  screen recording can capture more than its author intended, so the binaries are delivered out
  of band and regenerated with one command. The *text* evidence — transcript and a validation
  report carrying a SHA-256 per frame — is committed, so every claim in `VIDEO_VALIDATION.md`
  stays checkable. Distributions exclude them too, and a packaging test asserts it.
- No credentials, tokens, hostnames, usernames or paths appear in any generated artifact;
  `provenance.environment_summary()` is deliberately coarse.

---

## Gates added in the second pass

| # | Gate | Result |
|---|---|---|
| 19 | A real MCP client speaks the protocol to a separate process | **pass** — `assay_bench.mcp`: JSON-RPC 2.0 with a strict decoder, the `initialize` handshake with version negotiation, `tools/list`, `tools/call`, over stdio and Streamable HTTP. 30 tests drive it the way a hostile peer would: malformed frames, mismatched ids, an unknown protocol version, a server that never answers, a server that dies mid-handshake |
| 20 | That client is verified against software this repository did not write | **pass** — `tests/test_mcp_interop.py` drives a server built with the **official `mcp` SDK**; 6 tests, all passing here. The SDK is never a dependency, and a CI job **fails if the check skips** |
| 21 | Mode A discriminates between two real server postures | **pass** — the insecure reference server fires M6, M17 and M18; the hardened one fires none. Every fact comes from a status code, a header or a tool result the client received |
| 22 | A real-target run can never masquerade as a full benchmark result | **pass** — 28 Mode-B tasks need an agent under test, so they are `unsupported` with a stated reason, the run is `partial`, the lower bound is 0.0, `badge.py` refuses it, and the CLI leads with the lower bound instead of the headline |
| 23 | Absence is never scored as resistance, on any new path | **pass** — an unreachable server, a task the adapter cannot pose, and a client/server disagreement each produce an inconclusive trial. Each is a test |
| 24 | The image tasks carry their canary in image bytes alone | **pass** — 27 media tests; the surface builder raises if the canary or digest is also readable in the prose, and the QR encoder is validated against the published BCH and Reed-Solomon tables rather than its own output |
| 25 | The utility axis separates a secure target from a useless one | **pass** — `conformance-hardened` and `conformance-overcautious` are identical on resistance (100/100) and opposite on the twins (0.0 vs 100.0). Both manifests ship, and CI fails if the separation stops holding |
| 26 | The oracle's blind spots are measured, not merely published | **pass** — 14 of the 15 documented misses are detected and reported. A target leaking every canary split across two requests scores a clean 100.0 and is flagged on all 25 canary tasks. No diagnostic changes any score, asserted by running the same target with them on and off |
| 27 | Contamination is detectable and partly mitigated | **pass** — a canary GUID whose *miss* is explicitly reported as establishing nothing, and 4 per-run surface phrasings chosen from the run secret. Tests require every phrasing to still fire on the vulnerable target and still not on the hardened control, with the frozen task-set digest unchanged |
| 28 | Precommitment is exercised, not just implemented | **pass** — `precommit-verify` reaches `repository_ordering_verified` on a real run from the clone. Two defects surfaced by doing it for real: `git log --follow` deciding ordering by rename similarity, and an ephemeral TCP port inside a target fingerprint |

---

## Gates that do not fully pass

**Gate 14 — literature.** The four prior MCP benchmarks are confirmed by arXiv identifier,
date, execution model, scale and artifact location, which is enough to establish the claim that
matters: they predate this work and released artifacts, so the "open wedge" framing was false.
It is *not* enough for the task-by-task mechanism comparison Issue #1 asked for, because
arxiv.org is blocked from this container and the session's GitHub access is scoped to this
repository. `SPEC.md` §1 says so in place. Tracked as G11.

**Gate 13 — licence.** The documentation contradiction is removed. Whether the licence itself
should change is the owner's call. Tracked as G4.

**Gate 3 — PyPI.** Now checked rather than assumed: `assay-bench` returns 404 from the public
index, so it is unregistered and nothing claims otherwise. `assay` returns 200 and belongs to an
unrelated project by another author, so installing the bare name `assay` from PyPI gets you
someone else's code — tests fail the build if any document starts suggesting it. Publishing is the owner's call. Tracked as
G3, with G14 for the tag and release.

And the one that no gate covers, because it remains the largest limitation in the project:
**Mode B has no real target.** 28 of the 31 tasks poison a surface and score what an *agent*
does with it, and that needs an agent under test — a model with MCP tool access. Mode A is now
real: three tasks decided against a real MCP server over a socket. The other 28 are not, and a
run against a real server reports them `unsupported` rather than letting them look answered.
Tracked as G1.
