# Contributing to Assay

Assay is an **open standard**: a frozen task set scored by a recomputable HMAC oracle, plus a
runner and a verifier that state their evidence level explicitly. Everything in this repository
runs on the Python **standard library** alone — including the test suite, which is written
against `unittest` rather than pytest so that claim stays true.

## Develop

```bash
python -m unittest discover -s tests -t .
PYTHONPATH=src python -m assay_bench run --target vulnerable --trials 5 --out /tmp/scorecard.json
python src/assay_verifier.py verify /tmp/scorecard.json --require run_complete
python coverage.py
python leaderboard/build_site.py
PYTHONPATH=src python -m assay_bench reference --check
PYTHONPATH=src python -m assay_bench.sync_data --check
```

`python -m pytest tests/ -q` also works if you prefer pytest — it collects `unittest.TestCase`
subclasses natively — but pytest is not required and is not installed by CI's core job.

> **Note on `python -m unittest discover` without arguments.** Run from the repository root it
> reports `Ran 0 tests ... OK`, because the tests live under `tests/` and discovery starts in
> the current directory. That green result means *nothing ran*. Always pass
> `-s tests -t .`, which is what CI does.

CI runs all of the above on every PR, plus `git diff --exit-code` after every generator, so a
stale generated file fails the build.

## What a change must not break

- **Frozen fields.** Task ids, oracle class, mode, and severity weights are immutable within a
  `MAJOR.MINOR` line (see [`SPEC.md`](SPEC.md) §9). `tasks.json` is the single source of truth;
  nothing else may hold a second copy of a weight or a mode. Open an issue before touching one.
- **The oracle.** Widening the frozen encoding set in `assay_bench/canary.py` changes the oracle
  and is a MAJOR bump. Known false negatives are *documented* in
  `tests/test_oracle_blind_spots.py`, not patched.
- **Backwards compatibility.** `tests/fixtures/legacy_v0_1/` holds v0.1 manifests. They must
  keep verifying.
- **The trust boundary.** `tests/test_trust_boundary.py` asserts that certain attacks *succeed*
  against the verifier. Those are the properties Assay does not have. If one starts failing you
  have strengthened a guarantee — update the claim wording in README, SPEC §4.2, SUBMIT.md and
  the verifier docstring in the same change, and only then.

## Numbers in prose

Documentation that states an exact count -- "500 tests", "31 tasks", "15 blind spots" -- is
checked against reality by `tests/test_artifacts_and_docs.py::DocumentedNumbersMatchReality`. Add
a test and those numbers go stale, so the guard fails and you update them in the same change.

```bash
python audit/collect_evidence.py --sync-docs
```

rewrites every stated test count to the measured one.

## Claims discipline

`tests/test_artifacts_and_docs.py::ClaimConsistency` fails the build if withdrawn wording
reappears on any surface, and `ExecutableDocumentation` runs every fenced command in the docs.
A command you cannot run is a command you may not document. If you add a claim, add its row to
[`audit/CLAIM_EVIDENCE_MATRIX.md`](audit/CLAIM_EVIDENCE_MATRIX.md) with its evidence.

Never use `assert` for input validation: `python -O` removes assertions, which would turn a
rejecting verifier into an accepting one. Raise an explicit exception from `assay_bench.errors`
and return a stable exit code (0 ok, 1 verification failed, 2 usage, 3 malformed).

## Submit a leaderboard result

See [`leaderboard/SUBMIT.md`](leaderboard/SUBMIT.md). Register a precommitment first, run on
loopback or in-process only, then add your manifest under `leaderboard/manifests/` and one entry
to `leaderboard/entries.json`. The score is recomputed from the findings at build time, so it
cannot disagree with them — which is not the same as it being true, and the board shows the
verification levels and the attestation status in their own columns for exactly that reason.
