# Submitting to the Assay leaderboard

Read this section before the steps, because it determines how your row will be labelled.

## What a submission can and cannot prove

The build recomputes your score from your findings and re-checks every canary triple, so a
stated number cannot disagree with the findings it summarises, and a document altered after
sealing is rejected. Those are coherence properties.

They are not evidence that you ran anything. **If you hold the run secret you can compute a
valid digest and paste it into an invented `observed` string, and the verifier will confirm
it** — see `tests/test_trust_boundary.py`. You can also omit findings, which raises your score.
That is why a row shows levels rather than a badge, and why the Attested column exists:

| level | established by |
|---|---|
| `format_valid`, `internally_consistent`, `canary_correspondence_verified` | the verifier, offline |
| `catalog_bound`, `run_complete` | the verifier, against the frozen `tasks.json` |
| `precommitment_verified` | CI, against repository history — never a timestamp inside your JSON |
| `maintainer_attested` | a maintainer's independent rerun, recorded in `attest/` |

A row with `internally_consistent` and nothing else is a self-reported number in a
well-formed envelope. Please do not cite it as more than that, and we will not either.

## Steps

**1. Register a precommitment, in its own commit, before you run.**

```bash
python -m assay_bench precommit --target vulnerable --trials 25 --secret-out /tmp/run.secret
```

This writes `precommit/registry/<run-id>.json` binding the benchmark version, task-set digest,
target fingerprint, trial plan, run id and a nonce. Commit and push **that file alone**:

```bash
git add precommit/registry/<run-id>.json
git commit -m 'precommit: <target>'
git push
```

The ordering evidence is the commit that introduces the record, not the timestamp inside it. A
commitment landing in the same commit as the result proves nothing and will be reported as such.

**2. Run the benchmark, reusing the committed run id and secret.**

```bash
python -m assay_bench run --target vulnerable --trials 25 --run-id <run-id> --run-secret <hex> --out leaderboard/manifests/<name>.json
```

Run on **loopback or in-process only**; published rows never target a live third-party
endpoint. Pin your model snapshot, temperature and trial count `N` in the manifest.

**3. Check it yourself before opening a PR.**

```bash
python assay_verifier.py verify leaderboard/manifests/<name>.json --require run_complete
python -m assay_bench precommit-verify --manifest leaderboard/manifests/<name>.json --require repository_ordering_verified
```

**4. Open a PR** adding the manifest and one entry to `entries.json` (see `schema.json`). Set
`class` to `measurement` for a real target, or `conformance` for a built-in deterministic stub;
the two are tabled separately so a stub's 100.0 is never read as a product result.

**5. Automated check.** CI runs `python leaderboard/build_site.py`, which verifies every
manifest. A failing manifest blocks the merge.

**6. Maintainer rerun.** A maintainer reruns the target at the pinned version and records the
comparison in `attest/`. Comparison is on run invariants (per-task fired/ASR, scores, target
fingerprint, task-set digest), not bytes, because a rerun mints a fresh secret.

Disclose self-authored targets as such.
