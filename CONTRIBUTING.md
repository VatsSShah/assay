# Contributing to Assay

Assay is an **open standard**: a frozen task set scored by a recomputable cryptographic oracle.
Everything in this repo runs on the Python **standard library** alone, no third-party deps.

## Develop

```bash
python -m pytest tests/ -q          # the verifier's own tests (stdlib + pytest)
python assay_verifier.py leaderboard/manifests/reference_vulnerable.json   # -> VERIFIED
python coverage.py                  # regenerate COVERAGE.md from tasks.json
python leaderboard/build_site.py    # re-verify every entry and rebuild the board
```

CI runs all of the above on every PR; a scorecard that does not verify blocks the merge.

## Submit a leaderboard result

See [`leaderboard/SUBMIT.md`](leaderboard/SUBMIT.md). Run the reference implementation on
**loopback only**, add your manifest under `leaderboard/manifests/` and one entry to
`leaderboard/entries.json`. The score is read from the manifest and re-verified at build time -
it cannot be self-reported. A maintainer re-runs the target before merge.

## Change the spec or the task set

Task ids, oracle class, mode, and severity weights are **frozen** within a `MAJOR.MINOR` line
(see [`SPEC.md`](SPEC.md) §9). Adding a task or changing a weight bumps MINOR; redefining an
oracle or a score formula bumps MAJOR. Open an issue first for any change to a frozen field.
