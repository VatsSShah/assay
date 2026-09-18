# Pre-run commitment registry

This directory holds commitment records registered **before** a run. Each is a small JSON
document binding a run secret's commitment to the parameters of the run it will authenticate.

## Why the v0.1 arrangement was not enough

v0.1 put `run_secret_commitment` and `run_secret_reveal` in the same manifest. Checking
`SHA-256(reveal) == commitment` then proves only that the submitter owns a SHA-256
implementation: nothing establishes that the commitment existed before the results did. A
submitter could run fifty times with fifty secrets and publish the best one, and no check could
see it. The v0.1 claim that commit-reveal "kills cherry-picking" has been withdrawn.

## Trust model

A commitment is evidence only if a party the submitter does not control witnessed it before the
results existed. Three levels, each naming its authority:

| level | authority | what it shows | offline? |
|---|---|---|---|
| `local_commitment_consistency` | arithmetic | the reveal hashes to the commitment, and the record's bound fields match the manifest | yes |
| `repository_ordering_verified` | git history of this repository | the commit introducing the record is a strict ancestor of, and dated earlier than, the commit introducing the manifest | yes, in a clone |
| `precommitment_verified` | the forge's push/event record, checked in CI | the ordering was witnessed by a party the submitter does not control | no |

An offline run reaches at most the second level, and the tooling reports it as
*local commitment consistency* rather than relabelling it as externally-timestamped
precommitment. `created_at_submitter_clock` inside a record is recorded for human reading and is
**never consulted by verification**.

## What even the top level does not prove

That every run was published. A submitter may register N commitments, run N times and reveal
one. All N records remain visible here, and `assay precommit-list` flags unrevealed ones — a
deterrent and an audit trail, not a proof. The permitted wording is therefore *"unpublished runs
are visible as unrevealed registry records"*, never *"kills cherry-picking"* or
*"result grinding is impossible"*.

## What a record binds

`commitment`, `benchmark_version`, `task_set_digest`, `target_fingerprint`, `trial_plan`,
`run_id`, `nonce` — sealed by `record_digest`, a SHA-256 over exactly those fields in canonical
form. A manifest that differs on any of them cannot claim the record. A record may authenticate
**at most one** manifest; a second binding is rejected as reuse.

## Operational edge cases

| situation | behaviour |
|---|---|
| rebase / amend / force-push | verification reads the commit that *currently* introduces the record; a rewritten history fails the ancestry check rather than passing on inertia |
| clock skew | ancestry is the primary test; a committer-date inversion is reported explicitly, not tolerated silently |
| retries | one record binds one manifest; publish a second result and it is rejected as reuse |
| abandoned commitments | records stay, listed as `UNREVEALED` — that visibility is the anti-grinding signal |
| multiple targets | a record binds one target fingerprint; a manifest for another target cannot claim it |
| duplicate commitments | two records with the same commitment make the registry unloadable, by design |
| secret rotation | a new run means a new secret means a new record |
| offline runs | reach `local_commitment_consistency`, and `repository_ordering_verified` in a clone; never the external level |

## Commands

```bash
python -m assay_bench precommit --target vulnerable --trials 25 --secret-out /tmp/run.secret
python -m assay_bench precommit-list
python -m assay_bench precommit-verify --manifest leaderboard/manifests/reference_vulnerable.json
```

Every case above is covered by `tests/test_precommit.py`, which builds throwaway git
repositories and commits artifacts in each order rather than mocking the history.

## Why this directory is otherwise empty

The committed conformance runs use a **published, fixed** run secret so their artifacts are
byte-reproducible (see `assay_bench/cli.py::REFERENCE_RUN_SECRET`). A precommitment over a
published secret would be theatre, so none is registered for them. The first real record here
will accompany the first measurement submission.
