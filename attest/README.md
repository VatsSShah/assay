# Maintainer attestations

A manifest that passes `assay verify` has said nothing about whether anyone other than its
author ever ran the target. This directory holds that separate claim.

An attestation records: the maintainer, the code commit they ran from, the submitted manifest's
integrity hash, and a comparison of **run invariants** — the per-task fired/ASR vector, the two
scores, the target fingerprint and the task-set digest.

Comparison is on invariants rather than bytes because a rerun mints a fresh run secret, so
digests, envelopes, integrity hashes and timestamps all differ legitimately. A rerun that
matches on invariants and differs on those fields is exactly what an honest reproduction looks
like.

```bash
PYTHONPATH=src python -m assay_bench attest --submitted <manifest.json> --rerun <rerun.json> \
    --maintainer <name> --out attest/<name>.json
```

Status is one of `match`, `diverged`, or `rerun_failed`. The verifier never emits
`independently_rerun` or `maintainer_attested`; the leaderboard reads them from here and shows
them in their own column, so a coherence check can never be mistaken for an independent
reproduction.

An attestation covers the target described by `target_fingerprint`. It does **not** attest that
the target is any particular commercial product — nothing in the artifact ties a fingerprint to
a product name.

## Two kinds of record, and why the difference is a field

A file in a directory called `attest/` reads as an attestation. One that is not must say so
somewhere a machine can check, not in a note a reader has to parse. Every record therefore
carries `kind`:

| kind | what it establishes |
|---|---|
| `maintainer_attestation` | a maintainer, independent of the submitter, reran the target and compared invariants. The only kind the leaderboard shows as attested, and the only kind that can ever support `maintainer_attested`. |
| `clean_clone_reproduction` | someone reran from a fresh clone of the published source and the invariants matched. Evidence the artifacts are reproducible. It says nothing about independence, and when the rerunner is the party that produced the artifacts it is a self-check. |

## The one record here

`precommitted_mcp_insecure.json` is a **`clean_clone_reproduction`**, not an attestation. The
precommitted run was reran from a fresh clone of this repository against the reference MCP
server built from that clone's own source, and the invariants digests matched exactly on both
sides. That is real evidence the shipped artifacts reproduce from published source.

It is **not** a maintainer attestation, because the rerun was performed by the same session that
produced the artifacts. Its own `scope` field begins *"This is NOT a maintainer attestation"*,
and a test asserts that no shipped record claims to be one: a record claiming a maintainer rerun
that never happened would be fabricated evidence, which is the one thing this repository must
never contain.

**No maintainer attestation has been performed.** The first will accompany the first measurement
submission, and it is a person's act rather than a script's.
