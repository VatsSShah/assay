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

## Why this directory is otherwise empty

No measurement rows exist yet, and the built-in conformance targets are stubs anyone can rerun
from a clean clone in seconds, so a maintainer attestation over them would add nothing. The
first record here will accompany the first measurement submission.
