# Security policy

## What this project is

Assay is a benchmark task set, a runner and a verifier for **MCP security evaluation**. It ships
adversarial content by design: poisoned tool descriptions, injection templates and exfiltration
mechanics are the subject matter. That content is inert — it targets the built-in deterministic
conformance stubs and nothing else — but treat the repository as you would any offensive-security
corpus.

## Reporting a vulnerability

Open a [GitHub security advisory](https://github.com/VatsSShah/assay/security/advisories/new) for
anything that would let someone produce a misleading Assay result, or affect a user running this
code. Please do not open a public issue for those.

Ordinary bugs, wrong numbers and documentation errors belong in the public issue tracker, and are
more useful there.

## What counts as a vulnerability here

This project's security property is **evidential**, so the interesting failures are ones that let
a document claim more than it should:

| in scope | example |
|---|---|
| A manifest that reaches a verification level it should not | a tampered canary that still recomputes |
| A way to make a partial run look complete | bypassing the catalog count or the validity assessment |
| A way to raise a score by reporting less | anything that breaks the omission-proof lower bound |
| A precommitment that verifies without the ordering holding | forging repository ancestry |
| Code execution, path traversal or data exfiltration from running the tools | a crafted manifest that writes outside its output path |
| Secret leakage | the run secret appearing in provenance, logs or a registry record |

## What is already known and is not a vulnerability

These are documented limits, not bugs. Reporting them is welcome as discussion, but they are
already stated in `SPEC.md` §4.2 and pinned as *passing* tests in
`tests/test_trust_boundary.py`:

- **A keyholder can fabricate a passing manifest.** `observed` is submitter-supplied text and the
  submitter holds the run secret. No document check can fix this; it is why attestation is a
  separate artifact.
- **Under-reporting cannot be detected from the document alone.** It can only be made
  unprofitable, which the lower bound does.
- **The oracle misses 15 of 22 tested egress transformations.** Split, re-encoded, compressed,
  encrypted, hashed and paraphrased exfiltration are not detected. See
  `tests/test_oracle_blind_spots.py`.
- **Commitment and reveal in one document prove no ordering.** That is why `precommit/` exists.

## Supported versions

Only the latest commit on `main` is supported. There is no PyPI release yet (see
`REMAINING_GAPS.md` G3), so there is nothing to patch downstream; if that changes, this section
will name the supported release line.

## Handling secrets

The run secret is the only sensitive value the tooling produces. It must not appear in
provenance, logs, or a precommitment record, and a test asserts that it does not. `assay
precommit --secret-out` writes it to a file you control; keep it private until the reveal.

The committed conformance fixtures use a **published, fixed** run secret on purpose: they are
mechanism validation, not results, so there is nothing to protect and byte-reproducibility is
worth more. Never reuse that secret for a real run.
