# Independent replications

This directory holds replication submissions (`*.submission.json`, schema
`assay/replication-submission/1`) and, beside each, the experiment bundle it references. The
procedure, ethics and evidence rules are in [`docs/REPLICATION_GUIDE.md`](../../docs/REPLICATION_GUIDE.md).

**There are no accepted replications yet.** `TEMPLATE.submission.json` is a starting point
filled with `<REPLACE: ...>` placeholders; it deliberately fails validation until every
placeholder is replaced and the counts, digests and verification output are real.

## Layout

```
experiments/independent-replications/
  <researcher>-<experiment_id>.submission.json
  <researcher>-<experiment_id>/            # the bundle; evidence.bundle_path points here
    experiment.json, config.json, configurations/..., artifact_index.json, ...
```

## What CI checks

For every `*.submission.json` here except the template, CI runs
`assay replication validate <submission> --bundle <its bundle>`, and it runs
`assay verify-artifacts` on every bundle. Those checks establish that a submission is complete,
that its digests, counts and model identity agree with a bundle that verifies, and that every
claimed evidence level is backed by the artifacts it needs. **They do not establish that the
experiment happened as described.** Structural validation is not proof of factual authenticity.

## Evidence levels (independent attributes, not a ladder)

| level | attribute | what backs a claim of it |
|---|---|---|
| 1 | `self_reported` | always true: the submitter ran it and says so |
| 2 | `independently_witnessed` | witness receipts in the bundle that verify under a key the bundle's trust file declares independent, and that is not the key that signed the artifact index |
| 3 | `independently_reproduced` | a `replicates` reference to an earlier experiment, by a researcher who is not its original operator |

Level 3 never implies Level 2. A careful reproduction can be self-observed; a witnessed run can be
the only run there is.

## Deviations are required

`deviations` must be present. An empty list is a claim that the method was followed exactly; if
anything differed (model id, routing, trial count, configuration, prompt variant, timeouts,
retries), list it with its reason and its possible impact on the result.
