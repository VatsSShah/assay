# Published experiment bundles

**No published experiment bundle with full traces exists yet.** This directory is where one will
go: an `experiments/published/<experiment_id>/` directory in the bundle layout that
`assay verify-artifacts` checks (`experiment.json`, `configurations/<name>/{scorecard.json,
trials.json, traces.jsonl}`, `artifact_index.json`, optionally `artifact_index.sig.json` and
`witness/`). CI verifies every bundle placed here; an empty directory passes because there is
nothing to verify, not because anything was verified.

## What exists instead

The 2026-10-28 spectrum results in [`demo/arsenal/spectrum/`](../../demo/arsenal/spectrum/) are
**summary-level, self-reported evidence**: eight scorecards, one per model, 5 trials per task, run
through OpenRouter. They carry per-task outcome tallies, findings, utility and diagnostics, and
each one verifies with `assay verify` up to `catalog_bound`. They do **not** carry raw trial
records, traces or transcripts, no witness observed them, and no model revision was verified. Read
[`research/statistical-analysis.md`](../../research/statistical-analysis.md) for what they can and
cannot support; it is generated from those files and states the limitations first.

## Publishing a bundle here

1. Produce it with `assay experiment run`, which writes the bundle and its artifact index.
2. Redact it before it leaves your machine (`assay redact`), then rebuild the index.
3. Sign the index if you can (`assay sign-artifacts`, key in `ASSAY_ARTIFACT_KEY`).
4. Check it: `PYTHONPATH=src python -m assay_bench verify-artifacts experiments/published/<experiment_id>`.
5. Generate the report beside it: `PYTHONPATH=src python -m assay_bench analyze
   experiments/published/<experiment_id> --markdown experiments/published/<experiment_id>/REPORT.md`
   (then rebuild the index, since REPORT.md is a new file in the bundle).

Negative and inconclusive results are published on the same terms as positive ones. A bundle that
only appears when the numbers look interesting is a selection effect, not evidence.
