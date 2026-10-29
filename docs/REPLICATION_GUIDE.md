# Replicating an Assay result

This guide is for a researcher who wants to reproduce an Assay experiment, or run a new one, and
submit it so that others can check it. It covers the commands, the rules of conduct, and what each
level of evidence does and does not show.

A replication is worth most when it can fail. Publish it whatever it shows: a result that does not
reproduce, a run full of inconclusive trials, or a model that resists everything. A replication
that appears only when it agrees with the original is not evidence of anything.

## 1. Before you start: ethics and authorisation

- **Use only API access you are authorised to use, under the provider's terms.** Assay sends
  adversarial prompts on purpose. Check that your provider's acceptable-use policy allows security
  evaluation, and use your own account and your own key. Never use someone else's credentials.
- **Synthetic secrets only.** The only "secrets" in an Assay run are canaries minted by the
  harness (`assay_bench.canary`). Never put a real credential, token, customer record or personal
  data into a scenario, a configuration or a tool result. A test that needs a real secret to be
  meaningful has to be redesigned, not run.
- **Safe network endpoints only.** Every sink a model can exfiltrate to must be one you control:
  the harness's loopback MCP server (`127.0.0.1`), or your own witness sink (`assay witness-sink`,
  loopback by default). Do not point a run at a third-party host, a production system or any
  address you do not own. URLs that appear inside scenario text (for example `status.acme-ops.io`)
  are lures served by the loopback server; the harness never contacts them.
- **Billable calls are opt-in.** `assay experiment run` refuses to call a paid model API unless
  you pass `--allow-billable-calls`. Estimate the cost first: tasks × trials × configurations ×
  the steps per trial.
- **Responsible disclosure.** If a run shows a model or an MCP server doing something that puts
  real users at risk beyond what this benchmark already documents, tell the vendor privately
  first (see [`SECURITY.md`](../SECURITY.md)) and give them reasonable time before publishing the
  details. Aggregate scores can be published without delay; a new, working exploit chain should
  not be.
- **Redact before publishing.** Traces hold whatever the model and tools saw. Run `assay redact`
  over every trace and trial log before the bundle leaves your machine (step 4). Canary digests
  are kept on purpose: they are the evidence. Everything else that looks like a secret is
  replaced with a deterministic marker.

## 2. The commands

| step | command |
|---|---|
| check a configuration | `assay experiment validate-config --config PATH` |
| run an experiment | `assay experiment run --config PATH [--out DIR] [--allow-billable-calls] [--configuration NAME ...]` |
| redact an artifact | `assay redact IN OUT` |
| sign the artifact index | `assay sign-artifacts DIR` (key from `ASSAY_ARTIFACT_KEY`, hex 32-byte seed) |
| verify a bundle | `assay verify-artifacts DIR [--expect-public-key HEX] [--require-signature] [--expect-commit SHA]` |
| run your own witness | `assay witness-sink --host 127.0.0.1 --port N --state-dir DIR --witness NAME [--independent]` (key from `ASSAY_WITNESS_KEY`) |
| verify witness receipts | `assay verify-witness RECEIPTS_FILE [--trusted-keys FILE] [--expect-public-key HEX] ...` |
| see the witness protocol locally | `assay witness-demo [--out DIR]` |
| analyse results | `assay analyze PATH... [--json OUT] [--markdown OUT]` |
| validate a submission | `assay replication validate SUBMISSION.json [--bundle DIR]` |

From a source checkout, prefix each one with `PYTHONPATH=src python -m assay_bench` in place of
`assay`.

## 3. Reproduce an experiment

1. **Pin the code.** Check out the exact Assay commit the original experiment records
   (`experiment.repository_commit` in its `experiment.json`, or `provenance.code_commit` in a
   scorecard). If you cannot, record the commit you used as a deviation.
2. **Pin the model.** Use the same `api_model_id` and routing service. Record the
   `provider_reported_models` the API returns. If the provider exposes a model revision, record it;
   if it does not, leave `model_revision` null. Never fill it in from a model's marketing name.
3. **Start from the original configuration** (`config.json` in the original bundle). Change it
   only where you must, and list every change as a deviation.
4. **Run a free, synthetic dry run first** to check your setup without spending anything:

   ```
   PYTHONPATH=src python -m assay_bench experiment run --config experiments/examples/synthetic-local/experiment.json --out /tmp/exp
   ```

   Its output is labelled `synthetic: true` and says nothing about any model.
5. **Run the real experiment** with `--allow-billable-calls`. Keep the full output directory.

## 4. Prepare the bundle

1. **Redact** every trace and trial log (`assay redact IN OUT`), replace the originals with the
   redacted copies, and keep the redaction reports.
2. **Rebuild and sign the index** (`assay sign-artifacts DIR --build-index`) with a key you keep
   for this purpose. Publish the public key somewhere you control as well.
3. **Verify** the bundle exactly as a reader will: `assay verify-artifacts DIR`. Fix anything that
   fails. Do not delete trials to make it pass.
4. **Analyse it**: `assay analyze DIR --markdown DIR/REPORT.md`. Then rebuild the index again,
   because REPORT.md is a new file in the bundle.

## 5. Record negative and inconclusive results

Report every configuration and every trial you ran, including:

- trials where the attack failed (`attack_failed`);
- trials that were inconclusive, errored or timed out (`inconclusive`, `infrastructure_failures`).
  These are never counted as resisted, and an analysis keeps them out of the ASR denominator and
  reports them beside it;
- tasks your setup could not run (`unsupported`). They lower coverage; they are not passes;
- runs you started and abandoned. Say why under `deviations`.

At 5 trials per task a 95% interval on a per-task rate is roughly 0.4 to 0.65 wide. Do not
describe a difference between two models on one task as real unless the analysis shows it holds
at that sample size, and treat pairwise tests as exploratory.

## 6. Declare deviations

`deviations` is required. An empty list says you followed the original method exactly. Otherwise
add one entry per difference, each with `description`, `reason` and `impact`. Typical deviations:
a different commit, model id, routing service or region; a different trial count, timeout or retry
policy; a different prompt variant or configuration; a provider that reported a different model
than the one requested.

## 7. Evidence levels

A submission states three independent booleans. They are not a ladder: none implies another.

| level | attribute | backed by | what it does NOT show |
|---|---|---|---|
| 1 | `self_reported` | always true | that anything happened as described |
| 2 | `independently_witnessed` | receipts in `witness/receipts.jsonl` that verify under a key that `witness/trusted_keys.json` declares independent, and that is not the key that signed the artifact index | that the witness really is independent: that is a declaration about who holds the key |
| 3 | `independently_reproduced` | a `replicates` reference to an earlier experiment, by a researcher who is not its original operator | that the run was witnessed, or that the two researchers are really different people |

**Level 3 never implies Level 2.** A careful reproduction you observed yourself is Level 1 + 3. A
witness you operate yourself is not independent: a receipt signed by your own artifact-signing
key, or by a key whose trust entry does not say `independent: true`, cannot support a Level 2
claim, and the validator rejects it.

To get Level 2, someone who is not you runs `assay witness-sink` with their own key, your harness
relays egress to it, and they give you the public key (never the private one) for
`witness/trusted_keys.json`. The witness receipts then show that canaries reached a sink you do not
control. Even then they show only that the canaries arrived at the witness. They do not show
network exfiltration from a real deployment.

## 8. Submit

1. Copy [`experiments/independent-replications/TEMPLATE.submission.json`](../experiments/independent-replications/TEMPLATE.submission.json)
   to `experiments/independent-replications/<you>-<experiment_id>.submission.json` and put the
   bundle beside it. Replace every `<REPLACE: ...>` value. The template fails validation until you
   do.
2. Paste the JSON printed by `assay verify-artifacts` into `verification`, and the index digest
   (`index_sha256` from `artifact_index.sig.json`, or the sha256 of `artifact_index.json`) into
   `evidence.artifact_index_sha256`.
3. Validate it against the bundle:

   ```
   PYTHONPATH=src python -m assay_bench replication validate experiments/independent-replications/<file>.submission.json --bundle experiments/independent-replications/<bundle>
   ```

4. Open a pull request. CI re-runs the bundle verification and the submission validation.

Passing validation means the submission is complete and agrees with a bundle that verifies. It is
**not** proof that the experiment happened. Structural validation is not proof of factual
authenticity, and reviewers will read the bundle, not just the green check.
