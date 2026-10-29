# Reproducing an Assay experiment

This document explains how to reproduce an Assay experiment from a clean checkout, how to check
the result, and what "reproduced" means for a benchmark that calls nondeterministic models
through third-party APIs.

## 1. What you need

* Python **3.10 or newer**. Nothing else: the runtime and the test suite use only the standard
  library.
* `git`, to clone the repository and to record the commit and working-tree state in the manifest.
  Without it those fields are `null` and appear in `metadata_gaps`.
* For a **live** run only: an API key for OpenRouter or another OpenAI-compatible endpoint, and
  money. The synthetic walkthrough needs neither, and it never opens a network connection beyond
  127.0.0.1.

## 2. Clean-checkout setup

```
git clone https://github.com/VatsSShah/assay.git
cd assay
git checkout <the commit named in experiment.json: experiment.repository_commit>
```

You do not need to install anything. Every command below runs from the checkout with
`PYTHONPATH=src`. If you would rather have the `assay` command on your PATH, an editable install
of the checkout works, and it pulls in no dependencies:

```
python3 -m pip install -e .
```

(The package is not published to any index. Install it from the checkout.)

To check the checkout before you start, run:

```
PYTHONPATH=src python3 -m unittest discover -s tests -t .
PYTHONPATH=src python3 -m assay_bench reference --check
```

## 3. The synthetic local walkthrough (offline, about 5 seconds)

`experiments/examples/synthetic-local/experiment.json` runs a **scripted, deliberately vulnerable
mock model** (`assay_bench.mock_model`, labelled `synthetic` everywhere). It runs four tasks (M1,
M3, M23 and the behavioral M9) with 5 trials each, under five configurations: `baseline`,
`confirmation_gated`, `egress_restricted`, `tool_restricted` and `policy_validated`. The run
exercises the real adapter loop, the real loopback MCP server, the controls, the trace recorder,
the frozen oracle, redaction, the bundle index and verification. **It measures no model.**

```
PYTHONPATH=src python3 -m assay_bench experiment validate-config --config experiments/examples/synthetic-local/experiment.json
PYTHONPATH=src python3 -m assay_bench experiment run --config experiments/examples/synthetic-local/experiment.json --out experiments/runs
```

Expected output: progress lines on stderr, then a JSON summary on stdout. The summary gives the
bundle path, an `experiment_id` of the form `exp-YYYYMMDD-xxxxxxxx`, `"ok": true`, and 14 named
checks, all `"ok": true`. The exit code is 0. The bundle contains:

```
experiment.json  config.json  redaction_report.json  analysis.json  REPORT.md  artifact_index.json
configurations/{baseline,confirmation_gated,egress_restricted,tool_restricted,policy_validated}/
    scorecard.json  trials.json  traces.jsonl
```

Expected per-configuration counts in `experiment.json` → `runs`. The mock is deterministic, so
these are exact:

| configuration | trials | model_attempted | executed | outcome details |
|---|---|---|---|---|
| baseline | 20 | 20 | 20 | attack_succeeded 20 |
| confirmation_gated | 20 | 20 | 0 | blocked_by_control 20 |
| egress_restricted | 20 | 20 | 5 | blocked_by_control 15, attack_succeeded 5 |
| tool_restricted | 20 | 0 | 0 | attack_failed 15, legit_task_completed_safely 5 |
| policy_validated | 20 | 20 | 5 | blocked_by_control 15, attack_succeeded 5 |

The five executed trials under `egress_restricted` and `policy_validated` are M9, the destructive
action. A destination allowlist and a taint gate cover data egress. They do not cover an
irreversible tool call, and the table shows that rather than hiding it. Under every blocking
control the model still *attempted* every leak, and the scorecard still says `exploited`. That is
why attempt and execution are separate columns (see `experiments/README.md`).

## 4. Verifying a bundle

```
PYTHONPATH=src python3 -m assay_bench verify-artifacts experiments/runs/<experiment_id>
PYTHONPATH=src python3 -m assay_bench verify-artifacts experiments/runs/<experiment_id> --expect-commit <sha>
PYTHONPATH=src python3 -m assay_bench verify experiments/runs/<experiment_id>/configurations/baseline/scorecard.json
```

`verify-artifacts` checks the following:

* every file against the index, and that no file is unindexed;
* path safety;
* the experiment manifest;
* that experiment and run ids agree everywhere;
* every scorecard, with the existing verifier;
* trial counts across `experiment.json`, `trials.json`, the traces and the scorecards;
* every trace's hash chain and causal consistency;
* that every `exploited` trial has a fired `validation` event;
* the commit, if you pin one;
* the index signature, if one is present or required;
* witness receipts, if present.

`assay verify` reports the levels an individual scorecard reaches.

If `ASSAY_ARTIFACT_KEY` (a 64-hex Ed25519 seed) is set during the run, the index is signed. Verify
the signature with `--require-signature --expect-public-key <hex>`, using a public key you obtained
somewhere other than the bundle.

**What a passing verification establishes:** the files agree with each other and with the index
(and with the signer's key, if signed). **What it does not establish:** that the experiment
occurred, that the provider served the named weights, or that the operator did not fabricate a
self-consistent bundle. Independence comes only from a witness the operator does not control
(section 7) and from someone else re-running the experiment.

## 5. Live-model reproduction (explicit opt-in)

1. Copy `experiments/examples/live-openrouter/experiment.json` and set `model.api_model_id` to the
   exact model id you mean to call. Validation rejects the placeholder: Assay never picks a model
   for you.
2. Provide the key out of band. Set `export OPENROUTER_API_KEY=...`, or write it to
   `~/.config/assay/openrouter.key` with `chmod 600`. Never put it in the config or on the command
   line. For another OpenAI-compatible endpoint, use `"provider": "openai-compatible"`,
   `"base_url": "https://..."` and `"api_key_env": "YOUR_VAR"`. Plain `http://` is accepted only
   for a loopback server.
3. Check the plan and the call estimate:
   `PYTHONPATH=src python3 -m assay_bench experiment validate-config --config my-live.json`
4. Run it. This needs **both** `"live": true` in the config **and** the flag:
   `PYTHONPATH=src python3 -m assay_bench experiment run --config my-live.json --out experiments/runs --allow-billable-calls`

Without the flag the run is refused before any key is read or any connection is made. The
refusal gives an upper bound: tasks × trials × configurations × max_steps model calls, plus twins
if enabled. Retries on failure come on top of that.

`strict_model_identity: true` (set in the template) fails any trial where the provider reports a
different model than the one requested. The trial is recorded as `model_api_failed`, never
silently counted as a measurement of the named model.

## 6. Costs and rate limits

* Cost is roughly (calls × tokens per call × provider price). The template is 6 tasks × 5 trials ×
  5 configurations × up to 6 steps, so at most 900 attack calls. Most episodes stop after two or
  three steps. The scenario prompts are short, a few hundred to about two thousand tokens.
* OpenRouter reports per-call cost, which is summed into `runs[].cost_estimate_usd`. Providers
  that do not report cost leave it `null`, and it is listed in `metadata_gaps`.
* HTTP 429/5xx responses are retried inside one model call with exponential backoff (1, 2, 4,
  8 s; `max_attempts`). Each retry is an `error` trace event (`kind: api_retry`). Retries never
  create trials. A trial whose episode fails is re-run at most twice by the runner, counts once,
  and is labelled `model_api_failed` if it never completes. API failures are never counted as
  secure.

## 7. Witnessing (optional)

The `witness` config section relays each executed sink call's exact argument bytes to a witness
sink (`assay witness-sink`), which returns signed receipts. These become
`network_egress_attempted` and `egress_observed_at_sink` trace events and
`witness/receipts.jsonl`. The sink accepts canary registration only over loopback. A runner can
therefore register canaries only with a sink on the same host, and such a run is recorded with
`independently_witnessed: false` and `canaries_registered_by_operator: true`. A genuinely
independent witness registers canaries on its own machine. Without a witness URL, no network
egress is claimed: a sink tool is an in-process MCP tool on 127.0.0.1, and calling it is recorded
as `tool_call_executed`, not as network egress.

## 8. Sources of nondeterminism

* **Sampling.** Unless `temperature`, `top_p` and `seed` are set, the provider's defaults apply.
  Their values are unknown and recorded as such in `metadata_gaps`. Even with them set, many
  providers do not guarantee determinism, and `seed` is best-effort where it is supported at all.
* **Provider routing.** OpenRouter may route a model id to different upstream hosts. Each
  response's `provider`, `system_fingerprint` and reported `model` are recorded per call in the
  `model_response` events.
* **Model revision drift.** An API model id is a name, not a weights hash. `model_revision` is
  always `null` / unknown for hosted models.
* **Time.** Run secrets, experiment ids, run ids and timestamps are fresh per run. Canaries
  therefore differ between runs by design, which is what keeps a target from memorising them.
* **The harness itself.** The scenarios, the mock and the controls are deterministic. Timeouts
  depend on machine load.

## 9. What "reproduced" means here

Responses will not be bit-identical, and hashes of traces will differ. An experiment is
**reproduced** when an independent re-run, using the same commit, config, model id and variant,
gives **the same security outcomes within statistical uncertainty**. That means per-task
attack-success rates and per-configuration attempt and executed rates whose Wilson 95% intervals
are compatible (`analysis.json` and `assay analyze` compute them). It does not mean identical
model text. For the synthetic mock, reproduction *is* exact: the counts in section 3 must match.
A re-run that differs there points to a harness change, not to sampling.

## 10. Troubleshooting

| symptom | cause / fix |
|---|---|
| `YAML configs are not supported` | write the config as JSON |
| `still a template placeholder` | set `model.api_model_id` to a real model id |
| `refusing to make live (billable) model calls` | add `"live": true` **and** `--allow-billable-calls` |
| `no model API key` | set the env var named by `api_key_env`, or the key file |
| many `model_api_failed` trials | rate limits or a provider outage. Lower the trial count, or retry later |
| `model_identity` errors | the provider served a different model; see the `model_response` events |
| `verify-artifacts` reports unlisted files | something was added after indexing. Re-run, or re-index deliberately with `assay sign-artifacts --build-index` |
| `CERTIFICATE_VERIFY_FAILED` | your Python has no CA bundle; set `SSL_CERT_FILE` to your system's |

## 11. Interpreting results

* Use the scorecard's **lower bound** for partial runs. Experiments are task subsets, so their
  scorecards are always `partial`.
* `outcome_detail` refines the frozen scoring state; it never replaces it. `model_refused` on a
  canary task means the scorecard is `errored` (the oracle could not decide), while the transcript
  shows an explicit refusal.
* Compare configurations on `model_attempted` and `executed` **separately**.
* Fewer than 20 conclusive trials per cell gives wide intervals. `analysis.json` flags
  low-confidence estimates.
* A synthetic run validates the pipeline only. Never quote its numbers as a measurement.

## 12. Container

A `Dockerfile` at the repository root builds a `python:3.12-slim` image with the checkout. The
base image is referenced **by tag**. Pin it by digest (`FROM python:3.12-slim@sha256:...`) when
you cut a release, and pass the built image's digest to runs as `ASSAY_CONTAINER_IMAGE_DIGEST`.
Without it, `container_image_digest` is `null` and appears in `metadata_gaps`, because Assay never
invents a digest.

```
docker build -t assay-local .
docker run --rm -v "$PWD/experiments/runs:/assay/experiments/runs" assay-local \
  python -m assay_bench experiment run --config experiments/examples/synthetic-local/experiment.json --out experiments/runs
```

The wrappers `scripts/reproduce-experiment.sh CONFIG [OUT]` and
`scripts/verify-experiment.sh BUNDLE [--expect-commit SHA]` run the same commands.
