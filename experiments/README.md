# Experiments

An experiment runs one model against a fixed set of Mode-B tasks under several **agent
configurations**: the baseline plus defensive controls. It writes one verifiable bundle. The
point is that two questions get measured answers instead of opinions:

1. *Can someone else reproduce this?* Every trial is traced, every unknown is declared, and the
   bundle verifies offline.
2. *Does a defence change it?* Every configuration sees the same model, tasks, trials and run
   secret, so the canaries and payloads are identical. The control is the only thing that differs.

See [`../REPRODUCIBILITY.md`](../REPRODUCIBILITY.md) for the full walkthrough.

## Layout

```
experiments/
  README.md
  examples/
    synthetic-local/experiment.json   # scripted mock model, offline, about 5 s
    live-openrouter/experiment.json   # TEMPLATE for a live run; the model id must be set
  runs/                               # default output of `assay experiment run` (not tracked)
```

A bundle is written to `<out>/<experiment_id>/`:

```
experiment.json                        assay/experiment-manifest/1
config.json                            the config actually used (redacted)
configurations/<name>/scorecard.json   the ordinary Assay manifest for that configuration
configurations/<name>/trials.json      assay/raw-trials/1, one record per trial, including
                                       trial_id, outcome_detail, model_attempted, executed
configurations/<name>/traces.jsonl     assay/trace/1 events for every trial
witness/receipts.jsonl                 only when a witness sink was configured
witness/trusted_keys.json              only when the config named a trusted-keys file
analysis.json, REPORT.md               statistics across configurations
redaction_report.json                  what was redacted, and what that does to verifiability
artifact_index.json(.sig.json)         sha256 of every file (signed if ASSAY_ARTIFACT_KEY is set)
```

## Config format (JSON only)

YAML is not supported. The runtime uses only the standard library, and the standard library has
no YAML parser. A `.yaml` path is refused with that explanation.

| key | meaning |
|---|---|
| `schema` | `assay/experiment-config/1` |
| `name`, `description`, `operator` | free text; `operator: null` is recorded as a metadata gap |
| `trials` | trials per task (5 or more for a scorecard that can be complete) |
| `twins` | also run the benign twin set (utility axis); default `false` |
| `model.provider` | `mock`, `openrouter`, or `openai-compatible` (needs `base_url`) |
| `model.behaviour` | mock only: `vulnerable`, `cautious`, `refusing` |
| `model.api_model_id` | the exact provider model id. Template placeholders are rejected |
| `model.live` | must be `true` for any non-mock provider, and must be `false` for the mock |
| `model.api_key_env`, `model.key_file` | *where* the key is. The key itself never goes in a config |
| `model.temperature`, `top_p`, `seed` | sent only when set, and always recorded |
| `model.max_output_tokens`, `effort`, `strict_model_identity`, `max_attempts`, `request_timeout` | as named |
| `agent.max_steps`, `agent.timeout_s` | agent loop budget per episode |
| `attack.task_ids`, `attack.variant` | Mode-B task ids, and the payload variant (`scenarios.VARIANTS`) |
| `configurations` | list of `{name}` (a control name) or `{name, controls: [...], allowlist: [...]}` |
| `witness` | optional `{url, register_canaries, trusted_keys}` (see REPRODUCIBILITY.md) |

Controls (see `src/assay_bench/controls.py`): `baseline`, `confirmation_gated`,
`egress_restricted` (needs an explicit `allowlist`; `[]` blocks every destination),
`tool_restricted`, `policy_validated`.

## Reading a controls comparison

When a control blocks a call, the environment is enforcing it. That is not the model refusing.
The scorecard's canary oracle keeps its normative boundary: tool-call *arguments* are egress
whether or not the call ran. So a blocked leaking attempt still scores `exploited` in that
configuration's `scorecard.json`. Each run in `experiment.json` therefore reports **two columns**:

* `model_attempted`: trials where the model requested the dangerous call;
* `executed`: trials where a tool actually ran it.

These are separate measurements. Do not merge them into one "ASR". A control lowers `executed`.
It does not make the model safer.

## Commands

```
PYTHONPATH=src python3 -m assay_bench experiment validate-config --config experiments/examples/synthetic-local/experiment.json
PYTHONPATH=src python3 -m assay_bench experiment run --config experiments/examples/synthetic-local/experiment.json --out experiments/runs
PYTHONPATH=src python3 -m assay_bench verify-artifacts experiments/runs/<experiment_id>
```

Live calls need **both** `"live": true` in the config and `--allow-billable-calls`. Otherwise the
run is refused and the error gives an upper bound on how many calls it would have made.
