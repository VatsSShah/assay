# Assay evidence format: traces, bundles, signatures, redaction

This document specifies what an Assay experiment directory contains and how an independent
researcher checks it **offline, without trusting the author**. Code:
[`src/assay_bench/trace.py`](../src/assay_bench/trace.py),
[`src/assay_bench/bundle.py`](../src/assay_bench/bundle.py),
[`src/assay_bench/redaction.py`](../src/assay_bench/redaction.py).

> **What verification establishes, and what it does not.**
> A passing `verify-artifacts` shows that the files are exactly the ones the artifact index
> lists, that they agree with each other, and, if the index is signed, that the holder of the
> signing key vouches for this index. That is **integrity relative to the signer**. It is
> **not proof that the experiment occurred**, that the named model was the one queried, or that
> nothing was left out before indexing: an author can fabricate a whole directory, index it and
> sign it. Only receipts from an independently operated witness (see
> [`INDEPENDENT_WITNESS_GUIDE.md`](INDEPENDENT_WITNESS_GUIDE.md)) or an independent rerun narrow
> that gap, and the verifier reports the witness check separately for exactly that reason.

All commands assume a source checkout and the repository convention
`PYTHONPATH=src python -m assay_bench ...`.

---

## 1. Traces: schema `assay/trace/1`

`configurations/<name>/traces.jsonl` holds one JSON object per line, one event per line, for
every trial of that configuration. Every event has every field below:

| field | meaning |
|---|---|
| `schema` | always `assay/trace/1` |
| `event_id` | `<trial_id>#<seq:04d>` |
| `trial_id` | `<run_id>:<task_id>:<trial_index>` |
| `seq` | 0, 1, 2, ... within a trial, with no gaps |
| `timestamp` | timezone-aware UTC ISO-8601; never goes backwards within a trial |
| `type` | one of the event types below |
| `actor` | `user`, `operator`, `harness`, `model`, `tool`, `attacker`, `environment`, `witness` |
| `source`, `destination` | e.g. `mcp:search_runbook`, `https://...`; or null |
| `content` | the (possibly redacted) JSON content; null if only a reference is kept |
| `content_ref` | pointer to content kept elsewhere, or null |
| `content_sha256` | SHA-256 of the canonical JSON of the **original, pre-redaction** content |
| `redacted` | true if `content` differs from the original |
| `parents` | causal parents: ids of **earlier** events in the same trial |
| `prev_hash` | `event_hash` of the previous event in the trial; 64 zeros for `seq` 0 |
| `event_hash` | SHA-256 of the canonical JSON of the event without `event_hash` |

Canonical JSON everywhere in Assay is
`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`,
with NaN and Infinity forbidden.

### Event types

`user_request`, `agent_config`, `tools_exposed`, `payload_delivered`, `model_response`,
`model_output_contains_canary`, `tool_call_requested`, `tool_call_blocked`,
`tool_call_executed`, `tool_result`, `tool_error`, `network_egress_attempted`,
`network_egress_blocked`, `egress_observed_at_sink`, `validation`, `error`, `final_response`.

### The five-way distinction

Five of those types record **different** security outcomes, and are never merged:

| # | event type | what it means | what it does NOT mean |
|---|---|---|---|
| 1 | `model_output_contains_canary` | the model **generated** the dangerous string (in prose or in arguments) | that it asked for anything to be done with it |
| 2 | `tool_call_requested` | the model **requested** a tool call | that any tool ran it |
| 3 | `tool_call_executed` | a tool **accepted and executed** the call | that anything left the machine |
| 4 | `network_egress_attempted` | the harness **transmitted** bytes to a destination | that they arrived anywhere |
| 5 | `egress_observed_at_sink` | the bytes **arrived** at a controlled destination | that the destination's operator is independent (see the receipt's `independent` and the verifier's trust source) |

A model can do (1) and never (2). A confirmation control can refuse (3) after (2)
(`tool_call_blocked`). A sandbox can stop (4) after (3) (`network_egress_blocked`). Only a sink
can speak to (5), and only an independent one says anything the author could not have written.
Reporting a (1) as a (5) would overstate a finding by up to four steps, so the trace keeps them
apart and the consistency rules below enforce their order.

### Consistency rules (`check_trace`)

`check_trace(events, known_tools=None, expect_trial_id=None)` returns human-readable problems; an
empty list means consistent. It flags:

* `seq` not increasing from 0 without gaps; duplicate `event_id`s; `event_id` not matching
  `<trial_id>#<seq:04d>`; a `trial_id` that conflicts with the event id or with `expect_trial_id`;
* unknown `schema`, `type` or `actor`; missing fields; timestamps that go backwards;
* hash chain breaks (`prev_hash`) and `event_hash` mismatches; `content_sha256` that does not
  match unredacted content;
* a parent that does not exist, or that is the event itself or a **later** event;
* `tool_call_executed` for a tool not in `tools_exposed` (or not in `known_tools`). A *request*
  for an unexposed tool is not a problem: a model can hallucinate a tool name, and an honest trace
  records that request answered by a `tool_error` or a block;
* `tool_call_executed` / `tool_call_blocked` without a `tool_call_requested` parent;
* `tool_call_requested` with no `tool_call_executed`, `tool_call_blocked` or `tool_error` child
  ("requested but no execution outcome recorded");
* `network_egress_attempted` without a `tool_call_executed` ancestor;
* `egress_observed_at_sink` without a `network_egress_attempted` ancestor, unless its content
  says `observed_independently: true`;
* a `validation` with `fired: true` and a `canary_digest`, where no `tool_call_requested`
  carries that digest (in any of the oracle's four frozen encodings). A fired validation on the
  canary oracle with no digest at all is also flagged; protocol and behavioral oracle decisions
  are not checkable from the trace and are not flagged.

**Limit of the hash chain.** The chain detects accidental edits, deletion and reordering. It does
not protect against the author: anyone can recompute an unsigned chain end to end, so a
fabricated trace with a correct chain is indistinguishable from a recorded one. A test asserts
this limit (`tests/test_trace_consistency.py`, `test_the_chain_does_not_protect_against_its_author`).

---

## 2. Bundle layout

```
experiments/<context>/<experiment_id>/
  experiment.json                         # assay/experiment-manifest/1
  config.json                             # the configuration actually used (redacted)
  configurations/<name>/scorecard.json    # the Assay scorecard from runner.run
  configurations/<name>/trials.json       # assay/raw-trials/1, + trial_id, outcome_detail
  configurations/<name>/traces.jsonl      # assay/trace/1 events for every trial
  witness/receipts.jsonl                  # optional, assay/witness-receipt/1
  witness/trusted_keys.json               # optional, public keys only
  analysis.json, REPORT.md                # generated analysis
  redaction_report.json                   # assay/redaction-report/1
  artifact_index.json                     # assay/artifact-index/1
  artifact_index.sig.json                 # optional, assay/artifact-signature/1
```

`experiment_id` matches `^exp-\d{8}-[0-9a-f]{8}$`.

### Artifact index: `assay/artifact-index/1`

```json
{"schema": "assay/artifact-index/1",
 "experiment_id": "exp-20261029-0a1b2c3d",
 "created_at": "2026-10-29T10:00:00+00:00",
 "files": [{"path": "configurations/baseline/scorecard.json", "sha256": "<64 hex>", "bytes": 1234}],
 "note": "integrity relative to whoever produced/signed this index; not proof the experiment occurred"}
```

`files` is sorted by path, lists every file in the directory except the index and its signature,
and uses relative POSIX paths only. Building an index refuses symlinks and special files, and
deletes any existing signature (which was over an earlier index).

### Signature: `assay/artifact-signature/1`

```json
{"schema": "assay/artifact-signature/1", "algorithm": "ed25519",
 "public_key": "<64 hex>", "value": "<128 hex>", "signer": "<label>",
 "index_sha256": "<sha256 of the canonical JSON of the index>"}
```

The signed message is `b"assay/artifact-index/1\x00"` followed by the canonical JSON of the
index. The domain tag means a signature over an index can never be replayed as a signature over
anything else Assay signs. `signer` is a self-declared label, not an identity. A valid signature
by an **unpinned** key shows only that whoever holds that key signed this index: an attacker
who rewrites the files can re-index and sign with their own key. Pin the key you expect.

---

## 3. Verification

```
PYTHONPATH=src python -m assay_bench verify-artifacts experiments/<context>/<experiment_id> \
    --expect-public-key <signer public key hex> --require-signature \
    --expect-commit <repository commit> --trusted-witness-keys <your trusted_keys.json>
```

It prints a JSON object with `ok`, `experiment_id`, `failed`, `establishes`,
`does_not_establish` and every named check, and exits 0 if all pass, 1 if any fails, 3 if the
index or signature cannot be parsed at all. It never contacts the network and never executes
anything from the bundle. The checks:

| check | what it verifies |
|---|---|
| `index_schema` | schema, experiment id pattern, entry shape, 64-hex hashes, sorted unique paths |
| `path_safety` | no absolute paths, `..`, `.`, empty components, NUL, backslashes, or symlinks resolving outside the bundle |
| `size_caps` | every file within 200 MB (JSON documents are parsed under a 50 MB cap) |
| `files_match_index` | every listed file exists and its size and SHA-256 match |
| `no_unlisted_files` | nothing in the directory is missing from the index; an unindexed file is unverified, and a symlink is reported |
| `signature` | the signature verifies over this exact index and, if `--expect-public-key` is given, was made by that key; required if `--require-signature` |
| `experiment_manifest_valid` | `experiment.json` passes `experiment.validate_experiment_manifest`; fails with "validator unavailable" if that module cannot be imported, never a silent pass |
| `experiment_id_consistent` | the id agrees across `experiment.json` and the index; each scorecard's and trial log's `run_id` matches its configuration's run; every traced trial belongs to its configuration's run |
| `scorecards_verify` | every scorecard reaches `internally_consistent` under the existing `assay_verifier` |
| `trial_counts_consistent` | `trials_executed` = trial records = distinct traced trials; `trials_scheduled` = `trials_per_task` x tasks in the scorecard |
| `traces_consistent` | `check_trace` passes for every trial |
| `traces_match_trials` | every trial record has a trace and vice versa; a trial recorded `exploited` has a fired `validation` event, and a fired validation is recorded `exploited` |
| `repository_commit` | `experiment.json` declares the commit given by `--expect-commit` (prefix of at least 7) |
| `witness_receipts` | if `witness/receipts.jsonl` exists: every receipt verifies under `witness_receipt.verify_receipts` against the trusted keys, with no replays, and is about a trial in this bundle |

Members are parsed only if their bytes match the index; reasoning about unverified bytes would
report conclusions about the wrong file.

**Trust source for witness keys.** `witness/trusted_keys.json` inside the bundle is controlled by
the operator: it is the author's own claim about whom to trust, so a pass against it shows only
that the receipts are self-consistent with keys the author chose. When the verifier falls back to
it, the check's detail says `OPERATOR-SUPPLIED key file`. Real trust comes only from keys you
obtained independently and pass from outside the bundle with `--trusted-witness-keys` (the
detail then says the keys came from outside the bundle), or from pinning a witness key with
`assay verify-witness --expect-public-key`. With no trust anchor at all, receipt verification
fails closed.

### Signing

```
ASSAY_ARTIFACT_KEY=<64 hex seed> PYTHONPATH=src python -m assay_bench sign-artifacts \
    experiments/<context>/<experiment_id> --signer "<label>" [--build-index]
```

The key is read from `$ASSAY_ARTIFACT_KEY` only, never from an argument (arguments land in shell
history and process listings). Mint one with `assay witness-key`. Signing refuses an index that
no longer matches the directory; `--build-index` rebuilds it from the current contents first,
using the experiment id in `experiment.json`.

---

## 4. Redaction

```
PYTHONPATH=src python -m assay_bench redact IN.jsonl OUT.jsonl [--preserve VALUE ...] [--report PATH]
```

`IN` may be `.json` or `.jsonl`. Every string (object keys included) is scanned, including the
JSON-encoded strings that tool-call arguments arrive as, and the result still parses.

**Markers.** A match is replaced by `[REDACTED:<kind>:<first 12 hex of sha256(value)>]`. The
same value always gets the same marker, so a reader can see that two occurrences are the same
secret without learning it. Kinds: `api_key` (`sk-...` including `sk-proj-`, `sk-or-v1-`,
`sk-ant-`; `AIza...`; `ghp_`/`gho_`/`github_pat_`; `xox[bpoas]-`), `aws_access_key`
(`AKIA`/`ASIA` + 16), `bearer_token` (the token after `Bearer`), `jwt`, `private_key` (PEM
blocks), `email` (except `example.com/.org/.net` and the `.invalid`, `.test`, `.example`,
`.localhost` TLDs), `env_value` (values of at least 8 characters of environment variables whose
name contains `KEY`, `TOKEN`, `SECRET` or `PASSWORD`, read at redaction time), and
`configured_secret` (exact values the caller supplies). Home directories become
`/Users/<redacted>/`, `/home/<redacted>/`, `C:\Users\<redacted>\`.

**Canaries are preserved.** Assay's canaries are deliberately secret-shaped (`sk-...`, `AKIA...`,
JWTs). Anything in the preserve list, and any match that overlaps a preserved value (an envelope
that contains a preserved digest), is left verbatim. The `redact` command automatically
preserves 16-hex digests found under `canary_digest`, `canary_id` or `digest` keys in the input,
so redacting a trial log or a trace cannot erase the evidence its findings rest on.

**Reproducibility impact** (also stated in the report's `impact` field):

* A trace event's `content_sha256` is over the **original** content. After redaction a reader
  can still verify the hash chain and every unredacted event, but can re-verify a redacted
  event only if given its original (`trace.verify_content(event, original)`).
* Redacting a trace file rewrites the redacted events, so `assay redact` re-seals each trial's
  chain. The new chain does **not** match an index or signature made over the unredacted file.
  Redact before indexing and signing.
* Markers are **unkeyed** hash prefixes. A low-entropy value (an e-mail address, a username)
  can be confirmed by anyone who guesses it and hashes the guess.
* Canary correspondence stays re-checkable because canary values and digests are preserved.
* Redaction is pattern-based. A secret in a shape it does not recognise (an AWS *secret* key,
  a password in prose, a key split across strings) may remain. The report is not a guarantee
  that the artifact contains no secret.

The report (`assay/redaction-report/1`) contains `counts` per kind, `total`,
`preserved_matches` (candidate matches left visible because they overlap evidence),
`env_var_names_matched` (names only, never values), `marker_format` and `impact`.
