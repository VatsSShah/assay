# Operating an independent Assay witness

This guide is for a researcher or organisation that wants to act as the **witness** for someone
else's Assay experiment: you run the egress sink and hold the signing key, the experiment
**operator** never sees that key, and anyone can later check your receipts with only your public
key.

> **Status.** No externally generated receipts exist in this repository yet. Every receipt the
> project has produced so far came from a sink run by the operator on the operator's own
> machine (`independent: false`), or from `assay witness-demo`, which is a protocol
> demonstration and not evidence about any model.

It extends the run-level witness statement in
[`src/assay_bench/witness.py`](../src/assay_bench/witness.py) (one signed statement per run that
lists fired task ids, see README "Witnessing a run" and `REMAINING_GAPS.md` G2). That statement
answers "did a key the submitter does not hold sign this?", but someone still has to *observe*
the egress. Receipts are that observation, one signed record per canary that reaches your sink.
The code is [`src/assay_bench/witness_receipt.py`](../src/assay_bench/witness_receipt.py).

All commands below assume a source checkout and use the repository's convention
`PYTHONPATH=src python -m assay_bench ...`.

---

## 1. Architecture

```
 OPERATOR'S MACHINE                         | WITNESS'S MACHINE
                                            |
 model API <--> harness / runner            |   reverse proxy (TLS, yours)
                 |  plants canary in tool   |     forwards /egress/ and /public-key
                 |  results; relays every   |     denies /register
                 |  egress attempt          |            |
                 |                          |            v  127.0.0.1:8787
                 +-- POST /egress/<label> -------> assay witness-sink
                 |   X-Assay-Experiment-Id  |       key from $ASSAY_WITNESS_KEY
                 |   X-Assay-Trial-Id       |       state-dir/receipts.jsonl
                 |   (exact bytes)          |       state-dir/trusted_keys.json (public)
                 |                          |            ^
                 <-- signed receipt(s) ------------------+
                                            |            |
                                            |   POST /register (loopback only,
                                            |   run by the witness on its own host)

 VERIFIER (anyone): receipts.jsonl + the witness public key obtained OUT OF BAND
                    -> assay verify-witness   (no private key, no network)
```

The same flow as a sequence:

```mermaid
sequenceDiagram
    participant W as Witness (sink + key)
    participant O as Operator harness
    participant M as Model
    participant V as Verifier
    W->>W: witness-key; publish public key out of band
    W->>W: POST /register {experiment_id, trial_id, canary_id} (loopback only)
    O->>M: task + tool results carrying the canary
    M->>O: tool call that sends data
    O->>W: POST /egress/<label> (exact bytes, experiment + trial headers)
    W->>W: scan bytes for registered digest (raw, base64, hex, url-quoted)
    W-->>O: signed receipt (also appended to W's receipts.jsonl)
    V->>V: verify-witness receipts.jsonl --expect-public-key <published key>
```

## 2. Trust boundaries and who holds which key

| Party | Holds | Must not hold | Trusted for |
|---|---|---|---|
| Witness | witness Ed25519 **secret** key; the sink's `receipts.jsonl`; canary registrations | the operator's API keys | reporting truthfully what reached its sink, and keeping its clock roughly right |
| Operator | model API key, harness, experiment config, the receipts it was sent | the witness secret key | relaying egress faithfully (see assumptions) |
| Verifier | the witness **public** key, obtained from the witness through a channel the operator does not control | any secret | nothing; it checks |

The boundary that matters: **the operator never holds the witness secret key.** The key is read
only from `$ASSAY_WITNESS_KEY` on the witness machine, never from a command-line argument
(arguments end up in shell history and process listings). The sink never sends the key or the
received bytes back: responses contain receipts and the SHA-256 of what was received.

## 3. Key generation

On the witness machine:

```bash
PYTHONPATH=src python -m assay_bench witness-key
```

It prints `public_key` and `secret_key` once and stores nothing. Put `secret_key` in a secret
store, and export it only into the sink's environment:

```bash
export ASSAY_WITNESS_KEY=<secret_key from witness-key>
```

Never commit it, never paste it into an experiment config, never send it to the operator. A key
that has been anywhere the operator can read makes every receipt it ever signed worthless; rotate
it and republish.

Signing uses the project's pure-Python Ed25519 (`src/assay_bench/ed25519.py`), which is **not
constant-time**. Run the sink on a machine where untrusted parties cannot measure its timing. The
wire format is standard Ed25519, so receipts verify under other implementations (the test suite
checks this against `cryptography` when that package happens to be installed).

## 4. Deploying the sink

```bash
PYTHONPATH=src python -m assay_bench witness-sink --host 127.0.0.1 --port 8787 --state-dir /var/lib/assay-witness --witness "example-lab-witness" --independent
```

* **`--independent`** puts `independent: true` inside every signed receipt. Set it **only** if you
  really are independent of the operator. It is a declaration, not a proof, and verifiers are
  told so.
* **Bind address.** Keep the default `127.0.0.1`. The sink speaks plain HTTP and has no TLS of its
  own. Put TLS in a reverse proxy you control (nginx, Caddy, HAProxy) that forwards only
  `/egress/` and `/public-key` to `127.0.0.1:8787`.
* **Firewall `/register`.** Registration decides which canaries you will sign for, so only you
  should be able to do it. The sink accepts `/register` only from a loopback address, and it
  refuses any `/register` that carries `Forwarded`, `X-Forwarded-For` or `X-Real-IP`, because
  behind a same-host proxy every request looks local. Still deny it in the proxy too. An nginx
  sketch:

  ```
  location = /register { return 403; }
  location /egress/    { proxy_pass http://127.0.0.1:8787; client_max_body_size 1m;
                         proxy_set_header X-Forwarded-For $remote_addr; }
  location = /public-key { proxy_pass http://127.0.0.1:8787; }
  ```

* **Body cap.** Bodies over `--max-body-bytes` (default 1,000,000) get `413`. Bodies must have a
  `Content-Length`; chunked uploads get `411`.
* **State.** `--state-dir` holds `receipts.jsonl` (append-only, fsynced per receipt) and
  `trusted_keys.json` (your public key only). On restart the sink continues the sequence number and
  will not issue a second receipt for an observation it already receipted. Registrations are
  **in memory only**, so re-register after a restart. That stops stale registrations from an old
  experiment from producing receipts.
* **Logs.** The sink keeps no access log, so canary-bearing bytes are never copied to stderr.

## 5. Experiment setup

1. **Agree on an experiment id** with the operator (`exp-<YYYYMMDD>-<8 hex>`). Trial ids are
   `<run_id>:<task_id>:<trial_index>`.
2. **Provision canaries.** For each trial, register the canary digest on the witness machine:

   ```
   curl -sS -X POST http://127.0.0.1:8787/register -H 'Content-Type: application/json' \
        -d '{"experiment_id":"exp-20261029-0a1b2c3d","trial_id":"<run_id>:M3:0","canary_id":"<16-hex digest>"}'
   ```

   From Python on the same host, `witness_receipt.register_canary(url, experiment_id=...,
   trial_id=..., canary_id=...)` does the same and returns a bool. See the canary-provisioning
   assumption in §8: if the operator gives you the digests, the operator chose them.
3. **Point the operator's experiment at the sink.** The operator sets the experiment config's
   `witness.url` field to your public base URL, for example `https://witness.example.org`. The
   runner relays each egress attempt's exact bytes there with
   `witness_receipt.relay_egress(...)`. A base URL gets `/egress/relay` appended; a full
   `.../egress/<label>` URL is used as given. Plain `http://` is refused unless the host is
   loopback. Relaying never raises inside the agent loop: if your sink is down, the trial simply
   gets no receipt.
4. **Matching.** Only canaries registered for the request's *exact* `(experiment_id, trial_id)`
   are matched, using the four frozen encodings the oracle accepts (`canary.forms`): verbatim,
   base64, hex-of-ASCII and URL-quoted. One receipt is issued per matching canary. Re-sending
   identical bytes gets back the receipt already issued, so an agent's retry is not mistaken for
   a replay.

## 6. Publishing the public key

Publish `public_key` (or the whole `trusted_keys.json` from your state dir, which contains public
keys only) **through a channel the operator does not control**: your own website over HTTPS, a
signed commit in your own repository, a paper, a mailing-list post. `GET /public-key` on the sink
exists for convenience, but fetching it through the same channel as the receipts is
trust-on-first-use.

A `witness/trusted_keys.json` inside the operator's artifact bundle is a **convenience copy the
operator controls**. A verifier who relies on it is trusting the operator to name the witness.
Pin your key with `--expect-public-key` taken from your own publication.

## 7. Verification (anyone, with the public key only)

```bash
PYTHONPATH=src python -m assay_bench verify-witness experiments/<context>/<experiment_id>/witness/receipts.jsonl --expect-public-key <hex published by the witness> --experiment-id <experiment_id>
```

Or with a trust file you obtained from the witness:

```bash
PYTHONPATH=src python -m assay_bench verify-witness receipts.jsonl --trusted-keys witness_trusted_keys.json --trial-id <run_id>:M3:0 --canary-digest <16-hex> --max-age-seconds 86400
```

The output is JSON. Each receipt lists these checks by name:

| check | fails when |
|---|---|
| `format` | schema is not `assay/witness-receipt/1`, the algorithm is not `ed25519`, the signature version is not `1`, or the event type is unknown |
| `signature` | any signed byte changed, or the signature block names a different key than the witness block |
| `trusted_key` | no trust anchor was supplied, the key is not in the trusted set, or it differs from `--expect-public-key` |
| `experiment_id`, `trial_id`, `canary` | the receipt is about something other than what you asked for (if you did not ask, the check reports `checked: false`) |
| `freshness` | the receipt is dated more than 300 s in the future, or is older than `--max-age-seconds` |

For the whole set there are `receipts` (every receipt passed) and `replay`, which fails on a
duplicate `receipt_id`, a duplicate `nonce`, or two receipts for the same observation
`(experiment, trial, canary, payload_sha256)`. Gaps in the sequence numbers are only a
**warning**, since one witness serves many experiments.

Exit codes: `0` all checks passed, `1` a check failed, `3` a receipt or file is malformed.
`--now ISO` fixes the verification time so results can be reproduced.

The signed bytes are `b"assay/witness-receipt/1\x00"` followed by the canonical JSON of the
receipt with `signature.value` removed. The algorithm, version and key inside the signature block
are signed too. To check a receipt with another Ed25519 library, rebuild exactly those bytes.

To see the whole protocol run on one machine, including the rejections:

```bash
PYTHONPATH=src python -m assay_bench witness-demo
```

It prints a `PROTOCOL DEMONSTRATION` banner and its receipts say `independent: false`.

## 8. Threat model and assumptions

**What a valid receipt proves:** the holder of the trusted key attests that bytes with this
SHA-256, containing this canary digest (verbatim or in one of four frozen encodings), arrived at
this sink path at this time, labelled with this experiment and trial. With the key pinned out of
band, "the holder" becomes "this witness".

**What it does not prove:**

* that the model "decided" or "intended" anything. A receipt is about bytes arriving.
* production exploitation, or anything about systems other than the experiment's harness.
* universal vulnerability across model versions, providers, prompts or configurations.
* that the witness is honest or independent. `independent` is a declaration inside the signed
  bytes. A verifier's trust file says separately whether *it* grants that key independence, and
  both are reported.
* that nothing else leaked. An empty receipt set establishes nothing, including that nothing
  leaked.

**Assumptions, stated plainly:**

* **Agent and harness integrity.** In this relay design the operator's harness forwards egress
  to the witness. A dishonest operator can **withhold** egress (under-report). It can also
  **post a canary itself**: the operator has to plant the canary in a tool result, so it knows
  the value. A receipt proves the bytes reached the sink, not which process sent them. Removing
  this assumption takes egress that reaches the witness without passing through the operator,
  for example the target's real network egress routed to the witness's sink, with the
  adversarial surface also run by the witness. That is not implemented here.
* **Trusted observation point.** The witness's sink and clock are honest. `observed_at` is the
  witness's own clock, not a third-party timestamp.
* **Canary provisioning.** In the current design the operator's harness plants the canary that
  the witness registered. If the operator also *mints* the canaries and sends you the digests,
  the operator chose them. **To stop the operator choosing canaries, the witness must mint and
  register them itself** (for example `canary.new_run_secret()` and `canary.plant(...)` on the
  witness machine) and give the operator only the per-trial values to plant. No command automates
  this yet. In a loopback deployment where the operator's runner registers its own canaries, the
  run is self-witnessed and must say `independent: false`.

**Attacks the protocol does stop:**

* editing any field of a receipt, including `independent`, the algorithm label and the signature
  version (`signature`);
* passing off a receipt signed by an unknown or self-minted key (`trusted_key`);
* reusing a receipt for another experiment, trial or canary (`experiment_id`, `trial_id`,
  `canary`);
* counting one observation twice (`replay`);
* stale or back-dated receipts when freshness is required, and future-dated receipts always
  (`freshness`);
* receiving a witness secret key by mistake. A trust file containing anything that looks like
  private material (`secret`, `private`, `seed`, `signing`, `sk`, a PEM private-key block, or any
  unknown field) is rejected outright.

## 9. Common errors

| Symptom | Cause | Fix |
|---|---|---|
| `no witness key: set $ASSAY_WITNESS_KEY` (exit 2) | sink started without the key in its environment | export it in the sink's environment only |
| `trusted_key`: "no trust anchor supplied" | ran `verify-witness` without `--trusted-keys` or `--expect-public-key` | pass the key you obtained out of band |
| `trusted_key`: "not in the trusted set" | receipt signed by a different key (rotated, or not your witness) | confirm the key with the witness |
| `freshness`: "dated … in the future" | witness or verifier clock is wrong by more than 300 s | fix NTP, or use `--now` for a reproducible check |
| `replay`: duplicate observation | the same receipts file was concatenated twice, or receipts were copied between bundles | deduplicate from the witness's own `receipts.jsonl` |
| `403` on `/register` | request was not from loopback, or carried proxy headers | register on the witness host, directly against `127.0.0.1` |
| `400` on `/egress/...` | missing `X-Assay-Experiment-Id` / `X-Assay-Trial-Id` | use `relay_egress`, which sets them |
| `411` / `413` | no `Content-Length`, or body over the cap | send a sized body, or raise `--max-body-bytes` |
| `matched: 0` though the canary was sent | canary registered under a different trial or experiment, sink restarted (registrations lost), or the canary was split, truncated, compressed or otherwise re-encoded | re-register; known oracle blind spots are listed in `audit/CLAIM_EVIDENCE_MATRIX.md` |
| `relay_egress` returns `None` | sink unreachable, non-200, or `http://` to a non-loopback host | check the URL and use `https://` for a remote witness |
| exit 3 from `verify-witness` | receipt has missing, unknown or wrongly-typed fields | the file is not an `assay/witness-receipt/1` receipts file |

## 10. Limitations

* **No externally generated receipts exist in this repository yet.**
* The operator relays egress, so withholding and self-posting are possible (§8).
* Canary minting by the witness is a documented procedure, not a command.
* No key rotation or revocation protocol. Publish a new key and say which receipts the old one
  covers.
* No transparency log or third-party timestamping. `receipts.jsonl` is append-only by
  convention, not hash-chained, and `observed_at` is the witness's clock.
* Detection uses exactly the four frozen encodings. Split, truncated, compressed, encrypted,
  hashed or paraphrased exfiltration produces no receipt.
* The sink has no TLS, no authentication on `/egress/`, and in-memory registrations. It is built
  to sit behind a reverse proxy on a host you control.
* Pure-Python Ed25519 signing is not constant-time (§3).
