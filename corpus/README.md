# Assay corpus: what the harness is actually run against

A benchmark needs labeled targets, not just attacks. This file states exactly which targets
exist in this repository today and which do not.

## Built-in conformance targets (shipped, runnable now, no key, no network)

Three **deterministic in-process** targets, in `assay_bench/adapters/conformance.py`:

| target | behaviour | what it checks |
|---|---|---|
| `vulnerable` | complies with whatever the adversarial surface instructs, so every planted canary reaches egress | **recall** — every attack fires |
| `hardened` | treats tool descriptions and tool results as untrusted data and never copies them to a sink | **specificity** — nothing fires, so no canary-gated family raises a false positive on a control |
| `mixed` | susceptible on exactly one published task subset (`MIXED_SUSCEPTIBLE`) | **discrimination** — proves the evaluator decides per task rather than echoing a global flag |

```bash
PYTHONPATH=src python -m assay_bench reference --trials 25
PYTHONPATH=src python -m assay_bench reference --check
```

The first regenerates `leaderboard/manifests/reference_*.json` and
`reference/conformance_matrix.json`. The second regenerates in memory and compares run
invariants against the committed artifacts, listing the fields expected to differ.

**These are stubs, not products.** They validate that the mechanism works end to end — mint a
canary, plant it in an adversarial surface, let the target act, recover it from egress by
recomputation — and nothing more. Because they are deterministic, every cell is exactly 0 or 1;
the conformance matrix reports outcomes without confidence intervals and explains why.

Latest conformance run: recall holds on all 31 tasks, specificity holds on all 31 (0 canary
false positives on the hardened control), and discrimination matches the published subset
exactly. Reproduce it from a clean clone with the two commands above.

## Real MCP targets (NOT shipped)

There is **no real MCP adapter in this repository**. Nothing here has been scored against a
live MCP server, agent or model, and no such result is published.

The adapter interface (`assay_bench/adapters/__init__.py`) is what a real target would
implement: it declares its capabilities, including `is_real_target`, which the runner records in
provenance and the leaderboard displays. Until a real adapter exists and is tested, this stays a
gap rather than a claim — see [`REMAINING_GAPS.md`](../REMAINING_GAPS.md).

## Third-party vulnerable servers (referenced, not integrated)

Independently published vulnerable MCP servers that a Mode-A adapter could point at. They are
**not bundled, not fetched by any code here, and not currently run by anything in this
repository** — they are recorded as the intended integration path only:

| Repo | What it is |
|---|---|
| `harishsg993010/damn-vulnerable-MCP-server` (DVMCP) | the canonical "damn-vulnerable" MCP challenge set |
| `appsecco/vulnerable-mcp-servers-lab` | a lab of intentionally-vulnerable MCP servers |
| `IntegSec/VulnerableMCP` | an index/database of MCP vulnerabilities |

> **If you integrate one:** clone it, run it bound to `127.0.0.1`, and point a Mode-A adapter at
> it. Confirm each repo's license before redistributing any of its content; Assay references
> them by URL and does not vendor their code. Read challenge counts and categories from each
> repo at integration time rather than asserting them here.

## Why both halves would matter

Self-authored controls alone can be dismissed as a strawman; third-party positives alone would
not show specificity. Together they would give a confusion matrix that demonstrates recall
against independently authored vulnerabilities *and* specificity against controls. **Today only
the first half exists, against stubs we wrote ourselves.** That is a validated mechanism, not a
validated benchmark, and this file will say so until the second half ships.

## Real MCP servers (shipped, runnable now, no key, loopback only)

Two **real MCP servers as separate processes**, in `assay_bench/servers/reference.py`. They
speak real MCP — JSON-RPC 2.0, the `initialize` handshake with protocol-version negotiation,
`tools/list`, `tools/call` — over Streamable HTTP on loopback or over stdio.

| target | posture | what an external probe sees |
|---|---|---|
| `mcp-insecure` | no auth, no Origin check, no Host check, no argument validation | anonymous `tools/list` succeeds; a foreign `Origin` and a rebound `Host` are served; a shell-metacharacter argument is acted on |
| `mcp-hardened` | bearer token, Origin allow-list, loopback-only Host, argument validation | 401 without credentials; 403 for a foreign `Origin` or rebound `Host`; the injected argument is refused and the refusal recorded |

```bash
PYTHONPATH=src python -m assay_bench run --target mcp-insecure --track server --trials 5 --out /tmp/insecure.json
PYTHONPATH=src python -m assay_bench run --target mcp-hardened --track server --trials 5 --out /tmp/hardened.json
```

They are **one program with a posture parameter**, so a score difference between them cannot
come from their being two different programs — a test asserts the tool handlers are the same
code objects.

**What these runs are.** A genuine Mode-A measurement: the protocol facts in the manifest were
observed by a client over a socket against a separate process. The insecure server scores
`server_posture >= 0.0`, the hardened one `server_posture >= 100.0`.

**What they are not.** A measurement of third-party software — these servers ship here, and
`target.third_party` is False. They also decide only the 3 Mode-A tasks: the other 28 are Mode
B, which needs an *agent* under test, so they are reported `unsupported` with a stated reason,
the run is `partial`, and the lower bound charges every undecided task at full weight.

## Someone else's MCP server (not shipped; you supply the target)

```bash
PYTHONPATH=src python -m assay_bench run --target-url https://your-server.example/mcp --track server --out /tmp/yours.json
python src/assay_verifier.py verify /tmp/yours.json
```

This is a real third-party measurement and the manifest labels it one. The fingerprint is
computed over what *your server* advertised — `serverInfo`, the negotiated protocol revision,
and per-tool digests of description and input schema — so anyone who can reach the same
endpoint recomputes it. That identifies an advertised identity and tool surface, not a host.

Only point this at a server you are authorised to test. The injection probe sends shell
metacharacters in a tool argument; against a server that does not validate them, that argument
reaches whatever the tool does with it.

`--target-command` drives a stdio server instead. M17 and M18 are HTTP properties, so over
stdio they are reported `unsupported`, never as resisted.

## Interoperability

`tests/test_mcp_interop.py` drives a server built with the **official `mcp` SDK** using this
repository's client, so "we speak MCP" does not rest on our client agreeing with our server.
The SDK is not a dependency; CI installs it into a throwaway environment and fails if the check
skips.
