# Remaining gaps

What this repository still does not do, and what is blocked on a decision the audit cannot make.
Nothing here is hidden in a footnote elsewhere: every item is also reflected in README, SPEC or
`corpus/README.md`, and several are enforced by tests that would fail if the claim strengthened
without the gap closing.

---

## G1 — Real MCP: closed for Mode A, open for Mode B

**Status: Mode A closed. Mode B remains open, and is now the single most important
limitation.**

At baseline the only adapters were three deterministic in-process stubs. Nothing crossed a
process boundary, spoke a wire protocol, or could be pointed at software the harness did not
import, so every number was a property of the harness talking to itself.

### What shipped

`assay_bench.mcp` is a real MCP implementation, stdlib-only:

- `jsonrpc.py` — JSON-RPC 2.0 framing with a strict decoder (a lenient one would let a
  non-compliant server look compliant, which is what the Mode-A tasks exist to detect);
- `client.py` — the real `initialize` handshake with protocol-version negotiation,
  `tools/list`, `tools/call`, over **stdio** (subprocess, newline-delimited frames, deadline
  enforced so a silent server cannot wedge a run) and **Streamable HTTP** (including SSE
  bodies), recording what it saw on the wire;
- `server.py` — a server framework with security posture as a parameter;
- `assay_bench.servers.reference` — two real MCP servers, `insecure` and `hardened`, as
  separate processes. One program, two postures, so a score difference between them cannot
  come from their being two different programs (a test asserts the handlers are the same code
  objects).

`assay_bench.adapters.mcp_probe.MCPServerProbe` is the Mode-A adapter, `is_real_target=True`.
It decides all three Mode-A tasks from what it observed over a socket: M18 from whether an
anonymous `tools/list` returned tools, M17 from whether the server served a request carrying a
foreign `Origin` and a rebound `Host`, M6 from whether the server acted on an argument carrying
shell metacharacters.

    assay run --target mcp-insecure  --track server --trials 5 --out /tmp/insecure.json
    assay run --target mcp-hardened  --track server --trials 5 --out /tmp/hardened.json
    assay run --target-url https://your-server.example/mcp --target-token "$TOKEN" --track server

The last form is a genuine third-party measurement and is labelled as one
(`target.third_party`).

### Interoperability, so this is not our client agreeing with our server

`tests/test_mcp_interop.py` stands this client up against a server built with the **official
`mcp` SDK** and drives the handshake, negotiation, `tools/list` and `tools/call`. The SDK is
never a dependency of this package: CI installs it into a throwaway environment and the runtime
stays stdlib-only. The CI job **fails if the check skips**, because a green run with the one
external check silently skipped is the kind of green that means nothing.

### What Mode A against these servers does and does not establish

It establishes that the protocol facts in the manifest were observed by a client over a socket
against a separate process — a real handshake, real HTTP status codes, real refusals. The
insecure server scores `server_posture >= 0.0` and the hardened one `server_posture >= 100.0`,
and the two are told apart by observation alone.

It does not establish a measurement of third-party software: these servers are shipped here.
`target.third_party` is False for them and True only when an operator points the adapter at
something else.

### What is still open: Mode B

28 of the 31 tasks are Mode B: they poison a surface and score what an *agent* does with it.
That needs an agent under test — something that reads a poisoned tool description and decides.
No such target exists here, and none can be written honestly without a model to drive.

This is now enforced rather than described. `Capabilities` carries
`drives_agent_under_test` / `drives_server_under_test`; the server probe declares the second
only, so every Mode-B task is reported `unsupported` with a stated reason, the run is `partial`,
the lower bound charges every undecided task at full weight, and `badge.py` refuses it. **A
real-server run cannot be made to look like a full benchmark result.**

**What would close it:** an adapter driving a real agent (an LLM with MCP tool access) against
the adversarial surface, with a defined egress capture boundary.

---

## G2 — A keyholder can still fabricate a passing manifest

**Status: open by construction. Not fixable by any document check.**

`observed` is submitter-supplied text and the submitter holds the run secret. Compute the digest,
paste it into an invented string, and the verifier confirms it. `run_complete` forces a
fabrication to cover all 31 tasks, which raises the cost slightly and nothing more.

Mitigations that exist: the limit is stated in the verifier docstring, README's first table, SPEC
§4.2, SUBMIT.md and the leaderboard page; it is pinned as a *passing* test
(`test_a_full_catalog_fabrication_also_reaches_run_complete`); and the only artifact that
addresses it — an independent maintainer rerun — is kept in a separate, repository-controlled
place.

The adjacent problem, **under-reporting**, is now unprofitable even though it remains
undetectable. Scores use the frozen catalog's weight total as the denominator, and every manifest
carries a lower bound charging each unreported, unsupported or inconclusive task at full weight.
Omission can never raise that number: dropping a fully-exploited task leaves it unchanged,
dropping any task that resisted strictly lowers it. Cherry-picking therefore gains nothing. That
is a smaller claim than detection, and it is the one that holds.

**What would reduce it, and the first piece that now exists.** The reductions named are a
trusted execution path or evidence from the target side. The Mode-A path now has the second in
embryo: the reference servers keep their own action log, written by the code that performs an
action rather than by the client that asked for it, and `MCPServerProbe` **cross-checks** its
own observation against it. A disagreement makes the trial inconclusive instead of letting
either side win — a test drives exactly that case.

This is honest about its own scope. It only applies where the operator controls the server, it
is not signed, and a submitter who controls both sides controls both accounts. It reduces
nothing for a Mode-B submission, which is where the fabrication concern actually bites. The
general problem stands.

---

## G3 — Not on PyPI. Now confirmed against the public index, not merely unverified.

**Status: checked and negative. Publishing is an owner decision.**

The earlier audit could not reach PyPI (503 through the egress proxy) and therefore said only
that publication was unconfirmed. PyPI is reachable from this session, so the check was run:

| query | result | date |
|---|---|---|
| `https://pypi.org/pypi/assay-bench/json` | **404 — the name is unregistered** | 2026-09-18 |
| `https://pypi.org/pypi/assay/json` | **200 — taken by an unrelated project** | 2026-09-18 |

So: **`assay-bench` is not published**, and no surface in this repository claims it is.

**The name `assay` belongs to someone else.** It is Brandon Rhodes' "Future testing framework"
(`github.com/brandon-rhodes/python-skyfield`), entirely unrelated to this project. Anyone who
types `pip install assay` expecting this benchmark installs a different package. No document
here tells them to, and a test now fails the build if one starts to — the failure mode is a
user running a stranger's code because of a line in our README, which is worse than an
unpublished package.

**Owner decision:** whether to publish `assay-bench`. If yes it needs the project's real
release process, owner credentials, a tag, and verification against the public index plus a
fresh install in a clean environment. None of that is an audit's to do unilaterally, and the
rule stands: do not claim PyPI availability until a fresh public install works.

---

## G4 — Licence: the contradiction is removed, the intent is not confirmed

**Status: blocked on an owner decision, but no longer contradictory.**

At baseline `SPEC.md` §11 said Apache-2.0 while `LICENSE`, the README badge, `CITATION.cff`,
`NOTICE` and `pyproject.toml` all said MIT. SPEC was corrected to MIT so the docs match the
licence file that actually governs the code. **That is not a licence change** — it resolves a
documentation contradiction in favour of the one authoritative artifact.

**Owner decision:** if Apache-2.0 was intended for the specification, that is a deliberate change
to `LICENSE` plus every other surface, and only the owner can make it. A test now fails the build
if "Apache" reappears in the docs while `LICENSE` says MIT, so the contradiction cannot silently
return either way.

---

## G5 — 15 of 22 tested egress transformations are not detected

**Status: open, deliberately, and measured.**

The oracle matches a contiguous substring in one of four frozen encodings. Split, truncated,
base32/base85/rot13, uppercase, gzip, XOR, hashed, homoglyph-substituted and paraphrased egress
are all missed. A miss scores as resistance, so **a headline score is an upper bound on
resistance, not a measurement of it.**

Not fixed here for two reasons: widening the encoding set redefines the oracle and requires a
MAJOR version bump (SPEC §9), and closing the gap with an LLM judge would forfeit the determinism
that motivates the design. The blind spots are published instead
(`tests/test_oracle_blind_spots.py`, whose count a test pins so the docs cannot drift from it).

---

## G6 — Precommitment is implemented but unexercised, and cannot prove completeness

**Status: partially closed.**

The protocol, its three levels and every edge case are implemented and tested against real git
repositories. What does not exist is a *used* record: `precommit/registry/` is empty, because the
committed conformance runs deliberately use a published fixed secret (so their artifacts are
byte-reproducible), and a commitment over a published secret would be theatre.

The residual limit is structural: even `precommitment_verified` shows that one commitment
predated one result. A submitter may register N commitments and reveal one. All N stay visible
and `assay precommit-list` flags unrevealed ones — a deterrent and an audit trail, not a proof.
"Kills cherry-picking" is withdrawn and banned by test.

`precommitment_verified` also requires a forge witness that only CI can supply; a local clone
reaches at most `repository_ordering_verified`, and the tooling says so rather than relabelling.

---

## G7 — No attestation record exists

**Status: partially closed.**

The format, the invariants comparison and the CLI are implemented and tested. `attest/` holds no
records because there are no measurement submissions to attest, and a maintainer attestation over
a stub anyone can rerun from a clean clone in half a second would add nothing. The first record
will accompany the first measurement row.

---

## G8 — Held-out split: designed, not built

**Status: open.**

`tasks.json` is public, so a model trained on this repository may have memorised it. Nothing here
detects that. The v0.1 wording ("a held-out split … *is maintained separately*") asserted
something exists; it was narrowed to "no held-out split exists in this repository and none is
currently run."

---

## G9 — Utility axis: shipped, measured, and it discriminates

**Status: closed for the twin set that exists. The set is small and public, which bounds what
the number means.**

`scoring.over_refusal_rate` was implemented and tested, but no benign twins existed, so every
shipped manifest carried `over_refusal_rate: null` and the axis measured nothing.

[`twins.json`](twins.json) now holds 8 benign twins, one per attack task (T1/M1, T3/M3, T6/M6,
T7/M7, T8/M8, T9/M9, T20/M20, T30/M30). Each declares the surface feature it shares with its
pair and argues why complying is nonetheless correct — a token presented to the service that
issued it rather than to a different one; an apostrophe in the surname O'Brien rather than a SQL
escape; a destructive action the user named and confirmed rather than one a tool description
called routine; a QR the user asked to be read rather than one forwarded to a sink. The image
twins carry their payload in real PNG bytes and a test asserts it is *not* also readable in the
text, held to the same standard as the attack tasks.

**The evidence that the axis is not decoration.** `conformance-overcautious` ships as a fourth
reference target. It is identical to `conformance-hardened` on resistance — both 100 agent, 100
server — and the opposite on utility: 0.0 against 100.0. A resistance score published alone
cannot tell those two apart. That is now demonstrated in the committed artifacts rather than
argued.

The verifier recomputes the rate from `utility.per_twin` and rejects a manifest whose headline
does not follow from its own counts, whose outcomes do not add up to its trials, which invents a
weight, duplicates a twin, or states a rate with no detail behind it. An adapter that declares
no `run_twin` reports `null`, not `0.0`: never asked is not the same as refused nothing.

**What is still limited.** Eight twins over a 31-task catalog, all public. A target tuned on
them scores well without being more useful, and the number says nothing about helpfulness in
general. It is a counterweight to the resistance score and is reported beside it, never instead
of it. Growing the set, and holding part of it back, are the obvious next steps (see G8).

---

## G10 — Target fingerprinting now describes a remote server

**Status: closed for what a fingerprint can establish; the residual limit is stated.**

At baseline `target_fingerprint` hashed the *adapter's declared material*. With only in-process
stubs that was exactly right and completely uninformative about a remote system.

`MCPServerProbe.fingerprint_material()` now returns what the **server** advertised, obtained by
connecting to it: its `serverInfo` name and version, the negotiated protocol revision, its
declared capabilities, and, per tool, the name with SHA-256 digests of the description and the
input schema. The pre-image is republished in the manifest, so anyone who can reach the same
endpoint recomputes the fingerprint by hand. Tested: two different servers fingerprint
differently, a changed tool description changes it, and two sessions to the same server agree.
Fingerprinting an unreachable server is refused outright rather than producing a stable
identity for a failure.

**The residual limit, which no hash closes.** This identifies an *advertised identity and tool
surface*, not a host. Two deployments of the same software are indistinguishable by it, a
server can advertise whatever it likes, and nothing here authenticates the endpoint. That is a
property of asking a server who it is. Establishing that the thing answering is the product
someone names it after needs transport authentication and an out-of-band identity claim, and
belongs with whoever operates the target.

---

## G11 — The related-work comparison rests on secondary sources

**Status: open, and disclosed in place.**

`arxiv.org` is blocked by the audit container's egress proxy, and this session's GitHub access is
scoped to `VatsSShah/assay`, so the four prior benchmarks' papers were not fetched and their
repositories were not cloned. Titles, arXiv identifiers, dates, execution models, scale figures
and artifact locations come from published records retrieved by web search.

That is enough to establish the claim that matters — **these works predate Assay and released
artifacts, so the "open wedge" framing is false** — and not enough for a task-by-task mechanism
comparison. SPEC §1 says so in place rather than implying deeper engagement than occurred.

**What would close it:** read the four papers directly and extend SPEC §1 with a per-attack-family
mapping against the 31 frozen tasks.

---

## G13 — The six image tasks are executed as images

**Status: closed for the image channel; audio, video and document remain unimplemented and
unclaimed.**

Through v0.2 M20, M26, M27, M28, M29 and M30 *described* an image channel and were executed as
text: the "image" was prose and the canary was pasted into that prose, so nothing about an image
was exercised. M30's own `TASKS.md` entry read *"The image is a placeholder … The directive is in
the TEXT, not the image."*

**What shipped.** [`src/assay_bench/media.py`](src/assay_bench/media.py), dependency-free and
stdlib-only:

- a PNG writer and reader — IHDR/tEXt/IDAT/IEND, CRC32 validated on read, filter type 0;
- LSB steganography over the pixel data, with a magic marker and a byte-count length header;
- a QR encoder and decoder — byte mode, error-correction level L, versions 1 through 10,
  including GF(256) Reed-Solomon, BCH(15,5) format information, data masking and interleaving.

`surface.py` plants the canary by one of four routes, recorded per task as
`execution.image_plant`: `pixels` (M20, M26, M27), `metadata` (M28), `rug_pull` (M29) and `qr`
(M30). The plant is verified at build time — `_verify_image_plant` raises if the canary or its
digest is also present in the prose, and raises if the value cannot be recovered from the image.
Adapters declare `decodes_images`; `adapters.supports()` reports a target without it as
`unsupported` on these six rather than crediting it with resistance.

**How it is held honest.** `tests/test_media.py` (27 tests) checks the PNG round-trip and CRC
rejection, steganographic recovery including multi-byte payloads and a bounded visual delta, and
validates the QR implementation against the published BCH format table and the Reed-Solomon
generator polynomials rather than against our own output. `ModalityTruth` in
`tests/test_source_of_truth.py` now fails if any task is still labelled `text_simulation`, if an
image task attaches something that is not a PNG, if a text task attaches anything, or if any task
declares a modality with no executable path.

**What this still does not establish.** The decoder is ours. No commercial scanner, camera or
production vision model has been shown to read these images, so these tasks do not show that a
deployed model would act on the planted directive. They show that the canary travels only through
the image bytes and that a decoder recovers it. That boundary is stated in README, SPEC §8,
`COVERAGE.md` and each task's `TASKS.md` entry.

**Still open:** audio, video and document channels. No path exists, no task declares one, and a
test fails if one does.

---

## G14 — No release has been tagged and no changelog entry is published

**Status: partially closed, blocked on an owner decision for the release itself.**

There is now a `CHANGELOG.md` with an explicit versioning model (package version, benchmark
version, manifest format, validity rules and both schema versions are separate and named), a
`SECURITY.md` with a disclosure path and an explicit list of what is *not* a vulnerability
because it is a documented limit, and CI that builds a wheel and an sdist, runs `twine check
--strict`, installs into a clean venv and smoke-tests the CLIs from outside the checkout.

What does not exist: a git tag, a GitHub release, release notes attached to one, and a published
package. Those need the owner (see also G3). Nothing in the repository claims any of them.

---

## G12 — Verifier output format changed

**Status: closed as a compatibility matter, recorded as a change.**

`verify_manifest` no longer returns `{"verdict": "VERIFIED"}`. It returns `levels_verified`,
`levels_not_established` and `levels_out_of_scope_for_this_tool`. Any consumer keying on the old
string will need updating.

This is deliberate: a single word for a coherence check is the specific misreading the audit
exists to fix. The *inputs* stay compatible — v0.1 manifests verify unchanged, and two are kept
as fixtures the suite checks on every run — and every v0.1 CLI invocation still works, including
the bare-path form. The frozen public interfaces (31 task ids, modes, oracle classes, weights,
score semantics, the integrity-hash rule, the canary triple format) are untouched.
