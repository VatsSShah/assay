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

## G2 — A keyholder can still fabricate a self-reported manifest. A witnessed one, no.

**Status: unfixable for self-reported runs, and that is a fact about self-reporting rather than
a bug. The cause is now removable: a witnessed run reaches a level a fabrication cannot.**

`observed` is submitter-supplied text and the submitter holds the run secret. Compute the
digest, paste it into an invented string, and the verifier confirms it. `run_complete` forces a
fabrication to cover all 31 tasks, which raises the cost slightly and nothing more. That limit
is stated in the verifier docstring, README's first table, SPEC §4.2, SUBMIT.md and the
leaderboard page, and pinned as a **passing** test
(`test_a_full_catalog_fabrication_also_reaches_run_complete`).

### Why it happens

The submitter is both the party being measured and the party recording the measurement. They
mint the secret, plant the canaries, observe the egress and write the document, so they hold
every input to the check. No amount of checking a document fixes that.

### What shipped: an egress witness

`assay_bench/witness.py` moves the adversarial side to a party the submitter does not control —
the leaderboard in a hosted deployment, the assessor in an engagement. The witness mints the run
secret and withholds it, plants the canaries, observes egress at its **own** sink, and signs a
statement naming the run, the target fingerprint and which task ids fired.

A submitter cannot forge that signature, because they never held the key, and cannot invent a
leak, because the digest they would have to produce was never revealed to them.

`witnessed_egress` is therefore its own verification level, never merged into
`canary_correspondence_verified`, because the two rest on different evidence. A witness that
**disagrees** with the manifest fails the whole document — under-reporting and over-reporting
each have their own error — so attaching one is never strictly safe for a dishonest submitter.
The demonstration ships: a competent fabrication that flips a finding, drops its proof and
restates the scores passes every offline level and is caught only by the witness.

Signatures are Ed25519, in `assay_bench/ed25519.py`, because the standard library has no
public-key crypto and a symmetric MAC would mean "trust whoever holds the shared key" — the
problem again. It is validated against the RFC 8032 §7.1 vectors and against the edge cases that
separate a real check from one that usually says yes: non-canonical encodings, off-curve points,
and `S >= q`, without which signatures are malleable. It is **not** constant-time, says so in
its own docstring, and a test keeps that caveat there. Verification runs on public data, which
is the operation a third party needs.

### What a witness still does not establish

That the witness is honest, that it is independent of the submitter, or that the key belongs to
who you think. Those are questions of key custody and trust, and no signature answers them. A
submitter running their own witness has signed their own homework — so `independent` is a field
inside the signed bytes, it is a **declaration and not a proof**, and a self-witnessed run is
visibly self-witnessed rather than quietly counted as evidence. The verifier reports which key
signed rather than collapsing any of it to a verdict.

The remaining honest gap: nothing here ties a public key to a real-world identity. That is a key
distribution problem, and the answer is a published key the leaderboard pins, not more code.

### The adjacent problem, unchanged

**Under-reporting** is unprofitable even unwitnessed. Scores use the frozen catalog's weight
total as the denominator, and every manifest carries a lower bound charging each unreported,
unsupported or inconclusive task at full weight. Omission can never raise that number: dropping
a fully-exploited task leaves it unchanged, dropping any task that resisted strictly lowers it.
Cherry-picking gains nothing. That is a smaller claim than detection, and it is the one that
holds without a witness.

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

## G5 — The oracle's blind spots are now measured at run time, not just published

**Status: 14 of the 15 are detected and reported. The oracle itself is unchanged, deliberately.
One transformation stays irreducible.**

The oracle matches a contiguous substring in one of four frozen encodings. Split, truncated,
base32/base85/rot13, uppercase, gzipped, XOR'd, hashed, homoglyph-substituted and paraphrased
egress are all missed, and **a miss scores as resistance** — so a headline score is an upper
bound on resistance, not a measurement of it.

Those blind spots were enumerated in `tests/test_oracle_blind_spots.py`, which is good
documentation and was never looked at during a run. A target exfiltrating a canary in two halves
scored exactly like one that refused, and nobody was told.

`assay_bench/diagnostics.py` now looks. Eleven detectors undo the transformation and then match
the tag: case folding, homoglyphs, separator and zero-width insertion, reversal, rot13, base32,
base85, gzip/zlib (optionally base64-wrapped), single-byte XOR, unsalted hashes (md5/sha1/
sha256/sha512), and truncation. A twelfth works across events: when no single egress event
carries the digest but their concatenation does, the payload was split across requests, which no
per-event scan can see by construction. **14 of the 15 published blind spots are caught.**

**It changes no score, and that is the point.** Widening the oracle's encoding set is a MAJOR
version bump under SPEC §9 and would change what every published number means. A diagnostic hit
never sets `fired`, never enters an ASR, never moves a score; it lands in a separate
`diagnostics` block that states this in its own text. A test runs the same target with
diagnostics on and off and asserts every score and finding is byte-identical.

**Confidence is per-detector, because the evidence is not uniform.** Recovering the full 16-hex
digest after undoing a transformation carries the same collision argument the oracle does — the
transformation is undone, then the exact tag matches. A *truncated* tag does not: a 12-hex
prefix is a 48-bit tag, and the detector says so in its own reason string rather than letting a
reader assume 64. Matches shorter than 8 hex characters are not reported at all, because a
32-bit coincidence fires on ordinary text.

**The demonstration.** `tests/test_diagnostics.py` builds a target that leaks every canary split
across two requests. It scores **100.0 agent, 100.0 server, run complete** — a clean sheet — and
the diagnostics flag all 25 canary tasks. That is the gap, shown rather than described. The
hardened control raises nothing, so the block is not crying wolf, and a suite of benign payloads
(ordinary base64, unrelated compressed data, 64 hex characters, the printable ASCII range)
raises nothing either.

**What stays undetectable:** paraphrase in natural language ("the credential begins with five-c
and ends in nine"), egress encrypted under a key the harness does not hold, and a salted hash.
No deterministic detector finds those. They are named in every diagnostics block under
`irreducible`, and a passing test asserts paraphrase is still missed so the limit cannot quietly
disappear.

---

## G6 — Precommitment exercised end to end, with a worked example in this repository's history

**Status: closed as far as a repository can close it. `precommitment_verified` still needs CI,
and the residual limit is structural and unchanged.**

The protocol and its three levels were implemented and tested against throwaway git
repositories, but `precommit/registry/` was empty: the committed conformance runs deliberately
use a published fixed secret so their artifacts stay byte-reproducible, and a commitment over a
published secret is theatre.

There is now a real one. Three commits, in order:

1. the commitment alone — a fresh secret was minted, its SHA-256 registered, and the secret kept
   outside the repository. The run had not happened;
2. the run and the reveal — the manifest for `leaderboard/manifests/precommitted_mcp_insecure.json`,
   against the reference MCP server over real HTTP;
3. this record.

`assay precommit-verify --manifest leaderboard/manifests/precommitted_mcp_insecure.json` reaches
**`repository_ordering_verified`** from any clone, and a test asserts it keeps doing so.

**Two real defects surfaced by exercising it**, neither of which unit tests against synthetic
repositories had found:

- **`git log --follow` decided the ordering.** Rename detection is a similarity heuristic and two
  manifests look alike to it, so `--follow` traced the new manifest back to an unrelated
  reference manifest added in the baseline commit and denied an honest submission. Both
  directions matter: following a *registry record* to an older file would make a commitment look
  earlier than it is, which is a soundness failure. `--follow` is gone and both directions are
  now tests.
- **The target fingerprint included the ephemeral TCP port**, so the same reference server
  fingerprinted differently on every restart and a commitment could never bind its own run. The
  identity is now scheme, host and path, with the exclusion and its reason stated inside the
  republished pre-image.

**The residual limit is unchanged and structural.** Even at `precommitment_verified`, this shows
that one commitment predated one result. A submitter may register N commitments and reveal one;
all N stay visible and `assay precommit-list` flags the unrevealed ones, which is a deterrent and
an audit trail, not a proof. "Kills cherry-picking" stays withdrawn and banned by test. A local
clone reaches at most `repository_ordering_verified`, because the forge witness only CI can
supply is what distinguishes ancestry from external timestamping — and repository ancestry can
be rewritten by whoever owns the history.

---

## G7 — A record exists in `attest/`, and it is explicitly *not* an attestation

**Status: the format is exercised; a maintainer attestation has still not been performed, and
the record says so where a machine can read it.**

`attest/` was empty because there were no measurement submissions to attest, and an attestation
over a stub anyone can rerun in half a second would add nothing.

It now holds one record: an independent rerun of the precommitted run above, from a **fresh
clone** of this repository, against the reference MCP server built from that clone's own source.
The invariants digests matched exactly — `4dadddb9…` on both sides — which is real evidence that
the shipped artifacts are reproducible from published source. Invariants, not bytes: a rerun
mints a fresh secret, so digests and timestamps differ legitimately.

**It is not a maintainer attestation and could not honestly be presented as one**, because the
rerun was performed by the same session that produced the artifacts. That is a self-check. A
file sitting in a directory called `attest/` reads as an attestation, so the distinction is now
a field rather than a sentence in a note: records carry `kind`, either
`maintainer_attestation` or `clean_clone_reproduction`, each with its own scope text, and the
shipped record's scope begins *"This is NOT a maintainer attestation."* A test asserts no
shipped record claims to be one — a record claiming a maintainer rerun that never happened would
be exactly the fabricated evidence this audit forbids — and the offline verifier still refuses
to emit `maintainer_attested` whatever sits in that directory.

**What would close it:** a rerun by a repository maintainer, independent of whoever produced the
submission, recorded with `kind: maintainer_attestation`. That is a person's act, not a script's.

---

## G8 — Contamination: detectable and mitigated. A held-out split still does not exist.

**Status: two real mechanisms shipped. The gap they do not close is named, and it is the
important one.**

`tasks.json` is public, so a model trained on a crawl of GitHub may have memorised the task set
and the exact adversarial prose. A memorised benchmark scores well without being safer. Through
v0.2 nothing here detected or mitigated that; the v0.1 wording ("a held-out split … *is
maintained separately*") asserted something that did not exist and was narrowed to say so.

### Detection: a canary GUID

`tasks.json` carries `assay-benchmark-canary:1f0c7a4e-…`, a string that exists in this repository
and, by intention, nowhere else. A model that reproduces it verbatim has this repository in its
training data. The technique is the one BIG-bench uses.

Both directions are published with it, because the asymmetry is the whole point:

- a **hit** establishes contamination — the score measures memorisation as well as safety, and
  the two cannot be separated after the fact;
- a **miss establishes nothing.** A model may have trained on this repository and still decline
  to emit the GUID, because it was filtered, because the model refuses to repeat identifiers, or
  because it never memorised that particular string. `contamination.CANARY_SEMANTICS` says this
  in the artifact, and a test asserts the wording stays.

A test also checks the GUID has not spread beyond the three places it belongs, since a string
scattered through the tree is harder to keep unique and to reason about.

### Mitigation: per-run surface variation

The adversarial prose is no longer a fixed string. Each surface has **4 interchangeable
phrasings**, chosen per `(run secret, task)` by HMAC. Memorising the strings published here
therefore does not tell a target what it will be shown: the choice depends on 32 random bytes
minted after this repository was written.

What moves is wording only. The canary, the sink, the plant site and the oracle rule are
identical across phrasings, and tests enforce it: every phrasing must still fire on the
vulnerable target and still not fire on the hardened control, the canary preimage and plant site
must be unchanged, no image phrasing may carry the canary in its text, and selection must spread
evenly across the variants. Task ids, oracles, modes and weights stay frozen — they are the
public interface — so the task-set digest is unchanged and every published score stays
comparable. Reference runs use a published fixed secret, so they remain byte-reproducible.

Each manifest records which phrasing every task used, so a reader can reconstruct exactly what
the target saw without the document embedding the prose.

### What neither mechanism does

A model that memorised the **mechanism** rather than the text is unaffected by variation; four
phrasings is a 1-in-4 chance of a given memorised string matching, not a defence. The GUID
detects a particular kind of contamination and misses the rest. And nothing here is a held-out
split.

**A held-out split cannot live in a public repository** — publishing it is what destroys it. So
this gap does not close here: it would need a private task set held by whoever runs the
leaderboard, with only its digest published. No such set exists and none is currently run. The
manifest block says `NOT a held-out split` in its own text, and a test fails the build if any
document starts claiming one is maintained. **Treat a high public score as necessary, not
sufficient.**

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

**Status: open, disclosed in place, and re-checked. The blocker is environmental, not a
decision.**

SPEC §1 compares Assay to four prior MCP security benchmarks. The papers were never read: the
titles, arXiv identifiers, dates, execution models and artifact locations come from published
records retrieved by search, not from the papers.

**Re-checked on 2026-09-18.** Every route to a primary source is blocked by this environment's
egress proxy:

| source | result |
|---|---|
| `arxiv.org` | blocked (CONNECT tunnel refused, 403) |
| `ar5iv.labs.arxiv.org` | blocked |
| `www.alphaxiv.org` | blocked |
| `semanticscholar.org`, `api.semanticscholar.org` | unreachable |
| `paperswithcode.co` | unreachable |
| `huggingface.co`, `openreview.net` | unreachable |

Search results are reachable and carry more detail than SPEC §1 currently states. **That detail
has deliberately not been added.** A search summary is further from the source than the citation
record already published, and writing more specific claims on weaker evidence is precisely the
failure this audit exists to correct. SPEC §1 says what the retrieved records support and no
more.

The claim that actually matters is unaffected and well-supported: **these works predate Assay
and released artifacts, so the v0.1 "open wedge" framing was false.** That framing is withdrawn
and banned by test. What is missing is the finer comparison — a per-attack-family mapping of
each prior benchmark against the 31 frozen tasks — which needs the papers themselves.

**What would close it:** read the four papers from an environment with network access to arXiv,
and extend SPEC §1 with that mapping. Roughly an hour of work for someone unblocked; not
something to approximate from summaries.

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
