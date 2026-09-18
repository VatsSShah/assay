# Remaining gaps

What this repository still does not do, and what is blocked on a decision the audit cannot make.
Nothing here is hidden in a footnote elsewhere: every item is also reflected in README, SPEC or
`corpus/README.md`, and several are enforced by tests that would fail if the claim strengthened
without the gap closing.

---

## G1 — No real MCP adapter exists. Nothing has been scored against a real system.

**Status: open. The single most important limitation.**

The runner drives an adapter; the only adapters that exist are three deterministic in-process
conformance stubs. There is no MCP transport implementation, no client, and no path that touches
a real server, agent or model. Every number in this repository is a property of the harness and
its own stubs.

What was built toward it: the adapter interface (`assay_bench/adapters/__init__.py`) declares
capabilities including `is_real_target`, which the runner records in provenance, the verifier
surfaces, `badge.py` refuses to badge, and the leaderboard displays. The seam is real and tested;
what plugs into it is not written.

**Why it was not attempted here.** A stub with a persuasive name would be worse than the gap.
Implementing a real adapter means MCP transport, session lifecycle, tool discovery, a defined
egress capture boundary, and a way to establish that the thing on the other end is what the
manifest says it is — none of which can be tested honestly in an environment with no network and
no MCP server to point at.

**What would close it:** an adapter with `is_real_target=True`, tested against a locally-run
open-source vulnerable MCP server (`corpus/README.md` lists candidates), plus a defined answer to
target identity — because `target_fingerprint` currently fingerprints the *adapter's declared
material*, not the remote system.

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

**What would reduce it:** a trusted execution path, or evidence from the target side (a signed
egress log from an instrumented server). Both are large and neither is planned here.

---

## G3 — No PyPI release; `pipx run assay-bench` was removed, not fixed

**Status: blocked on an owner decision.**

PyPI is unreachable from the audit environment (503 through the egress proxy; `pip download`
finds no distributions), so the audit could not confirm whether `assay-bench` is published.
Supporting evidence that it is not: the repository has no tags and no GitHub releases.

Per the operating rule not to claim a publication succeeded without checking the public index,
**nothing was published and nothing is claimed.** The README now documents `pip install -e .`,
which works and is tested end to end.

**Owner decision:** whether to publish. If yes, it needs the project's real release process,
owner credentials, a tag, and verification against the public index plus a fresh install in a
clean environment — none of which an audit should do unilaterally.

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

## G9 — Utility axis: formula shipped, twins not authored

**Status: open.**

`scoring.over_refusal_rate` is implemented and tested (helpful → 0%, over-cautious → 100%), but
no benign twin tasks exist. Every shipped manifest carries `over_refusal_rate: null`, and a test
asserts that, so the axis cannot appear to be measured before it is. No target has been measured
on it.

---

## G10 — Target fingerprinting does not identify a remote system

**Status: open, and scoped by G1.**

`target_fingerprint` is now precisely specified — a SHA-256 over a canonical serialisation of a
named field list, with the pre-image republished so anyone can recompute it — and it is tested
for stability and for sensitivity to each contributing field. But it fingerprints the *adapter's
declared material*. With only in-process stubs that is exactly right; with a real remote target
it would not be enough to establish identity. Designing that belongs with G1.

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
