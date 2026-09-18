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
