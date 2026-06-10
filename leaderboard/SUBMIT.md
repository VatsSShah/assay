# Submitting to the Assay leaderboard

The leaderboard resists score-gaming: the verifier recomputes the score from the findings and
re-checks every canary proof, so a score cannot be inflated or self-reported. A maintainer re-runs
the target to attest the row.

1. **Score your target** with the reference implementation, producing a scorecard manifest
   (`manifest_schema.json`). Run on **loopback only**; published rows never target a live
   third-party endpoint.
2. **Open a PR** adding your manifest under `manifests/` and one entry to `entries.json`
   (see `schema.json`).
3. **Automated check.** CI runs `python build_site.py`, which calls the verifier on your
   manifest: the commitment must bind the revealed secret, every canary triple must
   recompute, and the integrity hash must match. A failing manifest blocks the merge.
4. **Maintainer re-run.** A maintainer re-runs the target at the pinned `Assay` version and
   confirms the score before merge.

Disclose self-authored targets as such. Pin your model snapshot, temperature, and trial
count `N` in the manifest so the row is reproducible.
