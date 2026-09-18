"""The limits of verification, written as passing tests.

Every test in this file asserts that an attack SUCCEEDS against the verifier. That is
deliberate. These are the properties Assay does not have, pinned down so that:

  * no future change can quietly claim them without a test here failing;
  * the documentation cannot drift away from the code, because the wording in README,
    SPEC §4, SUBMIT.md and the verifier docstring is derived from exactly this list;
  * a reader can run one command and see the boundary for themselves rather than taking
    a prose claim on trust.

If one of these ever starts failing, the corresponding limitation has been fixed and the
claim wording may be strengthened -- but not before.
"""

from __future__ import annotations

import unittest

from .helpers import V, canary_finding, reference, rescore, reseal, synthetic_manifest


class WhatAKeyholderCanFabricate(unittest.TestCase):
    def test_keyholder_can_synthesise_a_passing_canary_without_any_run(self):
        """THE central limitation. The FP=0 argument bounds forgery by a party WITHOUT the
        run secret. The submitter is the keyholder, so for them there is nothing to forge:
        compute the digest, paste it into an invented string, ship the triple."""
        secret = "11" * 32
        invented = "I typed this by hand, no target existed " + V.digest(secret, "assay/M1|t|0")
        m = synthetic_manifest(secret=secret, findings=[
            canary_finding("M1", secret, observed=invented),
            canary_finding("M2", secret, asr=0.0, weight=0.7),
        ])
        out = V.verify_manifest(m)

        self.assertIn("canary_correspondence_verified", out["levels_verified"],
                      "the verifier confirms a digest it cannot attribute to a run")
        self.assertEqual(out["canary_confirmed"], 1)
        # The one thing that does push back: a fabrication covering part of the catalog
        # cannot claim to be a whole benchmark run.
        self.assertNotIn("run_complete", out["levels_verified"])

    def test_a_full_catalog_fabrication_also_reaches_run_complete(self):
        """Completeness is a counting check, not evidence. A submitter willing to fabricate
        all 31 findings reaches every level this tool can award. Only an independent rerun
        distinguishes that from a real run."""
        from assay_bench.catalog import load_catalog

        secret = "22" * 32
        catalog = load_catalog()
        findings = []
        for task in catalog:
            if task.oracle == "canary":
                findings.append({
                    "id": task.id, "attack": task.attack, "mode": task.mode,
                    "oracle": task.oracle, "evidence_type": task.evidence_type,
                    "fired": True, "asr": 1.0, "asr_ci": [0.0, 1.0], "weight": task.weight,
                    "canary": {"origin": f"assay/{task.id}", "tool": task.attack, "step": 0,
                               "observed": "fabricated " + V.digest(
                                   secret, f"assay/{task.id}|{task.attack}|0")}})
            else:
                findings.append({
                    "id": task.id, "attack": task.attack, "mode": task.mode,
                    "oracle": task.oracle, "evidence_type": task.evidence_type,
                    "fired": False, "asr": 0.0, "asr_ci": [0.0, 1.0], "weight": task.weight})
        m = synthetic_manifest(secret=secret, findings=findings)
        out = V.verify_manifest(m)
        self.assertEqual(out["levels_verified"],
                         ["format_valid", "internally_consistent",
                          "canary_correspondence_verified", "catalog_bound", "run_complete"])
        self.assertIsNone(out["target_is_real"],
                          "a fabrication carries no provenance, which is itself a signal")


class WhatASubmitterCanOmit(unittest.TestCase):
    def test_cherry_picking_the_clean_tasks_is_visible_in_the_lower_bound(self):
        """Under-reporting cannot be detected from the document alone. What CAN be done is to
        stop rewarding it, and to refuse to call the result complete."""
        from assay_bench.catalog import load_catalog
        from assay_bench.validity import lower_bound, score_over_fixed_denominator

        catalog = load_catalog()
        full = reference("mixed")
        honest_full = full["validity"]["agent_resistance_lower_bound"]

        # Report only the tasks that happened to resist -- the classic cherry-pick.
        kept = [f for f in full["findings"] if f["mode"] == "B" and not f["fired"]]
        self.assertGreater(len(kept), 5)

        # The headline number over that shrunken report looks perfect...
        flattering = score_over_fixed_denominator(catalog, kept, "B")
        self.assertEqual(flattering, 100.0)

        # ...while the lower bound charges every unreported task in full, so cherry-picking
        # gains exactly nothing. Here the dropped tasks were fully exploited, so charging them
        # at full weight reproduces what they actually reported and the bound is UNCHANGED.
        honest = lower_bound(catalog, kept, "B")
        self.assertLessEqual(honest, honest_full,
                             "cherry-picking must never beat an honest complete report")
        self.assertEqual(honest, honest_full)

        # And dropping a task that resisted DOES strictly lower it, because the bound then
        # charges weight the submitter had evidence it did not deserve.
        resisted = next(f for f in full["findings"] if f["mode"] == "B" and f["asr"] < 1.0)
        without = [f for f in full["findings"] if f["id"] != resisted["id"]]
        self.assertLess(lower_bound(catalog, without, "B"), honest_full)

    def test_omitting_a_task_can_never_raise_the_lower_bound(self):
        from assay_bench.catalog import load_catalog
        from assay_bench.validity import lower_bound

        catalog = load_catalog()
        findings = reference("mixed")["findings"]
        baseline = lower_bound(catalog, findings, "B")
        for drop in range(len(findings)):
            trimmed = [f for i, f in enumerate(findings) if i != drop]
            self.assertLessEqual(lower_bound(catalog, trimmed, "B"), baseline + 1e-9)

    def test_partial_runs_cannot_masquerade_as_complete(self):
        """A submitter's own completion claim is not trusted: the catalog count overrides it."""
        partial = reference("vulnerable")
        partial["findings"] = partial["findings"][:10]
        partial["scope"]["completion"] = "complete"
        partial["scope"]["tasks_reported"] = 10
        partial["validity"]["assessment"]["completion"] = "complete"
        rescore(partial)
        out = V.verify_manifest(partial)
        self.assertNotIn("run_complete", out["levels_verified"])
        self.assertEqual(len(out["tasks_unreported"]), 21)


class WhatCommitRevealDoesNotShow(unittest.TestCase):
    def test_commitment_and_reveal_in_one_document_prove_no_ordering(self):
        """A submitter can mint a fresh secret AFTER seeing results, recompute every digest
        against it, and produce a manifest whose commitment binds perfectly."""
        secret_a, secret_b = "33" * 32, "44" * 32
        first = synthetic_manifest(secret=secret_a, findings=[canary_finding("M1", secret_a)])
        self.assertIn("internally_consistent", V.verify_manifest(first)["levels_verified"])

        # Same "result", re-minted under a different secret chosen later. Equally valid.
        second = synthetic_manifest(secret=secret_b, findings=[canary_finding("M1", secret_b)])
        self.assertIn("internally_consistent", V.verify_manifest(second)["levels_verified"])
        self.assertNotEqual(first["run_secret_commitment"], second["run_secret_commitment"])

    def test_the_verifier_never_claims_precommitment(self):
        out = V.verify_manifest(reference("vulnerable"))
        self.assertNotIn("precommitment_verified", out["levels_verified"])
        self.assertIn("precommitment_verified", out["levels_out_of_scope_for_this_tool"])


class WhatVerificationNeverImplies(unittest.TestCase):
    def test_attestation_levels_are_structurally_out_of_reach(self):
        out = V.verify_manifest(reference("hardened"))
        for level in ("independently_rerun", "maintainer_attested"):
            self.assertNotIn(level, out["levels_verified"])
            self.assertIn(level, out["levels_out_of_scope_for_this_tool"])

    def test_target_identity_is_not_checked(self):
        """The target block is free text. A manifest may name any product; nothing in the
        document ties the fingerprint to that name."""
        m = reference("hardened")
        m["target"]["kind"] = "SomeVendor Production Agent v9"
        m["target"]["note"] = "definitely the real thing"
        reseal(m)
        out = V.verify_manifest(m)
        self.assertIn("internally_consistent", out["levels_verified"])
        self.assertIs(out["target_is_real"], False,
                      "provenance still says it was a stub, which is the only honest signal")


if __name__ == "__main__":
    unittest.main()
