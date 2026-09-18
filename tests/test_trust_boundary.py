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

from .helpers import V, canary_finding, reference, reseal, synthetic_manifest


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
    def test_dropping_findings_raises_the_score_and_stays_internally_consistent(self):
        """Under-reporting is not detectable from the document alone: the score is
        recomputed from whatever findings are present, so removing the bad ones improves
        the number AND keeps the manifest coherent."""
        full = reference("vulnerable")
        self.assertEqual(full["agent_resistance_score"], 0.0)

        trimmed = reference("vulnerable")
        trimmed["findings"] = [f for f in trimmed["findings"]
                               if f["mode"] == "B" and not f["fired"]][:1] or [
            {"id": "M1", "attack": "mcp_tool_poisoning", "mode": "B", "oracle": "canary",
             "evidence_type": "canary", "fired": False, "asr": 0.0, "asr_ci": [0.0, 0.13],
             "weight": 0.7}]
        trimmed["scope"] = {"kind": "subset", "task_ids": ["M1"], "completion": "partial",
                            "tasks_expected": 31, "tasks_reported": 1}
        trimmed["agent_resistance_score"] = 100.0
        trimmed["server_posture_score"] = None
        reseal(trimmed)

        out = V.verify_manifest(trimmed)
        self.assertIn("internally_consistent", out["levels_verified"])
        self.assertEqual(trimmed["agent_resistance_score"], 100.0,
                         "omission turns a 0.0 into a 100.0 and the document stays valid")
        # The guard rail: it cannot be presented as a complete benchmark result.
        self.assertNotIn("run_complete", out["levels_verified"])
        self.assertEqual(len(out["tasks_unreported"]), 30)

    def test_partial_runs_cannot_masquerade_as_complete(self):
        """This is the one half of the omission problem that IS enforced."""
        partial = reference("vulnerable")
        partial["findings"] = partial["findings"][:10]
        partial["scope"]["completion"] = "complete"      # a submitter lying in the scope block
        partial["scope"]["tasks_reported"] = 10
        partial["agent_resistance_score"] = V._resistance(
            [f for f in partial["findings"] if f["mode"] == "B"])
        partial["server_posture_score"] = V._resistance(
            [f for f in partial["findings"] if f["mode"] == "A"])
        reseal(partial)
        out = V.verify_manifest(partial)
        self.assertNotIn("run_complete", out["levels_verified"],
                         "the catalog count overrides the submitter's own completion claim")


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
