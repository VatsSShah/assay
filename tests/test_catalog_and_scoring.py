"""Canonical catalog validation, and the proof that the two scorers cannot drift."""

from __future__ import annotations

import copy
import json
import random
import unittest
from pathlib import Path

import scoring
from .helpers import ROOT, V
from assay_bench.catalog import (Catalog, load_catalog, task_set_digest,
                                 validate_catalog_document)
from assay_bench.errors import MalformedInput, ValidationError

RAW = json.loads((ROOT / "tasks.json").read_text(encoding="utf-8"))


class FrozenCatalog(unittest.TestCase):
    def test_the_shipped_catalog_validates(self):
        catalog = load_catalog()
        self.assertEqual(len(catalog), 31)
        self.assertEqual(catalog.version, "0.1")
        self.assertEqual(catalog.split, "public")

    def test_the_frozen_shape_is_what_the_docs_claim(self):
        catalog = load_catalog()
        self.assertEqual(len(catalog.for_mode("B")), 28)
        self.assertEqual(len(catalog.for_mode("A")), 3)
        counts = {}
        for task in catalog:
            counts[task.oracle] = counts.get(task.oracle, 0) + 1
        self.assertEqual(counts, {"canary": 25, "behavioral": 4, "protocol": 2})

    def test_n_tasks_must_match_the_array(self):
        doc = copy.deepcopy(RAW)
        doc["n_tasks"] = 30
        with self.assertRaisesRegex(ValidationError, "n_tasks"):
            validate_catalog_document(doc)

    def test_duplicate_ids_are_rejected(self):
        doc = copy.deepcopy(RAW)
        doc["tasks"].append(copy.deepcopy(doc["tasks"][0]))
        doc["n_tasks"] = len(doc["tasks"])
        with self.assertRaisesRegex(ValidationError, "duplicate task id"):
            validate_catalog_document(doc)

    def test_an_unpublished_weight_is_rejected(self):
        doc = copy.deepcopy(RAW)
        doc["tasks"][0]["weight"] = 0.55
        with self.assertRaisesRegex(ValidationError, "not one of the published severity"):
            validate_catalog_document(doc)

    def test_oracle_and_evidence_type_must_agree(self):
        doc = copy.deepcopy(RAW)
        doc["tasks"][0]["evidence_type"] = "behavioral"
        with self.assertRaisesRegex(ValidationError, "requires evidence_type"):
            validate_catalog_document(doc)

    def test_bad_mode_or_oracle_is_rejected(self):
        for field, value in (("mode", "C"), ("oracle", "llm-judge")):
            with self.subTest(field=field):
                doc = copy.deepcopy(RAW)
                doc["tasks"][0][field] = value
                with self.assertRaises(ValidationError):
                    validate_catalog_document(doc)

    def test_missing_keys_are_malformed(self):
        for key in ("benchmark", "weights", "tasks", "n_tasks"):
            with self.subTest(key=key):
                doc = copy.deepcopy(RAW)
                del doc[key]
                with self.assertRaises(MalformedInput):
                    validate_catalog_document(doc)

    def test_non_finite_weight_is_rejected(self):
        doc = copy.deepcopy(RAW)
        doc["tasks"][0]["weight"] = float("nan")
        with self.assertRaises(ValidationError):
            validate_catalog_document(doc)


class TaskSetDigest(unittest.TestCase):
    def test_digest_is_stable_across_loads(self):
        self.assertEqual(load_catalog().digest, load_catalog().digest)

    def test_digest_ignores_editorial_fields(self):
        """A typo fix in a title must not look like a task-set change."""
        doc = copy.deepcopy(RAW)
        doc["tasks"][0]["title"] = "Tool-description poisoning (typo fixed)"
        doc["tasks"][0]["crosswalk"] = {}
        self.assertEqual(task_set_digest(doc), task_set_digest(RAW))

    def test_digest_changes_when_a_frozen_field_changes(self):
        for field, value in (("weight", 1.0), ("mode", "A"), ("oracle", "behavioral"),
                             ("id", "M1x")):
            with self.subTest(field=field):
                doc = copy.deepcopy(RAW)
                doc["tasks"][0][field] = value
                self.assertNotEqual(task_set_digest(doc), task_set_digest(RAW))

    def test_digest_is_order_independent(self):
        doc = copy.deepcopy(RAW)
        doc["tasks"] = list(reversed(doc["tasks"]))
        self.assertEqual(task_set_digest(doc), task_set_digest(RAW))


class ScoringParity(unittest.TestCase):
    """assay_verifier inlines the score formula so it can run as a single file. That copy
    must be indistinguishable from the canonical scorer, or a manifest could be generated
    with one number and rejected for stating it."""

    def test_randomised_parity_over_twenty_thousand_cases(self):
        rng = random.Random(20260918)
        for _ in range(20000):
            results = [{"id": f"T{i}", "mode": "B",
                        "weight": rng.choice([0.2, 0.4, 0.7, 1.0]),
                        "hits": rng.randint(0, 25), "trials": 25}
                       for i in range(rng.randint(1, 31))]
            canonical = scoring._resistance(results)
            inlined = V._resistance([{"weight": r["weight"], "asr": r["hits"] / r["trials"]}
                                     for r in results])
            self.assertEqual(canonical, inlined, results)

    def test_parity_at_varied_trial_counts(self):
        rng = random.Random(7)
        for trials in (1, 5, 7, 25, 100, 999):
            results = [{"id": f"T{i}", "mode": "B", "weight": rng.choice([0.2, 0.4, 0.7, 1.0]),
                        "hits": rng.randint(0, trials), "trials": trials} for i in range(12)]
            self.assertEqual(
                scoring._resistance(results),
                V._resistance([{"weight": r["weight"], "asr": r["hits"] / r["trials"]}
                               for r in results]))

    def test_every_shipped_manifest_score_survives_a_round_trip(self):
        for name in ("reference_vulnerable", "reference_hardened", "reference_mixed"):
            with self.subTest(manifest=name):
                m = json.loads((ROOT / "leaderboard" / "manifests" / f"{name}.json").read_text())
                n = m["trials_per_task"]
                results = [{"id": f["id"], "mode": f["mode"], "weight": f["weight"],
                            "hits": round(f["asr"] * n), "trials": n} for f in m["findings"]]
                computed = scoring.score(results)
                self.assertEqual(computed["agent_resistance_score"], m["agent_resistance_score"])
                self.assertEqual(computed["server_posture_score"], m["server_posture_score"])


class ScoringInvariants(unittest.TestCase):
    def test_zero_trials_is_rejected(self):
        with self.assertRaises(scoring.ScoringError):
            scoring._resistance([{"mode": "B", "weight": 0.7, "hits": 0, "trials": 0}])

    def test_hits_exceeding_trials_is_rejected(self):
        with self.assertRaises(scoring.ScoringError):
            scoring._resistance([{"mode": "B", "weight": 0.7, "hits": 26, "trials": 25}])

    def test_non_finite_weight_is_rejected(self):
        with self.assertRaises(scoring.ScoringError):
            scoring._resistance([{"mode": "B", "weight": float("inf"), "hits": 1, "trials": 2}])

    def test_bools_are_not_accepted_as_counts(self):
        with self.assertRaises(scoring.ScoringError):
            scoring._resistance([{"mode": "B", "weight": 0.7, "hits": True, "trials": 25}])

    def test_empty_mode_scores_null_not_zero(self):
        out = scoring.score([{"id": "a", "mode": "B", "weight": 1.0, "hits": 0, "trials": 5}])
        self.assertEqual(out["agent_resistance_score"], 100.0)
        self.assertIsNone(out["server_posture_score"])

    def test_wilson_bounds_and_input_guards(self):
        lo, hi = scoring.wilson_ci(25, 25)
        self.assertTrue(0 <= lo <= hi <= 1)
        self.assertEqual(hi, 1.0)
        for bad in ((0, 0), (-1, 5), (6, 5), (True, 5)):
            with self.subTest(args=bad):
                with self.assertRaises(scoring.ScoringError):
                    scoring.wilson_ci(*bad)

    def test_over_refusal_rate_is_implemented_and_guarded(self):
        self.assertIsNone(scoring.over_refusal_rate([]))
        self.assertEqual(
            scoring.over_refusal_rate([{"weight": 1.0, "completions": 10, "trials": 10}]), 0.0)
        self.assertEqual(
            scoring.over_refusal_rate([{"weight": 1.0, "completions": 0, "trials": 10}]), 100.0)
        with self.assertRaises(scoring.ScoringError):
            scoring.over_refusal_rate([{"weight": 1.0, "completions": 11, "trials": 10}])

    def test_every_shipped_manifest_measures_the_utility_axis_and_shows_its_working(self):
        """Through v0.2 no benign twins existed and every manifest said null.

        Twins are authored now, so the rule flips: a shipped manifest must carry a real rate
        AND the per-twin detail behind it. A bare number nobody can recompute is what this
        repository exists not to publish.
        """
        for path in sorted((ROOT / "leaderboard" / "manifests").glob("*.json")):
            manifest = json.loads(path.read_text())
            with self.subTest(manifest=path.name):
                rate = manifest["over_refusal_rate"]
                if rate is None:
                    # Legitimate only when the target could not be asked to do benign work at
                    # all -- the MCP server probe has no agent, so it refuses nothing because
                    # nothing was requested of it. It must not carry a utility block either,
                    # or the null would be contradicted by its own detail.
                    self.assertNotIn("utility", manifest,
                                     f"{path.name} reports no rate but ships a utility block")
                    continue
                self.assertIn("utility", manifest, f"{path.name} states a rate with no detail")
                self.assertEqual(manifest["utility"]["over_refusal_rate"], rate)
                self.assertEqual(manifest["utility"]["twins_reported"],
                                 manifest["utility"]["twins_scored"],
                                 f"{path.name}: a twin was excluded from a reference run, which "
                                 f"should be deterministic")

    def test_every_conformance_reference_run_measures_the_utility_axis(self):
        """The conformance targets CAN do benign work, so a null from one is a regression."""
        for name in ("vulnerable", "hardened", "mixed", "overcautious"):
            path = ROOT / "leaderboard" / "manifests" / f"reference_{name}.json"
            with self.subTest(manifest=path.name):
                manifest = json.loads(path.read_text())
                self.assertIsNotNone(manifest["over_refusal_rate"],
                                     f"{path.name} stopped measuring the utility axis")

    def test_the_reference_runs_show_the_axis_discriminating(self):
        """Hardened and overcautious must be identical on resistance and opposite on utility.

        If they are not, the utility axis is decoration and the resistance score can be gamed
        by refusing everything.
        """
        loaded = {}
        for name in ("hardened", "overcautious"):
            path = ROOT / "leaderboard" / "manifests" / f"reference_{name}.json"
            if not path.is_file():
                self.skipTest(f"{path.name} is not shipped")
            loaded[name] = json.loads(path.read_text())
        self.assertEqual(loaded["hardened"]["agent_resistance_score"],
                         loaded["overcautious"]["agent_resistance_score"])
        self.assertEqual(loaded["hardened"]["over_refusal_rate"], 0.0)
        self.assertEqual(loaded["overcautious"]["over_refusal_rate"], 100.0)


if __name__ == "__main__":
    unittest.main()
