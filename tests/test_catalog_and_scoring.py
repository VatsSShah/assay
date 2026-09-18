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

    def test_no_shipped_manifest_claims_an_over_refusal_rate(self):
        """The axis is defined but no benign twins exist, so every manifest must say null."""
        for path in sorted((ROOT / "leaderboard" / "manifests").glob("*.json")):
            with self.subTest(manifest=path.name):
                self.assertIsNone(json.loads(path.read_text())["over_refusal_rate"])


if __name__ == "__main__":
    unittest.main()
