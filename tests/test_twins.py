"""The utility axis: benign twins, and the property that makes the number worth reading.

A resistance score published alone rewards a target that refuses everything. The point of this
axis is that `conformance-hardened` and `conformance-overcautious` score **identically** on
resistance -- 100 and 100 -- and separate completely on the twins. If they did not, the axis
would be decoration.

The other property under test is confusability. A twin that is obviously benign is completed by
everything and measures nothing, so each twin declares the surface feature it shares with its
attack pair, and that feature has to actually be present in both.
"""

from __future__ import annotations

import copy
import json
import unittest

from .helpers import ROOT, V, reseal
from assay_bench import twins as twins_mod
from assay_bench.adapters import TwinCapable, TwinEpisode, TwinOutcome
from assay_bench.adapters.conformance import build
from assay_bench.catalog import load_catalog
from assay_bench.errors import MalformedInput, ValidationError
from assay_bench.runner import run
from assay_bench.twins import build_twin_surface, load_twins

CATALOG = load_catalog()
TWINS = load_twins()
DOC = json.loads((ROOT / "twins.json").read_text())


class TheAxisSeparatesSecureFromUseless(unittest.TestCase):
    """The reason this axis exists, stated as a test."""

    @classmethod
    def setUpClass(cls):
        cls.runs = {name: run(build(name), catalog=CATALOG, trials=5, command="test")
                    for name in ("vulnerable", "hardened", "overcautious")}

    def test_hardened_and_overcautious_are_identical_on_resistance(self):
        hardened, overcautious = self.runs["hardened"], self.runs["overcautious"]
        self.assertEqual(hardened["agent_resistance_score"],
                         overcautious["agent_resistance_score"])
        self.assertEqual(hardened["server_posture_score"],
                         overcautious["server_posture_score"])
        self.assertEqual(hardened["agent_resistance_score"], 100.0)

    def test_the_twin_set_separates_them_completely(self):
        self.assertEqual(self.runs["hardened"]["over_refusal_rate"], 0.0)
        self.assertEqual(self.runs["overcautious"]["over_refusal_rate"], 100.0)

    def test_a_vulnerable_target_is_not_penalised_on_utility(self):
        """Over-refusal and susceptibility are independent axes; conflating them hides both."""
        self.assertEqual(self.runs["vulnerable"]["over_refusal_rate"], 0.0)
        self.assertEqual(self.runs["vulnerable"]["agent_resistance_score"], 0.0)

    def test_every_run_publishes_the_per_twin_detail_behind_the_number(self):
        for name, manifest in self.runs.items():
            with self.subTest(target=name):
                utility = manifest["utility"]
                self.assertEqual(utility["twins_reported"], len(TWINS))
                self.assertEqual(len(utility["per_twin"]), len(TWINS))
                self.assertEqual(utility["twin_set_version"], TWINS.version)


class TwinsAreConfusableWithTheirPairs(unittest.TestCase):
    """A twin that is obviously benign measures nothing."""

    def test_every_twin_pairs_with_a_real_frozen_task(self):
        for twin in TWINS:
            with self.subTest(twin=twin.id):
                CATALOG.require(twin.pairs_with)

    def test_no_attack_has_two_twins(self):
        """Two twins for one attack would double its influence without saying so."""
        pairs = [t.pairs_with for t in TWINS]
        self.assertEqual(len(pairs), len(set(pairs)))

    def test_every_twin_argues_its_benignness_and_its_confusability(self):
        for twin in TWINS:
            with self.subTest(twin=twin.id):
                self.assertGreater(len(twin.benign_because), 60)
                self.assertGreater(len(twin.shared_surface), 20)
                self.assertGreater(len(twin.over_refusal_looks_like), 20)
                # The argument must name the attack it is distinguishing itself from, otherwise
                # it is an assertion rather than a comparison.
                self.assertIn(twin.pairs_with, twin.benign_because,
                              f"{twin.id} does not say how it differs from {twin.pairs_with}")

    def test_an_image_twin_really_carries_its_payload_in_the_image(self):
        """Same standard the attack tasks are held to: the value is in the bytes or nowhere."""
        for twin in TWINS:
            if not twin.image_plant:
                continue
            surface = build_twin_surface(twin)
            with self.subTest(twin=twin.id):
                self.assertTrue(surface["attachments"])
                attachment = surface["attachments"][0]
                self.assertTrue(attachment["data"].startswith(b"\x89PNG\r\n\x1a\n"))
                blob = json.dumps(surface["tool_catalog"]) + json.dumps(surface["tool_results"])
                self.assertNotIn(twin.image_payload, blob,
                                 f"{twin.id}: the payload is readable in the text, so a target "
                                 f"that never looks at the image completes it anyway")

    def test_an_image_twins_payload_is_recoverable_by_a_real_decoder(self):
        from assay_bench.adapters.conformance import decode_attachment

        for twin in TWINS:
            if not twin.image_plant:
                continue
            surface = build_twin_surface(twin)
            with self.subTest(twin=twin.id):
                self.assertEqual(decode_attachment(surface["attachments"][0]),
                                 twin.image_payload)

    def test_a_twin_surface_looks_like_an_attack_surface(self):
        """A target that could tell them apart by shape would score well by spotting the test."""
        for twin in TWINS:
            surface = build_twin_surface(twin)
            with self.subTest(twin=twin.id):
                self.assertEqual(sorted(surface),
                                 ["arguments", "attachments", "expected_payload",
                                  "tool_catalog", "tool_results", "user_request"])
                self.assertTrue(surface["tool_catalog"])
                self.assertTrue(surface["tool_catalog"][0]["description"])


class TwinSetValidation(unittest.TestCase):
    def test_a_free_form_weight_is_refused(self):
        doc = copy.deepcopy(DOC)
        doc["twins"][0]["weight"] = 0.55
        with self.assertRaisesRegex(ValidationError, "published twin weights"):
            twins_mod.validate_twin_document(doc)

    def test_a_duplicate_id_is_refused(self):
        doc = copy.deepcopy(DOC)
        doc["twins"].append(copy.deepcopy(doc["twins"][0]))
        with self.assertRaisesRegex(ValidationError, "duplicate twin id"):
            twins_mod.validate_twin_document(doc)

    def test_a_second_twin_for_one_attack_is_refused(self):
        doc = copy.deepcopy(DOC)
        extra = copy.deepcopy(doc["twins"][0])
        extra["id"] = "T1b"
        doc["twins"].append(extra)
        with self.assertRaisesRegex(ValidationError, "already has a twin"):
            twins_mod.validate_twin_document(doc)

    def test_an_unargued_twin_is_refused(self):
        """A twin whose benignness is asserted rather than argued cannot be assessed."""
        doc = copy.deepcopy(DOC)
        doc["twins"][0]["benign_because"] = "it is fine"
        with self.assertRaisesRegex(ValidationError, "real sentence"):
            twins_mod.validate_twin_document(doc)

    def test_a_missing_field_is_refused(self):
        doc = copy.deepcopy(DOC)
        del doc["twins"][0]["correct_behavior"]
        with self.assertRaises(MalformedInput):
            twins_mod.validate_twin_document(doc)

    def test_the_packaged_twin_set_is_the_canonical_one(self):
        packaged = ROOT / "src" / "assay_bench" / "data" / "twins.json"
        self.assertEqual(packaged.read_bytes(), (ROOT / "twins.json").read_bytes())


class AbsenceIsNotCompliance(unittest.TestCase):
    """The same rule the attack side follows: never score an absence as a good outcome."""

    def test_an_adapter_that_cannot_do_benign_work_reports_null_not_zero(self):
        """Never asked is not the same as refused nothing."""

        class NoTwins:
            name, version, kind = "no-twins", "1.0", "test-stub"

            def capabilities(self):
                from assay_bench.adapters import Capabilities
                return Capabilities(emits_network_egress=True, emits_tool_calls=True,
                                    exposes_protocol_facts=True, supports_reset=True,
                                    decodes_images=True, drives_agent_under_test=True,
                                    drives_server_under_test=True)

            def reset(self):
                pass

            def fingerprint_material(self):
                return {"kind": "no-twins"}

            def run_episode(self, episode):
                from assay_bench.adapters import Observation
                return Observation(
                    task_id=episode.task_id, trial=episode.trial,
                    egress=[{"channel": "network", "tool": "x", "step": 0, "payload": "no"}],
                    protocol_facts={"unauthenticated_tools_list": False,
                                    "origin_header_checked": True, "rebind_protection": True},
                    actions=[{"action": "x", "performed": False, "confirmed_by_user": False}])

        adapter = NoTwins()
        self.assertFalse(isinstance(adapter, TwinCapable))
        manifest = run(adapter, catalog=CATALOG, trials=5, command="test")
        self.assertIsNone(manifest["over_refusal_rate"])
        self.assertNotIn("utility", manifest)

    def test_a_twin_whose_every_trial_errors_leaves_the_denominator(self):
        results = [{"id": "T1", "weight": 1.0, "trials": 5, "completions": 0, "errored": 5,
                    "twin_set_version": "0.1"},
                   {"id": "T3", "weight": 1.0, "trials": 5, "completions": 5, "errored": 0,
                    "twin_set_version": "0.1"}]
        out = twins_mod.score(results)
        self.assertEqual(out["twins_scored"], 1)
        self.assertEqual(out["twins_excluded"], [{"id": "T1", "reason": "every trial errored"}])
        # T1 is neither a refusal nor a completion; the rate reflects only what was decided.
        self.assertEqual(out["over_refusal_rate"], 0.0)

    def test_a_twin_set_where_everything_errors_yields_null(self):
        results = [{"id": "T1", "weight": 1.0, "trials": 3, "completions": 0, "errored": 3,
                    "twin_set_version": "0.1"}]
        self.assertIsNone(twins_mod.score(results)["over_refusal_rate"])

    def test_an_adapter_that_raises_on_a_twin_records_an_errored_trial(self):
        class Exploding:
            def run_twin(self, episode):
                raise RuntimeError("boom")

        target = build("hardened")
        target.run_twin = Exploding().run_twin       # type: ignore[method-assign]
        manifest = run(target, catalog=CATALOG, trials=5, command="test")
        self.assertIsNone(manifest["over_refusal_rate"])
        self.assertEqual(manifest["utility"]["twins_scored"], 0)

    def test_an_unknown_outcome_word_is_refused(self):
        with self.assertRaises(ValidationError):
            twins_mod.classify("probably_fine")


class TheVerifierRecomputesTheAxis(unittest.TestCase):
    """The scalar a reader quotes must be derived, not asserted."""

    @classmethod
    def setUpClass(cls):
        cls.manifest = run(build("overcautious"), catalog=CATALOG, trials=5, command="test")

    def test_an_honest_manifest_verifies(self):
        out = V.verify_manifest(self.manifest)
        self.assertIn("internally_consistent", out["levels_verified"])

    def _rejects(self, mutate, pattern):
        doc = copy.deepcopy(self.manifest)
        mutate(doc)
        with self.assertRaisesRegex(Exception, pattern):
            V.verify_manifest(reseal(doc))

    def test_a_flattering_rate_with_untouched_counts_is_rejected(self):
        self._rejects(lambda d: (d.update(over_refusal_rate=0.0),
                                 d["utility"].update(over_refusal_rate=0.0)),
                      "per-twin counts imply")

    def test_a_headline_that_disagrees_with_the_block_is_rejected(self):
        self._rejects(lambda d: d.update(over_refusal_rate=0.0), "at the top level")

    def test_outcomes_that_do_not_add_up_are_rejected(self):
        self._rejects(lambda d: d["utility"]["per_twin"][0].update(refusals=4), "not trials")

    def test_an_inflated_completion_count_is_rejected(self):
        self._rejects(lambda d: d["utility"]["per_twin"][0].update(completions=5), "not trials")

    def test_a_wrong_scored_count_is_rejected(self):
        self._rejects(lambda d: d["utility"].update(twins_scored=99), "twins_scored")

    def test_an_invented_weight_is_rejected(self):
        self._rejects(lambda d: d["utility"]["per_twin"][0].update(weight=0.05),
                      "published twin weights")

    def test_a_duplicated_twin_is_rejected(self):
        self._rejects(lambda d: d["utility"]["per_twin"].append(
            dict(d["utility"]["per_twin"][0])), "twice")

    def test_a_rate_with_no_detail_behind_it_is_rejected(self):
        self._rejects(lambda d: d.pop("utility"), "no utility block backs it")

    def test_a_negative_count_is_rejected(self):
        self._rejects(lambda d: d["utility"]["per_twin"][0].update(refusals=-5),
                      "non-negative integer")


if __name__ == "__main__":
    unittest.main()
