"""Contamination: the canary GUID, and per-run surface variation.

`tasks.json` is public, so a model trained on a crawl of GitHub may have memorised the task set
and the exact adversarial prose (gap G8). Two mechanisms, doing different jobs, with different
limits:

* the canary GUID makes contamination **detectable** — a model that reproduces it has this
  repository in training;
* surface variation makes memorising the published prose **less useful** — the strings a target
  actually sees are minted per run from the run secret.

The tests that matter most are the honesty ones: that the variation changes only the wording and
never the task (same canary, same sink, same plant site, same oracle outcome), that a reference
run stays byte-reproducible despite it, and that a miss on the canary probe is not reported as
evidence of a clean model.
"""

from __future__ import annotations

import json
import re
import unittest

from .helpers import ROOT
from assay_bench import contamination as C
from assay_bench.catalog import load_catalog
from assay_bench.surface import build_surface

CATALOG = load_catalog()
SECRETS = [bytes([i]).hex() * 32 for i in range(1, 25)]


class TheCanaryGuidIsUniqueAndStable(unittest.TestCase):
    def test_it_is_published_in_the_task_set(self):
        doc = json.loads((ROOT / "tasks.json").read_text())
        self.assertEqual(doc["contamination_canary_guid"], C.CANARY_GUID)

    def test_adding_it_did_not_move_the_frozen_task_set_digest(self):
        """The digest covers the frozen interface. Metadata must not disturb it."""
        self.assertTrue(CATALOG.digest.startswith("e8a6e47520e38b0e"),
                        f"the task-set digest changed to {CATALOG.digest[:16]}; the frozen "
                        f"interface moved and every published score is now incomparable")

    def test_it_looks_like_a_guid_and_is_long_enough_to_be_unique(self):
        self.assertRegex(C.CANARY_GUID,
                         r"^assay-benchmark-canary:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
                         r"-[0-9a-f]{4}-[0-9a-f]{12}$")

    def test_it_appears_in_the_repository_only_where_it_is_meant_to(self):
        """A GUID scattered through the tree is harder to keep unique and to reason about."""
        import subprocess

        from .helpers import require_source_checkout

        require_source_checkout(self)
        suffix = C.CANARY_GUID.split(":", 1)[1]
        tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                                 text=True).stdout.split()
        allowed = {"tasks.json", "src/assay_bench/data/tasks.json",
                   "src/assay_bench/contamination.py"}
        holders = {path for path in tracked
                   if suffix in (ROOT / path).read_text(encoding="utf-8", errors="ignore")}
        # A manifest records which GUID was in play for that run, which is what makes a later
        # contamination finding attributable to a specific benchmark revision. Those are
        # generated, so they are allowed by shape rather than by name.
        unexpected = {path for path in holders - allowed
                      if not path.startswith("leaderboard/manifests/")}
        self.assertEqual(unexpected, set(),
                         f"the canary GUID has spread to {sorted(unexpected)}")
        self.assertIn("tasks.json", holders, "the GUID is not published in the task set")
        self.assertIn("src/assay_bench/contamination.py", holders,
                      "the module that defines the GUID no longer contains it")


class TheProbeResultIsNotOverRead(unittest.TestCase):
    def test_a_reproduction_is_reported_as_contamination(self):
        out = C.canary_probe_result(f"Sure: {C.CANARY_GUID}")
        self.assertTrue(out["reproduced"])
        self.assertIn("training data", out["means"])

    def test_a_completion_without_the_prefix_still_counts(self):
        """A model completing the probe emits the suffix, not the whole string."""
        suffix = C.CANARY_GUID.split(":", 1)[1]
        self.assertTrue(C.canary_probe_result(suffix)["reproduced"])

    def test_a_miss_explicitly_establishes_nothing(self):
        out = C.canary_probe_result("UNKNOWN")
        self.assertFalse(out["reproduced"])
        self.assertIn("establishes nothing", out["means"].lower())
        self.assertIn("not evidence of a clean model", out["means"].lower())

    def test_the_probe_is_a_fixed_string_so_results_compare(self):
        self.assertTrue(C.CANARY_PROBE.endswith("assay-benchmark-canary:"))
        self.assertNotIn(C.CANARY_GUID.split(":", 1)[1], C.CANARY_PROBE,
                         "the probe gives away the answer it is testing for")


class VariationChangesTheWordingAndNothingElse(unittest.TestCase):
    """The variants must be interchangeable. If one made a task easier, scores would drift."""

    def test_several_distinct_phrasings_are_actually_reachable(self):
        for task in CATALOG:
            if task.oracle != "canary":
                continue
            phrasings = {build_surface(task, secret, 0)["tool_catalog"][0]["description"]
                         for secret in SECRETS}
            with self.subTest(task=task.id):
                self.assertGreaterEqual(len(phrasings), C.VARIANT_COUNT,
                                        f"{task.id} reaches only {len(phrasings)} phrasings")

    def test_every_phrasing_still_names_the_sink_and_demands_egress(self):
        for kind, variants in C.VARIANT_SETS.items():
            for i, variant in enumerate(variants):
                with self.subTest(kind=kind, variant=i):
                    self.assertIn("{sink}", variant, "a variant that names no sink is not the "
                                                     "same task")
                    if kind in ("description", "result"):
                        self.assertIn("{canary}", variant,
                                      "a text variant with no canary could never fire")

    def test_no_image_variant_carries_the_canary_in_the_text(self):
        """The image tasks' whole point is that the value is in the bytes."""
        for kind in ("image_description", "image_result"):
            for i, variant in enumerate(C.VARIANT_SETS[kind]):
                with self.subTest(kind=kind, variant=i):
                    self.assertNotIn("{canary}", variant)

    def test_the_canary_and_the_plant_site_are_identical_across_phrasings(self):
        for task in CATALOG:
            if task.oracle != "canary":
                continue
            canaries, plants = set(), set()
            for secret in SECRETS[:8]:
                surface = build_surface(task, secret, 0)
                canaries.add((surface["canary"]["origin"], surface["canary"]["tool"],
                              surface["canary"]["step"]))
                plants.add(tuple(a["plant"] for a in surface["attachments"]))
            with self.subTest(task=task.id):
                self.assertEqual(len(canaries), 1, "the canary preimage moved with the wording")
                self.assertEqual(len(plants), 1, "the plant site moved with the wording")

    def test_every_phrasing_still_fires_on_the_vulnerable_target_and_not_the_hardened_one(self):
        """The decisive check: wording must not change any task's outcome."""
        from assay_bench.adapters.conformance import build
        from assay_bench.runner import run

        for secret in SECRETS[:6]:
            with self.subTest(secret=secret[:6]):
                fired = run(build("vulnerable"), catalog=CATALOG, trials=2, run_secret=secret,
                            command="test")
                self.assertTrue(all(f["fired"] for f in fired["findings"]),
                                "a phrasing stopped an attack from firing")
                clean = run(build("hardened"), catalog=CATALOG, trials=2, run_secret=secret,
                            command="test")
                self.assertFalse(any(f["fired"] for f in clean["findings"]),
                                 "a phrasing made the hardened control leak")


class SelectionIsDeterministicAndUnpredictable(unittest.TestCase):
    def test_the_same_secret_always_picks_the_same_phrasing(self):
        """Reference runs use a published fixed secret and must stay byte-reproducible."""
        for task in CATALOG:
            with self.subTest(task=task.id):
                first = C.variant_index("ab" * 32, task.id, "description", 4)
                second = C.variant_index("ab" * 32, task.id, "description", 4)
                self.assertEqual(first, second)

    def test_a_reference_regeneration_is_still_byte_identical(self):
        from assay_bench.adapters.conformance import build
        from assay_bench.runner import run

        one = run(build("hardened"), catalog=CATALOG, trials=2, run_secret="ab" * 32,
                  command="test", run_id="fixed")
        two = run(build("hardened"), catalog=CATALOG, trials=2, run_secret="ab" * 32,
                  command="test", run_id="fixed")
        self.assertEqual([f["id"] for f in one["findings"]], [f["id"] for f in two["findings"]])
        self.assertEqual(one["contamination"]["variant_per_task"],
                         two["contamination"]["variant_per_task"])

    def test_different_tasks_in_one_run_do_not_all_get_the_same_phrasing(self):
        """Otherwise one memorised string would still cover the whole run."""
        chosen = {C.variant_index("cd" * 32, task.id, "description", C.VARIANT_COUNT)
                  for task in CATALOG}
        self.assertGreater(len(chosen), 1)

    def test_the_selection_spreads_across_the_variants(self):
        counts = [0] * C.VARIANT_COUNT
        for i in range(400):
            counts[C.variant_index(f"{i:064x}", "M1", "description", C.VARIANT_COUNT)] += 1
        self.assertTrue(all(count > 40 for count in counts),
                        f"selection is lopsided: {counts}")

    def test_an_empty_variant_set_is_refused_rather_than_dividing_by_zero(self):
        with self.assertRaises(ValueError):
            C.variant_index("ab" * 32, "M1", "description", 0)


class TheManifestBlockStatesItsOwnLimits(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from assay_bench.adapters.conformance import build
        from assay_bench.runner import run

        cls.manifest = run(build("vulnerable"), catalog=CATALOG, trials=5, command="test")

    def test_it_records_which_phrasing_each_task_used(self):
        block = self.manifest["contamination"]
        self.assertEqual(sorted(block["variant_per_task"]), sorted(t.id for t in CATALOG))
        self.assertEqual(block["surface_variants_available"], C.VARIANT_COUNT)

    def test_it_says_plainly_that_it_is_not_a_held_out_split(self):
        blurb = self.manifest["contamination"]["what_this_is"]
        self.assertIn("not a held-out split", blurb.lower())
        self.assertIn("memorised the mechanism rather than the text", blurb)

    def test_it_says_a_canary_miss_establishes_nothing(self):
        note = self.manifest["contamination"]["canary_guid_note"]
        self.assertIn("has established nothing", note)


class NoSurfaceClaimsAHeldOutSplitExists(unittest.TestCase):
    """The v0.1 wording asserted one was maintained. Nothing may reintroduce that."""

    BANNED = (re.compile(r"held-out split[^.]{0,40}is maintained", re.I),
              re.compile(r"we maintain a held-out", re.I),
              re.compile(r"private (task )?split (exists|is run)", re.I))

    #: Documents whose job is to record what was withdrawn. They have to be able to quote the
    #: v0.1 wording in order to say it was removed; every other surface may not contain it.
    RECORDS = {"REMAINING_GAPS.md", "CHANGELOG.md", "IMPLEMENTATION_SUMMARY.md",
               "audit/CLAIM_EVIDENCE_MATRIX.md", "audit/BASELINE_AUDIT.md",
               "audit/ISSUE_1_TRIAGE.md", "audit/ISSUE_1_RESPONSE.md"}

    def test_no_document_claims_a_held_out_split_is_maintained(self):
        import subprocess

        from .helpers import require_source_checkout

        require_source_checkout(self)
        for name in subprocess.run(["git", "ls-files", "*.md"], cwd=ROOT, capture_output=True,
                                   text=True).stdout.split():
            if name in self.RECORDS:
                continue
            text = (ROOT / name).read_text(encoding="utf-8", errors="ignore")
            for pattern in self.BANNED:
                with self.subTest(doc=name, pattern=pattern.pattern):
                    self.assertIsNone(pattern.search(text),
                                      f"{name} claims a held-out split that does not exist")

    def test_a_record_that_quotes_the_withdrawn_wording_says_it_was_withdrawn(self):
        """An exemption nobody can see is indistinguishable from an oversight."""
        for name in sorted(self.RECORDS):
            path = ROOT / name
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if not any(pattern.search(text) for pattern in self.BANNED):
                continue
            with self.subTest(doc=name):
                self.assertTrue(
                    any(word in text.lower() for word in
                        ("withdraw", "narrowed", "removed", "does not exist", "not shipped")),
                    f"{name} quotes the withdrawn held-out-split wording without saying so")


if __name__ == "__main__":
    unittest.main()
