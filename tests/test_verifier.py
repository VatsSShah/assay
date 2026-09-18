"""Verifier behaviour: what it accepts, what it rejects, and at which level."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from .helpers import (ROOT, MANIFESTS, LEGACY, V, canary_finding, first_fired_canary,
                      legacy, load, mutate, reference, reseal, synthetic_manifest)

#: The levels an ordinary, unwitnessed manifest can reach offline. `witnessed_egress` is
#: deliberately NOT here: it needs a signature from a party the submitter does not control, so a
#: document that reaches every level on this list has still not reached that one.
ALL_LEVELS = ["format_valid", "internally_consistent", "canary_correspondence_verified",
              "catalog_bound", "run_complete"]

#: The full published vocabulary, which `assay-verify levels` must print.
PUBLISHED_LEVELS = ALL_LEVELS + ["witnessed_egress"]


class ShippedManifests(unittest.TestCase):
    def test_every_generated_reference_manifest_reaches_every_level(self):
        for name in ("vulnerable", "hardened", "mixed"):
            with self.subTest(target=name):
                out = V.verify_manifest(reference(name))
                self.assertEqual(out["levels_verified"], ALL_LEVELS)
                self.assertEqual(out["canary_confirmed"], out["canary_findings"])
                self.assertEqual(out["findings_reported"], 31)
                self.assertEqual(out["tasks_unreported"], [])

    def test_legacy_v0_1_manifests_still_verify(self):
        """The v0.1 artifacts are a public interface; a new verifier must not orphan them."""
        for name in ("vulnerable", "hardened"):
            with self.subTest(target=name):
                out = V.verify_manifest(legacy(name))
                self.assertIn("internally_consistent", out["levels_verified"])
                self.assertIn("catalog_bound", out["levels_verified"])
                self.assertIn("run_complete", out["levels_verified"])

    def test_conformance_runs_declare_they_are_not_real_targets(self):
        for name in ("vulnerable", "hardened", "mixed"):
            with self.subTest(target=name):
                self.assertIs(V.verify_manifest(reference(name))["target_is_real"], False)


class TripleRecomputation(unittest.TestCase):
    def test_correct_secret_proves_and_wrong_secret_does_not(self):
        observed = "sk-LEAK" + V.digest("cd" * 32, "o|t|0") + "END"
        self.assertTrue(V.verify_triple("cd" * 32, "o", "t", 0, observed))
        self.assertFalse(V.verify_triple("00" * 32, "o", "t", 0, observed))

    def test_every_documented_encoding_is_detected(self):
        import base64, urllib.parse
        d = V.digest("11" * 32, "o|t|3")
        for label, encoded in (
            ("raw", d),
            ("base64", base64.b64encode(d.encode()).decode()),
            ("hex-of-ascii", d.encode().hex()),
            ("urlquote", urllib.parse.quote(d)),
        ):
            with self.subTest(encoding=label):
                self.assertTrue(V.verify_triple("11" * 32, "o", "t", 3, f"...{encoded}..."))

    def test_wrong_preimage_component_does_not_recompute(self):
        d = V.digest("22" * 32, "origin|tool|0")
        for bad in (("other", "tool", 0), ("origin", "other", 0), ("origin", "tool", 1)):
            with self.subTest(preimage=bad):
                self.assertFalse(V.verify_triple("22" * 32, bad[0], bad[1], bad[2], d))

    def test_malformed_secret_is_rejected_not_crashed(self):
        for bad in ("zz" * 32, "abc", "", "ab" * 16):
            with self.subTest(secret=bad[:8]):
                with self.assertRaises(V.InconsistentManifest):
                    V.verify_triple(bad, "o", "t", 0, "x")

    def test_non_string_observed_and_bool_step_are_rejected(self):
        with self.assertRaises(V.InconsistentManifest):
            V.verify_triple("ab" * 32, "o", "t", 0, 12345)
        with self.assertRaises(V.InconsistentManifest):
            V.verify_triple("ab" * 32, "o", "t", True, "x")

    def test_unicode_and_very_large_observed_are_handled(self):
        d = V.digest("33" * 32, "o|t|0")
        big = ("é中\U0001f600" * 200_000) + d
        self.assertTrue(V.verify_triple("33" * 32, "o", "t", 0, big))
        self.assertFalse(V.verify_triple("33" * 32, "o", "t", 0, "é中" * 100_000))


class CommitmentAndIntegrity(unittest.TestCase):
    def test_commitment_must_bind_the_revealed_secret(self):
        m = reference("vulnerable")
        self.assertEqual(V.commitment(m["run_secret_reveal"]), m["run_secret_commitment"])
        m["run_secret_reveal"] = "ff" * 32
        with self.assertRaises(V.InconsistentManifest):
            V.verify_manifest(m)

    def test_alteration_after_sealing_is_detected(self):
        m = reference("vulnerable")
        m["target"]["note"] = "silently edited after publication"
        with self.assertRaisesRegex(V.InconsistentManifest, "integrity hash mismatch"):
            V.verify_manifest(m)

    def test_wrong_integrity_hash_is_detected(self):
        m = reference("hardened")
        m["integrity_hash"] = "00" * 32
        with self.assertRaisesRegex(V.InconsistentManifest, "integrity hash mismatch"):
            V.verify_manifest(m)


class CanaryInvariants(unittest.TestCase):
    def test_tampered_observed_does_not_recompute(self):
        m = mutate(reference("vulnerable"),
                   lambda d: first_fired_canary(d)["canary"].update(observed="sk-WRONGdeadbeef"))
        with self.assertRaisesRegex(V.InconsistentManifest, "does not recompute"):
            V.verify_manifest(m)

    def test_fired_canary_with_zero_asr_is_rejected(self):
        def hobble(d):
            f = first_fired_canary(d)
            f["asr"] = 0.0
        with self.assertRaisesRegex(V.InconsistentManifest, "cannot have asr 0"):
            V.verify_manifest(mutate(reference("vulnerable"), hobble))

    def test_fired_canary_without_a_proof_triple_is_rejected(self):
        def strip(d):
            first_fired_canary(d).pop("canary")
        with self.assertRaisesRegex(V.InconsistentManifest, "ships no proof triple"):
            V.verify_manifest(mutate(reference("vulnerable"), strip))

    def test_not_fired_canary_carrying_a_proof_is_rejected(self):
        def flip(d):
            f = first_fired_canary(d)
            f["fired"] = False
            f["asr"] = 0.0
        with self.assertRaisesRegex(V.InconsistentManifest, "not fired but ships a canary proof"):
            V.verify_manifest(mutate(reference("vulnerable"), flip))

    def test_canary_proof_on_a_non_canary_task_is_rejected(self):
        def graft(d):
            for f in d["findings"]:
                if f["oracle"] == "behavioral":
                    f["canary"] = {"origin": "z", "tool": "z", "step": 0, "observed": "x"}
                    return
            raise AssertionError("no behavioral task to graft onto")
        with self.assertRaisesRegex(V.InconsistentManifest, "must not carry a canary proof"):
            V.verify_manifest(mutate(reference("vulnerable"), graft))

    def test_relabelling_a_canary_to_dodge_the_proof_is_rejected(self):
        def relabel(d):
            first_fired_canary(d)["evidence_type"] = "behavioral"
        with self.assertRaisesRegex(V.InconsistentManifest, "requires evidence_type"):
            V.verify_manifest(mutate(reference("vulnerable"), relabel))

    def test_not_fired_canary_with_nonzero_asr_is_rejected(self):
        def bad(d):
            for f in d["findings"]:
                if f["oracle"] == "canary" and not f["fired"]:
                    f["asr"] = 0.5
                    return
            raise AssertionError("no unfired canary in fixture")
        with self.assertRaisesRegex(V.InconsistentManifest, "cannot have asr"):
            V.verify_manifest(mutate(reference("hardened"), bad))


class ScoreBinding(unittest.TestCase):
    def test_a_score_the_findings_do_not_imply_is_rejected(self):
        m = synthetic_manifest()
        m["agent_resistance_score"] = 100.0
        m["server_posture_score"] = None
        reseal(m)
        with self.assertRaisesRegex(V.InconsistentManifest, "findings imply"):
            V.verify_manifest(m)

    def test_inflated_score_on_real_findings_is_rejected(self):
        m = reference("vulnerable")
        m["agent_resistance_score"] = 95.0
        reseal(m)
        with self.assertRaisesRegex(V.InconsistentManifest, "recompute"):
            V.verify_manifest(m)

    def test_score_out_of_range_is_rejected(self):
        for value in (-1.0, 101.0, float("nan"), float("inf")):
            with self.subTest(score=value):
                m = reference("hardened")
                m["agent_resistance_score"] = value
                reseal(m)
                with self.assertRaises(V.VerifierError):
                    V.verify_manifest(m)


class CatalogBinding(unittest.TestCase):
    def test_duplicate_task_ids_are_rejected(self):
        def dup(d):
            d["findings"].append(json.loads(json.dumps(d["findings"][0])))
        with self.assertRaisesRegex(V.InconsistentManifest, "duplicate finding"):
            V.verify_manifest(mutate(reference("vulnerable"), dup))

    def test_unknown_task_id_is_rejected(self):
        with self.assertRaisesRegex(V.InconsistentManifest, "not a task in the frozen catalog"):
            V.verify_manifest(mutate(reference("vulnerable"),
                                     lambda d: d["findings"][0].update(id="NOT-A-TASK")))

    def test_altered_weight_is_rejected(self):
        with self.assertRaisesRegex(V.InconsistentManifest, "severity weights are frozen"):
            V.verify_manifest(mutate(reference("vulnerable"),
                                     lambda d: d["findings"][0].update(weight=0.01)))

    def test_mode_flip_between_denominators_is_rejected(self):
        with self.assertRaisesRegex(V.InconsistentManifest, "frozen catalog says"):
            V.verify_manifest(mutate(reference("vulnerable"),
                                     lambda d: d["findings"][0].update(mode="A")))

    def test_oracle_downgrade_is_rejected(self):
        def downgrade(d):
            f = first_fired_canary(d)
            f["oracle"] = "behavioral"
            f["evidence_type"] = "behavioral"
            f.pop("canary")
        with self.assertRaisesRegex(V.InconsistentManifest, "frozen catalog says"):
            V.verify_manifest(mutate(reference("vulnerable"), downgrade))

    def test_missing_tasks_block_run_complete_but_not_consistency(self):
        def drop(d):
            d["findings"] = d["findings"][:5]
            d["scope"]["completion"] = "partial"
            d["scope"]["tasks_reported"] = 5
        out = V.verify_manifest(mutate(reference("vulnerable"), drop))
        self.assertIn("internally_consistent", out["levels_verified"])
        self.assertNotIn("run_complete", out["levels_verified"])
        self.assertEqual(len(out["tasks_unreported"]), 26)

    def test_an_explicitly_supplied_catalog_is_used(self):
        out = V.verify_manifest(reference("vulnerable"), catalog=load(ROOT / "tasks.json"))
        self.assertIn("catalog_bound", out["levels_verified"])

    def test_without_a_catalog_the_level_is_reported_unestablished_not_passed(self):
        """The verifier is single-file by design, so it must degrade honestly when
        tasks.json is absent rather than claim a binding it could not check."""
        import os
        import tempfile
        m = reference("vulnerable")
        saved = os.environ.pop("ASSAY_TASKS", None)
        original = V.load_frozen_catalog
        try:
            V.load_frozen_catalog = lambda path=None: None
            out = V.verify_manifest(m)
            self.assertIn("internally_consistent", out["levels_verified"])
            self.assertNotIn("catalog_bound", out["levels_verified"])
            self.assertNotIn("run_complete", out["levels_verified"])
            self.assertIn("tasks.json not found", out["levels_not_established"]["catalog_bound"])
        finally:
            V.load_frozen_catalog = original
            if saved is not None:
                os.environ["ASSAY_TASKS"] = saved


class VersionDispatch(unittest.TestCase):
    def test_unknown_major_version_is_refused_with_an_explanation(self):
        m = reference("vulnerable")
        m["version"] = "99.0"
        reseal(m)
        with self.assertRaisesRegex(V.UnsupportedVersion, "unknown MAJOR"):
            V.verify_manifest(m)

    def test_unknown_minor_in_a_known_major_is_still_refused(self):
        m = reference("vulnerable")
        m["version"] = "0.99"
        reseal(m)
        with self.assertRaises(V.UnsupportedVersion):
            V.verify_manifest(m)

    def test_supported_versions_are_declared(self):
        self.assertIn("0.1", V.SUPPORTED_VERSIONS)


class StructuralValidation(unittest.TestCase):
    def test_missing_required_field_is_malformed_not_a_crash(self):
        for field in ("track", "findings", "integrity_hash", "harness", "over_refusal_rate"):
            with self.subTest(field=field):
                m = reference("hardened")
                del m[field]
                with self.assertRaises(V.MalformedManifest):
                    V.verify_manifest(m)

    def test_unknown_top_level_field_is_rejected(self):
        m = mutate(reference("hardened"), lambda d: d.update(sneaky_extra=1))
        with self.assertRaisesRegex(V.MalformedManifest, "unknown field"):
            V.verify_manifest(m)

    def test_non_object_manifest_is_rejected(self):
        for bad in ([], "string", 7, None):
            with self.subTest(value=type(bad).__name__):
                with self.assertRaises(V.MalformedManifest):
                    V.verify_manifest(bad)

    def test_bad_trials_per_task_is_rejected(self):
        for bad in (0, -1, True, 1.5, "25"):
            with self.subTest(value=bad):
                m = reference("hardened")
                m["trials_per_task"] = bad
                reseal(m)
                with self.assertRaises(V.VerifierError):
                    V.verify_manifest(m)

    def test_malformed_confidence_interval_is_rejected(self):
        for ci in ([0.5], [0.9, 0.1], [0.0, 2.0], "0-1", [float("nan"), 1.0]):
            with self.subTest(ci=ci):
                m = reference("hardened")
                m["findings"][0]["asr_ci"] = ci
                reseal(m)
                with self.assertRaises(V.VerifierError):
                    V.verify_manifest(m)

    def test_invalid_track_is_rejected(self):
        m = mutate(reference("hardened"), lambda d: d.update(track="both"))
        with self.assertRaisesRegex(V.InconsistentManifest, "invalid track"):
            V.verify_manifest(m)


class RequireOption(unittest.TestCase):
    def test_require_raises_when_a_level_is_not_reached(self):
        partial = synthetic_manifest(findings=[canary_finding("M1", "ab" * 32)])
        with self.assertRaisesRegex(V.VerifierError, "run_complete"):
            V.verify_manifest(partial, require=("run_complete",))

    def test_require_passes_on_a_complete_run(self):
        out = V.verify_manifest(reference("vulnerable"), require=tuple(ALL_LEVELS))
        self.assertEqual(out["levels_verified"], ALL_LEVELS)


class CommandLine(unittest.TestCase):
    """Exit codes are part of the contract: CI and reviewers key on them."""

    def _run(self, *args, optimize=False):
        cmd = [sys.executable] + (["-O"] if optimize else []) + [
            str(ROOT / "src" / "assay_verifier.py")]
        return subprocess.run(cmd + list(args), capture_output=True, text=True, cwd=ROOT)

    def test_valid_manifest_exits_zero(self):
        r = self._run("verify", str(MANIFESTS / "reference_vulnerable.json"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("levels_verified", r.stdout)

    def test_legacy_bare_path_form_still_works(self):
        r = self._run(str(LEGACY / "reference_hardened.json"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_tampered_manifest_exits_one(self):
        import tempfile
        m = reference("vulnerable")
        first_fired_canary(m)["canary"]["observed"] = "TAMPERED"
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(m, fh)
            path = fh.name
        try:
            r = self._run("verify", path)
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("assay:", r.stderr)
        finally:
            Path(path).unlink()

    def test_assertions_disabled_does_not_weaken_rejection(self):
        """python -O strips `assert`. If validation used assertions, a tampered manifest
        would verify under -O. It must not."""
        import tempfile
        m = reference("vulnerable")
        first_fired_canary(m)["canary"]["observed"] = "TAMPERED"
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(m, fh)
            path = fh.name
        try:
            plain = self._run("verify", path)
            optimized = self._run("verify", path, optimize=True)
            self.assertEqual(plain.returncode, 1)
            self.assertEqual(optimized.returncode, 1,
                             "python -O must not turn a rejection into an acceptance")
        finally:
            Path(path).unlink()

    def test_unreadable_file_exits_three(self):
        r = self._run("verify", "/nonexistent/manifest.json")
        self.assertEqual(r.returncode, 3)

    def test_invalid_json_exits_three(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{not json")
            path = fh.name
        try:
            self.assertEqual(self._run("verify", path).returncode, 3)
        finally:
            Path(path).unlink()

    def test_usage_error_exits_two(self):
        self.assertEqual(self._run("verify").returncode, 2)
        self.assertEqual(self._run("--bogus").returncode, 2)
        self.assertEqual(self._run("verify", "a.json", "--require", "nope").returncode, 2)

    def test_triple_subcommand_reports_presence_and_absence(self):
        d = V.digest("ab" * 32, "o|t|0")
        ok = self._run("triple", "ab" * 32, "o", "t", "0", f"leak {d} end")
        self.assertEqual(ok.returncode, 0)
        self.assertIn("DIGEST PRESENT", ok.stdout)
        bad = self._run("triple", "ab" * 32, "o", "t", "0", "nothing here")
        self.assertEqual(bad.returncode, 1)
        self.assertIn("DIGEST ABSENT", bad.stdout)

    def test_levels_subcommand_lists_the_vocabulary(self):
        r = self._run("levels")
        self.assertEqual(r.returncode, 0)
        payload = json.loads(r.stdout)
        self.assertEqual(payload["verifiable_here"], PUBLISHED_LEVELS)
        self.assertIn("maintainer_attested", payload["out_of_scope_for_this_tool"])


if __name__ == "__main__":
    unittest.main()


class ValidityBlockIsVerified(unittest.TestCase):
    """The validity block claims things a reader relies on, so none of it is taken on trust.

    Every case below was ACCEPTED before this cross-check existed: the block was written by the
    submitter and, apart from the lower bound, never recomputed.
    """

    def _mutate(self, fn):
        import copy
        m = copy.deepcopy(reference("vulnerable"))
        fn(m)
        return reseal(m)

    def test_the_shipped_manifests_still_verify(self):
        for name in ("vulnerable", "hardened", "mixed"):
            with self.subTest(target=name):
                self.assertIn("run_complete", V.verify_manifest(reference(name))["levels_verified"])

    def test_a_tally_that_does_not_sum_to_the_trial_count_is_rejected(self):
        m = self._mutate(lambda d: d["validity"]["per_task_outcomes"].update(M1={"exploited": 3}))
        with self.assertRaisesRegex(V.InconsistentManifest, "accounts for 3 trial"):
            V.verify_manifest(m)

    def test_findings_must_follow_from_the_tally(self):
        m = self._mutate(lambda d: d["validity"]["per_task_outcomes"].update(
            {t: {"resisted": d["trials_per_task"]} for t in d["validity"]["per_task_outcomes"]}))
        with self.assertRaisesRegex(V.InconsistentManifest, "fired=True but the trial tally"):
            V.verify_manifest(m)

    def test_an_asr_that_the_tally_does_not_imply_is_rejected(self):
        def half(d):
            n = d["trials_per_task"]
            d["validity"]["per_task_outcomes"]["M1"] = {"exploited": n // 2, "resisted": n - n // 2}
        with self.assertRaisesRegex(V.InconsistentManifest, "but the tally implies"):
            V.verify_manifest(self._mutate(half))

    def test_a_missing_per_task_tally_is_rejected(self):
        m = self._mutate(lambda d: d["validity"].pop("per_task_outcomes"))
        with self.assertRaisesRegex(V.MalformedManifest, "not checkable without"):
            V.verify_manifest(m)

    def test_a_tally_covering_the_wrong_tasks_is_rejected(self):
        m = self._mutate(lambda d: d["validity"]["per_task_outcomes"].update(ZZZ={"exploited": 25}))
        with self.assertRaisesRegex(V.InconsistentManifest, "extra and is missing"):
            V.verify_manifest(m)

    def test_unknown_or_negative_trial_states_are_rejected(self):
        with self.assertRaisesRegex(V.InconsistentManifest, "unknown trial state"):
            V.verify_manifest(self._mutate(
                lambda d: d["validity"]["per_task_outcomes"].update(M1={"vibes": 25})))
        with self.assertRaisesRegex(V.InconsistentManifest, "non-negative integer"):
            V.verify_manifest(self._mutate(
                lambda d: d["validity"]["per_task_outcomes"].update(
                    M1={"exploited": 26, "resisted": -1})))

    def test_every_stated_task_list_is_recomputed(self):
        for field, value, pattern in (
            ("inconclusive_tasks", ["M1"], "inconclusive_tasks"),
            ("unsupported_tasks", ["M1"], "unsupported_tasks"),
            ("tasks_below_conclusive_rate", ["M1"], "tasks_below_conclusive_rate"),
            ("missing_tasks", ["M1"], "missing_tasks"),
        ):
            with self.subTest(field=field):
                m = self._mutate(lambda d, f=field, v=value: d["validity"]["assessment"].update({f: v}))
                with self.assertRaisesRegex(V.InconsistentManifest, pattern):
                    V.verify_manifest(m)

    def test_every_stated_count_is_recomputed(self):
        for field, value in (("required_tasks", 2), ("reported_tasks", 99),
                             ("trials_per_task", 1)):
            with self.subTest(field=field):
                m = self._mutate(lambda d, f=field, v=value: d["validity"]["assessment"].update({f: v}))
                with self.assertRaises(V.InconsistentManifest):
                    V.verify_manifest(m)

    def test_an_unknown_rules_version_is_refused(self):
        m = self._mutate(lambda d: d["validity"].update(rules_version="99"))
        with self.assertRaisesRegex(V.InconsistentManifest, "cannot check it"):
            V.verify_manifest(m)

    def test_an_inflated_lower_bound_is_rejected(self):
        m = self._mutate(lambda d: d["validity"].update(agent_resistance_lower_bound=99.0))
        with self.assertRaisesRegex(V.InconsistentManifest, "lower bound must charge"):
            V.verify_manifest(m)

    def test_completion_cannot_be_chosen_when_the_facts_force_partial(self):
        """The runner computes completion; a submitter restating it is checked against the facts."""
        import copy
        m = copy.deepcopy(reference("vulnerable"))
        dropped = m["findings"].pop()
        m["validity"]["per_task_outcomes"].pop(dropped["id"])
        m["validity"]["assessment"].update(missing_tasks=[dropped["id"]], reported_tasks=30)
        m["agent_resistance_score"] = V._fixed_denominator_score(
            load(ROOT / "tasks.json"), m["findings"], "B")
        m["server_posture_score"] = V._fixed_denominator_score(
            load(ROOT / "tasks.json"), m["findings"], "A")
        block = m["validity"]
        block["agent_resistance_lower_bound"] = V._fixed_denominator_score(
            load(ROOT / "tasks.json"), m["findings"], "B", missing_asr=1.0)
        block["server_posture_lower_bound"] = V._fixed_denominator_score(
            load(ROOT / "tasks.json"), m["findings"], "A", missing_asr=1.0)
        reseal(m)
        with self.assertRaisesRegex(V.InconsistentManifest, "says 'complete' but the run has"):
            V.verify_manifest(m)


class NestedFieldTyping(unittest.TestCase):
    """The schema types every nested field; the verifier must too, or the two disagree.

    Each case below was ACCEPTED before: `_check_structure` validated the top level and stopped.
    """

    def _mutate(self, fn):
        import copy
        m = copy.deepcopy(reference("vulnerable"))
        fn(m)
        return reseal(m)

    def test_target_fields_are_typed(self):
        for name, fn, pattern in (
            ("note is an object", lambda d: d["target"].update(note={"a": 1}), "note must be a string"),
            ("note is a number", lambda d: d["target"].update(note=5), "note must be a string"),
            ("kind is empty", lambda d: d["target"].update(kind=""), "kind must be a non-empty"),
            ("model_snapshot is a list", lambda d: d["target"].update(model_snapshot=[]),
             "model_snapshot must be a string or null"),
        ):
            with self.subTest(case=name):
                with self.assertRaisesRegex(V.InconsistentManifest, pattern):
                    V.verify_manifest(self._mutate(fn))

    def test_an_unknown_field_inside_target_is_rejected(self):
        with self.assertRaisesRegex(V.MalformedManifest, "target has unknown field"):
            V.verify_manifest(self._mutate(lambda d: d["target"].update(sneaky=1)))

    def test_harness_fields_are_typed(self):
        for key in ("engine", "assay_version"):
            with self.subTest(field=key):
                with self.assertRaisesRegex(V.InconsistentManifest, f"harness.{key} must be"):
                    V.verify_manifest(self._mutate(lambda d, k=key: d["harness"].update({k: None})))

    def test_top_level_strings_must_be_non_empty_strings(self):
        for key in ("target_fingerprint", "generated_at"):
            with self.subTest(field=key):
                with self.assertRaisesRegex(V.InconsistentManifest, key):
                    V.verify_manifest(self._mutate(lambda d, k=key: d.update({k: 12345})))

    def test_a_model_snapshot_of_null_is_allowed(self):
        """Null is the honest value for a target that is not a model; it must stay legal."""
        m = self._mutate(lambda d: d["target"].update(model_snapshot=None))
        self.assertIn("internally_consistent", V.verify_manifest(m)["levels_verified"])
