"""Replication submissions: complete, consistent with their bundle, and claiming no more than the
evidence supports.

The cases that matter most are the ones that would let a submission overclaim: a Level-2
("independently witnessed") claim with no receipts, or with receipts the operator signed itself;
a Level-3 ("independently reproduced") claim with nothing it reproduces, or by the original
operator; and a template that passes before anyone has filled it in.
"""

from __future__ import annotations

import argparse
import contextlib
import glob
import io
import json
import tempfile
import unittest
from pathlib import Path

from .helpers import ROOT
from assay_bench import ed25519
from assay_bench.replication import SCHEMA, add_cli, validate_submission

TEMPLATE = ROOT / "experiments" / "independent-replications" / "TEMPLATE.submission.json"
SYNTHETIC_CONFIG = ROOT / "experiments" / "examples" / "synthetic-local" / "experiment.json"


def status(result: dict, name: str) -> str:
    return next(c["status"] for c in result["checks"] if c["name"] == name)


def detail(result: dict, name: str) -> str:
    return next(c["detail"] for c in result["checks"] if c["name"] == name)


def structural_submission() -> dict:
    """A complete, well-formed submission with no bundle-dependent claims."""
    return {
        "schema": SCHEMA,
        "researcher": {"id": "researcher-b", "is_pseudonym": True, "contact": None},
        "assay_commit": "a" * 40,
        "experiment": {"experiment_id": "exp-20261029-0123abcd", "config_path": "config.json"},
        "model": {"provider": "example", "api_model_id": "example/model-1",
                  "routing_service": None, "provider_reported_models": ["example/model-1"],
                  "model_revision": None},
        "results": {"configurations": [{
            "name": "baseline", "trials_scheduled": 10, "trials_executed": 10,
            "attack_succeeded": 3, "attack_failed": 5, "inconclusive": 1,
            "infrastructure_failures": 1, "unsupported": 0}]},
        "evidence": {"bundle_path": "researcher-b-exp", "artifact_index_sha256": "b" * 64,
                     "artifact_signing_public_key": "c" * 64},
        "verification": {"ok": True, "checks": [{"name": "files_match_index", "ok": True}],
                         "experiment_id": "exp-20261029-0123abcd"},
        "witness": None,
        "deviations": [],
        "replicates": None,
        "evidence_levels": {"self_reported": True, "independently_witnessed": False,
                            "independently_reproduced": False},
    }


class Structural(unittest.TestCase):
    def test_a_complete_self_reported_submission_is_structurally_valid(self):
        result = validate_submission(structural_submission())
        self.assertTrue(result["ok"], result["checks"])
        self.assertEqual(status(result, "bundle_checks"), "not_checked")
        self.assertIn("not proof of factual authenticity", result["note"])
        self.assertTrue(result["evidence_levels"]["self_reported"]["supported"])

    def test_missing_deviations_field_is_rejected(self):
        doc = structural_submission()
        del doc["deviations"]
        result = validate_submission(doc)
        self.assertFalse(result["ok"])
        self.assertEqual(status(result, "required_fields"), "fail")
        self.assertIn("deviations", detail(result, "required_fields"))
        self.assertEqual(status(result, "deviations"), "fail")

    def test_an_empty_deviations_list_is_allowed(self):
        self.assertTrue(validate_submission(structural_submission())["ok"])

    def test_a_deviation_must_say_why_and_what_it_changes(self):
        doc = structural_submission()
        doc["deviations"] = [{"description": "ran 10 trials instead of 25"}]
        self.assertEqual(status(validate_submission(doc), "deviations"), "fail")

    def test_outcome_counts_must_add_up(self):
        doc = structural_submission()
        doc["results"]["configurations"][0]["attack_failed"] = 4
        self.assertEqual(status(validate_submission(doc), "results_summary"), "fail")

    def test_a_failing_verification_output_is_rejected(self):
        doc = structural_submission()
        doc["verification"]["ok"] = False
        self.assertEqual(status(validate_submission(doc), "verification_output"), "fail")

    def test_self_reported_must_be_true(self):
        doc = structural_submission()
        doc["evidence_levels"]["self_reported"] = False
        self.assertEqual(status(validate_submission(doc), "evidence_levels"), "fail")

    def test_the_template_fails_until_filled_in(self):
        doc = json.loads(TEMPLATE.read_text(encoding="utf-8"))
        result = validate_submission(doc)
        self.assertFalse(result["ok"])
        self.assertEqual(status(result, "no_placeholders"), "fail")
        # It must remain a structurally complete starting point, not a broken file.
        self.assertEqual(status(result, "required_fields"), "pass")
        self.assertEqual(status(result, "schema"), "pass")


class EvidenceLevels(unittest.TestCase):
    def test_level_2_claim_without_receipts_is_rejected(self):
        doc = structural_submission()
        doc["evidence_levels"]["independently_witnessed"] = True
        result = validate_submission(doc)
        self.assertFalse(result["ok"])
        self.assertEqual(status(result, "claim_independently_witnessed"), "fail")
        self.assertFalse(result["evidence_levels"]["independently_witnessed"]["supported"])

    def test_level_2_claim_cannot_be_confirmed_without_the_bundle(self):
        doc = structural_submission()
        doc["evidence_levels"]["independently_witnessed"] = True
        doc["witness"] = {"name": "w", "public_key": "d" * 64, "independent": True,
                          "receipts_path": "witness/receipts.jsonl"}
        result = validate_submission(doc)
        self.assertEqual(status(result, "claim_independently_witnessed"), "fail")
        self.assertIn("--bundle", detail(result, "claim_independently_witnessed"))

    def test_self_signed_witness_claimed_independent_is_rejected(self):
        doc = structural_submission()
        doc["evidence_levels"]["independently_witnessed"] = True
        signing = doc["evidence"]["artifact_signing_public_key"]
        doc["witness"] = {"name": "me", "public_key": signing, "independent": True,
                          "receipts_path": "witness/receipts.jsonl"}
        result = validate_submission(doc)
        self.assertEqual(status(result, "claim_independently_witnessed"), "fail")
        self.assertIn("artifact-signing key", detail(result, "claim_independently_witnessed"))

    def test_level_3_claim_without_replicates_is_rejected(self):
        doc = structural_submission()
        doc["evidence_levels"]["independently_reproduced"] = True
        result = validate_submission(doc)
        self.assertFalse(result["ok"])
        self.assertEqual(status(result, "claim_independently_reproduced"), "fail")
        self.assertIn("replicates", detail(result, "claim_independently_reproduced"))

    def test_level_3_by_the_original_operator_is_rejected(self):
        doc = structural_submission()
        doc["evidence_levels"]["independently_reproduced"] = True
        doc["replicates"] = {"experiment_id": "exp-20261001-00000001", "scorecard": None,
                             "original_operator": "Researcher-B "}
        result = validate_submission(doc)
        self.assertEqual(status(result, "claim_independently_reproduced"), "fail")

    def test_level_3_is_supported_without_implying_level_2(self):
        doc = structural_submission()
        doc["evidence_levels"]["independently_reproduced"] = True
        doc["replicates"] = {"experiment_id": "exp-20261001-00000001", "scorecard": None,
                             "original_operator": "researcher-a"}
        result = validate_submission(doc)
        self.assertTrue(result["ok"], result["checks"])
        self.assertTrue(result["evidence_levels"]["independently_reproduced"]["supported"])
        self.assertFalse(result["evidence_levels"]["independently_witnessed"]["claimed"])
        self.assertIsNone(result["evidence_levels"]["independently_witnessed"]["supported"])


class Cli(unittest.TestCase):
    def _parser(self):
        parser = argparse.ArgumentParser()
        add_cli(parser.add_subparsers(dest="command"))
        return parser

    def test_validate_exit_codes(self):
        tmp = Path(tempfile.mkdtemp())
        good = tmp / "good.submission.json"
        good.write_text(json.dumps(structural_submission()))
        with contextlib.redirect_stdout(io.StringIO()):
            args = self._parser().parse_args(["replication", "validate", str(good)])
            self.assertEqual(args.func(args), 0)
            args = self._parser().parse_args(["replication", "validate", str(TEMPLATE)])
            self.assertEqual(args.func(args), 1)

    def test_malformed_json_is_malformed_input(self):
        from assay_bench.errors import MalformedInput

        tmp = Path(tempfile.mkdtemp())
        bad = tmp / "bad.json"
        bad.write_text("{not json")
        args = self._parser().parse_args(["replication", "validate", str(bad)])
        with self.assertRaises(MalformedInput):
            args.func(args)


class AgainstABundle(unittest.TestCase):
    """End to end against a synthetic bundle, when the experiment and bundle workstreams are
    present. Skipped, with the reason, when they are not."""

    @classmethod
    def setUpClass(cls):
        try:
            from assay_bench import bundle, experiment  # noqa: F401
            from assay_bench import witness_receipt  # noqa: F401
        except ImportError as exc:
            raise unittest.SkipTest(f"experiment/bundle modules unavailable: {exc}")
        if not SYNTHETIC_CONFIG.is_file():
            raise unittest.SkipTest(f"{SYNTHETIC_CONFIG.relative_to(ROOT)} is not present")

    def _make_bundle(self) -> Path:
        from assay_bench import experiment

        out = Path(tempfile.mkdtemp())
        parser = argparse.ArgumentParser()
        experiment.add_cli(parser.add_subparsers(dest="command"))
        args = parser.parse_args(["experiment", "run", "--config", str(SYNTHETIC_CONFIG),
                                  "--out", str(out)])
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = args.func(args)
        self.assertEqual(rc, 0)
        found = sorted(glob.glob(str(out / "exp-*")))
        self.assertEqual(len(found), 1, found)
        return Path(found[0])

    def _sign(self, bdir: Path, key: bytes) -> None:
        from assay_bench import bundle

        exp_id = json.loads((bdir / "experiment.json").read_text())["experiment"]["experiment_id"]
        bundle.build_index(bdir, experiment_id=exp_id)
        bundle.sign_index(bdir, key, signer="operator")

    def _submission(self, bdir: Path) -> dict:
        from assay_bench import bundle

        exp = json.loads((bdir / "experiment.json").read_text())
        index = json.loads((bdir / "artifact_index.json").read_text())
        sig = bdir / "artifact_index.sig.json"
        doc = structural_submission()
        doc["assay_commit"] = exp["experiment"]["repository_commit"] or "f" * 40
        doc["experiment"] = {"experiment_id": exp["experiment"]["experiment_id"],
                             "config_path": "config.json"}
        m = exp["model"]
        doc["model"] = {k: m.get(k) for k in ("provider", "api_model_id", "routing_service",
                                              "model_revision")}
        doc["model"]["provider_reported_models"] = list(m.get("provider_reported_models") or [])
        doc["results"] = {"configurations": [
            {"name": r["configuration"], **{k: r[k] for k in (
                "trials_scheduled", "trials_executed", "attack_succeeded", "attack_failed",
                "inconclusive", "infrastructure_failures", "unsupported")}}
            for r in exp["runs"]]}
        doc["evidence"] = {"bundle_path": str(bdir), "artifact_index_sha256":
                           bundle.index_sha256(index),
                           "artifact_signing_public_key":
                           json.loads(sig.read_text())["public_key"] if sig.is_file() else None}
        doc["verification"] = bundle.verify_bundle(bdir)
        return doc

    def _add_receipts(self, bdir: Path, witness_key: bytes, *, independent: bool) -> str:
        from assay_bench import witness_receipt as wr

        exp_id = json.loads((bdir / "experiment.json").read_text())["experiment"]["experiment_id"]
        trial_id, digest = None, None
        for tfile in sorted(bdir.glob("configurations/*/trials.json")):
            tasks = json.loads(tfile.read_text()).get("tasks") or {}
            for records in tasks.values():
                for rec in records:
                    if rec.get("canary_digest") and rec.get("trial_id"):
                        trial_id, digest = rec["trial_id"], rec["canary_digest"]
                        break
                if trial_id:
                    break
            if trial_id:
                break
        if trial_id is None:
            self.skipTest("synthetic bundle has no canary-bearing trial to witness")
        pub = ed25519.public_key(witness_key).hex()
        receipt = wr.sign_receipt(wr.build_receipt(
            experiment_id=exp_id, trial_id=trial_id, canary_id=digest, witness_name="witness-x",
            public_key=pub, independent=independent, sink="/egress",
            payload=f"leak {digest}".encode(), sequence=0), witness_key)
        (bdir / "witness").mkdir(exist_ok=True)
        (bdir / "witness" / "receipts.jsonl").write_text(json.dumps(receipt) + "\n")
        (bdir / "witness" / "trusted_keys.json").write_text(json.dumps(
            wr.trusted_keys_document([{"name": "witness-x", "public_key": pub,
                                       "independent": independent}])))
        return pub

    def test_valid_submission_against_its_bundle(self):
        bdir = self._make_bundle()
        # Outside a git checkout (an unpacked sdist) the runner records repository_commit null,
        # and the validator rightly refuses to confirm a commit the bundle never recorded. No
        # submission can be valid against such a bundle, so there is nothing to test here.
        exp = json.loads((bdir / "experiment.json").read_text())
        if exp["experiment"]["repository_commit"] is None:
            self.skipTest("bundle recorded no repository commit (not a git checkout)")
        self._sign(bdir, ed25519.generate_keypair()[0])
        doc = self._submission(bdir)
        result = validate_submission(doc, bundle_dir=bdir)
        self.assertTrue(result["ok"], [c for c in result["checks"] if c["status"] == "fail"])
        for name in ("artifact_index_digest", "bundle_verifies", "trial_counts_match",
                     "model_identity_matches", "experiment_id_matches"):
            self.assertEqual(status(result, name), "pass", name)

    def test_counts_that_disagree_with_the_bundle_are_rejected(self):
        bdir = self._make_bundle()
        self._sign(bdir, ed25519.generate_keypair()[0])
        doc = self._submission(bdir)
        # Still structurally valid (executed <= scheduled), but not what the bundle says.
        doc["results"]["configurations"][0]["trials_scheduled"] += 1
        result = validate_submission(doc, bundle_dir=bdir)
        self.assertEqual(status(result, "results_summary"), "pass")
        self.assertEqual(status(result, "trial_counts_match"), "fail")

    def test_self_signed_witness_in_the_bundle_does_not_support_level_2(self):
        bdir = self._make_bundle()
        key = ed25519.generate_keypair()[0]
        pub = self._add_receipts(bdir, key, independent=True)
        self._sign(bdir, key)  # the operator's artifact key IS the witness key
        doc = self._submission(bdir)
        doc["evidence"]["artifact_signing_public_key"] = None  # make the bundle reveal it
        doc["witness"] = {"name": "witness-x", "public_key": pub, "independent": True,
                          "receipts_path": "witness/receipts.jsonl"}
        doc["evidence_levels"]["independently_witnessed"] = True
        result = validate_submission(doc, bundle_dir=bdir)
        self.assertEqual(status(result, "claim_independently_witnessed"), "fail")
        self.assertIn("artifact-signing key", detail(result, "claim_independently_witnessed"))

    def test_independent_witness_receipts_support_level_2(self):
        bdir = self._make_bundle()
        witness_key = ed25519.generate_keypair()[0]
        pub = self._add_receipts(bdir, witness_key, independent=True)
        self._sign(bdir, ed25519.generate_keypair()[0])
        doc = self._submission(bdir)
        doc["witness"] = {"name": "witness-x", "public_key": pub, "independent": True,
                          "receipts_path": "witness/receipts.jsonl"}
        doc["evidence_levels"]["independently_witnessed"] = True
        result = validate_submission(doc, bundle_dir=bdir)
        self.assertEqual(status(result, "claim_independently_witnessed"), "pass",
                         detail(result, "claim_independently_witnessed"))
        self.assertFalse(result["evidence_levels"]["independently_reproduced"]["claimed"])


if __name__ == "__main__":
    unittest.main()
