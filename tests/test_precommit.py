"""Precommitment ordering, tested against real git repositories.

Each test builds a throwaway repo, commits artifacts in a chosen order, and asserts which
verification level the result reaches. Nothing is mocked, because the whole point of the
design is that the ordering authority is git history rather than a timestamp a submitter
wrote into a file.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from .helpers import V
from assay_bench import precommit
from assay_bench.adapters.conformance import build as build_target
from assay_bench.catalog import load_catalog
from assay_bench.errors import MalformedInput, PrecommitmentError
from assay_bench.provenance import target_fingerprint
from assay_bench.runner import run

CATALOG = load_catalog()
GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "Assay Test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "Assay Test", "GIT_COMMITTER_EMAIL": "test@example.invalid",
}


class _RepoCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="assay-precommit-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._git("init", "-q", "-b", "main")
        (self.tmp / "precommit" / "registry").mkdir(parents=True)
        (self.tmp / "leaderboard" / "manifests").mkdir(parents=True)
        (self.tmp / "README").write_text("seed\n")
        self._git("add", "-A")
        self._git("commit", "-qm", "seed")

    def _git(self, *args, when: int | None = None):
        env = dict(GIT_ENV)
        if when is not None:
            stamp = f"{when} +0000"
            env["GIT_AUTHOR_DATE"] = stamp
            env["GIT_COMMITTER_DATE"] = stamp
        result = subprocess.run(["git", "-C", str(self.tmp), *args], env=env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def _make_run(self, target="vulnerable", trials=2, secret=None):
        adapter = build_target(target)
        fingerprint = target_fingerprint(adapter, CATALOG)
        secret = secret or "9f" * 32
        record = precommit.create_record(
            run_secret=secret, benchmark_version=CATALOG.version,
            task_set_digest=CATALOG.digest, target_fingerprint=fingerprint, trials=trials)
        manifest = run(adapter, catalog=CATALOG, trials=trials, run_secret=secret,
                       command="test", run_id=record["run_id"])
        return record, manifest

    def _write_record(self, record):
        path = self.tmp / "precommit" / "registry" / f"{record['run_id']}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, indent=2) + "\n")
        return path

    def _write_manifest(self, manifest, name="result.json"):
        path = self.tmp / "leaderboard" / "manifests" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(manifest, indent=2) + "\n")
        return path

    def _verify(self, manifest, manifest_path, **kw):
        return precommit.verify(manifest, repo=self.tmp, manifest_path=str(manifest_path),
                                registry_dir=self.tmp / "precommit" / "registry", **kw)


class ValidOrdering(_RepoCase):
    def test_commitment_committed_before_the_manifest_verifies_ordering(self):
        record, manifest = self._make_run()
        self._write_record(record)
        self._git("add", "-A")
        self._git("commit", "-qm", "precommit", when=1_700_000_000)

        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "result", when=1_700_000_600)

        out = self._verify(manifest, path)
        self.assertIn(precommit.LEVEL_LOCAL, out["levels_verified"])
        self.assertIn(precommit.LEVEL_REPO, out["levels_verified"])
        self.assertNotIn(precommit.LEVEL_EXTERNAL, out["levels_verified"],
                         "a local clone cannot establish external timestamping")
        self.assertIn("forge witness", out["levels_not_established"][precommit.LEVEL_EXTERNAL])

    def test_a_forge_witness_upgrades_to_precommitment_verified(self):
        record, manifest = self._make_run()
        self._write_record(record)
        self._git("add", "-A")
        self._git("commit", "-qm", "precommit", when=1_700_000_000)
        commitment_commit = self._git("rev-parse", "HEAD")

        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "result", when=1_700_000_600)

        out = self._verify(manifest, path,
                           external_witness={"commitment_commit": commitment_commit,
                                             "source": "test-forge"})
        self.assertIn(precommit.LEVEL_EXTERNAL, out["levels_verified"])

    def test_a_witness_naming_the_wrong_commit_does_not_upgrade(self):
        record, manifest = self._make_run()
        self._write_record(record)
        self._git("add", "-A")
        self._git("commit", "-qm", "precommit", when=1_700_000_000)
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "result", when=1_700_000_600)
        out = self._verify(manifest, path,
                           external_witness={"commitment_commit": "0" * 40})
        self.assertNotIn(precommit.LEVEL_EXTERNAL, out["levels_verified"])


class RenameHeuristicsMustNotDecideOrdering(_RepoCase):
    """`git log --follow` is a similarity heuristic, and two manifests look alike to it.

    The first real precommitted run in this repository was denied `repository_ordering_verified`
    because `--follow` traced its manifest back to an unrelated reference manifest added in the
    baseline commit. Both directions of that error matter: following a manifest to an older file
    denies an honest submission, and following a *registry record* to an older file would make a
    commitment look earlier than it is, which is a soundness failure rather than an annoyance.
    """

    def _similar_file(self, directory: str, name: str, payload: dict, when: int):
        path = self.tmp / directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2) + "\n")
        self._git("add", "-A")
        self._git("commit", "-qm", f"add {name}", when=when)
        return path

    def test_an_older_lookalike_manifest_does_not_become_this_ones_commit(self):
        record, manifest = self._make_run()
        # An earlier, structurally near-identical manifest. Rename detection finds it similar.
        decoy = dict(manifest)
        decoy["run_id"] = "00000000-0000-4000-8000-000000000000"
        self._similar_file("leaderboard/manifests", "reference_decoy.json", decoy,
                           when=1_600_000_000)

        self._write_record(record)
        self._git("add", "-A")
        self._git("commit", "-qm", "precommit", when=1_700_000_000)
        path = self._write_manifest(manifest, name="precommitted_result.json")
        self._git("add", "-A")
        self._git("commit", "-qm", "result", when=1_700_000_600)

        sha, timestamp = precommit.introducing_commit(
            self.tmp, "leaderboard/manifests/precommitted_result.json")
        self.assertEqual(timestamp, 1_700_000_600,
                         "the manifest's commit was resolved to an older lookalike")
        out = self._verify(manifest, path)
        self.assertIn(precommit.LEVEL_REPO, out["levels_verified"],
                      out["levels_not_established"])

    def test_an_older_lookalike_record_cannot_lend_a_commitment_its_date(self):
        """The soundness direction: a commitment must not inherit an older file's commit."""
        record, manifest = self._make_run()
        # A genuine second record, so the registry loader accepts it and the question under
        # test is ordering rather than validation.
        decoy = precommit.create_record(
            run_secret="1a" * 32, benchmark_version=CATALOG.version,
            task_set_digest=CATALOG.digest,
            target_fingerprint=record["target_fingerprint"], trials=2)
        self._similar_file("precommit/registry", f"{decoy['run_id']}.json", decoy,
                           when=1_600_000_000)

        # Commit the manifest FIRST, then the commitment: the ordering is genuinely wrong.
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "result", when=1_700_000_000)
        self._write_record(record)
        self._git("add", "-A")
        self._git("commit", "-qm", "precommit", when=1_700_000_600)

        out = self._verify(manifest, path)
        self.assertNotIn(precommit.LEVEL_REPO, out["levels_verified"],
                         "a commitment committed after the result was accepted because rename "
                         "detection lent it an older file's commit")


class InvalidOrdering(_RepoCase):
    def test_same_commit_commitment_and_reveal_prove_nothing(self):
        """This is exactly the v0.1 situation, and it must not read as verified."""
        record, manifest = self._make_run()
        self._write_record(record)
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "both at once", when=1_700_000_000)

        out = self._verify(manifest, path)
        self.assertIn(precommit.LEVEL_LOCAL, out["levels_verified"])
        self.assertNotIn(precommit.LEVEL_REPO, out["levels_verified"])
        self.assertIn("same commit", out["levels_not_established"][precommit.LEVEL_REPO])

    def test_commitment_committed_after_the_manifest_is_rejected(self):
        record, manifest = self._make_run()
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "result first", when=1_700_000_000)

        self._write_record(record)
        self._git("add", "-A")
        self._git("commit", "-qm", "late commitment", when=1_700_000_600)

        out = self._verify(manifest, path)
        self.assertNotIn(precommit.LEVEL_REPO, out["levels_verified"])
        self.assertIn("not an ancestor", out["levels_not_established"][precommit.LEVEL_REPO])

    def test_clock_inversion_is_reported_even_when_ancestry_holds(self):
        record, manifest = self._make_run()
        self._write_record(record)
        self._git("add", "-A")
        self._git("commit", "-qm", "precommit", when=1_700_000_600)
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "result", when=1_700_000_000)  # earlier date, later commit

        out = self._verify(manifest, path)
        self.assertNotIn(precommit.LEVEL_REPO, out["levels_verified"])
        self.assertIn("inverted", out["levels_not_established"][precommit.LEVEL_REPO])

    def test_an_uncommitted_record_carries_no_ordering(self):
        record, manifest = self._make_run()
        self._write_record(record)  # never committed
        path = self._write_manifest(manifest)
        self._git("add", "leaderboard")
        self._git("commit", "-qm", "result only")
        out = self._verify(manifest, path)
        self.assertNotIn(precommit.LEVEL_REPO, out["levels_verified"])

    def test_history_rewrite_destroys_the_ordering_evidence(self):
        """Ancestry is read from the history that exists now. A rewrite that collapses the
        two commits into one leaves the files intact but the evidence gone -- and the
        result must degrade to 'not established', never stay verified on inertia."""
        record, manifest = self._make_run()
        record_path = self._write_record(record)
        self._git("add", "-A")
        self._git("commit", "-qm", "precommit", when=1_700_000_000)
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "result", when=1_700_000_600)
        self.assertIn(precommit.LEVEL_REPO, self._verify(manifest, path)["levels_verified"])

        saved_record = record_path.read_text()
        saved_manifest = path.read_text()
        self._git("reset", "-q", "--hard", "HEAD~2")
        self._write_record(record).write_text(saved_record)
        self._write_manifest(manifest).write_text(saved_manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "squashed rewrite", when=1_700_001_000)

        out = self._verify(manifest, path)
        self.assertIn(precommit.LEVEL_LOCAL, out["levels_verified"])
        self.assertNotIn(precommit.LEVEL_REPO, out["levels_verified"])
        self.assertIn("same commit", out["levels_not_established"][precommit.LEVEL_REPO])


class BindingAndReuse(_RepoCase):
    def test_missing_registry_record_is_an_error(self):
        _, manifest = self._make_run()
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "result")
        with self.assertRaisesRegex(PrecommitmentError, "never registered"):
            self._verify(manifest, path)

    def test_a_record_for_a_different_target_cannot_be_claimed(self):
        record, manifest = self._make_run(target="vulnerable")
        record["target_fingerprint"] = target_fingerprint(build_target("hardened"), CATALOG)
        record["record_digest"] = precommit.bound_digest(record)
        self._write_record(record)
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "both")
        with self.assertRaisesRegex(PrecommitmentError, "target_fingerprint"):
            self._verify(manifest, path)

    def test_a_record_with_a_different_trial_plan_cannot_be_claimed(self):
        record, manifest = self._make_run(trials=2)
        record["trial_plan"]["trials_per_task"] = 25
        record["record_digest"] = precommit.bound_digest(record)
        self._write_record(record)
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "both")
        with self.assertRaisesRegex(PrecommitmentError, "trials_per_task"):
            self._verify(manifest, path)

    def test_reusing_one_commitment_for_a_second_manifest_is_rejected(self):
        record, manifest = self._make_run()
        path = self._write_record(record)
        self._git("add", "-A")
        self._git("commit", "-qm", "precommit", when=1_700_000_000)

        precommit.bind_record(path, manifest)
        # A second run of the SAME target with the SAME secret and run id: every binding
        # field matches, so only the reuse rule can stop it. It must.
        second = run(build_target("vulnerable"), catalog=CATALOG, trials=2,
                     run_secret=manifest["run_secret_reveal"], command="test",
                     run_id=record["run_id"], target_note="a second publication")
        self.assertNotEqual(second["integrity_hash"], manifest["integrity_hash"])
        with self.assertRaisesRegex(PrecommitmentError, "reuse"):
            self._verify(second, self._write_manifest(second, "second.json"))

    def test_binding_the_same_manifest_twice_is_idempotent(self):
        record, manifest = self._make_run()
        path = self._write_record(record)
        precommit.bind_record(path, manifest)
        precommit.bind_record(path, manifest)
        self.assertEqual(json.loads(path.read_text())["bound_manifest_integrity_hash"],
                         manifest["integrity_hash"])

    def test_binding_a_second_manifest_to_a_bound_record_is_refused(self):
        record, manifest = self._make_run()
        path = self._write_record(record)
        precommit.bind_record(path, manifest)
        other = dict(manifest, integrity_hash="ff" * 32)
        with self.assertRaisesRegex(PrecommitmentError, "already bound"):
            precommit.bind_record(path, other)

    def test_a_manifest_whose_own_commitment_is_wrong_is_rejected_first(self):
        record, manifest = self._make_run()
        self._write_record(record)
        manifest["run_secret_commitment"] = "00" * 32
        path = self._write_manifest(manifest)
        self._git("add", "-A")
        self._git("commit", "-qm", "both")
        with self.assertRaisesRegex(PrecommitmentError, "does not bind its reveal"):
            self._verify(manifest, path)


class PrecommitCommandLine(unittest.TestCase):
    """The documented `assay precommit` flow, driven through the real CLI.

    It is excused from the documentation runner because it writes a registry record into the
    repository; here it writes into a temporary one instead, so the command itself is still
    covered.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="assay-precommit-cli-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.registry = self.tmp / "registry"

    def _cli(self, *args):
        import os
        import sys
        root = Path(__file__).resolve().parent.parent
        env = dict(os.environ, PYTHONPATH=str(root / "src"))
        return subprocess.run([sys.executable, "-m", "assay_bench", *args], cwd=root, env=env,
                              capture_output=True, text=True, timeout=120)

    def test_precommit_writes_a_valid_record_and_keeps_the_secret_out_of_it(self):
        secret_file = self.tmp / "run.secret"
        r = self._cli("precommit", "--target", "vulnerable", "--trials", "25",
                      "--registry", str(self.registry), "--secret-out", str(secret_file))
        self.assertEqual(r.returncode, 0, r.stderr)

        records = list(self.registry.glob("*.json"))
        self.assertEqual(len(records), 1)
        record = precommit.validate_record(json.loads(records[0].read_text()))

        secret = secret_file.read_text().strip()
        self.assertEqual(len(secret), 64)
        self.assertEqual(record["commitment"], precommit.secret_commitment(secret))
        self.assertNotIn(secret, records[0].read_text(),
                         "the registry record must never contain the secret it commits to")
        self.assertIsNone(record["bound_manifest_integrity_hash"])

    def test_precommit_list_flags_unrevealed_records(self):
        self._cli("precommit", "--target", "vulnerable", "--trials", "25",
                  "--registry", str(self.registry), "--secret-out", str(self.tmp / "s"))
        r = self._cli("precommit-list", "--registry", str(self.registry))
        self.assertEqual(r.returncode, 0, r.stderr)
        payload = json.loads(r.stdout)
        self.assertEqual(payload["unrevealed"], 1)
        self.assertEqual(payload["records"][0]["state"], "UNREVEALED")

    def test_precommit_verify_reports_a_missing_record_rather_than_passing(self):
        manifest = Path(__file__).resolve().parent.parent / "leaderboard" / "manifests" / "reference_vulnerable.json"
        r = self._cli("precommit-verify", "--manifest", str(manifest),
                      "--registry", str(self.registry))
        self.assertEqual(r.returncode, 1)
        self.assertIn("never registered", r.stderr)

    def test_the_shipped_worked_example_reaches_repository_ordering(self):
        """Through v0.2 the registry was empty and this test asserted that.

        It now asserts the opposite, against the real record: the protocol is not just
        implemented and unit-tested, it has been run once end to end in this repository's own
        history, and anyone with a clone can re-derive that. A local clone cannot reach
        `precommitment_verified` -- that needs a forge witness only CI can supply -- and the
        tooling must keep saying so rather than relabelling what it has.
        """
        root = Path(__file__).resolve().parent.parent
        records = sorted((root / "precommit" / "registry").glob("*.json"))
        self.assertTrue(records, "the worked example's registry record is missing")
        if not (root / ".git").exists():                  # an unpacked sdist has no history
            self.skipTest("not a git checkout, so repository ordering cannot be read")
        for record_path in records:
            record = json.loads(record_path.read_text())
            manifests = [p for p in (root / "leaderboard" / "manifests").glob("*.json")
                         if (json.loads(p.read_text()).get("provenance") or {}).get("run_id")
                         == record["run_id"]]
            with self.subTest(run_id=record["run_id"]):
                self.assertEqual(len(manifests), 1,
                                 "every committed commitment must have exactly one revealed "
                                 "manifest, or `precommit-list` should be flagging it")
                manifest = json.loads(manifests[0].read_text())
                out = precommit.verify(manifest, repo=root, manifest_path=str(manifests[0]))
                self.assertIn(precommit.LEVEL_LOCAL, out["levels_verified"])
                self.assertIn(precommit.LEVEL_REPO, out["levels_verified"],
                              out["levels_not_established"])
                self.assertNotIn(precommit.LEVEL_EXTERNAL, out["levels_verified"])


class RecordIntegrity(unittest.TestCase):
    def test_a_tampered_record_is_detected(self):
        record = precommit.create_record(run_secret="ab" * 32, benchmark_version="0.1",
                                         task_set_digest="d" * 64,
                                         target_fingerprint="cafe", trials=25)
        precommit.validate_record(record)
        record["target_fingerprint"] = "beef"
        with self.assertRaisesRegex(PrecommitmentError, "was altered"):
            precommit.validate_record(record)

    def test_unknown_schema_is_refused(self):
        record = precommit.create_record(run_secret="ab" * 32, benchmark_version="0.1",
                                         task_set_digest="d" * 64,
                                         target_fingerprint="cafe", trials=25)
        record["schema"] = "assay/precommit-record/99"
        with self.assertRaisesRegex(PrecommitmentError, "unsupported"):
            precommit.validate_record(record)

    def test_missing_fields_are_malformed(self):
        with self.assertRaises(MalformedInput):
            precommit.validate_record({"schema": precommit.RECORD_SCHEMA})

    def test_a_bad_trial_plan_is_refused_at_creation(self):
        from assay_bench.errors import ValidationError
        with self.assertRaises(ValidationError):
            precommit.create_record(run_secret="ab" * 32, benchmark_version="0.1",
                                    task_set_digest="d" * 64, target_fingerprint="x", trials=0)

    def test_duplicate_commitments_in_one_registry_are_detected(self):
        tmp = Path(tempfile.mkdtemp(prefix="assay-registry-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        for name in ("a", "b"):
            record = precommit.create_record(run_secret="cd" * 32, benchmark_version="0.1",
                                             task_set_digest="d" * 64,
                                             target_fingerprint="x", trials=5)
            (tmp / f"{name}.json").write_text(json.dumps(record))
        with self.assertRaisesRegex(PrecommitmentError, "registered twice"):
            precommit.load_registry(tmp)


if __name__ == "__main__":
    unittest.main()
