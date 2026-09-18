"""Generated artifacts stay current, the published schema matches the executable checks,
and every executable snippet in the documentation actually runs."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from .helpers import ROOT, V
from assay_bench.manifest import (OPTIONAL_TOP_LEVEL, REQUIRED_FINDING, REQUIRED_TOP_LEVEL,
                                  validate_structure)


def sh(*args, cwd=ROOT, env=None):
    return subprocess.run([sys.executable, *args], cwd=cwd, capture_output=True, text=True,
                          env=env)


class SchemaParity(unittest.TestCase):
    """manifest_schema.json is the published contract; assay_bench.manifest is the code that
    enforces it. Nothing loads a JSON Schema engine at runtime, so these must be kept in
    step by test rather than by faith."""

    def setUp(self):
        self.schema = json.loads((ROOT / "manifest_schema.json").read_text())

    def test_required_top_level_fields_agree(self):
        self.assertEqual(sorted(self.schema["required"]), sorted(REQUIRED_TOP_LEVEL))

    def test_declared_properties_agree(self):
        self.assertEqual(sorted(self.schema["properties"]),
                         sorted(set(REQUIRED_TOP_LEVEL) | set(OPTIONAL_TOP_LEVEL)))

    def test_finding_required_fields_agree(self):
        item = self.schema["properties"]["findings"]["items"]
        self.assertEqual(sorted(item["required"]), sorted(REQUIRED_FINDING))

    def test_enumerations_agree(self):
        item = self.schema["properties"]["findings"]["items"]["properties"]
        self.assertEqual(item["mode"]["enum"], ["A", "B"])
        self.assertEqual(item["oracle"]["enum"], ["canary", "protocol", "behavioral"])
        self.assertEqual(item["evidence_type"]["enum"], ["canary", "protocol-fact", "behavioral"])
        self.assertEqual(self.schema["properties"]["track"]["enum"], ["agent", "server"])

    def test_the_schema_forbids_extra_fields_and_so_does_the_code(self):
        self.assertFalse(self.schema["additionalProperties"])
        m = json.loads((ROOT / "leaderboard" / "manifests" / "reference_hardened.json").read_text())
        m["surprise"] = 1
        from assay_bench.errors import MalformedInput
        with self.assertRaises(MalformedInput):
            validate_structure(m)

    def test_every_shipped_manifest_passes_the_executable_schema(self):
        for path in sorted((ROOT / "leaderboard" / "manifests").glob("*.json")):
            with self.subTest(manifest=path.name):
                validate_structure(json.loads(path.read_text()))

    def test_legacy_manifests_pass_the_executable_schema_too(self):
        for path in sorted((ROOT / "tests" / "fixtures" / "legacy_v0_1").glob("reference_*.json")):
            with self.subTest(manifest=path.name):
                validate_structure(json.loads(path.read_text()))


class GeneratedFilesAreCurrent(unittest.TestCase):
    """A generator must be idempotent: running it against a clean tree must not change a
    byte. CI additionally runs `git diff --exit-code` so a stale committed artifact fails
    the build; here we test the property that makes that check meaningful."""

    def _idempotent(self, script_args, *paths):
        targets = [ROOT / p for p in paths]
        before = {p: p.read_bytes() for p in targets if p.is_file()}
        r = sh(*script_args)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        after = {p: p.read_bytes() for p in targets if p.is_file()}
        self.assertEqual(sorted(before), sorted(after), "a generator added or removed a file")
        for path in targets:
            self.assertEqual(before.get(path), after.get(path),
                             f"{path.name} changed when regenerated from a clean tree")

    def test_coverage_matrix_regenerates_identically(self):
        self._idempotent(["coverage.py"], "COVERAGE.md")

    def test_leaderboard_site_regenerates_identically(self):
        self._idempotent(["leaderboard/build_site.py"], "leaderboard/index.md")

    def test_packaged_task_set_is_in_sync_with_the_canonical_one(self):
        r = sh("-m", "assay_bench.sync_data", "--check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_reference_artifacts_regenerate_to_the_same_invariants(self):
        r = sh("-m", "assay_bench", "reference", "--check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        payload = json.loads(r.stdout)
        self.assertTrue(payload["ok"], payload["problems"])
        self.assertIn("run_secret_reveal", payload["expected_to_differ"])

    def test_reference_regeneration_is_byte_reproducible(self):
        self._idempotent(
            ["-m", "assay_bench", "reference"],
            "leaderboard/manifests/reference_vulnerable.json",
            "leaderboard/manifests/reference_hardened.json",
            "leaderboard/manifests/reference_mixed.json",
            "reference/conformance_matrix.json")


class ConformanceMatrixHonesty(unittest.TestCase):
    def setUp(self):
        self.matrix = json.loads((ROOT / "reference" / "conformance_matrix.json").read_text())

    def test_it_says_plainly_that_it_is_not_a_product_measurement(self):
        blurb = self.matrix["what_this_is"].lower()
        self.assertIn("deterministic", blurb)
        self.assertIn("not a measurement", blurb)

    def test_it_explains_why_there_are_no_confidence_intervals(self):
        self.assertIn("why_there_are_no_confidence_intervals", self.matrix)
        self.assertTrue(all("asr_ci" not in row for row in self.matrix["rows"]))
        self.assertTrue(all("fp_ci" not in row for row in self.matrix["rows"]))

    def test_recall_specificity_and_discrimination_all_hold(self):
        s = self.matrix["summary"]
        self.assertTrue(s["recall_all_attacks_fire_on_vulnerable"])
        self.assertTrue(s["specificity_nothing_fires_on_hardened"])
        self.assertTrue(s["discrimination_mixed_matches_published_subset"])
        self.assertEqual(s["canary_false_positives_on_hardened"], 0)

    def test_it_covers_every_frozen_task(self):
        self.assertEqual(self.matrix["n_tasks"], 31)
        self.assertEqual(len(self.matrix["rows"]), 31)


class ExecutableDocumentation(unittest.TestCase):
    """Every fenced bash command in the docs is extracted and run. A documented command
    that does not exist is the defect that started this audit."""

    DOCS = ("README.md", "SPEC.md", "CONTRIBUTING.md", "corpus/README.md",
            "leaderboard/SUBMIT.md", "demo/DEMO_RUNBOOK.md")

    #: Commands we run verbatim. Anything else found in the docs must be listed in
    #: ALLOWED_UNRUN with a reason, so a new undocumented command cannot slip in.
    ALLOWED_UNRUN = {
        "pip install -e .": "mutates the environment; covered by test_packaging",
        "python -m unittest discover -s tests -t .": (
            "running the suite inside the suite would recurse forever; this IS the suite"),
        "python -m pytest tests/ -q": (
            "optional third-party runner, deliberately not a dependency; the same tests run "
            "under unittest, which is what CI's core job uses"),
        "python -m build": "requires the 'build' package; covered by test_packaging",
        "pip install assay-bench": "requires a PyPI release that does not exist yet",
        "git add precommit/registry/<run-id>.json": "illustrative git usage",
        "git commit -m 'precommit: <target>'": "illustrative git usage",
        "git push": "illustrative git usage",
        "python -m assay_bench precommit --target vulnerable --trials 25 --secret-out /tmp/run.secret": (
            "writes a registry record into the repository, so running it here would dirty the "
            "tree; tests/test_precommit.py drives the same CLI against a temporary registry"),
        "bash demo/reset.sh": "covered by tests/test_demo.py",
        "bash demo/run_demo.sh": "covered by tests/test_demo.py",
        "ASSAY_DEMO_PAUSE=1.1 bash demo/run_demo.sh": (
            "the same script with pacing; tests/test_demo.py runs it paced and asserts the "
            "outcome is identical"),
        "bash demo/record_video.sh": "needs a browser and encoder; covered by test_demo",
    }

    def _commands(self, doc: Path):
        text = doc.read_text(encoding="utf-8")
        out = []
        for block in re.findall(r"```(?:bash|sh|console)\n(.*?)```", text, re.S):
            for line in block.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                line = re.sub(r"\s+#.*$", "", line).strip()
                if line:
                    out.append(line)
        return out

    def test_every_documented_command_is_runnable_or_explicitly_excused(self):
        checked = 0
        for name in self.DOCS:
            doc = ROOT / name
            if not doc.is_file():
                continue
            for command in self._commands(doc):
                if command in self.ALLOWED_UNRUN:
                    continue
                if "<" in command or ">" in command:
                    continue  # placeholder arguments, exercised by the CLI tests
                with self.subTest(doc=name, command=command):
                    parts = command.split()
                    self.assertIn(parts[0], ("python", "python3"),
                                  f"{name}: undocumented tool {parts[0]!r}")
                    r = sh(*parts[1:])
                    self.assertIn(r.returncode, (0,),
                                  f"{name}: `{command}` exited {r.returncode}\n"
                                  f"{r.stdout[-600:]}\n{r.stderr[-600:]}")
                    checked += 1
        self.assertGreater(checked, 5, "documentation should contain runnable commands")

    #: Modules the docs may mention without this repo depending on them. Each needs a reason,
    #: so an accidentally-documented missing module still fails.
    OPTIONAL_MODULES = {
        "pytest": "an optional alternative runner; the suite requires only unittest",
        "build": "an optional packaging front-end; the wheel also builds via setuptools directly",
    }

    def test_no_documentation_references_a_module_that_does_not_exist(self):
        for name in self.DOCS + ("TASKS.md", "leaderboard/SUBMIT.md"):
            doc = ROOT / name
            if not doc.is_file():
                continue
            for match in re.findall(r"python -m ([\w.]+)", doc.read_text(encoding="utf-8")):
                if match in self.OPTIONAL_MODULES:
                    continue
                with self.subTest(doc=name, module=match):
                    r = sh("-c", f"import importlib; importlib.import_module({match!r})")
                    self.assertEqual(r.returncode, 0,
                                     f"{name} documents `python -m {match}` which does not import")


class ClaimConsistency(unittest.TestCase):
    """Wording that the audit withdrew must not creep back in."""

    WITHDRAWN = {
        "kills cherry-picking": "precommitment does not prove every run was published",
        "auditable cold": "verification is coherence, not attestation",
        "cannot be inflated or self-reported": "a keyholder can fabricate a passing canary",
        "open wedge": "four MCP security benchmarks predate this repository",
        "zero false positives instead of": "scoped to canary tasks only, and FP != FN",
    }
    SURFACES = ("README.md", "SPEC.md", "CONTRIBUTING.md", "corpus/README.md",
                "leaderboard/SUBMIT.md", "leaderboard/index.md", "COVERAGE.md",
                "CITATION.cff", "assay_verifier.py", "scoring.py", "badge.py",
                "leaderboard/build_site.py", "manifest_schema.json")

    def test_withdrawn_claims_are_absent_from_every_surface(self):
        for name in self.SURFACES:
            path = ROOT / name
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8").lower()
            for phrase, why in self.WITHDRAWN.items():
                with self.subTest(surface=name, phrase=phrase):
                    self.assertNotIn(phrase.lower(), text, f"{name}: {why}")

    def test_the_license_is_stated_consistently(self):
        self.assertIn("MIT License", (ROOT / "LICENSE").read_text())
        for name in ("SPEC.md", "README.md", "NOTICE", "CITATION.cff"):
            text = (ROOT / name).read_text(encoding="utf-8")
            with self.subTest(surface=name):
                self.assertNotIn("Apache", text,
                                 f"{name} names a licence that is not the one in LICENSE")

    def test_the_verification_vocabulary_is_used_everywhere_it_should_be(self):
        for name in ("README.md", "SPEC.md", "leaderboard/SUBMIT.md", "leaderboard/index.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            with self.subTest(surface=name):
                self.assertIn("internally_consistent", text)

    def test_the_task_count_is_stated_consistently(self):
        catalog_size = len(json.loads((ROOT / "tasks.json").read_text())["tasks"])
        self.assertEqual(catalog_size, 31)
        for name in ("README.md", "SPEC.md", "COVERAGE.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            with self.subTest(surface=name):
                self.assertIn("31", text)


if __name__ == "__main__":
    unittest.main()
