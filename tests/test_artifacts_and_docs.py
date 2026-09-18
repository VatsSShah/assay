"""Generated artifacts stay current, the published schema matches the executable checks,
and every executable snippet in the documentation actually runs."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from .helpers import ROOT, V, require_source_checkout
from assay_bench.manifest import (OPTIONAL_TOP_LEVEL, REQUIRED_FINDING, REQUIRED_TOP_LEVEL,
                                  validate_structure)


def sh(*args, cwd=ROOT, env=None):
    import os
    env = env if env is not None else dict(os.environ, PYTHONPATH=str(ROOT / "src"))
    return subprocess.run([sys.executable, *args], cwd=cwd, capture_output=True, text=True,
                          env=env)


def run_documented(command: str):
    """Execute a documented shell command, honouring a leading `VAR=value` prefix.

    The docs use `PYTHONPATH=src python -m assay_bench ...` because the package lives under
    src/. Stripping the prefix and passing it as an environment override runs exactly what a
    reader would run.
    """
    import os

    parts = command.split()
    env = dict(os.environ)
    while parts and "=" in parts[0] and not parts[0].startswith("-"):
        key, _, value = parts[0].partition("=")
        env[key] = value
        parts = parts[1:]
    if not parts or parts[0] not in ("python", "python3"):
        return None, parts
    return subprocess.run([sys.executable, *parts[1:]], cwd=ROOT, capture_output=True,
                          text=True, env=env), parts


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


class InstallInstructionsPointAtThisProject(unittest.TestCase):
    """No document may tell a reader to install a package that is not this one.

    `assay` on PyPI is an unrelated testing framework by a different author, and `assay-bench`
    is unregistered (both checked against the public index; see REMAINING_GAPS G3). A README
    line saying `pip install assay` would send readers to a stranger's code, which is a worse
    outcome than having no release at all.

    Two scopes, because they carry different risk. Inside a fenced code block the text is
    something a reader copies and runs, so it is checked in *every* tracked document including
    the audit records. In prose the same string may be a description of a withdrawn claim,
    which the audit trail must be able to quote; those documents are named below with a reason
    rather than being matched by a heuristic.
    """

    #: Documents whose job is to record what was withdrawn, so they must be able to quote it in
    #: prose. None of them may carry it in a runnable code block.
    RECORDS = {"REMAINING_GAPS.md", "CHANGELOG.md", "BASELINE_AUDIT.md", "ISSUE_1_TRIAGE.md",
               "ISSUE_1_RESPONSE.md", "CLAIM_EVIDENCE_MATRIX.md"}

    #: The release runbook is the one place an install command legitimately appears, because it
    #: describes the step performed immediately AFTER publishing and exists to make sure that
    #: step is verified. It is exempt only for `assay-bench`, never for the unrelated `assay`,
    #: and only while it also carries the rule that the claim must not be made until the install
    #: works -- which the next test checks.
    RUNBOOK = "RELEASING.md"

    #: `pip install assay` -- the unrelated project. The negative lookahead keeps `assay-bench`
    #: out of this pattern; it has its own test.
    WRONG_PACKAGE = re.compile(r"\b(pip|pipx|uv)\s+(install|run)\s+(-\S+\s+)*assay\b(?!-)")
    #: `pip install assay-bench` -- this project, from an index it is not published to.
    UNPUBLISHED = re.compile(r"\b(pip|pipx|uv)\s+(install|run)\s+(-\S+\s+)*assay-bench\b")

    def _docs(self):
        require_source_checkout(self)
        listed = subprocess.run(["git", "ls-files", "*.md"], cwd=ROOT, capture_output=True,
                                text=True).stdout.split()
        return [ROOT / name for name in listed]

    @staticmethod
    def _code_block_lines(text: str):
        """Yield only the lines inside fenced code blocks: what a reader copies and runs."""
        inside = False
        for line in text.splitlines():
            if line.lstrip().startswith("```"):
                inside = not inside
                continue
            if inside:
                yield line

    def test_no_runnable_block_anywhere_installs_the_wrong_or_unpublished_package(self):
        for path in self._docs():
            text = path.read_text(encoding="utf-8", errors="ignore")
            for line in self._code_block_lines(text):
                with self.subTest(doc=path.name, line=line.strip()[:70]):
                    self.assertIsNone(self.WRONG_PACKAGE.search(line),
                                      f"{path.name} has a runnable line installing PyPI's "
                                      f"`assay`, an unrelated project by another author")
                    if path.name == self.RUNBOOK:
                        continue
                    self.assertIsNone(self.UNPUBLISHED.search(line),
                                      f"{path.name} has a runnable line installing "
                                      f"assay-bench from an index it is not published to")

    def test_no_user_facing_document_even_mentions_installing_it_that_way(self):
        for path in self._docs():
            if path.name in self.RECORDS:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for line in text.splitlines():
                with self.subTest(doc=path.name, line=line.strip()[:70]):
                    self.assertIsNone(self.WRONG_PACKAGE.search(line),
                                      f"{path.name} points a reader at PyPI's `assay`")
                    if path.name == self.RUNBOOK:
                        continue
                    self.assertIsNone(self.UNPUBLISHED.search(line),
                                      f"{path.name} presents assay-bench as installable from "
                                      f"an index it is not published to")

    def test_the_runbooks_exemption_is_earned(self):
        """The runbook may show the install only because it exists to verify it.

        An exemption granted on a filename alone would let the runbook quietly become a place
        that tells people the package is available. It has to keep saying the opposite.
        """
        path = ROOT / self.RUNBOOK
        if not path.is_file():
            self.skipTest(f"{self.RUNBOOK} is not present")
        text = path.read_text(encoding="utf-8")
        self.assertIn("NEEDS CREDENTIALS", text,
                      "the runbook must mark the publish step as not-yet-performed")
        self.assertIn("Do not update any document to say the package is installable from PyPI",
                      text)
        self.assertIn("404", text, "the runbook must record the checked index status")

    def test_the_record_documents_state_why_they_are_allowed_to_mention_it(self):
        """An exemption nobody can see is indistinguishable from an oversight."""
        for name in self.RECORDS:
            matches = [p for p in self._docs() if p.name == name]
            if not matches:
                continue
            text = matches[0].read_text(encoding="utf-8", errors="ignore")
            if not (self.WRONG_PACKAGE.search(text) or self.UNPUBLISHED.search(text)):
                continue
            with self.subTest(doc=name):
                self.assertTrue(
                    any(word in text.lower() for word in ("withdraw", "removed", "unrelated",
                                                          "not published", "does not exist")),
                    f"{name} mentions the install line without saying it was withdrawn")


class ExecutableDocumentation(unittest.TestCase):
    """Every fenced bash command in the docs is extracted and run. A documented command
    that does not exist is the defect that started this audit."""

    DOCS = ("README.md", "SPEC.md", "CONTRIBUTING.md", "corpus/README.md",
            "leaderboard/SUBMIT.md", "demo/DEMO_RUNBOOK.md")

    #: Commands we run verbatim. Anything else found in the docs must be listed in
    #: ALLOWED_UNRUN with a reason, so a new undocumented command cannot slip in.
    ALLOWED_UNRUN = {
        "pip install -e .": "mutates the environment; covered by tests/test_packaging.py",
        "assay run --target vulnerable --trials 25 --out /tmp/scorecard.json": (
            "the INSTALLED console script; tests/test_packaging.py runs exactly this from a "
            "clean venv outside the checkout"),
        "assay verify /tmp/scorecard.json --require run_complete": (
            "the INSTALLED console script; covered by tests/test_packaging.py"),
        "python audit/collect_evidence.py --sync-docs": (
            "runs the whole suite to measure it, so running it here would recurse; "
            "DocumentedNumbersMatchReality already asserts the numbers it writes"),
        "python audit/collect_evidence.py": (
            "runs the whole suite to measure it; same recursion, and CI runs it in its own step"),
        "python -m unittest discover -s tests -t .": (
            "running the suite inside the suite would recurse forever; this IS the suite"),
        "python -m pytest tests/ -q": (
            "optional third-party runner, deliberately not a dependency; the same tests run "
            "under unittest, which is what CI's core job uses"),
        "python -m build": "requires the 'build' package; covered by test_packaging",
        "git add precommit/registry/<run-id>.json": "illustrative git usage",
        "git commit -m 'precommit: <target>'": "illustrative git usage",
        "git push": "illustrative git usage",
        "PYTHONPATH=src python -m assay_bench precommit --target vulnerable --trials 25 --secret-out /tmp/run.secret": (
            "writes a registry record into the repository, so running it here would dirty the "
            "tree; tests/test_precommit.py drives the same CLI against a temporary registry"),
        "PYTHONPATH=src python -m assay_bench run --target-url https://your-server.example/mcp --track server --out /tmp/yours.json": (
            "needs a third-party MCP server, which by definition this repository does not "
            "ship; tests/test_mcp_probe.py drives the same code path against a real server on "
            "loopback, and tests/test_mcp_interop.py against a server built with the official "
            "MCP SDK"),
        "python src/assay_verifier.py verify /tmp/yours.json": (
            "verifies the manifest the command above would produce, so it cannot run without a "
            "third-party server either; the same verification runs on every shipped manifest"),
        'PYTHONPATH=src python -m assay_bench witness-sign --manifest /tmp/scorecard.json --witness "your-name" --independent --out /tmp/statement.json': (
            "needs $ASSAY_WITNESS_KEY, which is deliberately not a command-line argument and "
            "must never be committed; tests/test_witness.py drives the same signing path with "
            "a generated key, and the CLI's own no-key error is asserted there"),
        "PYTHONPATH=src python -m assay_bench witness-verify --statement /tmp/statement.json --manifest /tmp/scorecard.json": (
            "verifies the statement the command above would produce, so it cannot run without "
            "a signing key either; the same verification runs over generated statements in "
            "tests/test_witness.py"),
        "bash demo/reset.sh": "covered by tests/test_demo.py",
        "bash demo/run_demo.sh": "covered by tests/test_demo.py",
        "ASSAY_DEMO_PAUSE=1.1 bash demo/run_demo.sh": (
            "the same script with pacing; tests/test_demo.py runs it paced and asserts the "
            "outcome is identical"),
        "bash demo/record_video.sh": "needs a browser and encoder; covered by test_demo",
    }

    def test_no_excuse_outlives_the_command_it_excuses(self):
        """A stale entry in ALLOWED_UNRUN silently pre-authorises a line that was removed.

        `pip install assay-bench` sat here after the line was withdrawn from every document, so
        reintroducing an install instruction for an unpublished package would have passed the
        build unremarked. An excuse must name a command the documentation actually contains.
        """
        documented = set()
        for name in self.DOCS:
            doc = ROOT / name
            if doc.is_file():
                documented.update(self._commands(doc))
        # Some excused commands live outside DOCS: in other markdown (the runbook, the
        # precommit README), or in CI and the PR template, which are instructions to a
        # contributor just as much as a README is. All of them count as "still documented";
        # anything in none of them is dead.
        for name in ("demo/DEMO_RUNBOOK.md", "precommit/README.md", "README.md"):
            doc = ROOT / name
            if doc.is_file():
                documented.update(self._commands(doc))
        # The workflow and the PR template are repository files an sdist does not ship, so
        # without them an excuse would look dead when it is merely out of view.
        require_source_checkout(self)
        elsewhere = ""
        for name in (".github/workflows/ci.yml", ".github/PULL_REQUEST_TEMPLATE.md"):
            path = ROOT / name
            if path.is_file():
                elsewhere += path.read_text(encoding="utf-8")
        for excused in sorted(self.ALLOWED_UNRUN):
            with self.subTest(command=excused):
                self.assertTrue(excused in documented or excused in elsewhere,
                                f"ALLOWED_UNRUN excuses {excused!r}, which no document, "
                                f"workflow or template contains any more; remove the excuse "
                                f"rather than leaving it to pre-authorise the line coming back")

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
                    r, parts = run_documented(command)
                    self.assertIsNotNone(
                        r, f"{name}: undocumented tool {parts[0] if parts else '?'!r}")
                    self.assertEqual(r.returncode, 0,
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
                    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
                    r = sh("-c", f"import importlib; importlib.import_module({match!r})", env=env)
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
            if not (ROOT / name).is_file():
                continue
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


class CommandLineRobustness(unittest.TestCase):
    """A CLI that tracebacks on a typo is one people stop trusting to tell them anything.

    Every invocation below must exit with a documented code and a one-line message, never a
    Python traceback.
    """

    EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_MALFORMED = 0, 1, 2, 3

    def _assay(self, *args):
        import os
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
        return subprocess.run([sys.executable, "-m", "assay_bench", *args], cwd=ROOT,
                              capture_output=True, text=True, env=env, timeout=120)

    def _assert_clean(self, result, expected_code, context):
        self.assertEqual(result.returncode, expected_code,
                         f"{context}: expected exit {expected_code}, got {result.returncode}\n"
                         f"{result.stdout[-400:]}{result.stderr[-400:]}")
        self.assertNotIn("Traceback", result.stderr, f"{context}: leaked a traceback")
        self.assertNotIn("Traceback", result.stdout, f"{context}: leaked a traceback")

    def test_no_arguments_prints_help_and_exits_two(self):
        self._assert_clean(self._assay(), self.EXIT_USAGE, "no arguments")

    def test_an_unknown_subcommand_exits_two(self):
        self._assert_clean(self._assay("bogus"), self.EXIT_USAGE, "unknown subcommand")

    def test_help_and_version_work(self):
        for flag in ("--help", "--version"):
            with self.subTest(flag=flag):
                self._assert_clean(self._assay(flag), self.EXIT_OK, flag)

    def test_a_missing_input_file_exits_three_with_a_message(self):
        for args in (("verify", "/nonexistent.json"),
                     ("precommit-verify", "--manifest", "/nonexistent.json"),
                     ("attest", "--submitted", "/nonexistent.json", "--maintainer", "m")):
            with self.subTest(command=args[0]):
                r = self._assay(*args)
                self._assert_clean(r, self.EXIT_MALFORMED, args[0])
                self.assertIn("assay:", r.stderr)

    def test_malformed_json_exits_three_with_a_message(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{not json")
            path = fh.name
        try:
            for args in (("verify", path),
                         ("precommit-verify", "--manifest", path),
                         ("attest", "--submitted", path, "--maintainer", "m")):
                with self.subTest(command=args[0]):
                    r = self._assay(*args)
                    self._assert_clean(r, self.EXIT_MALFORMED, args[0])
                    self.assertIn("JSON", r.stderr)
        finally:
            Path(path).unlink()

    def test_invalid_option_values_exit_cleanly(self):
        for args, code in ((("run", "--target", "nope"), self.EXIT_FAILED),
                           (("run", "--trials", "-1"), self.EXIT_FAILED),
                           (("run", "--trials", "abc"), self.EXIT_USAGE),
                           (("run", "--task", "NOT-A-TASK"), self.EXIT_FAILED),
                           (("reference", "--trials", "0"), self.EXIT_FAILED)):
            with self.subTest(args=args):
                self._assert_clean(self._assay(*args), code, " ".join(args))

    def test_an_empty_registry_directory_is_not_an_error(self):
        import tempfile
        self._assert_clean(self._assay("precommit-list", "--registry",
                                       tempfile.mkdtemp()), self.EXIT_OK, "empty registry")


class DocumentedNumbersMatchReality(unittest.TestCase):
    """Stale numbers in prose are exactly the failure this project exists to prevent.

    Every count the documentation states about this repository is recomputed here. When the
    suite grows, these fail and the docs get updated in the same change -- which is the point.
    """

    PROSE = ("README.md", "SPEC.md", "CONTRIBUTING.md", "CHANGELOG.md",
             "IMPLEMENTATION_SUMMARY.md", "REMAINING_GAPS.md", "COVERAGE.md",
             "audit/CLEAN_CLONE_ACCEPTANCE.md", "audit/ISSUE_1_TRIAGE.md",
             "audit/ISSUE_1_RESPONSE.md", "audit/CLAIM_EVIDENCE_MATRIX.md",
             "demo/PRESENTATION_REVISION_BRIEF.md", "corpus/README.md")

    @classmethod
    def setUpClass(cls):
        import unittest as _u
        loader = _u.TestLoader()
        suite = loader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT))

        def count(s):
            n = 0
            for item in s:
                n += count(item) if isinstance(item, _u.TestSuite) else 1
            return n

        cls.total = count(suite)

    def test_the_stated_test_count_is_the_real_one(self):
        """Any three-digit number described as a test count must be the actual total.

        Checkout-only. The documented number describes the repository's suite; a tree unpacked
        from an sdist runs a subset, because the tests needing git history or CI configuration
        skip there. The previous version allowed a second hardcoded number for that subset,
        which went stale the moment the suite grew -- a hand-kept count inside the test whose
        entire job is to catch hand-kept counts.
        """
        require_source_checkout(self)
        allowed = {str(self.total)}
        pattern = re.compile(r"(\d{3})\s*(?:tests|run)\b|(?:tests|suite)[^.\n]{0,24}?\b(\d{3})\b")
        for name in self.PROSE:
            path = ROOT / name
            if not path.is_file():
                continue
            for match in pattern.finditer(path.read_text(encoding="utf-8")):
                number = match.group(1) or match.group(2)
                with self.subTest(doc=name, number=number):
                    self.assertIn(number, allowed,
                                  f"{name} states {number} where the suite has {self.total}")

    def test_the_stated_task_count_is_the_real_one(self):
        catalog = json.loads((ROOT / "tasks.json").read_text())
        counts = {
            "tasks": len(catalog["tasks"]),
            "mode_b": sum(1 for t in catalog["tasks"] if t["mode"] == "B"),
            "mode_a": sum(1 for t in catalog["tasks"] if t["mode"] == "A"),
            "canary": sum(1 for t in catalog["tasks"] if t["oracle"] == "canary"),
            "behavioral": sum(1 for t in catalog["tasks"] if t["oracle"] == "behavioral"),
            "protocol": sum(1 for t in catalog["tasks"] if t["oracle"] == "protocol"),
        }
        self.assertEqual(counts, {"tasks": 31, "mode_b": 28, "mode_a": 3,
                                  "canary": 25, "behavioral": 4, "protocol": 2},
                         "the frozen shape changed; every document stating it must be updated")
        for name in ("README.md", "SPEC.md", "CHANGELOG.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            with self.subTest(doc=name):
                self.assertIn("31", text)

    def test_the_stated_blind_spot_count_is_the_real_one(self):
        from .test_oracle_blind_spots import CASES

        detected = sum(1 for _, observed, expected, _ in CASES if expected)
        missed = len(CASES) - detected
        for name in ("README.md", "SPEC.md", "CHANGELOG.md", "IMPLEMENTATION_SUMMARY.md",
                     "demo/PRESENTATION_REVISION_BRIEF.md", "audit/ISSUE_1_TRIAGE.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            if "blind spot" not in text.lower() and "transformation" not in text.lower():
                continue
            with self.subTest(doc=name):
                self.assertIn(str(missed), text,
                              f"{name} discusses the blind spots but not the real count ({missed})")

    def test_the_stated_multimodal_count_is_the_real_one(self):
        catalog = json.loads((ROOT / "tasks.json").read_text())
        image = [t["id"] for t in catalog["tasks"]
                 if (t.get("execution") or {}).get("implemented_modality") == "image"]
        simulated = [t["id"] for t in catalog["tasks"]
                     if (t.get("execution") or {}).get("implemented_modality") == "text_simulation"]
        self.assertEqual(len(image), 6)
        self.assertEqual(simulated, [], "a text simulation is still labelled as one somewhere")
        for name in ("README.md", "SPEC.md", "COVERAGE.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            with self.subTest(doc=name):
                self.assertIn("Six", text)
                for tid in image:
                    self.assertIn(tid, text, f"{name} omits image task {tid}")
