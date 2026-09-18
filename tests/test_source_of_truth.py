"""One source of truth: tasks.json, and drift checks against everything derived from it.

The failure this guards against is the ordinary one: TASKS.md describes a mechanism, tasks.json
encodes different metadata, COVERAGE.md is regenerated from a third thing, and the runner
registers a fourth. Nobody notices until a number is wrong.

`tasks.json` is canonical. TASKS.md's summary table, COVERAGE.md, and what the runner actually
registers at run time are all checked against it here.
"""

from __future__ import annotations

import json
import re
import unittest

from .helpers import ROOT, require_source_checkout
from assay_bench.adapters import MODALITY_CAPABILITY, REQUIRED_CAPABILITY
from assay_bench.catalog import load_catalog
from assay_bench.errors import MalformedInput, ValidationError
from assay_bench.catalog import validate_catalog_document

CATALOG = load_catalog()
DOC = json.loads((ROOT / "tasks.json").read_text())
TASKS_MD = (ROOT / "TASKS.md").read_text()
COVERAGE_MD = (ROOT / "COVERAGE.md").read_text()

#: The multimodal marker in TASKS.md is U+1F5BC followed by U+FE0F, so match both codepoints.
_MULTIMODAL_MARKER = "\U0001F5BC\uFE0F"
_ROW = re.compile(r"^\|\s*(M\d+|OBF)\s*(" + _MULTIMODAL_MARKER + r")?\s*\|\s*([^|]+?)\s*"
                  r"\|\s*([AB])\s*\|\s*(\w+)\s*\|\s*([^|]+?)\s*\|")


def _tasks_md_rows() -> dict[str, dict]:
    rows = {}
    for line in TASKS_MD.splitlines():
        m = _ROW.match(line)
        if m:
            rows[m.group(1)] = {"multimodal": bool(m.group(2)), "title": m.group(3).strip(),
                                "mode": m.group(4), "oracle": m.group(5),
                                "channel": m.group(6).strip()}
    return rows


class ExecutionContracts(unittest.TestCase):
    def test_every_task_carries_an_execution_contract(self):
        for task in CATALOG:
            with self.subTest(task=task.id):
                self.assertTrue(task.execution, f"{task.id} has no execution contract")
                for key in ("channel", "declared_modality", "implemented_modality",
                            "requires_capabilities"):
                    self.assertIn(key, task.execution)

    def test_required_capabilities_match_the_oracle_registry(self):
        """The contract in the data must agree with what the code demands at run time.

        A task needs its oracle's channels plus, for a non-text channel, the capability that
        decodes it. Both halves are listed in the data so a reader can see why an adapter that
        cannot read pixels is reported `unsupported` on M20 rather than credited with resisting.
        """
        for task in CATALOG:
            expected = set(REQUIRED_CAPABILITY[task.oracle])
            modality_capability = MODALITY_CAPABILITY.get(task.declared_modality)
            if modality_capability:
                expected.add(modality_capability)
            with self.subTest(task=task.id, oracle=task.oracle):
                self.assertEqual(set(task.execution["requires_capabilities"]), expected)

    def test_a_task_that_needs_a_decoder_says_so_and_the_runtime_agrees(self):
        """The declared requirement and `supports()` must not drift apart."""
        from assay_bench.adapters import Capabilities, supports

        oracle_only = Capabilities(emits_network_egress=True, emits_tool_calls=True,
                                   exposes_protocol_facts=True)
        with_decoder = Capabilities(emits_network_egress=True, emits_tool_calls=True,
                                    exposes_protocol_facts=True, decodes_images=True)
        for task in CATALOG:
            needs_decoder = "decodes_images" in task.execution["requires_capabilities"]
            with self.subTest(task=task.id):
                self.assertEqual(supports(oracle_only, task.oracle, task.declared_modality),
                                 not needs_decoder)
                self.assertTrue(supports(with_decoder, task.oracle, task.declared_modality))

    def test_a_contract_claiming_an_unimplemented_modality_is_rejected(self):
        import copy
        doc = copy.deepcopy(DOC)
        doc["tasks"][0]["execution"]["declared_modality"] = "image"
        doc["tasks"][0]["execution"]["implemented_modality"] = "text"
        with self.assertRaisesRegex(ValidationError, "use 'text_simulation'"):
            validate_catalog_document(doc)

    def test_an_unknown_modality_is_rejected(self):
        import copy
        doc = copy.deepcopy(DOC)
        doc["tasks"][0]["execution"]["declared_modality"] = "holographic"
        with self.assertRaises(ValidationError):
            validate_catalog_document(doc)

    def test_a_malformed_contract_is_rejected(self):
        import copy
        doc = copy.deepcopy(DOC)
        del doc["tasks"][0]["execution"]["channel"]
        with self.assertRaises(MalformedInput):
            validate_catalog_document(doc)


class DriftAgainstTasksMd(unittest.TestCase):
    def setUp(self):
        self.rows = _tasks_md_rows()

    def test_tasks_md_lists_exactly_the_catalog(self):
        self.assertEqual(sorted(self.rows), sorted(t.id for t in CATALOG))

    def test_mode_oracle_and_title_agree(self):
        for task in CATALOG:
            with self.subTest(task=task.id):
                row = self.rows[task.id]
                self.assertEqual(row["mode"], task.mode)
                self.assertEqual(row["oracle"], task.oracle)
                self.assertEqual(row["title"], task.title)

    def test_channel_agrees(self):
        for task in CATALOG:
            with self.subTest(task=task.id):
                self.assertEqual(self.rows[task.id]["channel"], task.channel)

    def test_the_multimodal_marker_agrees_with_the_declared_modality(self):
        for task in CATALOG:
            with self.subTest(task=task.id):
                self.assertEqual(self.rows[task.id]["multimodal"],
                                 task.declared_modality != "text",
                                 f"{task.id}: the marker in TASKS.md and the declared modality "
                                 f"in tasks.json disagree")

    def test_every_task_has_a_detail_section(self):
        for task in CATALOG:
            with self.subTest(task=task.id):
                self.assertIn(f"### {task.id},", TASKS_MD)

    def test_the_weight_in_each_detail_section_matches_the_catalog(self):
        for task in CATALOG:
            with self.subTest(task=task.id):
                section = TASKS_MD.split(f"### {task.id},", 1)[1].split("\n### ")[0]
                self.assertIn(f"severity weight {task.weight}", section,
                              f"{task.id}: TASKS.md states a different severity weight")


class DriftAgainstCoverage(unittest.TestCase):
    def test_coverage_lists_every_task_once(self):
        for task in CATALOG:
            with self.subTest(task=task.id):
                self.assertEqual(COVERAGE_MD.count(f"| {task.id} |"), 1)

    def test_coverage_states_the_same_mode_oracle_and_channel(self):
        for task in CATALOG:
            with self.subTest(task=task.id):
                row = next(line for line in COVERAGE_MD.splitlines()
                           if line.startswith(f"| {task.id} |"))
                cells = [c.strip() for c in row.split("|")]
                self.assertEqual(cells[3], task.mode)
                self.assertEqual(cells[4], task.oracle)
                self.assertEqual(cells[5], f"`{task.channel}`")

    def test_coverage_flags_every_text_simulation(self):
        for task in CATALOG:
            row = next(line for line in COVERAGE_MD.splitlines()
                       if line.startswith(f"| {task.id} |"))
            with self.subTest(task=task.id):
                self.assertEqual("text sim" in row, task.is_text_simulation)


class DriftAgainstRuntime(unittest.TestCase):
    """What the runner registers at run time must be the catalog, not a copy of it."""

    def test_the_runner_reports_exactly_the_catalog_tasks(self):
        from assay_bench.adapters.conformance import build
        from assay_bench.runner import run

        manifest = run(build("vulnerable"), catalog=CATALOG, trials=2, command="test")
        self.assertEqual(sorted(f["id"] for f in manifest["findings"]),
                         sorted(t.id for t in CATALOG))

    def test_runtime_findings_restate_the_catalog_exactly(self):
        from assay_bench.adapters.conformance import build
        from assay_bench.runner import run

        manifest = run(build("mixed"), catalog=CATALOG, trials=2, command="test")
        for finding in manifest["findings"]:
            task = CATALOG.require(finding["id"])
            with self.subTest(task=task.id):
                self.assertEqual(finding["mode"], task.mode)
                self.assertEqual(finding["oracle"], task.oracle)
                self.assertEqual(finding["evidence_type"], task.evidence_type)
                self.assertEqual(finding["weight"], task.weight)
                self.assertEqual(finding["attack"], task.attack)

    def test_no_other_tracked_file_holds_a_second_copy_of_the_weights(self):
        """A grep-level guard: severity weights live in tasks.json and nowhere else."""
        import subprocess
        allowed = {"tasks.json", "src/assay_bench/data/tasks.json", "TASKS.md", "COVERAGE.md",
                   "SPEC.md", "audit/RUN_SUMMARY.json", "reference/conformance_matrix.json"}
        require_source_checkout(self)
        tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                                 text=True).stdout.split()
        offenders = []
        for path in tracked:
            # Tests legitimately build fixtures with weights; the rule is about production code.
            if path in allowed or not path.endswith(".py") or path.startswith("tests/"):
                continue
            text = (ROOT / path).read_text(encoding="utf-8", errors="ignore")
            if re.search(r'"weight"\s*:\s*0\.[247]', text) or re.search(r"weight\s*=\s*0\.[247]\b", text):
                offenders.append(path)
        self.assertEqual(offenders, [], f"severity weights hard-coded outside tasks.json: {offenders}")

    def test_the_packaged_catalog_is_the_canonical_one(self):
        packaged = (ROOT / "src" / "assay_bench" / "data" / "tasks.json").read_bytes()
        self.assertEqual(packaged, (ROOT / "tasks.json").read_bytes())


class ModalityTruth(unittest.TestCase):
    """No claim about a modality may outrun the executable path.

    Through v0.2 the six image tasks were text simulations: the "image" was described in prose
    and the canary was pasted into that prose, so nothing about an image was ever exercised.
    They now build real PNG bytes and the canary rides only in the image. These tests hold the
    new claim to the same standard the old one was held to: the label must match the code, in
    both directions, and no *other* modality may quietly acquire a label it has not earned.
    """

    #: Tasks whose channel is an image and which now really execute as images.
    IMAGE = {"M20", "M26", "M27", "M28", "M29", "M30"}

    #: Modalities with no executable path at all. A task may not claim these.
    UNIMPLEMENTED = ("audio", "video", "document")

    def test_no_task_is_still_a_text_simulation(self):
        self.assertEqual({t.id for t in CATALOG if t.is_text_simulation}, set())

    def test_the_image_tasks_declare_and_implement_the_image_channel(self):
        for task in CATALOG:
            with self.subTest(task=task.id):
                if task.id in self.IMAGE:
                    self.assertEqual(task.declared_modality, "image")
                    self.assertEqual(task.implemented_modality, "image")
                    self.assertIn(task.execution.get("image_plant"),
                                  ("pixels", "metadata", "qr", "rug_pull"))
                else:
                    self.assertEqual(task.declared_modality, "text")
                    self.assertEqual(task.implemented_modality, "text")

    def test_no_task_claims_a_modality_with_no_executable_path(self):
        for task in CATALOG:
            with self.subTest(task=task.id):
                self.assertNotIn(task.declared_modality, self.UNIMPLEMENTED)
                self.assertNotIn(task.implemented_modality, self.UNIMPLEMENTED)

    def test_the_image_label_is_backed_by_a_surface_that_really_attaches_an_image(self):
        """The label is only as good as what the surface builder emits."""
        from assay_bench.surface import build_surface

        for task in CATALOG:
            surface = build_surface(task, run_secret="00" * 32, trial=0)
            with self.subTest(task=task.id):
                if task.id in self.IMAGE:
                    self.assertTrue(surface["attachments"],
                                    f"{task.id} claims the image channel but attaches nothing")
                    for attachment in surface["attachments"]:
                        self.assertEqual(attachment["media_type"], "image/png")
                        self.assertTrue(attachment["data"].startswith(b"\x89PNG\r\n\x1a\n"),
                                        f"{task.id}: attachment is not a PNG")
                else:
                    self.assertFalse(surface["attachments"],
                                     f"{task.id} is a text task but attaches a file")

    def test_the_documentation_does_not_claim_a_modality_the_catalog_does_not_implement(self):
        implemented = {t.implemented_modality for t in CATALOG}
        for name in ("README.md", "SPEC.md", "COVERAGE.md", "corpus/README.md"):
            if not (ROOT / name).is_file():
                continue
            lowered = (ROOT / name).read_text().lower()
            for modality in self.UNIMPLEMENTED:
                with self.subTest(surface=name, modality=modality):
                    if modality in implemented:
                        continue
                    # Mentioning a modality is fine; claiming tasks run on it is not.
                    for phrase in (f"{modality} tasks", f"{modality} channel is implemented",
                                   f"scored on {modality}"):
                        self.assertNotIn(phrase, lowered,
                                         f"{name} claims a shipped {modality} path")

    def test_surfaces_that_mention_the_image_track_say_what_is_and_is_not_verified(self):
        """`image` now means real pixels. It still does not mean a third-party scanner read them."""
        for name in ("README.md", "SPEC.md"):
            text = (ROOT / name).read_text()
            if "multimodal" not in text.lower() and "image" not in text.lower():
                continue
            with self.subTest(surface=name):
                self.assertTrue("assay_bench.media" in text
                                or "assay_bench/media.py" in text,
                                f"{name} describes the image track without naming the module "
                                f"that builds and reads the images")


if __name__ == "__main__":
    unittest.main()


class CodeAndDocsAgree(unittest.TestCase):
    """Cross-checks that would otherwise only be caught by someone reading both carefully."""

    def test_every_verification_level_is_documented_in_the_readme(self):
        import assay_verifier as V

        readme = (ROOT / "README.md").read_text()
        for level in V.LEVELS + V.LEVELS_OUT_OF_SCOPE:
            with self.subTest(level=level):
                self.assertIn(level, readme)

    def test_the_validity_module_documents_all_eight_rules(self):
        from assay_bench import validity

        self.assertEqual(len(re.findall(r"^V(\d)\.", validity.__doc__, re.M)), 8)

    def test_the_minimum_trial_count_is_stated_where_it_is_enforced(self):
        from assay_bench import validity

        n = str(validity.MIN_TRIALS_COMPLETE)
        self.assertIn(n, (ROOT / "README.md").read_text())
        spec = (ROOT / "SPEC.md").read_text()
        self.assertTrue(f"N >= {n}" in spec or f"N ≥ {n}" in spec,
                        "SPEC must state the minimum trial count that validity enforces")

    def test_the_observed_length_bound_is_published_in_the_schema(self):
        import assay_verifier as V

        schema = json.loads((ROOT / "manifest_schema.json").read_text())
        self.assertIn(str(V.MAX_OBSERVED_CHARS), json.dumps(schema),
                      "the schema must publish the bound the verifier enforces")

    def test_every_oracle_class_in_the_catalog_has_an_evaluator(self):
        from assay_bench.adapters import Observation
        from assay_bench.errors import ValidationError
        from assay_bench.oracles import evaluate

        for oracle in {t.oracle for t in CATALOG}:
            with self.subTest(oracle=oracle):
                try:
                    evaluate(oracle, "x", Observation(task_id="T", trial=0), None)
                except ValidationError as exc:
                    self.assertNotIn("unknown oracle", str(exc))

    def test_every_cli_subcommand_is_documented_somewhere(self):
        from assay_bench.cli import build_parser

        parser = build_parser()
        subcommands = list(parser._subparsers._group_actions[0].choices)
        docs = "".join((ROOT / n).read_text() for n in
                       ("README.md", "CONTRIBUTING.md", "SPEC.md", "leaderboard/SUBMIT.md",
                        "precommit/README.md", "attest/README.md", "CHANGELOG.md"))
        for command in subcommands:
            with self.subTest(command=command):
                self.assertIn(command, docs, f"CLI subcommand {command!r} is undocumented")

    def test_the_schema_and_the_code_agree_on_the_manifest_shape(self):
        from assay_bench.manifest import OPTIONAL_TOP_LEVEL, REQUIRED_TOP_LEVEL

        schema = json.loads((ROOT / "manifest_schema.json").read_text())
        self.assertEqual(sorted(schema["required"]), sorted(REQUIRED_TOP_LEVEL))
        self.assertEqual(sorted(schema["properties"]),
                         sorted(set(REQUIRED_TOP_LEVEL) | set(OPTIONAL_TOP_LEVEL)))
