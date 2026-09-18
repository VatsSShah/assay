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
from assay_bench.adapters import REQUIRED_CAPABILITY
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
        """The contract in the data must agree with what the code demands at run time."""
        for task in CATALOG:
            with self.subTest(task=task.id, oracle=task.oracle):
                self.assertEqual(tuple(task.execution["requires_capabilities"]),
                                 REQUIRED_CAPABILITY[task.oracle])

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
    """No claim about a modality may outrun the executable path."""

    SIMULATED = {"M20", "M26", "M27", "M28", "M29", "M30"}

    def test_the_six_image_tasks_are_labelled_text_simulations(self):
        self.assertEqual({t.id for t in CATALOG if t.is_text_simulation}, self.SIMULATED)

    def test_no_task_claims_a_native_non_text_implementation(self):
        for task in CATALOG:
            with self.subTest(task=task.id):
                self.assertIn(task.implemented_modality, ("text", "text_simulation"))

    def test_the_documentation_does_not_claim_shipped_multimodal_execution(self):
        for name in ("README.md", "SPEC.md", "COVERAGE.md", "corpus/README.md"):
            if not (ROOT / name).is_file():
                continue
            text = (ROOT / name).read_text()
            with self.subTest(surface=name):
                for phrase in ("carry the canary through a non-text channel",
                               "scored by the same oracle (no per-modality judge"):
                    self.assertNotIn(phrase, text,
                                     f"{name} implies a shipped non-text execution path")

    def test_surfaces_that_mention_multimodal_also_say_it_is_simulated(self):
        for name in ("README.md", "SPEC.md"):
            text = (ROOT / name).read_text()
            if "multimodal" in text.lower():
                with self.subTest(surface=name):
                    self.assertTrue(
                        "text simulation" in text.lower() or "simulated" in text.lower(),
                        f"{name} mentions the multimodal track without saying it is simulated")


if __name__ == "__main__":
    unittest.main()
