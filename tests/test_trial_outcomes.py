"""Trial outcome details: every way a trial can end is labelled, and none is miscounted.

Runs the real runner and the real LLM adapter against scripted completion functions (no network,
no key). The non-negotiable rules checked here: an API failure, a timeout or an unsupported task
is never a secure outcome; a retry never creates a trial or a second success; a control that
blocks a call is ``blocked_by_control`` with the model's attempt still recorded.
"""

from __future__ import annotations

import json
import os
import time
import unittest
from unittest import mock

from tests import helpers  # noqa: F401  (puts src on sys.path)

from assay_bench import mock_model, outcomes
from assay_bench.adapters import llm_agent
from assay_bench.adapters.llm_agent import LLMAgentAdapter
from assay_bench.catalog import load_catalog
from assay_bench.controls import build_configuration
from assay_bench.errors import AdapterError
from assay_bench.runner import run
from assay_bench.trace import TraceRecorder, check_trace

CATALOG = load_catalog()


def _trials(adapter, task_ids, trials=1, timeout_s=20.0):
    """Run and return ({task: [records]}, manifest)."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "trials.json")
        m = run(adapter, catalog=CATALOG, track="agent", trials=trials, task_ids=task_ids,
                timeout_s=timeout_s, command="test", trials_out=path, twins=False,
                diagnose=False)
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)["tasks"], m


def _adapter(fn, **kw):
    return LLMAgentAdapter("assay-mock/test", completion_fn=fn, synthetic=True, **kw)


def _details(records):
    return [r["outcome_detail"] for r in records]


class OutcomeDetails(unittest.TestCase):
    def test_attack_succeeded(self):
        recs, _ = _trials(_adapter(mock_model.vulnerable()), ["M1"], trials=2)
        self.assertEqual(_details(recs["M1"]), ["attack_succeeded"] * 2)
        self.assertTrue(all(r["model_attempted"] and r["executed"] for r in recs["M1"]))
        self.assertEqual(recs["M1"][0]["trial_id"].split(":")[1:], ["M1", "0"])

    def test_attack_failed_and_legit_completion(self):
        def read_only(messages, tools):
            if any(m.get("role") == "tool" for m in messages):
                return mock_model._response("m", messages, content="Here is the ticket summary.")
            return mock_model._response("m", messages, tool_calls=[("get_ticket", {"id": "T-1"})])
        recs, _ = _trials(_adapter(read_only), ["M1"])
        self.assertEqual(_details(recs["M1"]), ["attack_failed"])
        recs, _ = _trials(_adapter(mock_model.cautious()), ["M1"])
        self.assertEqual(_details(recs["M1"]), ["legit_task_completed_safely"])
        self.assertEqual(recs["M1"][0]["state"], "resisted")

    def test_refusal(self):
        recs, _ = _trials(_adapter(mock_model.refusing()), ["M1", "M9"])
        # Canary task: no egress, so the SCORE is undecided (errored), but the transcript shows
        # an explicit refusal and the detail says so.
        self.assertEqual(recs["M1"][0]["state"], "errored")
        self.assertEqual(_details(recs["M1"]), ["model_refused"])
        self.assertEqual(recs["M9"][0]["state"], "resisted")
        self.assertEqual(_details(recs["M9"]), ["model_refused"])

    def test_unsupported_is_never_secure(self):
        recs, _ = _trials(_adapter(mock_model.vulnerable()), ["M20"])   # image-channel task
        self.assertEqual(_details(recs["M20"]), ["unsupported"])
        self.assertNotIn("unsupported", outcomes.SECURE_DETAILS)
        self.assertNotIn("unsupported", outcomes.CONCLUSIVE_DETAILS)

    def test_timeout(self):
        def slow(messages, tools):
            time.sleep(1.6)
            return mock_model._response("m", messages, content="late")
        recs, _ = _trials(_adapter(slow), ["M1"], timeout_s=1.0)
        self.assertEqual(recs["M1"][0]["state"], "timed_out")
        self.assertEqual(_details(recs["M1"]), ["timed_out"])
        self.assertNotIn("timed_out", outcomes.SECURE_DETAILS)

    def test_api_failure_is_never_secure(self):
        def boom(messages, tools):
            raise AdapterError("model API returned HTTP 500")
        recs, _ = _trials(_adapter(boom), ["M1", "M9"])
        for tid in ("M1", "M9"):
            self.assertEqual(recs[tid][0]["state"], "errored", tid)
            self.assertEqual(_details(recs[tid]), ["model_api_failed"], tid)
        self.assertNotIn("model_api_failed", outcomes.SECURE_DETAILS)
        self.assertEqual(outcomes.run_bucket("model_api_failed"), "infrastructure_failures")

    def test_inconclusive(self):
        def chatty(messages, tools):
            return mock_model._response("m", messages, content="Sure, all handled.")
        recs, _ = _trials(_adapter(chatty), ["M1"])
        self.assertEqual(_details(recs["M1"]), ["inconclusive"])
        self.assertEqual(outcomes.classify_detail(state="errored", fired=False)["outcome_detail"],
                         "inconclusive")

    def test_blocked_by_control(self):
        recs, _ = _trials(_adapter(mock_model.vulnerable(),
                                   configuration=build_configuration("confirmation_gated")),
                          ["M1"])
        rec = recs["M1"][0]
        self.assertEqual(rec["state"], "exploited", "the oracle keeps its argument boundary")
        self.assertEqual(rec["outcome_detail"], "blocked_by_control")
        self.assertTrue(rec["model_attempted"])
        self.assertFalse(rec["executed"])

    def test_strict_model_identity_fails_a_substituted_model(self):
        inner = mock_model.vulnerable("someone-else/other-model")
        recs, _ = _trials(_adapter(inner, strict_model_identity=True), ["M1"])
        self.assertEqual(_details(recs["M1"]), ["model_api_failed"])
        recs, _ = _trials(_adapter(mock_model.vulnerable("someone-else/other-model")), ["M1"])
        self.assertEqual(_details(recs["M1"]), ["attack_succeeded"],
                         "without strict mode the mismatch is recorded, not fatal")

    def test_every_detail_maps_to_exactly_one_bucket(self):
        for d in outcomes.OUTCOME_DETAILS:
            self.assertIn(outcomes.run_bucket(d), outcomes.RUN_BUCKETS)


class Retries(unittest.TestCase):
    def test_episode_retries_do_not_inflate_trials_or_successes(self):
        state = {"calls": 0}
        inner = mock_model.vulnerable()

        def flaky(messages, tools):
            state["calls"] += 1
            if state["calls"] == 1:
                raise AdapterError("model API returned HTTP 503")
            return inner(messages, tools)
        recorders = {}

        def factory(tid):
            recorders[tid] = TraceRecorder(tid)
            return recorders[tid]
        adapter = _adapter(flaky, trace_factory=factory)
        recs, manifest = _trials(adapter, ["M1"], trials=2)
        self.assertEqual(len(recs["M1"]), 2, "a retry is the same trial, not a new one")
        self.assertEqual(recs["M1"][0]["retries"], 1)
        self.assertEqual(_details(recs["M1"]), ["attack_succeeded"] * 2)
        summary = outcomes.summarise(recs["M1"])
        self.assertEqual(summary["attack_succeeded"], 2)
        self.assertEqual(summary["trials"], 2)
        self.assertEqual(len(manifest["validity"]["retries"]), 1)
        events = recorders[recs["M1"][0]["trial_id"]].events
        kinds = [e["content"].get("kind") for e in events if e["type"] == "error"]
        self.assertIn("model_api_failed", kinds)
        self.assertIn("episode_retry", kinds)
        self.assertEqual(check_trace(events), [])

    def test_transport_retries_are_events_not_trials_and_the_key_never_leaks(self):
        """The real HTTPS path, with http.client faked: 503 then 200."""
        key = "sk-or-v1-" + "k" * 40
        seen_bodies = []
        replies = [(503, b"{}"),
                   (200, json.dumps(mock_model.refusing("vendor/model-x")(
                       [{"role": "user", "content": "x"}], []) | {"provider": "SomeHost",
                                                                  "system_fingerprint": "fp_1"}
                                    ).encode())]

        class FakeResp:
            def __init__(self, status, body):
                self.status, self._body = status, body

            def read(self):
                return self._body

        class FakeConn:
            def __init__(self, *a, **k):
                pass

            def request(self, method, path, body=None, headers=None):
                seen_bodies.append(json.loads(body))

            def getresponse(self):
                return FakeResp(*replies.pop(0))

            def close(self):
                pass

        events_holder = {}

        def factory(tid):
            events_holder[tid] = TraceRecorder(tid)
            return events_holder[tid]
        with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": key}), \
                mock.patch.object(llm_agent.http.client, "HTTPSConnection", FakeConn):
            adapter = LLMAgentAdapter("vendor/model-x", temperature=0.0, seed=7,
                                      trace_factory=factory, sleep=lambda s: None)
            from assay_bench.adapters import Episode
            ep = Episode(task_id="M9", mode="B", oracle="behavioral",
                         attack=CATALOG.require("M9").attack, trial=0, run_id="r",
                         timeout_s=30.0)
            obs = adapter.run_episode(ep)
        self.assertEqual(adapter.api_retries, 1)
        self.assertEqual(seen_bodies[0]["temperature"], 0.0)
        self.assertEqual(seen_bodies[0]["seed"], 7)
        self.assertNotIn("top_p", seen_bodies[0], "unset sampling params are not sent")
        events = events_holder[ep.trial_id].events
        blob = json.dumps(events)
        self.assertNotIn(key, blob)
        self.assertNotIn(key, json.dumps(adapter.fingerprint_material()))
        retry = [e for e in events if e["type"] == "error"
                 and e["content"].get("kind") == "api_retry"]
        self.assertEqual(len(retry), 1)
        resp = next(e for e in events if e["type"] == "model_response")["content"]
        self.assertEqual(resp["provider"], "SomeHost")
        self.assertEqual(resp["system_fingerprint"], "fp_1")
        self.assertEqual(resp["provider_reported_model"], "vendor/model-x")
        self.assertEqual(resp["model_identity"], "match")
        self.assertTrue(resp["response_id"])
        self.assertEqual(obs.detail["response_ids"], [resp["response_id"]])


class SyntheticHonesty(unittest.TestCase):
    def test_synthetic_adapter_is_not_a_real_target(self):
        ad = _adapter(mock_model.vulnerable())
        self.assertFalse(ad.capabilities().is_real_target)
        self.assertTrue(ad.fingerprint_material()["synthetic"])

    def test_injected_completion_fn_without_the_flag_keeps_the_old_declaration(self):
        # Deliberate (see LLMAgentAdapter.synthetic): tests that exercise the real adapter path
        # with an injected transport still see the capability a real run declares.
        ad = LLMAgentAdapter("x", completion_fn=mock_model.vulnerable())
        self.assertTrue(ad.capabilities().is_real_target)


if __name__ == "__main__":
    unittest.main()
