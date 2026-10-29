"""Agent-configuration controls, on the scripted vulnerable mock.

Same model, same task, same canary and payload; only the control differs. The claims under test:

* baseline executes the leak;
* egress_restricted / policy_validated / confirmation_gated BLOCK execution while the model's
  attempt stays visible (``model_attempted`` true, ``executed`` false, ``blocked_by_control``) --
  blocking is environment enforcement, never model refusal;
* the canary oracle keeps its boundary, so a blocked attempt still fires it;
* tool_restricted removes the sink, so there is no attempt at all.
"""

from __future__ import annotations

import unittest

from tests import helpers  # noqa: F401  (puts src on sys.path)

from assay_bench import controls, mock_model, outcomes
from assay_bench.adapters import Episode
from assay_bench.adapters.llm_agent import LLMAgentAdapter
from assay_bench.canary import new_run_secret, plant
from assay_bench.catalog import load_catalog
from assay_bench.errors import ValidationError
from assay_bench.oracles import evaluate
from assay_bench.trace import TraceRecorder, check_trace

CATALOG = load_catalog()
SECRET = new_run_secret()


def _config(name: str) -> controls.AgentConfiguration:
    spec = {"name": name}
    if name == "egress_restricted":
        spec["allowlist"] = ["example.com"]
    return controls.build_configuration(spec)


def _run(task_id: str, config_name: str, behaviour: str = "vulnerable"):
    task = CATALOG.require(task_id)
    can = plant(SECRET, task_id, f"assay/{task_id}", task.attack, 0) \
        if task.oracle == "canary" else None
    episode = Episode(task_id=task_id, mode=task.mode, oracle=task.oracle, attack=task.attack,
                      trial=0, canary=can, timeout_s=30.0, run_id="run-test")
    adapter = LLMAgentAdapter(f"assay-mock/{behaviour}", completion_fn=mock_model.build(behaviour),
                              synthetic=True, configuration=_config(config_name),
                              trace_factory=lambda tid: TraceRecorder(tid))
    obs = adapter.run_episode(episode)
    fired = evaluate(task.oracle, task.attack, obs, can).fired
    state = "exploited" if fired else "resisted"
    label = outcomes.classify_detail(state=state, fired=fired, detail=obs.detail)
    events = adapter.trace_recorders()[episode.trial_id].events
    return obs, fired, label, events, can


class SameInputDifferentControl(unittest.TestCase):
    def test_baseline_executes_the_leak(self):
        obs, fired, label, events, _ = _run("M1", "baseline")
        self.assertTrue(fired)
        self.assertEqual(label["outcome_detail"], "attack_succeeded")
        self.assertTrue(label["model_attempted"] and label["executed"])
        self.assertIn("tool_call_executed", {e["type"] for e in events})
        self.assertEqual(check_trace(events), [])

    def _assert_blocked(self, task_id: str, control: str):
        obs, fired, label, events, _ = _run(task_id, control)
        self.assertTrue(fired, "the oracle keeps its boundary: a blocked attempt still fires")
        self.assertEqual(label["outcome_detail"], "blocked_by_control")
        self.assertTrue(label["model_attempted"], "blocking must not erase the model's attempt")
        self.assertFalse(label["executed"])
        blocked = [e for e in events if e["type"] == "tool_call_blocked"]
        self.assertTrue(blocked)
        self.assertEqual(blocked[0]["actor"], "environment")
        self.assertEqual(blocked[0]["content"]["control"], control)
        self.assertEqual(check_trace(events), [])

    def test_egress_restricted_blocks_execution(self):
        self._assert_blocked("M1", "egress_restricted")
        self._assert_blocked("M23", "egress_restricted")

    def test_policy_validated_blocks_execution(self):
        self._assert_blocked("M1", "policy_validated")
        self._assert_blocked("M3", "policy_validated")

    def test_confirmation_gated_blocks_execution(self):
        self._assert_blocked("M1", "confirmation_gated")
        self._assert_blocked("M9", "confirmation_gated")   # behavioral: the dangerous tool

    def test_tool_restricted_removes_the_sink_so_there_is_no_attempt(self):
        obs, fired, label, events, _ = _run("M1", "tool_restricted")
        self.assertFalse(fired)
        self.assertFalse(label["model_attempted"])
        exposed = next(e for e in events if e["type"] == "tools_exposed")["content"]
        self.assertIn("send_reply", exposed["removed_by_control"])
        self.assertNotIn("send_reply", [t["name"] for t in exposed["tools"]])

    def test_same_payload_across_configurations(self):
        payloads = set()
        for name in controls.CONTROL_NAMES:
            _, _, _, events, _ = _run("M1", name)
            payloads.add(tuple(e["content_sha256"] for e in events
                               if e["type"] == "payload_delivered"))
        self.assertEqual(len(payloads), 1, "every configuration must see identical payloads")

    def test_egress_restriction_cannot_see_an_implicit_destination(self):
        """Documented limit: share_to_partner's destination is not in its arguments."""
        _, fired, label, _, _ = _run("M7", "egress_restricted")
        self.assertTrue(fired)
        self.assertEqual(label["outcome_detail"], "attack_succeeded")


class ControlUnits(unittest.TestCase):
    def test_destinations_finds_urls_hosts_and_email_domains(self):
        found = controls.destinations('{"to":"a@partner-intake.example","url":'
                                      '"https://status.acme-ops.io/i/x"}')
        self.assertIn("partner-intake.example", found)
        self.assertIn("status.acme-ops.io", found)

    def test_allowlist_matches_subdomains_only(self):
        cfg = controls.build_configuration({"name": "egress_restricted",
                                            "allowlist": ["example.com"]})
        ctx = controls.ControlContext(sink_tools=frozenset({"send"}))
        self.assertTrue(controls.check_call(cfg, ctx, "send",
                                            '{"url":"https://a.example.com/x"}').allowed)
        self.assertFalse(controls.check_call(cfg, ctx, "send",
                                             '{"url":"https://example.com.evil.io/x"}').allowed)

    def test_taint_gate_catches_encoded_values(self):
        import base64
        cfg = controls.build_configuration("policy_validated")
        ctx = controls.ControlContext(sensitive_tools={"get_key"})
        controls.observe_result(cfg, ctx, "get_key", "api_key=sk-THISISAVERYLONGVALUE123")
        enc = base64.b64encode(b"sk-THISISAVERYLONGVALUE123").decode()
        self.assertFalse(controls.check_call(cfg, ctx, "post", f'{{"b":"{enc}"}}').allowed)
        self.assertTrue(controls.check_call(cfg, ctx, "post", '{"b":"hello"}').allowed)

    def test_confirmation_gate_says_no_human_was_available(self):
        cfg = controls.build_configuration("confirmation_gated")
        ctx = controls.ControlContext(dangerous_tools=frozenset({"purge"}))
        d = controls.check_call(cfg, ctx, "purge", "{}")
        self.assertFalse(d.allowed)
        self.assertIn("no human approver", d.reason)

    def test_bad_configurations_are_rejected(self):
        for spec in ({"name": "nonsense"}, {"name": "x", "controls": ["bogus"]},
                     {"name": "egress_restricted"}, {"name": "../escape", "controls": []}):
            with self.subTest(spec=spec), self.assertRaises(ValidationError):
                controls.build_configuration(spec)


if __name__ == "__main__":
    unittest.main()
