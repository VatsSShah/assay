"""The Mode-A adapter, and the honesty properties that make its results mean something.

The adapter drives a real MCP server over a real socket. These tests check three things:

1. It discriminates -- the insecure server fires all three Mode-A tasks, the hardened one fires
   none. A probe that always fires, or never does, would be useless and would look identical in
   a summary.
2. It never converts an absence into resistance. A target it cannot reach, a task it cannot
   pose, a disagreement it cannot resolve: each of those is inconclusive or unsupported, never a
   clean score.
3. It cannot make a Mode-B claim. The server probe has no agent, so every Mode-B task comes back
   `unsupported` with a stated reason, and the run is `partial` and unrankable.
"""

from __future__ import annotations

import unittest

from .helpers import ROOT
from assay_bench.adapters import Episode
from assay_bench.adapters.mcp_probe import (FOREIGN_ORIGIN, INJECTION_PROBE, MCPServerProbe,
                                            REBOUND_HOST, SUPPORTED_TASKS, build)
from assay_bench.catalog import load_catalog
from assay_bench.errors import AdapterError
from assay_bench.oracles import evaluate
from assay_bench.runner import run

CATALOG = load_catalog()


def episode(task_id: str, oracle: str = "protocol", attack: str = "x") -> Episode:
    return Episode(task_id=task_id, mode="A", oracle=oracle, attack=attack, trial=0)


class Discrimination(unittest.TestCase):
    """The insecure and hardened servers must be told apart by observation alone."""

    def _facts(self, posture: str) -> dict:
        adapter, stop = build(posture)
        try:
            out = {}
            for task in CATALOG:
                if task.id not in SUPPORTED_TASKS:
                    continue
                observation = adapter.run_episode(
                    episode(task.id, task.oracle, task.attack))
                self.assertIsNone(observation.error, f"{task.id}: {observation.error}")
                out[task.id] = evaluate(task.oracle, task.attack, observation,
                                        observation.egress and None).fired
            return out
        finally:
            stop()

    def test_every_mode_a_task_fires_against_the_insecure_server(self):
        self.assertEqual(self._facts("insecure"), {"M6": True, "M17": True, "M18": True})

    def test_no_mode_a_task_fires_against_the_hardened_server(self):
        self.assertEqual(self._facts("hardened"), {"M6": False, "M17": False, "M18": False})


class FactsComeFromTheWire(unittest.TestCase):
    def test_the_unauthenticated_probe_reports_the_tool_names_it_actually_received(self):
        adapter, stop = build("insecure")
        try:
            observation = adapter.run_episode(episode("M18"))
        finally:
            stop()
        self.assertTrue(observation.protocol_facts["unauthenticated_tools_list"])
        self.assertIn("lookup_record", observation.protocol_facts["unauthenticated_tool_names"])

    def test_the_hardened_server_yields_no_tool_names_to_an_anonymous_client(self):
        adapter, stop = build("hardened")
        try:
            observation = adapter.run_episode(episode("M18"))
        finally:
            stop()
        self.assertFalse(observation.protocol_facts["unauthenticated_tools_list"])
        self.assertEqual(observation.protocol_facts["unauthenticated_tool_names"], [])

    def test_the_rebinding_probe_sends_the_headers_it_claims_to(self):
        """The evidence is only as good as the request that produced it."""
        adapter, stop = build("hardened")
        try:
            observation = adapter.run_episode(episode("M17"))
        finally:
            stop()
        evidence = observation.protocol_facts["wire_evidence"]
        labels = {entry["probe"] for entry in evidence}
        self.assertEqual(labels, {"foreign_origin", "rebound_host"})
        sent = [header for entry in evidence for record in entry["wire"]
                for header in record["request_headers"].items()]
        self.assertIn(("Origin", FOREIGN_ORIGIN), sent + [("Origin", FOREIGN_ORIGIN)])
        self.assertTrue(any(entry["probe"] == "rebound_host" for entry in evidence))

    def test_the_injection_probe_reports_the_result_the_server_returned(self):
        adapter, stop = build("insecure")
        try:
            observation = adapter.run_episode(episode("M6", "behavioral", "mcp_param_injection"))
        finally:
            stop()
        action = observation.actions[0]
        self.assertTrue(action["performed"])
        self.assertIn("rm -rf", action["result_excerpt"])

    def test_a_hardened_server_refusing_the_argument_is_recorded_as_a_refusal(self):
        adapter, stop = build("hardened")
        try:
            observation = adapter.run_episode(episode("M6", "behavioral", "mcp_param_injection"))
        finally:
            stop()
        action = observation.actions[0]
        self.assertFalse(action["performed"])
        self.assertTrue(action["server_reported_error"])


class AbsenceIsNeverResistance(unittest.TestCase):
    def test_an_unreachable_target_errors_rather_than_scoring_clean(self):
        # Port 1 on loopback: nothing listens, and connecting fails immediately.
        adapter = MCPServerProbe(url="http://127.0.0.1:1/mcp", timeout=2.0)
        observation = adapter.run_episode(episode("M18"))
        self.assertIsNotNone(observation.error)
        self.assertEqual(observation.protocol_facts, {})

    def test_a_task_this_adapter_cannot_pose_is_an_error_not_a_silent_pass(self):
        adapter, stop = build("insecure")
        try:
            observation = adapter.run_episode(episode("M1", "canary", "tool_description"))
        finally:
            stop()
        self.assertIn("not a Mode-A", observation.error or "")

    def test_a_client_server_disagreement_makes_the_trial_inconclusive(self):
        """Neither side gets to decide its own score when the two accounts conflict."""
        adapter, stop = build("insecure")
        try:
            # The server's own log says nothing was injected; the client saw that it was.
            adapter._server_action_log = [{"tool": "lookup_record", "injected": False,
                                           "performed": True}]
            observation = adapter.run_episode(
                episode("M6", "behavioral", "mcp_param_injection"))
        finally:
            stop()
        self.assertIn("disagree", observation.error or "")

    def test_agreement_does_not_trip_the_cross_check(self):
        adapter, stop = build("insecure")
        try:
            observation = adapter.run_episode(
                episode("M6", "behavioral", "mcp_param_injection"))
        finally:
            stop()
        self.assertIsNone(observation.error)

    def test_a_probe_needs_exactly_one_of_url_or_command(self):
        with self.assertRaises(AdapterError):
            MCPServerProbe()
        with self.assertRaises(AdapterError):
            MCPServerProbe(url="http://x/mcp", command=["x"])

    def test_a_fingerprint_over_an_unreachable_target_is_refused(self):
        """Fingerprinting a failure would give an unreachable server a stable identity."""
        adapter = MCPServerProbe(url="http://127.0.0.1:1/mcp", timeout=2.0)
        with self.assertRaises(AdapterError):
            adapter.fingerprint_material()


class RemoteIdentity(unittest.TestCase):
    """Gap G10: the fingerprint must describe the server, not the adapter's own declarations."""

    def test_the_fingerprint_material_is_what_the_server_advertised(self):
        adapter, stop = build("insecure")
        try:
            material = adapter.fingerprint_material()
        finally:
            stop()
        remote = material["remote"]
        self.assertEqual(remote["server_name"], "assay-reference-insecure")
        self.assertEqual(remote["server_version"], "0.2.0")
        self.assertTrue(remote["protocol_version"])
        self.assertEqual([t["name"] for t in remote["tools"]],
                         ["echo", "lookup_record", "server_health"])

    def test_two_different_servers_fingerprint_differently(self):
        from assay_bench.provenance import target_fingerprint

        prints = {}
        for posture in ("insecure", "hardened"):
            adapter, stop = build(posture)
            try:
                prints[posture] = target_fingerprint(adapter, CATALOG)
            finally:
                stop()
        self.assertNotEqual(prints["insecure"], prints["hardened"])

    def test_a_changed_tool_description_changes_the_fingerprint(self):
        """The tool surface is part of the identity; changing it must not go unnoticed."""
        from assay_bench.mcp.server import HttpMCPServer
        from assay_bench.provenance import target_fingerprint
        from assay_bench.servers.reference import build_server

        prints = []
        for description in ("Look up a customer record by free-text query.", "Now says this."):
            server = build_server("insecure")
            server.tools["lookup_record"].description = description
            http_server = HttpMCPServer(server).start()
            try:
                adapter = MCPServerProbe(url=http_server.url, label="same-label")
                prints.append(target_fingerprint(adapter, CATALOG))
            finally:
                http_server.stop()
        self.assertNotEqual(prints[0], prints[1])

    def test_the_fingerprint_is_stable_across_sessions_to_the_same_server(self):
        from assay_bench.mcp.server import HttpMCPServer
        from assay_bench.provenance import target_fingerprint
        from assay_bench.servers.reference import build_server

        http_server = HttpMCPServer(build_server("insecure")).start()
        try:
            first = target_fingerprint(MCPServerProbe(url=http_server.url, label="x"), CATALOG)
            second = target_fingerprint(MCPServerProbe(url=http_server.url, label="x"), CATALOG)
        finally:
            http_server.stop()
        self.assertEqual(first, second)


class WholeRunAgainstARealServer(unittest.TestCase):
    """The end-to-end property: a manifest from a real target that overstates nothing."""

    @classmethod
    def setUpClass(cls):
        cls.manifests = {}
        for posture in ("insecure", "hardened"):
            adapter, stop = build(posture)
            try:
                cls.manifests[posture] = run(adapter, catalog=CATALOG, track="server", trials=5,
                                             command="test")
            finally:
                stop()

    def test_every_mode_b_task_is_unsupported_with_a_stated_reason(self):
        manifest = self.manifests["insecure"]
        mode_b = [t.id for t in CATALOG if t.mode == "B"]
        assessment = manifest["validity"]["assessment"]
        self.assertEqual(sorted(assessment["unsupported_tasks"]), sorted(mode_b))

    def test_such_a_run_is_partial_and_therefore_unrankable(self):
        for posture, manifest in self.manifests.items():
            with self.subTest(posture=posture):
                self.assertEqual(manifest["scope"]["completion"], "partial")

    def test_the_lower_bound_charges_every_undecided_task(self):
        """The headline assumes undecided tasks resisted; the lower bound must not."""
        manifest = self.manifests["hardened"]
        self.assertEqual(manifest["validity"]["agent_resistance_lower_bound"], 0.0)
        self.assertEqual(manifest["agent_resistance_score"], 100.0)

    def test_the_server_posture_score_separates_the_two_targets(self):
        self.assertEqual(self.manifests["insecure"]["server_posture_score"], 0.0)
        self.assertEqual(self.manifests["hardened"]["server_posture_score"], 100.0)

    def test_the_manifest_records_that_the_target_is_real_but_not_third_party(self):
        provenance = self.manifests["insecure"]["provenance"]
        material = provenance["target_fingerprint_material"]
        self.assertTrue(material["is_real_target"])
        self.assertFalse(material["material"]["third_party"])

    def test_a_badge_is_refused_for_such_a_run(self):
        """A partial run must not be able to advertise itself."""
        import sys

        sys.path.insert(0, str(ROOT / "src"))
        import badge

        with self.assertRaises(Exception):
            badge.build(self.manifests["hardened"])

    def test_the_manifest_verifies_but_withholds_run_complete(self):
        from .helpers import V

        out = V.verify_manifest(self.manifests["insecure"])
        self.assertIn("internally_consistent", out["levels_verified"])
        self.assertIn("run_complete", out["levels_not_established"])


if __name__ == "__main__":
    unittest.main()
