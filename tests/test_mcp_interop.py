"""Interoperability with the **official** MCP SDK.

Every other test in this repository stands our client up against our server. Two programs by
the same author agreeing with each other establishes that they agree, not that either speaks
MCP. This module is the check that does establish it: it builds a server with the official
`mcp` package and drives it with this repository's client over a real subprocess, exercising
the handshake, protocol-version negotiation, `tools/list` and `tools/call`.

The `mcp` package is **not** a dependency of this project -- the runtime is stdlib-only and
stays that way. The test is skipped when the package is absent, and the skip is reported rather
than hidden, because "0 failures" with this test silently skipped would be exactly the kind of
green that means nothing. CI installs the package into a throwaway environment so the check
actually runs there; `tests/test_artifacts_and_docs.py` asserts the workflow still does.

To run it locally:

    python -m venv /tmp/mcp-sdk && /tmp/mcp-sdk/bin/pip install mcp
    ASSAY_MCP_SDK_PYTHON=/tmp/mcp-sdk/bin/python python -m unittest tests.test_mcp_interop -v
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from .helpers import ROOT                 # noqa: F401 - puts src/ on sys.path
from assay_bench.mcp.client import MCPClient, StdioTransport, text_of

#: An interpreter that has the official SDK installed. Defaults to the one running the tests,
#: so a developer who installed `mcp` alongside the project gets the check for free.
SDK_PYTHON = os.environ.get("ASSAY_MCP_SDK_PYTHON", sys.executable)


def _sdk_entrypoint() -> tuple[str, str] | None:
    """Find the official SDK's server class, across the v1/v2 rename.

    v1 exposed `mcp.server.fastmcp.FastMCP`; v2 renamed it to `mcp.server.mcpserver.MCPServer`.
    Probing for both means the check keeps working across that boundary instead of silently
    skipping -- a skip that looks like "the SDK is missing" when the SDK is merely newer is the
    failure mode worth avoiding here.
    """
    probe = textwrap.dedent("""
        import json
        for module, attribute in (("mcp.server.mcpserver", "MCPServer"),
                                  ("mcp.server.fastmcp", "FastMCP")):
            try:
                __import__(module)
            except Exception:
                continue
            print(json.dumps([module, attribute]))
            break
        """)
    try:
        result = subprocess.run([SDK_PYTHON, "-c", probe], capture_output=True, text=True,
                                timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    module, attribute = json.loads(result.stdout.strip())
    return module, attribute


ENTRYPOINT = _sdk_entrypoint()

SERVER_SOURCE = textwrap.dedent('''
    """A server built with the OFFICIAL MCP SDK, driven by this repository's client."""
    from {module} import {attribute} as Server

    server = Server("official-sdk-reference")


    @server.tool()
    def add(a: int, b: int) -> int:
        """Add two integers."""
        return a + b


    @server.tool()
    def shout(text: str) -> str:
        """Upper-case the text given."""
        return text.upper()


    if __name__ == "__main__":
        server.run()
    ''')


@unittest.skipIf(ENTRYPOINT is None,
                 f"the official mcp SDK is not importable by {SDK_PYTHON!r}; set "
                 f"ASSAY_MCP_SDK_PYTHON to an interpreter that has it")
class OfficialSDKInterop(unittest.TestCase):
    """Our client must drive a server written by someone else."""

    @classmethod
    def setUpClass(cls):
        module, attribute = ENTRYPOINT            # type: ignore[misc]
        cls.tmp = tempfile.mkdtemp(prefix="assay-mcp-interop-")
        cls.script = Path(cls.tmp) / "sdk_server.py"
        cls.script.write_text(SERVER_SOURCE.format(module=module, attribute=attribute))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _client(self) -> MCPClient:
        transport = StdioTransport([SDK_PYTHON, "-u", str(self.script)])
        # The SDK server imports a substantial dependency tree at start-up, so the budget here
        # is generous; a stingy timeout would make this look like a protocol failure.
        client = MCPClient(transport, timeout=60.0)
        self.addCleanup(client.close)
        return client

    def test_the_handshake_succeeds_against_a_third_party_server(self):
        client = self._client()
        result = client.initialize()
        self.assertEqual(result["serverInfo"]["name"], "official-sdk-reference")
        self.assertTrue(client.protocol_version)

    def test_tools_list_returns_what_the_sdk_registered(self):
        client = self._client()
        client.initialize()
        tools = {t.name: t for t in client.list_tools()}
        self.assertEqual(set(tools), {"add", "shout"})
        self.assertEqual(tools["add"].description.strip(), "Add two integers.")
        self.assertEqual(tools["add"].input_schema["type"], "object")

    def test_a_tool_call_returns_the_computed_result(self):
        client = self._client()
        client.initialize()
        self.assertEqual(text_of(client.call_tool("add", {"a": 17, "b": 25})), "42")
        self.assertEqual(text_of(client.call_tool("shout", {"text": "quiet"})), "QUIET")

    def test_the_negotiated_version_is_one_this_client_declares(self):
        """Negotiating something we do not implement would be a silent compatibility lie."""
        from assay_bench.mcp import SUPPORTED_PROTOCOL_VERSIONS

        client = self._client()
        client.initialize()
        self.assertIn(client.protocol_version, SUPPORTED_PROTOCOL_VERSIONS)

    def test_the_probe_adapter_can_fingerprint_a_third_party_server(self):
        """The Mode-A identity path must work against software we did not write."""
        from assay_bench.adapters.mcp_probe import MCPServerProbe

        adapter = MCPServerProbe(command=[SDK_PYTHON, "-u", str(self.script)], timeout=60.0,
                                 third_party=True)
        material = adapter.fingerprint_material()
        self.assertTrue(material["third_party"])
        self.assertEqual(material["remote"]["server_name"], "official-sdk-reference")
        self.assertEqual([t["name"] for t in material["remote"]["tools"]], ["add", "shout"])

    def test_a_stdio_target_reports_the_transport_tasks_unsupported(self):
        """M17 and M18 are HTTP properties; over stdio they must be unsupported, not resisted."""
        from assay_bench.adapters import supports
        from assay_bench.adapters.mcp_probe import MCPServerProbe

        adapter = MCPServerProbe(command=[SDK_PYTHON, "-u", str(self.script)], timeout=60.0)
        capabilities = adapter.capabilities()
        self.assertFalse(capabilities.exposes_protocol_facts)
        self.assertFalse(supports(capabilities, "protocol", "text", "A"))


class TheSkipIsVisible(unittest.TestCase):
    """A skipped interop check must be legible, not a silent hole in a green run."""

    def test_the_repository_says_how_to_run_this_check(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn("ASSAY_MCP_SDK_PYTHON", workflow,
                      "CI must run the interop check against the official SDK, otherwise the "
                      "claim that this client speaks MCP rests on our own server agreeing")


if __name__ == "__main__":
    unittest.main()
