"""The MCP implementation: framing, handshake, transports, and the two reference servers.

These tests exist because the claim they support is a strong one -- that the harness speaks a
real protocol to a real process rather than to itself. So they check the protocol layer the way
a hostile peer would: malformed frames, mismatched ids, a server that answers a different
version, a server that never answers at all.

Interoperability with the *official* MCP SDK is checked separately in `test_mcp_interop.py`,
because a client and a server written by the same author agreeing with each other proves only
that they agree.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import unittest

from .helpers import ROOT
from assay_bench.mcp import SUPPORTED_PROTOCOL_VERSIONS
from assay_bench.mcp.client import (HttpTransport, MCPClient, StdioTransport, TransportError,
                                    _first_sse_data, stdio_server_command, text_of)
from assay_bench.mcp.jsonrpc import (JsonRpcError, Notification, ProtocolViolation, Request,
                                     Response, decode_message, encode_message)
from assay_bench.mcp.server import HttpMCPServer, MCPServer, Posture, Tool, text_result
from assay_bench.servers.reference import build_server

ENV = dict(os.environ, PYTHONPATH=str(ROOT / "src"))


class Framing(unittest.TestCase):
    def test_a_request_round_trips(self):
        request = Request(method="tools/list", params={"a": 1}, id=7)
        decoded = decode_message(encode_message(request))
        self.assertIsInstance(decoded, Request)
        self.assertEqual((decoded.method, decoded.params, decoded.id), ("tools/list", {"a": 1}, 7))

    def test_encoding_never_emits_a_newline(self):
        """The stdio framing is newline-delimited, so a payload newline would split a frame."""
        request = Request(method="echo", params={"text": "one\ntwo\r\nthree "}, id=1)
        raw = encode_message(request)
        self.assertNotIn(b"\n", raw)
        self.assertNotIn(b"\r", raw)
        self.assertEqual(decode_message(raw).params["text"], "one\ntwo\r\nthree ")

    def test_a_notification_has_no_id_and_decodes_as_one(self):
        decoded = decode_message(encode_message(Notification("notifications/initialized")))
        self.assertIsInstance(decoded, Notification)

    def test_an_error_response_carries_its_code(self):
        decoded = decode_message(encode_message(
            Response(id=3, error=JsonRpcError(-32601, "no such method"))))
        self.assertIsInstance(decoded, Response)
        with self.assertRaises(JsonRpcError) as caught:
            decoded.raise_for_error()
        self.assertEqual(caught.exception.code, -32601)

    def test_malformed_frames_are_rejected_rather_than_guessed_at(self):
        for raw, why in [
            (b"not json", "not JSON"),
            (b"[1,2,3]", "an array, not an object"),
            (b'{"id":1,"result":{}}', "no jsonrpc field"),
            (b'{"jsonrpc":"1.0","id":1,"result":{}}', "wrong jsonrpc version"),
            (b'{"jsonrpc":"2.0","result":{}}', "a response with no id"),
            (b'{"jsonrpc":"2.0","id":1}', "neither result nor error"),
            (b'{"jsonrpc":"2.0","id":1,"method":5}', "non-string method"),
            (b'{"jsonrpc":"2.0","id":1,"method":"x","params":[1]}', "positional params"),
            (b'{"jsonrpc":"2.0","id":1,"error":{"message":"x"}}', "error with no code"),
            (b'{"jsonrpc":"2.0","id":1,"error":{"code":"x","message":"y"}}', "non-int code"),
            (b"\xff\xfe", "not UTF-8"),
        ]:
            with self.subTest(why=why):
                with self.assertRaises(ProtocolViolation):
                    decode_message(raw)

    def test_an_sse_body_with_a_multiline_data_field_is_reassembled(self):
        """Truncating at the first `data:` line would silently corrupt a split JSON body."""
        body = b'event: message\ndata: {"jsonrpc":"2.0",\ndata: "id":1,"result":{}}\n\n'
        self.assertEqual(json.loads(_first_sse_data(body))["id"], 1)

    def test_an_event_stream_with_no_data_field_is_a_violation(self):
        with self.assertRaises(ProtocolViolation):
            _first_sse_data(b"event: ping\n\n")


class Handshake(unittest.TestCase):
    def setUp(self):
        self.server = HttpMCPServer(build_server("insecure")).start()
        self.addCleanup(self.server.stop)

    def test_initialize_negotiates_a_version_this_client_knows(self):
        with MCPClient(HttpTransport(self.server.url)) as client:
            client.initialize()
            self.assertIn(client.protocol_version, SUPPORTED_PROTOCOL_VERSIONS)
            self.assertEqual(client.server_info["name"], "assay-reference-insecure")

    def test_tools_list_before_initialize_is_refused_by_the_client(self):
        """A client that skips the handshake would make an uninitialised server look compliant."""
        with MCPClient(HttpTransport(self.server.url)) as client:
            with self.assertRaises(ProtocolViolation):
                client.list_tools()

    def test_a_server_offering_an_unknown_protocol_version_is_a_violation(self):
        class TimeTraveller(MCPServer):
            def _dispatch(self, request):
                if request.method == "initialize":
                    return {"protocolVersion": "2099-01-01", "capabilities": {},
                            "serverInfo": {"name": "future", "version": "1"}}
                return super()._dispatch(request)

        with HttpMCPServer(TimeTraveller("future", "1")) as server:
            with MCPClient(HttpTransport(server.url)) as client:
                with self.assertRaisesRegex(ProtocolViolation, "2099-01-01"):
                    client.initialize()

    def test_a_mismatched_response_id_is_a_violation(self):
        class Confused(MCPServer):
            def handle(self, message):
                response = super().handle(message)
                if response is not None:
                    response.id = 999
                return response

        with HttpMCPServer(Confused("confused", "1")) as server:
            with MCPClient(HttpTransport(server.url)) as client:
                with self.assertRaisesRegex(ProtocolViolation, "does not match"):
                    client.initialize()

    def test_an_unknown_method_comes_back_as_a_protocol_error_not_a_crash(self):
        with MCPClient(HttpTransport(self.server.url)) as client:
            client.initialize()
            with self.assertRaises(JsonRpcError) as caught:
                client._call("resources/list")
            self.assertEqual(caught.exception.code, -32601)


class StdioTransportTests(unittest.TestCase):
    def _client(self, posture="insecure"):
        transport = StdioTransport(
            stdio_server_command("assay_bench.servers.reference", "--posture", posture,
                                 "--transport", "stdio"), env=ENV)
        client = MCPClient(transport, timeout=20.0)
        self.addCleanup(client.close)
        return client

    def test_a_full_session_works_over_a_real_subprocess(self):
        client = self._client()
        client.initialize()
        names = {t.name for t in client.list_tools()}
        self.assertEqual(names, {"lookup_record", "echo", "server_health"})
        self.assertEqual(text_of(client.call_tool("echo", {"message": "hello"})), "hello")

    def test_a_command_that_does_not_exist_is_a_transport_error(self):
        with self.assertRaises(TransportError):
            StdioTransport(["/nonexistent/assay-not-a-real-binary"])

    def test_a_server_that_never_answers_times_out_rather_than_hanging(self):
        """A target that accepts a request and goes quiet must not wedge the whole run."""
        script = "import sys\nfor line in sys.stdin.buffer: pass\n"
        transport = StdioTransport([sys.executable, "-u", "-c", script])
        client = MCPClient(transport, timeout=1.0)
        self.addCleanup(client.close)
        with self.assertRaisesRegex(TransportError, "did not answer"):
            client.initialize()

    def test_a_server_that_exits_immediately_reports_its_stderr(self):
        script = "import sys\nsys.stderr.write('boom: config missing\\n')\nraise SystemExit(3)\n"
        transport = StdioTransport([sys.executable, "-u", "-c", script])
        client = MCPClient(transport, timeout=5.0)
        self.addCleanup(client.close)
        with self.assertRaises(TransportError) as caught:
            client.initialize()
        self.assertIn("boom: config missing", str(caught.exception))

    def test_a_server_emitting_a_malformed_frame_is_a_violation_not_a_silent_pass(self):
        script = ("import sys\n"
                  "sys.stdin.buffer.readline()\n"
                  "sys.stdout.buffer.write(b'{oops}\\n'); sys.stdout.buffer.flush()\n"
                  "for line in sys.stdin.buffer: pass\n")
        transport = StdioTransport([sys.executable, "-u", "-c", script])
        client = MCPClient(transport, timeout=5.0)
        self.addCleanup(client.close)
        with self.assertRaises(ProtocolViolation):
            client.initialize()


class PostureIsObservable(unittest.TestCase):
    """The whole Mode-A argument is that posture is visible from outside. Check that it is."""

    def test_the_insecure_server_serves_an_anonymous_tools_list(self):
        with HttpMCPServer(build_server("insecure")) as server:
            with MCPClient(HttpTransport(server.url)) as client:
                client.initialize()
                self.assertTrue(client.list_tools())

    def test_the_hardened_server_refuses_an_anonymous_client_with_401(self):
        hardened = build_server("hardened", token="s3cret")
        with HttpMCPServer(hardened) as server:
            with MCPClient(HttpTransport(server.url)) as client:
                response, observation = client.transport.request(
                    Request(method="initialize", params={}, id=1), 5.0)
                self.assertEqual(observation.status, 401)
                self.assertIn("bearer", observation.response_headers
                              .get("www-authenticate", "").lower())

    def test_the_hardened_server_accepts_the_right_token(self):
        hardened = build_server("hardened", token="s3cret")
        with HttpMCPServer(hardened) as server:
            transport = HttpTransport(server.url, {"Authorization": "Bearer s3cret"})
            with MCPClient(transport) as client:
                client.initialize()
                self.assertTrue(client.list_tools())

    def test_the_hardened_server_rejects_a_foreign_origin(self):
        hardened = build_server("hardened", token="s3cret")
        with HttpMCPServer(hardened) as server:
            transport = HttpTransport(server.url, {"Authorization": "Bearer s3cret",
                                                   "Origin": "http://attacker.example"})
            response, observation = transport.request(Request("initialize", {}, 1), 5.0)
            self.assertEqual(observation.status, 403)

    def test_the_hardened_server_accepts_a_loopback_origin(self):
        """Rejecting everything would be a different bug wearing the same passing test."""
        hardened = build_server("hardened", token="s3cret")
        with HttpMCPServer(hardened) as server:
            transport = HttpTransport(server.url, {"Authorization": "Bearer s3cret",
                                                   "Origin": "http://localhost:3000"})
            with MCPClient(transport) as client:
                client.initialize()

    def test_the_hardened_server_rejects_a_rebound_host(self):
        hardened = build_server("hardened", token="s3cret")
        with HttpMCPServer(hardened) as server:
            transport = HttpTransport(server.url, {"Authorization": "Bearer s3cret",
                                                   "Host": "mcp.attacker.example"})
            response, observation = transport.request(Request("initialize", {}, 1), 5.0)
            self.assertEqual(observation.status, 403)

    def test_the_insecure_server_acts_on_an_injected_argument(self):
        server = build_server("insecure")
        with HttpMCPServer(server) as http_server:
            with MCPClient(HttpTransport(http_server.url)) as client:
                client.initialize()
                body = text_of(client.call_tool("lookup_record",
                                                {"query": "acme'; rm -rf /srv; echo '"}))
        self.assertIn("rm -rf /srv", body)
        self.assertTrue(any(e.get("injected") for e in server.action_log))

    def test_the_hardened_server_refuses_it_and_records_the_refusal(self):
        server = build_server("hardened", token="t")
        with HttpMCPServer(server) as http_server:
            transport = HttpTransport(http_server.url, {"Authorization": "Bearer t"})
            with MCPClient(transport) as client:
                client.initialize()
                result = client.call_tool("lookup_record",
                                          {"query": "acme'; rm -rf /srv; echo '"})
        self.assertTrue(result["isError"])
        self.assertTrue(all(not e.get("performed") for e in server.action_log))

    def test_a_benign_argument_still_works_on_the_hardened_server(self):
        """A server that refused every argument would pass the test above for the wrong reason."""
        server = build_server("hardened", token="t")
        with HttpMCPServer(server) as http_server:
            transport = HttpTransport(http_server.url, {"Authorization": "Bearer t"})
            with MCPClient(transport) as client:
                client.initialize()
                result = client.call_tool("lookup_record", {"query": "acme corporation"})
        self.assertFalse(result.get("isError"))
        self.assertIn("2 records matched", text_of(result))

    def test_the_two_postures_are_the_same_program(self):
        """A score difference between them must come from posture, not from different code."""
        insecure, hardened = build_server("insecure"), build_server("hardened", token="t")
        self.assertEqual(sorted(insecure.tools), sorted(hardened.tools))
        for name in insecure.tools:
            self.assertEqual(insecure.tools[name].handler.__code__,
                             hardened.tools[name].handler.__code__)


class ServerProcess(unittest.TestCase):
    def test_the_http_server_runs_as_a_process_and_announces_its_url_on_stderr(self):
        """stdout carries protocol frames, so nothing else may be written there."""
        proc = subprocess.Popen(
            [sys.executable, "-u", "-m", "assay_bench.servers.reference",
             "--posture", "insecure", "--transport", "http", "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, cwd=ROOT)

        def cleanup():
            proc.kill()
            proc.wait(timeout=5)
            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    stream.close()

        self.addCleanup(cleanup)
        # The very first stderr line must be the announcement: anything else there (a warning,
        # a banner) would corrupt the only machine-readable channel a supervisor has.
        line = proc.stderr.readline().decode()
        announced = json.loads(line)
        self.assertIn("url", announced)
        with MCPClient(HttpTransport(announced["url"])) as client:
            client.initialize()
            self.assertTrue(client.list_tools())

    def test_an_unknown_posture_is_refused_rather_than_defaulted(self):
        with self.assertRaises(ValueError):
            build_server("mostly-secure")


class ConcurrentSessions(unittest.TestCase):
    def test_the_server_serves_several_clients_at_once(self):
        """The runner opens a session per probe; a server that serialises them would time out."""
        errors: list[Exception] = []

        def session(url):
            try:
                with MCPClient(HttpTransport(url), timeout=15.0) as client:
                    client.initialize()
                    client.list_tools()
            except Exception as exc:              # noqa: BLE001
                errors.append(exc)

        with HttpMCPServer(build_server("insecure")) as server:
            threads = [threading.Thread(target=session, args=(server.url,)) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=20)
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
