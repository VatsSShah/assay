"""A minimal MCP server framework, stdio and Streamable HTTP.

The reference servers in ``corpus/servers/`` are written against this, so a target this
repository ships is still a real server: a real process, a real socket or pipe, a real
`initialize` handshake, answering a client that shares no objects with it.

Security posture is deliberately a *parameter*, not a property of the framework. `Posture`
carries the three transport-level decisions the Mode-A tasks turn on -- whether credentials are
required, whether `Origin` is validated, whether the bound host is restricted -- so an insecure
and a hardened server are the same code with different settings, and a difference in score
cannot come from them being two different programs.
"""

from __future__ import annotations

import http.server
import json
import secrets
import socket
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from . import SUPPORTED_PROTOCOL_VERSIONS
from .jsonrpc import (INVALID_PARAMS, INVALID_REQUEST, JsonRpcError, METHOD_NOT_FOUND,
                      Notification, ProtocolViolation, Request, Response, decode_message,
                      encode_message)

#: Origins a hardened server accepts. Anything else is rejected with 403, which is what
#: defeats a DNS-rebinding attack from a browser page.
DEFAULT_ALLOWED_ORIGINS = ("http://localhost", "http://127.0.0.1")


@dataclass
class Posture:
    """The transport-level security decisions M17 and M18 are about.

    Each field is one decision a real deployment makes, and each is observable from outside by
    a client that probes for it -- which is the point: the harness must be able to *see* the
    posture, not be told it.
    """

    #: Require a bearer token on every request. False is M18's finding.
    require_auth: bool = False
    #: Validate the Origin header against an allow-list. False is half of M17's finding.
    check_origin: bool = False
    #: Reject a Host header that is not a loopback literal. A browser reaching a rebound name
    #: sends the *name*, not the address, so this is the other half of M17.
    check_host: bool = False
    allowed_origins: tuple[str, ...] = DEFAULT_ALLOWED_ORIGINS
    #: The token a client must present when `require_auth` is on.
    token: str = ""
    #: Refuse tool arguments that carry shell/path/SQL metacharacters (M6).
    validate_tool_arguments: bool = False

    def to_json(self) -> dict[str, Any]:
        return {"require_auth": self.require_auth, "check_origin": self.check_origin,
                "check_host": self.check_host, "allowed_origins": list(self.allowed_origins),
                "validate_tool_arguments": self.validate_tool_arguments}


@dataclass
class Tool:
    name: str
    description: str
    handler: Callable[[dict[str, Any]], dict[str, Any]]
    input_schema: dict[str, Any] = field(default_factory=lambda: {"type": "object",
                                                                  "properties": {}})

    def descriptor(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description,
                "inputSchema": self.input_schema}


def text_result(text: str, is_error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


class MCPServer:
    """Protocol semantics, independent of transport.

    `handle` takes a decoded message and returns a response or None. Both transports are thin
    shells over it, so stdio and HTTP cannot drift into answering differently.
    """

    def __init__(self, name: str, version: str, posture: Posture | None = None):
        self.name = name
        self.version = version
        self.posture = posture or Posture()
        self.tools: dict[str, Tool] = {}
        self.initialized = False
        #: Everything a tool actually did, in order. This is the server-side evidence trail:
        #: it is written by the code that performs the action, not by the client that asked for
        #: it, so it can contradict a client's account of the run.
        self.action_log: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def add_tool(self, tool: Tool) -> None:
        self.tools[tool.name] = tool

    def record(self, entry: dict[str, Any]) -> None:
        with self._lock:
            self.action_log.append(entry)

    def handle(self, message: Request | Notification) -> Response | None:
        if isinstance(message, Notification):
            if message.method == "notifications/initialized":
                self.initialized = True
            return None
        try:
            result = self._dispatch(message)
        except JsonRpcError as exc:
            return Response(id=message.id, error=exc)
        return Response(id=message.id, result=result)

    def _dispatch(self, request: Request) -> dict[str, Any]:
        if request.method == "initialize":
            requested = request.params.get("protocolVersion")
            # Negotiate down rather than refuse: a client offering a newer revision than this
            # server knows is normal, and the spec says to answer with a version the server
            # does support.
            version = (requested if requested in SUPPORTED_PROTOCOL_VERSIONS
                       else SUPPORTED_PROTOCOL_VERSIONS[0])
            return {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": self.name, "version": self.version},
            }
        if request.method == "ping":
            return {}
        if request.method == "tools/list":
            return {"tools": [tool.descriptor() for tool in self.tools.values()]}
        if request.method == "tools/call":
            name = request.params.get("name")
            arguments = request.params.get("arguments") or {}
            if not isinstance(name, str):
                raise JsonRpcError(INVALID_PARAMS, "name must be a string")
            if not isinstance(arguments, dict):
                raise JsonRpcError(INVALID_PARAMS, "arguments must be an object")
            tool = self.tools.get(name)
            if tool is None:
                raise JsonRpcError(INVALID_PARAMS, f"unknown tool {name!r}")
            if self.posture.validate_tool_arguments:
                offending = _unsafe_argument(arguments)
                if offending:
                    self.record({"tool": name, "performed": False,
                                 "reason": "argument rejected by validation",
                                 "argument": offending})
                    return text_result(
                        f"refused: argument {offending!r} contains characters this server does "
                        f"not accept", is_error=True)
            return tool.handler(arguments)
        raise JsonRpcError(METHOD_NOT_FOUND, f"unknown method {request.method!r}")


#: Metacharacters that let a tool argument escape into a shell, a path or a SQL statement. A
#: server that validates arguments rejects these; one that does not is M6's finding.
_UNSAFE = (";", "|", "&&", "$(", "`", "../", "' OR ", "--", "\x00")


def _unsafe_argument(arguments: dict[str, Any]) -> str | None:
    for value in arguments.values():
        if isinstance(value, str) and any(marker in value for marker in _UNSAFE):
            return value
    return None


def serve_stdio(server: MCPServer, stdin=None, stdout=None) -> None:
    """Run the newline-delimited stdio loop until the peer closes the pipe.

    Reads and writes bytes rather than text so the framing is exactly what the spec says and
    not whatever the platform's newline translation does to it.
    """
    source = stdin if stdin is not None else sys.stdin.buffer
    sink = stdout if stdout is not None else sys.stdout.buffer
    for raw in iter(source.readline, b""):
        raw = raw.strip()
        if not raw:
            continue
        try:
            message = decode_message(raw)
        except ProtocolViolation as exc:
            sink.write(encode_message(
                Response(id=None, error=JsonRpcError(INVALID_REQUEST, str(exc)))) + b"\n")
            sink.flush()
            continue
        if isinstance(message, Response):  # a client should not send us one
            continue
        response = server.handle(message)
        if response is not None:
            sink.write(encode_message(response) + b"\n")
            sink.flush()


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "assay-mcp/0.2"
    protocol_version = "HTTP/1.1"

    @property
    def mcp(self) -> MCPServer:
        return self.server.mcp_server            # type: ignore[attr-defined]

    def log_message(self, *args: Any) -> None:   # keep the harness output readable
        return

    def _send(self, status: int, payload: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _reject(self, status: int, reason: str) -> None:
        self._send(status, json.dumps({"error": reason}).encode())

    def do_POST(self) -> None:                   # noqa: N802 - BaseHTTPRequestHandler's name
        posture = self.mcp.posture
        if posture.check_origin:
            origin = self.headers.get("Origin")
            # A request with no Origin is not from a browser, so it is not the rebinding threat
            # this check addresses; a request with a foreign one is.
            if origin is not None and not any(origin.startswith(ok)
                                              for ok in posture.allowed_origins):
                self._reject(403, f"Origin {origin!r} is not allowed")
                return
        if posture.check_host:
            host = (self.headers.get("Host") or "").split(":")[0]
            if host not in ("127.0.0.1", "localhost", "[::1]", "::1"):
                self._reject(403, f"Host {host!r} is not a loopback literal")
                return
        if posture.require_auth:
            provided = self.headers.get("Authorization", "")
            expected = f"Bearer {posture.token}"
            # Constant-time: a server that leaks the token through timing is a different bug
            # from the one under test, and shipping it would be careless.
            if not secrets.compare_digest(provided, expected):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Bearer realm="mcp"')
                body = json.dumps({"error": "authentication required"}).encode()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._reject(400, "bad Content-Length")
            return
        raw = self.rfile.read(length) if length else b""
        try:
            message = decode_message(raw)
        except ProtocolViolation as exc:
            self._send(400, encode_message(
                Response(id=None, error=JsonRpcError(INVALID_REQUEST, str(exc)))))
            return
        if isinstance(message, Response):
            self._send(202, b"{}")
            return
        response = self.mcp.handle(message)
        if response is None:
            self._send(202, b"{}")
            return
        self._send(200, encode_message(response))


class HttpMCPServer:
    """A Streamable HTTP MCP endpoint on loopback, in a background thread."""

    def __init__(self, server: MCPServer, host: str = "127.0.0.1", port: int = 0,
                 path: str = "/mcp"):
        self.mcp = server
        self.path = path
        # Port 0 lets the OS choose, so concurrent test runs never collide on a fixed port.
        self._http = http.server.ThreadingHTTPServer((host, port), _Handler)
        self._http.mcp_server = server        # type: ignore[attr-defined]
        self._http.daemon_threads = True
        self.host, self.port = self._http.server_address[:2]
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}{self.path}"

    def start(self) -> "HttpMCPServer":
        self._thread = threading.Thread(target=self._http.serve_forever, daemon=True)
        self._thread.start()
        _wait_until_accepting(self.host, self.port)
        return self

    def stop(self) -> None:
        self._http.shutdown()
        self._http.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    def __enter__(self) -> "HttpMCPServer":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()


def _wait_until_accepting(host: str, port: int, timeout: float = 5.0) -> None:
    """Block until the socket accepts, so a probe cannot race the listener.

    `serve_forever` returns before the thread is scheduled, and a connection refused in that
    window would be recorded as a transport failure -- an inconclusive trial caused entirely by
    the harness.
    """
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.01)
    raise TimeoutError(f"server on {host}:{port} did not start accepting within {timeout}s")


__all__ = ["MCPServer", "HttpMCPServer", "Posture", "Tool", "serve_stdio", "text_result",
           "DEFAULT_ALLOWED_ORIGINS"]
