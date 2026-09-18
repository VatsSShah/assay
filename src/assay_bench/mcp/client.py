"""An MCP client: the real `initialize` handshake, `tools/list` and `tools/call`.

Two transports, because the Mode-A tasks need both kinds of evidence:

* :class:`StdioTransport` spawns a server as a subprocess and exchanges newline-delimited
  JSON-RPC on its stdin/stdout. This is how most MCP servers are deployed, and it is the
  transport the optional interoperability test drives the official SDK over.
* :class:`HttpTransport` POSTs to a Streamable HTTP endpoint. The transport-level tasks --
  unauthenticated exposure (M18) and DNS rebinding (M17) -- are *HTTP* properties, so they can
  only be observed here. The transport records what it saw on the wire (status codes, headers
  echoed, whether credentials were required) so the adapter reports observations rather than
  assertions.

Everything the client records about a peer is an observation with a provenance: the status
line, the response headers, the negotiated protocol version, the advertised server info. None
of it is supplied by the harness.
"""

from __future__ import annotations

import http.client
import json
import os
import selectors
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from . import CLIENT_INFO, SUPPORTED_PROTOCOL_VERSIONS
from .jsonrpc import (JsonRpcError, Notification, ProtocolViolation, Request, Response,
                      decode_message, encode_message)


class TransportError(Exception):
    """The connection failed, as opposed to the peer answering with an error.

    The harness treats this as an inconclusive trial, never as resistance.
    """


@dataclass
class WireObservation:
    """What was actually seen on the wire for one exchange.

    Kept separately from the decoded result because the protocol tasks are decided by transport
    facts -- a status code, a rejected Origin -- that never appear in a JSON-RPC result.
    """

    request_headers: dict[str, str] = field(default_factory=dict)
    status: int | None = None
    reason: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    body_bytes: int = 0
    error: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {"request_headers": dict(self.request_headers), "status": self.status,
                "reason": self.reason, "response_headers": dict(self.response_headers),
                "body_bytes": self.body_bytes, "error": self.error}


class Transport:
    """What a transport must do. Deliberately tiny: one round trip, one notification, close."""

    name = "abstract"

    def request(self, message: Request, timeout: float) -> tuple[Response, WireObservation]:
        raise NotImplementedError

    def notify(self, message: Notification, timeout: float) -> WireObservation:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class StdioTransport(Transport):
    """Newline-delimited JSON-RPC over a subprocess's stdin/stdout.

    The server's stderr is drained on a thread and kept, because a server that crashes writes
    its reason there and losing it turns a diagnosable failure into "the trial errored".
    """

    name = "stdio"

    def __init__(self, command: list[str], env: dict[str, str] | None = None,
                 cwd: str | None = None):
        self.command = list(command)
        merged = dict(os.environ)
        merged.update(env or {})
        # Line buffering on the child's side keeps a frame from sitting in a pipe buffer.
        merged.setdefault("PYTHONUNBUFFERED", "1")
        try:
            self._proc = subprocess.Popen(
                self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=merged, cwd=cwd, bufsize=0)
        except OSError as exc:
            raise TransportError(f"could not start {self.command[0]!r}: {exc}") from None
        self.stderr_text = ""
        self._stderr_lock = threading.Lock()
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()

    def _drain_stderr(self) -> None:
        stream = self._proc.stderr
        if stream is None:  # pragma: no cover - always a pipe here
            return
        for chunk in iter(lambda: stream.readline(), b""):
            with self._stderr_lock:
                self.stderr_text += chunk.decode("utf-8", "replace")

    def _stderr_tail(self, limit: int = 2000) -> str:
        with self._stderr_lock:
            text = self.stderr_text
        return text[-limit:]

    def _write(self, payload: bytes) -> None:
        if self._proc.poll() is not None:
            raise TransportError(
                f"server exited with code {self._proc.returncode} before the request; "
                f"stderr: {self._stderr_tail()}")
        try:
            self._proc.stdin.write(payload + b"\n")   # type: ignore[union-attr]
            self._proc.stdin.flush()                  # type: ignore[union-attr]
        except (BrokenPipeError, OSError) as exc:
            raise TransportError(
                f"writing to the server failed: {exc}; stderr: {self._stderr_tail()}") from None

    def _read_line(self, timeout: float) -> bytes:
        """Read one frame, honouring a wall-clock deadline.

        `readline` on a pipe blocks indefinitely, which would hang the whole run on a server
        that accepts a request and never answers -- a plausible thing for a broken target to
        do, so it is handled rather than assumed away.
        """
        stdout = self._proc.stdout
        if stdout is None:  # pragma: no cover
            raise TransportError("server has no stdout")
        deadline = time.monotonic() + timeout
        selector = selectors.DefaultSelector()
        selector.register(stdout, selectors.EVENT_READ)
        buffer = bytearray()
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TransportError(
                        f"server did not answer within {timeout}s; "
                        f"stderr: {self._stderr_tail()}")
                if not selector.select(timeout=min(remaining, 0.25)):
                    if self._proc.poll() is not None and not buffer:
                        raise TransportError(
                            f"server exited with code {self._proc.returncode} without "
                            f"answering; stderr: {self._stderr_tail()}")
                    continue
                byte = stdout.read(1)
                if byte == b"":
                    raise TransportError(
                        f"server closed stdout mid-frame; stderr: {self._stderr_tail()}")
                if byte == b"\n":
                    return bytes(buffer)
                buffer.extend(byte)
        finally:
            selector.close()

    def request(self, message: Request, timeout: float) -> tuple[Response, WireObservation]:
        observation = WireObservation()
        self._write(encode_message(message))
        raw = self._read_line(timeout)
        observation.body_bytes = len(raw)
        decoded = decode_message(raw)
        if not isinstance(decoded, Response):
            raise ProtocolViolation(
                f"expected a response to {message.method!r}, got a "
                f"{type(decoded).__name__.lower()}")
        if decoded.id != message.id:
            raise ProtocolViolation(
                f"response id {decoded.id!r} does not match request id {message.id!r}")
        return decoded, observation

    def notify(self, message: Notification, timeout: float) -> WireObservation:
        self._write(encode_message(message))
        return WireObservation()

    def close(self) -> None:
        if self._proc.poll() is None:
            try:
                if self._proc.stdin is not None:
                    self._proc.stdin.close()
            except OSError:
                pass
            try:
                self._proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:  # pragma: no cover - a wedged child
                    self._proc.kill()
                    self._proc.wait(timeout=2.0)
        for stream in (self._proc.stdin, self._proc.stdout, self._proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:  # pragma: no cover
                pass


class HttpTransport(Transport):
    """Streamable HTTP: one JSON-RPC message per POST.

    `extra_headers` exists so a probe can send the headers a real attacker would -- a foreign
    `Origin`, no `Authorization` -- and record what the server did with them. That is the whole
    evidence base for M17 and M18, so it has to be the client's own observation.
    """

    name = "http"

    def __init__(self, url: str, extra_headers: dict[str, str] | None = None,
                 session_id: str | None = None):
        self.url = url
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https"):
            raise TransportError(f"unsupported scheme {parsed.scheme!r}")
        self._host = parsed.hostname or "127.0.0.1"
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self._path = parsed.path or "/"
        if parsed.query:
            self._path += "?" + parsed.query
        self._https = parsed.scheme == "https"
        self.extra_headers = dict(extra_headers or {})
        self.session_id = session_id

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            # The spec requires a client to accept both, because a server may answer a single
            # POST with either a JSON body or an SSE stream.
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        headers.update(self.extra_headers)
        return headers

    def _post(self, payload: bytes, timeout: float) -> WireObservation:
        headers = self._headers()
        observation = WireObservation(request_headers=dict(headers))
        cls = http.client.HTTPSConnection if self._https else http.client.HTTPConnection
        connection = cls(self._host, self._port, timeout=timeout)
        try:
            connection.request("POST", self._path, body=payload, headers=headers)
            response = connection.getresponse()
            observation.status = response.status
            observation.reason = response.reason
            observation.response_headers = {k.lower(): v for k, v in response.getheaders()}
            observation.raw_body = response.read()          # type: ignore[attr-defined]
            observation.body_bytes = len(observation.raw_body)  # type: ignore[attr-defined]
            new_session = observation.response_headers.get("mcp-session-id")
            if new_session:
                self.session_id = new_session
        except (OSError, http.client.HTTPException) as exc:
            raise TransportError(f"POST {self.url} failed: {exc}") from None
        finally:
            connection.close()
        return observation

    def request(self, message: Request, timeout: float) -> tuple[Response, WireObservation]:
        observation = self._post(encode_message(message), timeout)
        body: bytes = getattr(observation, "raw_body", b"")
        if observation.status is None or observation.status >= 400:
            # A refusal is a real answer -- it is exactly what a server that checks Origin or
            # requires credentials does -- so it is returned, not raised.
            observation.error = f"HTTP {observation.status} {observation.reason}"
            return Response(id=message.id,
                            error=JsonRpcError(-32000, observation.error,
                                               body[:512].decode("utf-8", "replace"))), observation
        content_type = observation.response_headers.get("content-type", "")
        if content_type.startswith("text/event-stream"):
            body = _first_sse_data(body)
        decoded = decode_message(body)
        if not isinstance(decoded, Response):
            raise ProtocolViolation(
                f"expected a response to {message.method!r}, got a "
                f"{type(decoded).__name__.lower()}")
        if decoded.id != message.id:
            raise ProtocolViolation(
                f"response id {decoded.id!r} does not match request id {message.id!r}")
        return decoded, observation

    def notify(self, message: Notification, timeout: float) -> WireObservation:
        return self._post(encode_message(message), timeout)

    def close(self) -> None:
        return None


def _first_sse_data(body: bytes) -> bytes:
    """Pull the first `data:` payload out of an SSE stream.

    A Streamable HTTP server may answer a single request with an event stream carrying one
    message. Reassembling multi-line data fields matters: a JSON body split across two `data:`
    lines is concatenated with newlines per the SSE spec, and treating only the first line as
    the message would silently truncate it.
    """
    lines: list[str] = []
    for raw_line in body.decode("utf-8", "replace").splitlines():
        if raw_line.startswith("data:"):
            lines.append(raw_line[5:].lstrip())
        elif not raw_line and lines:
            break
    if not lines:
        raise ProtocolViolation("event stream carried no data field")
    return "\n".join(lines).encode("utf-8")


@dataclass
class ToolDescriptor:
    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description,
                "inputSchema": self.input_schema}


class MCPClient:
    """The protocol layer: handshake, discovery, invocation.

    One client instance is one MCP session. `initialize` must precede everything else, and this
    class enforces that rather than trusting the caller, because a server that answers
    `tools/list` *before* initialization is itself a finding worth recording honestly.
    """

    def __init__(self, transport: Transport, timeout: float = 10.0):
        self.transport = transport
        self.timeout = timeout
        self._next_id = 0
        self.initialized = False
        self.protocol_version: str | None = None
        self.server_info: dict[str, Any] = {}
        self.server_capabilities: dict[str, Any] = {}
        #: Every wire observation, in order. The adapter reads this to report protocol facts.
        self.wire_log: list[dict[str, Any]] = []

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        request = Request(method=method, params=params or {}, id=self._id())
        response, observation = self.transport.request(request, self.timeout)
        self.wire_log.append({"method": method, **observation.to_json()})
        return response.raise_for_error()

    def initialize(self) -> dict[str, Any]:
        """Perform the real handshake and negotiate a protocol version.

        A server answering with a version this client does not know is a hard failure rather
        than something to paper over: continuing would mean guessing at semantics, and a guess
        recorded as an observation is the thing this repository exists not to do.
        """
        result = self._call("initialize", {
            "protocolVersion": SUPPORTED_PROTOCOL_VERSIONS[0],
            "capabilities": {"roots": {"listChanged": False}, "sampling": {}},
            "clientInfo": dict(CLIENT_INFO),
        })
        if not isinstance(result, dict):
            raise ProtocolViolation("initialize result is not an object")
        version = result.get("protocolVersion")
        if version not in SUPPORTED_PROTOCOL_VERSIONS:
            raise ProtocolViolation(
                f"server negotiated protocol version {version!r}, which this client does not "
                f"support (knows {list(SUPPORTED_PROTOCOL_VERSIONS)})")
        self.protocol_version = version
        self.server_info = result.get("serverInfo") or {}
        self.server_capabilities = result.get("capabilities") or {}
        self.transport.notify(Notification("notifications/initialized"), self.timeout)
        self.initialized = True
        return result

    def list_tools(self, require_initialized: bool = True) -> list[ToolDescriptor]:
        if require_initialized and not self.initialized:
            raise ProtocolViolation("tools/list before initialize")
        result = self._call("tools/list")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            raise ProtocolViolation("tools/list result must be an object with a tools array")
        tools = []
        for entry in result["tools"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                raise ProtocolViolation("each tool must be an object with a name")
            tools.append(ToolDescriptor(name=entry["name"],
                                        description=entry.get("description") or "",
                                        input_schema=entry.get("inputSchema") or {}))
        return tools

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.initialized:
            raise ProtocolViolation("tools/call before initialize")
        result = self._call("tools/call", {"name": name, "arguments": arguments or {}})
        if not isinstance(result, dict):
            raise ProtocolViolation("tools/call result is not an object")
        return result

    def close(self) -> None:
        self.transport.close()

    def __enter__(self) -> "MCPClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def text_of(tool_result: dict[str, Any]) -> str:
    """Flatten an MCP tool result's content blocks to text.

    Only `text` blocks are joined. An image block's data is deliberately *not* stringified into
    the egress channel: doing so would let base64 image bytes count as a text leak and inflate
    the canary oracle.
    """
    blocks = tool_result.get("content")
    if not isinstance(blocks, list):
        return ""
    out = []
    for block in blocks:
        if isinstance(block, dict) and block.get("type") == "text":
            out.append(str(block.get("text", "")))
    return "\n".join(out)


def stdio_server_command(module: str, *args: str) -> list[str]:
    """The command that runs one of this repository's reference servers over stdio."""
    return [sys.executable, "-u", "-m", module, *args]


def terminate_quietly(proc: subprocess.Popen) -> None:  # pragma: no cover - cleanup helper
    if proc.poll() is not None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2.0)


__all__ = ["MCPClient", "StdioTransport", "HttpTransport", "Transport", "TransportError",
           "ToolDescriptor", "WireObservation", "text_of", "stdio_server_command",
           "terminate_quietly", "json"]
