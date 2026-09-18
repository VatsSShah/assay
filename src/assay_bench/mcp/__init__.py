"""A real Model Context Protocol implementation: JSON-RPC 2.0 over stdio and Streamable HTTP.

This exists to close the largest gap in the repository. Before it, the only adapters were
in-process conformance stubs, so every number was a property of the harness talking to itself.
Nothing crossed a process boundary, spoke a wire protocol, or could be pointed at software the
harness did not import.

What is here is stdlib-only and deliberately small:

* :mod:`assay_bench.mcp.jsonrpc` -- JSON-RPC 2.0 request/response/notification framing, the
  error taxonomy, and the two MCP transports' message delimiting rules.
* :mod:`assay_bench.mcp.client` -- an MCP client that performs the real `initialize` handshake,
  negotiates a protocol version, lists tools and calls them, over either transport.
* :mod:`assay_bench.mcp.server` -- a minimal MCP server framework, used by the deliberately
  insecure and hardened reference servers in ``corpus/servers/``.

**What this does and does not establish.** It establishes that the harness speaks MCP over a
real transport to a real separate process, and that the Mode-A protocol facts it reports were
observed on a wire rather than declared by a stub. It does *not* establish that any published
number measures third-party software: the reference servers are shipped by this repository.
A run against someone else's server is a real measurement of that server; a run against ours is
still mechanism validation, and `provenance.target.kind` says which.

Interoperability with the official MCP SDK is checked separately and optionally in
``tests/test_mcp_interop.py``: when the `mcp` package is installed, the suite stands this
client up against a server built with it, so "we speak MCP" is not a claim resting on our own
server agreeing with our own client. That test skips when the package is absent, and its
skipping is itself reported rather than hidden.
"""

from __future__ import annotations

from .jsonrpc import (JsonRpcError, Notification, Request, Response, decode_message,
                      encode_message)

#: The MCP revisions this client can negotiate, newest first. `initialize` offers the newest
#: and accepts whatever the server answers with, provided it is one of these.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

#: What this client advertises about itself in `initialize`.
CLIENT_INFO = {"name": "assay-bench", "version": "0.2.0"}

__all__ = [
    "SUPPORTED_PROTOCOL_VERSIONS",
    "CLIENT_INFO",
    "JsonRpcError",
    "Notification",
    "Request",
    "Response",
    "decode_message",
    "encode_message",
]
