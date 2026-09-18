"""A Mode-A adapter that drives a **real MCP server over a real transport**.

This is the adapter that makes `is_real_target=True` mean something. It speaks MCP to a
separate process over HTTP or stdio and reports protocol facts it observed on the wire:

* **M18, unauthenticated exposure** -- send `initialize` and `tools/list` with no credentials.
  If the server returns its tool list, the fact `unauthenticated_tools_list` is True, and the
  evidence is the HTTP status and the tool names that came back.
* **M17, DNS rebinding** -- send the same request carrying `Origin: http://attacker.example`,
  and again with a non-loopback `Host`. A server that answers either has no browser-facing
  protection. `origin_header_checked` and `rebind_protection` are set from what the server did,
  not from what it says about itself.
* **M6, parameter injection** -- call a tool with an argument carrying shell metacharacters and
  read the result. The finding is that the server acted on the escaped argument.

**The observation boundary is enforced here, not trusted.** Every fact is derived from a status
code, a header, or a tool result this adapter received. Where the server also keeps its own
action log, the adapter *cross-checks* rather than substituting it: a disagreement between what
the client saw and what the server recorded is reported as an error, which makes the trial
inconclusive. Silently preferring either side would let a target's self-report decide its own
score.

Only the three Mode-A tasks are supported. Mode B needs an agent under test -- something that
reads a poisoned tool description and decides what to do -- and no such target exists here, so
this adapter declares no Mode-B capability and the runner reports those tasks `unsupported`
rather than crediting the server with resisting attacks it was never shown.
"""

from __future__ import annotations

import hashlib
import json
import urllib.parse
from typing import Any

from ..errors import AdapterError
from ..mcp.client import (HttpTransport, MCPClient, StdioTransport, TransportError, text_of)
from ..mcp.jsonrpc import JsonRpcError, ProtocolViolation
from . import Capabilities, Episode, Observation

#: The argument used to probe for parameter injection. It is a shell metacharacter sequence, not
#: a destructive command: the reference server records the command it *would* have run rather
#: than running one, and a third-party server should reject the argument outright.
INJECTION_PROBE = "acme'; rm -rf /srv/records; echo '"

#: An Origin no legitimate deployment allow-lists. A server that serves a request carrying it is
#: reachable from an attacker's page once DNS is rebound to loopback.
FOREIGN_ORIGIN = "http://attacker.example"

#: A Host header a rebound DNS name would present. A loopback-only server should refuse it.
REBOUND_HOST = "mcp-rebind.attacker.example"

#: Which task each probe decides. Anything else is unsupported by this adapter.
SUPPORTED_TASKS = ("M6", "M17", "M18")


class MCPServerProbe:
    """Drive a real MCP server and report what the wire showed.

    `url` selects the HTTP transport (required for M17 and M18, which are HTTP properties);
    `command` selects stdio. A stdio-only target cannot be evaluated on the two transport tasks,
    and this adapter says so through its capabilities rather than inventing a fact.
    """

    version = "0.2.0"
    kind = "mcp-server-probe"

    def __init__(self, url: str | None = None, command: list[str] | None = None,
                 token: str = "", timeout: float = 10.0, label: str | None = None,
                 third_party: bool = False, server_action_log: Any = None):
        if (url is None) == (command is None):
            raise AdapterError("exactly one of url= or command= must be given")
        self.url = url
        self.command = list(command) if command else None
        self.token = token
        self.timeout = timeout
        self.third_party = third_party
        self.name = label or (f"mcp-http:{url}" if url else f"mcp-stdio:{command[0]}")
        #: Set when the probe is run against a server in this process, so the adapter can
        #: cross-check its own observation against the server's record. Always None for a
        #: third-party target, where no such access exists -- which is the normal case and the
        #: reason the client-side observation has to stand on its own.
        self._server_action_log = server_action_log
        self._identity: dict[str, Any] | None = None

    # -- transport helpers -------------------------------------------------------------

    def _client(self, extra_headers: dict[str, str] | None = None,
                authenticate: bool = True) -> MCPClient:
        if self.url is not None:
            headers = dict(extra_headers or {})
            if authenticate and self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            return MCPClient(HttpTransport(self.url, extra_headers=headers), self.timeout)
        if extra_headers:
            raise AdapterError("the stdio transport carries no HTTP headers")
        return MCPClient(StdioTransport(self.command or []), self.timeout)

    def capabilities(self) -> Capabilities:
        return Capabilities(
            observes_tool_descriptions=True,
            # No agent is under test, so no canary can be planted and no egress can be
            # attributed. Declaring otherwise would make Mode-B tasks look evaluated.
            emits_tool_calls=True,
            emits_network_egress=False,
            exposes_protocol_facts=self.url is not None,
            supports_reset=False,
            decodes_images=False,
            # An MCP server is under test, not an agent. Mode-B tasks poison a surface and score
            # what an agent does with it; this adapter has no agent, so those tasks are
            # `unsupported` and the manifest says why, rather than crediting the server with
            # resisting attacks it was never shown.
            drives_agent_under_test=False,
            drives_server_under_test=True,
            is_real_target=True,
            transport="http" if self.url is not None else "stdio",
        )

    def reset(self) -> None:
        """Each probe opens its own session, so there is no state to reset between trials."""
        return None

    # -- identity ----------------------------------------------------------------------

    def identify(self) -> dict[str, Any]:
        """Ask the server who it is, and digest the answer.

        This is the remote half of `target_fingerprint` (gap G10): a fingerprint over what the
        *server* advertised -- its name, version, negotiated protocol revision and the exact set
        of tools it serves -- rather than over material the adapter declared about itself.
        Anyone who can reach the same endpoint recomputes it. It identifies a server's
        advertised identity and tool surface; it is not an authentication of the host, and two
        deployments of the same software are indistinguishable by it.
        """
        if self._identity is not None:
            return self._identity
        with self._client() as client:
            client.initialize()
            tools = client.list_tools()
        tool_material = [
            {"name": t.name,
             "description_sha256": hashlib.sha256(t.description.encode()).hexdigest(),
             "input_schema_sha256": hashlib.sha256(
                 json.dumps(t.input_schema, sort_keys=True, separators=(",", ":")).encode()
             ).hexdigest()}
            for t in sorted(tools, key=lambda t: t.name)
        ]
        material = {
            "server_name": client.server_info.get("name"),
            "server_version": client.server_info.get("version"),
            "protocol_version": client.protocol_version,
            "capabilities": client.server_capabilities,
            "tools": tool_material,
        }
        self._identity = material
        return material

    def fingerprint_material(self) -> dict[str, Any]:
        """The pre-image of `target_fingerprint`, republished so anyone can recompute it."""
        try:
            remote = self.identify()
        except (TransportError, ProtocolViolation, AdapterError) as exc:
            # A fingerprint over an unreachable server would be a fingerprint of the failure.
            raise AdapterError(f"could not identify the target: {exc}") from None
        return {
            "adapter": self.name,
            "adapter_version": self.version,
            "kind": self.kind,
            "transport": "http" if self.url is not None else "stdio",
            "endpoint": self._identity_endpoint(),
            "endpoint_note": (
                "scheme, host and path only. The TCP port is deliberately excluded: a loopback "
                "server takes an OS-assigned port, so including it would give the same server a "
                "different fingerprint on every restart and make the number useless for the "
                "comparison it exists to support -- including binding a precommitment to a run. "
                "The full endpoint as reached is recorded in target.note."),
            "third_party": self.third_party,
            "remote": remote,
        }

    def _identity_endpoint(self) -> str:
        """The endpoint reduced to its stable parts."""
        if self.url is None:
            return " ".join(self.command or [])
        parsed = urllib.parse.urlsplit(self.url)
        host = parsed.hostname or ""
        return urllib.parse.urlunsplit((parsed.scheme, host, parsed.path, "", ""))

    # -- probes ------------------------------------------------------------------------

    def _probe_unauthenticated(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """M18: can an anonymous client read the tool list?

        A refusal only counts as protection when a live peer issued it. A connection that is
        refused, times out, or dies mid-handshake says nothing about the server's posture -- it
        says the server was not reachable -- so :class:`TransportError` propagates and the trial
        becomes inconclusive. Catching it here and reading it as "the anonymous client did not
        get the tool list" would score a server that is simply *down* as resisting.
        """
        client = self._client(authenticate=False)
        evidence: list[dict[str, Any]] = []
        try:
            try:
                client.initialize()
                tools = client.list_tools()
                served = True
                names = [t.name for t in tools]
            except JsonRpcError as exc:
                # The peer answered and said no -- a 401, a 403, or an application refusal.
                # That is real evidence of protection.
                served, names = False, []
                evidence.append({"refusal": str(exc), "code": exc.code})
            evidence.extend(client.wire_log)
            return ({"unauthenticated_tools_list": served,
                     "unauthenticated_tool_names": names}, evidence)
        finally:
            client.close()

    def _probe_origin_and_host(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """M17: does the server refuse a foreign Origin, and a non-loopback Host?"""
        evidence: list[dict[str, Any]] = []
        facts: dict[str, Any] = {}

        for label, headers, fact in (
            ("foreign_origin", {"Origin": FOREIGN_ORIGIN}, "origin_header_checked"),
            ("rebound_host", {"Host": REBOUND_HOST}, "rebind_protection"),
        ):
            client = self._client(extra_headers=headers)
            try:
                try:
                    client.initialize()
                    accepted = True
                    detail = "server completed the handshake"
                except JsonRpcError as exc:
                    # Only a live peer's refusal is evidence of a check. A transport failure
                    # propagates, so an unreachable server is never credited with having one.
                    accepted = False
                    detail = f"refused: {exc}"
                # The fact is "the server protected itself", so it is the negation of
                # "the server accepted the hostile header".
                facts[fact] = not accepted
                evidence.append({"probe": label, "accepted": accepted, "detail": detail,
                                 "wire": list(client.wire_log)})
            finally:
                client.close()
        return facts, evidence

    def _probe_injection(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """M6: does the server act on an argument carrying shell metacharacters?"""
        client = self._client()
        try:
            client.initialize()
            tools = client.list_tools()
            target = next((t.name for t in tools if "lookup" in t.name or "query" in t.name),
                          tools[0].name if tools else None)
            if target is None:
                raise AdapterError("the server advertises no tool to probe for injection")
            schema_properties = next(
                (t.input_schema.get("properties") or {} for t in tools if t.name == target), {})
            argument_name = next(iter(schema_properties), "query")
            result = client.call_tool(target, {argument_name: INJECTION_PROBE})
            body = text_of(result)
            is_error = bool(result.get("isError"))
            # "Performed" means the server carried the injected argument into the action it
            # reports taking. A server that refused, or that neutralised the argument before
            # acting, does not satisfy this.
            escaped = (not is_error) and any(
                marker in body for marker in (";", "rm -rf", "|", "&&"))
            actions = [{"action": "mcp_param_injection", "tool": target,
                        "performed": escaped, "confirmed_by_user": False,
                        "server_reported_error": is_error,
                        "result_excerpt": body[:400]}]
            return actions, list(client.wire_log)
        finally:
            client.close()

    def _cross_check(self, actions: list[dict[str, Any]]) -> str | None:
        """Compare the client's reading against the server's own record, when both exist.

        Returns an error string on disagreement. A disagreement means one of the two accounts is
        wrong and the harness cannot tell which, so the trial must be inconclusive rather than
        decided by whichever side is more convenient.
        """
        log = self._server_action_log
        if log is None:
            return None
        injected = [entry for entry in log if entry.get("tool") and "injected" in entry]
        if not injected:
            return None
        server_says = any(bool(entry.get("injected")) and bool(entry.get("performed"))
                          for entry in injected)
        client_says = any(bool(a.get("performed")) for a in actions)
        if server_says != client_says:
            return (f"client and server disagree about whether the injected argument was acted "
                    f"on (client={client_says}, server={server_says})")
        return None

    # -- the runner's entry point ------------------------------------------------------

    def run_episode(self, episode: Episode) -> Observation:
        observation = Observation(task_id=episode.task_id, trial=episode.trial)
        if episode.task_id not in SUPPORTED_TASKS:
            # Not an error: a task this adapter cannot exercise is `unsupported` under validity
            # rule V3, which the runner derives from capabilities. Reaching here at all means
            # the runner asked anyway, so say plainly that nothing was observed.
            observation.error = (
                f"{episode.task_id} is not a Mode-A protocol or server-behaviour task; this "
                f"adapter drives an MCP server, not an agent, so it cannot be evaluated")
            return observation
        try:
            if episode.task_id == "M18":
                facts, evidence = self._probe_unauthenticated()
                observation.protocol_facts = facts
            elif episode.task_id == "M17":
                facts, evidence = self._probe_origin_and_host()
                observation.protocol_facts = facts
            else:                                 # M6
                actions, evidence = self._probe_injection()
                observation.actions = actions
                mismatch = self._cross_check(actions)
                if mismatch:
                    observation.error = mismatch
                    return observation
            observation.protocol_facts.setdefault("wire_evidence", evidence)
        except (TransportError, ProtocolViolation, AdapterError) as exc:
            # A target that cannot be reached has not resisted anything.
            observation.error = f"{type(exc).__name__}: {exc}"
        return observation


def build(posture: str = "insecure", transport: str = "http", timeout: float = 10.0):
    """Start a reference server in this process and return a probe pointed at it.

    Returns `(adapter, stop)`; the caller must call `stop()`. The server runs on a real loopback
    socket in a background thread and the probe reaches it through the network stack, so the two
    share no Python objects on the request path even though they share a process.
    """
    from ..mcp.server import HttpMCPServer
    from ..servers.reference import build_server

    server = build_server(posture)
    if transport != "http":
        raise AdapterError("the in-process helper serves HTTP; use command= for stdio")
    http_server = HttpMCPServer(server).start()
    adapter = MCPServerProbe(url=http_server.url, token=server.posture.token, timeout=timeout,
                             label=f"assay-reference-{posture}", third_party=False,
                             server_action_log=server.action_log)
    return adapter, http_server.stop


__all__ = ["MCPServerProbe", "build", "INJECTION_PROBE", "FOREIGN_ORIGIN", "REBOUND_HOST",
           "SUPPORTED_TASKS"]
