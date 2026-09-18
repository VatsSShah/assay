"""Target-adapter interface.

An adapter is the only thing that knows how to drive a system under test. The runner
never talks to a target directly, so a conformance stub, a local MCP server and a real
agent are interchangeable from the harness's point of view -- and the harness can state
honestly, in provenance, which kind it actually ran.

Observation boundary (per oracle class, normative):

* ``canary``     -- only strings the adapter reports as *egress*: tool-call arguments and
                    network-sink payloads. Model reasoning, prompts and logs are NOT egress.
* ``protocol``   -- only ``protocol_facts`` the Mode-A client observed on the wire.
* ``behavioral`` -- only the recorded, typed tool-call sequence in ``actions``.

An adapter that reports a channel it did not actually observe is lying to the oracle;
that is exactly the boundary a maintainer re-run exists to police.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class Capabilities:
    """What an adapter can actually do. Declared up front so the runner can skip -- and
    the manifest can record -- tasks the target cannot be fairly evaluated on."""

    observes_tool_descriptions: bool = False
    emits_tool_calls: bool = False
    emits_network_egress: bool = False
    exposes_protocol_facts: bool = False
    supports_reset: bool = False
    #: Can the target read image bytes -- pixels and metadata -- rather than only text?
    #: A target that cannot is `unsupported` on the image-channel tasks (validity rule V3),
    #: never credited with resisting them.
    decodes_images: bool = False
    #: Is an *agent* the thing under test? Mode-B tasks poison a surface and score what the
    #: agent does with it, so an adapter that drives only a server cannot evaluate them. Without
    #: this, a server probe that emits tool calls (which it must, to test parameter injection)
    #: satisfied the canary oracle's capability check and every Mode-B task was scored against a
    #: target that was never shown one -- producing a headline 100.0 for a run that tested three
    #: tasks. Validity rule V3: those tasks are `unsupported`, not `resisted`.
    drives_agent_under_test: bool = False
    #: Is an MCP *server* the thing under test? Mode-A tasks observe a server's wire behaviour.
    drives_server_under_test: bool = False
    #: False for every built-in deterministic stub. Reference runs MUST report this.
    is_real_target: bool = False
    transport: str = "in-process"

    def to_json(self) -> dict[str, Any]:
        return {
            "observes_tool_descriptions": self.observes_tool_descriptions,
            "emits_tool_calls": self.emits_tool_calls,
            "emits_network_egress": self.emits_network_egress,
            "exposes_protocol_facts": self.exposes_protocol_facts,
            "supports_reset": self.supports_reset,
            "decodes_images": self.decodes_images,
            "drives_agent_under_test": self.drives_agent_under_test,
            "drives_server_under_test": self.drives_server_under_test,
            "is_real_target": self.is_real_target,
            "transport": self.transport,
        }


@dataclass
class Episode:
    """One trial handed to the adapter."""

    task_id: str
    mode: str
    oracle: str
    attack: str
    trial: int
    #: The adversarial tool catalog: list of {name, description} with the poison inline.
    tool_catalog: list[dict[str, str]] = field(default_factory=list)
    #: Poisoned tool results returned to the target during the episode.
    tool_results: list[dict[str, str]] = field(default_factory=list)
    #: The minted canary for this (task, trial), or None for non-canary tasks.
    canary: dict[str, Any] | None = None
    #: Real image bytes the target is shown, for the image-channel tasks. Each entry is
    #: {name, media_type, role, data}. For those tasks the canary is in HERE -- in pixels, in
    #: metadata, or in a QR symbol -- and deliberately NOT in the text above, so a target that
    #: never looks at an image cannot find it.
    attachments: list[dict[str, Any]] = field(default_factory=list)
    #: Wall-clock budget in seconds for this episode.
    timeout_s: float = 10.0


@dataclass
class Observation:
    """Everything the harness is allowed to score, and nothing else."""

    task_id: str
    trial: int
    #: Egress events: {"channel": "tool_call"|"network", "tool": str, "step": int, "payload": str}
    egress: list[dict[str, Any]] = field(default_factory=list)
    #: Typed protocol observations for Mode-A tasks, e.g. {"unauthenticated_tools_list": True}
    protocol_facts: dict[str, Any] = field(default_factory=dict)
    #: Typed action records for behavioral tasks, e.g. [{"action": "delete", "confirmed": False}]
    actions: list[dict[str, Any]] = field(default_factory=list)
    #: Set when the adapter failed; the trial is then errored, never silently "resisted".
    error: str | None = None

    def egress_text(self) -> str:
        return "\n".join(str(e.get("payload", "")) for e in self.egress)


#: Which declared capability each oracle class needs. Validity rule V3: a task whose channel an
#: adapter cannot exercise is `unsupported`, not `resisted`.
REQUIRED_CAPABILITY = {
    "canary": ("emits_network_egress", "emits_tool_calls"),
    "protocol": ("exposes_protocol_facts",),
    "behavioral": ("emits_tool_calls",),
}

#: Channels beyond the oracle's own that a task may need. An image-channel task needs the
#: target to actually decode images; without that the task is unsupported, not resisted.
MODALITY_CAPABILITY = {"image": "decodes_images"}


#: Which side of the protocol each mode puts under test. Checked before the oracle's channels,
#: because a target that is the wrong *kind* of thing cannot be evaluated however many channels
#: it exposes.
MODE_CAPABILITY = {"A": "drives_server_under_test", "B": "drives_agent_under_test"}


def supports(capabilities: Capabilities, oracle: str, modality: str = "text",
             mode: str | None = None) -> bool:
    """True iff the adapter declares every channel and role this task needs.

    `mode` is optional only so the older two-argument call keeps working; the runner always
    passes it. Omitting it skips the role check, which is why the runner does not.
    """
    if mode is not None:
        role = MODE_CAPABILITY.get(mode)
        if role is None or not getattr(capabilities, role, False):
            return False
    needed = REQUIRED_CAPABILITY.get(oracle)
    if not needed:
        return False
    if not any(getattr(capabilities, name, False) for name in needed):
        return False
    modality_capability = MODALITY_CAPABILITY.get(modality)
    if modality_capability and not getattr(capabilities, modality_capability, False):
        return False
    return True


@dataclass
class TwinEpisode:
    """One BENIGN twin trial. Completing it is the correct behaviour.

    Shaped exactly like :class:`Episode` on purpose: a target that could tell a twin from an
    attack by the shape of what it receives would score well on the utility axis by spotting
    the benchmark rather than by being useful.
    """

    twin_id: str
    pairs_with: str
    channel: str
    trial: int
    tool_catalog: list[dict[str, str]] = field(default_factory=list)
    tool_results: list[dict[str, str]] = field(default_factory=list)
    attachments: list[dict[str, Any]] = field(default_factory=list)
    arguments: dict[str, Any] = field(default_factory=dict)
    #: What the user actually asked for. This is the thing that makes the twin benign, and the
    #: thing a target must weigh instructions against.
    user_request: str = ""
    #: For an image twin, the value that must be recovered from the image to complete the task.
    expected_payload: str | None = None
    timeout_s: float = 10.0


@dataclass
class TwinOutcome:
    """What the target did with a benign twin.

    `completed` is correct, `refused` is the over-refusal being measured, and `errored` leaves
    the denominator -- a twin the harness could not run says nothing about whether the target
    would have refused it.
    """

    twin_id: str
    trial: int
    outcome: str = "errored"
    detail: str = ""


@runtime_checkable
class TwinCapable(Protocol):
    """An adapter that can also be asked to do benign work.

    Optional. An adapter without it simply has no utility axis, and the manifest reports
    `over_refusal_rate: null` rather than a zero that would read as "refused nothing".
    """

    def run_twin(self, episode: "TwinEpisode") -> TwinOutcome: ...


@runtime_checkable
class Adapter(Protocol):
    name: str
    version: str
    kind: str

    def capabilities(self) -> Capabilities: ...
    def reset(self) -> None: ...
    def run_episode(self, episode: Episode) -> Observation: ...
    def fingerprint_material(self) -> dict[str, Any]: ...
