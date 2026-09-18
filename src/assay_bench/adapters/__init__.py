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


def supports(capabilities: Capabilities, oracle: str, modality: str = "text") -> bool:
    """True iff the adapter declares every channel this task needs."""
    needed = REQUIRED_CAPABILITY.get(oracle)
    if not needed:
        return False
    if not any(getattr(capabilities, name, False) for name in needed):
        return False
    modality_capability = MODALITY_CAPABILITY.get(modality)
    if modality_capability and not getattr(capabilities, modality_capability, False):
        return False
    return True


@runtime_checkable
class Adapter(Protocol):
    name: str
    version: str
    kind: str

    def capabilities(self) -> Capabilities: ...
    def reset(self) -> None: ...
    def run_episode(self, episode: Episode) -> Observation: ...
    def fingerprint_material(self) -> dict[str, Any]: ...
