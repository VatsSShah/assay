"""Render COVERAGE.md, every frozen task mapped to the recognised MCP taxonomies.

Reads the frozen tasks.json (the baked-in, already-verified crosswalk) and writes a
skimmable matrix. Stdlib only; run ``python coverage.py``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

HERE = Path(__file__).parent
TASKS = json.loads((HERE / "tasks.json").read_text())["tasks"]

# (crosswalk key, column header, how to shorten an entry to its leading id)
COLUMNS = [
    ("owasp_mcp_top10", "OWASP MCP", lambda e: e.split(":")[0]),
    ("adversa_mcp_top25", "Adversa-25", lambda e: (m.group() if (m := re.search(r"#\d+", e)) else e)),
    ("owasp_agentic_asi", "OWASP ASI", lambda e: e.split(":")[0]),
    ("mitre_atlas", "MITRE ATLAS", lambda e: e.split(" ")[0]),
]


def _cell(crosswalk: dict, key: str, shorten) -> str:
    entries = crosswalk.get(key, [])
    return ", ".join(shorten(e) for e in entries) if entries else "-"


def _modality(task: dict) -> str:
    """Declared channel, and -- when they differ -- what the runner actually exercises."""
    execution = task.get("execution") or {}
    declared = execution.get("declared_modality", "text")
    implemented = execution.get("implemented_modality", "text")
    if implemented == "text_simulation":
        return f"{declared} (**text sim**)"
    return declared


def build() -> str:
    header = ("| ID | Task | Mode | Oracle | Channel | Modality | "
              + " | ".join(c[1] for c in COLUMNS) + " |")
    rule = "|----|------|------|--------|---------|----------|" + "|".join(["------"] * len(COLUMNS)) + "|"
    rows = [header, rule]
    for t in TASKS:
        cells = [_cell(t["crosswalk"], key, fn) for key, _, fn in COLUMNS]
        execution = t.get("execution") or {}
        rows.append(f"| {t['id']} | {t['title']} | {t['mode']} | {t['oracle']} | "
                    f"`{execution.get('channel', 'tool-call')}` | {_modality(t)} | "
                    + " | ".join(cells) + " |")
    return (
        "# Assay coverage matrix\n\n"
        f"{len(TASKS)} frozen tasks. Mode A = MCP server under test; Mode B = agent under test.\n\n"
        "**Oracle column.** `canary` means a hit is decided by recomputing an HMAC digest "
        "rather than by a grader, so a *spurious* hit would require forging a 64-bit tag "
        "without the run secret (SPEC.md §4). It does not mean the task has no false "
        "*negatives*: egress that splits, re-encodes outside the four frozen forms, "
        "compresses, encrypts or paraphrases the digest is missed, and those blind spots are "
        "measured in `audit/CLAIM_EVIDENCE_MATRIX.md`. `protocol` and `behavioral` tasks are "
        "deterministic but carry no cryptographic guarantee at all, and the headline scores "
        "aggregate all three classes.\n\n"
        "**Modality column.** `text` means the runner exercises the task's own channel. "
        "**`text sim`** means the task *describes* a non-text channel but the shipped runner "
        "exercises it as text: no pixel, audio or document decoding path exists in this "
        "repository, and `TASKS.md` states for each of these tasks that the image is a "
        "placeholder and the directive rides the accompanying text. Six tasks are in that "
        "state. Treat them as text-channel tasks until a real modality path ships.\n\n"
        "Mappings are rendered from the crosswalk in `tasks.json`; no id is hand-copied into "
        "this file. They are our reading of each taxonomy, not an endorsement by its "
        "publisher.\n\n"
        + "\n".join(rows) + "\n"
    )


if __name__ == "__main__":
    out = HERE / "COVERAGE.md"
    out.write_text(build())
    print(f"wrote {out}: {len(TASKS)} tasks")
