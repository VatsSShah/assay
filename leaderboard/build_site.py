"""Build the leaderboard: re-verify every entry's manifest, then render the board.

What the verifier gate does: it recomputes each score from the findings and re-checks every
canary triple, so a row's number cannot disagree with the findings it claims to summarise,
and a manifest altered after sealing is rejected. An entry that fails aborts the build.

What the gate does NOT do, and why this page prints levels instead of a badge: verification
is a coherence property. It cannot show that a target ran, that the report is complete, or
that the commitment predated the run. Those are separate columns, sourced from separate
artifacts (``precommit/registry/`` and ``attest/``), and a blank column means "not
established" -- never "assumed".

Conformance rows (built-in deterministic stubs) are tabled apart from measurement rows so a
stub's 100.0 can never be read as a product result. Stdlib only; run ``python build_site.py``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent))
from assay_verifier import verify_manifest  # noqa: E402

sys.path.insert(0, str(HERE.parent))
from assay_bench import attest  # noqa: E402

SCORE_KEY = {"agent": "agent_resistance_score", "server": "server_posture_score"}
ATTEST_DIR = HERE.parent / "attest"

LEVEL_ABBREV = {
    "format_valid": "F",
    "internally_consistent": "I",
    "canary_correspondence_verified": "C",
    "catalog_bound": "B",
    "run_complete": "R",
}


def _row(entry: dict, attestations: dict) -> dict:
    manifest = json.loads((HERE / entry["manifest"]).read_text())
    # Raises on failure: a manifest that does not verify never reaches the board.
    result = verify_manifest(manifest, require=("internally_consistent",))
    provenance = manifest.get("provenance") or {}
    record = attestations.get(manifest["integrity_hash"])
    return {
        "target": entry["target_name"],
        "track": entry["track"],
        "class": entry["class"],
        "score": manifest[SCORE_KEY[entry["track"]]],
        "version": manifest["version"],
        "submitter": entry["submitter"],
        "date": entry["date"],
        "manifest": entry["manifest"],
        "notes": entry.get("notes", ""),
        "levels": "".join(LEVEL_ABBREV[lv] for lv in result["levels_verified"]
                          if lv in LEVEL_ABBREV),
        "real_target": provenance.get("target_is_real"),
        "precommitment": manifest.get("precommitment", {}).get("level") if isinstance(
            manifest.get("precommitment"), dict) else None,
        "attestation": record["status"] if record else None,
    }


def _table(rows: list[dict], track: str, klass: str) -> str:
    kind = "Agent Resistance" if track == "agent" else "Server Posture"
    picked = sorted([r for r in rows if r["track"] == track and r["class"] == klass],
                    key=lambda r: (-(r["score"] if r["score"] is not None else -1), r["target"]))
    heading = f"### {kind} (Mode {'B' if track == 'agent' else 'A'}) - {klass}"
    lines = [heading, ""]
    if not picked:
        lines.append(f"_No {klass} rows yet._")
        return "\n".join(lines)
    lines += ["| # | Target | Score | Assay | Levels | Precommit | Attested | Submitter | Manifest | Notes |",
              "|---|--------|-------|-------|--------|-----------|----------|-----------|----------|-------|"]
    for i, r in enumerate(picked, 1):
        lines.append(
            f"| {i} | {r['target']} | **{r['score']}** | v{r['version']} | `{r['levels']}` | "
            f"{r['precommitment'] or '-'} | {r['attestation'] or '-'} | {r['submitter']} | "
            f"[manifest]({r['manifest']}) | {r['notes']} |")
    return "\n".join(lines)


def build() -> str:
    entries = json.loads((HERE / "entries.json").read_text())
    attestations = attest.load_all(ATTEST_DIR)
    rows = [_row(e, attestations) for e in entries]
    return (
        "# Assay leaderboard\n\n"
        "Every row links to a manifest whose canary triples anyone can recompute. The build "
        "re-verifies each one and refuses to publish a row whose stated score disagrees with "
        "its own findings, or whose document was altered after sealing.\n\n"
        "**Read the Levels column, not the score alone.** Verification is a coherence "
        "property of a document, not evidence that a run happened:\n\n"
        "| code | level | what it establishes |\n"
        "|------|-------|---------------------|\n"
        "| `F` | format_valid | the document satisfies the manifest schema |\n"
        "| `I` | internally_consistent | commitment binds the reveal, integrity hash matches, "
        "scores equal what the findings imply |\n"
        "| `C` | canary_correspondence_verified | every fired canary's triple recomputes under "
        "the revealed secret |\n"
        "| `B` | catalog_bound | every finding is a frozen task, with the catalog's own mode, "
        "oracle and weight |\n"
        "| `R` | run_complete | all 31 frozen tasks reported, no errors or timeouts |\n\n"
        "**Precommit** and **Attested** are separate artifacts, not verifier output. "
        "`Precommit` records whether a commitment was registered before the run and how that "
        "ordering was established (see [`../precommit/`](../precommit/)). `Attested` records "
        "whether a maintainer independently reran the target (see [`../attest/`](../attest/)). "
        "A dash means *not established*, never *assumed*.\n\n"
        "A submitter who holds the run secret can synthesise a passing canary without running "
        "anything; that is why `C` is not an attestation and why the Attested column exists. "
        "See [SUBMIT.md](SUBMIT.md).\n\n"
        "## Conformance rows (built-in deterministic stubs)\n\n"
        "These validate the harness, not a product. They are tabled separately so a stub's "
        "100.0 is never mistaken for a measurement of a real system.\n\n"
        + _table(rows, "agent", "conformance") + "\n\n"
        + _table(rows, "server", "conformance") + "\n\n"
        "## Measurement rows (real targets)\n\n"
        + _table(rows, "agent", "measurement") + "\n\n"
        + _table(rows, "server", "measurement") + "\n"
    )


if __name__ == "__main__":
    out = HERE / "index.md"
    out.write_text(build())
    count = len(json.loads((HERE / "entries.json").read_text()))
    print(f"wrote {out}, {count} entries re-verified")
