"""Standalone verifier tests, standard library + pytest only, no scoring engine."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import assay_verifier as V  # noqa: E402

MANIFESTS = ROOT / "leaderboard" / "manifests"


@pytest.mark.parametrize("name", ["reference_vulnerable.json", "reference_hardened.json"])
def test_shipped_scorecards_verify(name):
    out = V.verify_manifest(json.loads((MANIFESTS / name).read_text()))
    assert out["verdict"] == "VERIFIED" and out["confirmed"] == out["canary_findings"]


def test_triple_proves_real_and_rejects_forgery():
    observed = "sk-LEAK" + V.digest("cd" * 32, "o|t|0") + "END"
    assert V.verify_triple("cd" * 32, "o", "t", 0, observed)
    assert not V.verify_triple("00" * 32, "o", "t", 0, observed)


def test_commitment_binds_the_secret():
    m = json.loads((MANIFESTS / "reference_vulnerable.json").read_text())
    assert V.commitment(m["run_secret_reveal"]) == m["run_secret_commitment"]
    m["run_secret_reveal"] = "ff" * 32
    with pytest.raises(AssertionError):
        V.verify_manifest(m)


def test_tampered_canary_is_rejected():
    m = json.loads((MANIFESTS / "reference_vulnerable.json").read_text())
    fired = next(f for f in m["findings"] if f.get("canary"))
    fired["canary"]["observed"] = "sk-WRONGdeadbeefdeadbeefEND"
    with pytest.raises(AssertionError):
        V.verify_manifest(m)


def test_forged_score_is_rejected():
    m = {"benchmark": "Assay", "version": "0.1", "track": "agent",
         "target": {"kind": "forged", "model_snapshot": None, "note": "x"}, "target_fingerprint": "x",
         "trials_per_task": 25, "generated_at": "2026-01-01T00:00:00+00:00",
         "harness": {"engine": "x", "assay_version": "0.1"},
         "agent_resistance_score": 100.0, "server_posture_score": None, "over_refusal_rate": None,
         "findings": [], "run_secret_reveal": "ab" * 32}
    m["run_secret_commitment"] = V.commitment("ab" * 32)
    m["integrity_hash"] = V.integrity_hash(m)
    with pytest.raises(AssertionError):          # score 100 with empty findings must not verify
        V.verify_manifest(m)


def test_fired_canary_with_zero_asr_is_rejected():
    # A real canary proof shipped with asr 0 would recompute resistance to 100, this closes it.
    m = json.loads((MANIFESTS / "reference_vulnerable.json").read_text())
    fired = next(f for f in m["findings"] if f.get("canary"))
    fired["asr"] = 0.0
    m["integrity_hash"] = V.integrity_hash(m)
    with pytest.raises(AssertionError):
        V.verify_manifest(m)


def test_canary_relabelled_to_dodge_proof_is_rejected():
    # oracle stays "canary" but evidence_type flips, the proof gate keys on oracle, not the label.
    m = json.loads((MANIFESTS / "reference_vulnerable.json").read_text())
    fired = next(f for f in m["findings"] if f.get("canary"))
    fired["evidence_type"] = "behavioral"
    m["integrity_hash"] = V.integrity_hash(m)
    with pytest.raises(AssertionError):
        V.verify_manifest(m)
