"""Assay benchmark runner: the open harness that mints canaries, drives a target
through the frozen task set, evaluates the three oracle classes, and emits a
scorecard manifest that ``assay_verifier`` accepts.

Nothing in this package requires a third-party dependency. What it can and cannot
establish is documented in ``SPEC.md`` §3-§4 and ``audit/CLAIM_EVIDENCE_MATRIX.md``;
in particular a conformance run against the built-in deterministic targets is
*mechanism validation*, never a measurement of a real product.
"""

from __future__ import annotations

__all__ = ["BENCHMARK", "RUNNER_VERSION", "SUPPORTED_MANIFEST_VERSIONS"]

BENCHMARK = "Assay"

#: Version of this harness implementation (independent of the frozen task-set version).
RUNNER_VERSION = "0.2.0"

#: Manifest/benchmark versions this tree can produce and verify. See SPEC.md §9.
SUPPORTED_MANIFEST_VERSIONS = ("0.1", "0.2")
