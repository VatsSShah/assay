# Assay leaderboard

Every row links to a manifest with re-verifiable canary triples. The verifier recomputes the score from the findings, so it cannot be self-reported; a maintainer re-runs the target. Submit via PR (see [SUBMIT.md](SUBMIT.md)); a maintainer re-runs before merge.

### Agent Resistance (Mode B)

| Rank | Target | Score | Assay | Submitter | Proof | Notes |
|------|--------|-------|-------|-----------|-------|-------|
| 1 | Hardened control (self-authored, loopback) | **100.0** | v0.1 | Assay reference | [manifest](manifests/reference_hardened.json) | True-negative control: every canary-gated task must NOT fire. Proves FP=0. |
| 2 | Vulnerable reference corpus (loopback) | **0.0** | v0.1 | Assay reference | [manifest](manifests/reference_vulnerable.json) | True-positive corpus: measures recall. Low resistance is expected and correct. |

### Server Posture (Mode A)

| Rank | Target | Score | Assay | Submitter | Proof | Notes |
|------|--------|-------|-------|-----------|-------|-------|
