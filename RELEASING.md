# Releasing

Two steps in this file need credentials or network access that a sandboxed agent does not have,
and they are marked. Everything else is already automated and checked by CI.

## Version numbers move independently

| what | where | moves when |
|---|---|---|
| package version | `pyproject.toml` | the code changes |
| benchmark version | `tasks.json` `version` | the **frozen task set** changes — task ids, modes, oracle classes or weights |
| manifest format | `provenance.manifest_format` | the scorecard document shape grows |
| validity rules | `validity.rules_version` | the completeness rules change |

A package release does **not** move the benchmark line. v0.2.0 ships benchmark `0.1` unchanged,
which is why every valid v0.1 score is still comparable. See [SPEC.md](SPEC.md) §9.

## Before tagging

```bash
python -m unittest discover -s tests -t .
python -m assay_bench reference --check
git diff --exit-code
```

CI must be green, including the `mcp-interop` job — it fails if the check against the official
MCP SDK *skips*, because a green run with the one external check silently skipped is the kind of
green that means nothing.

## Tag

```bash
git tag -a v0.2.0 -m "..."      # see CHANGELOG.md for what belongs in the message
git push origin v0.2.0
```

> **Agent note.** Some sandboxed environments proxy git and accept branch pushes while rejecting
> tag refs and ref deletions (`send-pack: unexpected disconnect`, then a misleading
> `Everything up-to-date`). If that happens, the tag has **not** been created — check with
> `git ls-remote --tags origin` rather than trusting the exit code, and push the tag from a
> machine with direct access.

## Build and check

```bash
python -m build
python -m twine check --strict dist/*
```

Both must PASS. The distribution must carry no recordings; CI asserts that.

## Publish — NEEDS CREDENTIALS

```bash
python -m twine upload dist/*
```

Then **verify against the public index before claiming anything**:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://pypi.org/pypi/assay-bench/json   # expect 200
python -m venv /tmp/fresh && /tmp/fresh/bin/pip install assay-bench
/tmp/fresh/bin/assay --version
/tmp/fresh/bin/assay run --target vulnerable --trials 5 --out /tmp/sc.json
/tmp/fresh/bin/assay verify /tmp/sc.json --require run_complete
```

**Do not update any document to say the package is installable from PyPI until that fresh
install works.** Tests currently fail the build if a document claims it, and they should stay
that way until the claim is true.

### Two facts about the name, checked 2026-09-18

- `assay-bench` on PyPI: **404, unregistered.** The name is free.
- `assay` on PyPI: **200, taken** — an unrelated testing framework by another author. Anyone who
  installs the bare name expecting this benchmark gets someone else's code. No document here
  points at it and a test keeps it that way.

## Release notes

`CHANGELOG.md` is the source. A release note that omits the "what this still does not do"
section is not a release note for this project — the whole point of the v0.2.0 audit was that
the limits travel with the claims.
