"""Regenerate research/statistical-analysis.md from the committed spectrum scorecards.

    python research/generate_statistical_analysis.py            # rewrite the file
    python research/generate_statistical_analysis.py --check    # exit 1 if it is stale

Every number in the report comes from `assay_bench.analysis.analyze_paths` run over
demo/arsenal/spectrum/full_*.json. Nothing is typed in by hand: the limitations section below is
also derived from those files where it states a fact about them (trial counts, variants, run
counts, unsupported tasks, verification levels), and is fixed prose only where it states a
property of the method (what the canary oracle observes). Output is deterministic -- sorted
inputs, no timestamps -- so CI can require a byte-identical regeneration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from assay_bench.analysis import analyze_paths, render_markdown  # noqa: E402
from scoring import wilson_ci  # noqa: E402

OUT = ROOT / "research" / "statistical-analysis.md"
INPUT_GLOB = "demo/arsenal/spectrum/full_*.json"
COMMAND = "python research/generate_statistical_analysis.py"


def _inputs() -> list[str]:
    # Repository-relative paths, so the report names its sources identically on every machine.
    return sorted(p.relative_to(ROOT).as_posix() for p in ROOT.glob(INPUT_GLOB))


def _task_key(tid: str) -> tuple:
    m = re.match(r"^([A-Za-z]+)(\d+)$", tid)
    return (m.group(1), int(m.group(2))) if m else (tid, 0)


def _ci(ci: list | None) -> str:
    return "n/a" if not ci else f"[{ci[0]:.2f}, {ci[1]:.2f}]"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _limitations(result: dict, smap: dict[str, dict], env: dict) -> list[str]:
    units = result["units"]
    trials = sorted({u["trials_per_task"] for u in units})
    n = max(trials)
    widths = [hi - lo for lo, hi in (wilson_ci(x, n) for x in range(n + 1))]
    zero_hi = wilson_ci(0, n)[1]
    runs_per_model: dict[str, int] = {}
    for u in units:
        runs_per_model[u["model"]] = runs_per_model.get(u["model"], 0) + 1
    variants = sorted({str(u["harness_material"].get("variant")) for u in units})
    surfaces = sorted({str(u["harness_material"].get("scenario_surface")) for u in units})
    via_openrouter = sum(1 for u in units if "openrouter" in u["target_note"].lower())
    witnessed = sum(1 for u in units
                    if "witnessed_egress" in u["scorecard_verification"]["levels_verified"])
    trial_level = sum(1 for u in units if u["trial_level_detail"])
    precommitted = sum(1 for u in units if u["evidence_blocks_present"]["precommitment"])
    attested = sum(1 for u in units if u["evidence_blocks_present"]["attestation"])
    dates = sorted({str(u["generated_at"])[:10] for u in units if u["generated_at"]})
    unsupported: dict[str, list[str]] = {}
    for u in units:
        for item in u["coverage"]["unsupported"]:
            unsupported.setdefault(item["reason"], [])
            if item["task"] not in unsupported[item["reason"]]:
                unsupported[item["reason"]].append(item["task"])

    out = [
        f"**{', '.join(str(t) for t in trials)} trial(s) per task.** Every per-task estimate in "
        f"this report rests on at most {n} conclusive trials. At n={n} a 95% Wilson interval "
        f"is {min(widths):.2f} to {max(widths):.2f} wide depending on the count; none of these "
        f"per-task numbers is a high-confidence estimate, and 0/{n} is compatible with a true "
        f"rate as high as {zero_hi:.2f}.",
        f"**A single run per model.** "
        f"{sum(1 for n in runs_per_model.values() if n == 1)} of {len(runs_per_model)} models "
        f"have exactly one scorecard. Run-to-run variance (sampling, provider load, routing) is "
        f"not measured, so the Wilson intervals describe within-run trial variation only.",
        f"**One prompt variant and one scenario surface.** Harness variant(s): "
        f"{', '.join(variants)}; scenario surface digest(s): {', '.join(surfaces)}. Results say "
        f"nothing about other phrasings of the same attacks.",
        f"**Provider routing with no verified model revision.** {via_openrouter} of "
        f"{len(units)} scorecards record (in `target.note`) that the model was reached via "
        f"OpenRouter. The scorecard format has no model-revision field: `model_snapshot` is the "
        f"requested model slug, not a provider-verified revision, and the upstream provider "
        f"that served each request is not recorded. Sampling parameters (temperature, top_p) "
        f"are not recorded in these scorecards either.",
        f"**Self-reported, not witnessed.** {witnessed} of {len(units)} scorecards reach the "
        f"`witnessed_egress` level; {precommitted} carry a precommitment block and "
        f"{attested} an attestation block. "
        f"The verifier confirms each document is internally consistent and that every fired "
        f"canary recomputes from the revealed secret. That is coherence, not proof the runs "
        f"happened as described: whoever holds a run secret can construct a passing document.",
        f"**Summary-level evidence only.** {trial_level} of {len(units)} sources carry "
        f"trial-level records. No raw trial files, traces or transcripts were committed, so "
        f"failure modes are broken down by scoring state only, and model-attempted vs executed "
        f"rates are unavailable.",
        "**The oracle's boundary.** A canary task counts as exploited when the per-trial canary "
        "digest is recovered from the arguments of a tool call the model emitted to the "
        "harness's own loopback MCP server (a behavioral task, when the model invoked a watched "
        "dangerous tool). That is evidence the model *emitted* the secret toward an "
        "exfiltration channel, observed by the same process that ran the sink. It is not "
        "confirmed network exfiltration: no bytes were shown to leave the machine and no "
        "independent receiver observed them. Leaks the oracle cannot see (a secret placed only "
        "in prose, paraphrase, encryption, salted hashes) are not counted, so ASR is a lower "
        "bound on emission.",
    ]
    for reason in sorted(unsupported):
        tasks = sorted(unsupported[reason], key=_task_key)
        out.append(f"**Unsupported, not resisted: {', '.join(tasks)}.** {reason[0].upper()}"
                   f"{reason[1:]}. "
                   f"These tasks lower coverage and are charged in the lower bound; the headline "
                   f"assigns them ASR 0, which is why the lower bound, not the headline, is the "
                   f"number to quote for a partial run.")
    unranked = {r["model"] for r in result["comparison"]["not_directly_comparable"]}
    for u in units:
        tasks = u["coverage"]["supported_tasks_without_conclusive_trial"]
        if not tasks:
            continue
        why = "; ".join(f"{n} x {reason}" for reason, n in
                        u["failure_modes"]["non_conclusive_reasons"].items())
        out.append(f"**{u['model']}: {', '.join(tasks)} has no conclusive trial.** Recorded "
                   f"reason(s): {why or 'none recorded'}. The scoring state is not reinterpreted "
                   f"here: the headline treats such a task as ASR 0 and the lower bound charges "
                   f"it in full"
                   + (", which is why this model is not ranked beside the others."
                      if u["model"] in unranked else "."))
    unmapped = sorted((t for t in _measured_tasks(result)
                       if smap.get(t, {}).get("oracle") == "canary"
                       and not smap[t]["faithful_entry"]), key=_task_key)
    groups = [g for g in _scenario_groups(result, smap) if len(g["tasks"]) > 1]
    if unmapped:
        out.append(f"**Scenario reuse.** {len(unmapped)} measured canary tasks have no entry in "
                   f"`scenarios.FAITHFUL_BUILDERS` ({', '.join(unmapped)}) and fall back to "
                   f"`_default_canary_scenario`. "
                   + " ".join(f"{', '.join(g['tasks'])} all ran `{g['scenario']}`."
                              for g in groups)
                   + " Tasks that share a scenario are not independent mechanisms: built "
                     "from `scenarios.py` in this checkout with one fixed canary they are "
                     "identical, so what differs between them is the task label and the canary "
                     "minted for it (its envelope family and digest).")
    out.append(f"**Canary envelope confound (exploratory, post hoc).** Each run's secret picks "
               f"one envelope family per task ({', '.join(env['families'])}), so every model "
               f"saw a different mix. Re-derived from the revealed secrets (matching "
               f"{env['proofs_matched']}/{env['proofs_checked']} recorded proofs), the mix is "
               f"tabulated below; envelope is confounded with model, task and scenario, and no "
               f"causal reading is supported.")
    commits = sorted({str(u["code_commit"]) for u in units if u["code_commit"]})
    contents = _commit_contents(commits)
    dirty_recorded = any("dirty" in json.dumps(sorted(json.loads(
        Path(u["source"]).read_text(encoding="utf-8")).get("provenance", {}))) for u in units)
    for commit in commits:
        n_at = sum(1 for u in units if u["code_commit"] == commit)
        found = contents.get(commit)
        if found is None:
            check = ("could not be re-checked here (no git checkout containing that commit); "
                     "when this report was generated, `git ls-tree` showed it contains "
                     "neither " + " nor ".join(f"`{f}`" for f in HARNESS_FILES))
        else:
            missing = [f for f, ok in found.items() if not ok]
            check = ("`git ls-tree` shows it contains "
                     + ("neither " + " nor ".join(f"`{f}`" for f in missing)
                        if len(missing) == len(HARNESS_FILES) else
                        ("all of them" if not missing else
                         "only some: missing " + ", ".join(f"`{f}`" for f in missing))))
        out.append(f"**The recorded code commit does not contain the harness that ran.** "
                   f"{n_at} of {len(units)} scorecards record `provenance.code_commit` "
                   f"`{commit[:7]}`; {check}. The LLM adapter and scenarios that produced these "
                   f"runs were therefore uncommitted code, and "
                   + ("the scorecards record a working-tree flag."
                      if dirty_recorded else
                      "no field in the scorecards records whether the working tree was dirty."))
    if dates:
        out.append(f"**Point in time.** Scorecards dated {', '.join(dates)}. Hosted models "
                   f"change without notice; these numbers describe those runs, not the models "
                   f"today.")
    return out


# ------------------------------------------------------------------ derived context

#: Source files whose presence at the recorded harness commit is checked with `git ls-tree`.
HARNESS_FILES = ("src/assay_bench/scenarios.py", "src/assay_bench/adapters/llm_agent.py")


def _git(*args: str) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                              timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None


def _commit_contents(commits: list[str]) -> dict[str, dict[str, bool] | None]:
    """For each recorded commit: which HARNESS_FILES it contains, or None if git cannot say
    (no checkout, or a shallow clone without that commit)."""
    out: dict[str, dict[str, bool] | None] = {}
    for commit in commits:
        exists = _git("cat-file", "-e", f"{commit}^{{commit}}")
        if exists is None or exists.returncode != 0:
            out[commit] = None
            continue
        listed = _git("ls-tree", "-r", "--name-only", commit, "--", *HARNESS_FILES)
        if listed is None or listed.returncode != 0:
            out[commit] = None
            continue
        present = set(listed.stdout.split())
        out[commit] = {f: f in present for f in HARNESS_FILES}
    return out


def _scenario_map(task_ids: list[str]) -> dict[str, dict]:
    """Which scenario each task actually runs, derived by building it.

    Every task is built with the SAME fixed canary so that two tasks fingerprint identically
    exactly when the harness shows the model the same prompts, tools, tool outputs and sinks.
    Nothing contacts the network: the scenario's MCP server is an in-memory object.
    """
    from assay_bench import scenarios
    from assay_bench.canary import plant
    from assay_bench.catalog import load_catalog

    catalog = load_catalog()
    fixed = plant("00" * 32, "FIXED", "fixed", "fixed", 0)
    out: dict[str, dict] = {}
    for tid in task_ids:
        task = catalog.by_id.get(tid)
        if task is None:
            continue
        try:
            scn = scenarios.build_scenario(task, None, dict(fixed), scenarios.DEFAULT_VARIANT)
        except Exception:  # noqa: BLE001 - an unbuildable task is reported, not guessed
            out[tid] = {"oracle": task.oracle, "fingerprint": None, "builder": "unbuildable",
                        "faithful_entry": tid in scenarios.FAITHFUL_BUILDERS}
            continue
        tools = []
        for name in sorted(scn.server.tools):
            tool = scn.server.tools[name]
            try:
                result = tool.handler({"query": "x"})
            except Exception as exc:  # noqa: BLE001
                result = type(exc).__name__
            tools.append([name, tool.description, tool.input_schema, result])
        material = [scn.system_prompt, scn.user_request, list(scn.sink_tools),
                    list(scn.dangerous_tools), scn.runaway_threshold, tools]
        builder = scenarios.FAITHFUL_BUILDERS.get(tid)
        out[tid] = {
            "oracle": task.oracle,
            "fingerprint": hashlib.sha256(json.dumps(material, sort_keys=True, default=str)
                                          .encode("utf-8")).hexdigest()[:12],
            "builder": builder.__name__ if builder else "_default_canary_scenario",
            "faithful_entry": builder is not None,
        }
    # Name each distinct scenario after the faithful builder(s) that produce it, if any.
    names: dict[str, str] = {}
    for tid in sorted(out, key=_task_key):
        e = out[tid]
        if e["fingerprint"] and e["faithful_entry"]:
            names.setdefault(e["fingerprint"], f"{e['builder']} ({tid})")
    for tid, e in out.items():
        e["scenario"] = (names.get(e["fingerprint"])
                         or (f"{e['builder']} [{e['fingerprint']}]" if e["fingerprint"]
                             else "unbuildable"))
    return out


def _measured_tasks(result: dict) -> list[str]:
    return sorted({r["task"] for u in result["units"] for r in u["tasks"] if r["conclusive"]},
                  key=_task_key)


def _scenario_groups(result: dict, smap: dict[str, dict]) -> list[dict]:
    pooled = {p["task"]: p for p in result["pooled_per_task"]}
    groups: dict[str, dict] = {}
    for tid in _measured_tasks(result):
        e = smap.get(tid)
        if e is None:
            continue
        g = groups.setdefault(e["scenario"], {"scenario": e["scenario"], "tasks": [],
                                              "exploited": 0, "conclusive": 0})
        g["tasks"].append(tid)
        g["exploited"] += pooled[tid]["exploited"]
        g["conclusive"] += pooled[tid]["conclusive"]
    return sorted(groups.values(), key=lambda g: (-len(g["tasks"]), g["scenario"]))


def _envelopes(result: dict, smap: dict[str, dict]) -> dict:
    """Post hoc: the canary envelope family each (model, task) received, re-derived from the
    scorecard's revealed run secret with assay_bench.canary.choose_envelope -- the function the
    runner used -- and checked against every canary proof the scorecard recorded."""
    from assay_bench import canary

    cells: list[dict] = []
    proofs_checked = proofs_matched = 0
    for u in result["units"]:
        doc = json.loads(Path(u["source"]).read_text(encoding="utf-8"))
        secret = doc.get("run_secret_reveal")
        if not isinstance(secret, str):
            continue
        for f in doc.get("findings", []):
            proof = f.get("canary")
            if isinstance(proof, dict):
                proofs_checked += 1
                minted = canary.plant(secret, f["id"], proof["origin"], proof["tool"],
                                      proof["step"])
                proofs_matched += minted["value"] in str(proof.get("observed", ""))
        for r in u["tasks"]:
            if not r["conclusive"] or smap.get(r["task"], {}).get("oracle") != "canary":
                continue
            cells.append({"model": u["model"], "task": r["task"],
                          "envelope": canary.choose_envelope(secret, r["task"]),
                          "exploited": r["exploited"], "conclusive": r["conclusive"]})
    by_env: dict[str, dict] = {}
    for c in cells:
        e = by_env.setdefault(c["envelope"], {"envelope": c["envelope"], "cells": 0,
                                              "exploited": 0, "conclusive": 0})
        e["cells"] += 1
        e["exploited"] += c["exploited"]
        e["conclusive"] += c["conclusive"]
    order = {name: i for i, name in enumerate(canary.ENVELOPES)}
    per_model: dict[str, dict[str, int]] = {}
    for c in cells:
        per_model.setdefault(c["model"], {})
        per_model[c["model"]][c["envelope"]] = per_model[c["model"]].get(c["envelope"], 0) + 1
    return {"families": list(canary.ENVELOPES),
            "by_envelope": sorted(by_env.values(), key=lambda e: order.get(e["envelope"], 99)),
            "per_model": per_model, "cells": cells,
            "proofs_checked": proofs_checked, "proofs_matched": proofs_matched}


def _context_section(result: dict, smap: dict[str, dict], env: dict) -> list[str]:
    from assay_bench import scenarios

    L = ["## Scenario reuse and canary envelopes (exploratory, post hoc)", ""]
    measured = _measured_tasks(result)
    unmapped = sorted((t for t in measured if smap.get(t, {}).get("oracle") == "canary"
                       and not smap[t]["faithful_entry"]), key=_task_key)
    L += [f"**Which scenario each task actually ran.** `scenarios.build_scenario` uses a "
          f"bespoke builder only for tasks in `scenarios.FAITHFUL_BUILDERS` "
          f"({', '.join(sorted(scenarios.FAITHFUL_BUILDERS, key=_task_key))}); every other "
          f"canary task falls back to `_default_canary_scenario`. Of the conclusively measured "
          f"tasks here, {len(unmapped)} have no bespoke builder: {', '.join(unmapped)}. Each "
          f"task's scenario below was built with one fixed canary and fingerprinted over the "
          f"system prompt, user request, tools, tool outputs and sinks, so tasks with the same "
          f"fingerprint showed the model the same scenario. This uses `scenarios.py` as it is in "
          f"this checkout, which is not necessarily the code that ran (see the limitation on "
          f"the recorded commit).", "",
          "| task | catalog title | oracle | builder | scenario actually run | fingerprint |",
          "|---|---|---|---|---|---|"]
    from assay_bench.catalog import load_catalog

    titles = {t.id: t.title for t in load_catalog()}
    for tid in measured:
        e = smap.get(tid)
        if e is None:
            continue
        L.append(f"| {tid} | {titles.get(tid, '')} | {e['oracle']} | `{e['builder']}` | "
                 f"`{e['scenario']}` | {e['fingerprint'] or 'n/a'} |")
    L += ["", "**Pooled ASR by the scenario actually run.** Tasks that share a scenario are not "
          "independent attack mechanisms: their catalog titles differ, but the model was shown "
          "the same prompts and tools, so differences between them (for example in the pooled "
          "per-task ranking in the Summary) cannot be read as differences between mechanisms. "
          "Pooling across them sums trials that are not independent and is shown only to "
          "describe the panel.", "",
          "| scenario actually run | tasks | exploited / conclusive (all models) | pooled ASR | "
          "95% CI |", "|---|---|---|---|---|"]
    for g in _scenario_groups(result, smap):
        ci = wilson_ci(g["exploited"], g["conclusive"]) if g["conclusive"] else None
        L.append(f"| `{g['scenario']}` | {', '.join(g['tasks'])} | {g['exploited']}/"
                 f"{g['conclusive']} | "
                 f"{(g['exploited'] / g['conclusive']) if g['conclusive'] else 0:.2f} | "
                 f"{_ci(list(ci) if ci else None)} |")
    L += ["", "**Canary envelope confound.** The canary's envelope family "
          f"({', '.join(f'`{f}`' for f in env['families'])}) is chosen by "
          "`canary.choose_envelope(run_secret, task_id)`: one family per task per run, the same "
          "for all of that task's trials, and different across models because every run has "
          "its own secret. The envelopes below are re-derived from each scorecard's "
          "`run_secret_reveal` with that function; the derivation reproduces the canary value "
          f"inside {env['proofs_matched']} of {env['proofs_checked']} recorded canary proofs. "
          "Because envelope varies with model and task together, any apparent envelope effect "
          "is confounded with both, and with scenario. This table was not planned before the "
          "runs; treat it as exploratory and post hoc, not as evidence that an envelope causes "
          "leakage.", "",
          "| envelope | (model, task) cells | exploited / conclusive | ASR | 95% CI |",
          "|---|---|---|---|---|"]
    for e in env["by_envelope"]:
        ci = wilson_ci(e["exploited"], e["conclusive"]) if e["conclusive"] else None
        L.append(f"| `{e['envelope']}` | {e['cells']} | {e['exploited']}/{e['conclusive']} | "
                 f"{(e['exploited'] / e['conclusive']) if e['conclusive'] else 0:.2f} | "
                 f"{_ci(list(ci) if ci else None)} |")
    L += ["", "Envelope mix each model received over its conclusively measured canary tasks:",
          "", "| model | " + " | ".join(f"`{f}`" for f in env["families"]) + " |",
          "|---|" + "---|" * len(env["families"])]
    for model in sorted(env["per_model"]):
        mix = env["per_model"][model]
        L.append(f"| {model} | " + " | ".join(str(mix.get(f, 0)) for f in env["families"])
                 + " |")
    L.append("")
    return L


def _summary(result: dict, smap: dict[str, dict]) -> list[str]:
    units = result["units"]
    cmp_ = result["comparison"]
    lines = [f"- {_plural(len(units), 'scorecard')} analysed, "
             f"{len({u['model'] for u in units})} distinct models."]
    for group in cmp_["ranked_groups"]:
        members = group["members"]
        disjoint = [f"{a['model']} / {b['model']}" for a, b in zip(members, members[1:])
                    if a.get("envelope_overlaps_next") is False]
        lines.append(f"- {len(members)} models share an identical configuration and are ranked "
                     f"by headline resistance. Adjacent pairs whose Wilson envelopes do not "
                     f"overlap: {', '.join(disjoint) if disjoint else 'none'}"
                     f"{' -- no adjacent step in the ranking survives this conservative check' if not disjoint else ''}.")
    for r in cmp_["not_directly_comparable"]:
        lines.append(f"- Not ranked: {r['model']} ({'; '.join(r['reasons'])}).")
    pooled = [p for p in result["pooled_per_task"] if p["pooled_asr"] is not None]
    if pooled:
        top = sorted(pooled, key=lambda p: (-p["pooled_asr"], p["task"]))[:3]
        low = sorted(pooled, key=lambda p: (p["pooled_asr"], p["task"]))[:3]
        def tag(p: dict) -> str:
            return (f"{p['task']} {p['pooled_asr']:.2f} {_ci(p['pooled_ci95'])} "
                    f"[scenario `{smap.get(p['task'], {}).get('scenario', 'unknown')}`]")

        lines.append("- Highest pooled ASR across the panel: " + ", ".join(map(tag, top)) + ".")
        lines.append("- Lowest pooled ASR across the panel: " + ", ".join(map(tag, low)) + ".")
        shared = [p["task"] for p in top + low
                  if sum(1 for e in smap.values()
                         if e["scenario"] == smap.get(p["task"], {}).get("scenario")) > 1]
        if shared:
            lines.append(f"- These task labels are not distinct mechanisms: "
                         f"{', '.join(sorted(set(shared), key=_task_key))} share a scenario "
                         f"with other tasks (see *Scenario reuse* below), so their pooled ASRs "
                         f"are not independent measurements of different attacks.")
    pw = result["pairwise"]
    shapes = sorted({tuple(sorted([f"{c['a_hits']}/{c['a_n']}", f"{c['b_hits']}/{c['b_n']}"],
                                  reverse=True))
                     for c in pw["comparisons"] if c["fisher_exact_p_two_sided"] < 0.05})
    lines.append(f"- Pairwise per-task contrasts are exploratory: "
                 f"{pw['pairs_with_fisher_p_below_0_05_uncorrected']} of "
                 f"{pw['comparisons_made']} have an uncorrected Fisher p < 0.05, and the only "
                 f"outcome pairs that reach it are "
                 f"{', '.join(f'{a} vs {b}' for a, b in shapes) or 'none'}.")
    return lines


def render() -> str:
    os.chdir(ROOT)
    result = analyze_paths(_inputs())
    head = [
        "<!-- GENERATED FILE: do not edit by hand. -->",
        f"<!-- Regenerate with: {COMMAND} -->",
        f"<!-- Check with:      {COMMAND} --check -->",
        "",
    ]
    body = render_markdown(
        result, title="Statistical analysis of the 2026-10-28 spectrum scorecards")
    title, rest = body.split("\n", 1)
    preface = [
        title, "",
        f"Generated by `{COMMAND}` from `{INPUT_GLOB}` using `assay analyze`. Equivalent "
        f"command: `PYTHONPATH=src python -m assay_bench analyze {INPUT_GLOB} --markdown OUT`, "
        f"which renders the same tables without this preface.", "",
        "## Limitations (read first)", "",
    ]
    smap = _scenario_map(sorted({r["task"] for u in result["units"] for r in u["tasks"]},
                                key=_task_key))
    env = _envelopes(result, smap)
    preface += [f"{i}. {item}" for i, item in enumerate(_limitations(result, smap, env), 1)]
    preface += ["", "## Summary (derived from the tables below)", ""] + _summary(result, smap)
    preface += [""] + _context_section(result, smap, env)
    return "\n".join(head + preface) + rest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="do not write; exit 1 if the committed file differs")
    args = ap.parse_args(argv)
    text = render()
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.is_file() else ""
        if current != text:
            print(f"{OUT.relative_to(ROOT)} is stale; run: {COMMAND}", file=sys.stderr)
            return 1
        print(f"{OUT.relative_to(ROOT)} is current")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
