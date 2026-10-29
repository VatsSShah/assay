"""Independent-replication submissions: what a second researcher hands back, and how it is checked.

A result that only its author has produced is a self-report, however carefully it was made. The
point of a replication submission is to let someone else's run be compared with the original on
stated terms: which commit, which model identity, which configuration, which deviations, and
what evidence backs each claim.

Schema ``assay/replication-submission/1``. Evidence levels are three INDEPENDENT booleans, not a
ladder, because they answer different questions:

* **Level 1 -- ``self_reported``.** The submitter ran it and says so. Always true for a submission;
  it is the floor, not an achievement.
* **Level 2 -- ``independently_witnessed``.** Canary arrivals were observed and signed by a witness
  whose key the bundle's trust file declares independent, and that key is not the key that signed
  the artifact index. It answers "did someone other than the operator observe the egress?"
* **Level 3 -- ``independently_reproduced``.** A different researcher re-ran a named, earlier
  experiment. It answers "does the result survive a second operator?"

Level 3 never implies Level 2: a faithful reproduction can be entirely self-observed, and a
witnessed run can be the only run there is. Each claim is checked on its own evidence.

What ``validate_submission`` establishes: the document is complete and well-formed; when the
bundle is supplied, the bundle verifies, the submission's digests, counts and model identity agree
with it, and each claimed evidence level is backed by the artifacts it requires. What it does NOT
establish: that any of it is TRUE. Structural validation is not proof of factual authenticity --
a researcher who fabricates a bundle, a witness key and a pseudonym can produce a document that
passes every check here. Independence is a declaration about key custody and people, and no
signature can prove it.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .errors import EXIT_OK, EXIT_VERIFICATION_FAILED, MalformedInput

SCHEMA = "assay/replication-submission/1"

STRUCTURAL_NOTE = (
    "Structural validation is not proof of factual authenticity: these checks show the "
    "submission is complete, internally consistent and (with --bundle) agrees with a bundle "
    "that verifies. They cannot show the experiment happened, that the named model answered, or "
    "that a witness declared independent really is.")

EVIDENCE_LEVELS = {
    "self_reported": "Level 1: the submitter ran it and reports it (always true)",
    "independently_witnessed": "Level 2: egress observed and signed by a witness key declared "
                               "independent, distinct from the artifact-signing key",
    "independently_reproduced": "Level 3: a different researcher re-ran a named earlier "
                                "experiment (does NOT imply Level 2)",
}

COUNT_FIELDS = ("trials_scheduled", "trials_executed", "attack_succeeded", "attack_failed",
                "inconclusive", "infrastructure_failures", "unsupported")

MAX_SUBMISSION_BYTES = 5_000_000

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
_EXPERIMENT_ID = re.compile(r"^exp-\d{8}-[0-9a-f]{8}$")
_PLACEHOLDER = re.compile(r"<REPLACE[^>]*>|REPLACE_ME")

PASS, FAIL, NOT_CHECKED = "pass", "fail", "not_checked"


def _check(name: str, status: str, detail: str) -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail}


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _placeholders(obj: Any, path: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(obj, dict):
        for k in sorted(obj):
            found += _placeholders(obj[k], f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found += _placeholders(v, f"{path}[{i}]")
    elif isinstance(obj, str) and _PLACEHOLDER.search(obj):
        found.append(path)
    return found


def _norm_person(value: Any) -> str:
    return str(value).strip().casefold()


# ------------------------------------------------------------------------- structural checks

def _structural(doc: dict[str, Any]) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    add = checks.append

    add(_check("schema", PASS if doc.get("schema") == SCHEMA else FAIL,
               f"schema is {doc.get('schema')!r}" + ("" if doc.get("schema") == SCHEMA
                                                     else f", expected {SCHEMA!r}")))

    required = ("researcher", "assay_commit", "experiment", "model", "results", "evidence",
                "verification", "witness", "deviations", "replicates", "evidence_levels")
    missing = [k for k in required if k not in doc]
    add(_check("required_fields", FAIL if missing else PASS,
               f"missing: {', '.join(missing)}" if missing else "every required field present "
               "(witness and replicates may be null; deviations may be empty but must exist)"))

    holes = _placeholders(doc)
    add(_check("no_placeholders", FAIL if holes else PASS,
               f"placeholder values at {', '.join(holes[:8])}{'...' if len(holes) > 8 else ''}"
               if holes else "no template placeholder remains"))

    r = doc.get("researcher")
    ok = isinstance(r, dict) and _nonempty_str(r.get("id")) and \
        isinstance(r.get("is_pseudonym"), bool)
    add(_check("researcher", PASS if ok else FAIL,
               "researcher id (name or pseudonym) present" if ok else
               "researcher must be {id: non-empty string, is_pseudonym: bool, contact?: string}"))

    commit = doc.get("assay_commit")
    ok = isinstance(commit, str) and bool(_COMMIT.match(commit))
    add(_check("assay_commit", PASS if ok else FAIL,
               "full lowercase git commit id" if ok else
               f"assay_commit must be a full 40-hex (or 64-hex) commit id, got {commit!r}"))

    e = doc.get("experiment")
    problems = []
    if not isinstance(e, dict):
        problems.append("experiment must be an object")
    else:
        if not (isinstance(e.get("experiment_id"), str) and _EXPERIMENT_ID.match(e["experiment_id"])):
            problems.append(f"experiment_id must match exp-YYYYMMDD-<8 hex>, got "
                            f"{e.get('experiment_id')!r}")
        has_path = _nonempty_str(e.get("config_path"))
        has_cfg = isinstance(e.get("config"), dict)
        if not (has_path or has_cfg):
            problems.append("experiment needs config_path (path inside the bundle) or config")
    add(_check("experiment", FAIL if problems else PASS, "; ".join(problems) or
               "experiment id and configuration reference present"))

    m = doc.get("model")
    problems = []
    if not isinstance(m, dict):
        problems.append("model must be an object")
    else:
        for key in ("provider", "api_model_id"):
            if not _nonempty_str(m.get(key)):
                problems.append(f"model.{key} must be a non-empty string")
        if "routing_service" not in m or not (m["routing_service"] is None
                                              or _nonempty_str(m["routing_service"])):
            problems.append("model.routing_service must be present (string, or null if direct)")
        prm = m.get("provider_reported_models")
        if not (isinstance(prm, list) and all(_nonempty_str(x) for x in prm)):
            problems.append("model.provider_reported_models must be a list of strings "
                            "(empty if the provider reported none)")
        if "model_revision" not in m or not (m["model_revision"] is None
                                             or _nonempty_str(m["model_revision"])):
            problems.append("model.model_revision must be present (string, or null if unknown)")
    add(_check("model_identity", FAIL if problems else PASS, "; ".join(problems) or
               "provider, api_model_id, routing_service, provider_reported_models, "
               "model_revision all stated"))

    res = doc.get("results")
    problems = []
    configs = res.get("configurations") if isinstance(res, dict) else None
    if not isinstance(configs, list) or not configs:
        problems.append("results.configurations must be a non-empty list")
    else:
        names = set()
        for i, c in enumerate(configs):
            where = f"results.configurations[{i}]"
            if not isinstance(c, dict) or not _nonempty_str(c.get("name")):
                problems.append(f"{where}: needs a name")
                continue
            if c["name"] in names:
                problems.append(f"{where}: duplicate configuration {c['name']!r}")
            names.add(c["name"])
            bad = [f for f in COUNT_FIELDS if isinstance(c.get(f), bool)
                   or not isinstance(c.get(f), int) or c[f] < 0]
            if bad:
                problems.append(f"{where}: {', '.join(bad)} must be non-negative integers")
                continue
            parts = (c["attack_succeeded"] + c["attack_failed"] + c["inconclusive"]
                     + c["infrastructure_failures"] + c["unsupported"])
            if parts != c["trials_executed"]:
                problems.append(f"{where}: outcomes sum to {parts}, trials_executed is "
                                f"{c['trials_executed']}")
            if c["trials_executed"] > c["trials_scheduled"]:
                problems.append(f"{where}: more trials executed than scheduled")
    add(_check("results_summary", FAIL if problems else PASS, "; ".join(problems) or
               "every configuration's outcome counts add up (negative and inconclusive results "
               "included)"))

    ev = doc.get("evidence")
    problems = []
    if not isinstance(ev, dict):
        problems.append("evidence must be an object")
    else:
        if not _nonempty_str(ev.get("bundle_path")):
            problems.append("evidence.bundle_path must name the bundle directory")
        if not (isinstance(ev.get("artifact_index_sha256"), str)
                and _HEX64.match(ev["artifact_index_sha256"])):
            problems.append("evidence.artifact_index_sha256 must be 64 lowercase hex")
        key = ev.get("artifact_signing_public_key")
        if key is not None and not (isinstance(key, str) and _HEX64.match(key)):
            problems.append("evidence.artifact_signing_public_key must be 64 hex or null")
    add(_check("evidence_reference", FAIL if problems else PASS, "; ".join(problems) or
               "bundle path and artifact-index digest present"))

    v = doc.get("verification")
    if not isinstance(v, dict) or not isinstance(v.get("ok"), bool) \
            or not isinstance(v.get("checks"), list):
        add(_check("verification_output", FAIL,
                   "verification must be the JSON printed by `assay verify-artifacts` "
                   "({ok, checks, ...})"))
    elif not v["ok"]:
        failed = [c.get("name") for c in v["checks"] if isinstance(c, dict) and not c.get("ok")]
        add(_check("verification_output", FAIL,
                   "the attached verification output reports ok=false"
                   + (f"; failed checks: {failed}" if failed else "")))
    else:
        add(_check("verification_output", PASS, "attached verify-artifacts output reports ok"))

    d = doc.get("deviations")
    problems = []
    if not isinstance(d, list):
        problems.append("deviations must be a list (empty if there were none)")
    else:
        for i, item in enumerate(d):
            if not (isinstance(item, dict) and _nonempty_str(item.get("description"))
                    and _nonempty_str(item.get("reason")) and _nonempty_str(item.get("impact"))):
                problems.append(f"deviations[{i}] needs description, reason and impact")
    add(_check("deviations", FAIL if problems else PASS, "; ".join(problems) or
               f"{len(d)} methodological deviation(s) declared"))

    w = doc.get("witness")
    problems = []
    if w is not None:
        if not isinstance(w, dict):
            problems.append("witness must be an object or null")
        else:
            if not _nonempty_str(w.get("name")):
                problems.append("witness.name required")
            if not (isinstance(w.get("public_key"), str) and _HEX64.match(w["public_key"])):
                problems.append("witness.public_key must be 64 hex")
            if not isinstance(w.get("independent"), bool):
                problems.append("witness.independent must be a boolean")
            if not _nonempty_str(w.get("receipts_path")):
                problems.append("witness.receipts_path must name the receipts file in the bundle")
    add(_check("witness_block", FAIL if problems else PASS, "; ".join(problems) or
               ("no witness" if w is None else "witness block well-formed")))

    rep = doc.get("replicates")
    problems = []
    if rep is not None:
        if not isinstance(rep, dict):
            problems.append("replicates must be an object or null")
        else:
            if not (_nonempty_str(rep.get("experiment_id")) or _nonempty_str(rep.get("scorecard"))):
                problems.append("replicates needs the original experiment_id or scorecard reference")
            if not _nonempty_str(rep.get("original_operator")):
                problems.append("replicates.original_operator required")
    add(_check("replicates_block", FAIL if problems else PASS, "; ".join(problems) or
               ("not a replication of a named experiment" if rep is None
                else "names the original experiment and operator")))

    lv = doc.get("evidence_levels")
    problems = []
    if not isinstance(lv, dict):
        problems.append("evidence_levels must be an object")
    else:
        extra = sorted(set(lv) - set(EVIDENCE_LEVELS))
        if extra:
            problems.append(f"unknown evidence level(s) {extra}")
        for k in EVIDENCE_LEVELS:
            if not isinstance(lv.get(k), bool):
                problems.append(f"evidence_levels.{k} must be a boolean")
        if lv.get("self_reported") is not True:
            problems.append("self_reported must be true: every submission is at least a self-report")
    add(_check("evidence_levels", FAIL if problems else PASS, "; ".join(problems) or
               "three independent booleans"))
    return checks


# ----------------------------------------------------------------------------- bundle checks

def _load_json(path: Path, what: str) -> Any:
    try:
        if path.stat().st_size > 50_000_000:
            raise MalformedInput(f"{what} {path} is too large")
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise MalformedInput(f"cannot read {what} {path}: {exc.strerror}") from None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedInput(f"{what} {path} is not valid JSON: {exc}") from None


def _bundle_checks(doc: dict[str, Any], bundle_dir: Path) -> tuple[list[dict[str, str]],
                                                                  dict[str, Any]]:
    checks: list[dict[str, str]] = []
    add = checks.append
    facts: dict[str, Any] = {"signing_key": None, "operator": None, "experiment_id": None}
    if not bundle_dir.is_dir():
        add(_check("bundle_present", FAIL, f"{bundle_dir} is not a directory"))
        return checks, facts
    ev = doc.get("evidence") if isinstance(doc.get("evidence"), dict) else {}

    # -- artifact index digest
    index_path = bundle_dir / "artifact_index.json"
    index = None
    if not index_path.is_file():
        add(_check("artifact_index_digest", FAIL, "bundle has no artifact_index.json"))
    else:
        raw = index_path.read_bytes()
        index = _load_json(index_path, "artifact index")
        digests = {"file bytes": hashlib.sha256(raw).hexdigest()}
        try:
            from .bundle import index_sha256

            digests["canonical index (as signed)"] = index_sha256(index)
        except Exception:  # noqa: BLE001 - the file-bytes digest still applies
            pass
        claimed = ev.get("artifact_index_sha256")
        hit = [k for k, v in digests.items() if v == claimed]
        add(_check("artifact_index_digest", PASS if hit else FAIL,
                   f"matches the {hit[0]} digest" if hit else
                   f"submission says {claimed!r}; bundle index is "
                   + " / ".join(f"{v} ({k})" for k, v in sorted(digests.items()))))
    sig_path = bundle_dir / "artifact_index.sig.json"
    if sig_path.is_file():
        sig = _load_json(sig_path, "artifact index signature")
        if isinstance(sig, dict) and isinstance(sig.get("public_key"), str):
            facts["signing_key"] = sig["public_key"].lower()

    # -- bundle verification
    try:
        from .bundle import verify_bundle
    except ImportError:
        verify_bundle = None
    if verify_bundle is None:
        add(_check("bundle_verifies", FAIL, "assay_bench.bundle is unavailable; the bundle "
                                            "cannot be verified, so nothing it contains is "
                                            "relied on"))
        fresh = None
    else:
        try:
            fresh = verify_bundle(bundle_dir)
        except Exception as exc:  # noqa: BLE001 - a bundle that cannot be read does not verify
            fresh = {"ok": False, "checks": [{"name": "read", "ok": False,
                                              "detail": f"{type(exc).__name__}: {exc}"}]}
        failed = [c.get("name") for c in fresh.get("checks", []) if not c.get("ok")]
        add(_check("bundle_verifies", PASS if fresh.get("ok") else FAIL,
                   "verify_bundle: every check passed" if fresh.get("ok")
                   else f"verify_bundle failed: {failed}"))
        submitted = doc.get("verification") if isinstance(doc.get("verification"), dict) else {}
        same = (submitted.get("ok") == fresh.get("ok")
                and submitted.get("experiment_id") == fresh.get("experiment_id"))
        add(_check("verification_output_matches_bundle", PASS if same else FAIL,
                   "attached verification output agrees with a fresh verification" if same else
                   f"attached output (ok={submitted.get('ok')}, experiment_id="
                   f"{submitted.get('experiment_id')!r}) disagrees with a fresh run "
                   f"(ok={fresh.get('ok')}, experiment_id={fresh.get('experiment_id')!r})"))

    # -- experiment manifest: id, commit, model identity, counts
    exp_path = bundle_dir / "experiment.json"
    if not exp_path.is_file():
        add(_check("experiment_manifest", FAIL, "bundle has no experiment.json"))
        return checks, facts
    exp = _load_json(exp_path, "experiment manifest")
    meta = exp.get("experiment") if isinstance(exp, dict) else None
    meta = meta if isinstance(meta, dict) else {}
    facts["operator"] = meta.get("operator")
    facts["experiment_id"] = meta.get("experiment_id")

    sub_exp = doc.get("experiment") if isinstance(doc.get("experiment"), dict) else {}
    ok = sub_exp.get("experiment_id") == meta.get("experiment_id")
    add(_check("experiment_id_matches", PASS if ok else FAIL,
               f"experiment_id {meta.get('experiment_id')!r}" if ok else
               f"submission names {sub_exp.get('experiment_id')!r}, bundle is "
               f"{meta.get('experiment_id')!r}"))
    if _nonempty_str(sub_exp.get("config_path")):
        try:
            from .bundle import safe_join

            target = safe_join(bundle_dir, sub_exp["config_path"])
            ok, detail = target.is_file(), f"{sub_exp['config_path']} " + (
                "is in the bundle" if target.is_file() else "is not in the bundle")
        except Exception as exc:  # noqa: BLE001 - unsafe or unresolvable path
            ok, detail = False, f"config_path rejected: {exc}"
        add(_check("config_reference", PASS if ok else FAIL, detail))

    ok = doc.get("assay_commit") == meta.get("repository_commit")
    add(_check("assay_commit_matches", PASS if ok else FAIL,
               "matches experiment.repository_commit" if ok else
               f"submission says {doc.get('assay_commit')!r}, bundle recorded "
               f"{meta.get('repository_commit')!r}"))

    model = exp.get("model") if isinstance(exp.get("model"), dict) else {}
    sub_model = doc.get("model") if isinstance(doc.get("model"), dict) else {}
    diffs = []
    for key in ("provider", "api_model_id", "routing_service", "model_revision"):
        if sub_model.get(key) != model.get(key):
            diffs.append(f"{key}: submission {sub_model.get(key)!r} vs bundle {model.get(key)!r}")
    a = sorted(sub_model.get("provider_reported_models") or [])
    b = sorted(model.get("provider_reported_models") or [])
    if a != b:
        diffs.append(f"provider_reported_models: submission {a} vs bundle {b}")
    add(_check("model_identity_matches", FAIL if diffs else PASS,
               "; ".join(diffs) or "identical to experiment.json model block"))

    runs = {r.get("configuration"): r for r in exp.get("runs") or [] if isinstance(r, dict)}
    res = doc.get("results") if isinstance(doc.get("results"), dict) else {}
    stated = {c.get("name"): c for c in res.get("configurations") or [] if isinstance(c, dict)}
    diffs = []
    if set(runs) != set(stated):
        diffs.append(f"configurations differ: submission {sorted(map(str, stated))} vs bundle "
                     f"{sorted(map(str, runs))}")
    for name in sorted(set(runs) & set(stated), key=str):
        for f in COUNT_FIELDS:
            if stated[name].get(f) != runs[name].get(f):
                diffs.append(f"{name}.{f}: submission {stated[name].get(f)!r} vs bundle "
                             f"{runs[name].get(f)!r}")
    add(_check("trial_counts_match", FAIL if diffs else PASS,
               "; ".join(diffs[:8]) or "every configuration's counts equal experiment.json runs"))
    return checks, facts


def _witness_level(doc: dict[str, Any], bundle_dir: Path | None,
                   facts: dict[str, Any]) -> dict[str, str]:
    """Level 2 is supported only by receipts that verify under a key declared independent that
    is not the artifact-signing key. Anything less is a self-observation."""
    name = "claim_independently_witnessed"
    w = doc.get("witness")
    if not isinstance(w, dict):
        return _check(name, FAIL, "Level 2 claimed but there is no witness block or receipts")
    if w.get("independent") is not True:
        return _check(name, FAIL, "Level 2 claimed but the witness block does not declare the "
                                  "witness independent")
    signing = ((doc.get("evidence") or {}).get("artifact_signing_public_key")
               if isinstance(doc.get("evidence"), dict) else None) or facts.get("signing_key")
    wkey = str(w.get("public_key", "")).lower()
    if signing and wkey == str(signing).lower():
        return _check(name, FAIL, "the witness key is the artifact-signing key: the operator "
                                  "witnessed its own run, which is not independent")
    if bundle_dir is None:
        return _check(name, FAIL, "Level 2 cannot be confirmed without the bundle that holds "
                                  "the receipts (pass --bundle)")
    rel = str(w.get("receipts_path") or "witness/receipts.jsonl")
    try:
        from .bundle import safe_join
        from .witness_receipt import load_trusted_keys, read_receipts, verify_receipts
    except ImportError:
        return _check(name, FAIL, "witness receipt verifier unavailable")
    try:
        receipts_file = safe_join(bundle_dir, rel)
        keys_file = safe_join(bundle_dir, "witness/trusted_keys.json")
    except Exception as exc:  # noqa: BLE001
        return _check(name, FAIL, f"unsafe receipts path: {exc}")
    if not receipts_file.is_file():
        return _check(name, FAIL, f"Level 2 claimed but {rel} is not in the bundle")
    if not keys_file.is_file():
        return _check(name, FAIL, "no witness/trusted_keys.json: no key is declared independent")
    try:
        receipts = read_receipts(receipts_file)
        trusted = load_trusted_keys(keys_file)
        result = verify_receipts(receipts, trusted_keys=trusted,
                                 expect_experiment_id=facts.get("experiment_id"))
    except Exception as exc:  # noqa: BLE001 - malformed receipts or keys do not support a claim
        return _check(name, FAIL, f"receipts did not verify: {type(exc).__name__}: {exc}")
    if not receipts:
        return _check(name, FAIL, "the receipts file is empty")
    if not result.get("ok"):
        failed = [c["name"] for c in result.get("checks", []) if not c.get("ok")]
        return _check(name, FAIL, f"receipts did not verify: {failed}")
    signers = sorted({str(r.get("signature", {}).get("public_key", "")).lower()
                      for r in receipts if isinstance(r, dict)})
    if signing and str(signing).lower() in signers:
        return _check(name, FAIL, "a receipt is signed by the artifact-signing key: the "
                                  "operator witnessed its own run")
    if any(not r.get("independent_granted_by_trust_file") for r in result.get("receipts", [])):
        return _check(name, FAIL, "at least one receipt's key is not declared independent by "
                                  "witness/trusted_keys.json (and declared independent by the "
                                  "receipt itself)")
    if wkey not in signers:
        return _check(name, FAIL, "the submission's witness.public_key signed none of the "
                                  "receipts")
    return _check(name, PASS, f"{len(receipts)} receipt(s) verify under independent key(s) "
                              f"distinct from the artifact-signing key; independence is still "
                              f"the trust file's declaration, not a proof")


def _reproduced_level(doc: dict[str, Any], facts: dict[str, Any]) -> dict[str, str]:
    name = "claim_independently_reproduced"
    rep = doc.get("replicates")
    if not isinstance(rep, dict) or not (_nonempty_str(rep.get("experiment_id"))
                                         or _nonempty_str(rep.get("scorecard"))):
        return _check(name, FAIL, "Level 3 claimed but no `replicates` reference names the "
                                  "original experiment or scorecard")
    original = rep.get("original_operator")
    if not _nonempty_str(original):
        return _check(name, FAIL, "Level 3 claimed but replicates.original_operator is missing")
    researcher = (doc.get("researcher") or {}).get("id") if isinstance(doc.get("researcher"),
                                                                       dict) else None
    if _norm_person(researcher) == _norm_person(original):
        return _check(name, FAIL, "the researcher is the original operator: re-running your own "
                                  "experiment is a repeat, not an independent reproduction")
    if facts.get("operator") is not None and _norm_person(facts["operator"]) == _norm_person(original):
        return _check(name, FAIL, "the bundle's experiment.operator is the original operator")
    if facts.get("experiment_id") and facts["experiment_id"] == rep.get("experiment_id"):
        return _check(name, FAIL, "the bundle IS the original experiment, not a reproduction")
    return _check(name, PASS, "names an earlier experiment by a different operator; whether the "
                              "two people are really different is not something a document "
                              "can prove")


# ------------------------------------------------------------------------------- public API

def validate_submission(doc: Any, *, bundle_dir: str | Path | None = None) -> dict[str, Any]:
    """Validate a replication submission; with ``bundle_dir``, check it against the bundle.

    Returns ``{"ok", "checks": [{name, status, detail}], "evidence_levels": {...}, "note"}``.
    ``ok`` is true only if no check has status ``fail``. A claimed evidence level that cannot be
    confirmed is a failure, not a pass: an unconfirmed claim is exactly what this guards against.
    """
    if not isinstance(doc, dict):
        raise MalformedInput("a replication submission must be a JSON object")
    checks = _structural(doc)
    facts: dict[str, Any] = {"signing_key": None, "operator": None, "experiment_id": None}
    bdir = Path(bundle_dir) if bundle_dir is not None else None
    if bdir is not None:
        more, facts = _bundle_checks(doc, bdir)
        checks += more
    else:
        checks.append(_check("bundle_checks", NOT_CHECKED,
                             "no --bundle given: digests, counts and model identity were not "
                             "compared with the artifacts"))

    levels = doc.get("evidence_levels") if isinstance(doc.get("evidence_levels"), dict) else {}
    summary: dict[str, Any] = {}
    for level, meaning in EVIDENCE_LEVELS.items():
        summary[level] = {"claimed": levels.get(level) is True, "meaning": meaning,
                          "supported": None}
    summary["self_reported"]["supported"] = levels.get("self_reported") is True
    if levels.get("independently_witnessed") is True:
        c = _witness_level(doc, bdir, facts)
        checks.append(c)
        summary["independently_witnessed"]["supported"] = c["status"] == PASS
    if levels.get("independently_reproduced") is True:
        c = _reproduced_level(doc, facts)
        checks.append(c)
        summary["independently_reproduced"]["supported"] = c["status"] == PASS

    return {
        "schema": SCHEMA,
        "ok": not any(c["status"] == FAIL for c in checks),
        "checks": checks,
        "evidence_levels": summary,
        "bundle_checked": bdir is not None,
        "note": STRUCTURAL_NOTE,
    }


# ------------------------------------------------------------------------------------ CLI

def cmd_validate(args) -> int:
    path = Path(args.submission)
    try:
        if path.stat().st_size > MAX_SUBMISSION_BYTES:
            raise MalformedInput(f"{path} is larger than {MAX_SUBMISSION_BYTES} bytes")
        doc = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise MalformedInput(f"cannot read submission {str(path)!r}: {exc.strerror}") from None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedInput(f"submission {str(path)!r} is not valid JSON: {exc}") from None
    result = validate_submission(doc, bundle_dir=args.bundle)
    print(json.dumps(result, indent=2))
    return EXIT_OK if result["ok"] else EXIT_VERIFICATION_FAILED


def add_cli(sub) -> None:
    rep = sub.add_parser("replication", help="independent-replication submissions")
    rsub = rep.add_subparsers(dest="replication_command", required=True)
    v = rsub.add_parser("validate", help="validate a replication submission (structural, and "
                                         "against its bundle with --bundle)")
    v.add_argument("submission", metavar="SUBMISSION.json")
    v.add_argument("--bundle", metavar="DIR",
                   help="the experiment bundle the submission references; required to confirm "
                        "Level 2 claims and to compare digests, counts and model identity")
    v.set_defaults(func=cmd_validate)
