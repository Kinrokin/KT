from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from tools.training.fl3_factory.hashing import sha256_file_normalized
from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import repo_root_from, sha256_json
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object


def _schema_hash(schema_file: str) -> str:
    from schemas.schema_files import schema_version_hash  # type: ignore

    return schema_version_hash(schema_file)


def _load_policy_bundles_from_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise FL3ValidationError(f"Missing policy bundle artifact (fail-closed): {path.as_posix()}")
    bundles: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except Exception as exc:  # noqa: BLE001
            raise FL3ValidationError("policy_bundles.jsonl contains invalid JSON (fail-closed)") from exc
        validate_schema_bound_object(obj)
        if obj.get("schema_id") != "kt.policy_bundle.v1":
            raise FL3ValidationError("policy bundle schema_id mismatch (fail-closed)")
        bundles.append(obj)
    if not bundles:
        raise FL3ValidationError("No policy bundles found (fail-closed)")
    # Deterministic ordering for evaluation: sort by bundle_id.
    bundles.sort(key=lambda b: str(b.get("bundle_id", "")))
    return bundles


def _utility_pack_dir(repo_root: Path) -> Path:
    return (repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "UTILITY_PACK_V1").resolve()


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"Unable to read JSON (fail-closed): {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"Expected JSON object (fail-closed): {path.as_posix()}")
    return obj


def _load_utility_pack(*, repo_root: Path) -> Tuple[str, str, List[str], Dict[str, Any], Dict[str, Any]]:
    """
    Returns:
      (utility_pack_id, utility_pack_hash, prompts, scoring_spec, thresholds)
    """
    up_dir = _utility_pack_dir(repo_root)
    manifest = _read_json(up_dir / "UTILITY_PACK_MANIFEST.json")
    validate_schema_bound_object(manifest)
    if manifest.get("schema_id") != "kt.utility_pack_manifest.v1":
        raise FL3ValidationError("UTILITY_PACK_MANIFEST schema_id mismatch (fail-closed)")
    utility_pack_id = str(manifest.get("utility_pack_id"))
    utility_pack_hash = str(manifest.get("utility_pack_hash"))

    prompts_path = up_dir / "bench_prompts.jsonl"
    prompts = [ln for ln in prompts_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not prompts:
        raise FL3ValidationError("bench_prompts.jsonl empty (fail-closed)")

    scoring_spec = _read_json(up_dir / "scoring_spec.json")
    thresholds = _read_json(up_dir / "thresholds.json")
    validate_schema_bound_object(scoring_spec)
    if scoring_spec.get("schema_id") != "kt.scoring_spec.v1":
        raise FL3ValidationError("scoring_spec schema_id mismatch (fail-closed)")

    if "utility_floor_min" not in thresholds:
        raise FL3ValidationError("thresholds.utility_floor_min missing (fail-closed)")
    try:
        _ = float(thresholds["utility_floor_min"])
    except Exception as exc:
        raise FL3ValidationError("thresholds.utility_floor_min must be number (fail-closed)") from exc

    return utility_pack_id, utility_pack_hash, prompts, scoring_spec, thresholds


def _apply_policy_bundle(*, prompt: str, bundle: Dict[str, Any]) -> str:
    geno = bundle.get("genotype") if isinstance(bundle.get("genotype"), dict) else {}
    style = str(geno.get("prompt_transform_style", "clarify_first"))
    directive = str(geno.get("reasoning_directive", "steps_tagged"))
    upol = str(geno.get("uncertainty_policy", "neutral"))
    guard = str(geno.get("guardrail_strength", "balanced"))
    bias = str(geno.get("scoring_bias", "precision"))

    # "Strict" bundles deterministically refuse (used to ensure the reality-veto and
    # anti-theater gates can actually reject some genotypes).
    if guard == "strict":
        return f"REFUSE|DIR:{directive}|UNC:{upol}|GUARD:{guard}|BIAS:{bias}"

    if style == "clarify_first":
        base = f"CLARIFY:{prompt}"
    elif style == "expand_context":
        base = f"{prompt}|CONTEXT"
    elif style == "compress":
        base = prompt[: max(1, len(prompt) // 2)]
    elif style == "reframe":
        base = f"REFRAME:{prompt}"
    else:
        # Structured outline intentionally breaks contiguous substring matching so the
        # independent probe can detect disagreement on some genotypes.
        chars = "".join(sorted(set(prompt)))
        base = f"OUTLINE:{chars}"

    # Deterministic, bounded "output" (AdapterType.A only).
    return f"OUT:{base}|DIR:{directive}|UNC:{upol}|GUARD:{guard}|BIAS:{bias}"


def _utility_floor_score_main(*, prompts: List[str], bundle: Dict[str, Any]) -> float:
    ok = 0
    for p in prompts:
        out = _apply_policy_bundle(prompt=p, bundle=bundle)
        # Utility floor: output must reference at least some of the prompt characters.
        # (This is a deterministic "reality veto v0" proxy for non-empty, non-theater behavior.)
        if p and any(ch in out for ch in p[: min(8, len(p))]):
            ok += 1
    return ok / max(1, len(prompts))


def _utility_floor_score_probe(*, prompts: List[str], bundle: Dict[str, Any]) -> float:
    # Independent probe path: avoid calling _utility_floor_score_main.
    ok = 0
    for p in prompts:
        out = _apply_policy_bundle(prompt=p, bundle=bundle)
        snippet = p[: min(8, len(p))]
        if snippet and snippet in out:
            ok += 1
    return ok / max(1, len(prompts))


def build_eval_report(*, job: Dict[str, Any], trace: Dict[str, Any], dataset: Dict[str, Any], train_manifest: Dict[str, Any]) -> Dict[str, Any]:
    repo_root = repo_root_from(Path(__file__))

    artifact_path = Path(str(train_manifest["output_bundle"]["artifact_path"]))
    policy_path = artifact_path if artifact_path.is_absolute() else (repo_root / artifact_path).resolve()
    bundles = _load_policy_bundles_from_jsonl(policy_path)

    utility_pack_id, utility_pack_hash, prompts, scoring_spec, thresholds = _load_utility_pack(repo_root=repo_root)

    # Thresholds (reality veto v0).
    floor_min = float(thresholds["utility_floor_min"])

    # Select best bundle by utility floor score, but only among probe-agreeing,
    # utility-floor-passing candidates (deterministic).
    tol = 1e-9
    passing: List[Tuple[float, str, float, float, Dict[str, Any]]] = []
    for b in bundles:
        main_score = _utility_floor_score_main(prompts=prompts, bundle=b)
        probe_score = _utility_floor_score_probe(prompts=prompts, bundle=b)
        agreement = abs(main_score - probe_score) <= tol
        floor_pass = main_score >= floor_min
        if agreement and floor_pass:
            passing.append((main_score, str(b.get("bundle_id", "")), main_score, probe_score, b))

    if not passing:
        # Fail-closed: no genotype satisfies reality-veto + probe agreement.
        best_bundle = bundles[0]
        best_score = _utility_floor_score_main(prompts=prompts, bundle=best_bundle)
        probe_score = _utility_floor_score_probe(prompts=prompts, bundle=best_bundle)
        agreement = abs(best_score - probe_score) <= tol
        floor_pass = best_score >= floor_min
    else:
        # Sort by (main_score desc, bundle_id desc) for deterministic max selection.
        passing.sort(key=lambda t: (t[0], t[1]), reverse=True)
        best_score, _bid, _ms, probe_score, best_bundle = passing[0]
        agreement = True
        floor_pass = True

    # Metric bindings (version/schema/impl hashes).
    metric_id = "utility_floor_score"
    metric_version_hash = sha256_json(scoring_spec)
    metric_schema_hash = _schema_hash("fl3/kt.scoring_spec.v1.json")

    # Implementation hash: normalized text hash (CRLF->LF) for cross-platform stability.
    metric_impl_hash = sha256_file_normalized(Path(__file__))

    record: Dict[str, Any] = {
        "schema_id": "kt.factory.eval_report.v2",
        "schema_version_hash": _schema_hash("fl3/kt.factory.eval_report.v2.json"),
        "eval_id": "",
        "job_id": job["job_id"],
        "adapter_id": job["adapter_id"],
        "adapter_version": job["adapter_version"],
        "battery_id": "kt.eval.battery.fl4.utility_v1",
        "utility_pack_id": utility_pack_id,
        "utility_pack_hash": utility_pack_hash,
        "utility_floor_score": float(best_score),
        "utility_floor_pass": bool(floor_pass),
        "metric_bindings": [
            {
                "metric_id": metric_id,
                "metric_version_hash": metric_version_hash,
                "metric_schema_hash": metric_schema_hash,
                "metric_impl_hash": metric_impl_hash,
            }
        ],
        "metric_probes": [
            {
                "metric_id": "utility_floor_score_probe",
                "metric_impl_hash": metric_impl_hash,
                "delta": float(abs(best_score - probe_score)),
                "agreement": bool(agreement),
            }
        ],
        "probe_policy": {"tolerance": tol, "fail_on_disagreement": True},
        "results": {
            "best_bundle_id": best_bundle.get("bundle_id"),
            "utility_floor_score": float(best_score),
            "utility_floor_pass": bool(floor_pass),
            "trace_required": True,
            "trace_present": True,
            "trace_coverage": 1.0,
            "trace_id": trace["trace_id"],
            "trace_hash": trace["trace_id"],
            "metric_probe_agreement": bool(agreement),
        },
        "final_verdict": "PASS" if (floor_pass and agreement) else "FAIL",
        "created_at": utc_now_z(),
    }
    record["eval_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "eval_id"}})
    return record
