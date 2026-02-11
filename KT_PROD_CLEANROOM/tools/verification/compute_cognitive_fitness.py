from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash
from tools.verification.fl3_validators import (
    FL3ValidationError,
    assert_path_under_exports,
    read_json,
    repo_root_from,
    validate_schema_bound_object,
)


_AXES = (
    "reasoning_depth",
    "transfer_capacity",
    "coherence_under_pressure",
    "self_correction",
    "epistemic_behavior",
    "novel_structure",
)


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _stable_axis_score(*, axis: str, prompt: str, baseline: str) -> float:
    h = hashlib.sha256(f"{axis}|{prompt}|{baseline}".encode("utf-8")).digest()
    n = int.from_bytes(h[:8], "big", signed=False)
    u = n / float(2**64)
    return 0.25 + 0.50 * u


def _law_bundle_hash(*, repo_root: Path) -> str:
    p = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.sha256"
    if not p.exists():
        raise FL3ValidationError("Missing LAW_BUNDLE_FL3.sha256 (fail-closed)")
    return p.read_text(encoding="utf-8").strip()


def _anchor_cache_key(
    *,
    battery_manifest_hash: str,
    baseline_model_hash: str,
    metric_definition_hash: str,
    anchor_set_id: str,
) -> str:
    payload = f"{battery_manifest_hash}|{baseline_model_hash}|{metric_definition_hash}|{anchor_set_id}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _baseline_model_hash(anchor: Dict[str, Any]) -> str:
    baseline = str(anchor.get("baseline_model_id", ""))
    gp = anchor.get("generation_params") if isinstance(anchor.get("generation_params"), dict) else {}
    payload = {"baseline_model_id": baseline, "generation_params": gp}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def _metric_definition_hash() -> str:
    # Bind the axis evaluation definition by schema version hashes (stable, fail-closed).
    # This prevents cache reuse across incompatible axis semantics.
    payload = {
        "discovery_battery_result": schema_version_hash("fl3/kt.discovery_battery_result.v1.json"),
        "cognitive_fitness": schema_version_hash("fl3/kt.cognitive_fitness.v2.json"),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def _battery_manifest_hash(*, battery_result: Dict[str, Any]) -> str:
    # Best-effort binding: battery_id is already content-addressed in FL3.
    return str(battery_result.get("battery_id", ""))


def _compute_anchor_eval_bundle(anchor: Dict[str, Any]) -> Dict[str, Any]:
    items = anchor.get("items")
    if not isinstance(items, list) or len(items) < 1:
        raise FL3ValidationError("Anchor items missing (fail-closed)")
    per_item: List[Dict[str, Any]] = []
    totals: Dict[str, float] = {k: 0.0 for k in _AXES}
    for it in items:
        if not isinstance(it, dict):
            continue
        prompt = str(it.get("prompt", ""))
        baseline = str(it.get("baseline_response", ""))
        scores = {axis: _stable_axis_score(axis=axis, prompt=prompt, baseline=baseline) for axis in _AXES}
        for axis in _AXES:
            totals[axis] += float(scores[axis])
        per_item.append({"prompt_hash": hashlib.sha256(prompt.encode("utf-8")).hexdigest(), "axis_scores": scores})

    n = float(len(per_item))
    axis_scores = {axis: max(0.0, min(1.0, totals[axis] / n)) for axis in _AXES}
    return {"anchor_set_id": str(anchor["anchor_set_id"]), "axis_scores": axis_scores, "items": per_item}


def _load_or_build_anchor_eval(
    *,
    repo_root: Path,
    cache_root: Optional[Path],
    battery_result: Dict[str, Any],
    anchor: Dict[str, Any],
) -> Tuple[Dict[str, Any], str]:
    bundle = _compute_anchor_eval_bundle(anchor)
    cache_key = _anchor_cache_key(
        battery_manifest_hash=_battery_manifest_hash(battery_result=battery_result),
        baseline_model_hash=_baseline_model_hash(anchor),
        metric_definition_hash=_metric_definition_hash(),
        anchor_set_id=str(anchor["anchor_set_id"]),
    )
    law_hash = _law_bundle_hash(repo_root=repo_root)

    if cache_root is not None:
        cache_root.mkdir(parents=True, exist_ok=True)
        cache_path = cache_root / f"anchor_eval_{cache_key}.json"
        if cache_path.exists():
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            if not isinstance(cached, dict) or cached.get("cache_key") != cache_key or cached.get("law_bundle_hash") != law_hash:
                raise FL3ValidationError("Anchor cache record invalid (fail-closed)")
            if cached.get("bundle") != bundle:
                raise FL3ValidationError("Anchor cache mismatch vs recompute (fail-closed)")
            sig = cached.get("signature")
            payload = {"cache_key": cache_key, "law_bundle_hash": law_hash, "bundle": bundle}
            expected_sig = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            ).hexdigest()
            if sig != expected_sig:
                raise FL3ValidationError("Anchor cache signature mismatch (fail-closed)")
        else:
            payload = {"cache_key": cache_key, "law_bundle_hash": law_hash, "bundle": bundle}
            signature = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            ).hexdigest()
            cache_path.write_text(
                json.dumps({"cache_key": cache_key, "law_bundle_hash": law_hash, "bundle": bundle, "signature": signature}, sort_keys=True, indent=2, ensure_ascii=True)
                + "\n",
                encoding="utf-8",
            )

    anchor_eval_hash = hashlib.sha256(
        json.dumps(bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    return bundle, anchor_eval_hash


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def compute_cognitive_fitness(
    *,
    battery_result: Dict[str, Any],
    anchor: Dict[str, Any],
    role_spec: Dict[str, Any],
    policy: Dict[str, Any],
    role_id: str,
    anchor_cache_root: Optional[Path] = None,
) -> Dict[str, Any]:
    validate_schema_bound_object(battery_result)
    validate_schema_bound_object(anchor)
    validate_schema_bound_object(role_spec)
    validate_schema_bound_object(policy)

    if policy.get("schema_id") != "kt.cognitive_fitness_policy.v1":
        raise FL3ValidationError("COGNITIVE_FITNESS_POLICY schema_id mismatch (fail-closed)")

    raw_axes = battery_result.get("axis_scores")
    if not isinstance(raw_axes, dict):
        raise FL3ValidationError("battery_result.axis_scores missing (fail-closed)")
    for axis in _AXES:
        if axis not in raw_axes:
            raise FL3ValidationError("battery_result.axis_scores missing axis (fail-closed)")

    anchor_eval_bundle, anchor_eval_hash = _load_or_build_anchor_eval(
        repo_root=repo_root_from(Path(__file__)),
        cache_root=anchor_cache_root,
        battery_result=battery_result,
        anchor=anchor,
    )
    anchor_axes = anchor_eval_bundle["axis_scores"]

    # Evidence hashes are content-addressed values used for replay auditing.
    battery_bundle_hash = hashlib.sha256(
        json.dumps(battery_result, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    trace_replay_report = {"trace_replay": "SKIPPED", "job_id": str(battery_result.get("job_id"))}
    trace_replay_hash = hashlib.sha256(
        json.dumps(trace_replay_report, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()

    axes: Dict[str, Dict[str, float]] = {}
    for axis in _AXES:
        raw = float(raw_axes[axis])
        baseline = float(anchor_axes[axis])
        delta = raw - baseline
        normalized = _clamp01(0.5 + delta)
        axes[axis] = {"raw_score": raw, "anchor_delta": delta, "normalized_score": normalized}

    canary_pass = bool(battery_result.get("canary_pass"))
    role_drift_flag = bool(battery_result.get("role_drift_flag"))

    role_weighting = policy.get("role_weighting")
    if not isinstance(role_weighting, dict) or role_id not in role_weighting:
        raise FL3ValidationError("policy.role_weighting missing role_id (fail-closed)")
    weights = role_weighting[role_id]
    if not isinstance(weights, dict) or len(weights) < 1:
        raise FL3ValidationError("policy.role_weighting role entry invalid (fail-closed)")
    total_w = 0.0
    score = 0.0
    for axis, w in weights.items():
        if axis not in axes:
            raise FL3ValidationError("policy.role_weighting references unknown axis (fail-closed)")
        ww = float(w)
        total_w += ww
        score += ww * float(axes[axis]["normalized_score"])
    if total_w <= 0.0:
        raise FL3ValidationError("policy.role_weighting total weight invalid (fail-closed)")
    weighted_score = score / total_w

    thresholds = policy["promotion_thresholds"]
    promote_min = float(thresholds["promote_min"])
    shadow_min = float(thresholds["shadow_min"])

    if policy.get("canary_rule") == "FAIL_IF_FALSE" and not canary_pass:
        verdict = "HALT"
    elif policy.get("role_drift_rule") == "FAIL_IF_TRUE" and role_drift_flag:
        verdict = "SHADOW"
    elif weighted_score >= promote_min:
        verdict = "PROMOTE"
    elif weighted_score >= shadow_min:
        verdict = "SHADOW"
    else:
        verdict = "QUARANTINE"

    record: Dict[str, Any] = {
        "schema_id": "kt.cognitive_fitness.v2",
        "schema_version_hash": schema_version_hash("fl3/kt.cognitive_fitness.v2.json"),
        "fitness_id": "",
        "adapter_id": str(battery_result["adapter_id"]),
        "adapter_version": str(battery_result["adapter_version"]),
        "job_id": str(battery_result["job_id"]),
        "axes": axes,
        "promotion_verdict": verdict,
        "canary_pass": canary_pass,
        "role_id": role_id,
        "role_drift_flag": role_drift_flag,
        "evidence": {
            "anchor_set_id": str(anchor["anchor_set_id"]),
            "battery_id": str(battery_result["battery_id"]),
            "battery_result_id": str(battery_result["result_id"]),
            "role_spec_id": str(role_spec["role_spec_id"]),
            "evidence_hashes": {
                "battery_bundle_hash": battery_bundle_hash,
                "anchor_eval_hash": anchor_eval_hash,
                "trace_replay_hash": trace_replay_hash,
            },
        },
        "created_at": _utc_now_z(),
    }
    record["fitness_id"] = sha256_hex_of_obj(record, drop_keys={"created_at", "fitness_id"})
    validate_schema_bound_object(record)

    return record, trace_replay_report


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--battery-result", required=True)
    ap.add_argument("--role-id", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--trace-replay-out", required=True)
    ap.add_argument("--anchor", default="KT_PROD_CLEANROOM/AUDITS/ANCHOR_REFERENCE_SET.json")
    ap.add_argument("--role-spec", default="KT_PROD_CLEANROOM/AUDITS/ROLE_FITNESS_WEIGHTS.json")
    ap.add_argument("--policy", default="KT_PROD_CLEANROOM/AUDITS/COGNITIVE_FITNESS_POLICY.json")
    ap.add_argument("--anchor-cache-root", default="KT_PROD_CLEANROOM/exports/adapters_shadow/_anchor_cache")
    args = ap.parse_args(argv)

    repo_root = repo_root_from(Path(__file__))
    out_path = (repo_root / args.out).resolve()
    trace_out_path = (repo_root / args.trace_replay_out).resolve()
    assert_path_under_exports(repo_root=repo_root, path=out_path, allow_promoted=True)
    assert_path_under_exports(repo_root=repo_root, path=trace_out_path, allow_promoted=True)

    battery_result = read_json((repo_root / args.battery_result).resolve())
    anchor = read_json((repo_root / args.anchor).resolve())
    role_spec = read_json((repo_root / args.role_spec).resolve())
    policy = read_json((repo_root / args.policy).resolve())
    cache_root = (repo_root / args.anchor_cache_root).resolve() if args.anchor_cache_root else None
    if cache_root is not None:
        assert_path_under_exports(repo_root=repo_root, path=cache_root, allow_promoted=True)

    record, trace_replay_report = compute_cognitive_fitness(
        battery_result=battery_result,
        anchor=anchor,
        role_spec=role_spec,
        policy=policy,
        role_id=str(args.role_id),
        anchor_cache_root=cache_root,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, sort_keys=True, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    trace_out_path.parent.mkdir(parents=True, exist_ok=True)
    trace_out_path.write_text(
        json.dumps(trace_replay_report, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
