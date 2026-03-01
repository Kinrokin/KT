from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from schemas.fl3_schema_common import sha256_hex_of_obj
from tools.eval.validator_engine import ValidatorError, evaluate_validators
from tools.training.fl3_factory.manifests import sha256_file as sha256_file_canonical
from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import repo_root_from
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.worm_write import write_text_worm


_SUITE_SCHEMA_ID = "kt.suite_definition.v1"
_CAT_SCHEMA_IDS = {"kt.validator_catalog.v1", "kt.validator_catalog.v2"}
_POLICY_SCHEMA_ID = "kt.axis_scoring_policy.v1"
_OUTPUTS_SCHEMA_ID = "kt.suite_outputs.v1"
_EVAL_SCHEMA_ID = "kt.suite_eval_report.v1"
_FITNESS_SCHEMA_ID = "kt.axis_fitness_report.v1"


def _read_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"FAIL_CLOSED: unreadable JSON {name}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"FAIL_CLOSED: {name} must be a JSON object: {path.as_posix()}")
    return obj


def _load_ref(repo_root: Path, ref: str) -> Path:
    r = str(ref).replace("\\", "/").strip()
    if not r:
        raise FL3ValidationError("FAIL_CLOSED: missing ref path")
    p = Path(r)
    if p.is_absolute():
        return p.resolve()
    return (repo_root / r).resolve()


def _compute_axis_scores(
    *, policy: Dict[str, Any], suite_case_results: Dict[str, Dict[str, Any]]
) -> tuple[Dict[str, float], bool]:
    axes = policy.get("axes") if isinstance(policy.get("axes"), list) else []
    thresholds = policy.get("verdict_thresholds") if isinstance(policy.get("verdict_thresholds"), dict) else {}
    quarantine_on_gate_fail = bool(thresholds.get("quarantine_on_gate_fail", True))

    axis_scores: Dict[str, float] = {}
    gate_ok_all = True

    def _aggregate(values: List[float], *, aggregator: str) -> float:
        if not values:
            return 0.0
        agg = str(aggregator).strip().upper()
        if agg == "MEAN":
            return float(sum(values)) / float(len(values))
        if agg == "TRIMMED_MEAN_5":
            n = len(values)
            k = int(float(n) * 0.05)
            if k <= 0:
                return float(sum(values)) / float(n)
            vs = sorted(float(x) for x in values)
            trimmed = vs[k : n - k]
            if not trimmed:
                return float(sum(vs)) / float(n)
            return float(sum(trimmed)) / float(len(trimmed))
        raise FL3ValidationError(f"FAIL_CLOSED: unknown aggregator: {aggregator!r}")

    for ax in axes:
        if not isinstance(ax, dict):
            continue
        axis_id = str(ax.get("axis_id", "")).strip()
        gate_ids = ax.get("gate_validator_ids") if isinstance(ax.get("gate_validator_ids"), list) else []
        soft = ax.get("soft_validator_weights") if isinstance(ax.get("soft_validator_weights"), list) else []
        aggregator = str(ax.get("aggregator", "")).strip().upper()
        if aggregator not in {"MEAN", "TRIMMED_MEAN_5"}:
            raise FL3ValidationError(f"FAIL_CLOSED: invalid axis aggregator: {axis_id} aggregator={aggregator!r}")

        # Gate: any failure of any gate validator across any case trips the gate.
        gate_ok = True
        gate_id_set = {str(x).strip() for x in gate_ids if isinstance(x, str) and x.strip()}
        if gate_id_set:
            found_any = False
            for case in suite_case_results.values():
                vrs = case.get("validator_results") if isinstance(case.get("validator_results"), list) else []
                for vr in vrs:
                    if not isinstance(vr, dict):
                        continue
                    vid = str(vr.get("validator_id", "")).strip()
                    if vid in gate_id_set:
                        found_any = True
                        if not bool(vr.get("passed", False)):
                            gate_ok = False
            if not found_any:
                raise FL3ValidationError(f"FAIL_CLOSED: axis gate validators not present in suite results: {axis_id}")

        # Soft score: weighted mean across per-validator aggregates, where each validator's
        # aggregate uses the axis-level aggregator (MEAN or TRIMMED_MEAN_5) across occurrences.
        weights: Dict[str, float] = {}
        for row in soft:
            if not isinstance(row, dict):
                continue
            vid = str(row.get("validator_id", "")).strip()
            w = row.get("weight")
            if not vid or not isinstance(w, (int, float)):
                continue
            weights[vid] = float(w)

        if not weights:
            raise FL3ValidationError(f"FAIL_CLOSED: axis has no soft validators: {axis_id}")

        scores_by_vid: Dict[str, List[float]] = {k: [] for k in weights.keys()}
        for case in suite_case_results.values():
            vrs = case.get("validator_results") if isinstance(case.get("validator_results"), list) else []
            for vr in vrs:
                if not isinstance(vr, dict):
                    continue
                vid = str(vr.get("validator_id", "")).strip()
                if vid not in scores_by_vid:
                    continue
                scores_by_vid[vid].append(float(vr.get("score", 0.0)))

        missing = sorted([k for k, v in scores_by_vid.items() if not v])
        if missing:
            raise FL3ValidationError(f"FAIL_CLOSED: axis soft validators missing from suite results: {axis_id} missing={missing}")
        denom = float(sum(weights.values()))
        if denom <= 0.0:
            raise FL3ValidationError(f"FAIL_CLOSED: axis soft validator weights sum to <= 0: {axis_id}")
        numer = 0.0
        for vid, vals in scores_by_vid.items():
            numer += float(weights[vid]) * float(_aggregate(vals, aggregator=aggregator))
        score = max(0.0, min(1.0, float(numer / denom)))
        if not gate_ok and quarantine_on_gate_fail:
            score = 0.0
        axis_scores[axis_id] = score
        gate_ok_all = gate_ok_all and gate_ok

    return {k: axis_scores[k] for k in sorted(axis_scores.keys())}, bool(gate_ok_all)


def _decision(*, policy: Dict[str, Any], axis_scores: Dict[str, float], hard_gate_pass: bool) -> str:
    thresholds = policy.get("verdict_thresholds") if isinstance(policy.get("verdict_thresholds"), dict) else {}
    quarantine_on_gate_fail = bool(thresholds.get("quarantine_on_gate_fail", True))
    promote_min = thresholds.get("promote_min") if isinstance(thresholds.get("promote_min"), dict) else {}
    hold_min = thresholds.get("hold_min") if isinstance(thresholds.get("hold_min"), dict) else {}

    if quarantine_on_gate_fail and not hard_gate_pass:
        return "QUARANTINE"

    def _all_ge(th: Dict[str, Any]) -> bool:
        for ax, v in axis_scores.items():
            if ax not in th:
                return False
            if float(v) < float(th.get(ax)):
                return False
        return True

    if _all_ge(promote_min):
        return "PROMOTE"
    if _all_ge(hold_min):
        return "HOLD"
    return "QUARANTINE"


def run_suite_eval(*, suite_def_path: Path, suite_outputs_path: Path, out_dir: Path) -> tuple[Dict[str, Any], Dict[str, Any]]:
    repo_root = repo_root_from(Path(__file__))

    suite_def = _read_json_dict(suite_def_path, name="suite_definition")
    validate_schema_bound_object(suite_def)
    if suite_def.get("schema_id") != _SUITE_SCHEMA_ID:
        raise FL3ValidationError("FAIL_CLOSED: suite_definition schema_id mismatch")

    suite_root_hash = sha256_file_canonical(suite_def_path.resolve())
    if not str(suite_def.get("suite_id", "")).strip():
        raise FL3ValidationError("FAIL_CLOSED: suite_id missing")

    outputs = _read_json_dict(suite_outputs_path, name="suite_outputs")
    validate_schema_bound_object(outputs)
    if outputs.get("schema_id") != _OUTPUTS_SCHEMA_ID:
        raise FL3ValidationError("FAIL_CLOSED: suite_outputs schema_id mismatch")

    if str(outputs.get("suite_id", "")).strip() != str(suite_def.get("suite_id", "")).strip():
        raise FL3ValidationError("FAIL_CLOSED: suite_outputs.suite_id mismatch vs suite_definition")
    if str(outputs.get("suite_root_hash", "")).strip() != suite_root_hash:
        raise FL3ValidationError("FAIL_CLOSED: suite_outputs.suite_root_hash mismatch vs suite_definition hash")

    cat_ref = str(suite_def.get("validator_catalog_ref", "")).strip()
    policy_ref = str(suite_def.get("axis_scoring_policy_ref", "")).strip()
    cat_path = _load_ref(repo_root, cat_ref)
    policy_path = _load_ref(repo_root, policy_ref)

    catalog = _read_json_dict(cat_path, name="validator_catalog")
    validate_schema_bound_object(catalog)
    if catalog.get("schema_id") not in _CAT_SCHEMA_IDS:
        raise FL3ValidationError("FAIL_CLOSED: validator_catalog schema_id mismatch")
    if str(catalog.get("validator_catalog_id", "")).strip() != str(suite_def.get("validator_catalog_id", "")).strip():
        raise FL3ValidationError("FAIL_CLOSED: suite_definition.validator_catalog_id mismatch")

    policy = _read_json_dict(policy_path, name="axis_scoring_policy")
    validate_schema_bound_object(policy)
    if policy.get("schema_id") != _POLICY_SCHEMA_ID:
        raise FL3ValidationError("FAIL_CLOSED: axis_scoring_policy schema_id mismatch")
    if str(policy.get("axis_scoring_policy_id", "")).strip() != str(suite_def.get("axis_scoring_policy_id", "")).strip():
        raise FL3ValidationError("FAIL_CLOSED: suite_definition.axis_scoring_policy_id mismatch")

    cases = suite_def.get("cases") if isinstance(suite_def.get("cases"), list) else []
    case_ids = [str(c.get("case_id", "")).strip() for c in cases if isinstance(c, dict)]
    out_rows = outputs.get("outputs") if isinstance(outputs.get("outputs"), list) else []
    out_case_ids = [str(r.get("case_id", "")).strip() for r in out_rows if isinstance(r, dict)]
    if sorted(case_ids) != sorted(out_case_ids):
        raise FL3ValidationError("FAIL_CLOSED: suite_outputs case_id set mismatch vs suite_definition")

    by_case_output = {str(r.get("case_id", "")).strip(): str(r.get("output_text", "")) for r in out_rows if isinstance(r, dict)}

    case_results: List[Dict[str, Any]] = []
    suite_case_results_map: Dict[str, Dict[str, Any]] = {}
    any_fail = False
    for c in sorted([c for c in cases if isinstance(c, dict)], key=lambda d: str(d.get("case_id", ""))):
        cid = str(c.get("case_id", "")).strip()
        output_text = by_case_output.get(cid, "")
        validator_ids = c.get("validator_ids") if isinstance(c.get("validator_ids"), list) else []
        vids = [str(x).strip() for x in validator_ids if isinstance(x, str) and x.strip()]
        try:
            vrs = evaluate_validators(validator_catalog=catalog, validator_ids=vids, output_text=output_text)
        except ValidatorError as exc:
            raise FL3ValidationError(f"FAIL_CLOSED: validator execution error: {exc}") from exc

        passed = all(r.passed for r in vrs)
        any_fail = any_fail or (not passed)
        failed_ids = sorted([r.validator_id for r in vrs if not r.passed])
        vr_rows = [
            {"validator_id": r.validator_id, "passed": bool(r.passed), "score": float(r.score), "notes": r.notes}
            for r in vrs
        ]
        row = {"case_id": cid, "passed": bool(passed), "failed_validator_ids": failed_ids, "validator_results": vr_rows, "notes": None}
        case_results.append(row)
        suite_case_results_map[cid] = row

    created_at = utc_now_z()
    # Build schema-bound payload using registry-driven schema_version_hashes.
    from schemas.schema_files import schema_version_hash  # type: ignore

    suite_eval_report = {
        "schema_id": _EVAL_SCHEMA_ID,
        "schema_version_hash": schema_version_hash("fl3/kt.suite_eval_report.v1.json"),
        "suite_eval_report_id": "",
        "suite_outputs_id": str(outputs.get("suite_outputs_id", "")).strip(),
        "suite_definition_id": str(suite_def.get("suite_definition_id", "")).strip(),
        "validator_catalog_id": str(catalog.get("validator_catalog_id", "")).strip(),
        "axis_scoring_policy_id": str(policy.get("axis_scoring_policy_id", "")).strip(),
        "status": "FAIL" if any_fail else "PASS",
        "case_results": case_results,
        "created_at": created_at,
        "notes": None,
    }
    suite_eval_report["suite_eval_report_id"] = sha256_hex_of_obj(
        suite_eval_report, drop_keys={"created_at", "suite_eval_report_id"}
    )
    validate_schema_bound_object(suite_eval_report)

    axis_scores, hard_gate_pass = _compute_axis_scores(policy=policy, suite_case_results=suite_case_results_map)
    decision = _decision(policy=policy, axis_scores=axis_scores, hard_gate_pass=hard_gate_pass)

    axis_fitness_report: Dict[str, Any] = {
        "schema_id": _FITNESS_SCHEMA_ID,
        "schema_version_hash": schema_version_hash("fl3/kt.axis_fitness_report.v1.json"),
        "axis_fitness_report_id": "",
        "suite_eval_report_id": str(suite_eval_report.get("suite_eval_report_id", "")).strip(),
        "axis_scoring_policy_id": str(policy.get("axis_scoring_policy_id", "")).strip(),
        "decision": decision,
        "axis_scores": axis_scores,
        "hard_gate_pass": bool(hard_gate_pass),
        "created_at": created_at,
        "notes": None,
    }
    axis_fitness_report["axis_fitness_report_id"] = sha256_hex_of_obj(
        axis_fitness_report, drop_keys={"created_at", "axis_fitness_report_id"}
    )
    validate_schema_bound_object(axis_fitness_report)

    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    write_text_worm(
        path=out_dir / "suite_eval_report.json",
        text=json.dumps(suite_eval_report, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        label="suite_eval_report.json",
    )
    write_text_worm(
        path=out_dir / "axis_fitness_report.json",
        text=json.dumps(axis_fitness_report, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        label="axis_fitness_report.json",
    )
    return suite_eval_report, axis_fitness_report


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="EPIC_17 deterministic suite evaluator (consumes suite_outputs; emits eval + axis fitness reports WORM).")
    ap.add_argument("--suite-def", required=True, help="Path to kt.suite_definition.v1 JSON.")
    ap.add_argument("--suite-outputs", required=True, help="Path to kt.suite_outputs.v1 JSON.")
    ap.add_argument("--out-dir", required=True, help="Output directory (WORM writes suite_eval_report.json + axis_fitness_report.json).")
    args = ap.parse_args(list(argv) if argv is not None else None)

    _ = run_suite_eval(suite_def_path=Path(args.suite_def), suite_outputs_path=Path(args.suite_outputs), out_dir=Path(args.out_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
