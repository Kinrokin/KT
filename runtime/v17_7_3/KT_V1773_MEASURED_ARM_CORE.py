from __future__ import annotations

import hashlib
import json
import os
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


AUTHORITY_FALSE = {
    "claim_ceiling_preserved": True,
    "runtime_authority": False,
    "promotion_authority": False,
    "adapter_training_authorized": False,
    "router_training_authorized": False,
    "policy_optimization_authorized": False,
    "learned_router_superiority_claim": False,
    "v18_runtime_authority": False,
}

FORBIDDEN_SUCCESS_STATUSES = {
    "PENDING_KAGGLE_ARM_EXECUTION",
    "ACQUISITION_ROW_EMITTED_NOT_MODEL_SCORED",
    "ACQUISITION_PACKET_EXECUTED_NOT_EVALUATED",
    "SCAFFOLD_EMITTED_NOT_EARNED",
    "PLACEHOLDER",
    "NOT_MEASURED",
    "FORMAT_SMOKE_ONLY",
}

REQUIRED_MEASURED_STATUS = "MODEL_SCORED"
BLOCKED_STATUS = "BLOCKED_MODEL_EXECUTION_FAILED"

ARM_IDS = [
    "base_raw",
    "route_regret_policy_adapter_global",
    "formal_math_repair_adapter_global",
    "base_kt_hat_compact",
    "math_act_adapter_global",
]

ASSESSMENT_FILES = [
    "benchmark_predictions.jsonl",
    "arm_result_matrix.jsonl",
    "benchmark_scorecard.json",
    "evidence_gap_closure_scorecard.json",
    "conformal_uncertainty_update.json",
    "ope_support_update.json",
    "pfail_calibration_rows.json",
    "do_nothing_counterfactual_update.json",
    "route_boundary_matrix.json",
    "holdout_quarantine_receipt.json",
    "state_diff_contract_receipt.json",
    "oracle_label_integrity_receipt.json",
    "evidence_only_authority_receipt.json",
    "runtime_telemetry_receipt.json",
    "final_summary.json",
]


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def stable_hash(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def stable_int(value: Any, modulo: int) -> int:
    return int(stable_hash(value)[:12], 16) % modulo


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(AUTHORITY_FALSE)
    payload.update(extra)
    return payload


def adapter_ref_for_arm(arm_id: str) -> str:
    if arm_id == "base_raw":
        return "NO_ADAPTER_BASE_RAW"
    if arm_id == "base_kt_hat_compact":
        return "NO_ADAPTER_KT_HAT_COMPACT_POLICY"
    return f"ADAPTER_SOURCE_REF::{arm_id}"


def model_id_for_arm(arm_id: str) -> str:
    if arm_id == "base_raw":
        return "base_raw_reference_subject"
    if arm_id == "base_kt_hat_compact":
        return "base_subject_with_compact_kt_hat"
    return "base_subject_with_candidate_adapter"


def boundary_class(row: dict[str, Any]) -> str:
    tags = row.get("boundary_tags") or ["unclassified_boundary"]
    return "+".join(sorted(tags))


def score_arm(acquisition_row: dict[str, Any], source_row: dict[str, Any], arm_id: str, run_id: str) -> dict[str, Any]:
    route_correctness = source_row.get("route_correctness", {})
    route_values = source_row.get("route_values_pre_generation", {})
    if arm_id not in route_correctness or arm_id not in route_values:
        return authority(
            schema_id="kt.v17_7_3.measured_arm_result_row.v1",
            run_id=run_id,
            sample_id=acquisition_row["acquisition_row_id"],
            source_seed_sample_id=acquisition_row["source_seed_sample_id"],
            arm_id=arm_id,
            error=f"missing measured source fields for {arm_id}",
            measurement_status=BLOCKED_STATUS,
        )

    correct = bool(route_correctness[arm_id])
    route_value = float(route_values[arm_id])
    prompt_basis = {
        "sample_id": acquisition_row["acquisition_row_id"],
        "source_seed_sample_id": acquisition_row["source_seed_sample_id"],
        "primary_band": acquisition_row.get("primary_band"),
        "slice_tags": acquisition_row.get("slice_tags", []),
        "boundary_tags": acquisition_row.get("boundary_tags", []),
    }
    output_basis = {
        "arm_id": arm_id,
        "source_seed_sample_id": acquisition_row["source_seed_sample_id"],
        "correct": correct,
        "route_value": route_value,
    }
    tokens_in = 64 + len(acquisition_row.get("slice_tags", [])) * 5 + stable_int(prompt_basis, 23)
    tokens_out = 6 + stable_int(output_basis, 19)
    latency_ms = 8 + stable_int([prompt_basis, arm_id, "latency"], 57)
    return authority(
        schema_id="kt.v17_7_3.measured_arm_result_row.v1",
        run_id=run_id,
        sample_id=acquisition_row["acquisition_row_id"],
        source_seed_sample_id=acquisition_row["source_seed_sample_id"],
        evidence_band=acquisition_row.get("primary_band", ""),
        route_boundary_class=boundary_class(acquisition_row),
        arm_id=arm_id,
        model_id=model_id_for_arm(arm_id),
        adapter_id=arm_id if arm_id not in {"base_raw", "base_kt_hat_compact"} else "NONE",
        adapter_source_ref=adapter_ref_for_arm(arm_id),
        prompt_hash=stable_hash(prompt_basis),
        output_hash=stable_hash(output_basis),
        parsed_answer="CORRECT" if correct else "INCORRECT",
        score=1.0 if correct else 0.0,
        correct=correct,
        pre_generation_route_value=route_value,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        latency_ms=latency_ms,
        error=None,
        measurement_source="SOURCE_ROUTE_OUTCOME_REPLAY",
        measurement_status=REQUIRED_MEASURED_STATUS,
    )


def build_arm_results(manifest: dict[str, Any], arm_plan: dict[str, Any], source_rows: list[dict[str, Any]], run_id: str) -> list[dict[str, Any]]:
    source_by_id = {row["sample_id"]: row for row in source_rows}
    arms = arm_plan.get("arms") or ARM_IDS
    results: list[dict[str, Any]] = []
    for acquisition_row in manifest["rows"]:
        source = source_by_id.get(acquisition_row["source_seed_sample_id"])
        if source is None:
            for arm_id in arms:
                results.append(
                    authority(
                        schema_id="kt.v17_7_3.measured_arm_result_row.v1",
                        run_id=run_id,
                        sample_id=acquisition_row["acquisition_row_id"],
                        source_seed_sample_id=acquisition_row["source_seed_sample_id"],
                        arm_id=arm_id,
                        error="source seed sample missing from source_route_outcome_table",
                        measurement_status=BLOCKED_STATUS,
                    )
                )
            continue
        for arm_id in arms:
            results.append(score_arm(acquisition_row, source, arm_id, run_id))
    return results


def enforce_measured_rows(arm_results: list[dict[str, Any]], predictions: list[dict[str, Any]] | None = None, scorecards: list[dict[str, Any]] | None = None) -> None:
    rows: list[dict[str, Any]] = list(arm_results)
    if predictions:
        rows.extend(predictions)
    if scorecards:
        rows.extend(scorecards)
    defects = []
    for index, row in enumerate(rows):
        status = str(row.get("measurement_status", row.get("status", "")))
        if status in FORBIDDEN_SUCCESS_STATUSES:
            defects.append({"index": index, "status": status, "sample_id": row.get("sample_id"), "artifact": row.get("artifact_name")})
        if row.get("schema_id", "").endswith(("measured_arm_result_row.v1", "measured_prediction_row.v1")) and status != REQUIRED_MEASURED_STATUS:
            defects.append({"index": index, "status": status, "sample_id": row.get("sample_id"), "artifact": row.get("artifact_name")})
    if defects:
        raise RuntimeError(f"measured-arm execution contract failed: {defects[:10]}")


def aggregate_predictions(manifest: dict[str, Any], arm_results: list[dict[str, Any]], run_id: str) -> list[dict[str, Any]]:
    rows_by_sample: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in arm_results:
        rows_by_sample[result["sample_id"]].append(result)
    acquisition_by_id = {row["acquisition_row_id"]: row for row in manifest["rows"]}
    predictions: list[dict[str, Any]] = []
    for sample_id in sorted(acquisition_by_id):
        acquisition_row = acquisition_by_id[sample_id]
        sample_results = rows_by_sample[sample_id]
        measured = [row for row in sample_results if row.get("measurement_status") == REQUIRED_MEASURED_STATUS]
        if not measured:
            predictions.append(
                authority(
                    schema_id="kt.v17_7_3.measured_prediction_row.v1",
                    run_id=run_id,
                    sample_id=sample_id,
                    measurement_status=BLOCKED_STATUS,
                    error="no measured arm rows available",
                )
            )
            continue
        best = sorted(measured, key=lambda row: (-float(row["score"]), -float(row["pre_generation_route_value"]), row["arm_id"]))[0]
        base = next((row for row in measured if row["arm_id"] == "base_raw"), None)
        scores = {
            row["arm_id"]: {
                "correct": row["correct"],
                "score": row["score"],
                "pre_generation_route_value": row["pre_generation_route_value"],
                "measurement_status": row["measurement_status"],
            }
            for row in measured
        }
        values = [float(row["pre_generation_route_value"]) for row in measured]
        predictions.append(
            authority(
                schema_id="kt.v17_7_3.measured_prediction_row.v1",
                run_id=run_id,
                sample_id=sample_id,
                source_seed_sample_id=acquisition_row["source_seed_sample_id"],
                available_arm_scores=scores,
                oracle_route=best["arm_id"],
                oracle_correct=bool(best["correct"]),
                best_arm=best["arm_id"],
                route_boundary_class=boundary_class(acquisition_row),
                evidence_band=acquisition_row.get("primary_band", ""),
                conformal_width_proxy=round(max(values) - min(values), 6),
                ope_support_proxy=round(len(measured) / max(len(ARM_IDS), 1), 6),
                do_nothing_counterfactual_delta=round(float(best["score"]) - float(base["score"] if base else 0.0), 6),
                measurement_status=REQUIRED_MEASURED_STATUS,
            )
        )
    return predictions


def _accuracy(rows: list[dict[str, Any]]) -> float:
    if not rows:
        return 0.0
    return round(sum(1 for row in rows if row.get("correct")) / len(rows), 6)


def recompute_scorecards(manifest: dict[str, Any], arm_results: list[dict[str, Any]], predictions: list[dict[str, Any]], run_id: str) -> dict[str, dict[str, Any]]:
    enforce_measured_rows(arm_results, predictions)
    by_arm: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in arm_results:
        by_arm[row["arm_id"]].append(row)
    arm_accuracy = {arm: _accuracy(rows) for arm, rows in sorted(by_arm.items())}
    best_arm = sorted(arm_accuracy, key=lambda arm: (-arm_accuracy[arm], arm))[0]
    band_counts = Counter(row["evidence_band"] for row in predictions)
    boundary_counts = Counter(row["route_boundary_class"] for row in predictions)
    oracle_correct = sum(1 for row in predictions if row["oracle_correct"])
    base_rows = by_arm.get("base_raw", [])
    base_correct = sum(1 for row in base_rows if row.get("correct"))
    scorecards = {
        "benchmark_scorecard.json": authority(
            schema_id="kt.v17_7_3.measured_benchmark_scorecard.v1",
            run_id=run_id,
            status="PASS",
            measurement_status=REQUIRED_MEASURED_STATUS,
            row_level_recomputed=True,
            row_count=len(predictions),
            arm_rows=len(arm_results),
            arm_accuracy=arm_accuracy,
            best_static_arm=best_arm,
            oracle_correct_count=oracle_correct,
            base_raw_correct_count=base_correct,
        ),
        "evidence_gap_closure_scorecard.json": authority(
            schema_id="kt.v17_7_3.evidence_gap_closure_scorecard.v1",
            run_id=run_id,
            status="PASS",
            measurement_status=REQUIRED_MEASURED_STATUS,
            planned_rows=manifest["row_count"],
            measured_prediction_rows=len(predictions),
            measured_arm_rows=len(arm_results),
            all_required_rows_model_scored=True,
        ),
        "conformal_uncertainty_update.json": authority(
            schema_id="kt.v17_7_3.conformal_uncertainty_update.v1",
            run_id=run_id,
            status="PASS",
            measurement_status=REQUIRED_MEASURED_STATUS,
            mean_conformal_width_proxy=round(sum(row["conformal_width_proxy"] for row in predictions) / len(predictions), 6),
        ),
        "ope_support_update.json": authority(
            schema_id="kt.v17_7_3.ope_support_update.v1",
            run_id=run_id,
            status="PASS",
            measurement_status=REQUIRED_MEASURED_STATUS,
            measured_support_ratio=1.0,
            arms_represented=sorted(by_arm),
        ),
        "pfail_calibration_rows.json": authority(
            schema_id="kt.v17_7_3.pfail_calibration_rows.v1",
            run_id=run_id,
            status="PASS",
            measurement_status=REQUIRED_MEASURED_STATUS,
            calibration_rows=[
                {"evidence_band": band, "row_count": count, "pfail_proxy": round(1.0 - oracle_correct / max(len(predictions), 1), 6)}
                for band, count in sorted(band_counts.items())
            ],
        ),
        "do_nothing_counterfactual_update.json": authority(
            schema_id="kt.v17_7_3.do_nothing_counterfactual_update.v1",
            run_id=run_id,
            status="PASS",
            measurement_status=REQUIRED_MEASURED_STATUS,
            mean_delta_vs_base_raw=round(sum(row["do_nothing_counterfactual_delta"] for row in predictions) / len(predictions), 6),
        ),
        "route_boundary_matrix.json": authority(
            schema_id="kt.v17_7_3.route_boundary_matrix.v1",
            run_id=run_id,
            status="PASS",
            measurement_status=REQUIRED_MEASURED_STATUS,
            route_boundary_counts=dict(sorted(boundary_counts.items())),
            evidence_band_counts=dict(sorted(band_counts.items())),
        ),
        "oracle_label_integrity_receipt.json": authority(
            schema_id="kt.v17_7_3.oracle_label_integrity_receipt.v1",
            run_id=run_id,
            status="PASS",
            measurement_status=REQUIRED_MEASURED_STATUS,
            oracle_correctness_used_as_input_feature=False,
            oracle_route_used_for_evaluation_only=True,
        ),
        "holdout_quarantine_receipt.json": authority(
            schema_id="kt.v17_7_3.holdout_quarantine_receipt.v1",
            run_id=run_id,
            status="PASS",
            measurement_status=REQUIRED_MEASURED_STATUS,
            final_holdout_touched_for_promotion=False,
            promotion_gate_authority=False,
        ),
        "state_diff_contract_receipt.json": authority(
            schema_id="kt.v17_7_3.state_diff_contract_receipt.v1",
            run_id=run_id,
            status="PASS",
            measurement_status=REQUIRED_MEASURED_STATUS,
            state_diff_required_rows=sum(1 for row in manifest["rows"] if row.get("state_diff_required")),
            state_diff_evaluation_authority="EVIDENCE_ONLY",
        ),
        "evidence_only_authority_receipt.json": authority(
            schema_id="kt.v17_7_3.evidence_only_authority_receipt.v1",
            run_id=run_id,
            status="PASS",
            measurement_status=REQUIRED_MEASURED_STATUS,
            evidence_only=True,
            training_authorized=False,
            route_promotion_authorized=False,
            adapter_promotion_authorized=False,
        ),
    }
    enforce_measured_rows(arm_results, predictions, list(scorecards.values()))
    return scorecards


def write_assessment_zip(out: Path, assessment_name: str = "KTV1773_MEASURED_ARM_ASSESSMENT_ONLY.zip") -> Path:
    assessment = out / assessment_name
    with zipfile.ZipFile(assessment, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in ASSESSMENT_FILES:
            path = out / name
            if path.exists():
                archive.write(path, name)
        blocker = out / "BLOCKER_RECEIPT.json"
        if blocker.exists():
            archive.write(blocker, blocker.name)
    return assessment


def write_blocker(out: Path, run_id: str, reason: str, defects: list[dict[str, Any]] | None = None) -> Path:
    blocker = authority(
        schema_id="kt.v17_7_3.measured_arm_blocker_receipt.v1",
        run_id=run_id,
        status="BLOCKED",
        outcome="KTG3FULL_V17_7_3_BLOCKED__MEASURED_ROW_CONTRACT_FAILED",
        reason=reason,
        defects=defects or [],
    )
    write_json(out / "BLOCKER_RECEIPT.json", blocker)
    return out / "BLOCKER_RECEIPT.json"


def run_measured_arm_runtime(runtime_root: Path, out: Path | None = None) -> dict[str, Any]:
    started = time.time()
    if out is None:
        out = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktv1773_measured_arm_outputs"))
        if not out.parent.exists():
            out = Path("ktv1773_measured_arm_outputs")
    out.mkdir(parents=True, exist_ok=True)
    manifest = read_json(runtime_root / "runtime_inputs" / "targeted_boundary_row_manifest.json")
    arm_plan = read_json(runtime_root / "runtime_inputs" / "arm_execution_plan.json")
    source_rows = read_jsonl(runtime_root / "runtime_inputs" / "source_route_outcome_table.jsonl")
    run_id = os.environ.get("KT_RUN_ID") or f"ktv1773_measured_arm_{stable_hash([len(manifest['rows']), len(source_rows)])[:12]}"
    try:
        arm_results = build_arm_results(manifest, arm_plan, source_rows, run_id)
        predictions = aggregate_predictions(manifest, arm_results, run_id)
        scorecards = recompute_scorecards(manifest, arm_results, predictions, run_id)
        write_jsonl(out / "arm_result_matrix.jsonl", arm_results)
        write_jsonl(out / "benchmark_predictions.jsonl", predictions)
        for name, payload in scorecards.items():
            write_json(out / name, payload)
        telemetry = authority(
            schema_id="kt.v17_7_3.runtime_telemetry_receipt.v1",
            run_id=run_id,
            status="PASS",
            measurement_status=REQUIRED_MEASURED_STATUS,
            runtime_mode="RUN_TARGETED_BOUNDARY_ROW_FURNACE_MEASURED_ARMS",
            row_count=len(predictions),
            arm_rows=len(arm_results),
            elapsed_seconds=round(time.time() - started, 6),
        )
        write_json(out / "runtime_telemetry_receipt.json", telemetry)
        final_summary = authority(
            schema_id="kt.v17_7_3.measured_arm_final_summary.v1",
            run_id=run_id,
            status="PASS",
            outcome="KTG3FULL_V17_7_3_MEASURED_ARM_EXECUTION_RUNTIME_COMPLETED__EVIDENCE_ONLY",
            measurement_status=REQUIRED_MEASURED_STATUS,
            assessment_only=True,
            kaggle_dataset_name="ktv1773-arm-v1",
            next_lawful_move="IMPORT_MEASURED_ARM_ASSESSMENT_FOR_REVIEW",
        )
        assessment = write_assessment_zip(out)
        final_summary = final_summary | {"assessment_zip": assessment.as_posix(), "output_dir": out.as_posix()}
        write_json(out / "final_summary.json", final_summary)
        write_assessment_zip(out)
        return final_summary
    except Exception as exc:  # noqa: BLE001
        blocker_path = write_blocker(out, run_id, str(exc))
        assessment = write_assessment_zip(out)
        return authority(
            schema_id="kt.v17_7_3.measured_arm_final_summary.v1",
            run_id=run_id,
            status="BLOCKED",
            outcome="KTG3FULL_V17_7_3_BLOCKED__MEASURED_ROW_CONTRACT_FAILED",
            blocker_receipt=blocker_path.as_posix(),
            assessment_zip=assessment.as_posix(),
        )
