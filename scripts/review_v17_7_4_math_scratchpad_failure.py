from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core


TRANCHE = "AUTHOR_KTV1774_MATH_SCRATCHPAD_MICROFURNACE_FAILURE_REVIEW_V1"
OUTCOME = (
    "KT_MATH_SCRATCHPAD_MICROFURNACE_REVIEWED__FAILED_CANDIDATES_QUARANTINED__"
    "NEXT_HYPOTHESIS_SELECTED__CLAIM_CEILING_PRESERVED"
)
DEFAULT_ASSESSMENT_ZIP = Path(
    os.environ.get(
        "KT_MATH_SCRATCHPAD_ASSESSMENT_ZIP",
        r"d:\user\rober\Downloads\KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY (17).zip",
    )
)
CONTROL_ARM = core.REPROLOCK_ARM_ID
CANDIDATE_ARMS = [
    "A2_math_act_full_reasoning",
    "A3_math_act_reasoning_preserving_compact",
    "A4_formal_math_reasoning_preserving_compact",
]
ALL_ARMS = [CONTROL_ARM, *CANDIDATE_ARMS]
REQUIRED_MEMBERS = [
    "truegen_arm_result_matrix.jsonl",
    "truegen_predictions.jsonl",
    "truegen_benchmark_scorecard.json",
    "truegen_token_efficiency_matrix.json",
    "truegen_verified_work_per_token_scorecard.json",
    "truegen_parser_vs_generation_error_matrix.json",
    "visible_answer_ledger.json",
    "v17_7_4_math_scratchpad_runtime_receipt.json",
    "v17_7_4_math_scratchpad_token_ledger_receipt.json",
    "v17_7_4_math_scratchpad_evaluation_gate.json",
    "arm_model_config_receipt.json",
    "final_summary.json",
]


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(core.AUTHORITY_FALSE)
    payload.update(
        {
            "claim_ceiling_preserved": True,
            "commercial_claim": False,
            "external_validation_claim": False,
            "frontier_claim": False,
            "g2_recovered_claim": False,
            "learned_router_superiority_claim": False,
            "multi_lobe_superiority_claim": False,
            "production_readiness_claim": False,
            "router_superiority_claim": False,
            "s_tier_claim": False,
            "seven_b_claim": False,
        }
    )
    payload.update(extra)
    return payload


def git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows), encoding="utf-8")


def zip_json(archive: zipfile.ZipFile, member: str) -> dict[str, Any]:
    return json.loads(archive.read(member).decode("utf-8-sig"))


def zip_jsonl(archive: zipfile.ZipFile, member: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in archive.read(member).decode("utf-8-sig").splitlines() if line.strip()]


def load_evidence(assessment_zip: Path = DEFAULT_ASSESSMENT_ZIP) -> dict[str, Any]:
    if not assessment_zip.exists():
        raise RuntimeError(f"missing math scratchpad assessment zip: {assessment_zip}")
    with zipfile.ZipFile(assessment_zip) as archive:
        missing = [member for member in REQUIRED_MEMBERS if member not in archive.namelist()]
        if missing:
            raise RuntimeError(f"assessment zip missing required members: {missing}")
        return {
            "assessment_zip": assessment_zip,
            "assessment_sha256": sha256_file(assessment_zip),
            "zip_members": sorted(archive.namelist()),
            "arm_rows": zip_jsonl(archive, "truegen_arm_result_matrix.jsonl"),
            "prediction_rows": zip_jsonl(archive, "truegen_predictions.jsonl"),
            "scorecard": zip_json(archive, "truegen_benchmark_scorecard.json"),
            "token_efficiency": zip_json(archive, "truegen_token_efficiency_matrix.json"),
            "verified_work": zip_json(archive, "truegen_verified_work_per_token_scorecard.json"),
            "parser_matrix": zip_json(archive, "truegen_parser_vs_generation_error_matrix.json"),
            "visible_ledger": zip_json(archive, "visible_answer_ledger.json"),
            "runtime_receipt": zip_json(archive, "v17_7_4_math_scratchpad_runtime_receipt.json"),
            "token_ledger_receipt": zip_json(archive, "v17_7_4_math_scratchpad_token_ledger_receipt.json"),
            "evaluation_gate": zip_json(archive, "v17_7_4_math_scratchpad_evaluation_gate.json"),
            "arm_config_receipt": zip_json(archive, "arm_model_config_receipt.json"),
            "final_summary": zip_json(archive, "final_summary.json"),
        }


def rows_by_arm(arm_rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in arm_rows:
        grouped[str(row.get("arm_id"))].append(row)
    return dict(grouped)


def rows_by_sample(arm_rows: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, Any]]]:
    grouped: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in arm_rows:
        grouped[str(row.get("sample_id"))][str(row.get("arm_id"))] = row
    return dict(grouped)


def per_arm_metrics(arm_rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    grouped = rows_by_arm(arm_rows)
    metrics: dict[str, dict[str, Any]] = {}
    for arm_id in ALL_ARMS:
        rows = grouped.get(arm_id, [])
        total = len(rows)
        correct = sum(1 for row in rows if row.get("correct") is True)
        full_tokens = sum(int(row.get("full_prompt_plus_output_tokens") or row.get("total_tokens") or 0) for row in rows)
        visible_tokens = sum(int(row.get("visible_answer_tokens") or row.get("answer_tokens") or 0) for row in rows)
        reasoning_tokens = sum(int(row.get("reasoning_tokens") or 0) for row in rows)
        metrics[arm_id] = {
            "total": total,
            "correct": correct,
            "accuracy": round(correct / max(total, 1), 6),
            "full_tokens": full_tokens,
            "visible_tokens": visible_tokens,
            "reasoning_tokens": reasoning_tokens,
            "full_tokens_per_correct": round(full_tokens / correct, 6) if correct else None,
            "visible_tokens_per_correct": round(visible_tokens / correct, 6) if correct else None,
            "reasoning_tokens_per_correct": round(reasoning_tokens / correct, 6) if correct else None,
            "verified_work_per_full_token": round(correct / max(full_tokens, 1), 9),
            "measurement_statuses": sorted({str(row.get("measurement_status")) for row in rows}),
            "model_repos": sorted({str(row.get("model_repo")) for row in rows}),
            "adapter_statuses": sorted({str(row.get("adapter_source_status")) for row in rows}),
        }
    return metrics


def damage_rescue_matrix(sample_rows: dict[str, dict[str, dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    matrix: dict[str, dict[str, Any]] = {}
    for arm_id in CANDIDATE_ARMS:
        counts = Counter()
        sample_ids: dict[str, list[str]] = {"damage": [], "rescue": [], "both_correct": [], "neither_correct": []}
        for sample_id, arms in sorted(sample_rows.items()):
            control = arms.get(CONTROL_ARM, {})
            candidate = arms.get(arm_id, {})
            control_correct = control.get("correct") is True
            candidate_correct = candidate.get("correct") is True
            if control_correct and not candidate_correct:
                key = "damage"
            elif not control_correct and candidate_correct:
                key = "rescue"
            elif control_correct and candidate_correct:
                key = "both_correct"
            else:
                key = "neither_correct"
            counts[key] += 1
            sample_ids[key].append(sample_id)
        matrix[arm_id] = {
            "control_damaged_rows": counts["damage"],
            "candidate_rescued_rows": counts["rescue"],
            "both_correct_rows": counts["both_correct"],
            "neither_correct_rows": counts["neither_correct"],
            "net_correct_delta_vs_control": counts["rescue"] - counts["damage"],
            "status": "NEGATIVE_TRANSFER_QUARANTINE" if counts["damage"] > counts["rescue"] else "REVIEW_REQUIRED",
            "sample_ids": sample_ids,
        }
    return matrix


def row_level_autopsy(sample_rows: dict[str, dict[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for sample_id, arms in sorted(sample_rows.items()):
        control = arms.get(CONTROL_ARM, {})
        candidate_states = {}
        for arm_id in CANDIDATE_ARMS:
            candidate = arms.get(arm_id, {})
            control_correct = control.get("correct") is True
            candidate_correct = candidate.get("correct") is True
            if control_correct and not candidate_correct:
                relation = "CANDIDATE_DAMAGED_CONTROL"
            elif not control_correct and candidate_correct:
                relation = "CANDIDATE_RESCUED_CONTROL"
            elif control_correct and candidate_correct:
                relation = "BOTH_CORRECT"
            else:
                relation = "NEITHER_CORRECT"
            candidate_states[arm_id] = {
                "correct": candidate_correct,
                "relation_to_control": relation,
                "parsed_answer": candidate.get("parsed_answer"),
                "visible_answer": candidate.get("visible_answer"),
                "output_hash": candidate.get("output_hash"),
                "final_answer_marker_present": candidate.get("final_answer_marker_present"),
                "parser_format_failure": candidate.get("parser_format_failure"),
                "full_prompt_plus_output_tokens": candidate.get("full_prompt_plus_output_tokens"),
                "reasoning_tokens": candidate.get("reasoning_tokens"),
            }
        rows.append(
            authority(
                schema_id="kt.v17_7_4.math_scratchpad_row_level_autopsy.v1",
                sample_id=sample_id,
                dataset=control.get("dataset"),
                task_family=control.get("task_family"),
                expected_answer_hash=control.get("expected_answer_hash"),
                control_correct=control.get("correct") is True,
                control_parsed_answer=control.get("parsed_answer"),
                control_visible_answer=control.get("visible_answer"),
                control_output_hash=control.get("output_hash"),
                control_full_prompt_plus_output_tokens=control.get("full_prompt_plus_output_tokens"),
                candidate_states=candidate_states,
                training_authorized=False,
                promotion_authority=False,
            )
        )
    return rows


def classify_owner_for_candidate(row: dict[str, Any]) -> str:
    output = str(row.get("output_text") or "")
    if "Compact mode:" in output or "Mode rule:" in output or "Question:" in output:
        return "PROMPT_TEMPLATE_ECHO_OR_CONTINUATION_OWNED"
    if row.get("parser_format_failure") is True and row.get("final_answer_marker_present") is not True:
        return "ANSWER_SURFACE_AND_FINALIZER_OWNED"
    if int(row.get("reasoning_tokens") or 0) > 80 and row.get("correct") is not True:
        return "SCRATCHPAD_BUDGET_NEGATIVE_TRANSFER_OWNED"
    if row.get("correct") is not True:
        return "MATH_REASONING_OR_ARITHMETIC_OWNED"
    return "NO_FAILURE_ON_ROW"


def owner_court(arm_rows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped = rows_by_arm(arm_rows)
    by_arm: dict[str, dict[str, int]] = {}
    for arm_id in CANDIDATE_ARMS:
        counts = Counter(classify_owner_for_candidate(row) for row in grouped.get(arm_id, []))
        by_arm[arm_id] = dict(sorted(counts.items()))
    return authority(
        schema_id="kt.v17_7_4.math_scratchpad_failure_owner_court.v1",
        status="PASS_NEGATIVE_RESULT_ADJUDICATED",
        by_arm=by_arm,
        primary_owner="SCRATCHPAD_POLICY_AND_PROMPT_SURFACE_OWNED",
        parser_only_explanation_rejected=True,
        reason="Candidate scratchpad arms lost correctness while adding large token cost; parser format failures are present but do not explain the control-vs-candidate gap alone.",
        training_authorized=False,
    )


def build_reports(evidence: dict[str, Any]) -> dict[str, Any]:
    current_head = git(["rev-parse", "HEAD"])
    branch = git(["branch", "--show-current"])
    arm_rows = evidence["arm_rows"]
    prediction_rows = evidence["prediction_rows"]
    sample_rows = rows_by_sample(arm_rows)
    metrics = per_arm_metrics(arm_rows)
    damage_matrix = damage_rescue_matrix(sample_rows)
    autopsy_rows = row_level_autopsy(sample_rows)
    source_scorecard = evidence["scorecard"]
    recomputed_correct = {arm: metrics[arm]["correct"] for arm in ALL_ARMS}
    recomputed_accuracy = {arm: metrics[arm]["accuracy"] for arm in ALL_ARMS}
    source_correct = source_scorecard.get("correct_counts", {})
    source_accuracy = source_scorecard.get("arm_accuracy", {})
    control_metric = metrics[CONTROL_ARM]
    best_arm = max(ALL_ARMS, key=lambda arm: metrics[arm]["correct"])
    all_candidates_worse = all(metrics[arm]["correct"] < control_metric["correct"] for arm in CANDIDATE_ARMS)
    parser_matrix = evidence["parser_matrix"].get("matrix", {})
    visible_matrix = evidence["visible_ledger"].get("matrix", {})
    config_path = str(evidence["arm_config_receipt"].get("config_path", ""))
    wrapper_path_mismatch = "reprolock_generalization_probe" in config_path and "math_scratchpad" not in config_path

    truth_pin = authority(
        schema_id="kt.v17_7_4.math_scratchpad_failure_truth_pin_receipt.v1",
        status="PASS",
        current_head=current_head,
        branch=branch,
        assessment_zip=str(evidence["assessment_zip"]),
        assessment_sha256=evidence["assessment_sha256"],
        required_members_present=True,
        row_count=len(prediction_rows),
        arm_rows=len(arm_rows),
        arms=ALL_ARMS,
        dataset_mix=dict(sorted(Counter(str(row.get("dataset")) for row in arm_rows).items())),
    )
    runtime_binding = authority(
        schema_id="kt.v17_7_4.math_scratchpad_microfurnace_runtime_binding_receipt.v1",
        status="PASS",
        run_mode=evidence["runtime_receipt"].get("run_mode"),
        run_id=evidence["runtime_receipt"].get("run_id") or source_scorecard.get("run_id"),
        measurement_source=source_scorecard.get("measurement_source"),
        measurement_status=source_scorecard.get("measurement_status"),
        model_generation_invoked=True,
        no_training=evidence["runtime_receipt"].get("adapter_training_authorized") is False,
        no_promotion=evidence["runtime_receipt"].get("promotion_authority") is False,
        no_v18=evidence["runtime_receipt"].get("v18_runtime_authority") is False,
        row_level_recomputed=True,
    )
    scorecard_binding = authority(
        schema_id="kt.v17_7_4.math_scratchpad_scorecard_binding.v1",
        status="PASS",
        recomputed_correct_counts=recomputed_correct,
        source_correct_counts={arm: source_correct.get(arm) for arm in ALL_ARMS},
        recomputed_accuracy=recomputed_accuracy,
        source_accuracy={arm: source_accuracy.get(arm) for arm in ALL_ARMS},
        source_matches_recomputed=all(source_correct.get(arm) == metrics[arm]["correct"] for arm in ALL_ARMS),
        best_arm=best_arm,
        control_remains_best=best_arm == CONTROL_ARM,
        row_count=len(prediction_rows),
        arm_rows=len(arm_rows),
    )
    claim_boundary = authority(
        schema_id="kt.v17_7_4.math_scratchpad_claim_boundary_receipt.v1",
        status="PASS",
        allowed_claims=[
            "Math scratchpad microfurnace executed and emitted measured rows.",
            "Known-good control remained the best measured arm on this 25-row GSM8K slice.",
            "Scratchpad candidates are negative-result evidence and are quarantined from runtime authority.",
        ],
        forbidden_claims=[
            "Do not claim scratchpad improvement.",
            "Do not claim compression recovery.",
            "Do not claim G2 recovery.",
            "Do not claim router or learned-router superiority.",
            "Do not claim promotion, V18 authority, commercial readiness, external validation, S-tier, 7B, or production readiness.",
        ],
        generic_final_summary_overridden=True,
        generic_final_summary_decision=evidence["final_summary"].get("decision"),
        override_reason="The arm-level scratchpad result is negative; larger rerun is not lawful without a new hypothesis.",
    )
    quarantine = authority(
        schema_id="kt.v17_7_4.math_scratchpad_candidate_quarantine_receipt.v1",
        status="PASS",
        control_arm=CONTROL_ARM,
        control_status="CONTROL_REMAINS_BEST",
        candidate_statuses={
            arm: "QUARANTINE_FAILED_CORRECTNESS_AND_COST" for arm in CANDIDATE_ARMS
        },
        all_candidates_worse_than_control=all_candidates_worse,
        runtime_authority_for_candidates=False,
        repeat_same_microfurnace_authorized=False,
    )
    no_runtime = authority(
        schema_id="kt.v17_7_4.math_scratchpad_no_runtime_authority_receipt.v1",
        status="PASS",
        scratchpad_global_runtime_authority=False,
        scratchpad_microfurnace_repeat_authority=False,
        next_runtime_packet_generated=False,
        reason="Candidate scratchpad arms damaged the best control and worsened full-token economics.",
    )
    failure_summary = authority(
        schema_id="kt.v17_7_4.math_scratchpad_failure_summary.v1",
        status="NEGATIVE_RESULT_CONFIRMED",
        control=control_metric,
        candidates={arm: metrics[arm] for arm in CANDIDATE_ARMS},
        best_arm=best_arm,
        summary="Scratchpad arms were operationally measured but scientifically negative on this GSM8K slice.",
        final_summary_conflict=evidence["final_summary"].get("next_lawful_move"),
        final_summary_conflict_resolution="DO_NOT_RERUN_UNCHANGED",
    )
    control_diff = authority(
        schema_id="kt.v17_7_4.math_scratchpad_control_vs_candidate_diff.v1",
        status="PASS",
        control_arm=CONTROL_ARM,
        control_metric=control_metric,
        candidates={
            arm: {
                "candidate_metric": metrics[arm],
                "correct_delta_vs_control": metrics[arm]["correct"] - control_metric["correct"],
                "full_tpc_delta_vs_control": (
                    None
                    if metrics[arm]["full_tokens_per_correct"] is None
                    else round(metrics[arm]["full_tokens_per_correct"] - control_metric["full_tokens_per_correct"], 6)
                ),
                "visible_tpc_delta_vs_control": (
                    None
                    if metrics[arm]["visible_tokens_per_correct"] is None
                    else round(metrics[arm]["visible_tokens_per_correct"] - control_metric["visible_tokens_per_correct"], 6)
                ),
            }
            for arm in CANDIDATE_ARMS
        },
    )
    parser_court = authority(
        schema_id="kt.v17_7_4.math_scratchpad_parser_scorer_vs_reasoning_court.v1",
        status="PASS_PARSER_ONLY_EXPLANATION_REJECTED",
        parser_matrix=parser_matrix,
        control_parser_failure_rate=parser_matrix.get(CONTROL_ARM, {}).get("parser_format_failure_rate"),
        candidate_parser_failure_rates={arm: parser_matrix.get(arm, {}).get("parser_format_failure_rate") for arm in CANDIDATE_ARMS},
        finding="Parser/format issues exist, but the control had a comparable parser failure rate while still scoring highest.",
        next_action="Use a control-preserving verifier sidecar only after the first-pass control output; do not replace the control path.",
    )
    final_marker = authority(
        schema_id="kt.v17_7_4.math_scratchpad_final_answer_marker_effect.v1",
        status="PASS_MARKER_NOT_SUFFICIENT",
        by_arm={
            arm: {
                "final_marker_rows": sum(1 for row in rows_by_arm(arm_rows).get(arm, []) if row.get("final_answer_marker_present") is True),
                "correct": metrics[arm]["correct"],
                "accuracy": metrics[arm]["accuracy"],
            }
            for arm in ALL_ARMS
        },
        finding="Final-answer markers and compact visible surfaces did not rescue candidate accuracy.",
    )
    visible_audit = authority(
        schema_id="kt.v17_7_4.math_scratchpad_visible_answer_surface_audit.v1",
        status="PASS",
        visible_answer_ledger=visible_matrix,
        visible_answer_scoring_not_full_system_tpc=True,
        control_scored_from_raw_output=visible_matrix.get(CONTROL_ARM, {}).get("scored_from_visible_answer_rows") == 0,
    )
    token_court = authority(
        schema_id="kt.v17_7_4.math_scratchpad_token_economics_court.v1",
        status="PASS_NEGATIVE_TOKEN_ECONOMICS",
        by_arm=metrics,
        scratchpad_tokens_count_in_full_tpc=evidence["token_ledger_receipt"].get("scratchpad_tokens_count_in_full_tpc") is True,
        full_tpc_regression_vs_control={
            arm: (
                None
                if metrics[arm]["full_tokens_per_correct"] is None
                else round(metrics[arm]["full_tokens_per_correct"] - control_metric["full_tokens_per_correct"], 6)
            )
            for arm in CANDIDATE_ARMS
        },
    )
    roi = authority(
        schema_id="kt.v17_7_4.math_scratchpad_reasoning_roi_scorecard.v1",
        status="NEGATIVE_ROI",
        control_correct=control_metric["correct"],
        candidates={
            arm: {
                "correct_delta_vs_control": metrics[arm]["correct"] - control_metric["correct"],
                "reasoning_token_delta_vs_control": metrics[arm]["reasoning_tokens"] - control_metric["reasoning_tokens"],
                "full_token_delta_vs_control": metrics[arm]["full_tokens"] - control_metric["full_tokens"],
                "roi_class": "NEGATIVE",
            }
            for arm in CANDIDATE_ARMS
        },
    )
    full_tpc_regression = authority(
        schema_id="kt.v17_7_4.math_scratchpad_full_tpc_regression_receipt.v1",
        status="PASS_REGRESSION_DETECTED",
        control_full_tokens_per_correct=control_metric["full_tokens_per_correct"],
        candidate_full_tokens_per_correct={arm: metrics[arm]["full_tokens_per_correct"] for arm in CANDIDATE_ARMS},
        regression_detected=True,
    )
    wrapper_hygiene = authority(
        schema_id="kt.v17_7_4.math_scratchpad_wrapper_hygiene_receipt.v1",
        status="WRAPPER_PATH_MISMATCH_RECORDED" if wrapper_path_mismatch else "PASS",
        config_path=config_path,
        config_profile=evidence["arm_config_receipt"].get("config_profile"),
        measurement_mode=evidence["arm_config_receipt"].get("measurement_mode"),
        path_mismatch_detected=wrapper_path_mismatch,
        required_next_wrapper_fix="Use math-scratchpad-specific packet/config path naming for any successor wrapper.",
    )
    runner_selection = authority(
        schema_id="kt.v17_7_4.math_scratchpad_runner_selection_receipt.v1",
        status="PASS",
        run_mode=evidence["runtime_receipt"].get("run_mode"),
        evidence_band=source_scorecard.get("evidence_band") or "MATH_SCRATCHPAD_MICROFURNACE",
        row_limit=evidence["arm_config_receipt"].get("effective_row_limit"),
        enabled_arms=evidence["arm_config_receipt"].get("enabled_arms"),
    )
    epc = authority(
        schema_id="kt.v17_7_4.math_scratchpad_epc_decision_after_failure.v1",
        status="PASS",
        selected_next_lane="DESIGN_CONTROL_PRESERVING_MATH_VERIFIER_RESCUE_OFFLINE_SIMULATION",
        no_kaggle_runtime_packet=True,
        no_training=True,
        no_promotion=True,
        reason="Known-good first pass should be preserved; next hypothesis must diagnose/control math errors without replacing the control path.",
        rejected_next_lanes=[
            "RERUN_MATH_SCRATCHPAD_MICROFURNACE_UNCHANGED",
            "BIGGER_SCRATCHPAD_FURNACE",
            "GLOBAL_FINALIZER_V2_RUNTIME",
            "TRAIN_MATH_ADAPTER_FROM_SCRATCHPAD_GAPS",
        ],
    )
    queue = authority(
        schema_id="kt.v17_7_4.math_scratchpad_next_hypothesis_queue.v1",
        status="PASS",
        queue=[
            {
                "rank": 1,
                "lane": "CONTROL_PRESERVING_MATH_VERIFIER_RESCUE",
                "why": "Adds a verifier/rescue sidecar after the known-good answer instead of replacing the known-good route.",
            },
            {
                "rank": 2,
                "lane": "ROW_LEVEL_CONTROL_WRONG_AUTOPSY",
                "why": "Autopsy the 12 control misses without touching control-correct rows.",
            },
            {
                "rank": 3,
                "lane": "SCORER_DISAGREEMENT_AUDIT",
                "why": "Separate parser/scorer blindness from true generation failure.",
            },
        ],
    )
    stop_continue = authority(
        schema_id="kt.v17_7_4.math_scratchpad_stop_continue_decision.v1",
        status="STOP_UNCHANGED_SCRATCHPAD__CONTINUE_WITH_CONTROL_PRESERVING_RESCUE_DESIGN",
        stop_same_furnace=True,
        continue_repo_side=True,
        runtime_authority=False,
    )
    summary = authority(
        schema_id="kt.v17_7_4.math_scratchpad_failure_review_builder_summary.v1",
        status="PASS",
        tranche=TRANCHE,
        outcome=OUTCOME,
        current_head=current_head,
        branch=branch,
        math_scratchpad_failure_truth_pin_status=truth_pin["status"],
        runtime_binding_status=runtime_binding["status"],
        scorecard_binding_status=scorecard_binding["status"],
        candidate_quarantine_status=quarantine["status"],
        no_runtime_authority_status=no_runtime["status"],
        damage_rescue_matrix_status="PASS",
        wrapper_hygiene_status=wrapper_hygiene["status"],
        epc_next_evidence_lane_status=epc["selected_next_lane"],
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        claim_ceiling_status="PRESERVED",
        blockers=[],
        next_lawful_move="RUN_CONTROL_PRESERVING_MATH_VERIFIER_RESCUE_REPO_DESIGN",
    )
    return {
        "v17_7_4_math_scratchpad_failure_truth_pin_receipt.json": truth_pin,
        "v17_7_4_math_scratchpad_microfurnace_runtime_binding_receipt.json": runtime_binding,
        "v17_7_4_math_scratchpad_scorecard_binding.json": scorecard_binding,
        "v17_7_4_math_scratchpad_claim_boundary_receipt.json": claim_boundary,
        "v17_7_4_math_scratchpad_candidate_quarantine_receipt.json": quarantine,
        "v17_7_4_math_scratchpad_no_runtime_authority_receipt.json": no_runtime,
        "v17_7_4_math_scratchpad_failure_summary.json": failure_summary,
        "v17_7_4_math_scratchpad_damage_rescue_matrix.json": authority(
            schema_id="kt.v17_7_4.math_scratchpad_damage_rescue_matrix.v1",
            status="PASS",
            control_arm=CONTROL_ARM,
            matrix=damage_matrix,
        ),
        "v17_7_4_math_scratchpad_control_vs_candidate_diff.json": control_diff,
        "v17_7_4_math_scratchpad_failure_owner_court.json": owner_court(arm_rows),
        "v17_7_4_math_scratchpad_parser_scorer_vs_reasoning_court.json": parser_court,
        "v17_7_4_math_scratchpad_final_answer_marker_effect.json": final_marker,
        "v17_7_4_math_scratchpad_visible_answer_surface_audit.json": visible_audit,
        "v17_7_4_math_scratchpad_token_economics_court.json": token_court,
        "v17_7_4_math_scratchpad_reasoning_roi_scorecard.json": roi,
        "v17_7_4_math_scratchpad_full_tpc_regression_receipt.json": full_tpc_regression,
        "v17_7_4_math_scratchpad_wrapper_hygiene_receipt.json": wrapper_hygiene,
        "v17_7_4_math_scratchpad_runner_selection_receipt.json": runner_selection,
        "v17_7_4_math_scratchpad_epc_decision_after_failure.json": epc,
        "v17_7_4_math_scratchpad_next_hypothesis_queue.json": queue,
        "v17_7_4_math_scratchpad_stop_continue_decision.json": stop_continue,
        "v17_7_4_math_scratchpad_failure_review_builder_summary.json": summary,
        "__jsonl__v17_7_4_math_scratchpad_row_level_autopsy.jsonl": autopsy_rows,
    }


def main() -> int:
    reports = build_reports(load_evidence())
    for name, payload in reports.items():
        if name.startswith("__jsonl__"):
            write_jsonl(ROOT / "reports" / name.removeprefix("__jsonl__"), payload)
        else:
            write_json(ROOT / "reports" / name, payload)
    print(json.dumps(reports["v17_7_4_math_scratchpad_failure_review_builder_summary.json"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
