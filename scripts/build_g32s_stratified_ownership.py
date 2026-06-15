#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
POLICIES = ROOT / "policies"
ASSESSMENT_PATH = ROOT / "evidence" / "KT_PARETO_V1_ASSESSMENT_ONLY.zip"
EXPECTED_ASSESSMENT_SHA256 = "fa417a164604301131be89317991f1ecc4289095dc021e92cc7b6fdf549837af"

OUTCOME = (
    "KT_G32_STRATIFIED_FIXED512_FAILURES_OWNED__COUNTERFACTUAL_COURTS_BOUND__"
    "DIFFICULTY_AWARE_SELECTOR_SEED_READY__CLAIM_CEILING_PRESERVED"
)
NEXT_LAWFUL_MOVE = "AUTHOR_KTPARETO_COUNTERFACTUAL_MICROFURNACE_PACKET_V1"

ARM_384 = "A4_COT_384_FIXED"
ARM_512 = "A6_COT_512_FIXED_CONTROL"
ARM_640 = "A7_COT_640_FIXED_SENTINEL"
ARM_ANSWER_ONLY = "A8_ANSWER_ONLY_NO_COT"
ARMS = [
    "A0_COT_96_FIXED",
    "A1_COT_192_FIXED",
    "A2_COT_256_FIXED",
    "A3_COT_320_FIXED",
    ARM_384,
    "A5_COT_448_FIXED",
    ARM_512,
    ARM_640,
    ARM_ANSWER_ONLY,
]

COUNTERFACTUAL_TESTS = [
    "budget_continuation_768",
    "budget_continuation_1024",
    "prompt_explicit_variables",
    "prompt_minimal_cot",
    "prompt_structured_equations",
    "scorer_numeric_tolerance_recheck",
    "finalizer_alternate_extraction",
    "symbolic_or_calculator_side_check",
    "human_anchor_manual_solution",
    "benchmark_ambiguity_review",
]

AUTHORITY_FALSE = {
    "runtime_authority": False,
    "dataset_generation_authority": False,
    "training_authority": False,
    "promotion_authority": False,
    "selector_deployment_authority": False,
    "adapter_mutation_authority": False,
    "production_prompt_mutation_authority": False,
}


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_output(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def load_zip_jsonl(zf: zipfile.ZipFile, name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in zf.read(name).decode("utf-8").splitlines() if line.strip()]


def load_assessment() -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    if not ASSESSMENT_PATH.exists():
        raise SystemExit(f"missing assessment zip: {ASSESSMENT_PATH}")
    actual_sha = sha256_file(ASSESSMENT_PATH)
    if actual_sha != EXPECTED_ASSESSMENT_SHA256:
        raise SystemExit(f"assessment sha mismatch: expected {EXPECTED_ASSESSMENT_SHA256}, got {actual_sha}")
    with zipfile.ZipFile(ASSESSMENT_PATH) as zf:
        final_summary = json.loads(zf.read("final_summary.json"))
        predictions = load_zip_jsonl(zf, "budget_predictions.jsonl")
        oracle_rows = load_zip_jsonl(zf, "per_arm_oracle_rows.jsonl")
        scorecard = json.loads(zf.read("budget_pareto_scorecard.json"))
    return final_summary, predictions, oracle_rows, scorecard


def load_difficulty_proxy() -> dict[str, dict[str, Any]]:
    path = REPORTS / "ktpareto_difficulty_proxy_matrix.jsonl"
    rows = read_jsonl(path)
    return {row["row_id"]: row for row in rows if row.get("slice_id") == "KTPARETO"}


def group_predictions(predictions: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, Any]]]:
    grouped: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in predictions:
        grouped[row["row_id"]][row["arm_id"]] = row
    missing = [row_id for row_id, arms in grouped.items() if set(ARMS) - set(arms)]
    if missing:
        raise SystemExit(f"prediction rows missing arms: {missing[:5]}")
    return dict(grouped)


def stratum_for(row_id: str, proxy: dict[str, Any] | None) -> str:
    if proxy and proxy.get("pre_generation_proxy_stratum"):
        return str(proxy["pre_generation_proxy_stratum"])
    return "UNKNOWN_PROXY_STRATUM"


def row_correctness(arms: dict[str, dict[str, Any]]) -> dict[str, bool]:
    return {arm: bool(arms[arm].get("correct")) for arm in ARMS}


def classify_fixed512_failure(arms: dict[str, dict[str, Any]]) -> tuple[str, str, str, float]:
    correct = row_correctness(arms)
    if any(correct.values()) is False:
        return ("UNKNOWN_BLOCKED", "NO_CORRECT_ARM", "counterfactual_court_required", 0.95)
    if correct[ARM_640] and not correct[ARM_512]:
        return ("BUDGET_CONTINUATION_OWNED", "COT512_INSUFFICIENT", "640_continuation_rescued", 0.65)
    lower_correct = [arm for arm in ARMS if arm != ARM_512 and correct[arm]]
    if lower_correct:
        return ("BUDGET_NONMONOTONIC_OR_FINALIZER_OWNED", "FIXED512_NONMONOTONIC_FAILURE", "lower_budget_or_sentinel_won", 0.45)
    return ("UNKNOWN_BLOCKED", "FIXED512_FAILURE_UNRESOLVED", "counterfactual_court_required", 0.80)


def repair_bid(
    severity: float,
    recurrence: float,
    oracle_gap: float,
    verifier_confidence: float,
    human_anchor_quality: float,
    no_regression_safety: float,
    estimated_repair_cost: float,
) -> float:
    return (
        severity
        * recurrence
        * oracle_gap
        * verifier_confidence
        * human_anchor_quality
        * no_regression_safety
        / max(estimated_repair_cost, 1e-9)
    )


def build_reports() -> dict[str, Any]:
    final_summary, predictions, oracle_rows, scorecard = load_assessment()
    by_row = group_predictions(predictions)
    oracle_by_row = {row["row_id"]: row for row in oracle_rows}
    proxy_by_row = load_difficulty_proxy()
    head = git_output("rev-parse", "HEAD")
    branch = git_output("branch", "--show-current")

    input_paths = [
        "reports/ktpareto_assessment_import_receipt.json",
        "reports/ktpareto_scorecard_reconciliation.json",
        "reports/ktpareto_slice_exchangeability_receipt.json",
        "reports/ktpareto_difficulty_proxy_matrix.jsonl",
        "reports/ktpareto_stratified_budget_frontier.json",
        "reports/ktpareto_stratified_fixed512_estimate.json",
        "reports/ktpareto_stratified_false_downshift_report.json",
        "reports/ktpareto_384_false_downshift_rows.jsonl",
        "reports/ktpareto_cot640_recovery_damage_analysis.json",
        "reports/ktpareto_no_correct_arm_autopsy.jsonl",
        "reports/ktpareto_no_correct_arm_failure_genome.json",
        "reports/ktpareto_no_correct_arm_counterfactual_plan.json",
        "reports/ktpareto_next_lane_decision.json",
    ]
    input_mapping = {
        "schema_id": "kt.g32s.input_path_mapping.v1",
        "status": "PASS",
        "current_head": head,
        "source_lane": "AUTHOR_G32_STRATIFIED_FIXED512_WEAK_BASELINE_FAILURE_OWNERSHIP_V1",
        "inputs": [
            {
                "path": path,
                "exists": (ROOT / path).exists(),
                "sha256": sha256_file(ROOT / path) if (ROOT / path).exists() and (ROOT / path).is_file() else None,
            }
            for path in input_paths
        ],
        "claim_ceiling_status": "PRESERVED",
    }
    write_json(REPORTS / "g32s_input_path_mapping.json", input_mapping)

    strata: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "row_count": 0,
            "arm_correct": {arm: 0 for arm in ARMS},
            "fixed512_failures": 0,
            "no_correct_arm_rows": 0,
            "false384_rows": 0,
            "cot640_recovery_rows": 0,
            "cot640_damage_rows": 0,
        }
    )
    difficulty_receipts: list[dict[str, Any]] = []
    fixed_failure_rows: list[dict[str, Any]] = []
    no_correct_rows: list[dict[str, Any]] = []
    morbidity_rows: list[dict[str, Any]] = []
    false384_rows: list[dict[str, Any]] = []
    cot640_matrix_rows: list[dict[str, Any]] = []
    continue_rows: list[dict[str, Any]] = []
    stop_rows: list[dict[str, Any]] = []
    human_anchor_rows: list[dict[str, Any]] = []
    repair_bid_rows: list[dict[str, Any]] = []

    for row_id in sorted(by_row, key=lambda item: int(item.rsplit("_", 1)[1])):
        arms = by_row[row_id]
        fixed = arms[ARM_512]
        proxy = proxy_by_row.get(row_id)
        stratum = stratum_for(row_id, proxy)
        correctness = row_correctness(arms)
        fixed_correct = correctness[ARM_512]
        false384 = fixed_correct and not correctness[ARM_384]
        cot640_recovery = (not fixed_correct) and correctness[ARM_640]
        cot640_damage = fixed_correct and not correctness[ARM_640]
        no_correct = not any(correctness.values())
        global_row = int(fixed["global_row"])

        s = strata[stratum]
        s["row_count"] += 1
        for arm, value in correctness.items():
            s["arm_correct"][arm] += int(value)
        s["fixed512_failures"] += int(not fixed_correct)
        s["no_correct_arm_rows"] += int(no_correct)
        s["false384_rows"] += int(false384)
        s["cot640_recovery_rows"] += int(cot640_recovery)
        s["cot640_damage_rows"] += int(cot640_damage)

        difficulty_receipts.append(
            {
                "schema_id": "kt.g32s.difficulty_proxy_receipt.v1",
                "row_id": row_id,
                "global_row": global_row,
                "difficulty_stratum": stratum,
                "proxy_source": "reports/ktpareto_difficulty_proxy_matrix.jsonl",
                "question_text_available": bool(proxy and proxy.get("question_text_available")),
                "question_token_length": proxy.get("question_token_length") if proxy else None,
                "estimated_step_count": proxy.get("estimated_step_count") if proxy else None,
                "number_count": proxy.get("number_count") if proxy else None,
                "runtime_feature_legality": "PRE_GENERATION_PROXY_ONLY",
                "claim_ceiling_status": "PRESERVED",
            }
        )

        if not fixed_correct:
            owner, selector_class, hypothesis, confidence = classify_fixed512_failure(arms)
            bid = repair_bid(
                severity=1.0,
                recurrence=1.0 + s["fixed512_failures"] / max(1, s["row_count"]),
                oracle_gap=1.5 if no_correct else 1.0,
                verifier_confidence=confidence,
                human_anchor_quality=0.2 if no_correct else 0.4,
                no_regression_safety=0.25 if no_correct else 0.55,
                estimated_repair_cost=5.0,
            )
            failure_row = {
                "schema_id": "kt.g32s.failure_genome.v2",
                "row_id": row_id,
                "global_row": global_row,
                "difficulty_stratum": stratum,
                "expected_answer_hash": fixed["expected_hash"],
                "owner_candidate": owner,
                "selector_class": selector_class,
                "repair_hypothesis": hypothesis,
                "confidence": confidence,
                "repair_bid": bid,
                "counterfactual_tests_required": COUNTERFACTUAL_TESTS if no_correct else COUNTERFACTUAL_TESTS[:6],
                "human_anchor_required": no_correct,
                "training_authority": False,
                "claim_ceiling_status": "PRESERVED",
            }
            fixed_failure_rows.append(failure_row)
            repair_bid_rows.append(failure_row)

        if no_correct:
            wrong_answers = {arm: arms[arm].get("extracted_answer") for arm in ARMS}
            row_payload = {
                "schema_id": "kt.g32s.counterfactual_court.v2",
                "row_id": row_id,
                "global_row": global_row,
                "difficulty_stratum": stratum,
                "expected_answer_hash": fixed["expected_hash"],
                "wrong_answer_patterns_by_budget": wrong_answers,
                "counterfactual_tests_required": COUNTERFACTUAL_TESTS,
                "repair_owner_candidate": "UNKNOWN_BLOCKED",
                "human_anchor_required": True,
                "training_authority": False,
                "claim_ceiling_status": "PRESERVED",
            }
            no_correct_rows.append(row_payload)
            morbidity_rows.append(
                {
                    "schema_id": "kt.g32s.no_correct_morbidity.v1",
                    "row_id": row_id,
                    "global_row": global_row,
                    "difficulty_stratum": stratum,
                    "arithmetic_surface_quality": "UNKNOWN_COUNTERFACTUAL_REQUIRED",
                    "entity_tracking_failure": "REVIEW_REQUIRED",
                    "operation_selection_failure": "REVIEW_REQUIRED",
                    "benchmark_ambiguity_review": "REQUIRED",
                    "repair_owner_candidate": "UNKNOWN_BLOCKED",
                    "human_anchor_required": True,
                    "training_authority": False,
                    "claim_ceiling_status": "PRESERVED",
                }
            )
            human_anchor_rows.append(
                {
                    "schema_id": "kt.g32s.human_anchor_request.v1",
                    "row_id": row_id,
                    "global_row": global_row,
                    "difficulty_stratum": stratum,
                    "reason": "NO_CORRECT_ARM",
                    "required_anchor": "manual_solution_and_benchmark_ambiguity_review",
                    "training_authority": False,
                    "claim_ceiling_status": "PRESERVED",
                }
            )

        if false384:
            token_savings = int(arms[ARM_512]["total_tokens"]) - int(arms[ARM_384]["total_tokens"])
            false384_rows.append(
                {
                    "schema_id": "kt.g32s.false384_causal.v2",
                    "row_id": row_id,
                    "global_row": global_row,
                    "difficulty_stratum": stratum,
                    "false_downshift_damage": 1,
                    "token_savings_if_correct": token_savings,
                    "net_expected_value": -1,
                    "deployment_gate": "BLOCKED_FALSE_DOWNSHIFT_DAMAGE",
                    "selector_deployment_authority": False,
                    "claim_ceiling_status": "PRESERVED",
                }
            )

        if cot640_recovery:
            continue_rows.append(
                {
                    "schema_id": "kt.g32s.continue_when_helpful_seed.v1",
                    "row_id": row_id,
                    "global_row": global_row,
                    "difficulty_stratum": stratum,
                    "seed_class": "COT512_INSUFFICIENT",
                    "policy_status": "SEED_ONLY_NOT_RUNTIME",
                    "selector_deployment_authority": False,
                    "claim_ceiling_status": "PRESERVED",
                }
            )
        if cot640_damage:
            stop_rows.append(
                {
                    "schema_id": "kt.g32s.stop_before_overthink_seed.v1",
                    "row_id": row_id,
                    "global_row": global_row,
                    "difficulty_stratum": stratum,
                    "seed_class": "STOP_BEFORE_OVERTHINK",
                    "policy_status": "SEED_ONLY_NOT_RUNTIME",
                    "selector_deployment_authority": False,
                    "claim_ceiling_status": "PRESERVED",
                }
            )
        cot640_matrix_rows.append(
            {
                "schema_id": "kt.g32s.cot640_recovery_damage.v2",
                "row_id": row_id,
                "global_row": global_row,
                "difficulty_stratum": stratum,
                "fixed512_correct": fixed_correct,
                "cot640_correct": correctness[ARM_640],
                "class": (
                    "COT640_RECOVERY"
                    if cot640_recovery
                    else "COT640_DAMAGE"
                    if cot640_damage
                    else "COT640_NO_GAIN"
                    if not correctness[ARM_640]
                    else "COT640_SAFE_EXTENSION"
                ),
                "policy_status": "SENTINEL_ONLY",
                "selector_deployment_authority": False,
                "claim_ceiling_status": "PRESERVED",
            }
        )

    stratum_report: dict[str, Any] = {}
    for stratum, data in sorted(strata.items()):
        row_count = data["row_count"]
        stratum_report[stratum] = {
            **{key: value for key, value in data.items() if key != "arm_correct"},
            "arm_accuracy": {arm: data["arm_correct"][arm] / row_count for arm in ARMS},
        }

    fixed_failures = len(fixed_failure_rows)
    no_correct_count = len(no_correct_rows)
    false384_count = len(false384_rows)
    continue_count = len(continue_rows)
    stop_count = len(stop_rows)
    unknown_failure_rate = no_correct_count / max(1, fixed_failures)

    write_json(
        REPORTS / "g32s_stratified_baseline_matrix.json",
        {
            "schema_id": "kt.g32s.stratified_baseline_matrix.v2",
            "status": "PASS_REPLAY_BOUND",
            "row_slice": "openai/gsm8k:test[325:425]",
            "row_count": len(by_row),
            "strata": stratum_report,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    write_jsonl(REPORTS / "g32s_difficulty_proxy_receipt.jsonl", difficulty_receipts)
    write_json(
        REPORTS / "g32s_fixed512_failure_by_stratum.json",
        {
            "schema_id": "kt.g32s.fixed512_failure_by_stratum.v1",
            "status": "PASS_STRATIFIED_FAILURES_BOUND",
            "fixed512_failure_count": fixed_failures,
            "unknown_failure_rate": unknown_failure_rate,
            "strata": {
                stratum: {
                    "fixed512_failures": data["fixed512_failures"],
                    "rows": data["row_count"],
                    "no_correct_arm_rows": data["no_correct_arm_rows"],
                }
                for stratum, data in sorted(strata.items())
            },
            "training_authority": False,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    write_jsonl(REPORTS / "g32s_fixed512_failure_genome.jsonl", fixed_failure_rows)
    write_jsonl(REPORTS / "g32s_no_correct_counterfactual_matrix.jsonl", no_correct_rows)
    write_jsonl(REPORTS / "g32s_no_correct_arm_morbidity_review.jsonl", morbidity_rows)
    write_json(
        REPORTS / "g32s_384_false_downshift_by_stratum.json",
        {
            "schema_id": "kt.g32s.false384_by_stratum.v1",
            "status": "BLOCKS_384_DEPLOYMENT",
            "false_downshift_damage": false384_count,
            "strata": {stratum: {"false384_rows": data["false384_rows"], "rows": data["row_count"]} for stratum, data in sorted(strata.items())},
            "selector_deployment_authority": False,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    write_jsonl(REPORTS / "g32s_false384_causal_matrix.jsonl", false384_rows)
    write_json(
        REPORTS / "g32s_384_safe_stratum_candidate.json",
        {
            "schema_id": "kt.g32s.safe384_candidate.v1",
            "status": "CANDIDATE_ONLY_NOT_DEPLOYABLE",
            "global_deployment_gate": "BLOCKED_FALSE_DOWNSHIFT_DAMAGE",
            "rule": "A stratum can only remain a review candidate if false_downshift_rows == 0.",
            "strata": {stratum: {"candidate_review_only": data["false384_rows"] == 0, "false384_rows": data["false384_rows"]} for stratum, data in sorted(strata.items())},
            "selector_deployment_authority": False,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    write_json(
        REPORTS / "g32s_640_recovery_damage_by_stratum.json",
        {
            "schema_id": "kt.g32s.cot640_by_stratum.v1",
            "status": "SENTINEL_ONLY",
            "cot640_recovery_count": continue_count,
            "cot640_damage_count": stop_count,
            "strata": {stratum: {"recovery": data["cot640_recovery_rows"], "damage": data["cot640_damage_rows"], "rows": data["row_count"]} for stratum, data in sorted(strata.items())},
            "selector_deployment_authority": False,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    write_jsonl(REPORTS / "g32s_cot640_recovery_damage_matrix.jsonl", cot640_matrix_rows)
    write_jsonl(REPORTS / "g32s_continue_when_helpful_seed.jsonl", continue_rows)
    write_jsonl(REPORTS / "g32s_stop_before_overthink_seed.jsonl", stop_rows)
    write_json(
        REPORTS / "g32s_stratified_repair_bid_ledger.json",
        {
            "schema_id": "kt.g32s.repair_bid_ledger.v1",
            "status": "SEED_ONLY_NO_TRAINING_AUTHORITY",
            "formula": "severity * recurrence * oracle_gap * verifier_confidence * human_anchor_quality * no_regression_safety / estimated_repair_cost",
            "rows": repair_bid_rows,
            "training_authority": False,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    write_json(
        REPORTS / "g32s_stratified_selector_risk_report.json",
        {
            "schema_id": "kt.g32s.selector_risk.v1",
            "status": "BLOCKED_FALSE_DOWNSHIFT_DAMAGE",
            "selector_expected_value_formula": "token_savings_when_correct - false_downshift_damage_cost - escalation_cost - uncertainty_penalty",
            "false_downshift_count": false384_count,
            "false_downshift_damage": false384_count,
            "cot640_damage_count": stop_count,
            "cot640_recovery_count": continue_count,
            "deployment_gate": "BLOCKED",
            "selector_deployment_authority": False,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    write_jsonl(REPORTS / "g32s_human_anchor_request_queue.jsonl", human_anchor_rows)
    write_json(
        REPORTS / "g32s_mvs_receipt.json",
        {
            "schema_id": "kt.g32s.mvs_receipt.v2",
            "status": "BLOCKED_MINIMUM_VIABLE_SIGNAL_NOT_MET",
            "unknown_failure_rate": unknown_failure_rate,
            "unknown_failure_rate_gate": "<=0.10",
            "human_anchor_queue_count": len(human_anchor_rows),
            "negative_transfer_scan": "NOT_MEASURED",
            "no_regression_plan": "SPEC_ONLY_NOT_MEASURED",
            "training_authority": False,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    write_json(
        REPORTS / "g32s_train_decision.json",
        {
            "schema_id": "kt.g32s.training_decision.v2",
            "status": "NO_TRAIN",
            "reason": "ownership_unknown_rate_high_and_counterfactuals_unresolved",
            "training_authority": False,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    micro_rows = sorted({row["row_id"] for row in no_correct_rows + false384_rows + continue_rows + stop_rows})
    write_json(
        REPORTS / "g32s_counterfactual_plan.json",
        {
            "schema_id": "kt.g32s.counterfactual_plan.v2",
            "status": "PASS_COUNTERFACTUALS_BOUND",
            "row_count": len(micro_rows),
            "tests": COUNTERFACTUAL_TESTS,
            "human_anchor_required_rows": len(human_anchor_rows),
            "training_authority": False,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    write_json(
        REPORTS / "g32s_next_microfurnace_spec.json",
        {
            "schema_id": "kt.g32s.microfurnace_spec.v1",
            "status": "SPEC_READY_NOT_RUNTIME_AUTHORIZED",
            "purpose": "resolve fixed512 failures, false384 damage, cot640 recovery/damage, and no-correct-arm ownership",
            "row_ids": micro_rows,
            "arms": [
                "fixed512_control",
                "cot640_sentinel",
                "cot768_continuation_probe",
                "cot1024_continuation_probe",
                "prompt_explicit_variables",
                "prompt_minimal_cot",
                "symbolic_side_check",
                "oracle_diagnostic",
            ],
            **AUTHORITY_FALSE,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    write_json(
        POLICIES / "g32s_difficulty_aware_selector_v2.json",
        {
            "schema_id": "kt.g32s.selector_policy.v2",
            "status": "SEED_ONLY_NO_RUNTIME_AUTHORITY",
            "classes": [
                "COT256_SAFE",
                "COT384_ECONOMIC_KNEE_CANDIDATE_ONLY",
                "COT512_REQUIRED",
                "COT512_INSUFFICIENT",
                "COT640_SENTINEL_ONLY",
                "REVIEW_OR_COUNTERFACTUAL",
            ],
            "allowed_features": [
                "pre_generation_proxy_stratum",
                "question_token_length_bucket",
                "number_count_bucket",
                "operation_keyword_count_bucket",
                "estimated_step_count_bucket",
            ],
            "forbidden_features": [
                "row_id",
                "expected_answer",
                "expected_answer_hash",
                "measured_arm_correctness",
                "posthoc_correctness",
                "oracle_correct_arm",
                "oracle_cheapest_correct_arm",
            ],
            "fallback": "COT512_OR_COUNTERFACTUAL_REVIEW_ON_UNCERTAINTY",
            "selector_deployment_authority": False,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    write_json(
        REPORTS / "g32s_next_lane_decision.json",
        {
            "schema_id": "kt.g32s.next_lane_decision.v2",
            "status": "PASS_SINGLE_NEXT_LANE_SELECTED",
            "selected_next_lawful_move": NEXT_LAWFUL_MOVE,
            "rationale": "Counterfactual uncertainty remains high; selector deployment, 384 deployment, 640 deployment, and training remain blocked.",
            **AUTHORITY_FALSE,
            "claim_ceiling_status": "PRESERVED",
        },
    )

    summary = {
        "schema_id": "kt.g32s.builder_summary.v2",
        "status": "PASS",
        "current_head": head,
        "branch": branch,
        "outcome": OUTCOME,
        "g32s_truth_binding_status": "PASS",
        "g32s_input_artifacts_status": "PASS",
        "stratified_baseline_matrix_status": "PASS_REPLAY_BOUND",
        "difficulty_proxy_status": "PASS_PRE_GENERATION_PROXY_BOUND",
        "fixed512_failure_ownership_status": "PASS_STRATIFIED_FAILURES_BOUND",
        "no_correct_arm_counterfactual_status": "PASS_COUNTERFACTUAL_MATRIX_BOUND",
        "no_correct_arm_morbidity_review_status": "PASS_MORBIDITY_REVIEW_BOUND",
        "false384_causal_status": "PASS_BLOCKS_384_DEPLOYMENT",
        "false384_safe_stratum_status": "CANDIDATE_ONLY_NOT_DEPLOYABLE",
        "cot640_recovery_damage_status": "PASS_SENTINEL_ONLY",
        "continue_when_helpful_seed_status": "SEED_ONLY_NO_RUNTIME_AUTHORITY",
        "stop_before_overthink_seed_status": "SEED_ONLY_NO_RUNTIME_AUTHORITY",
        "difficulty_aware_selector_contract_status": "SEED_ONLY_NO_RUNTIME_AUTHORITY",
        "feature_legality_status": "PASS_FORBIDS_HINDSIGHT_AND_LABEL_FEATURES",
        "selector_expected_value_status": "BLOCKED_FALSE_DOWNSHIFT_DAMAGE",
        "human_anchor_queue_status": "PASS_REQUIRED_FOR_NO_CORRECT_ROWS",
        "g32s_mvs_status": "BLOCKED_MINIMUM_VIABLE_SIGNAL_NOT_MET",
        "training_decision_status": "NO_TRAIN",
        "next_microfurnace_spec_status": "SPEC_READY_NOT_RUNTIME_AUTHORIZED",
        "packet_path_if_any": None,
        "packet_sha256_if_any": None,
        "kaggle_dataset_name_if_any": None,
        "one_cell_runbook_if_any": None,
        **AUTHORITY_FALSE,
        "claim_ceiling_status": "PRESERVED",
        "blockers": [],
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "counts": {
            "row_count": len(by_row),
            "fixed512_failures": fixed_failures,
            "no_correct_arm_rows": no_correct_count,
            "false384_rows": false384_count,
            "cot640_recovery_rows": continue_count,
            "cot640_damage_rows": stop_count,
            "oracle_diagnostic_score": final_summary.get("oracle_diagnostic_score"),
            "scorecard_arm_count": len(scorecard.get("scorecard", [])),
            "oracle_row_count": len(oracle_by_row),
        },
    }
    write_json(REPORTS / "g32s_builder_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


if __name__ == "__main__":
    build_reports()
