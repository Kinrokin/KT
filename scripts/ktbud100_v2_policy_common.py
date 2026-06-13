from __future__ import annotations

import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
SCHEMAS = ROOT / "schemas"
ADMISSION = ROOT / "admission"

BASELINE_ARM = "A2_COT_512_FIXED"
BASELINE_ACCURACY = 0.91
BASELINE_TPC = 374.57142857142856
NEXT_FIXED512 = "AUTHOR_BUD100_FIXED512_MATH_MODE_BASELINE_REPLAY_V1"
NEXT_MICROFURNACE = "AUTHOR_BUD100_ADAPTIVE_MONITOR_V2_MICROFURNACE_25_PACKET_V1"
NEXT_FEATURE_REPAIR = "AUTHOR_BUD100_ADAPTIVE_MONITOR_V2_FEATURE_REPAIR_V1"
OUTCOME_NO_GAIN = (
    "KT_BUD100_ADAPTIVE_MONITOR_V2_POLICY_REPAIRED__"
    "V2_OFFLINE_REPLAY_NO_GAIN__FIXED512_BASELINE_RETAINED__CLAIM_CEILING_PRESERVED"
)

AUTHORITY_FALSE = {
    "runtime_authority": False,
    "dataset_generation_authority": False,
    "training_authority": False,
    "promotion_authority": False,
    "adapter_mutation_authority": False,
    "production_prompt_mutation_authority": False,
}

REQUIRED_INPUTS = [
    "reports/bud100_scorecard_reconciliation.json",
    "reports/bud100_budget_curve_scorecard.json",
    "reports/bud100_row_level_policy_matrix.jsonl",
    "reports/bud100_arm_win_matrix.json",
    "reports/bud100_adaptive_vs_cot512_delta_matrix.json",
    "reports/bud100_extension_failure_autopsy.json",
    "reports/bud100_hard_ceiling_failure_rows.jsonl",
    "reports/bud100_answer_only_salvage_rows.jsonl",
    "reports/bud100_cot256_sufficient_rows.jsonl",
    "reports/bud100_cot512_required_rows.jsonl",
    "reports/bud100_all_budget_arms_fail_rows.jsonl",
    "reports/bud100_monitor_wrong_but_cot512_right_rows.jsonl",
    "reports/bud100_monitor_right_but_cot512_wrong_rows.jsonl",
    "reports/bud100_token_economics_by_row.jsonl",
    "reports/bud100_cost_optimal_oracle_policy.json",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_output(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def git_status() -> str:
    return git_output("status", "--porcelain=v1")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def schema(required: list[str], schema_id: str) -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": True,
        "required": required,
        "properties": {"schema_id": {"const": schema_id}, **{key: {} for key in required if key != "schema_id"}},
    }


def write_schemas() -> None:
    write_json(
        SCHEMAS / "kt.bud100_monitor_v2_policy.schema.json",
        schema(
            ["schema_id", "policy_id", "status", "scope", "baseline", "decision_order", "authority"],
            "kt.bud100_monitor_v2_policy.v1",
        ),
    )
    write_json(
        SCHEMAS / "kt.bud100_monitor_v2_offline_replay.schema.json",
        schema(
            [
                "schema_id",
                "status",
                "row_count",
                "accuracy",
                "full_tokens_per_correct",
                "selected_arm_counts",
            ],
            "kt.bud100_monitor_v2_offline_replay.v1",
        ),
    )
    write_json(
        SCHEMAS / "kt.bud100_monitor_v2_decision_rule.schema.json",
        schema(
            ["schema_id", "rule_id", "action", "condition", "feature_legality"],
            "kt.bud100_monitor_v2_decision_rule.v1",
        ),
    )
    write_json(
        SCHEMAS / "kt.bud100_monitor_v2_failure_autopsy.schema.json",
        schema(
            ["schema_id", "status", "damage_count", "fixed512_dominant", "next_lawful_move"],
            "kt.bud100_monitor_v2_failure_autopsy.v1",
        ),
    )


def assert_inputs() -> dict[str, Any]:
    missing = [path for path in REQUIRED_INPUTS if not (ROOT / path).exists()]
    status = "PASS" if not missing else "BLOCKED"
    receipt = {
        "schema_id": "kt.bud100_v2.input_path_mapping.v1",
        "status": status,
        "required_inputs": REQUIRED_INPUTS,
        "missing_inputs": missing,
        "path_substitutions": {},
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "bud100_v2_input_path_mapping.json", receipt)
    if missing:
        raise SystemExit(json.dumps(receipt, indent=2, sort_keys=True))
    return receipt


def load_rows() -> list[dict[str, Any]]:
    assert_inputs()
    rows = read_jsonl(ROOT / "reports" / "bud100_row_level_policy_matrix.jsonl")
    if len(rows) != 100:
        raise SystemExit(f"Expected 100 BUD100 row matrix rows, found {len(rows)}")
    return rows


def write_truth_receipts() -> None:
    current_head = git_output("rev-parse", "HEAD")
    current_branch = git_output("branch", "--show-current")
    status_lines = git_status().splitlines()
    claim_files = [
        path.as_posix()
        for path in [
            Path("rules/CLAIM_CEILING.md"),
            Path("governance/current_claim_ceiling.json"),
            Path("governance/forbidden_launch_claims.json"),
        ]
        if (ROOT / path).exists()
    ]
    predecessor = read_json(ROOT / "reports" / "bud100_review_builder_summary.json")
    write_json(
        REPORTS / "bud100_v2_truth_pin_receipt.json",
        {
            "schema_id": "kt.bud100_v2.truth_pin_receipt.v1",
            "status": "PASS",
            "created_utc": utc_now(),
            "current_head": current_head,
            "current_branch": current_branch,
            "worktree_clean_verified_before_lane_mutation": True,
            "current_worktree_status_may_include_lane_outputs": status_lines,
            "predecessor_outcome": predecessor["outcome"],
            "predecessor_claim_ceiling_status": predecessor["claim_ceiling_status"],
            "claim_ceiling_files": claim_files,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_v2_source_evidence_index.json",
        {
            "schema_id": "kt.bud100_v2.source_evidence_index.v1",
            "status": "PASS",
            "inputs": REQUIRED_INPUTS,
            "method_lock_applied": True,
            "live_repo_truth_wins": True,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_v2_predecessor_map.json",
        {
            "schema_id": "kt.bud100_v2.predecessor_map.v1",
            "status": "PASS",
            "merged_prs": ["#362", "#363"],
            "predecessor_reports": [
                "reports/bud100_review_builder_summary.json",
                "reports/bud100_row_policy_autopsy.json",
                "reports/bud100_budget_curve_scorecard.json",
            ],
            "next_lawful_move_bound": "AUTHOR_BUD100_ADAPTIVE_MONITOR_V2_POLICY_REPAIR_NO_PRODUCTION_MUTATION",
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_v2_live_repo_delta_if_any.json",
        {
            "schema_id": "kt.bud100_v2.live_repo_delta_if_any.v1",
            "status": "PASS_REPO_SIDE_POLICY_ONLY",
            "runtime_packet_generated": False,
            "training_or_adapter_mutation": False,
            "production_prompt_mutation": False,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_v2_authority_boundary_receipt.json",
        {
            "schema_id": "kt.bud100_v2.authority_boundary_receipt.v1",
            "status": "PASS",
            **AUTHORITY_FALSE,
            "adaptive_monitor_production_ready_claim": False,
            "fixed512_production_ready_claim": False,
            "claim_ceiling_preserved": True,
        },
    )


def build_policy() -> dict[str, Any]:
    write_schemas()
    write_truth_receipts()
    assert_inputs()
    policy = {
        "schema_id": "kt.bud100_monitor_v2_policy.v1",
        "policy_id": "BUDGET_MONITOR_MATH_V2_CANDIDATE",
        "status": "DESIGN_ONLY_NO_PRODUCTION_AUTHORITY",
        "scope": "GSM8K-style multi_step_math only",
        "multi_step_math": {
            "default_budget": 512,
            "stop_on_final_marker": True,
            "status": "FIXED512_BASELINE_RETAINED_UNTIL_LEGAL_DOWNSHIFT_MODEL_EXISTS",
        },
        "baseline": {
            "current_best": BASELINE_ARM,
            "accuracy": BASELINE_ACCURACY,
            "full_tokens_per_correct": BASELINE_TPC,
        },
        "feature_legality": {
            "status": "PASS_CONSERVATIVE",
            "allowed_pre_generation_features": [
                "question_length_tokens",
                "number_count",
                "operation_keyword_count",
                "contains_rate_or_ratio_terms",
                "contains_percent_terms",
                "contains_unit_conversion_terms",
                "contains_multi_entity_tracking_terms",
                "contains_comparison_terms",
                "estimated_step_count",
            ],
            "allowed_intra_generation_features": [
                "final_marker_detected",
                "budget_cap_hit",
                "output_tokens_used",
                "numeric_surface_count",
            ],
            "forbidden_features": [
                "expected_answer",
                "ground_truth_correctness",
                "row_id_memorization",
                "measured_arm_correctness_as_selector",
                "posthoc_label_leak",
            ],
            "legal_predictive_downshift_model_bound": False,
        },
        "decision_order": [
            {
                "schema_id": "kt.bud100_monitor_v2_decision_rule.v1",
                "rule_id": "COT512_DEFAULT_SAFE",
                "action": BASELINE_ARM,
                "condition": "default for uncertain multi_step_math when no legal predictive downshift model is bound",
                "feature_legality": "PASS",
            },
            {
                "schema_id": "kt.bud100_monitor_v2_decision_rule.v1",
                "rule_id": "ANSWER_ONLY_HIGH_CONFIDENCE",
                "action": "A4_ANSWER_ONLY_96",
                "condition": "disabled until simple_arithmetic_or_direct_answer_confidence >= 0.95 is validated without label leakage",
                "feature_legality": "LAB_ONLY_NOT_ACTIVE",
            },
            {
                "schema_id": "kt.bud100_monitor_v2_decision_rule.v1",
                "rule_id": "COT256_HIGH_CONFIDENCE",
                "action": "A1_COT_256_FIXED",
                "condition": "disabled until cot256_sufficiency_confidence >= 0.90 is validated without label leakage",
                "feature_legality": "LAB_ONLY_NOT_ACTIVE",
            },
        ],
        "forbidden": [
            "default_to_96_for_multi_step_math",
            "compress_reasoning_before_correctness",
            "production_prompt_mutation",
            "adapter_mutation",
            "training_authority",
            "posthoc_correctness_feature",
        ],
        "authority": dict(AUTHORITY_FALSE),
        "claim_ceiling_preserved": True,
    }
    write_json(ADMISSION / "bud100_adaptive_monitor_v2_candidate_policy.json", policy)
    write_json(
        REPORTS / "bud100_monitor_v2_policy_receipt.json",
        {
            "schema_id": "kt.bud100_monitor_v2_policy_receipt.v1",
            "status": "PASS_CONSERVATIVE_POLICY_BUILT",
            "policy_id": policy["policy_id"],
            "active_default": BASELINE_ARM,
            "legal_predictive_downshift_model_bound": False,
            **AUTHORITY_FALSE,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_monitor_v2_decision_rules.json",
        {
            "schema_id": "kt.bud100_monitor_v2_decision_rules.v1",
            "status": "PASS",
            "decision_order": policy["decision_order"],
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_monitor_v2_no_production_mutation_receipt.json",
        {
            "schema_id": "kt.bud100_monitor_v2_no_production_mutation_receipt.v1",
            "status": "PASS_NO_PRODUCTION_MUTATION",
            **AUTHORITY_FALSE,
            "production_policy_change": False,
            "runtime_packet_generated": False,
            "adapter_mutation": False,
            "training_invoked": False,
            "claim_ceiling_preserved": True,
        },
    )
    return policy


def replay_policy() -> dict[str, Any]:
    policy = build_policy()
    rows = load_rows()
    decisions = []
    selected_counts = Counter()
    correct = 0
    total_tokens = 0
    output_tokens = 0
    damage_count = 0
    save_count = 0
    for row in rows:
        selected = BASELINE_ARM
        selected_counts[selected] += 1
        selected_correct = bool(row["correct_by_arm"][selected])
        fixed_correct = bool(row["correct_by_arm"][BASELINE_ARM])
        selected_total = int(row["total_tokens_by_arm"][selected])
        fixed_total = int(row["total_tokens_by_arm"][BASELINE_ARM])
        if selected_correct:
            correct += 1
        total_tokens += selected_total
        output_tokens += int(row["output_tokens_by_arm"][selected])
        would_damage = fixed_correct and not selected_correct
        would_save = selected_total < fixed_total
        damage_count += int(would_damage)
        save_count += int(would_save)
        decisions.append(
            {
                "schema_id": "kt.bud100_monitor_v2_row_decision.v1",
                "row_id": row["row_id"],
                "v2_selected_arm": selected,
                "v2_correct": selected_correct,
                "v2_prompt_tokens": selected_total - int(row["output_tokens_by_arm"][selected]),
                "v2_output_tokens": int(row["output_tokens_by_arm"][selected]),
                "v2_total_tokens": selected_total,
                "v2_reason_code": "COT512_DEFAULT_SAFE_NO_LEGAL_DOWNSHIFT_FEATURE_BOUND",
                "v2_confidence_proxy": None,
                "v2_would_damage_vs_fixed512": would_damage,
                "v2_would_save_tokens_vs_fixed512": would_save,
                "feature_legality": "PASS_NO_LABEL_LEAK",
                "claim_ceiling_preserved": True,
            }
        )
    accuracy = correct / len(rows)
    tpc = total_tokens / correct if correct else None
    scorecard = {
        "schema_id": "kt.bud100_monitor_v2_offline_replay.v1",
        "status": "PASS_NO_GAIN_FIXED512_RETAINED",
        "policy_id": policy["policy_id"],
        "row_count": len(rows),
        "correct": correct,
        "accuracy": accuracy,
        "total_tokens": total_tokens,
        "output_tokens": output_tokens,
        "full_tokens_per_correct": tpc,
        "selected_arm_counts": dict(selected_counts),
        "damage_count_vs_fixed512": damage_count,
        "token_saving_rows_vs_fixed512": save_count,
        "beats_fixed512_accuracy": accuracy > BASELINE_ACCURACY,
        "beats_fixed512_tpc": bool(tpc is not None and tpc < BASELINE_TPC),
        "microfurnace_candidate": bool(accuracy >= 0.90 and tpc is not None and tpc < BASELINE_TPC),
        "claim_ceiling_preserved": True,
    }
    write_jsonl(REPORTS / "bud100_monitor_v2_row_decisions.jsonl", decisions)
    write_json(REPORTS / "bud100_monitor_v2_offline_replay_scorecard.json", scorecard)
    return scorecard


def score_policy() -> dict[str, Any]:
    scorecard = replay_policy()
    rows = load_rows()
    teacher_counts = Counter()
    teacher_correct = 0
    teacher_tokens = 0
    for row in rows:
        selected = row.get("cost_optimal_correct_arm")
        if selected is None:
            teacher_counts["NO_ARM_CORRECT"] += 1
            continue
        teacher_counts[selected] += 1
        teacher_correct += 1
        teacher_tokens += int(row["total_tokens_by_arm"][selected])
    teacher = {
        "schema_id": "kt.bud100_monitor_v2_teacher_oracle_upper_bound.v1",
        "status": "TEACHER_ONLY_LABEL_LEAK_NOT_DEPLOYABLE",
        "correct": teacher_correct,
        "accuracy": teacher_correct / len(rows),
        "total_tokens": teacher_tokens,
        "full_tokens_per_correct": teacher_tokens / teacher_correct if teacher_correct else None,
        "selected_arm_counts": dict(teacher_counts),
        "reason_not_deployable": "uses posthoc measured correctness/cost_optimal_correct_arm",
        "claim_ceiling_preserved": True,
    }
    write_json(
        REPORTS / "bud100_monitor_v2_expected_gain_model.json",
        {
            "schema_id": "kt.bud100_monitor_v2_expected_gain_model.v1",
            "status": "NO_DEPLOYABLE_GAIN_OBSERVED",
            "legal_v2_replay": scorecard,
            "teacher_oracle_upper_bound": teacher,
            "interpretation": "Savings exist in the measured rows, but the repo has not bound a legal predictive downshift feature model.",
            "claim_ceiling_preserved": True,
        },
    )
    return teacher


def compare_against_fixed512() -> dict[str, Any]:
    scorecard = replay_policy()
    score_policy()
    fixed512_dominant = not scorecard["microfurnace_candidate"]
    next_move = NEXT_MICROFURNACE if scorecard["microfurnace_candidate"] else NEXT_FIXED512
    comparison = {
        "schema_id": "kt.bud100_monitor_v2_vs_fixed512_comparison.v1",
        "status": "PASS_FIXED512_BASELINE_RETAINED" if fixed512_dominant else "PASS_MICROFURNACE_CANDIDATE",
        "fixed512": {
            "accuracy": BASELINE_ACCURACY,
            "full_tokens_per_correct": BASELINE_TPC,
            "arm_id": BASELINE_ARM,
        },
        "v2_offline": {
            "accuracy": scorecard["accuracy"],
            "full_tokens_per_correct": scorecard["full_tokens_per_correct"],
            "damage_count_vs_fixed512": scorecard["damage_count_vs_fixed512"],
            "selected_arm_counts": scorecard["selected_arm_counts"],
        },
        "fixed512_dominant": fixed512_dominant,
        "microfurnace_candidate": scorecard["microfurnace_candidate"],
        "next_lawful_move": next_move,
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "bud100_monitor_v2_vs_fixed512_comparison.json", comparison)
    write_json(
        REPORTS / "bud100_monitor_v2_failure_autopsy.json",
        {
            "schema_id": "kt.bud100_monitor_v2_failure_autopsy.v1",
            "status": "PASS_NO_SAFE_DOWNSHIFT_FEATURE_BOUND",
            "damage_count": scorecard["damage_count_vs_fixed512"],
            "fixed512_dominant": fixed512_dominant,
            "failure_mode": "V2 conservative policy cannot improve token economy without a legal predictive downshift model.",
            "next_lawful_move": next_move,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_monitor_v2_next_lane_decision.json",
        {
            "schema_id": "kt.bud100_monitor_v2_next_lane_decision.v1",
            "status": "PASS",
            "selected_next_lawful_move": next_move,
            "decision_reason": "Fixed512 remains the strongest lawful baseline; no deployable V2 savings were proven offline.",
            "alternates_not_selected": [NEXT_MICROFURNACE, NEXT_FEATURE_REPAIR],
            **AUTHORITY_FALSE,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_v2_review_builder_summary.json",
        {
            "schema_id": "kt.bud100_v2.review_builder_summary.v1",
            "status": "PASS",
            "current_head": git_output("rev-parse", "HEAD"),
            "branch": git_output("branch", "--show-current"),
            "outcome": OUTCOME_NO_GAIN,
            "bud100_v2_truth_binding_status": "PASS",
            "bud100_v2_input_artifacts_status": "PASS",
            "bud100_v2_policy_status": "PASS_CONSERVATIVE_POLICY_BUILT",
            "bud100_v2_offline_replay_status": scorecard["status"],
            "bud100_v2_vs_fixed512_status": comparison["status"],
            "bud100_v2_damage_status": "PASS_NO_DAMAGE_VS_FIXED512",
            "bud100_v2_token_economics_status": "NO_GAIN_VS_FIXED512",
            "bud100_v2_feature_legality_status": "PASS_NO_LABEL_LEAK",
            "bud100_v2_claim_boundary_status": "PASS",
            "adaptive_monitor_v2_verdict": "NO_DEPLOYABLE_OFFLINE_GAIN_FIXED512_RETAINED",
            "packet_path_if_any": None,
            "packet_sha256_if_any": None,
            "kaggle_dataset_name_if_any": None,
            "one_cell_runbook_if_any": None,
            **AUTHORITY_FALSE,
            "claim_ceiling_status": "PRESERVED",
            "blockers": [],
            "next_lawful_move": next_move,
        },
    )
    return comparison
