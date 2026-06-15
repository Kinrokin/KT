from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"

EXPECTED_NEXT = "AUTHOR_G32_STRATIFIED_FIXED512_WEAK_BASELINE_FAILURE_OWNERSHIP_V1"
EXPECTED_OUTCOME = (
    "KT_PARETO_IMPORTED__STRATIFIED_FIXED512_WEAK_BASELINE_REVIEW_BOUND__"
    "384_KNEE_NOT_DEPLOYABLE__640_SENTINEL_BOUND__G32_STRATIFIED_OWNERSHIP_NEXT__CLAIM_CEILING_PRESERVED"
)

REQUIRED_JSON = [
    "ktpareto_assessment_import_receipt.json",
    "ktpareto_scorecard_reconciliation.json",
    "ktpareto_slice_exchangeability_receipt.json",
    "ktpareto_stratified_budget_frontier.json",
    "ktpareto_stratified_fixed512_estimate.json",
    "ktpareto_stratified_false_downshift_report.json",
    "ktpareto_384_false_downshift_genome.json",
    "ktpareto_384_safe_stratum_candidate.json",
    "ktpareto_cot640_recovery_damage_analysis.json",
    "ktpareto_no_correct_arm_failure_genome.json",
    "ktpareto_no_correct_arm_counterfactual_plan.json",
    "ktpareto_claim_boundary_receipt.json",
    "ktpareto_next_lane_decision.json",
    "ktpareto_review_builder_summary.json",
]

REQUIRED_JSONL = [
    "ktpareto_difficulty_proxy_matrix.jsonl",
    "ktpareto_384_false_downshift_rows.jsonl",
    "ktpareto_cot640_escalation_candidate_rows.jsonl",
    "ktpareto_overthink_risk_rows.jsonl",
    "ktpareto_no_correct_arm_autopsy.jsonl",
]


def read_json(name: str) -> Any:
    return json.loads((REPORTS / name).read_text(encoding="utf-8"))


def read_jsonl(name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (REPORTS / name).read_text(encoding="utf-8").splitlines() if line.strip()]


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def validate() -> dict[str, Any]:
    missing = [str(REPORTS / name) for name in REQUIRED_JSON + REQUIRED_JSONL if not (REPORTS / name).exists()]
    assert_true(not missing, f"missing required reports: {missing}")

    summary = read_json("ktpareto_review_builder_summary.json")
    import_receipt = read_json("ktpareto_assessment_import_receipt.json")
    scorecard = read_json("ktpareto_scorecard_reconciliation.json")
    exchangeability = read_json("ktpareto_slice_exchangeability_receipt.json")
    fixed512 = read_json("ktpareto_stratified_fixed512_estimate.json")
    false384 = read_jsonl("ktpareto_384_false_downshift_rows.jsonl")
    genome384 = read_json("ktpareto_384_false_downshift_genome.json")
    cot640 = read_json("ktpareto_cot640_recovery_damage_analysis.json")
    no_correct = read_jsonl("ktpareto_no_correct_arm_autopsy.jsonl")
    no_correct_genome = read_json("ktpareto_no_correct_arm_failure_genome.json")
    claim = read_json("ktpareto_claim_boundary_receipt.json")
    next_lane = read_json("ktpareto_next_lane_decision.json")
    proxy_rows = read_jsonl("ktpareto_difficulty_proxy_matrix.jsonl")

    assert_true(summary["status"] == "PASS", "summary must pass")
    assert_true(summary["outcome"] == EXPECTED_OUTCOME, "unexpected outcome")
    assert_true(import_receipt["status"] == "PASS", "assessment import SHA must pass")
    assert_true(scorecard["status"] == "PASS", "scorecard reconciliation must pass")
    assert_true(scorecard["oracle_diagnostic_status"] == "PASS", "oracle diagnostic must pass")
    assert_true(scorecard["knee_candidate"] == 384, "knee candidate must be 384")
    assert_true(scorecard["false_downshift_count_at_384_vs_512"] == 7, "384 false-downshift count must be 7")
    assert_true(exchangeability["exchangeability_verdict"] in {"ROW_DIFFICULTY_STRATUM_REQUIRED", "PARTIAL_BEHAVIORAL_STRATIFICATION_ONLY"}, "exchangeability verdict must force stratum review")
    assert_true(len(proxy_rows) == 400, "difficulty proxy matrix must cover BUD100, KT512BASE, and KTPARETO rows")
    assert_true(fixed512["status"] == "FIXED512_WEAK_OR_SLICE_SHIFT_REVIEW_REQUIRED", "fixed512 weak/slice-shift court must trigger")
    assert_true(len(false384) == 7, "384 false-downshift rows must be 7")
    assert_true(genome384["deployment_authority"] is False, "384 deployment must be false")
    assert_true(genome384["knee_classification"] == "ECONOMIC_KNEE_CANDIDATE_ONLY", "384 must be non-deployable knee candidate")
    assert_true(cot640["classification"] == "SENTINEL_ONLY", "640 must be sentinel-only")
    assert_true(cot640["cot640_recovery_count"] == 4, "640 recovery rows must be 4")
    assert_true(cot640["cot640_damage_count"] == 2, "640 damage rows must be 2")
    assert_true(cot640["deployment_authority"] is False, "640 deployment must be false")
    assert_true(len(no_correct) == 14, "no-correct-arm autopsy must cover 14 rows")
    assert_true(no_correct_genome["training_authority"] is False, "no-correct-arm rows cannot authorize training")

    for key in [
        "dataset_generation_authority",
        "training_authority",
        "promotion_authority",
        "selector_deployment_authority",
        "runtime_authority",
        "adapter_mutation_authority",
        "production_prompt_mutation_authority",
    ]:
        assert_true(claim[key] is False, f"{key} must be false")
        assert_true(summary[key] is False, f"{key} must be false in summary")

    assert_true(next_lane["selected_next_lawful_move"] == EXPECTED_NEXT, "unexpected next lawful move")
    assert_true(summary["next_lawful_move"] == EXPECTED_NEXT, "summary next lawful move mismatch")
    assert_true(summary["packet_path_if_any"] is None, "review lane must not emit packet")
    assert_true(summary["kaggle_dataset_name_if_any"] is None, "review lane must not emit Kaggle dataset")

    receipt = {
        "schema_id": "kt.ktpareto.review_validation_receipt.v1",
        "status": "PASS",
        "assessment_import_status": import_receipt["status"],
        "scorecard_reconciliation_status": scorecard["status"],
        "slice_exchangeability_status": exchangeability["status"],
        "false_downshift_384_count": len(false384),
        "cot640_recovery_count": cot640["cot640_recovery_count"],
        "cot640_damage_count": cot640["cot640_damage_count"],
        "no_correct_arm_count": len(no_correct),
        "next_lawful_move": EXPECTED_NEXT,
        "claim_ceiling_preserved": True,
    }
    (REPORTS / "ktpareto_review_validation_receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return receipt


if __name__ == "__main__":
    print(json.dumps(validate(), indent=2, sort_keys=True))
