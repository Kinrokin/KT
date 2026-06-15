import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def ensure_review_imported() -> None:
    required = [
        ROOT / "reports" / "ktpareto_review_builder_summary.json",
        ROOT / "reports" / "ktpareto_assessment_import_receipt.json",
        ROOT / "reports" / "ktpareto_no_correct_arm_autopsy.jsonl",
    ]
    if all(path.exists() for path in required):
        return
    subprocess.run([sys.executable, "scripts/import_ktpareto_assessment.py"], cwd=ROOT, check=True)


def read_json(path: str):
    ensure_review_imported()
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def read_jsonl(path: str):
    ensure_review_imported()
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8").splitlines() if line.strip()]


def test_ktpareto_assessment_sha_and_scorecard_reconcile():
    receipt = read_json("reports/ktpareto_assessment_import_receipt.json")
    scorecard = read_json("reports/ktpareto_scorecard_reconciliation.json")
    assert receipt["status"] == "PASS"
    assert receipt["assessment_sha256"] == "fa417a164604301131be89317991f1ecc4289095dc021e92cc7b6fdf549837af"
    assert scorecard["status"] == "PASS"
    assert scorecard["oracle_diagnostic_status"] == "PASS"
    assert scorecard["knee_candidate"] == 384
    assert scorecard["false_downshift_count_at_384_vs_512"] == 7


def test_ktpareto_slice_exchangeability_and_proxy_matrix_exist():
    exchangeability = read_json("reports/ktpareto_slice_exchangeability_receipt.json")
    proxies = read_jsonl("reports/ktpareto_difficulty_proxy_matrix.jsonl")
    assert len(proxies) == 400
    assert {row["slice_id"] for row in proxies} == {"BUD100", "KT512BASE", "KTPARETO"}
    assert exchangeability["exchangeability_verdict"] in {
        "ROW_DIFFICULTY_STRATUM_REQUIRED",
        "PARTIAL_BEHAVIORAL_STRATIFICATION_ONLY",
    }
    required_fields = {
        "question_token_length",
        "number_count",
        "entity_count",
        "operation_keyword_count",
        "estimated_step_count",
        "rate_ratio_percent_terms",
        "fraction_decimal_terms",
        "unit_conversion_terms",
        "comparison_terms",
        "multi_entity_tracking_terms",
    }
    if exchangeability["question_text_status"].startswith("PASS"):
        assert required_fields <= set(proxies[0])


def test_ktpareto_384_is_not_deployable():
    false_rows = read_jsonl("reports/ktpareto_384_false_downshift_rows.jsonl")
    genome = read_json("reports/ktpareto_384_false_downshift_genome.json")
    candidate = read_json("reports/ktpareto_384_safe_stratum_candidate.json")
    assert len(false_rows) == 7
    assert genome["knee_classification"] == "ECONOMIC_KNEE_CANDIDATE_ONLY"
    assert genome["deployment_authority"] is False
    assert candidate["status"] == "CANDIDATE_ONLY_NOT_DEPLOYABLE"


def test_ktpareto_640_is_sentinel_only():
    analysis = read_json("reports/ktpareto_cot640_recovery_damage_analysis.json")
    recovery_rows = read_jsonl("reports/ktpareto_cot640_escalation_candidate_rows.jsonl")
    assert analysis["classification"] == "SENTINEL_ONLY"
    assert analysis["cot640_recovery_count"] == 4
    assert analysis["cot640_damage_count"] == 2
    assert analysis["deployment_authority"] is False
    assert len(recovery_rows) == 4


def test_ktpareto_no_correct_rows_feed_g32_not_training():
    rows = read_jsonl("reports/ktpareto_no_correct_arm_autopsy.jsonl")
    genome = read_json("reports/ktpareto_no_correct_arm_failure_genome.json")
    plan = read_json("reports/ktpareto_no_correct_arm_counterfactual_plan.json")
    assert len(rows) == 14
    assert genome["status"] == "PASS_G32_OWNERSHIP_REQUIRED"
    assert genome["training_authority"] is False
    assert plan["training_authority"] is False
    assert all(row["repair_owner_candidate"] == "UNKNOWN_G32_REQUIRED" for row in rows)


def test_ktpareto_review_authorities_and_next_lane():
    summary = read_json("reports/ktpareto_review_builder_summary.json")
    claim = read_json("reports/ktpareto_claim_boundary_receipt.json")
    next_lane = read_json("reports/ktpareto_next_lane_decision.json")
    assert summary["outcome"].startswith("KT_PARETO_IMPORTED__STRATIFIED_FIXED512_WEAK_BASELINE_REVIEW_BOUND")
    for key in [
        "dataset_generation_authority",
        "training_authority",
        "promotion_authority",
        "selector_deployment_authority",
        "runtime_authority",
        "adapter_mutation_authority",
        "production_prompt_mutation_authority",
    ]:
        assert summary[key] is False
        assert claim[key] is False
    assert next_lane["selected_next_lawful_move"] == "AUTHOR_G32_STRATIFIED_FIXED512_WEAK_BASELINE_FAILURE_OWNERSHIP_V1"
    assert summary["packet_path_if_any"] is None
    assert summary["kaggle_dataset_name_if_any"] is None
