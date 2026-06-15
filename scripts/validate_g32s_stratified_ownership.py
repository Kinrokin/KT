#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_JSON = [
    "reports/g32s_input_path_mapping.json",
    "reports/g32s_stratified_baseline_matrix.json",
    "reports/g32s_fixed512_failure_by_stratum.json",
    "reports/g32s_384_false_downshift_by_stratum.json",
    "reports/g32s_384_safe_stratum_candidate.json",
    "reports/g32s_640_recovery_damage_by_stratum.json",
    "reports/g32s_stratified_repair_bid_ledger.json",
    "reports/g32s_stratified_selector_risk_report.json",
    "reports/g32s_mvs_receipt.json",
    "reports/g32s_train_decision.json",
    "reports/g32s_counterfactual_plan.json",
    "reports/g32s_next_microfurnace_spec.json",
    "reports/g32s_next_lane_decision.json",
    "reports/g32s_builder_summary.json",
    "policies/g32s_difficulty_aware_selector_v2.json",
]

REQUIRED_JSONL = [
    "reports/g32s_difficulty_proxy_receipt.jsonl",
    "reports/g32s_fixed512_failure_genome.jsonl",
    "reports/g32s_no_correct_counterfactual_matrix.jsonl",
    "reports/g32s_no_correct_arm_morbidity_review.jsonl",
    "reports/g32s_false384_causal_matrix.jsonl",
    "reports/g32s_cot640_recovery_damage_matrix.jsonl",
    "reports/g32s_continue_when_helpful_seed.jsonl",
    "reports/g32s_stop_before_overthink_seed.jsonl",
    "reports/g32s_human_anchor_request_queue.jsonl",
]


def read_json(rel_path: str) -> dict[str, Any]:
    return json.loads((ROOT / rel_path).read_text(encoding="utf-8-sig"))


def read_jsonl(rel_path: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (ROOT / rel_path).read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def assert_false_authorities(payload: dict[str, Any], path: str) -> None:
    for key in [
        "runtime_authority",
        "dataset_generation_authority",
        "training_authority",
        "promotion_authority",
        "selector_deployment_authority",
        "adapter_mutation_authority",
        "production_prompt_mutation_authority",
    ]:
        if key in payload and payload[key] is not False:
            raise AssertionError(f"{path}: {key} must be false")


def main() -> dict[str, Any]:
    missing = [path for path in REQUIRED_JSON + REQUIRED_JSONL if not (ROOT / path).exists()]
    if missing:
        raise SystemExit(f"missing required G32S outputs: {missing}")

    for path in REQUIRED_JSON:
        assert_false_authorities(read_json(path), path)
    for path in REQUIRED_JSONL:
        for row in read_jsonl(path):
            assert_false_authorities(row, path)

    summary = read_json("reports/g32s_builder_summary.json")
    fixed = read_json("reports/g32s_fixed512_failure_by_stratum.json")
    false384 = read_json("reports/g32s_384_false_downshift_by_stratum.json")
    safe384 = read_json("reports/g32s_384_safe_stratum_candidate.json")
    cot640 = read_json("reports/g32s_640_recovery_damage_by_stratum.json")
    mvs = read_json("reports/g32s_mvs_receipt.json")
    train = read_json("reports/g32s_train_decision.json")
    next_lane = read_json("reports/g32s_next_lane_decision.json")
    policy = read_json("policies/g32s_difficulty_aware_selector_v2.json")
    no_correct = read_jsonl("reports/g32s_no_correct_counterfactual_matrix.jsonl")
    continue_seed = read_jsonl("reports/g32s_continue_when_helpful_seed.jsonl")
    stop_seed = read_jsonl("reports/g32s_stop_before_overthink_seed.jsonl")
    false_rows = read_jsonl("reports/g32s_false384_causal_matrix.jsonl")

    checks = {
        "summary_pass": summary["status"] == "PASS",
        "row_count_100": summary["counts"]["row_count"] == 100,
        "fixed512_failures_18": fixed["fixed512_failure_count"] == 18,
        "no_correct_14": len(no_correct) == 14,
        "false384_7": false384["false_downshift_damage"] == 7 and len(false_rows) == 7,
        "cot640_recovery_4": cot640["cot640_recovery_count"] == 4 and len(continue_seed) == 4,
        "cot640_damage_2": cot640["cot640_damage_count"] == 2 and len(stop_seed) == 2,
        "384_not_deployable": safe384["global_deployment_gate"] == "BLOCKED_FALSE_DOWNSHIFT_DAMAGE",
        "640_sentinel_only": cot640["status"] == "SENTINEL_ONLY",
        "mvs_blocks_training": mvs["training_authority"] is False and mvs["status"].startswith("BLOCKED"),
        "train_no_train": train["status"] == "NO_TRAIN" and train["training_authority"] is False,
        "selector_seed_only": policy["status"] == "SEED_ONLY_NO_RUNTIME_AUTHORITY",
        "selector_has_required_negative_class": "COT512_INSUFFICIENT" in policy["classes"],
        "feature_legality_forbids_hindsight": all(
            forbidden in policy["forbidden_features"]
            for forbidden in ["row_id", "expected_answer", "measured_arm_correctness", "posthoc_correctness", "oracle_correct_arm"]
        ),
        "single_next_lane": next_lane["selected_next_lawful_move"] == "AUTHOR_KTPARETO_COUNTERFACTUAL_MICROFURNACE_PACKET_V1",
        "claim_ceiling_preserved": summary["claim_ceiling_status"] == "PRESERVED",
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    result = {
        "schema_id": "kt.g32s.validation_receipt.v2",
        "status": status,
        "checks": checks,
        "next_lawful_move": next_lane["selected_next_lawful_move"],
        "claim_ceiling_status": "PRESERVED",
    }
    (ROOT / "reports").mkdir(parents=True, exist_ok=True)
    (ROOT / "reports" / "g32s_validation_receipt.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    if status != "PASS":
        raise SystemExit(1)
    return result


if __name__ == "__main__":
    main()
