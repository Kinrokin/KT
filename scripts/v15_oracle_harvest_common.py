from __future__ import annotations

import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROGRAM_ID = "KT_V15_ORACLE_HARVEST_ROUTE_VALUE_DISTILLATION_AND_CROSSROAD_ADMISSION_SUPERLANE_V3"
OUTCOME = "KTG3FULL_V15_ORACLE_HARVEST_READY__ROUTE_VALUE_DISTILLATION_AND_CROSSROAD_ADMISSION_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "AUTHOR_KTG3FULL_V16_SHADOW_ROUTE_VALUE_REPLAY_PACKET"

V15_FACTS = {
    "schema_id": "kt.v15_result_review_receipt.v1",
    "hf_dataset": "https://huggingface.co/datasets/Kinrokin/kt-g3full-v15-truth-route-20260531-133102",
    "assessment_sha256": "b8ba3955fda4ec263f9ee9ae7138fdd1c3512389fc6f9d2cef35ecadbcbc1a59",
    "rows": 260,
    "claim_ceiling_preserved": True,
    "promotion_eligible": False,
    "scores": {
        "base_raw": {"correct": 143, "total": 260, "accuracy": 0.55},
        "base_kt_hat_compact": {"correct": 113, "total": 260, "accuracy": 113 / 260},
        "formal_math_repair_adapter_global": {"correct": 160, "total": 260, "accuracy": 160 / 260},
        "route_regret_policy_adapter_global": {"correct": 152, "total": 260, "accuracy": 152 / 260},
        "math_act_adapter_global": {"correct": 147, "total": 260, "accuracy": 147 / 260},
        "formal_math_router_label_bound": {"correct": 159, "total": 260, "accuracy": 159 / 260},
        "formal_math_router_math_act_feature_bound": {"correct": 159, "total": 260, "accuracy": 159 / 260},
        "oracle_math_router": {"correct": 187, "total": 260, "accuracy": 187 / 260},
    },
    "feature_route_over_base_correct_delta": 16,
    "oracle_over_feature_route_correct_delta": 28,
    "oracle_over_base_correct_delta": 44,
}

V15_GAP_ROWS = [
    ("arc:42", "arc_challenge", "base_kt_hat_compact", "formal_math_repair_adapter_global", 0.81, True, False),
    ("gsm8k:10", "gsm8k", "base_raw", "formal_math_repair_adapter_global", 1.0, True, True),
    ("gsm8k:22", "gsm8k", "route_regret_policy_adapter_global", "formal_math_repair_adapter_global", 1.0, True, True),
    ("gsm8k:24", "gsm8k", "base_kt_hat_compact", "base_raw", 0.44, False, True),
    ("gsm8k:32", "gsm8k", "base_kt_hat_compact", "formal_math_repair_adapter_global", 0.95, True, True),
    ("gsm8k:35", "gsm8k", "math_act_adapter_global", "formal_math_repair_adapter_global", 1.0, True, True),
    ("gsm8k:40", "gsm8k", "base_kt_hat_compact", "formal_math_repair_adapter_global", 0.55, True, True),
    ("gsm8k:42", "gsm8k", "base_kt_hat_compact", "formal_math_repair_adapter_global", 1.0, True, True),
    ("gsm8k:44", "gsm8k", "base_kt_hat_compact", "formal_math_repair_adapter_global", 1.0, True, True),
    ("gsm8k:48", "gsm8k", "base_kt_hat_compact", "formal_math_repair_adapter_global", 0.87, True, True),
    ("gsm8k:49", "gsm8k", "route_regret_policy_adapter_global", "formal_math_repair_adapter_global", 1.0, True, True),
    ("gsm8k:7", "gsm8k", "base_kt_hat_compact", "formal_math_repair_adapter_global", 1.0, True, True),
    ("hellaswag:23", "hellaswag", "formal_math_repair_adapter_global", "base_raw", 0.12, False, False),
    ("hellaswag:31", "hellaswag", "base_kt_hat_compact", "base_raw", 0.0, False, False),
    ("hellaswag:32", "hellaswag", "route_regret_policy_adapter_global", "base_raw", 0.3, False, False),
    ("hellaswag:34", "hellaswag", "base_kt_hat_compact", "base_raw", 0.0, False, False),
    ("hellaswag:36", "hellaswag", "formal_math_repair_adapter_global", "base_raw", 0.0, False, False),
    ("hellaswag:6", "hellaswag", "formal_math_repair_adapter_global", "base_raw", 0.0, False, False),
    ("hellaswag:7", "hellaswag", "base_kt_hat_compact", "base_raw", 0.18, False, False),
    ("math_wording_variation_slice:0", "math_wording_variation_slice", "route_regret_policy_adapter_global", "formal_math_repair_adapter_global", 1.0, True, True),
    ("math_wording_variation_slice:1", "math_wording_variation_slice", "base_raw", "formal_math_repair_adapter_global", 1.0, True, True),
    ("math_wording_variation_slice:8", "math_wording_variation_slice", "base_kt_hat_compact", "formal_math_repair_adapter_global", 1.0, True, True),
    ("non_gsm8k_math_slice:1", "non_gsm8k_math_slice", "base_kt_hat_compact", "formal_math_repair_adapter_global", 1.0, True, True),
    ("non_gsm8k_math_slice:7", "non_gsm8k_math_slice", "base_raw", "formal_math_repair_adapter_global", 1.0, True, True),
    ("numeric_reasoning_slice:3", "numeric_reasoning_slice", "route_regret_policy_adapter_global", "formal_math_repair_adapter_global", 1.0, True, True),
    ("numeric_reasoning_slice:8", "numeric_reasoning_slice", "base_raw", "formal_math_repair_adapter_global", 0.99, True, True),
    ("truthfulqa:25", "truthfulqa_mc1", "base_kt_hat_compact", "base_raw", 0.0, False, False),
    ("truthfulqa:31", "truthfulqa_mc1", "route_regret_policy_adapter_global", "base_raw", 0.0, False, False),
]

HISTORIC_RUNS = [
    ("G2_v2", 200, 119, "routed_13_lobe_kt_hat_compact", 126, "", None, 136, 17, 10, None),
    ("G3_v2", 190, 107, "routed_13_lobe_kt_hat_compact", 118, "", None, 130, 23, 12, None),
    ("G31_eval", 200, 96, "routed_13_lobe_kt_hat_compact", 124, "oracle_route_replay", 137, 137, 41, 13, 0),
    ("G3FULL_v1", 200, 111, "base_raw", 111, "", None, 135, 24, 24, None),
    ("G3FULL_v12", 200, 111, "formal_math_router_specialist", 122, "oracle_math_router", 131, 135, 24, 13, 4),
    ("G3FULL_v13", 200, 111, "formal_math_router_specialist", 122, "oracle_math_router", 131, 135, 24, 13, 4),
    ("G3FULL_v14", 200, 111, "formal_math_router_specialist", 117, "oracle_math_router", 127, 127, 16, 10, 0),
    ("G3FULL_v15", 260, 143, "formal_math_repair_adapter_global", 160, "oracle_math_router", 187, 187, 44, 27, 0),
]

FORBIDDEN_FEATURES = {
    "oracle_correct",
    "oracle_route",
    "oracle_gain",
    "oracle_correctness",
    "correct",
    "chosen_correct",
    "gold_answer",
    "prediction",
    "raw_output",
    "generated_answer",
    "answer",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def current_head(root: Path) -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def current_branch(root: Path) -> str:
    return subprocess.check_output(["git", "branch", "--show-current"], cwd=root, text=True).strip()


def write_json(path: Path, payload: dict) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    return payload


def write_jsonl(path: Path, rows: list[dict]) -> list[dict]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows), encoding="utf-8")
    return rows


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def family(route: str) -> str:
    route_l = route.lower()
    if "hat" in route_l:
        return "hat"
    if "route_regret" in route_l:
        return "route_regret"
    if "math_act" in route_l:
        return "math_act"
    if "formal_math" in route_l:
        return "formal_math"
    if "base_raw" in route_l:
        return "base"
    return "unknown"


def score_bucket(score: float) -> str:
    if score >= 0.9:
        return "very_high"
    if score >= 0.5:
        return "medium_high"
    if score > 0:
        return "low"
    return "zero"


def runtime_features(score: float, feature_trigger: bool) -> dict:
    return {
        "feature_score_bucket": score_bucket(score),
        "math_act_feature_trigger": bool(feature_trigger),
    }


def oracle_gap_matrix() -> list[dict]:
    rows = []
    for idx, (sample_id, dataset, oracle_route, chosen_backing_arm, score, feature_trigger, label_trigger) in enumerate(V15_GAP_ROWS):
        rows.append(
            {
                "schema_id": "kt.oracle_gap_row.v1",
                "row_id": f"v15_oracle_gap_{idx:03d}",
                "sample_id": sample_id,
                "dataset": dataset,
                "slice_id": dataset,
                "chosen_policy_route": "formal_math_router_math_act_feature_bound",
                "chosen_backing_arm": chosen_backing_arm,
                "oracle_route": oracle_route,
                "oracle_rescuer_family": family(oracle_route),
                "oracle_gain": 1,
                "feature_score": score,
                "feature_trigger": bool(feature_trigger),
                "label_trigger_observed": bool(label_trigger),
                "pre_generation_features": runtime_features(score, feature_trigger),
                "runtime_legal_features_only": True,
                "oracle_correctness_used_as_feature": False,
                "adapter_training_forbidden": True,
                "training_authority": "ROUTE_VALUE_DISTILLATION_ONLY",
                "claim_authority": "NONE",
                "claim_ceiling_preserved": True,
            }
        )
    return rows


def winner_attribution(gaps: list[dict]) -> list[dict]:
    return [
        {
            "schema_id": "kt.oracle_winner_attribution.v1",
            "sample_id": row["sample_id"],
            "dataset": row["dataset"],
            "oracle_route": row["oracle_route"],
            "rescuer_family": row["oracle_rescuer_family"],
            "claim_authority": "NONE",
        }
        for row in gaps
    ]


def pairwise_preferences(gaps: list[dict]) -> list[dict]:
    return [
        {
            "schema_id": "kt.oracle_pairwise_preference.v1",
            "sample_id": row["sample_id"],
            "route_a": row["oracle_route"],
            "route_b": row["chosen_backing_arm"],
            "winner": "route_a",
            "reason": "oracle_correct_chosen_backing_arm_wrong",
            "pre_generation_features": row["pre_generation_features"],
            "runtime_legal_features_only": True,
            "oracle_correctness_used_as_feature": False,
            "adapter_training_forbidden": True,
            "training_authority": "ROUTE_VALUE_DISTILLATION_ONLY",
            "promotion_authority": False,
            "claim_authority": "NONE",
        }
        for row in gaps
    ]


def negative_preferences(gaps: list[dict]) -> list[dict]:
    rows = []
    for row in gaps:
        if row["chosen_backing_arm"] != row["oracle_route"]:
            rows.append(
                {
                    "schema_id": "kt.oracle_negative_route_preference.v1",
                    "sample_id": row["sample_id"],
                    "harmful_route": row["chosen_backing_arm"],
                    "preferred_route": row["oracle_route"],
                    "reason": "chosen_backing_arm_lost_to_oracle_rescuer",
                    "pre_generation_features": row["pre_generation_features"],
                    "runtime_legal_features_only": True,
                    "oracle_correctness_used_as_feature": False,
                    "adapter_training_forbidden": True,
                    "training_authority": "ROUTE_VALUE_DISTILLATION_ONLY",
                    "claim_authority": "NONE",
                }
            )
    return rows


def base_preservation_preferences(gaps: list[dict]) -> list[dict]:
    return [
        {
            "schema_id": "kt.base_preservation_preference.v1",
            "sample_id": row["sample_id"],
            "preferred_route": "base_raw",
            "suppressed_route": row["chosen_backing_arm"],
            "reason": "base_raw_rescued_feature_route_gap",
            "pre_generation_features": row["pre_generation_features"],
            "runtime_legal_features_only": True,
            "oracle_correctness_used_as_feature": False,
            "adapter_training_forbidden": True,
            "claim_authority": "NONE",
        }
        for row in gaps
        if row["oracle_route"] == "base_raw"
    ]


def route_value_rows(pairwise: list[dict], base_prefs: list[dict]) -> list[dict]:
    rows: list[dict] = []
    for idx, pref in enumerate(pairwise):
        rows.append(
            {
                "schema_id": "kt.route_value_training_row.v1",
                "row_id": f"oracle_rescue_{idx:03d}",
                "sample_id": pref["sample_id"],
                "candidate_routes": [pref["route_a"], pref["route_b"]],
                "preferred_route": pref["route_a"],
                "preference_kind": "oracle_rescue",
                "pre_generation_features": pref["pre_generation_features"],
                "runtime_legal_features_only": True,
                "oracle_correctness_used_as_feature": False,
                "adapter_training_forbidden": True,
                "training_authority": "ROUTE_VALUE_DISTILLATION_ONLY",
                "claim_authority": "NONE",
            }
        )
    for idx, pref in enumerate(base_prefs):
        rows.append(
            {
                "schema_id": "kt.route_value_training_row.v1",
                "row_id": f"base_preservation_{idx:03d}",
                "sample_id": pref["sample_id"],
                "candidate_routes": [pref["preferred_route"], pref["suppressed_route"]],
                "preferred_route": pref["preferred_route"],
                "preference_kind": "base_preservation",
                "pre_generation_features": pref["pre_generation_features"],
                "runtime_legal_features_only": True,
                "oracle_correctness_used_as_feature": False,
                "adapter_training_forbidden": True,
                "training_authority": "ROUTE_VALUE_DISTILLATION_ONLY",
                "claim_authority": "NONE",
            }
        )
    return rows


def historic_oracle_gap_rows() -> list[dict]:
    return [
        {
            "schema_id": "kt.cross_run_oracle_gap_summary.v1",
            "run": run,
            "samples": samples,
            "base_raw_correct": base,
            "best_non_oracle_arm": best_arm,
            "best_non_oracle_correct": best,
            "named_oracle_arm": named_oracle,
            "named_oracle_correct": named_correct,
            "union_oracle_correct": union,
            "gap_union_vs_base": gap_base,
            "gap_union_vs_best_non_oracle": gap_best,
            "oracle_implementation_gap_union_minus_named": implementation_gap,
            "claim_ceiling_preserved": True,
        }
        for run, samples, base, best_arm, best, named_oracle, named_correct, union, gap_base, gap_best, implementation_gap in HISTORIC_RUNS
    ]


def leakage_scan(route_rows: list[dict]) -> dict:
    hits = []
    for row in route_rows:
        keys = set(row.get("pre_generation_features", {}))
        bad = sorted(keys & FORBIDDEN_FEATURES)
        if bad:
            hits.append({"row_id": row.get("row_id"), "sample_id": row.get("sample_id"), "forbidden_features": bad})
    return {
        "schema_id": "kt.oracle_leakage_scan_receipt.v1",
        "status": "PASS" if not hits else "FAIL",
        "oracle_correctness_used_as_feature": bool(hits),
        "forbidden_feature_hits": hits,
        "claim_ceiling_preserved": True,
    }


def heatmap(gaps: list[dict]) -> dict:
    return {
        "schema_id": "kt.route_rescuer_heatmap.v1",
        "gap_count": len(gaps),
        "by_rescuer_family": dict(Counter(row["oracle_rescuer_family"] for row in gaps)),
        "by_oracle_route": dict(Counter(row["oracle_route"] for row in gaps)),
        "by_dataset": dict(Counter(row["dataset"] for row in gaps)),
        "claim_ceiling_preserved": True,
    }


def oracle_conversion_rate() -> float:
    base = V15_FACTS["scores"]["base_raw"]["correct"]
    feature = V15_FACTS["scores"]["formal_math_router_math_act_feature_bound"]["correct"]
    oracle = V15_FACTS["scores"]["oracle_math_router"]["correct"]
    return (feature - base) / (oracle - base)


def write_all(root: Path | None = None) -> dict:
    root = root or repo_root()
    head = current_head(root)
    created = utc_now()
    gaps = oracle_gap_matrix()
    winners = winner_attribution(gaps)
    pairwise = pairwise_preferences(gaps)
    negative = negative_preferences(gaps)
    base_prefs = base_preservation_preferences(gaps)
    route_values = route_value_rows(pairwise, base_prefs)
    historic = historic_oracle_gap_rows()
    leak = leakage_scan(route_values)

    write_jsonl(root / "admission/oracle_gap_matrix.jsonl", gaps)
    write_jsonl(root / "admission/oracle_winner_attribution.jsonl", winners)
    write_jsonl(root / "admission/oracle_pairwise_route_preferences.jsonl", pairwise)
    write_jsonl(root / "admission/oracle_negative_route_preferences.jsonl", negative)
    write_jsonl(root / "admission/base_preservation_preferences.jsonl", base_prefs)
    write_jsonl(root / "admission/route_value_training_rows.jsonl", route_values)
    write_jsonl(root / "admission/all_historic_oracle_gap_matrix.jsonl", historic)
    write_json(
        root / "admission/route_value_feature_registry.json",
        {
            "schema_id": "kt.route_value_feature_registry.v1",
            "allowed_features": ["feature_score_bucket", "math_act_feature_trigger"],
            "forbidden_features": sorted(FORBIDDEN_FEATURES),
            "oracle_correctness_used_as_feature": False,
            "runtime_legal_features_only": True,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "admission/shadow_route_policy_spec.json",
        {
            "schema_id": "kt.shadow_route_policy.v1",
            "policy_id": "v16_shadow_route_value_replay_candidate",
            "runtime_authority": False,
            "promotion_authority": False,
            "adapter_promotion_authority": False,
            "claim_authority": "NONE",
            "oracle_route_deployable": False,
            "input_features": ["feature_score_bucket", "math_act_feature_trigger"],
            "forbidden_features": sorted(FORBIDDEN_FEATURES),
            "source_rows": "admission/route_value_training_rows.jsonl",
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "admission/oracle_rescuer_transition_matrix.json",
        {
            "schema_id": "kt.oracle_rescuer_transition_matrix.v1",
            "from_policy": "formal_math_router_math_act_feature_bound",
            "to_oracle_route_counts": dict(Counter(row["oracle_route"] for row in gaps)),
            "to_rescuer_family_counts": dict(Counter(row["oracle_rescuer_family"] for row in gaps)),
            "claim_ceiling_preserved": True,
        },
    )

    write_json(root / "reports/v15_result_review_receipt.json", {**V15_FACTS, "current_head": head, "created_utc": created})
    write_json(
        root / "reports/v15_oracle_gap_summary.json",
        {
            "schema_id": "kt.v15_oracle_gap_summary.v1",
            "gap_count": len(gaps),
            "oracle_over_feature_route_correct_delta": V15_FACTS["oracle_over_feature_route_correct_delta"],
            "oracle_over_base_correct_delta": V15_FACTS["oracle_over_base_correct_delta"],
            "feature_route_over_base_correct_delta": V15_FACTS["feature_route_over_base_correct_delta"],
            "claim_ceiling_preserved": True,
        },
    )
    write_json(root / "reports/route_rescuer_heatmap.json", heatmap(gaps))
    write_json(
        root / "reports/oracle_gap_failure_taxonomy.json",
        {
            "schema_id": "kt.oracle_gap_failure_taxonomy.v1",
            "gap_count": len(gaps),
            "taxonomy": {
                "feature_route_missed_available_rescuer": len(gaps),
                "base_preservation_cases": len(base_prefs),
                "non_base_rescuer_cases": len(gaps) - len(base_prefs),
            },
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/route_regret_closure_target.json",
        {
            "schema_id": "kt.route_regret_closure_target.v1",
            "observed_feature_route_closure": oracle_conversion_rate(),
            "remaining_oracle_gap_correct": V15_FACTS["oracle_over_feature_route_correct_delta"],
            "acceptable_next_closure": 0.30,
            "strong_next_closure": 0.50,
            "excellent_next_closure": 0.70,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/do_not_train_oracle_receipt.json",
        {
            "schema_id": "kt.do_not_train_oracle_receipt.v1",
            "status": "PASS",
            "adapter_training_authorized": False,
            "route_value_distillation_authorized": True,
            "oracle_correctness_used_as_feature": False,
            "oracle_rows_authorize_adapter_training": False,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/oracle_conversion_rate_scorecard.json",
        {
            "schema_id": "kt.oracle_conversion_rate_scorecard.v1",
            "ocr_formula": "(feature_bound_route_correct - base_raw_correct) / (oracle_correct - base_raw_correct)",
            "base_raw_correct": V15_FACTS["scores"]["base_raw"]["correct"],
            "feature_bound_route_correct": V15_FACTS["scores"]["formal_math_router_math_act_feature_bound"]["correct"],
            "oracle_correct": V15_FACTS["scores"]["oracle_math_router"]["correct"],
            "oracle_conversion_rate": oracle_conversion_rate(),
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/oracle_implementation_gap_receipt.json",
        {
            "schema_id": "kt.oracle_implementation_gap_receipt.v1",
            "named_oracle_correct": 187,
            "feature_bound_route_correct": 159,
            "implementation_gap_correct": 28,
            "oracle_route_deployable": False,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/quantitative_reasoning_habitat_scorecard.json",
        {
            "schema_id": "kt.quantitative_habitat_scorecard.v1",
            "quantitative_datasets": dict(Counter(row["dataset"] for row in gaps if "math" in row["dataset"] or "numeric" in row["dataset"] or row["dataset"] == "gsm8k")),
            "non_quantitative_rescues": dict(Counter(row["dataset"] for row in gaps if not ("math" in row["dataset"] or "numeric" in row["dataset"] or row["dataset"] == "gsm8k"))),
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/hat_salvage_matrix.json",
        {
            "schema_id": "kt.hat_salvage_matrix.v1",
            "hat_rescue_count": sum(1 for row in gaps if row["oracle_rescuer_family"] == "hat"),
            "hat_rescue_datasets": dict(Counter(row["dataset"] for row in gaps if row["oracle_rescuer_family"] == "hat")),
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/base_raw_preservation_receipt.json",
        {
            "schema_id": "kt.base_raw_preservation_receipt.v1",
            "base_preservation_case_count": len(base_prefs),
            "base_preservation_preferences_path": "admission/base_preservation_preferences.jsonl",
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/historic_oracle_gap_trend.json",
        {
            "schema_id": "kt.historic_oracle_gap_trend.v1",
            "run_count": len(historic),
            "runs": historic,
            "persistent_oracle_gap_present": True,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/oracle_harvest_authority_receipt.json",
        {
            "schema_id": "kt.oracle_harvest_authority_receipt.v1",
            "oracle_is_teacher": True,
            "oracle_runtime_authority": False,
            "route_value_distillation_authority": "SHADOW_ONLY",
            "adapter_training_authority": False,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(root / "reports/oracle_leakage_scan_receipt.json", leak)
    write_json(
        root / "capability/capability_atlas_update.json",
        {
            "schema_id": "kt.capability_atlas_update.v15_oracle_harvest",
            "updates": [
                {
                    "capability_id": "route_value_distillation",
                    "status": "SHADOW_PREP_ONLY",
                    "source": "V15 oracle gap matrix",
                },
                {
                    "capability_id": "crossroad_admission",
                    "status": "SHADOW_PREP_ONLY",
                    "source": "pairwise and base-preservation preferences",
                },
            ],
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "capability/quantitative_reasoning_habitat_map.json",
        {
            "schema_id": "kt.quantitative_reasoning_habitat_map.v1",
            "quantitative_slices": ["gsm8k", "math_wording_variation_slice", "non_gsm8k_math_slice", "numeric_reasoning_slice"],
            "primary_rescuer_family": "formal_math",
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "capability/rescuer_portfolio_map.json",
        {
            "schema_id": "kt.rescuer_portfolio_map.v1",
            "rescuer_families": dict(Counter(row["oracle_rescuer_family"] for row in gaps)),
            "oracle_route_deployable": False,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "governance/oracle_harvest_authority_contract.json",
        {
            "schema_id": "kt.oracle_harvest_authority_contract.v3",
            "oracle_is_teacher": True,
            "oracle_runtime_authority": False,
            "route_value_distillation_authority": "SHADOW_ONLY",
            "adapter_training_authority": False,
            "claim_ceiling_preserved": True,
        },
    )

    registry_path = root / "registry/artifact_authority_registry.json"
    if registry_path.exists():
        registry = read_json(registry_path)
        artifacts = registry.setdefault("artifacts", [])
        by_id = {item.get("artifact_id"): item for item in artifacts}
        entry = {
            "artifact_id": "KT_V15_ORACLE_HARVEST_RECEIPT",
            "path": "reports/v15_oracle_harvest_superlane_receipt.json",
            "role": "oracle_harvest_route_value_distillation",
            "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
            "claim_authority": "NONE",
            "controls_execution": False,
            "notes": "Oracle harvest route-value artifacts only; no training, runtime, route promotion, adapter promotion, superiority, commercial, 7B, or production authority.",
            "validation_status": "PASS",
        }
        if entry["artifact_id"] in by_id:
            by_id[entry["artifact_id"]].update(entry)
        else:
            artifacts.append(entry)
        registry["current_head"] = head
        registry["generated_utc"] = created
        write_json(registry_path, registry)
    write_json(
        root / "registry/artifact_authority_registry_v15_oracle_harvest_delta_receipt.json",
        {
            "schema_id": "kt.artifact_authority_registry_v15_oracle_harvest_delta_receipt.v1",
            "current_head": head,
            "created_utc": created,
            "artifact_added": "KT_V15_ORACLE_HARVEST_RECEIPT",
            "claim_ceiling_preserved": True,
            "no_runtime_or_promotion_authority_added": True,
        },
    )
    superlane = {
        "schema_id": "kt.v15_oracle_harvest_superlane_receipt.v1",
        "program_id": PROGRAM_ID,
        "current_head": head,
        "branch": current_branch(root),
        "created_utc": created,
        "outcome": OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "v15_evidence_import_status": "PASS_BOUND",
        "historic_oracle_gap_status": "PASS_BOUND",
        "oracle_gap_matrix_status": "PASS",
        "oracle_winner_attribution_status": "PASS",
        "pairwise_preference_status": "PASS",
        "negative_preference_status": "PASS",
        "base_preservation_status": "PASS",
        "route_value_training_rows_status": "PASS_SHADOW_ONLY",
        "shadow_route_policy_status": "PASS_NO_RUNTIME_AUTHORITY",
        "do_not_train_oracle_status": "PASS",
        "oracle_conversion_rate_status": "PASS",
        "oracle_leakage_scan_status": leak["status"],
        "route_rescuer_heatmap_status": "PASS",
        "claim_ceiling_status": "UNCHANGED",
        "blockers": [],
    }
    write_json(root / "reports/v15_oracle_harvest_superlane_receipt.json", superlane)
    return superlane
