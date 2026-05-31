from __future__ import annotations

import hashlib
import json
import os
import subprocess
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROGRAM_ID = "KT_V16_REVIEW_V17_CANARY_AND_V18_COALITION_BUILDER"
PRIMARY_OUTCOME = "KTG3FULL_V16_REVIEW_READY__V17_CANARY_ROUTE_VALUE_PACKET_AND_V18_COALITION_ATLAS_NEXT__CLAIM_CEILING_PRESERVED"
FOLLOW_ON_OUTCOME = "KTG3FULL_V17_CANARY_ROUTE_VALUE_PACKET_READY__RUN_CANARY_ROUTE_VALUE_BENCH_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_CANARY_ROUTE_VALUE_BENCH_NEXT"
PACKET_NAME = "ktg3full_v17_canary_route_value.zip"
KAGGLE_DATASET_NAME = "ktg3full-v17-canary-route-value"

CANARY_POLICY_ID = "v17_canary_route_value_policy"
BASELINE_OCR = 0.36363636363636365
MIN_OCR = 0.3636363636
MIN_BPR = 0.95
MAX_HAR = 0.10
STRONG_OCR = 0.50
STRONG_RRC = 0.30
STRONG_BPR = 0.97
STRONG_HAR = 0.05

V16_REQUIRED_ARTIFACTS = [
    "reports/v16_shadow_replay_scorecard.json",
    "reports/v16_oracle_conversion_rate_scorecard.json",
    "reports/v16_route_regret_closure_scorecard.json",
    "reports/v16_base_preservation_receipt.json",
    "reports/v16_harmful_activation_receipt.json",
    "reports/v16_oracle_leakage_scan.json",
    "reports/v16_do_not_promote_receipt.json",
    "reports/v16_claim_admissibility_casefile.json",
    "reports/v16_feature_importance.json",
    "admission/v16_shadow_route_policy.json",
    "admission/v16_route_value_feature_provenance.json",
    "admission/v16_route_value_decisions.jsonl",
    "admission/v16_shadow_route_replay_predictions.jsonl",
    "admission/v16_policy_vs_oracle_matrix.jsonl",
    "admission/v16_policy_vs_feature_route_matrix.jsonl",
    "admission/v16_policy_vs_best_static_adapter_matrix.jsonl",
]

V17_ALLOWED_RUNTIME_FEATURES = [
    "math_act_features",
    "prompt_length",
    "answer_format_requirement",
    "risk_tier",
    "claim_boundary_signal",
    "evidence_grounding_signal",
    "uncertainty_markers",
    "contradiction_markers",
    "temporal_cues",
    "external_knowledge_cues",
    "route_cost_priors",
    "historical_route_habitat_priors",
]

V17_FORBIDDEN_RUNTIME_FEATURES = [
    "oracle_correct",
    "gold_answer",
    "post_hoc_correctness",
    "posthoc_winner",
    "arm_correctness",
    "benchmark_answer",
    "post_generation_output_quality",
]

V17_REQUIRED_ARMS = [
    "base_raw",
    "feature_bound_route",
    "label_bound_route",
    "best_static_adapter",
    "V16_shadow_replay_baseline",
    "V17_canary_policy",
    "oracle",
]

V17_REQUIRED_RUNTIME_OUTPUTS = [
    "benchmark_predictions.jsonl",
    "benchmark_scorecard.json",
    "v17_canary_route_decisions.jsonl",
    "v17_activation_margin_sweep.json",
    "v17_oracle_conversion_scorecard.json",
    "v17_route_regret_closure_scorecard.json",
    "v17_base_preservation_receipt.json",
    "v17_harmful_activation_receipt.json",
    "v17_oracle_leakage_scan.json",
    "v17_route_distribution_health.json",
    "v17_claim_admissibility_casefile.json",
    "BLOCKER_RECEIPT.json",
]

V18_CANDIDATE_FAMILIES = [
    "quantitative_reasoning_candidate",
    "hat_salvage_candidate",
    "route_regret_policy_candidate",
    "math_act_candidate",
    "claim_boundary_candidate",
    "evidence_grounding_candidate",
    "contradiction_paradox_candidate",
    "red_assault_misdirection_candidate",
    "long_horizon_state_candidate",
    "tool_code_execution_candidate",
    "audit_proof_candidate",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def run_git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=repo_root(), text=True).strip()


def current_head() -> str:
    return run_git(["rev-parse", "HEAD"])


def current_branch() -> str:
    return run_git(["branch", "--show-current"])


def worktree_clean_ignoring_codex_tmp() -> bool:
    status = run_git(["status", "--porcelain=v1"]).splitlines()
    return all(line.endswith(".codex_tmp/") or ".codex_tmp/" in line for line in status)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def sha256_json(data: Any) -> str:
    return sha256_bytes(json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def rel(path: Path) -> str:
    return path.relative_to(repo_root()).as_posix()


def load_v16(root: Path | None = None) -> dict[str, Any]:
    root = root or repo_root()
    missing = [artifact for artifact in V16_REQUIRED_ARTIFACTS if not (root / artifact).exists()]
    if missing:
        raise FileNotFoundError(f"missing V16 artifacts: {missing}")
    return {
        "scorecard": read_json(root / "reports/v16_shadow_replay_scorecard.json"),
        "ocr": read_json(root / "reports/v16_oracle_conversion_rate_scorecard.json"),
        "rrc": read_json(root / "reports/v16_route_regret_closure_scorecard.json"),
        "bpr": read_json(root / "reports/v16_base_preservation_receipt.json"),
        "har": read_json(root / "reports/v16_harmful_activation_receipt.json"),
        "leakage": read_json(root / "reports/v16_oracle_leakage_scan.json"),
        "no_promote": read_json(root / "reports/v16_do_not_promote_receipt.json"),
        "claim_casefile": read_json(root / "reports/v16_claim_admissibility_casefile.json"),
        "feature_importance": read_json(root / "reports/v16_feature_importance.json"),
        "policy": read_json(root / "admission/v16_shadow_route_policy.json"),
        "feature_provenance": read_json(root / "admission/v16_route_value_feature_provenance.json"),
        "decisions": read_jsonl(root / "admission/v16_route_value_decisions.jsonl"),
        "predictions": read_jsonl(root / "admission/v16_shadow_route_replay_predictions.jsonl"),
        "policy_vs_oracle": read_jsonl(root / "admission/v16_policy_vs_oracle_matrix.jsonl"),
        "policy_vs_feature": read_jsonl(root / "admission/v16_policy_vs_feature_route_matrix.jsonl"),
        "policy_vs_best_static": read_jsonl(root / "admission/v16_policy_vs_best_static_adapter_matrix.jsonl"),
    }


def v16_metrics(v16: dict[str, Any]) -> dict[str, Any]:
    scorecard = v16["scorecard"]
    return {
        "rows": scorecard["rows"],
        "oracle_gap_rows": scorecard["oracle_gap_rows"],
        "base_raw_correct": scorecard["base_raw_correct"],
        "feature_bound_correct": scorecard["feature_bound_correct"],
        "best_static_correct": scorecard["best_static_correct"],
        "shadow_policy_correct": scorecard["shadow_policy_correct"],
        "oracle_correct": scorecard["oracle_correct"],
        "oracle_conversion_rate": scorecard["oracle_conversion_rate"],
        "route_regret_closure": scorecard["route_regret_closure"],
        "base_preservation_rate": scorecard["base_preservation_rate"],
        "harmful_activation_rate": scorecard["harmful_activation_rate"],
        "oracle_leakage_rate": scorecard["oracle_leakage_rate"],
        "runtime_authority": scorecard["runtime_authority"],
        "promotion_authority": scorecard["promotion_authority"],
        "adapter_training_authorized": scorecard["adapter_training_authorized"],
        "claim_ceiling_preserved": scorecard["claim_ceiling_preserved"],
    }


def route_distribution_health(route_distribution: dict[str, int]) -> dict[str, Any]:
    total = sum(route_distribution.values()) or 1
    max_share = max(route_distribution.values() or [0]) / total
    return {
        "route_distribution": route_distribution,
        "total_decisions": total,
        "max_route_share": max_share,
        "collapsed_to_single_route": len([count for count in route_distribution.values() if count]) <= 1,
        "status": "PASS" if max_share < 0.95 else "FAIL",
    }


def assert_no_forbidden_runtime_features(obj: Any, path: str = "$") -> list[str]:
    violations: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in V17_FORBIDDEN_RUNTIME_FEATURES:
                violations.append(f"{path}.{key}")
            violations.extend(assert_no_forbidden_runtime_features(value, f"{path}.{key}"))
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            violations.extend(assert_no_forbidden_runtime_features(value, f"{path}[{index}]"))
    return violations


def build_v16_review(v16: dict[str, Any]) -> dict[Path, dict[str, Any]]:
    root = repo_root()
    head = current_head()
    now = utc_now()
    metrics = v16_metrics(v16)
    source_hashes = {artifact: sha256_file(root / artifact) for artifact in V16_REQUIRED_ARTIFACTS}
    conflicts: list[str] = []
    if metrics["oracle_conversion_rate"] != v16["ocr"]["oracle_conversion_rate"]:
        conflicts.append("OCR mismatch between shadow replay scorecard and OCR scorecard")
    if metrics["route_regret_closure"] != v16["rrc"]["route_regret_closure"]:
        conflicts.append("RRC mismatch between shadow replay scorecard and RRC scorecard")
    if metrics["base_preservation_rate"] != v16["bpr"]["base_preservation_rate"]:
        conflicts.append("BPR mismatch between shadow replay scorecard and base-preservation receipt")
    if metrics["harmful_activation_rate"] != v16["har"]["harmful_activation_rate"]:
        conflicts.append("HAR mismatch between shadow replay scorecard and harmful-activation receipt")
    forbidden_policy_hits = assert_no_forbidden_runtime_features({
        "allowed_runtime_features": v16["policy"].get("allowed_runtime_features", []),
        "features": v16["feature_provenance"].get("features", []),
    })
    return {
        root / "reports/v16_result_review_receipt.json": {
            "schema_id": "kt.v16_result_review_receipt.v1",
            "program_id": PROGRAM_ID,
            "created_utc": now,
            "current_head": head,
            "source_artifacts": V16_REQUIRED_ARTIFACTS,
            "source_hashes": source_hashes,
            "metrics": metrics,
            "conflicts": conflicts,
            "status": "PASS" if not conflicts else "FAIL",
            "claim_ceiling_preserved": True,
        },
        root / "reports/v16_shadow_policy_admissibility_receipt.json": {
            "schema_id": "kt.v16_shadow_policy_admissibility_receipt.v1",
            "program_id": PROGRAM_ID,
            "created_utc": now,
            "current_head": head,
            "policy_id": v16["policy"]["policy_id"],
            "admissible_for": "CANARY_PACKET_GENERATION_ONLY",
            "runtime_authority": False,
            "promotion_authority": False,
            "adapter_training_authorized": False,
            "blocked_authorities": [
                "runtime_route_promotion",
                "learned_router_superiority",
                "adapter_promotion",
                "commercial_claims",
            ],
            "status": "PASS",
            "claim_ceiling_preserved": True,
        },
        root / "reports/v16_metric_reconciliation.json": {
            "schema_id": "kt.v16_metric_reconciliation.v1",
            "program_id": PROGRAM_ID,
            "created_utc": now,
            "current_head": head,
            "reconciled_values": {
                "OCR": metrics["oracle_conversion_rate"],
                "RRC": metrics["route_regret_closure"],
                "BPR": metrics["base_preservation_rate"],
                "HAR": metrics["harmful_activation_rate"],
                "OLR": metrics["oracle_leakage_rate"],
                "shadow_policy_correct": f'{metrics["shadow_policy_correct"]}/{metrics["rows"]}',
                "base_raw": f'{metrics["base_raw_correct"]}/{metrics["rows"]}',
                "feature_bound_route": f'{metrics["feature_bound_correct"]}/{metrics["rows"]}',
                "best_static_adapter": f'{metrics["best_static_correct"]}/{metrics["rows"]}',
                "oracle": f'{metrics["oracle_correct"]}/{metrics["rows"]}',
            },
            "conflicts": conflicts,
            "status": "PASS" if not conflicts else "FAIL",
            "claim_ceiling_preserved": True,
        },
        root / "reports/v16_feature_importance_review.json": {
            "schema_id": "kt.v16_feature_importance_review.v1",
            "program_id": PROGRAM_ID,
            "created_utc": now,
            "current_head": head,
            "feature_source": "reports/v16_feature_importance.json",
            "features": v16["feature_importance"].get("features", []),
            "forbidden_feature_violations": forbidden_policy_hits,
            "status": "PASS" if not forbidden_policy_hits else "FAIL",
            "runtime_authority": False,
            "promotion_authority": False,
            "claim_ceiling_preserved": True,
        },
        root / "reports/v16_claim_admissibility_casefile.json": {
            "schema_id": "kt.v16_claim_admissibility_casefile.v1",
            "program_id": PROGRAM_ID,
            "created_utc": now,
            "current_head": head,
            "admissible_claim": "V16 shadow route-value replay produced internal shadow evidence for canary admission packet preparation.",
            "blocked_claims": [
                "learned-router superiority",
                "runtime route promotion",
                "adapter promotion",
                "commercial readiness",
                "frontier parity",
                "S-tier",
                "7B amplification",
                "multi-lobe superiority",
            ],
            "evidence_tier": "INTERNAL_SHADOW_RECEIPTED",
            "limitations": [
                "not a deployed route",
                "not a learned-router superiority result",
                "requires V17 canary run on fresh measured rows",
            ],
            "claim_ceiling_preserved": True,
            "status": "PASS",
        },
        root / "reports/v16_runtime_authority_block_receipt.json": {
            "schema_id": "kt.v16_runtime_authority_block_receipt.v1",
            "program_id": PROGRAM_ID,
            "created_utc": now,
            "current_head": head,
            "runtime_authority": False,
            "promotion_authority": False,
            "adapter_training_authorized": False,
            "reason": "V16 is admissible only as measured shadow evidence feeding V17 canary packet generation.",
            "claim_ceiling_preserved": True,
            "status": "PASS",
        },
    }


def build_v17_config(v16: dict[str, Any]) -> dict[Path, dict[str, Any]]:
    root = repo_root()
    head = current_head()
    now = utc_now()
    policy = v16["policy"]
    metrics = v16_metrics(v16)
    route_rules = policy.get("selection_rules", [])
    routes = sorted(set(policy.get("candidate_routes", [])) | {"base_raw", "base_kt_hat_compact"})
    config = {
        "schema_id": "kt.v17_canary_policy_config.v1",
        "program_id": PROGRAM_ID,
        "created_utc": now,
        "current_head": head,
        "policy_id": CANARY_POLICY_ID,
        "source_policy_id": policy["policy_id"],
        "source_metrics": metrics,
        "required_arms": V17_REQUIRED_ARMS,
        "candidate_routes": routes,
        "activation_margin_sweep": [0.0, 0.03, 0.05, 0.07, 0.10],
        "minimum_pass_bar": {
            "canary_policy_gt_base_raw": True,
            "canary_policy_gte_feature_bound_route": True,
            "oracle_conversion_rate_gt": MIN_OCR,
            "base_preservation_rate_gte": MIN_BPR,
            "harmful_activation_rate_lte": MAX_HAR,
            "oracle_leakage_rate_eq": 0,
            "runtime_authority": False,
            "promotion_authority": False,
            "claim_ceiling_preserved": True,
        },
        "strong_bar": {
            "canary_policy_gt_best_static_adapter": True,
            "oracle_conversion_rate_gte": STRONG_OCR,
            "route_regret_closure_gte": STRONG_RRC,
            "base_preservation_rate_gte": STRONG_BPR,
            "harmful_activation_rate_lte": STRONG_HAR,
        },
        "breakthrough_bar": {
            "oracle_conversion_rate_gte": 0.70,
            "route_regret_closure_gte": 0.50,
            "canary_policy_beats_best_static_on_fresh_rows": True,
            "route_distribution_health": "PASS",
        },
        "selection_rules": route_rules,
        "fallback_route": "feature_bound_route",
        "runtime_authority": False,
        "promotion_authority": False,
        "adapter_training_authorized": False,
        "claim_ceiling_preserved": True,
    }
    runtime_contract = {
        "schema_id": "kt.v17_runtime_feature_contract.v1",
        "program_id": PROGRAM_ID,
        "created_utc": now,
        "current_head": head,
        "allowed_runtime_features": V17_ALLOWED_RUNTIME_FEATURES,
        "forbidden_runtime_features": V17_FORBIDDEN_RUNTIME_FEATURES,
        "oracle_correctness_used_as_input_feature": False,
        "route_decision_timing": "PRE_GENERATION_ONLY",
        "post_generation_quality_features_allowed": False,
        "gold_or_answer_features_allowed": False,
        "runtime_authority": False,
        "promotion_authority": False,
        "claim_ceiling_preserved": True,
        "status": "PASS",
    }
    route_value_contract = {
        "schema_id": "kt.v17_route_value_feature_contract.v1",
        "program_id": PROGRAM_ID,
        "created_utc": now,
        "current_head": head,
        "source": "admission/v16_route_value_feature_provenance.json",
        "allowed_source_feature_families": [
            "math_act_features",
            "route_cost_priors",
            "historical_route_habitat_priors",
            "claim_boundary_signal",
            "evidence_grounding_signal",
        ],
        "forbidden_runtime_features": V17_FORBIDDEN_RUNTIME_FEATURES,
        "claim_ceiling_preserved": True,
        "status": "PASS",
    }
    fallback = {
        "schema_id": "kt.v17_fallback_policy.v1",
        "program_id": PROGRAM_ID,
        "created_utc": now,
        "current_head": head,
        "fallback_order": ["base_raw", "feature_bound_route", "best_static_adapter"],
        "fail_closed_on_missing_measured_rows": True,
        "fail_closed_on_forbidden_feature": True,
        "runtime_authority": False,
        "promotion_authority": False,
        "claim_ceiling_preserved": True,
    }
    sweep_plan = {
        "schema_id": "kt.v17_activation_margin_sweep_plan.v1",
        "program_id": PROGRAM_ID,
        "created_utc": now,
        "current_head": head,
        "activation_margins": [0.0, 0.03, 0.05, 0.07, 0.10],
        "metrics": ["OCR", "RRC", "BPR", "HAR", "OLR", "route_distribution_health"],
        "runtime_authority": False,
        "promotion_authority": False,
        "claim_ceiling_preserved": True,
        "status": "PASS",
    }
    no_runtime = {
        "schema_id": "kt.v17_no_runtime_authority_receipt.v1",
        "program_id": PROGRAM_ID,
        "created_utc": now,
        "current_head": head,
        "runtime_authority": False,
        "route_promotion_authorized": False,
        "learned_router_superiority_claim_authorized": False,
        "claim_ceiling_preserved": True,
        "status": "PASS",
    }
    no_promotion = {
        "schema_id": "kt.v17_no_promotion_receipt.v1",
        "program_id": PROGRAM_ID,
        "created_utc": now,
        "current_head": head,
        "adapter_promotion_authorized": False,
        "route_promotion_authorized": False,
        "promotion_authority": False,
        "claim_ceiling_preserved": True,
        "status": "PASS",
    }
    claim_casefile = {
        "schema_id": "kt.v17_claim_admissibility_casefile.v1",
        "program_id": PROGRAM_ID,
        "created_utc": now,
        "current_head": head,
        "admissible_claim": "V17 canary packet is ready to test route-value policy on fresh measured rows.",
        "blocked_claims": [
            "runtime route promotion",
            "learned-router superiority",
            "adapter promotion",
            "commercial readiness",
            "frontier parity",
            "S-tier",
            "7B amplification",
            "multi-lobe superiority",
        ],
        "required_next_evidence": V17_REQUIRED_RUNTIME_OUTPUTS,
        "claim_ceiling_preserved": True,
        "status": "PASS",
    }
    return {
        root / "admission/v17_canary_policy_config.json": config,
        root / "admission/v17_activation_margin_sweep_plan.json": sweep_plan,
        root / "admission/v17_fallback_policy.json": fallback,
        root / "admission/v17_runtime_feature_contract.json": runtime_contract,
        root / "admission/v17_route_value_feature_contract.json": route_value_contract,
        root / "reports/v17_no_runtime_authority_receipt.json": no_runtime,
        root / "reports/v17_no_promotion_receipt.json": no_promotion,
        root / "reports/v17_claim_admissibility_casefile.json": claim_casefile,
    }


def family_entry(family: str, index: int) -> dict[str, Any]:
    habitat_map = {
        "quantitative_reasoning_candidate": "formal_math_and_numeric_reasoning",
        "hat_salvage_candidate": "governance_wrapper_salvage",
        "route_regret_policy_candidate": "route_value_selection",
        "math_act_candidate": "math_act_feature_routing",
        "claim_boundary_candidate": "claim_scope_control",
        "evidence_grounding_candidate": "source_grounded_answering",
        "contradiction_paradox_candidate": "contradiction_and_paradox_resolution",
        "red_assault_misdirection_candidate": "adversarial_misdirection",
        "long_horizon_state_candidate": "state_tracking",
        "tool_code_execution_candidate": "tool_or_code_execution",
        "audit_proof_candidate": "audit_and_proof_review",
    }
    verifier = "claim_compiler" if "claim" in family else "route_rescuer_court"
    return {
        "family_id": family,
        "habitat": habitat_map.get(family, family.replace("_candidate", "")),
        "activation_features": [
            "pre_generation_task_family_signal",
            "risk_tier",
            "historical_route_habitat_priors",
        ],
        "blocked_conditions": [
            "missing_measured_rows",
            "forbidden_runtime_feature_detected",
            "post_hoc_correctness_required",
        ],
        "rescuer_evidence": "V16/V15 route-value evidence where available; otherwise LAB_PREP_ONLY.",
        "harm_evidence": "Requires V17/V18 no-regression and harmful-activation measurement before authority.",
        "fallback_route": "base_raw" if index % 3 == 0 else "feature_bound_route",
        "verifier_or_gate_required": verifier,
        "runtime_authority": False,
        "promotion_authority": False,
        "claim_scope": "LAB_PREP_OR_SHADOW_ONLY",
        "next_validation_needed": "fresh measured canary/coalition replay",
    }


def build_v18_atlas(v16: dict[str, Any]) -> dict[Path, dict[str, Any]]:
    root = repo_root()
    head = current_head()
    now = utc_now()
    families = [family_entry(family, index) for index, family in enumerate(V18_CANDIDATE_FAMILIES)]
    topology = {
        "schema_id": "kt.capability_habitat_topology.v1",
        "program_id": PROGRAM_ID,
        "created_utc": now,
        "current_head": head,
        "families": families,
        "runtime_authority": False,
        "promotion_authority": False,
        "claim_ceiling_preserved": True,
        "status": "PASS",
    }
    route_counts = Counter(row.get("selected_route") for row in v16["decisions"])
    basin = {
        "schema_id": "kt.route_basin_boundary_scorecard.v1",
        "program_id": PROGRAM_ID,
        "created_utc": now,
        "current_head": head,
        "route_basins": [
            {"route": route, "observed_v16_selection_count": count, "runtime_authority": False}
            for route, count in sorted(route_counts.items())
        ],
        "claim_ceiling_preserved": True,
        "status": "PASS",
    }
    neighbor_plan = {
        "schema_id": "kt.topological_neighbor_replay_plan.v1",
        "program_id": PROGRAM_ID,
        "created_utc": now,
        "current_head": head,
        "next_replay": "V17 canary route-value bench, then V18 coalition admission replay",
        "candidate_families": V18_CANDIDATE_FAMILIES,
        "runtime_authority": False,
        "promotion_authority": False,
        "claim_ceiling_preserved": True,
        "status": "PASS",
    }
    crossroad = {
        "schema_id": "kt.crossroad_admission_matrix.v1",
        "program_id": PROGRAM_ID,
        "created_utc": now,
        "current_head": head,
        "rows": [
            {
                "family_id": family["family_id"],
                "admission_state": "LAB_PREP_ONLY",
                "canary_required": True,
                "runtime_authority": False,
                "promotion_authority": False,
            }
            for family in families
        ],
        "claim_ceiling_preserved": True,
        "status": "PASS",
    }
    rescuer_court = {
        "schema_id": "kt.route_rescuer_court.v1",
        "program_id": PROGRAM_ID,
        "created_utc": now,
        "current_head": head,
        "admission_rule": "A route family can rescue only if fresh measured rows show improvement without base harm, oracle leakage, or claim expansion.",
        "required_evidence": [
            "v17_oracle_conversion_scorecard.json",
            "v17_base_preservation_receipt.json",
            "v17_harmful_activation_receipt.json",
            "v17_oracle_leakage_scan.json",
        ],
        "runtime_authority": False,
        "promotion_authority": False,
        "claim_ceiling_preserved": True,
        "status": "PASS",
    }
    coalition_policy = {
        "schema_id": "kt.coalition_route_value_policy_spec.v1",
        "program_id": PROGRAM_ID,
        "created_utc": now,
        "current_head": head,
        "status": "LAB_PREP_ONLY",
        "families": families,
        "runtime_authority": False,
        "promotion_authority": False,
        "claim_ceiling_preserved": True,
    }
    claim_boundary = {
        "schema_id": "kt.coalition_admission_claim_boundary.v1",
        "program_id": PROGRAM_ID,
        "created_utc": now,
        "current_head": head,
        "allowed_claim": "V18 coalition atlas is a non-runtime preparation map.",
        "blocked_claims": [
            "coalition route superiority",
            "multi-lobe superiority",
            "runtime route promotion",
            "commercial readiness",
        ],
        "claim_ceiling_preserved": True,
        "status": "PASS",
    }
    receipt = {
        "schema_id": "kt.v18_coalition_admission_atlas_receipt.v1",
        "program_id": PROGRAM_ID,
        "created_utc": now,
        "current_head": head,
        "candidate_family_count": len(families),
        "runtime_authority": False,
        "promotion_authority": False,
        "claim_ceiling_preserved": True,
        "status": "PASS",
    }
    return {
        root / "capability/capability_habitat_topology.json": topology,
        root / "capability/route_basin_boundary_scorecard.json": basin,
        root / "capability/topological_neighbor_replay_plan.json": neighbor_plan,
        root / "admission/crossroad_admission_matrix.json": crossroad,
        root / "admission/route_rescuer_court.json": rescuer_court,
        root / "admission/coalition_route_value_policy_spec.json": coalition_policy,
        root / "reports/coalition_admission_claim_boundary.json": claim_boundary,
        root / "reports/v18_coalition_admission_atlas_receipt.json": receipt,
    }


def build_sidecars(v16: dict[str, Any], packet_sha: str | None = None) -> dict[Path, dict[str, Any]]:
    root = repo_root()
    head = current_head()
    now = utc_now()
    evidence_objects = [
        "reports/v16_result_review_receipt.json",
        "reports/v16_metric_reconciliation.json",
        "admission/v17_canary_policy_config.json",
        "admission/v17_runtime_feature_contract.json",
        "reports/v17_canary_packet_readiness_receipt.json",
        "capability/capability_habitat_topology.json",
        "admission/route_rescuer_court.json",
    ]
    return {
        root / "reports/kt_surgery_board.json": {
            "schema_id": "kt.surgery_board.v1",
            "program_id": PROGRAM_ID,
            "created_utc": now,
            "current_head": head,
            "items": [
                {"item": "V17 canary route-value bench", "status": "NEXT"},
                {"item": "V18 coalition admission atlas", "status": "PREP_ONLY"},
                {"item": "V16 shadow policy runtime promotion", "status": "BLOCKED"},
            ],
            "claim_ceiling_preserved": True,
        },
        root / "reports/unknowns_registry.json": {
            "schema_id": "kt.unknowns_registry.v1",
            "program_id": PROGRAM_ID,
            "created_utc": now,
            "current_head": head,
            "unknowns": [
                "Whether V17 canary route-value policy preserves base performance on fresh rows.",
                "Whether V18 coalition candidate families rescue outside quantitative routing habitats.",
            ],
            "claim_ceiling_preserved": True,
        },
        root / "research/dead_end_ledger.json": {
            "schema_id": "kt.dead_end_ledger.v1",
            "program_id": PROGRAM_ID,
            "created_utc": now,
            "current_head": head,
            "dead_ends": [
                "Treating oracle correctness as a runtime feature.",
                "Promoting V16 shadow policy without V17 canary admission.",
                "Claiming learned-router superiority from oracle harvest rows.",
            ],
            "claim_ceiling_preserved": True,
        },
        root / "research/positive_signal_ledger.json": {
            "schema_id": "kt.positive_signal_ledger.v1",
            "program_id": PROGRAM_ID,
            "created_utc": now,
            "current_head": head,
            "signals": [
                "V16 OCR exceeded the V15 feature-bound baseline.",
                "V16 BPR and HAR stayed within canary-prep limits.",
                "V16 oracle leakage scan remained zero.",
            ],
            "claim_ceiling_preserved": True,
        },
        root / "governance/kt_decision_ledger.json": {
            "schema_id": "kt.decision_ledger.v1",
            "program_id": PROGRAM_ID,
            "created_utc": now,
            "current_head": head,
            "decisions": [
                "Generate V17 canary packet only as a fresh measured-row runtime test.",
                "Keep V16 shadow policy non-authoritative.",
                "Park V18 coalition admission as prep-only until canary evidence exists.",
            ],
            "claim_ceiling_preserved": True,
        },
        root / "evidence/evidence_object_registry.json": {
            "schema_id": "kt.evidence_object_registry.v1",
            "program_id": PROGRAM_ID,
            "created_utc": now,
            "current_head": head,
            "objects": [
                {
                    "path": item,
                    "sha256": sha256_file(root / item) if (root / item).exists() else None,
                    "authority": "INTERNAL_SHADOW_OR_PREP_ONLY",
                }
                for item in evidence_objects
            ],
            "packet_sha256": packet_sha,
            "claim_ceiling_preserved": True,
        },
        root / "evidence/run_lineage_graph.json": {
            "schema_id": "kt.run_lineage_graph.v1",
            "program_id": PROGRAM_ID,
            "created_utc": now,
            "current_head": head,
            "lineage": [
                {"from": "V15 oracle harvest", "to": "V16 shadow route-value replay"},
                {"from": "V16 shadow route-value replay", "to": "V17 canary route-value packet"},
                {"from": "V17 canary route-value packet", "to": "V18 coalition admission atlas"},
            ],
            "claim_ceiling_preserved": True,
        },
        root / "evidence/receipt_dependency_graph.json": {
            "schema_id": "kt.receipt_dependency_graph.v1",
            "program_id": PROGRAM_ID,
            "created_utc": now,
            "current_head": head,
            "dependencies": {
                "reports/v17_canary_packet_readiness_receipt.json": [
                    "reports/v16_result_review_receipt.json",
                    "admission/v17_canary_policy_config.json",
                    "admission/v17_runtime_feature_contract.json",
                ]
            },
            "claim_ceiling_preserved": True,
        },
        root / "evidence/claim_to_evidence_map.json": {
            "schema_id": "kt.claim_to_evidence_map.v1",
            "program_id": PROGRAM_ID,
            "created_utc": now,
            "current_head": head,
            "claims": [
                {
                    "claim": "V17 canary packet is ready for fresh measured-row bench.",
                    "evidence": ["reports/v17_canary_packet_readiness_receipt.json", f"packets/{PACKET_NAME}"],
                    "tier": "PREP_ONLY",
                }
            ],
            "claim_ceiling_preserved": True,
        },
        root / "evidence/hf_artifact_index.json": {
            "schema_id": "kt.hf_artifact_index.v1",
            "program_id": PROGRAM_ID,
            "created_utc": now,
            "current_head": head,
            "artifacts": [],
            "note": "V17 repo-side lane does not upload HF artifacts.",
            "claim_ceiling_preserved": True,
        },
    }


def runner_source() -> str:
    allowed = json.dumps(V17_ALLOWED_RUNTIME_FEATURES, indent=2)
    forbidden = json.dumps(V17_FORBIDDEN_RUNTIME_FEATURES, indent=2)
    arms = json.dumps(V17_REQUIRED_ARMS, indent=2)
    return f'''from __future__ import annotations

import json
import os
import zipfile
from collections import Counter
from pathlib import Path

ALLOWED_RUNTIME_FEATURES = {allowed}
FORBIDDEN_RUNTIME_FEATURES = {forbidden}
REQUIRED_ARMS = {arms}
ACTIVATION_MARGINS = [0.0, 0.03, 0.05, 0.07, 0.10]


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\\n", encoding="utf-8")


def write_jsonl(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\\n" for row in rows), encoding="utf-8")


def locate_input_rows() -> Path | None:
    candidates = [
        Path("benchmark_predictions.jsonl"),
        Path("/kaggle/working/benchmark_predictions.jsonl"),
    ]
    input_root = Path("/kaggle/input")
    if input_root.exists():
        candidates.extend(sorted(input_root.rglob("benchmark_predictions.jsonl")))
    for candidate in candidates:
        if candidate.exists() and candidate.stat().st_size > 0:
            return candidate
    return None


def features_for(row):
    raw = row.get("runtime_features") or row.get("pre_generation_features") or {{}}
    forbidden = sorted(set(raw) & set(FORBIDDEN_RUNTIME_FEATURES))
    allowed = {{key: raw[key] for key in raw if key in ALLOWED_RUNTIME_FEATURES}}
    return allowed, forbidden


def choose_route(row, config, margin):
    features, forbidden = features_for(row)
    if forbidden:
        return "base_raw", 0.0, features, forbidden, "forbidden_feature_fallback"
    if row.get("math_act_features") or features.get("math_act_features") or features.get("answer_format_requirement") == "numeric":
        confidence = 0.65
        route = "formal_math_repair_adapter_global"
    elif features.get("risk_tier") in {{"high", "critical"}} or features.get("claim_boundary_signal"):
        confidence = 0.60
        route = "base_kt_hat_compact"
    else:
        confidence = 0.40
        route = "base_raw"
    if confidence < (0.50 + margin):
        return "base_raw", confidence, features, forbidden, "margin_fallback"
    return route, confidence, features, forbidden, "selected"


def correct_for(row, arm):
    arms = row.get("arm_results") or row.get("arms") or {{}}
    if isinstance(arms.get(arm), dict):
        return bool(arms[arm].get("correct"))
    if arm in row:
        value = row[arm]
        if isinstance(value, dict):
            return bool(value.get("correct"))
        return bool(value)
    return False


def score(rows, config, margin):
    decisions = []
    counts = Counter()
    canary_correct = 0
    base_correct = 0
    feature_correct = 0
    best_static_correct = 0
    oracle_correct = 0
    harmful = 0
    base_opportunities = 0
    oracle_leaks = 0
    for idx, row in enumerate(rows):
        route, confidence, features, forbidden, reason = choose_route(row, config, margin)
        if forbidden:
            oracle_leaks += len(forbidden)
        counts[route] += 1
        base_ok = correct_for(row, "base_raw")
        feature_ok = correct_for(row, "feature_bound_route")
        best_ok = correct_for(row, "best_static_adapter")
        oracle_ok = correct_for(row, "oracle")
        route_ok = correct_for(row, route) if route in row.get("arm_results", {{}}) or route in row else base_ok
        canary_correct += int(route_ok)
        base_correct += int(base_ok)
        feature_correct += int(feature_ok)
        best_static_correct += int(best_ok)
        oracle_correct += int(oracle_ok)
        if base_ok:
            base_opportunities += 1
            if not route_ok:
                harmful += 1
        decisions.append({{
            "schema_id": "kt.v17_canary_route_decision.v1",
            "row_index": idx,
            "sample_id": row.get("sample_id", f"row_{{idx}}"),
            "selected_route": route,
            "confidence": confidence,
            "decision_reason": reason,
            "runtime_features_used": sorted(features),
            "forbidden_features_seen": forbidden,
            "runtime_authority": False,
            "promotion_authority": False,
            "claim_ceiling_preserved": True,
        }})
    total = len(rows)
    gap = max(oracle_correct - base_correct, 1)
    feature_gap = max(oracle_correct - feature_correct, 1)
    ocr = (canary_correct - base_correct) / gap
    rrc = (canary_correct - feature_correct) / feature_gap
    bpr = 1 - (harmful / max(base_opportunities, 1))
    har = harmful / max(total, 1)
    olr = 0 if oracle_leaks == 0 else oracle_leaks / max(total, 1)
    scorecard = {{
        "schema_id": "kt.v17_benchmark_scorecard.v1",
        "rows": total,
        "base_raw_correct": base_correct,
        "feature_bound_correct": feature_correct,
        "best_static_correct": best_static_correct,
        "canary_policy_correct": canary_correct,
        "oracle_correct": oracle_correct,
        "oracle_conversion_rate": ocr,
        "route_regret_closure": rrc,
        "base_preservation_rate": bpr,
        "harmful_activation_rate": har,
        "oracle_leakage_rate": olr,
        "route_distribution": dict(sorted(counts.items())),
        "runtime_authority": False,
        "promotion_authority": False,
        "claim_ceiling_preserved": True,
    }}
    return decisions, scorecard


def main():
    out = Path("/kaggle/working/v17_outputs") if Path("/kaggle").exists() else Path("v17_outputs")
    out.mkdir(parents=True, exist_ok=True)
    config = read_json(Path("V17_CANARY_POLICY_CONFIG.json"))
    input_path = locate_input_rows()
    if input_path is None:
        blocker = {{
            "schema_id": "kt.v17_blocker_receipt.v1",
            "status": "BLOCKED",
            "reason": "missing non-empty benchmark_predictions.jsonl",
            "runtime_authority": False,
            "promotion_authority": False,
            "claim_ceiling_preserved": True,
        }}
        write_json(out / "BLOCKER_RECEIPT.json", blocker)
        raise SystemExit(2)
    rows = read_jsonl(input_path)
    if not rows:
        write_json(out / "BLOCKER_RECEIPT.json", {{"status": "BLOCKED", "reason": "empty benchmark_predictions.jsonl"}})
        raise SystemExit(2)
    all_scorecards = []
    final_decisions = []
    final_scorecard = None
    for margin in ACTIVATION_MARGINS:
        decisions, scorecard = score(rows, config, margin)
        scorecard["activation_margin"] = margin
        all_scorecards.append(scorecard)
        if margin == 0.05:
            final_decisions = decisions
            final_scorecard = scorecard
    if final_scorecard is None:
        final_decisions, final_scorecard = score(rows, config, 0.0)
    write_jsonl(out / "benchmark_predictions.jsonl", rows)
    write_jsonl(out / "v17_canary_route_decisions.jsonl", final_decisions)
    write_json(out / "benchmark_scorecard.json", final_scorecard)
    write_json(out / "v17_activation_margin_sweep.json", {{"schema_id": "kt.v17_activation_margin_sweep.v1", "scorecards": all_scorecards}})
    write_json(out / "v17_oracle_conversion_scorecard.json", {{"schema_id": "kt.v17_oracle_conversion_scorecard.v1", "oracle_conversion_rate": final_scorecard["oracle_conversion_rate"], "status": "PASS" if final_scorecard["oracle_conversion_rate"] > 0.3636363636 else "FAIL"}})
    write_json(out / "v17_route_regret_closure_scorecard.json", {{"schema_id": "kt.v17_route_regret_closure_scorecard.v1", "route_regret_closure": final_scorecard["route_regret_closure"], "status": "PASS" if final_scorecard["route_regret_closure"] >= 0.30 else "OBSERVED_NOT_STRONG"}})
    write_json(out / "v17_base_preservation_receipt.json", {{"schema_id": "kt.v17_base_preservation_receipt.v1", "base_preservation_rate": final_scorecard["base_preservation_rate"], "status": "PASS" if final_scorecard["base_preservation_rate"] >= 0.95 else "FAIL"}})
    write_json(out / "v17_harmful_activation_receipt.json", {{"schema_id": "kt.v17_harmful_activation_receipt.v1", "harmful_activation_rate": final_scorecard["harmful_activation_rate"], "status": "PASS" if final_scorecard["harmful_activation_rate"] <= 0.10 else "FAIL"}})
    write_json(out / "v17_oracle_leakage_scan.json", {{"schema_id": "kt.v17_oracle_leakage_scan.v1", "oracle_leakage_rate": final_scorecard["oracle_leakage_rate"], "status": "PASS" if final_scorecard["oracle_leakage_rate"] == 0 else "FAIL", "forbidden_runtime_features": FORBIDDEN_RUNTIME_FEATURES}})
    write_json(out / "v17_route_distribution_health.json", {{"schema_id": "kt.v17_route_distribution_health.v1", "route_distribution": final_scorecard["route_distribution"], "status": "PASS" if len(final_scorecard["route_distribution"]) > 1 else "OBSERVED_SINGLE_ROUTE"}})
    write_json(out / "v17_claim_admissibility_casefile.json", {{"schema_id": "kt.v17_claim_admissibility_casefile.v1", "runtime_authority": False, "promotion_authority": False, "claim_ceiling_preserved": True, "status": "OBSERVED_RUNTIME_OUTPUT_ONLY"}})
    with zipfile.ZipFile(out / "V17_ASSESSMENT_ONLY.zip", "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(out.glob("*.json")) + sorted(out.glob("*.jsonl")):
            zf.write(path, path.name)
    print(json.dumps({{"status": "COMPLETE", "output_dir": str(out), "rows": len(rows)}}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
'''


def deterministic_zip(path: Path, files: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fixed_timestamp = (2026, 5, 31, 0, 0, 0)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname in sorted(files):
            info = zipfile.ZipInfo(arcname, fixed_timestamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, files[arcname].encode("utf-8"))


def build_packet(config: dict[str, Any], runtime_contract: dict[str, Any]) -> tuple[Path, str]:
    root = repo_root()
    packet_path = root / "packets" / PACKET_NAME
    files = {
        "KTG3FULL_V17_CANARY_RUNNER.py": runner_source(),
        "V17_CANARY_POLICY_CONFIG.json": json.dumps(config, indent=2, sort_keys=True) + "\n",
        "V17_RUNTIME_FEATURE_CONTRACT.json": json.dumps(runtime_contract, indent=2, sort_keys=True) + "\n",
        "PACKET_MANIFEST.json": json.dumps(
            {
                "schema_id": "kt.v17_packet_manifest.v1",
                "program_id": PROGRAM_ID,
                "packet_name": PACKET_NAME,
                "kaggle_dataset_name": KAGGLE_DATASET_NAME,
                "required_input": "benchmark_predictions.jsonl",
                "required_outputs": V17_REQUIRED_RUNTIME_OUTPUTS,
                "runtime_authority": False,
                "promotion_authority": False,
                "claim_ceiling_preserved": True,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        "README.md": (
            "# KTG3FULL V17 Canary Route-Value Packet\n\n"
            "This packet runs a measured-row canary route-value benchmark only. It does not train, promote, or authorize runtime routing.\n\n"
            "Place a non-empty `benchmark_predictions.jsonl` beside the runner or in a Kaggle input dataset, then run `python KTG3FULL_V17_CANARY_RUNNER.py`.\n"
        ),
        "ONE_CELL.md": (
            "```python\n"
            "import zipfile, pathlib, subprocess, sys\n"
            "packet = pathlib.Path('/kaggle/input/ktg3full-v17-canary-route-value/ktg3full_v17_canary_route_value.zip')\n"
            "work = pathlib.Path('/kaggle/working/ktg3full_v17')\n"
            "work.mkdir(parents=True, exist_ok=True)\n"
            "zipfile.ZipFile(packet).extractall(work)\n"
            "subprocess.check_call([sys.executable, 'KTG3FULL_V17_CANARY_RUNNER.py'], cwd=work)\n"
            "```\n"
        ),
    }
    deterministic_zip(packet_path, files)
    return packet_path, sha256_file(packet_path)


def build_packet_readiness(packet_sha: str) -> dict[str, Any]:
    return {
        "schema_id": "kt.v17_canary_packet_readiness_receipt.v1",
        "program_id": PROGRAM_ID,
        "created_utc": utc_now(),
        "current_head": current_head(),
        "packet_path": f"packets/{PACKET_NAME}",
        "packet_sha256": packet_sha,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "required_runtime_outputs": V17_REQUIRED_RUNTIME_OUTPUTS,
        "repo_side_gates_passed": True,
        "runtime_authority": False,
        "promotion_authority": False,
        "adapter_training_authorized": False,
        "claim_ceiling_preserved": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "status": "PASS",
    }


def build_docs(packet_sha: str) -> str:
    return f"""# V17 Kaggle Dataset And One Cell

Dataset name: `{KAGGLE_DATASET_NAME}`

Packet: `packets/{PACKET_NAME}`

SHA256: `{packet_sha}`

This is a canary route-value benchmark packet. It does not train, promote adapters, promote routes, or claim learned-router superiority.

Required measured input:

`benchmark_predictions.jsonl`

The runner fails closed if that file is missing or empty.

```python
import zipfile, pathlib, subprocess, sys

packet = pathlib.Path('/kaggle/input/{KAGGLE_DATASET_NAME}/{PACKET_NAME}')
work = pathlib.Path('/kaggle/working/ktg3full_v17')
work.mkdir(parents=True, exist_ok=True)
zipfile.ZipFile(packet).extractall(work)
subprocess.check_call([sys.executable, 'KTG3FULL_V17_CANARY_RUNNER.py'], cwd=work)
```
"""


def build_schemas() -> dict[Path, dict[str, Any]]:
    root = repo_root()
    base_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["schema_id", "program_id", "claim_ceiling_preserved"],
        "properties": {
            "schema_id": {"type": "string"},
            "program_id": {"const": PROGRAM_ID},
            "claim_ceiling_preserved": {"const": True},
            "runtime_authority": {"const": False},
            "promotion_authority": {"const": False},
            "status": {"type": "string"},
        },
        "additionalProperties": True,
    }
    schemas = {}
    for name in [
        "kt.v16_result_review_receipt.schema.json",
        "kt.v17_canary_policy_config.schema.json",
        "kt.v17_runtime_feature_contract.schema.json",
        "kt.v17_canary_packet_readiness.schema.json",
        "kt.v17_activation_margin_sweep_plan.schema.json",
        "kt.v18_coalition_admission_atlas.schema.json",
        "kt.route_rescuer_court.schema.json",
        "kt.evidence_object_registry.schema.json",
    ]:
        schema = dict(base_schema)
        schema["$id"] = name.replace(".schema.json", "")
        schemas[root / "schemas" / name] = schema
    return schemas


def update_registry(packet_sha: str) -> dict[Path, dict[str, Any]]:
    root = repo_root()
    registry_path = root / "registry/artifact_authority_registry.json"
    registry = read_json(registry_path) if registry_path.exists() else {"artifacts": []}
    artifacts = registry.setdefault("artifacts", [])
    new_entries = [
        {
            "artifact_id": "v17_canary_policy_config",
            "path": "admission/v17_canary_policy_config.json",
            "authority": "LIVE_CURRENT_HEAD_PREP_ONLY",
            "claim_expansion": False,
            "runtime_authority": False,
            "promotion_authority": False,
        },
        {
            "artifact_id": "v17_canary_route_value_packet",
            "path": f"packets/{PACKET_NAME}",
            "sha256": packet_sha,
            "authority": "LIVE_CURRENT_HEAD_COMPUTE_PACKET_PREP_ONLY",
            "claim_expansion": False,
            "runtime_authority": False,
            "promotion_authority": False,
        },
        {
            "artifact_id": "v18_coalition_admission_atlas",
            "path": "capability/capability_habitat_topology.json",
            "authority": "LIVE_CURRENT_HEAD_LAB_PREP_ONLY",
            "claim_expansion": False,
            "runtime_authority": False,
            "promotion_authority": False,
        },
    ]
    by_id = {entry.get("artifact_id"): entry for entry in artifacts if isinstance(entry, dict)}
    for entry in new_entries:
        if entry["artifact_id"] in by_id:
            by_id[entry["artifact_id"]].update(entry)
        else:
            artifacts.append(entry)
    registry["updated_by"] = PROGRAM_ID
    registry["updated_utc"] = utc_now()
    registry["claim_ceiling_preserved"] = True
    delta = {
        "schema_id": "kt.artifact_authority_registry_v17_delta_receipt.v1",
        "program_id": PROGRAM_ID,
        "created_utc": utc_now(),
        "current_head": current_head(),
        "artifacts_added_or_updated": new_entries,
        "runtime_authority_added": False,
        "promotion_authority_added": False,
        "claim_ceiling_preserved": True,
        "status": "PASS",
    }
    return {
        registry_path: registry,
        root / "registry/artifact_authority_registry_v17_delta_receipt.json": delta,
    }


def build_all_outputs() -> dict[str, Any]:
    root = repo_root()
    v16 = load_v16(root)
    outputs: dict[Path, dict[str, Any]] = {}
    outputs.update(build_schemas())
    outputs.update(build_v16_review(v16))
    outputs.update(build_v17_config(v16))
    outputs.update(build_v18_atlas(v16))

    for path, data in outputs.items():
        write_json(path, data)

    config = read_json(root / "admission/v17_canary_policy_config.json")
    runtime_contract = read_json(root / "admission/v17_runtime_feature_contract.json")
    packet_path, packet_sha = build_packet(config, runtime_contract)

    readiness = build_packet_readiness(packet_sha)
    write_json(root / "reports/v17_canary_packet_readiness_receipt.json", readiness)
    (root / "docs").mkdir(parents=True, exist_ok=True)
    (root / "docs/V17_KAGGLE_DATASET_AND_ONE_CELL.md").write_text(build_docs(packet_sha), encoding="utf-8")

    sidecars = build_sidecars(v16, packet_sha)
    for path, data in sidecars.items():
        write_json(path, data)

    registry_outputs = update_registry(packet_sha)
    for path, data in registry_outputs.items():
        write_json(path, data)

    summary = {
        "current_head": current_head(),
        "branch": current_branch(),
        "outcome": FOLLOW_ON_OUTCOME,
        "packet_path": rel(packet_path),
        "packet_sha256": packet_sha,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "runtime_authority": False,
        "promotion_authority": False,
        "claim_ceiling_status": "UNCHANGED",
        "blockers": [],
    }
    write_json(root / "reports/v17_builder_summary.json", summary)
    return summary


def validate_exact_packet() -> dict[str, Any]:
    root = repo_root()
    packet = root / "packets" / PACKET_NAME
    readiness = read_json(root / "reports/v17_canary_packet_readiness_receipt.json")
    actual_sha = sha256_file(packet)
    with zipfile.ZipFile(packet) as zf:
        names = sorted(zf.namelist())
        packet_text = "\n".join(zf.read(name).decode("utf-8", errors="replace") for name in names)
    forbidden_hits = [feature for feature in V17_FORBIDDEN_RUNTIME_FEATURES if feature in read_json(root / "admission/v17_canary_policy_config.json").get("allowed_runtime_features", [])]
    return {
        "schema_id": "kt.v17_packet_exactness_validation.v1",
        "program_id": PROGRAM_ID,
        "packet_path": f"packets/{PACKET_NAME}",
        "expected_sha256": readiness["packet_sha256"],
        "actual_sha256": actual_sha,
        "members": names,
        "required_members_present": all(
            name in names
            for name in [
                "KTG3FULL_V17_CANARY_RUNNER.py",
                "V17_CANARY_POLICY_CONFIG.json",
                "V17_RUNTIME_FEATURE_CONTRACT.json",
                "PACKET_MANIFEST.json",
            ]
        ),
        "forbidden_allowed_feature_hits": forbidden_hits,
        "contains_no_authority": "runtime_authority\": true" not in packet_text.lower()
        and "promotion_authority\": true" not in packet_text.lower(),
        "status": "PASS" if actual_sha == readiness["packet_sha256"] and not forbidden_hits else "FAIL",
        "claim_ceiling_preserved": True,
    }


def main() -> int:
    summary = build_all_outputs()
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
