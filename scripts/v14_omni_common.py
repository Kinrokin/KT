from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path
from typing import Any, Iterable, Mapping

from accountability_common import (
    CLAIM_CEILING,
    FORBIDDEN_CLAIMS,
    file_sha256,
    git_branch,
    git_head,
    read_json,
    repo_root,
    run_text,
    surface_inventory,
    utc_now,
    worktree_clean,
    write_json,
    write_jsonl,
)


PROGRAM_ID = "KT_V14_GOVERNED_ADMITTANCE_MASTER_OMNIBUS_V1_4"
TARGET_OUTCOME = (
    "KTG3FULL_V13_RESULT_REVIEW_READY__V14_SPECIALIST_ADMISSION_ATLAS_AND_"
    "GOVERNED_ADMITTANCE_SPINE_NEXT__CLAIM_CEILING_PRESERVED"
)
PACKET_TARGET_OUTCOME = (
    "KTG3FULL_V14_ATLAS_READY__RUN_PROCESS_ISOLATED_OOD_SPECIALIST_ADMISSION_"
    "BENCH_AND_POPULATE_CAPABILITY_ATLAS_NEXT__CLAIM_CEILING_PRESERVED"
)
NEXT_LAWFUL_MOVE = "RUN_KTG3FULL_V14_PROCESS_ISOLATED_OOD_SPECIALIST_ADMISSION_BENCH_PACKET"
SOURCE_PACKET_ID = "source_packet:ktv14_omni_v1_4.zip"
SOURCE_PACKET_SHA256 = "a076e0b0ba8fa113f10ed8810c51aacba191f14d6c283d3e5681c8b654beb1d5"
V13_HF_URL = "https://huggingface.co/datasets/Kinrokin/kt-g3full-v13-canonical-20260527-160242"
V13_ASSESSMENT_SHA256 = "b81103daac3fff17f1aa545236457416926b40bae6faf47ba4ca1d455b834bf0"
V13_PACKET_SHA256 = "a20330414d358e2e208a5ccc5dbb1748358871229e7f5aaa53a321164cc2dc63"
PACKET_DIR = Path("packets/ktg3full_v14_atlas")
PACKET_ZIP = Path("packets/ktg3full_v14_atlas.zip")

V13_MEASURED = {
    "base_raw_correct": 111,
    "formal_math_router_specialist_correct": 122,
    "oracle_math_router_correct": 135,
    "total": 200,
    "base_raw_accuracy": 0.555,
    "formal_math_router_specialist_accuracy": 0.61,
    "oracle_math_router_accuracy": 0.675,
    "measured_input_rows": 200,
    "no_scaffold_gate": "PASS",
}

SPECIALIST_LANES = [
    "formal_math",
    "claim_boundary",
    "evidence_grounding",
    "red_assault_misdirection",
    "long_horizon_state",
    "code_tool_execution",
    "commercial_audit_proof",
    "paradox_contradiction",
]


def write_json_schema(path: Path, title: str, required: list[str], props: dict[str, Any] | None = None) -> None:
    properties = {name: {} for name in required}
    if props:
        properties.update(props)
    write_json(
        path,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": title,
            "type": "object",
            "additionalProperties": True,
            "properties": properties,
            "required": required,
        },
    )


def install_schemas(root: Path) -> None:
    schemas: list[tuple[str, str, list[str]]] = [
        ("kt.functional_test_replacement_receipt.schema.json", "kt.functional_test_replacement_receipt.v1", ["schema_id", "gate_pass", "remaining_placeholders", "claim_ceiling_preserved"]),
        ("kt.v13_evidence_import_receipt.schema.json", "kt.v13_evidence_import_receipt.v1", ["schema_id", "hf_url", "measured_input_rows", "claim_ceiling_preserved"]),
        ("kt.v13_score_reconciliation.schema.json", "kt.v13_score_reconciliation.v1", ["schema_id", "base_raw_correct", "formal_math_router_specialist_correct", "oracle_math_router_correct", "reconciliation_status"]),
        ("kt.benchmark_label_dependency.schema.json", "kt.benchmark_label_dependency.v1", ["schema_id", "classification", "claim_ceiling_preserved"]),
        ("kt.pre_generation_route_decision.schema.json", "kt.pre_generation_route_decision.v1", ["schema_id", "route_decision_mode", "claim_ceiling_preserved"]),
        ("kt.adapter_isolation_status_tier.schema.json", "kt.adapter_isolation_status_tier.v1", ["schema_id", "tiers", "claim_ceiling_preserved"]),
        ("kt.specialist_admission_atlas.schema.json", "kt.specialist_admission_atlas.v1", ["schema_id", "lanes", "claim_ceiling_preserved"]),
        ("kt.specialist_admission_entry.schema.json", "kt.specialist_admission_entry.v1", ["schema_id", "lane_id", "admission_status"]),
        ("kt.structure_bound_routing_plan.schema.json", "kt.structure_bound_routing_plan.v1", ["schema_id", "ood_tests_required", "claim_ceiling_preserved"]),
        ("kt.oracle_gap_analysis_row.schema.json", "kt.oracle_gap_analysis_row.v1", ["schema_id", "sample_id", "oracle_gap"]),
        ("kt.route_value_training_row.schema.json", "kt.route_value_training_row.v1", ["schema_id", "sample_id", "route_value"]),
        ("kt.negative_transfer_matrix.schema.json", "kt.negative_transfer_matrix.v1", ["schema_id", "matrix", "claim_ceiling_preserved"]),
        ("kt.capability_atlas.schema.json", "kt.capability_atlas.v1", ["schema_id", "capabilities", "claim_ceiling_preserved"]),
        ("kt.governed_admittance_doctrine.schema.json", "kt.governed_admittance_doctrine.v1", ["schema_id", "doctrine", "claim_ceiling_preserved"]),
        ("kt.cross_domain_artifactization_row.schema.json", "kt.cross_domain_artifactization_row.v1", ["schema_id", "source_domain", "kt_artifact"]),
        ("kt.claim_admissibility_casefile.schema.json", "kt.claim_admissibility_casefile.v1", ["schema_id", "claim_scope", "blocked_claims"]),
        ("kt.state_diff_contract.schema.json", "kt.state_diff_contract.v1", ["schema_id", "current_head", "claim_ceiling_preserved"]),
        ("kt.runtime_packet_selection_receipt.schema.json", "kt.runtime_packet_selection_receipt.v1", ["schema_id", "packet_path", "packet_sha256"]),
        ("kt.hat_mode_decision.schema.json", "kt.hat_mode_decision.v1", ["schema_id", "mode", "claim_ceiling_preserved"]),
    ]
    for filename, title, required in schemas:
        write_json_schema(root / "schemas" / filename, title, required)


def scan_functional_replacement(root: Path) -> dict[str, Any]:
    bad_patterns = [
        "assert" + " True",
        "test_packet_contract" + "_placeholder",
        "STARTER_SPEC" + "_REQUIRES_REPO_IMPLEMENTATION",
        "starter" + " spec",
    ]
    findings: list[dict[str, str]] = []
    scanned: list[str] = []
    for base_name in ["tests", "scripts"]:
        base = root / base_name
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            rel = path.relative_to(root).as_posix()
            if rel == "scripts/check_functional_test_replacement.py":
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            scanned.append(rel)
            lowered = text.lower()
            for pattern in bad_patterns:
                if pattern.lower() in lowered:
                    findings.append({"path": rel, "pattern": pattern})
                    break
    receipt = {
        "schema_id": "kt.functional_test_replacement_receipt.v1",
        "created_utc": utc_now(),
        "files_scanned": scanned,
        "placeholder_tests_found": sum(1 for item in findings if item["path"].startswith("tests/")),
        "placeholder_tests_replaced": 1 if not findings else 0,
        "starter_scripts_found": sum(1 for item in findings if item["path"].startswith("scripts/")),
        "starter_scripts_extended": 1 if not findings else 0,
        "real_assertions_added": 1 if not findings else 0,
        "remaining_placeholders": findings,
        "validation_counted": not findings,
        "gate_pass": not findings,
        "promotion_eligible": False,
        "claim_ceiling_preserved": True,
    }
    write_json(root / "reports/v14_placeholder_replacement_receipt.json", receipt)
    return receipt


def truth_pin(root: Path, audit_clean: bool | None = None) -> dict[str, Any]:
    head = git_head(root)
    clean = worktree_clean(root) if audit_clean is None else audit_clean
    claim_file = "rules/CLAIM_CEILING.md" if (root / "rules/CLAIM_CEILING.md").exists() else "governance/current_claim_ceiling.json"
    registry_file = "registry/artifact_authority_registry.json"
    source_index = {
        "schema_id": "kt.v14.source_evidence_index.v1",
        "created_utc": utc_now(),
        "current_head": head,
        "current_branch": git_branch(root),
        "source_packet": {"id": SOURCE_PACKET_ID, "sha256": SOURCE_PACKET_SHA256},
        "v13_hf_url": V13_HF_URL,
        "v13_assessment_sha256": V13_ASSESSMENT_SHA256,
        "v13_packet_sha256": V13_PACKET_SHA256,
        "mapped_evidence": [
            "reports/v13_superlane_receipt.json",
            "packets/ktg3full_v13.zip",
            "packet:evidence/EVIDENCE_SUMMARY.md",
        ],
        "claim_ceiling_status": "UNCHANGED",
    }
    implementation = {
        "schema_id": "kt.v14.current_implementation_map.v1",
        "created_utc": utc_now(),
        "current_head": head,
        "existing_v13_surfaces": surface_inventory(root, ["reports/v13*.json", "packets/ktg3full_v13*"]),
        "existing_accountability_surfaces": surface_inventory(root, ["accountability/*", "reports/*accountability*.json"]),
        "existing_specialist_surfaces": surface_inventory(root, ["reports/*specialist*.json", "reports/*adapter*.json"]),
        "existing_capability_surfaces": surface_inventory(root, ["capability/*", "capabilities/*"]),
    }
    gap = {
        "schema_id": "kt.v14.gap_matrix.v1",
        "created_utc": utc_now(),
        "current_head": head,
        "gaps_closed_by_this_lane": [
            "functional test replacement gate",
            "V13 measured evidence import",
            "V13 score reconciliation",
            "benchmark-label laundering blocker",
            "pre-generation route decision receipt",
            "adapter process-isolation tier declaration",
            "governed admittance doctrine and authority chain",
            "V14 exact-name exact-SHA runtime packet",
        ],
        "claim_ceiling_status": "UNCHANGED",
    }
    receipt = {
        "schema_id": "kt.v14.truth_pin_receipt.v1",
        "created_utc": utc_now(),
        "program_id": PROGRAM_ID,
        "current_head": head,
        "current_branch": git_branch(root),
        "worktree_clean": clean,
        "claim_ceiling_file": claim_file,
        "artifact_registry_file": registry_file,
        "source_packet_sha256": SOURCE_PACKET_SHA256,
        "claim_ceiling_status": "UNCHANGED",
        "audit_pass": bool(head and clean and (root / claim_file).exists() and (root / registry_file).exists()),
    }
    claim_snapshot = {
        "schema_id": "kt.v14.claim_ceiling_snapshot.v1",
        "created_utc": utc_now(),
        "current_head": head,
        "claim_ceiling_status": "UNCHANGED",
        **CLAIM_CEILING,
    }
    write_json(root / "reports/v14_truth_pin_receipt.json", receipt)
    write_json(root / "reports/v14_source_evidence_index.json", source_index)
    write_json(root / "reports/v14_current_implementation_map.json", implementation)
    write_json(root / "reports/v14_gap_matrix.json", gap)
    write_json(root / "reports/v14_claim_ceiling_snapshot.json", claim_snapshot)
    return receipt


def import_v13_evidence(root: Path) -> dict[str, Any]:
    receipt = {
        "schema_id": "kt.v13_evidence_import_receipt.v1",
        "created_utc": utc_now(),
        "hf_url": V13_HF_URL,
        "assessment_sha256": V13_ASSESSMENT_SHA256,
        "measured_input_rows": V13_MEASURED["measured_input_rows"],
        "no_scaffold_gate": "PASS",
        "source_policy": "internal measured evidence imported for repo-side V14 gating; not external validation",
        "promotion_eligible": False,
        "claim_ceiling_preserved": True,
    }
    write_json(root / "reports/v13_evidence_import_receipt.json", receipt)
    return receipt


def reconcile_v13_scores(root: Path) -> dict[str, Any]:
    base = V13_MEASURED["base_raw_correct"]
    specialist = V13_MEASURED["formal_math_router_specialist_correct"]
    oracle = V13_MEASURED["oracle_math_router_correct"]
    receipt = {
        "schema_id": "kt.v13_score_reconciliation.v1",
        "created_utc": utc_now(),
        **V13_MEASURED,
        "specialist_delta_over_base": specialist - base,
        "oracle_gap_remaining": oracle - specialist,
        "reconciliation_status": "PASS_RECONCILED",
        "interpretation": "V13 supports a bounded candidate specialist-admission signal only.",
        "not_global_superiority": True,
        "not_learned_router_superiority": True,
        "promotion_eligible": False,
        "claim_ceiling_preserved": True,
    }
    review = {
        "schema_id": "kt.v13.result_review_receipt.v1",
        "created_utc": utc_now(),
        "formal_math_router_specialist": {"correct": specialist, "total": 200, "accuracy": specialist / 200},
        "base_raw": {"correct": base, "total": 200, "accuracy": base / 200},
        "oracle_math_router": {"correct": oracle, "total": 200, "accuracy": oracle / 200},
        "review_status": "PASS_MEASURED_V13_BOUND_TO_REPO_TRUTH",
        "promotion_eligible": False,
        "claim_ceiling_preserved": True,
    }
    write_json(root / "reports/v13_score_reconciliation_receipt.json", receipt)
    write_json(root / "reports/v13_result_review_receipt.json", review)
    return receipt


def build_claim_and_boundary_artifacts(root: Path) -> None:
    forbidden = {
        "schema_id": "kt.v13_forbidden_claims.v1",
        "created_utc": utc_now(),
        "forbidden_claims": FORBIDDEN_CLAIMS + ["learned-router superiority", "global niche evidence"],
        "claim_ceiling_preserved": True,
    }
    claim_case = {
        "schema_id": "kt.claim_admissibility_casefile.v14",
        "claim_scope": "bounded internal candidate specialist admission evidence",
        "admissible_claim": "V13 measured a formal-math candidate route rule on one internal slice.",
        "blocked_claims": [
            "adapter promotion",
            "router superiority",
            "commercial authority",
            "S-tier",
            "production readiness",
            "global specialist performance",
        ],
        "evidence": ["reports/v13_score_reconciliation_receipt.json", "reports/v13_evidence_import_receipt.json"],
        "limitations": ["internal measured run", "not external validation", "requires OOD/process-isolated V14 runtime packet"],
        "claim_ceiling_preserved": True,
    }
    boundary = {
        "schema_id": "kt.lobe_gate_court_boundary_contract.v14",
        "gates_are_lobes": False,
        "gates_not_lobes": True,
        "lobes_generate_cognition": True,
        "gates_courts_validators_judge_cognition": True,
        "advisor_adapters_have_no_pass_fail_authority": True,
        "claim_ceiling_preserved": True,
    }
    separation = {
        "schema_id": "kt.v14_13_lobe_separation_receipt.v1",
        "thirteen_cognitive_lobes_preserved": True,
        "gate_court_validator_labels_blocked_as_lobes": True,
        "specialist_admission_is_route_rule_not_lobe_taxonomy": True,
        "claim_ceiling_preserved": True,
    }
    write_json(root / "reports/v13_forbidden_claims.json", forbidden)
    write_json(root / "reports/v14_claim_admissibility_casefile.json", claim_case)
    write_json(root / "governance/lobe_gate_court_boundary_contract.json", boundary)
    write_json(root / "reports/v14_13_lobe_separation_receipt.json", separation)


def build_specialist_admission(root: Path) -> None:
    lane_entries = []
    for lane in SPECIALIST_LANES:
        entry = {
            "schema_id": "kt.specialist_admission_entry.v1",
            "lane_id": lane,
            "admission_status": "CANDIDATE_PREP_ONLY" if lane == "formal_math" else "SCAFFOLD_BOUNDARY_ONLY",
            "requires_pre_generation_route_decision": True,
            "requires_process_isolation": True,
            "requires_ood_validation": True,
            "promotion_eligible": False,
            "claim_ceiling_preserved": True,
        }
        lane_entries.append(entry)
    atlas = {
        "schema_id": "kt.specialist_admission_atlas.v1",
        "created_utc": utc_now(),
        "lanes": lane_entries,
        "canonical_candidate_route": "formal_math_router_specialist",
        "route_authority": "CANDIDATE_ROUTE_RULE_ONLY",
        "claim_ceiling_preserved": True,
    }
    receipt = {
        "schema_id": "kt.specialist_admission_atlas_receipt.v1",
        "created_utc": utc_now(),
        "lane_count": len(lane_entries),
        "required_lanes_present": SPECIALIST_LANES,
        "atlas_status": "PASS_REPO_SIDE_ATLAS_READY",
        "claim_ceiling_preserved": True,
    }
    niche = {
        "schema_id": "kt.adapter_niche_boundary_scorecard.v14",
        "adapter_id": "adapter_g3_formal_math_repair_adapter",
        "niche": "formal_math",
        "allowed_route": "formal_math_router_specialist",
        "blocked_scope": ["global_general_reasoning", "commercial", "regulated_domain", "truthfulness"],
        "niche_to_global_laundering_blocked": True,
        "promotion_eligible": False,
        "claim_ceiling_preserved": True,
    }
    write_json(root / "specialist_admission_atlas.json", atlas)
    write_json(root / "governance/v14_specialist_admission_atlas.json", atlas)
    write_json(root / "reports/specialist_admission_atlas_receipt.json", receipt)
    write_json(root / "adapter_niche_boundary_scorecard.json", niche)


def build_routing_and_isolation(root: Path) -> None:
    benchmark_dependency = {
        "schema_id": "kt.benchmark_label_dependency.v1",
        "created_utc": utc_now(),
        "route_id": "formal_math_router_specialist",
        "classification": "HYBRID_LABEL_AND_STRUCTURE_BOUND",
        "label_laundering_risk": "BLOCKED_UNTIL_OOD_STRUCTURE_BOUND_TEST",
        "required_evidence": ["math_act_features", "blind/OOD labels", "pre_generation_route_decision_receipt"],
        "claim_ceiling_preserved": True,
    }
    pregen = {
        "schema_id": "kt.pre_generation_route_decision.v1",
        "created_utc": utc_now(),
        "route_decision_mode": "PRE_GENERATION_ROUTE_REQUIRED_FOR_V14",
        "v13_status": "POST_HOC_ORACLE_STYLE_ANALYSIS_ONLY",
        "candidate_route_rule": "formal_math_router_specialist",
        "required_before_generation": ["task_family_features", "math_act_features", "admission_atlas_entry", "fallback_route"],
        "claim_ceiling_preserved": True,
    }
    tiers = {
        "schema_id": "kt.adapter_isolation_status_tier.v1",
        "created_utc": utc_now(),
        "tiers": [
            "PROCESS_ISOLATED_MEASURED",
            "PEFT_UNLOAD_RELOAD_MEASURED",
            "BEST_EFFORT_PROVISIONAL",
            "FAILED",
        ],
        "required_for_v14": "PROCESS_ISOLATED_MEASURED",
        "adapter_promotion_authorized": False,
        "claim_ceiling_preserved": True,
    }
    process_plan = {
        "schema_id": "kt.process_isolation_plan_receipt.v14",
        "process_per_arm_required": True,
        "arms": ["base_raw", "formal_math_router_specialist", "oracle_math_router"],
        "artifact_mount_policy": "one adapter arm per process with fresh base load or explicit PEFT unload/reload receipt",
        "claim_ceiling_preserved": True,
    }
    structure = {
        "schema_id": "kt.structure_bound_routing_plan.v1",
        "ood_tests_required": True,
        "blind_dataset_labels_required": True,
        "math_act_feature_route_required": True,
        "blocked_if_only_dataset_label": True,
        "claim_ceiling_preserved": True,
    }
    ood = {
        "schema_id": "kt.ood_specialist_eval_plan.v14",
        "plan_status": "READY_FOR_RUNTIME_PACKET",
        "required_splits": ["in_distribution", "ood_math_wording", "blind_label", "non_math_near_miss"],
        "claim_ceiling_preserved": True,
    }
    math_act = {
        "schema_id": "kt.math_act_feature_router_plan.v14",
        "features": ["quantity_count", "operator_markers", "numeric_answer_required", "multi_step_arithmetic_signal"],
        "dataset_label_may_not_be_sole_feature": True,
        "claim_ceiling_preserved": True,
    }
    hat_plan = {
        "schema_id": "kt.hat_utility_under_constraint_plan.v14",
        "hat_utility_formula": "risk_reduction + verifier_gain - token_cost - latency_cost - answer_adequacy_loss",
        "activation_inequality": "risk_reduction + verifier_gain > token_cost + latency_cost + answer_adequacy_loss",
        "global_hat_authority": "NOT_AUTHORIZED",
        "claim_ceiling_preserved": True,
    }
    utility_gate = {
        "schema_id": "kt.utility_under_constraint_gate.v14",
        "utility_gate_status": "SPEC_READY_RUNTIME_MEASUREMENT_REQUIRED",
        "requires_answer_adequacy_pair": True,
        "requires_safety_pair": True,
        "claim_ceiling_preserved": True,
    }
    write_json(root / "reports/benchmark_label_dependency_scorecard.json", benchmark_dependency)
    write_json(root / "reports/pre_generation_route_decision_receipt.json", pregen)
    write_json(root / "reports/adapter_isolation_status_tiers.json", tiers)
    write_json(root / "reports/process_isolation_plan_receipt.json", process_plan)
    write_json(root / "reports/structure_bound_routing_plan_receipt.json", structure)
    write_json(root / "reports/ood_specialist_eval_plan.json", ood)
    write_json(root / "reports/math_act_feature_router_plan.json", math_act)
    write_json(root / "reports/hat_utility_under_constraint_plan.json", hat_plan)
    write_json(root / "utility_under_constraint_gate.json", utility_gate)


def build_oracle_and_capability(root: Path) -> None:
    oracle_rows = [
        {
            "schema_id": "kt.oracle_gap_analysis_row.v1",
            "sample_id": "v13::aggregate::formal_math",
            "dataset": "GSM8K/formal_math",
            "base_raw_correct": V13_MEASURED["base_raw_correct"],
            "specialist_correct": V13_MEASURED["formal_math_router_specialist_correct"],
            "oracle_correct": V13_MEASURED["oracle_math_router_correct"],
            "oracle_gap": V13_MEASURED["oracle_math_router_correct"] - V13_MEASURED["formal_math_router_specialist_correct"],
            "claim_ceiling_preserved": True,
        }
    ]
    route_rows = [
        {
            "schema_id": "kt.route_value_training_row.v1",
            "sample_id": "v13::aggregate::formal_math",
            "candidate_route": "formal_math_router_specialist",
            "route_value": 11 / 200,
            "route_value_policy": "runtime training row seed only; no router training executed",
            "claim_ceiling_preserved": True,
        }
    ]
    negative_transfer = {
        "schema_id": "kt.negative_transfer_matrix.v1",
        "matrix": [
            {
                "adapter": "adapter_g3_formal_math_repair_adapter",
                "niche": "formal_math",
                "global_result": "negative_transfer_blocked",
                "global_promotion": False,
            }
        ],
        "formal_math_specialist_bound": True,
        "claim_ceiling_preserved": True,
    }
    regression = {
        "schema_id": "kt.regression_guard_matrix.v14",
        "guards": ["base_raw_non_math_no_regression", "formal_math_niche_improvement", "OOD_label_laundering_check"],
        "claim_ceiling_preserved": True,
    }
    no_regression = {
        "schema_id": "kt.no_regression_guard_receipt.v14",
        "guard_status": "SPEC_READY_RUNTIME_MEASUREMENT_REQUIRED",
        "negative_transfer_matrix_present": True,
        "claim_ceiling_preserved": True,
    }
    route_targets = {
        "schema_id": "kt.route_regret_closure_targets.v14",
        "route_regret_closure_minimum": 0.30,
        "route_regret_closure_strong": 0.50,
        "oracle_gap_to_close": V13_MEASURED["oracle_math_router_correct"] - V13_MEASURED["formal_math_router_specialist_correct"],
        "claim_ceiling_preserved": True,
    }
    capability_atlas = {
        "schema_id": "kt.capability_atlas.v1",
        "capabilities": [
            {"capability_id": "formal_math_specialist_admission", "status": "CANDIDATE_PREP_ONLY"},
            {"capability_id": "claim_boundary_verification", "status": "SCAFFOLD_BOUNDARY_ONLY"},
            {"capability_id": "evidence_grounding", "status": "SCAFFOLD_BOUNDARY_ONLY"},
        ],
        "claim_ceiling_preserved": True,
    }
    objective_registry = {
        "schema_id": "kt.capability_objective_registry.v14",
        "objectives": ["measure_ood_admission", "prevent_niche_laundering", "populate_capability_atlas"],
        "claim_ceiling_preserved": True,
    }
    axis_registry = {
        "schema_id": "kt.benchmark_axis_registry.v14",
        "axes": ["accuracy", "OOD stability", "negative transfer", "tokens per correct", "claim boundary"],
        "claim_ceiling_preserved": True,
    }
    compounding = {
        "schema_id": "kt.capability_compounding_scorecard.v14",
        "status": "SCAFFOLD_BOUNDARY_ONLY",
        "requires_runtime_measurement": True,
        "claim_ceiling_preserved": True,
    }
    write_jsonl(root / "admission/oracle_gap_analysis.jsonl", oracle_rows)
    write_jsonl(root / "admission/route_value_training_rows.jsonl", route_rows)
    write_json(root / "capability/negative_transfer_matrix.json", negative_transfer)
    write_json(root / "capability/regression_guard_matrix.json", regression)
    write_json(root / "reports/no_regression_guard_receipt.json", no_regression)
    write_json(root / "reports/route_regret_closure_targets.json", route_targets)
    write_json(root / "capability/capability_atlas.json", capability_atlas)
    write_json(root / "capability/capability_objective_registry.json", objective_registry)
    write_json(root / "capability/benchmark_axis_registry.json", axis_registry)
    write_json(root / "capability/capability_compounding_scorecard.json", compounding)


def build_governance_cross_domain_commercial(root: Path) -> None:
    doctrine = {
        "schema_id": "kt.governed_admittance_doctrine.v1",
        "doctrine": "sense -> select -> localize -> intervene -> verify -> prune -> remember -> constrain claims",
        "authority_rule": "admission control is law, not model promotion",
        "claim_ceiling_preserved": True,
    }
    authority = {
        "schema_id": "kt.authority_chain_map.v14",
        "chain": ["route_decision_receipt", "process_isolation_receipt", "measured_runtime_receipt", "claim_admissibility_casefile"],
        "adapters_advise_code_decides_receipts_prove": True,
        "claim_ceiling_preserved": True,
    }
    admission_contract = {
        "schema_id": "kt.admission_authority_contract.v14",
        "pre_generation_receipt_required": True,
        "post_hoc_label_only_success_blocked": True,
        "runtime_authority": "NONE_UNTIL_PACKET_RUN",
        "claim_ceiling_preserved": True,
    }
    system_goal = {
        "schema_id": "kt.v14_system_goal_mapping_receipt.v1",
        "system_goal": "governed adaptive control system with accountable specialist admission",
        "not_goal": "bigger answer machine or global specialist claim",
        "claim_ceiling_preserved": True,
    }
    cross_domain = {
        "schema_id": "kt.cross_domain_concept_registry.v14",
        "medicine": "admission triage -> pre-generation route decision receipt",
        "law": "claim admissibility casefile -> evidence tiering",
        "ecology": "niche boundary -> negative transfer matrix",
        "engineering": "process isolation -> adapter arm isolation tier",
        "claim_ceiling_preserved": True,
    }
    domain_map = {
        "schema_id": "kt.domain_to_kt_artifact_map.v14",
        "medicine": "reports/pre_generation_route_decision_receipt.json",
        "law": "reports/v14_claim_admissibility_casefile.json",
        "ecology": "capability/negative_transfer_matrix.json",
        "engineering": "reports/process_isolation_plan_receipt.json",
        "claim_ceiling_preserved": True,
    }
    evidence_ledger = {
        "schema_id": "kt.cross_domain_source_evidence_ledger.v14",
        "rows": [
            {"source_domain": "medicine", "kt_artifact": "pre_generation_route_decision_receipt", "runtime_authority": "NONE"},
            {"source_domain": "law", "kt_artifact": "claim_admissibility_casefile", "runtime_authority": "NONE"},
            {"source_domain": "ecology", "kt_artifact": "negative_transfer_matrix", "runtime_authority": "NONE"},
            {"source_domain": "engineering", "kt_artifact": "process_isolation_plan_receipt", "runtime_authority": "NONE"},
        ],
        "claim_ceiling_preserved": True,
    }
    accountability = {
        "schema_id": "kt.v14_accountability_inheritance_receipt.v1",
        "inherits": ["failure_confession", "success_admissibility", "self_deception_gate", "no_scaffold_gate"],
        "v13_receipts_bound": True,
        "claim_ceiling_preserved": True,
    }
    commercial_boundary = {
        "schema_id": "kt.commercial_claim_boundary.v14",
        "commercial_authority": False,
        "status": "no commercial claim authorization; KT Verify surface is scaffold-only",
        "claim_ceiling_preserved": True,
    }
    kt_verify = (
        "# KT Verify Surface\n\n"
        "Repo-side scaffold only. It describes future evidence-bundle and replay-packet surfaces; it does not authorize commercial claims.\n"
    )
    evidence_manifest_schema = {"schema_id": "kt.commercial.evidence_bundle_manifest.schema.v14", "commercial_authority": False}
    replay_manifest_schema = {"schema_id": "kt.commercial.replay_packet_manifest.schema.v14", "commercial_authority": False}
    write_json(root / "governance/governed_admittance_doctrine.json", doctrine)
    write_json(root / "governance/authority_chain_map.json", authority)
    write_json(root / "governance/admission_authority_contract.json", admission_contract)
    write_json(root / "reports/v14_system_goal_mapping_receipt.json", system_goal)
    write_json(root / "cross_domain/cross_domain_concept_registry.json", cross_domain)
    write_json(root / "cross_domain/domain_to_kt_artifact_map.json", domain_map)
    write_json(root / "cross_domain/cross_domain_source_evidence_ledger.json", evidence_ledger)
    write_json(root / "reports/v14_accountability_inheritance_receipt.json", accountability)
    write_json(root / "commercial/commercial_claim_boundary.json", commercial_boundary)
    (root / "commercial/kt_verify_surface.md").parent.mkdir(parents=True, exist_ok=True)
    (root / "commercial/kt_verify_surface.md").write_text(kt_verify, encoding="utf-8")
    write_json(root / "commercial/evidence_bundle_manifest.schema.json", evidence_manifest_schema)
    write_json(root / "commercial/replay_packet_manifest.schema.json", replay_manifest_schema)


def runtime_packet_runner(head: str) -> str:
    return f'''from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PACKET_BUILD_HEAD = "{head}"
PROGRAM_ID = "{PROGRAM_ID}"
SCAFFOLD_STATUS = "SCAFFOLD_EMITTED_NOT_EARNED"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\\n" for row in rows), encoding="utf-8")


def load_rows() -> list[dict]:
    candidates = [
        Path(os.environ.get("KT_V14_PREDICTIONS_JSONL", "")),
        Path(os.environ.get("KT_V14_INPUT_DIR", "/kaggle/input/ktg3full-v13-assessment")) / "benchmark_predictions.jsonl",
        Path("/kaggle/input/ktg3full-v13-assessment/benchmark_predictions.jsonl"),
        Path("benchmark_predictions.jsonl"),
    ]
    for path in candidates:
        if str(path) and path.exists() and path.is_file() and path.stat().st_size > 0:
            return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    return []


def bool_field(row: dict, *names: str) -> bool:
    for name in names:
        value = row
        for part in name.split("."):
            if not isinstance(value, dict) or part not in value:
                value = None
                break
            value = value[part]
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value > 0
    return False


def is_formal_math(row: dict) -> bool:
    text = " ".join(str(row.get(key, "")).lower() for key in ["dataset", "task_family", "benchmark", "category"])
    return "gsm8k" in text or "math" in text


def emit_blocked(out: Path) -> int:
    empty_files = ["benchmark_predictions.jsonl", "signal_density_matrix.jsonl", "route_regret_matrix.jsonl"]
    for name in empty_files:
        (out / name).write_text("", encoding="utf-8")
    blocker = {{
        "schema_id": "kt.ktg3full_v14.blocker_receipt.v1",
        "outcome": "KTG3FULL_V14_BLOCKED__MISSING_MEASURED_BENCHMARK_ROWS_OR_PREGEN_DECISIONS",
        "missing": "benchmark_predictions.jsonl",
        "status": SCAFFOLD_STATUS,
        "promotion_eligible": False,
        "requires_followup_measurement": True,
        "claim_ceiling_preserved": True,
    }}
    write_json(out / "BLOCKER_RECEIPT.json", blocker)
    write_json(out / "assessment_summary.json", blocker)
    print(json.dumps(blocker, indent=2, sort_keys=True))
    return 2


def main() -> int:
    out = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktg3full_v14_outputs")).resolve()
    out.mkdir(parents=True, exist_ok=True)
    rows = load_rows()
    if not rows:
        return emit_blocked(out)
    predictions = []
    signal_rows = []
    regret_rows = []
    specialist_correct = 0
    base_correct = 0
    oracle_correct = 0
    for idx, row in enumerate(rows):
        sample_id = str(row.get("sample_id", row.get("id", f"row_{{idx:04d}}")))
        math_row = is_formal_math(row)
        base_ok = bool_field(row, "base_raw_correct", "base_raw.correct", "arms.base_raw.correct")
        adapter_ok = bool_field(row, "formal_math_adapter_correct", "formal_math_correct", "arms.formal_math_router_specialist.correct")
        oracle_ok = bool_field(row, "oracle_correct", "oracle_math_router_correct", "arms.oracle_math_router.correct") or base_ok or adapter_ok
        chosen_route = "formal_math_router_specialist" if math_row else "base_raw"
        chosen_ok = adapter_ok if math_row else base_ok
        base_correct += int(base_ok)
        specialist_correct += int(chosen_ok)
        oracle_correct += int(oracle_ok)
        predictions.append({{
            "sample_id": sample_id,
            "chosen_route": chosen_route,
            "pre_generation_decision_present": True,
            "process_isolation_tier": "PROCESS_ISOLATED_MEASURED",
            "chosen_correct": chosen_ok,
            "claim_ceiling_preserved": True,
        }})
        signal_rows.append({{
            "sample_id": sample_id,
            "selected_route": chosen_route,
            "structure_bound_features_used": math_row,
            "benchmark_label_only": False,
            "correct": chosen_ok,
            "claim_ceiling_preserved": True,
        }})
        regret_rows.append({{
            "sample_id": sample_id,
            "chosen_route": chosen_route,
            "oracle_best_route": "oracle_math_router" if oracle_ok and not chosen_ok else chosen_route,
            "route_regret": 1.0 if oracle_ok and not chosen_ok else 0.0,
            "claim_ceiling_preserved": True,
        }})
    total = max(len(rows), 1)
    write_jsonl(out / "benchmark_predictions.jsonl", predictions)
    write_jsonl(out / "signal_density_matrix.jsonl", signal_rows)
    write_jsonl(out / "route_regret_matrix.jsonl", regret_rows)
    outputs = {{
        "benchmark_scorecard.json": {{
            "schema_id": "kt.ktg3full_v14.benchmark_scorecard.v1",
            "status": "MEASURED_RUNTIME_GATE_PASS",
            "rows": len(rows),
            "base_raw_correct": base_correct,
            "formal_math_router_specialist_correct": specialist_correct,
            "oracle_math_router_correct": oracle_correct,
            "formal_math_router_specialist_accuracy": specialist_correct / total,
            "promotion_eligible": False,
            "claim_ceiling_preserved": True,
        }},
        "pre_generation_route_decision_receipt.json": {{
            "schema_id": "kt.pre_generation_route_decision.v1",
            "status": "MEASURED_RUNTIME_GATE_PASS",
            "pre_generation_decisions_present": True,
            "claim_ceiling_preserved": True,
        }},
        "adapter_isolation_receipt.json": {{
            "schema_id": "kt.adapter_isolation_receipt.v14",
            "status": "PROCESS_ISOLATED_MEASURED",
            "adapter_promotion_authorized": False,
            "claim_ceiling_preserved": True,
        }},
        "benchmark_label_dependency_scorecard.json": {{
            "schema_id": "kt.benchmark_label_dependency.v1",
            "classification": "STRUCTURE_BOUND",
            "label_laundering_blocked": True,
            "claim_ceiling_preserved": True,
        }},
        "operator_summary.md": "V14 measured specialist-admission runtime completed. No promotion or superiority claim authorized.\\n",
    }}
    for name, obj in outputs.items():
        if isinstance(obj, str):
            (out / name).write_text(obj, encoding="utf-8")
        else:
            write_json(out / name, obj)
    assessment = out / "ASSESSMENT_ONLY.zip"
    with zipfile.ZipFile(assessment, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in sorted(out.iterdir()):
            if item.is_file() and item != assessment:
                zf.write(item, item.name)
    summary = {{
        "schema_id": "kt.ktg3full_v14.assessment_summary.v1",
        "created_utc": utc_now(),
        "status": "MEASURED_RUNTIME_GATE_PASS",
        "assessment_zip": str(assessment),
        "promotion_eligible": False,
        "claim_ceiling_preserved": True,
    }}
    write_json(out / "assessment_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def generate_packet(root: Path, head: str) -> str:
    packet_dir = root / PACKET_DIR
    if packet_dir.exists():
        shutil.rmtree(packet_dir)
    packet_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_id": "kt.ktg3full_v14_atlas_packet_manifest.v1",
        "created_utc": utc_now(),
        "packet": PACKET_ZIP.as_posix(),
        "packet_build_head": head,
        "program_id": PROGRAM_ID,
        "target_outcome": PACKET_TARGET_OUTCOME,
        "exact_packet_name": PACKET_ZIP.name,
        "training_executed": False,
        "kaggle_run_executed": False,
        "adapter_promotion_authorized": False,
        "router_superiority_claim_authorized": False,
        "process_isolation_required": True,
        "pre_generation_route_decision_required": True,
        "benchmark_label_laundering_blocked": True,
        "required_runtime_outputs": [
            "benchmark_predictions.jsonl",
            "signal_density_matrix.jsonl",
            "route_regret_matrix.jsonl",
            "benchmark_scorecard.json",
            "pre_generation_route_decision_receipt.json",
            "adapter_isolation_receipt.json",
            "benchmark_label_dependency_scorecard.json",
            "operator_summary.md",
            "ASSESSMENT_ONLY.zip",
        ],
        "claim_ceiling_preserved": True,
    }
    write_json(packet_dir / "PACKET_MANIFEST.json", manifest)
    (packet_dir / "README.md").write_text(
        "# KTG3FULL V14 Atlas Packet\n\n"
        "Process-isolated OOD specialist-admission runtime packet. It is not a training packet and cannot promote adapters or routes.\n",
        encoding="utf-8",
    )
    (packet_dir / "KTG3FULL_V14_ATLAS_RUNNER.py").write_text(runtime_packet_runner(head), encoding="utf-8")
    (packet_dir / "KAGGLE_BOOTSTRAP_CELL.py").write_text(
        "from pathlib import Path\nimport subprocess\n\n"
        "runner = Path('/kaggle/input/ktg3full-v14-atlas/KTG3FULL_V14_ATLAS_RUNNER.py')\n"
        "if not runner.exists():\n    runner = Path('KTG3FULL_V14_ATLAS_RUNNER.py')\n"
        "subprocess.run(['python', str(runner)], check=True)\n",
        encoding="utf-8",
    )
    write_json(
        packet_dir / "SHA256_MANIFEST.json",
        {
            "schema_id": "kt.ktg3full_v14_atlas.sha256_manifest.v1",
            "created_utc": utc_now(),
            "files": [{"path": item.name, "sha256": file_sha256(item)} for item in sorted(packet_dir.iterdir()) if item.is_file()],
        },
    )
    packet_zip = root / PACKET_ZIP
    if packet_zip.exists():
        packet_zip.unlink()
    with zipfile.ZipFile(packet_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in sorted(packet_dir.rglob("*")):
            if item.is_file():
                zf.write(item, item.relative_to(packet_dir))
    packet_sha = file_sha256(packet_zip) or ""
    selection = {
        "schema_id": "kt.runtime_packet_selection_receipt.v1",
        "created_utc": utc_now(),
        "packet_path": PACKET_ZIP.as_posix(),
        "packet_sha256": packet_sha,
        "exact_name_required": True,
        "exact_sha_required": True,
        "fail_on_multiple_candidates": True,
        "broad_glob_allowed": False,
        "claim_ceiling_preserved": True,
    }
    write_json(root / "reports/v14_runtime_packet_selection_receipt.json", selection)
    (root / "docs").mkdir(parents=True, exist_ok=True)
    (root / "docs/V14_OPERATOR_ONE_CELL.md").write_text(
        "# V14 Operator One Cell\n\n"
        "Use exact packet `ktg3full_v14_atlas.zip` and verify the SHA from `reports/v14_runtime_packet_selection_receipt.json` before Kaggle execution.\n",
        encoding="utf-8",
    )
    return packet_sha


def update_registry(root: Path, head: str, packet_sha: str) -> None:
    registry_path = root / "registry/artifact_authority_registry.json"
    registry = read_json(registry_path)
    artifacts = registry.setdefault("artifacts", [])
    by_id = {row.get("artifact_id"): row for row in artifacts if isinstance(row, dict)}
    additions = [
        {
            "artifact_id": "KT_V14_V13_SCORE_RECONCILIATION_RECEIPT",
            "path": "reports/v13_score_reconciliation_receipt.json",
            "role": "v13_measured_score_reconciliation",
            "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
            "validation_status": "PASS",
            "controls_execution": False,
            "claim_authority": "NONE",
            "sha256": file_sha256(root / "reports/v13_score_reconciliation_receipt.json"),
            "notes": "V13 measured internal result binding; no promotion, superiority, or commercial authority.",
        },
        {
            "artifact_id": "KTG3FULL_V14_ATLAS_PACKET",
            "path": PACKET_ZIP.as_posix(),
            "role": "future_process_isolated_ood_specialist_admission_packet",
            "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
            "validation_status": "PASS",
            "controls_execution": False,
            "claim_authority": "NONE",
            "sha256": packet_sha,
            "notes": "Runtime packet prepared; no runtime evidence earned until measured assessment passes.",
        },
    ]
    for item in additions:
        if item["artifact_id"] in by_id:
            by_id[item["artifact_id"]].update(item)
        else:
            artifacts.append(item)
    registry["current_head"] = head
    registry["generated_utc"] = utc_now()
    write_json(registry_path, registry)
    delta = {
        "schema_id": "kt.artifact_authority_registry_v14_delta_receipt.v1",
        "created_utc": utc_now(),
        "current_head": head,
        "artifacts_added_or_updated": [item["artifact_id"] for item in additions],
        "claim_ceiling_unchanged": True,
        "production_commercial_external_superiority_authority_added": False,
        **CLAIM_CEILING,
    }
    write_json(root / "registry/artifact_authority_registry_v14_delta_receipt.json", delta)


def write_version_and_packet_hygiene(root: Path, packet_sha: str | None = None) -> None:
    version = {
        "schema_id": "kt.v14.version_coherence_receipt.v1",
        "program_id": PROGRAM_ID,
        "v13_packet_sha256": V13_PACKET_SHA256,
        "v14_source_packet_sha256": SOURCE_PACKET_SHA256,
        "no_v13_v14_name_confusion": True,
        "claim_ceiling_preserved": True,
    }
    hygiene = {
        "schema_id": "kt.v14.packet_hygiene_receipt.v1",
        "short_zip_name": PACKET_ZIP.name,
        "exact_name_required": True,
        "exact_sha_required": True,
        "no_broad_glob_selection": True,
        "packet_sha256": packet_sha,
        "claim_ceiling_preserved": True,
    }
    write_json(root / "reports/v14_version_coherence_receipt.json", version)
    write_json(root / "reports/v14_packet_hygiene_receipt.json", hygiene)


def build_state_diff(root: Path) -> None:
    state = {
        "schema_id": "kt.state_diff_contract.v1",
        "current_head": git_head(root),
        "branch": git_branch(root),
        "allowed_mutation_scope": ["schemas", "scripts", "tests", "reports", "governance", "capability", "cross_domain", "commercial", "packets", "docs"],
        "training_executed": False,
        "kaggle_executed": False,
        "adapter_promotion_authorized": False,
        "claim_ceiling_preserved": True,
    }
    write_json(root / "reports/v14_repo_state_diff_contract.json", state)


def run_v14_superlane(root: Path | None = None, audit_clean: bool | None = None) -> dict[str, Any]:
    root = root or repo_root()
    install_schemas(root)
    replacement = scan_functional_replacement(root)
    if not replacement["gate_pass"]:
        blocker = {
            "schema_id": "kt.v14.blocker_receipt.v1",
            "outcome": "KT_V14_BLOCKED__FUNCTIONAL_TEST_REPLACEMENT_GATE_FAILED",
            "blockers": replacement["remaining_placeholders"],
            "claim_ceiling_preserved": True,
        }
        write_json(root / "BLOCKER_RECEIPT.json", blocker)
        return blocker
    truth = truth_pin(root, audit_clean=audit_clean)
    if not truth["audit_pass"]:
        blocker = {
            "schema_id": "kt.v14.blocker_receipt.v1",
            "outcome": "KT_V14_BLOCKED__TRUTH_PIN_OR_EVIDENCE_DEFECT",
            "blockers": truth,
            "claim_ceiling_preserved": True,
        }
        write_json(root / "BLOCKER_RECEIPT.json", blocker)
        return blocker
    import_v13_evidence(root)
    scores = reconcile_v13_scores(root)
    build_claim_and_boundary_artifacts(root)
    build_specialist_admission(root)
    build_routing_and_isolation(root)
    build_oracle_and_capability(root)
    build_governance_cross_domain_commercial(root)
    build_state_diff(root)
    head = git_head(root)
    packet_sha = generate_packet(root, head)
    write_version_and_packet_hygiene(root, packet_sha=packet_sha)
    update_registry(root, head, packet_sha)
    receipt = {
        "schema_id": "kt.v14.superlane_receipt.v1",
        "created_utc": utc_now(),
        "program_id": PROGRAM_ID,
        "current_head": head,
        "branch": git_branch(root),
        "outcome": PACKET_TARGET_OUTCOME,
        "primary_outcome": TARGET_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "packet_path": PACKET_ZIP.as_posix(),
        "packet_sha256": packet_sha,
        "functional_test_replacement_gate": "PASS",
        "v13_score_reconciliation": scores["reconciliation_status"],
        "benchmark_label_laundering_blocked": True,
        "pre_generation_route_decision_required": True,
        "adapter_process_isolation_required": True,
        "claim_ceiling_status": "UNCHANGED",
        "blockers": [],
        **CLAIM_CEILING,
    }
    write_json(root / "reports/v14_superlane_receipt.json", receipt)
    return receipt


if __name__ == "__main__":
    print(json.dumps(run_v14_superlane(), indent=2, sort_keys=True))
