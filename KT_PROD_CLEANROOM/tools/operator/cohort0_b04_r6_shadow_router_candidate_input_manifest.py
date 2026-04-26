from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import canonical_file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


REQUIRED_BRANCH = "authoritative/b04-r6-shadow-router-candidate-input-manifest"
OUTCOME = "B04_R6_SHADOW_ROUTER_CANDIDATE_AND_INPUT_MANIFEST_BOUND"
NEXT_MOVE_IF_BLOCKED = "AUTHOR_B04_R6_ADMISSIBLE_LEARNED_ROUTER_CANDIDATE_SOURCE_PACKET"
NEXT_MOVE_IF_AUTHORIZED = "EXECUTE_B04_R6_SHADOW_ROUTER_SUPERIORITY_SCREEN"

REQUIRED_PREVIOUS_MOVE = "AUTHOR_B04_R6_SHADOW_ROUTER_CANDIDATE_AND_INPUT_MANIFEST"
R6_HOLD_MOVE = "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF"

SCREEN_AUTHORIZED_VERDICT = "R6_SHADOW_SCREEN_EXECUTION_AUTHORIZED"
CANDIDATE_OR_INPUT_DEFECT_VERDICT = "R6_DEFERRED__CANDIDATE_OR_INPUT_MANIFEST_DEFECT"
CANDIDATE_BLOCKED_VERDICT = "R6_BLOCKED__CANDIDATE_NOT_ADMISSIBLE"

REQUIRED_COMPARATOR_ROWS = {
    "current_canonical_static_router",
    "best_static_adapter_control",
    "shadow_learned_router_candidate",
    "abstention_static_hold_control",
}
REQUIRED_METRICS = {
    "route_superiority",
    "outcome_delta",
    "control_preservation",
    "abstention_quality",
    "overrouting_penalty",
    "mirror_masked_invariance",
    "no_regression",
    "consequence_visibility",
}
REQUIRED_INPUT_FIELDS = {
    "candidate_id",
    "candidate_source_ref",
    "input_family_manifest",
    "holdout_boundary",
    "comparator_matrix_ref",
    "metric_thresholds_ref",
    "hard_disqualifier_ref",
}

FORBIDDEN_CLAIMS = [
    "r6_open",
    "learned_router_superiority_earned",
    "learned_router_cutover_authorized",
    "multi_lobe_authorized",
    "package_promotion_approved",
    "commercial_broadening",
    "external_verification_completed",
]

OUTPUTS = {
    "authority_packet": "b04_r6_shadow_router_candidate_input_manifest_packet.json",
    "receipt": "b04_r6_shadow_router_candidate_input_manifest_receipt.json",
    "candidate_manifest": "b04_r6_learned_router_candidate_manifest.json",
    "input_manifest": "b04_r6_shadow_router_input_manifest_bound.json",
    "comparator_binding": "b04_r6_shadow_router_comparator_binding_receipt.json",
    "execution_mode": "b04_r6_shadow_router_execution_mode_contract.json",
    "evidence_requirements": "b04_r6_shadow_router_evidence_requirements_receipt.json",
    "validation_matrix": "b04_r6_shadow_router_candidate_input_validation_matrix.json",
    "blocker_ledger": "b04_r6_shadow_router_candidate_input_blocker_ledger.json",
    "next_court": "b04_r6_shadow_router_candidate_input_next_court_receipt.json",
    "scorecard_schema": "b04_r6_shadow_router_scorecard_schema.json",
    "route_trace_schema": "b04_r6_shadow_router_route_decision_trace_schema.json",
    "invariance_trace_schema": "b04_r6_shadow_router_mirror_masked_invariance_trace_schema.json",
    "abstention_trace_schema": "b04_r6_shadow_router_abstention_overrouting_trace_schema.json",
    "clean_state": "b04_r6_shadow_router_candidate_input_clean_state_receipt.json",
}


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _sha_ref(path: Path, *, root: Path) -> Dict[str, str]:
    resolved = path.resolve()
    return {
        "path": resolved.relative_to(root.resolve()).as_posix(),
        "sha256": canonical_file_sha256(resolved),
    }


def _base(*, generated_utc: str, head: str, status: str = "PASS") -> Dict[str, Any]:
    return {
        "status": status,
        "generated_utc": generated_utc,
        "current_git_head": head,
        "authoritative_lane": "B04_R6_SHADOW_ROUTER_CANDIDATE_AND_INPUT_MANIFEST",
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "r6_authorized": False,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "learned_router_cutover_authorized": False,
        "multi_lobe_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _ensure_pass_and_bound(payload: Dict[str, Any], *, label: str) -> None:
    common.ensure_pass(payload, label=label)
    if payload.get("r6_authorized") is not False:
        raise RuntimeError(f"FAIL_CLOSED: {label} must keep R6 unauthorized")
    if payload.get("learned_router_superiority_earned") is not False:
        raise RuntimeError(f"FAIL_CLOSED: {label} must not claim learned-router superiority")


def _ensure_inputs(
    *,
    contract_receipt: Dict[str, Any],
    input_contract: Dict[str, Any],
    shadow_auth: Dict[str, Any],
    comparator_matrix: Dict[str, Any],
    metric_thresholds: Dict[str, Any],
    hard_disqualifiers: Dict[str, Any],
    evidence_requirements: Dict[str, Any],
    scorecard: Dict[str, Any],
    shadow_matrix: Dict[str, Any],
    route_health: Dict[str, Any],
    live_validation: Dict[str, Any],
) -> None:
    _ensure_pass_and_bound(contract_receipt, label="R6 comparator metric receipt")
    _ensure_pass_and_bound(input_contract, label="R6 input manifest contract")
    _ensure_pass_and_bound(shadow_auth, label="R6 shadow screen authorization contract")
    _ensure_pass_and_bound(comparator_matrix, label="R6 comparator matrix contract")
    _ensure_pass_and_bound(metric_thresholds, label="R6 metric threshold contract")
    _ensure_pass_and_bound(hard_disqualifiers, label="R6 hard disqualifier contract")
    _ensure_pass_and_bound(evidence_requirements, label="R6 evidence requirements contract")
    common.ensure_pass(scorecard, label="router superiority scorecard")
    common.ensure_pass(shadow_matrix, label="router shadow evaluation matrix")
    common.ensure_pass(route_health, label="route distribution health")
    common.ensure_pass(live_validation, label="trust-zone validation")

    if contract_receipt.get("next_lawful_move") != REQUIRED_PREVIOUS_MOVE:
        raise RuntimeError("FAIL_CLOSED: comparator receipt does not authorize candidate/input manifest court")
    if contract_receipt.get("screen_contract_authorized") is not True:
        raise RuntimeError("FAIL_CLOSED: comparator receipt must authorize the screen contract")
    if contract_receipt.get("screen_executable_now") is not False:
        raise RuntimeError("FAIL_CLOSED: screen must not already be executable before candidate/input manifest")
    if input_contract.get("must_be_bound_before_screen") is not True:
        raise RuntimeError("FAIL_CLOSED: input manifest contract must require binding before screen")
    if not REQUIRED_INPUT_FIELDS.issubset(set(input_contract.get("required_fields", []))):
        raise RuntimeError("FAIL_CLOSED: input manifest contract missing required fields")
    if shadow_auth.get("screen_contract_authorized") is not True or shadow_auth.get("screen_executable_now") is not False:
        raise RuntimeError("FAIL_CLOSED: shadow authorization must be contract-only and non-executable")
    if shadow_auth.get("r6_open") is not False:
        raise RuntimeError("FAIL_CLOSED: shadow authorization must not open R6")

    comparator_rows = {str(row.get("row_id", "")).strip() for row in comparator_matrix.get("rows", []) if isinstance(row, dict)}
    if not REQUIRED_COMPARATOR_ROWS.issubset(comparator_rows):
        raise RuntimeError("FAIL_CLOSED: comparator matrix missing required R6 rows")
    metrics = metric_thresholds.get("metrics")
    if not isinstance(metrics, dict) or not REQUIRED_METRICS.issubset(set(metrics)):
        raise RuntimeError("FAIL_CLOSED: metric threshold contract missing required metrics")
    if not isinstance(hard_disqualifiers.get("hard_disqualifiers"), list) or not hard_disqualifiers["hard_disqualifiers"]:
        raise RuntimeError("FAIL_CLOSED: hard disqualifier contract must bind hard stops")
    if "candidate/input manifest" not in evidence_requirements.get("missing_before_execution", []):
        raise RuntimeError("FAIL_CLOSED: evidence contract must identify candidate/input manifest as missing before this court")

    learned_candidate = scorecard.get("learned_router_candidate")
    if not isinstance(learned_candidate, dict):
        raise RuntimeError("FAIL_CLOSED: scorecard must include learned-router candidate object")
    if learned_candidate.get("promotion_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: learned-router candidate must remain non-promotable before shadow screen")
    if scorecard.get("superiority_earned") is not False:
        raise RuntimeError("FAIL_CLOSED: scorecard must not claim learned-router superiority")

    rows = shadow_matrix.get("rows")
    if not isinstance(rows, list) or not rows:
        raise RuntimeError("FAIL_CLOSED: shadow matrix must include input rows")
    case_ids = [str(row.get("case_id", "")).strip() for row in rows if isinstance(row, dict)]
    if len(case_ids) != len(set(case_ids)) or any(not case_id for case_id in case_ids):
        raise RuntimeError("FAIL_CLOSED: shadow matrix case IDs must be unique and non-empty")
    if any(row.get("no_regression_pass") is not True for row in rows if isinstance(row, dict)):
        raise RuntimeError("FAIL_CLOSED: shadow matrix rows must preserve no-regression")
    if route_health.get("canonical_static_router_preserved") is not True:
        raise RuntimeError("FAIL_CLOSED: route distribution health must preserve canonical static router")
    if route_health.get("route_collapse_detected") is not False:
        raise RuntimeError("FAIL_CLOSED: route distribution health must not detect route collapse")
    health_case_ids = {
        str(row.get("case_id", "")).strip()
        for row in route_health.get("route_quality_cost_latency_matrix", [])
        if isinstance(row, dict)
    }
    if set(case_ids) != health_case_ids:
        raise RuntimeError("FAIL_CLOSED: route health cases must match shadow matrix cases")
    if len(live_validation.get("failures", [])) != 0:
        raise RuntimeError("FAIL_CLOSED: trust-zone validation must have zero failures")


def _candidate_manifest(scorecard: Dict[str, Any]) -> Dict[str, Any]:
    candidate = dict(scorecard.get("learned_router_candidate", {}))
    candidate_id = str(candidate.get("candidate_id", "")).strip()
    status = str(candidate.get("candidate_status", "")).strip()
    no_candidate = status == "NO_ELIGIBLE_LEARNED_ROUTER_CANDIDATE_PRESENT" or not candidate_id
    return {
        "candidate_id": candidate_id,
        "candidate_status": status or "NO_ELIGIBLE_LEARNED_ROUTER_CANDIDATE_PRESENT",
        "candidate_source_ref": None,
        "candidate_source_sha256": None,
        "candidate_version": None,
        "training_lineage_or_derivation_record": None,
        "zone": "INTENDED_NOT_PROMOTED",
        "execution_role": "shadow_only_candidate_slot",
        "admissible_for_shadow_screen": not no_candidate,
        "admissibility_decision": "NOT_ADMISSIBLE" if no_candidate else "ADMISSIBLE_FOR_SHADOW_ONLY_SCREEN",
        "admissibility_reason": candidate.get(
            "eligibility_reason",
            "Current scorecard does not bind an eligible learned-router candidate.",
        ),
        "promotion_allowed": False,
    }


def _input_cases(shadow_matrix: Dict[str, Any], route_health: Dict[str, Any]) -> list[Dict[str, Any]]:
    health_by_case = {
        str(row.get("case_id", "")).strip(): row
        for row in route_health.get("route_quality_cost_latency_matrix", [])
        if isinstance(row, dict)
    }
    cases = []
    for row in shadow_matrix.get("rows", []):
        if not isinstance(row, dict):
            continue
        case_id = str(row.get("case_id", "")).strip()
        health = dict(health_by_case.get(case_id, {}))
        cases.append(
            {
                "case_id": case_id,
                "family": row.get("shadow_domain_tag") or row.get("baseline_domain_tag"),
                "baseline_domain_tag": row.get("baseline_domain_tag"),
                "shadow_domain_tag": row.get("shadow_domain_tag"),
                "baseline_adapter_ids": row.get("baseline_adapter_ids", []),
                "shadow_adapter_ids": row.get("shadow_adapter_ids", []),
                "best_static_provider_adapter_id": row.get("best_static_provider_adapter_id"),
                "fallback_engaged": row.get("fallback_engaged"),
                "no_regression_pass": row.get("no_regression_pass"),
                "route_quality_status": health.get("route_quality_status"),
                "route_quality_score": health.get("route_quality_score"),
                "mirror_variant_required": True,
                "masked_variant_required": True,
                "holdout_role": "frozen_shadow_screen_input",
            }
        )
    return sorted(cases, key=lambda row: row["case_id"])


def _evidence_refs(root: Path, reports_root: Path, governance_root: Path) -> Dict[str, Dict[str, str]]:
    rels = {
        "comparator_metric_receipt": reports_root / "b04_r6_comparator_metric_contract_receipt.json",
        "input_manifest_contract": reports_root / "b04_r6_shadow_screen_input_manifest_contract.json",
        "shadow_screen_authorization_contract": reports_root / "b04_r6_shadow_superiority_screen_authorization_contract.json",
        "comparator_matrix_contract": reports_root / "b04_r6_comparator_matrix_contract.json",
        "metric_thresholds_contract": reports_root / "b04_r6_metric_thresholds_contract.json",
        "hard_disqualifier_contract": reports_root / "b04_r6_hard_disqualifier_contract.json",
        "evidence_requirements_contract": reports_root / "b04_r6_evidence_requirements_contract.json",
        "router_superiority_scorecard": reports_root / "router_superiority_scorecard.json",
        "router_shadow_eval_matrix": reports_root / "router_shadow_eval_matrix.json",
        "route_distribution_health": reports_root / "route_distribution_health.json",
        "canonical_scope_manifest": governance_root / "canonical_scope_manifest.json",
        "trust_zone_registry": governance_root / "trust_zone_registry.json",
    }
    return {key: _sha_ref(path, root=root) for key, path in rels.items()}


def _build_payloads(
    *,
    generated_utc: str,
    head: str,
    evidence_refs: Dict[str, Dict[str, str]],
    candidate_manifest: Dict[str, Any],
    input_cases: list[Dict[str, Any]],
    comparator_matrix: Dict[str, Any],
    metric_thresholds: Dict[str, Any],
    hard_disqualifiers: Dict[str, Any],
    route_health: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:
    candidate_admissible = candidate_manifest["admissible_for_shadow_screen"] is True
    input_manifest_ready = bool(input_cases)
    screen_execution_authorized = candidate_admissible and input_manifest_ready
    verdict = SCREEN_AUTHORIZED_VERDICT if screen_execution_authorized else CANDIDATE_BLOCKED_VERDICT
    next_lawful_move = NEXT_MOVE_IF_AUTHORIZED if screen_execution_authorized else NEXT_MOVE_IF_BLOCKED
    base = _base(generated_utc=generated_utc, head=head)
    validation_checks = [
        {"check": "comparator_metric_contract_pass", "status": "PASS"},
        {"check": "input_manifest_contract_pass", "status": "PASS"},
        {"check": "comparator_rows_bound", "status": "PASS"},
        {"check": "metric_thresholds_bound", "status": "PASS"},
        {"check": "hard_disqualifiers_bound", "status": "PASS"},
        {"check": "input_case_ids_bound", "status": "PASS"},
        {"check": "route_health_static_router_preserved", "status": "PASS"},
        {"check": "candidate_admissible", "status": "PASS" if candidate_admissible else "BLOCKED"},
        {"check": "screen_execution_authorized", "status": "PASS" if screen_execution_authorized else "BLOCKED"},
    ]
    authority_packet = {
        "schema_id": "kt.operator.b04_r6_shadow_router_candidate_input_manifest_packet.v1",
        **base,
        "outcome": OUTCOME,
        "verdict": verdict,
        "screen_execution_authorized": screen_execution_authorized,
        "candidate_manifest": candidate_manifest,
        "input_manifest_ready": input_manifest_ready,
        "input_case_count": len(input_cases),
        "input_family_coverage": sorted({str(row["family"]) for row in input_cases}),
        "mirror_masked_coverage": {
            "mirror_variant_required_per_case": True,
            "masked_variant_required_per_case": True,
            "execution_must_emit_trace": True,
        },
        "holdout_boundary": {
            "frozen_case_ids": [row["case_id"] for row in input_cases],
            "case_addition_during_screen": "FORBIDDEN",
            "case_removal_during_screen": "FORBIDDEN",
            "beta_or_holdout_contamination": "HARD_STOP",
        },
        "comparator_binding_ref": OUTPUTS["comparator_binding"],
        "execution_mode": "shadow_only",
        "evidence_refs": evidence_refs,
        "allowed_next_outcomes": [
            SCREEN_AUTHORIZED_VERDICT,
            CANDIDATE_OR_INPUT_DEFECT_VERDICT,
            CANDIDATE_BLOCKED_VERDICT,
        ],
        "next_lawful_move": next_lawful_move,
    }
    receipt = {
        "schema_id": "kt.operator.b04_r6_shadow_router_candidate_input_manifest_receipt.v1",
        **base,
        "outcome": OUTCOME,
        "verdict": verdict,
        "candidate_admissible": candidate_admissible,
        "input_manifest_ready": input_manifest_ready,
        "screen_execution_authorized": screen_execution_authorized,
        "next_lawful_move": next_lawful_move,
    }
    candidate_payload = {
        "schema_id": "kt.operator.b04_r6_learned_router_candidate_manifest.v1",
        **base,
        "candidate": candidate_manifest,
        "screen_execution_authorized": screen_execution_authorized,
        "next_lawful_move": next_lawful_move,
    }
    input_payload = {
        "schema_id": "kt.operator.b04_r6_shadow_router_input_manifest_bound.v1",
        **base,
        "input_manifest_ready": input_manifest_ready,
        "input_cases": input_cases,
        "source_hashes": {
            "router_shadow_eval_matrix": evidence_refs["router_shadow_eval_matrix"],
            "route_distribution_health": evidence_refs["route_distribution_health"],
        },
        "family_coverage": sorted({str(row["family"]) for row in input_cases}),
        "fallback_case_ids": route_health.get("fallback_case_ids", []),
        "exclusion_rules": [
            "no case additions during counted shadow screen",
            "no case removals during counted shadow screen",
            "no untracked inputs",
            "no beta or holdout contamination",
            "no prep-only artifact as authority",
        ],
        "next_lawful_move": next_lawful_move,
    }
    comparator_binding = {
        "schema_id": "kt.operator.b04_r6_shadow_router_comparator_binding_receipt.v1",
        **base,
        "comparator_matrix_ref": evidence_refs["comparator_matrix_contract"],
        "metric_thresholds_ref": evidence_refs["metric_thresholds_contract"],
        "hard_disqualifier_ref": evidence_refs["hard_disqualifier_contract"],
        "comparator_rows": comparator_matrix.get("rows", []),
        "metrics": sorted(metric_thresholds.get("metrics", {}).keys()),
        "hard_disqualifiers": hard_disqualifiers.get("hard_disqualifiers", []),
        "mutation_rule": "Comparator, metric, and hard-disqualifier surfaces may not mutate during a counted shadow screen.",
        "next_lawful_move": next_lawful_move,
    }
    execution_mode = {
        "schema_id": "kt.operator.b04_r6_shadow_router_execution_mode_contract.v1",
        **base,
        "execution_mode": "shadow_only",
        "screen_execution_authorized": screen_execution_authorized,
        "activation_allowed": False,
        "package_promotion_allowed": False,
        "lobe_promotion_allowed": False,
        "product_or_commercial_claim_allowed": False,
        "next_lawful_move": next_lawful_move,
    }
    evidence_requirements = {
        "schema_id": "kt.operator.b04_r6_shadow_router_evidence_requirements_receipt.v1",
        **base,
        "required_for_future_execution": [
            "candidate/source manifest with hash",
            "bound input manifest",
            "route decision trace",
            "output scorecard",
            "no-overrouting and abstention preservation trace",
            "mirror/masked invariance trace",
            "blocker ledger on failure",
            "replayability receipt",
        ],
        "missing_before_execution": [] if screen_execution_authorized else ["admissible learned-router candidate source"],
        "next_lawful_move": next_lawful_move,
    }
    validation_matrix = {
        "schema_id": "kt.operator.b04_r6_shadow_router_candidate_input_validation_matrix.v1",
        **base,
        "checks": validation_checks,
        "failures": [] if screen_execution_authorized else [{"check": "candidate_admissible", "reason": candidate_manifest["admissibility_reason"]}],
        "next_lawful_move": next_lawful_move,
    }
    blocker_ledger = {
        "schema_id": "kt.operator.b04_r6_shadow_router_candidate_input_blocker_ledger.v1",
        **base,
        "live_blocker_count": 0 if screen_execution_authorized else 1,
        "r6_blocker_count": 0 if screen_execution_authorized else 1,
        "entries": []
        if screen_execution_authorized
        else [
            {
                "blocker_id": "B04_R6_ADMISSIBLE_LEARNED_ROUTER_CANDIDATE_NOT_BOUND",
                "status": "ACTIVE_BLOCKER",
                "resolution_path": NEXT_MOVE_IF_BLOCKED,
            }
        ],
        "next_lawful_move": next_lawful_move,
    }
    next_court = {
        "schema_id": "kt.operator.b04_r6_shadow_router_candidate_input_next_court_receipt.v1",
        **base,
        "verdict": verdict,
        "allowed_next_outcomes": [
            SCREEN_AUTHORIZED_VERDICT,
            CANDIDATE_OR_INPUT_DEFECT_VERDICT,
            CANDIDATE_BLOCKED_VERDICT,
        ],
        "screen_execution_authorized": screen_execution_authorized,
        "next_lawful_move": next_lawful_move,
    }
    prep_common = _base(generated_utc=generated_utc, head=head, status="PREP_ONLY")
    return {
        OUTPUTS["authority_packet"]: authority_packet,
        OUTPUTS["receipt"]: receipt,
        OUTPUTS["candidate_manifest"]: candidate_payload,
        OUTPUTS["input_manifest"]: input_payload,
        OUTPUTS["comparator_binding"]: comparator_binding,
        OUTPUTS["execution_mode"]: execution_mode,
        OUTPUTS["evidence_requirements"]: evidence_requirements,
        OUTPUTS["validation_matrix"]: validation_matrix,
        OUTPUTS["blocker_ledger"]: blocker_ledger,
        OUTPUTS["next_court"]: next_court,
        OUTPUTS["scorecard_schema"]: {
            "schema_id": "kt.operator.b04_r6_shadow_router_scorecard_schema.v1",
            **prep_common,
            "required_fields": [
                "status",
                "subject_head",
                "candidate_id",
                "comparator_matrix_ref",
                "metric_thresholds_ref",
                "superiority_earned",
                "hard_stop_failures",
                "r6_authorized",
            ],
            "required_false_until_later_court": ["superiority_earned", "r6_authorized"],
            "next_lawful_move": next_lawful_move,
        },
        OUTPUTS["route_trace_schema"]: {
            "schema_id": "kt.operator.b04_r6_shadow_router_route_decision_trace_schema.v1",
            **prep_common,
            "required_fields": ["case_id", "candidate_route", "static_route", "abstention_decision", "route_reason", "consequence_visibility"],
            "next_lawful_move": next_lawful_move,
        },
        OUTPUTS["invariance_trace_schema"]: {
            "schema_id": "kt.operator.b04_r6_shadow_router_mirror_masked_invariance_trace_schema.v1",
            **prep_common,
            "required_fields": ["case_id", "variant_type", "variant_hash", "route_preserved", "lawful_difference_reason"],
            "next_lawful_move": next_lawful_move,
        },
        OUTPUTS["abstention_trace_schema"]: {
            "schema_id": "kt.operator.b04_r6_shadow_router_abstention_overrouting_trace_schema.v1",
            **prep_common,
            "required_fields": ["case_id", "should_abstain", "did_abstain", "overrouting_detected", "hard_stop_triggered"],
            "next_lawful_move": next_lawful_move,
        },
        OUTPUTS["clean_state"]: {
            "schema_id": "kt.operator.b04_r6_shadow_router_candidate_input_clean_state_receipt.v1",
            **base,
            "current_git_branch": REQUIRED_BRANCH,
            "worktree_clean_at_lane_start": True,
            "next_lawful_move": next_lawful_move,
        },
    }


def run(*, reports_root: Path, governance_root: Path) -> Dict[str, Any]:
    root = repo_root()
    if common.git_current_branch_name(root) != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: must run on {REQUIRED_BRANCH}")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 candidate/input manifest run")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    if governance_root.resolve() != (root / "KT_PROD_CLEANROOM/governance").resolve():
        raise RuntimeError("FAIL_CLOSED: must read canonical governance root only")

    contract_receipt = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_comparator_metric_contract_receipt.json", label="R6 comparator metric receipt")
    input_contract = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_shadow_screen_input_manifest_contract.json", label="R6 shadow input contract")
    shadow_auth = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_shadow_superiority_screen_authorization_contract.json", label="R6 shadow authorization")
    comparator_matrix = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_comparator_matrix_contract.json", label="R6 comparator matrix")
    metric_thresholds = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_metric_thresholds_contract.json", label="R6 metric thresholds")
    hard_disqualifiers = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_hard_disqualifier_contract.json", label="R6 hard disqualifiers")
    evidence_requirements = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_evidence_requirements_contract.json", label="R6 evidence requirements")
    scorecard = _load(root, "KT_PROD_CLEANROOM/reports/router_superiority_scorecard.json", label="router superiority scorecard")
    shadow_matrix = _load(root, "KT_PROD_CLEANROOM/reports/router_shadow_eval_matrix.json", label="router shadow evaluation matrix")
    route_health = _load(root, "KT_PROD_CLEANROOM/reports/route_distribution_health.json", label="route distribution health")
    live_validation = validate_trust_zones(root=root)
    _ensure_inputs(
        contract_receipt=contract_receipt,
        input_contract=input_contract,
        shadow_auth=shadow_auth,
        comparator_matrix=comparator_matrix,
        metric_thresholds=metric_thresholds,
        hard_disqualifiers=hard_disqualifiers,
        evidence_requirements=evidence_requirements,
        scorecard=scorecard,
        shadow_matrix=shadow_matrix,
        route_health=route_health,
        live_validation=live_validation,
    )

    generated_utc = utc_now_iso_z()
    head = common.git_rev_parse(root, "HEAD")
    evidence_refs = _evidence_refs(root, reports_root.resolve(), governance_root.resolve())
    candidate_manifest = _candidate_manifest(scorecard)
    input_cases = _input_cases(shadow_matrix, route_health)
    payloads = _build_payloads(
        generated_utc=generated_utc,
        head=head,
        evidence_refs=evidence_refs,
        candidate_manifest=candidate_manifest,
        input_cases=input_cases,
        comparator_matrix=comparator_matrix,
        metric_thresholds=metric_thresholds,
        hard_disqualifiers=hard_disqualifiers,
        route_health=route_health,
    )
    for filename, payload in payloads.items():
        write_json_stable((reports_root / filename).resolve(), payload)
    receipt = payloads[OUTPUTS["receipt"]]
    return {
        "outcome": OUTCOME,
        "verdict": receipt["verdict"],
        "screen_execution_authorized": receipt["screen_execution_authorized"],
        "next_lawful_move": receipt["next_lawful_move"],
        "output_count": len(payloads),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Bind B04 R6 shadow-router candidate and input manifest.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    parser.add_argument("--governance-root", default="KT_PROD_CLEANROOM/governance")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(
        reports_root=common.resolve_path(root, args.reports_root),
        governance_root=common.resolve_path(root, args.governance_root),
    )
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
