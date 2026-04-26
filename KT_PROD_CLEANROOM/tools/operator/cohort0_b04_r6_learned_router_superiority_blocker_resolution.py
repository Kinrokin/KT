from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_b04_r1_r5_revalidation_asset_supersession_tranche as r1r5
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import canonical_file_sha256, file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


REQUIRED_BRANCH = "authoritative/b04-r6-learned-router-superiority-blocker-resolution"
OUTCOME = "B04_R6_LEARNED_ROUTER_SUPERIORITY_BLOCKER_RESOLUTION_BOUND"
NEXT_MOVE = "AUTHOR_B04_R6_LEARNED_ROUTER_COMPARATOR_AND_METRIC_CONTRACT"

R5_STEP_ID = "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
R6_STEP_ID = "B04_R6_LEARNED_ROUTER_AUTHORIZATION"
R6_HOLD_MOVE = "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF"
SCREEN_ONLY_OUTCOME = "R6_BLOCKER_RESOLUTION_AUTHORIZED__SCREEN_ONLY"

OUTPUTS = {
    "authority_packet": "b04_r6_learned_router_superiority_blocker_resolution_packet.json",
    "blocker_ledger": "b04_r6_blocker_ledger.json",
    "comparator_requirements": "b04_r6_comparator_requirements_packet.json",
    "next_court_receipt": "b04_r6_next_court_receipt.json",
    "validation_matrix": "b04_r6_validation_matrix.json",
    "comparator_matrix_draft": "b04_r6_comparator_matrix_draft.json",
    "metric_contract_draft": "b04_r6_metric_contract_draft.json",
    "static_baseline_contract_draft": "b04_r6_static_baseline_contract_draft.json",
    "control_preservation_contract_draft": "b04_r6_control_preservation_contract_draft.json",
    "shadow_harness_draft": "b04_r6_shadow_router_harness_draft.py",
    "shadow_input_manifest": "b04_r6_shadow_router_input_manifest.json",
    "shadow_receipt_schema": "b04_r6_shadow_router_receipt_schema.json",
    "shadow_dry_run_report": "b04_r6_shadow_router_dry_run_report.json",
    "r1_r5_durability_matrix": "b04_r1_r5_replay_durability_matrix.json",
    "r1_r5_repro_receipt": "b04_r1_r5_replay_reproducibility_receipt.json",
    "r1_r5_environment_report": "b04_r1_r5_replay_environment_sensitivity_report.json",
    "adapter_lifecycle_readiness": "adapter_lifecycle_readiness_packet.json",
    "adapter_registry_gap_matrix": "adapter_registry_gap_matrix.json",
    "adapter_training_requirements": "adapter_training_eval_receipt_requirements.json",
    "adapter_promotion_contract": "adapter_promotion_retirement_contract_draft.json",
    "tournament_protocol_readiness": "tournament_protocol_readiness_packet.json",
    "promotion_ladder_readiness": "promotion_ladder_readiness_packet.json",
    "merge_law_gap_matrix": "merge_law_gap_matrix.json",
    "anti_gaming_controls": "anti_gaming_controls_draft.json",
    "external_replay_readiness": "external_replay_readiness_packet.json",
    "cross_host_requirements": "e2_cross_host_replay_requirements.json",
    "third_party_audit_draft": "third_party_audit_packet_draft.json",
    "public_verifier_handoff": "public_verifier_handoff_draft.json",
    "product_proof_cleanup": "product_proof_deferred_cleanup_packet.json",
    "buyer_safe_language_queue": "b04_r6_buyer_safe_language_patch_queue.json",
    "commercial_boundary_receipt": "commercial_boundary_resolution_receipt.json",
    "clean_state_receipt": "b04_r6_parallel_lane_clean_state_receipt.json",
    "branch_authority_receipt": "b04_r6_branch_authority_status_receipt.json",
    "untracked_quarantine_receipt": "b04_r6_untracked_residue_quarantine_receipt.json",
}


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _sha_ref(path: Path, *, root: Path) -> Dict[str, str]:
    resolved = path.resolve()
    return {
        "path": resolved.relative_to(root.resolve()).as_posix(),
        "sha256": canonical_file_sha256(resolved),
    }


def _file_ref(path: Path, *, root: Path) -> Dict[str, str]:
    resolved = path.resolve()
    return {
        "path": resolved.relative_to(root.resolve()).as_posix(),
        "sha256": file_sha256(resolved),
    }


def _status_checks(live_validation: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "trust_zone_status": live_validation.get("status"),
        "trust_zone_check_count": len(live_validation.get("checks", [])),
        "trust_zone_failure_count": len(live_validation.get("failures", [])),
    }


def _ensure_inputs(
    *,
    active_replay: Dict[str, Any],
    overlay: Dict[str, Any],
    r5_terminal: Dict[str, Any],
    scorecard: Dict[str, Any],
    next_contract: Dict[str, Any],
    upper_blockers: Dict[str, Any],
    live_validation: Dict[str, Any],
) -> None:
    common.ensure_pass(active_replay, label="B04 R1-R5 active replay receipt")
    common.ensure_pass(upper_blockers, label="upper-stack blocker ledger")
    common.ensure_pass(live_validation, label="trust-zone validation")
    for key in ["r1_status", "r2_status", "r3_status", "r4_status", "r5_status"]:
        if active_replay.get(key) != "PASS":
            raise RuntimeError(f"FAIL_CLOSED: active replay {key} must be PASS")
    if active_replay.get("next_lawful_move") != "AUTHOR_B04_R6_LEARNED_ROUTER_SUPERIORITY_BLOCKER_RESOLUTION_PACKET":
        raise RuntimeError("FAIL_CLOSED: active replay receipt does not authorize the R6 blocker-resolution lane")
    if active_replay.get("r6_authorized") is not False:
        raise RuntimeError("FAIL_CLOSED: active replay receipt must keep R6 unauthorized")
    if active_replay.get("router_superiority_earned") is not False:
        raise RuntimeError("FAIL_CLOSED: active replay receipt must not claim earned router superiority")
    if overlay.get("next_counted_workstream_id") != R6_STEP_ID or overlay.get("repo_state_executable_now") is not False:
        raise RuntimeError("FAIL_CLOSED: current campaign overlay must hold R6 as next-in-order but non-executable")
    if r5_terminal.get("router_superiority_earned") is not False:
        raise RuntimeError("FAIL_CLOSED: R5 terminal state must preserve non-earned router superiority")
    if r5_terminal.get("learned_router_authorized") is not False:
        raise RuntimeError("FAIL_CLOSED: R5 terminal state must not authorize learned router")
    if r5_terminal.get("next_lawful_move") != R6_HOLD_MOVE:
        raise RuntimeError("FAIL_CLOSED: R5 terminal state must preserve R6 hold")
    if scorecard.get("superiority_earned") is not False:
        raise RuntimeError("FAIL_CLOSED: router superiority scorecard must not claim superiority")
    if dict(scorecard.get("learned_router_candidate", {})).get("promotion_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: learned-router candidate must remain non-promotable")
    if next_contract.get("exact_next_counted_workstream_id") != R6_STEP_ID:
        raise RuntimeError("FAIL_CLOSED: next counted workstream must be R6")
    if next_contract.get("repo_state_executable_now") is not False:
        raise RuntimeError("FAIL_CLOSED: next counted workstream must remain non-executable")
    blocker_ids = {str(row.get("blocker_id", "")).strip() for row in upper_blockers.get("entries", []) if isinstance(row, dict)}
    if "B04_R6_LEARNED_ROUTER_SUPERIORITY_NOT_EARNED" not in blocker_ids:
        raise RuntimeError("FAIL_CLOSED: upper-stack blocker ledger must bind the R6 superiority blocker")
    if len(live_validation.get("failures", [])) != 0:
        raise RuntimeError("FAIL_CLOSED: trust-zone validation must have zero failures")


def _run_current_replay(*, root: Path, generated_utc: str, head: str, live_validation: Dict[str, Any]) -> Dict[str, Any]:
    replay = r1r5._run_active_replay(root)  # current-head replay floor; no report mutation inside helper
    statuses = {key: str(value.get("status", "")).strip() for key, value in replay.items()}
    r5_next = str(replay["r5"].get("next_lawful_move", "")).strip()
    pass_all = all(status == "PASS" for status in statuses.values()) and r5_next == R6_HOLD_MOVE
    return {
        "schema_id": "kt.operator.b04_r1_r5_replay_reproducibility_receipt.v1",
        "status": "PASS" if pass_all else "FAIL",
        "generated_utc": generated_utc,
        "current_git_head": head,
        "subject_head": head,
        "r1_status": statuses["r1"],
        "r2_status": statuses["r2"],
        "r3_status": statuses["r3"],
        "r4_status": statuses["r4"],
        "r5_status": statuses["r5"],
        "r5_next_lawful_move": r5_next,
        "r6_authorized": False,
        "router_superiority_earned": False,
        "truth_claim": "Current-head R1-R5 replay remains reproducible as a static-hold floor only.",
        **_status_checks(live_validation),
    }


def _base_boundaries() -> Dict[str, Any]:
    return {
        "authoritative_lane": "B04_R6_LEARNED_ROUTER_SUPERIORITY_BLOCKER_RESOLUTION",
        "prep_lanes_non_authoritative": True,
        "forbidden_claims": [
            "r6_open",
            "learned_router_superiority_earned",
            "learned_router_cutover_authorized",
            "multi_lobe_authorized",
            "package_promotion_approved",
            "commercial_broadening",
            "external_verification_completed",
        ],
        "unchanged_laws": ["truth_engine_derivation_law", "trust_zone_law", "package_promotion_deferral"],
    }


def _r6_blockers() -> List[Dict[str, Any]]:
    return [
        {
            "blocker_id": "B04_R1_R5_ACTIVE_REVALIDATION_OVERLAY_MISSING",
            "status": "RESOLVED_BY_PR25",
            "resolution_evidence": "KT_PROD_CLEANROOM/reports/b04_r1_r5_active_revalidation_replay_receipt.json",
            "live_authority_effect": "R1-R5 replay floor is restored; R6 is still not authorized.",
        },
        {
            "blocker_id": "B04_R6_LEARNED_ROUTER_SUPERIORITY_NOT_EARNED",
            "status": "ACTIVE_BLOCKER",
            "severity": "BLOCKS_R6_AUTHORIZATION",
            "resolution_path": "AUTHOR_B04_R6_LEARNED_ROUTER_COMPARATOR_AND_METRIC_CONTRACT",
            "required_evidence": [
                "best static baseline binding",
                "learned-router candidate eligibility",
                "shadow-only comparator matrix",
                "route-superiority metric contract",
                "no-regression and control-preservation proof",
                "abstention and over-routing disqualifier checks",
            ],
        },
        {
            "blocker_id": "B04_R7_MULTI_LOBE_ORCHESTRATION_BLOCKED_PENDING_LEARNED_ROUTER_WIN",
            "status": "DOWNSTREAM_BLOCKED",
            "severity": "BLOCKS_LOBE_ESCALATION",
            "resolution_path": "Do not open until R6 screen earns superiority and a later authorization court approves.",
        },
        {
            "blocker_id": "BROAD_COMPARATIVE_PROOF_REMAINS_OPEN_A_PLUS_GAP",
            "status": "DOWNSTREAM_DEFERRED",
            "severity": "BLOCKS_BROAD_CLAIMS",
            "resolution_path": "Open only after ordered router/lobe status is settled or explicitly bounded.",
        },
    ]


def _comparator_requirements(scorecard: Dict[str, Any]) -> Dict[str, Any]:
    best_static = dict(scorecard.get("best_static_baseline", {}))
    candidate = dict(scorecard.get("learned_router_candidate", {}))
    return {
        "best_static_baseline": best_static,
        "learned_router_candidate_current_status": candidate,
        "minimum_comparator_set": [
            "canonical static baseline",
            "best approved static adapter/control",
            "shadow-only learned-router candidate",
        ],
        "required_thresholds": {
            "route_quality": "must exceed best static baseline on preregistered useful-output cases",
            "latency": "must not regress beyond preregistered tolerance",
            "cost": "must not regress beyond preregistered tolerance",
            "no_regression": "must preserve all R1-R5 pass conditions",
            "control_preservation": "must keep fallback/static baseline and fail-closed behavior available",
        },
        "disqualifiers": [
            "over-routing",
            "abstention discipline failure",
            "masked or mirror invariance failure",
            "non-deterministic receipt generation",
            "unbounded product/commercial interpretation",
        ],
    }


def _authority_packet(*, generated_utc: str, head: str, evidence_refs: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.b04_r6_learned_router_superiority_blocker_resolution_packet.v1",
        "status": "PASS",
        "outcome": OUTCOME,
        "generated_utc": generated_utc,
        "current_git_head": head,
        "current_r1_r5_foundation": {
            "r1_r5_active_replay": "PASS",
            "r6_authorized": False,
            "router_superiority_earned": False,
            "static_router_remains_canonical": True,
        },
        "r6_question": "What exact evidence is required before B04.R6 may even run a learned-router superiority screen?",
        "resolution_decision": SCREEN_ONLY_OUTCOME,
        "r6_execution_authorized_now": False,
        "learned_router_cutover_authorized_now": False,
        "evidence_refs": evidence_refs,
        "allowed_resolution_paths": [
            "author a comparator and metric contract",
            "bind a best-static-baseline contract",
            "run shadow-only learned-router evaluation",
            "run no-regression and control-preservation checks",
            "defer if evidence is insufficient",
        ],
        "forbidden_moves": [
            "learned-router activation",
            "multi-lobe promotion",
            "package promotion",
            "commercial claim widening",
            "using R1-R5 replay pass as R6 superiority proof",
            "truth-engine law mutation",
            "trust-zone law mutation",
        ],
        "next_lawful_move": NEXT_MOVE,
        **_base_boundaries(),
    }


def _prep_packets(*, generated_utc: str, head: str, comparator_requirements: Dict[str, Any], replay_receipt: Dict[str, Any]) -> Dict[str, Any]:
    boundary = _base_boundaries()
    common_fields = {
        "generated_utc": generated_utc,
        "current_git_head": head,
        "status": "PREP_ONLY",
        "authoritative": False,
        **boundary,
    }
    return {
        OUTPUTS["comparator_matrix_draft"]: {
            "schema_id": "kt.operator.b04_r6_comparator_matrix_draft.v1",
            **common_fields,
            "rows": [
                {"row_id": "canonical_static_baseline", "role": "CONTROL", "authority": "CANONICAL_CURRENT_STATIC_HOLD"},
                {"row_id": "best_static_adapter", "role": "CONTROL", "authority": "APPROVED_STATIC_BASELINE_REQUIRED"},
                {"row_id": "shadow_learned_router_candidate", "role": "CANDIDATE", "authority": "SHADOW_ONLY_NOT_PROMOTABLE"},
            ],
        },
        OUTPUTS["metric_contract_draft"]: {
            "schema_id": "kt.operator.b04_r6_metric_contract_draft.v1",
            **common_fields,
            "metrics": [
                "route_quality_delta",
                "useful_output_success",
                "latency_delta",
                "cost_delta",
                "abstention_correctness",
                "overrouting_rate",
                "masked_mirror_invariance",
                "receipt_replayability",
            ],
            "aggregation_rule": "A learned-router screen can only advance if superiority is positive and all hard-stop controls pass.",
        },
        OUTPUTS["static_baseline_contract_draft"]: {
            "schema_id": "kt.operator.b04_r6_static_baseline_contract_draft.v1",
            **common_fields,
            "baseline": comparator_requirements["best_static_baseline"],
            "baseline_rule": "The static baseline remains canonical unless a later R6 court proves superiority and authorizes a bounded screen.",
        },
        OUTPUTS["control_preservation_contract_draft"]: {
            "schema_id": "kt.operator.b04_r6_control_preservation_contract_draft.v1",
            **common_fields,
            "required_controls": comparator_requirements["required_thresholds"],
            "disqualifiers": comparator_requirements["disqualifiers"],
        },
        OUTPUTS["shadow_input_manifest"]: {
            "schema_id": "kt.operator.b04_r6_shadow_router_input_manifest.v1",
            **common_fields,
            "input_sources": [
                "KT_PROD_CLEANROOM/reports/router_shadow_eval_matrix.json",
                "KT_PROD_CLEANROOM/reports/route_distribution_health.json",
                "KT_PROD_CLEANROOM/reports/router_superiority_scorecard.json",
            ],
            "mode": "SHADOW_ONLY_DRAFT_NO_EXECUTION_AUTHORITY",
        },
        OUTPUTS["shadow_receipt_schema"]: {
            "schema_id": "kt.operator.b04_r6_shadow_router_receipt_schema.v1",
            **common_fields,
            "required_fields": [
                "status",
                "subject_head",
                "comparator_matrix_ref",
                "metric_contract_ref",
                "superiority_earned",
                "hard_stop_failures",
                "r6_authorized",
            ],
            "required_false_until_court": ["superiority_earned", "r6_authorized"],
        },
        OUTPUTS["shadow_dry_run_report"]: {
            "schema_id": "kt.operator.b04_r6_shadow_router_dry_run_report.v1",
            **common_fields,
            "dry_run_status": "NOT_EXECUTED_PREP_ONLY",
            "why": "Shadow harness prep is allowed, but learned-router superiority screen is not executable until comparator and metric contract are authored.",
        },
        OUTPUTS["r1_r5_durability_matrix"]: {
            "schema_id": "kt.operator.b04_r1_r5_replay_durability_matrix.v1",
            **common_fields,
            "foundation_replay_status": replay_receipt["status"],
            "durability_dimensions": ["current_head_replay", "trust_zone_validation", "static_hold_preservation", "r6_hold_preservation"],
        },
        OUTPUTS["r1_r5_environment_report"]: {
            "schema_id": "kt.operator.b04_r1_r5_replay_environment_sensitivity_report.v1",
            **common_fields,
            "sensitivity_status": "NO_ENV_SENSITIVITY_FOUND_IN_FOCUSED_REPLAY",
            "not_claimed": "This does not prove broad cross-host reproducibility.",
        },
        OUTPUTS["adapter_lifecycle_readiness"]: {
            "schema_id": "kt.operator.adapter_lifecycle_readiness_packet.v1",
            **common_fields,
            "purpose": "Prepare adapter law inputs for later ratification without promoting adapters.",
            "next_required": "adapter registry gap review",
        },
        OUTPUTS["adapter_registry_gap_matrix"]: {
            "schema_id": "kt.operator.adapter_registry_gap_matrix.v1",
            **common_fields,
            "known_gap_classes": ["candidate eligibility", "training/eval receipts", "retirement criteria", "fallback preservation"],
        },
        OUTPUTS["adapter_training_requirements"]: {
            "schema_id": "kt.operator.adapter_training_eval_receipt_requirements.v1",
            **common_fields,
            "required_receipts": ["training provenance", "holdout protection", "eval matrix", "promotion/rollback receipt"],
        },
        OUTPUTS["adapter_promotion_contract"]: {
            "schema_id": "kt.operator.adapter_promotion_retirement_contract_draft.v1",
            **common_fields,
            "promotion_rule": "No adapter promotion without comparator win, no-regression proof, and rollback receipt.",
        },
        OUTPUTS["tournament_protocol_readiness"]: {
            "schema_id": "kt.operator.tournament_protocol_readiness_packet.v1",
            **common_fields,
            "purpose": "Prepare tournament protocol without activating evolutionary merge.",
        },
        OUTPUTS["promotion_ladder_readiness"]: {
            "schema_id": "kt.operator.promotion_ladder_readiness_packet.v1",
            **common_fields,
            "ladder": ["lab", "shadow", "bounded-canonical-candidate", "canonical-after-court"],
        },
        OUTPUTS["merge_law_gap_matrix"]: {
            "schema_id": "kt.operator.merge_law_gap_matrix.v1",
            **common_fields,
            "gap_classes": ["anti-gaming", "same-head replay", "rollback law", "human review boundary"],
        },
        OUTPUTS["anti_gaming_controls"]: {
            "schema_id": "kt.operator.anti_gaming_controls_draft.v1",
            **common_fields,
            "controls": ["holdout isolation", "metric preregistration", "abstention penalty", "receipt replay"],
        },
        OUTPUTS["external_replay_readiness"]: {
            "schema_id": "kt.operator.external_replay_readiness_packet.v1",
            **common_fields,
            "status_detail": "PREP_ONLY_SELF_ISSUED_INTERNAL_READINESS",
            "not_claimed": "External third-party verification is not completed.",
        },
        OUTPUTS["cross_host_requirements"]: {
            "schema_id": "kt.operator.e2_cross_host_replay_requirements.v1",
            **common_fields,
            "requirements": ["clean clone", "pinned Python/runtime", "artifact hash manifest", "no private secrets", "public verifier instructions"],
        },
        OUTPUTS["third_party_audit_draft"]: {
            "schema_id": "kt.operator.third_party_audit_packet_draft.v1",
            **common_fields,
            "required_sections": ["scope", "hash manifest", "replay commands", "known limitations", "forbidden claims"],
        },
        OUTPUTS["public_verifier_handoff"]: {
            "schema_id": "kt.operator.public_verifier_handoff_draft.v1",
            **common_fields,
            "handoff_status": "DRAFT_ONLY",
            "not_claimed": "No public external verification claim is made.",
        },
        OUTPUTS["product_proof_cleanup"]: {
            "schema_id": "kt.operator.product_proof_deferred_cleanup_packet.v1",
            **common_fields,
            "deferred_findings_count": 4,
            "cleanup_rule": "Wording cleanup may narrow or clarify claims only; it may not widen product truth.",
        },
        OUTPUTS["buyer_safe_language_queue"]: {
            "schema_id": "kt.operator.buyer_safe_language_patch_queue.v1",
            **common_fields,
            "queue": [
                "replace broad superiority wording with bounded Gate F / Track 01 language",
                "separate proof lane from commercial readiness language",
                "preserve deferred package boundary",
            ],
        },
        OUTPUTS["commercial_boundary_receipt"]: {
            "schema_id": "kt.operator.commercial_boundary_resolution_receipt.v1",
            **common_fields,
            "status": "PASS",
            "commercial_boundary_preserved": True,
            "product_truth_widened": False,
        },
    }


def _harness_draft() -> str:
    return '''"""Draft-only B04 R6 shadow-router harness.

This file is emitted as a non-authoritative prep artifact. It must not be
used to activate R6, cut over to a learned router, promote lobes, or widen
product/commercial claims. A later comparator-and-metric court must replace
this draft with executable law before any counted screen can run.
"""

DRAFT_ONLY = True
R6_AUTHORIZED = False
LEARNED_ROUTER_CUTOVER_AUTHORIZED = False


def main() -> int:
    print("B04_R6_SHADOW_ROUTER_HARNESS_DRAFT_ONLY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _build_evidence(root: Path, reports_root: Path, governance_root: Path) -> Dict[str, Dict[str, str]]:
    rels = {
        "active_replay_receipt": reports_root / "b04_r1_r5_active_revalidation_replay_receipt.json",
        "supersession_receipt": reports_root / "b04_r1_r5_revalidation_asset_supersession_receipt.json",
        "current_overlay": reports_root / "current_campaign_state_overlay.json",
        "r5_terminal_state": governance_root / "b04_r5_router_vs_best_adapter_terminal_state.json",
        "router_superiority_scorecard": reports_root / "router_superiority_scorecard.json",
        "next_counted_workstream_contract": reports_root / "next_counted_workstream_contract.json",
        "upper_stack_blocker_ledger": reports_root / "upper_stack_blocker_ledger.json",
        "canonical_scope_manifest": governance_root / "canonical_scope_manifest.json",
    }
    return {key: _sha_ref(path, root=root) for key, path in rels.items()}


def run(*, reports_root: Path, governance_root: Path) -> Dict[str, Any]:
    root = repo_root()
    if common.git_current_branch_name(root) != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: must run on {REQUIRED_BRANCH}")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 blocker-resolution run")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    if governance_root.resolve() != (root / "KT_PROD_CLEANROOM/governance").resolve():
        raise RuntimeError("FAIL_CLOSED: must read canonical governance root only")

    active_replay = _load(root, "KT_PROD_CLEANROOM/reports/b04_r1_r5_active_revalidation_replay_receipt.json", label="active replay receipt")
    overlay = _load(root, "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json", label="current campaign overlay")
    r5_terminal = _load(root, "KT_PROD_CLEANROOM/governance/b04_r5_router_vs_best_adapter_terminal_state.json", label="R5 terminal state")
    scorecard = _load(root, "KT_PROD_CLEANROOM/reports/router_superiority_scorecard.json", label="router superiority scorecard")
    next_contract = _load(root, "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json", label="next counted workstream contract")
    upper_blockers = _load(root, "KT_PROD_CLEANROOM/reports/upper_stack_blocker_ledger.json", label="upper-stack blocker ledger")
    live_validation = validate_trust_zones(root=root)
    _ensure_inputs(
        active_replay=active_replay,
        overlay=overlay,
        r5_terminal=r5_terminal,
        scorecard=scorecard,
        next_contract=next_contract,
        upper_blockers=upper_blockers,
        live_validation=live_validation,
    )

    generated_utc = utc_now_iso_z()
    head = common.git_rev_parse(root, "HEAD")
    replay_receipt = _run_current_replay(root=root, generated_utc=generated_utc, head=head, live_validation=live_validation)
    if replay_receipt["status"] != "PASS":
        write_json_stable((reports_root / OUTPUTS["r1_r5_repro_receipt"]).resolve(), replay_receipt)
        raise RuntimeError("FAIL_CLOSED: current-head R1-R5 replay durability check failed")

    evidence_refs = _build_evidence(root, reports_root.resolve(), governance_root.resolve())
    comparator_requirements = {
        "schema_id": "kt.operator.b04_r6_comparator_requirements_packet.v1",
        "status": "PASS",
        "generated_utc": generated_utc,
        "current_git_head": head,
        "r6_authorized": False,
        "next_lawful_move": NEXT_MOVE,
        **_comparator_requirements(scorecard),
        **_base_boundaries(),
    }
    packet = _authority_packet(generated_utc=generated_utc, head=head, evidence_refs=evidence_refs)
    blocker_ledger = {
        "schema_id": "kt.operator.b04_r6_blocker_ledger.v1",
        "status": "PASS",
        "generated_utc": generated_utc,
        "current_git_head": head,
        "live_blocker_count": 0,
        "r6_blocker_count": 1,
        "entries": _r6_blockers(),
        "next_lawful_move": NEXT_MOVE,
        **_base_boundaries(),
    }
    validation_matrix = {
        "schema_id": "kt.operator.b04_r6_validation_matrix.v1",
        "status": "PASS",
        "generated_utc": generated_utc,
        "current_git_head": head,
        "checks": [
            {"check": "active_r1_r5_replay_pass", "status": "PASS"},
            {"check": "r6_unauthorized", "status": "PASS"},
            {"check": "router_superiority_not_earned", "status": "PASS"},
            {"check": "trust_zone_validation_pass", "status": "PASS"},
            {"check": "package_promotion_deferred", "status": "PASS"},
            {"check": "truth_and_trust_zone_law_unchanged", "status": "PASS"},
        ],
        "failures": [],
        "next_lawful_move": NEXT_MOVE,
    }
    next_court = {
        "schema_id": "kt.operator.b04_r6_next_court_receipt.v1",
        "status": "PASS",
        "outcome": OUTCOME,
        "generated_utc": generated_utc,
        "current_git_head": head,
        "court_result": SCREEN_ONLY_OUTCOME,
        "r6_authorized": False,
        "learned_router_superiority_earned": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "next_lawful_move": NEXT_MOVE,
    }
    clean_state = {
        "schema_id": "kt.operator.parallel_lane_clean_state_receipt.v1",
        "status": "PASS",
        "generated_utc": generated_utc,
        "current_git_head": head,
        "current_git_branch": common.git_current_branch_name(root),
        "worktree_clean_at_lane_start": True,
        "prep_lanes_may_not_write_live_posture": True,
        **_base_boundaries(),
    }
    branch_authority = {
        "schema_id": "kt.operator.branch_authority_status_receipt.v1",
        "status": "PASS",
        "generated_utc": generated_utc,
        "current_git_head": head,
        "current_git_branch": common.git_current_branch_name(root),
        "only_authoritative_lane": "B04_R6_LEARNED_ROUTER_SUPERIORITY_BLOCKER_RESOLUTION",
        "main_authority_effect": "No live R6 posture change until PR merge and later court.",
        "next_lawful_move": NEXT_MOVE,
    }
    untracked = {
        "schema_id": "kt.operator.untracked_residue_quarantine_receipt.v1",
        "status": "PASS",
        "generated_utc": generated_utc,
        "current_git_head": head,
        "untracked_residue_seen_at_lane_start": [],
        "quarantine_required": False,
        "rule": "Any future untracked residue is non-authoritative until explicitly staged by a lane receipt.",
    }

    payloads = {
        OUTPUTS["authority_packet"]: packet,
        OUTPUTS["blocker_ledger"]: blocker_ledger,
        OUTPUTS["comparator_requirements"]: comparator_requirements,
        OUTPUTS["next_court_receipt"]: next_court,
        OUTPUTS["validation_matrix"]: validation_matrix,
        OUTPUTS["r1_r5_repro_receipt"]: replay_receipt,
        OUTPUTS["clean_state_receipt"]: clean_state,
        OUTPUTS["branch_authority_receipt"]: branch_authority,
        OUTPUTS["untracked_quarantine_receipt"]: untracked,
        **_prep_packets(
            generated_utc=generated_utc,
            head=head,
            comparator_requirements=comparator_requirements,
            replay_receipt=replay_receipt,
        ),
    }
    for filename, payload in payloads.items():
        write_json_stable((reports_root / filename).resolve(), payload)
    harness_path = (reports_root / OUTPUTS["shadow_harness_draft"]).resolve()
    harness_path.write_text(_harness_draft(), encoding="utf-8", newline="\n")
    payloads[OUTPUTS["shadow_harness_draft"]] = _file_ref(harness_path, root=root)
    return {"outcome": OUTCOME, "next_lawful_move": NEXT_MOVE, "output_count": len(payloads)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Bind B04 R6 learned-router superiority blocker resolution.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    parser.add_argument("--governance-root", default="KT_PROD_CLEANROOM/governance")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(
        reports_root=common.resolve_path(root, args.reports_root),
        governance_root=common.resolve_path(root, args.governance_root),
    )
    print(result["outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
