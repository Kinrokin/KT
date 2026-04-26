from __future__ import annotations

import argparse
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import adapter_lifecycle_law_validate as r2
from tools.operator import cohort0_gate_f_common as common
from tools.operator import crucible_pressure_law_validate as r1
from tools.operator import router_ordered_proof_validate as ordered
from tools.operator import router_shadow_evaluation_ratification_validate as r4
from tools.operator import router_vs_best_adapter_proof_ratification_validate as r5
from tools.operator import tournament_promotion_merge_law_validate as r3
from tools.operator.titanium_common import canonical_file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


REQUIRED_BRANCH = "authoritative/b04-r1-r5-revalidation-asset-supersession"
OUTCOME = "B04_R1_R5_REVALIDATION_ASSET_SUPERSESSION_BOUND"
NEXT_MOVE = "AUTHOR_B04_R6_LEARNED_ROUTER_SUPERIORITY_BLOCKER_RESOLUTION_PACKET"

CURRENT_OVERLAY = "current_campaign_state_overlay.json"
OUTPUT_PACKET = "b04_r1_r5_revalidation_asset_supersession_packet.json"
OUTPUT_RECEIPT = "b04_r1_r5_revalidation_asset_supersession_receipt.json"
OUTPUT_REPLAY_RECEIPT = "b04_r1_r5_active_revalidation_replay_receipt.json"

R5_STEP_ID = "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
R6_STEP_ID = "B04_R6_LEARNED_ROUTER_AUTHORIZATION"
R6_HOLD_MOVE = "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF"


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _sha_ref(path: Path, *, root: Path) -> Dict[str, str]:
    resolved = path.resolve()
    return {
        "path": resolved.relative_to(root.resolve()).as_posix(),
        "sha256": canonical_file_sha256(resolved),
    }


def _ensure_pass(payload: Dict[str, Any], *, label: str) -> None:
    common.ensure_pass(payload, label=label)


def _ensure_authorized(
    *,
    upper_receipt: Dict[str, Any],
    upper_blockers: Dict[str, Any],
    readiness_recommendation: Dict[str, Any],
    next_contract: Dict[str, Any],
    resume: Dict[str, Any],
    reanchor: Dict[str, Any],
    scorecard: Dict[str, Any],
    live_validation: Dict[str, Any],
) -> None:
    _ensure_pass(upper_receipt, label="upper-stack readiness receipt")
    _ensure_pass(upper_blockers, label="upper-stack blocker ledger")
    _ensure_pass(readiness_recommendation, label="upper-stack next recommendation")
    _ensure_pass(live_validation, label="trust-zone validation")
    if upper_receipt.get("next_lawful_move") != "AUTHOR_B04_R1_R5_REVALIDATION_ASSET_SUPERSESSION_PACKET":
        raise RuntimeError("FAIL_CLOSED: upper-stack readiness does not authorize R1-R5 supersession")
    if upper_receipt.get("r1_through_r5_active_revalidation_replay_status") != "BLOCKED_MISSING_CURRENT_CAMPAIGN_STATE_OVERLAY":
        raise RuntimeError("FAIL_CLOSED: supersession lane requires the missing-overlay replay blocker")
    blocker_ids = {str(row.get("blocker_id", "")).strip() for row in upper_blockers.get("entries", []) if isinstance(row, dict)}
    if "B04_R1_R5_ACTIVE_REVALIDATION_OVERLAY_MISSING" not in blocker_ids:
        raise RuntimeError("FAIL_CLOSED: missing overlay blocker is not bound in upper-stack ledger")
    if int(upper_blockers.get("live_blocker_count", -1)) != 0:
        raise RuntimeError("FAIL_CLOSED: supersession lane requires zero live blockers")
    if next_contract.get("exact_next_counted_workstream_id") != R6_STEP_ID:
        raise RuntimeError("FAIL_CLOSED: current next contract must hold R6 as next in order")
    if next_contract.get("source_workstream_id") != R5_STEP_ID or next_contract.get("repo_state_executable_now") is not False:
        raise RuntimeError("FAIL_CLOSED: current next contract must be settled R5 static-hold context")
    if resume.get("workstream_id") != R5_STEP_ID or resume.get("exact_next_counted_workstream_id") != R6_STEP_ID:
        raise RuntimeError("FAIL_CLOSED: resume blockers must be settled R5/R6 hold context")
    if resume.get("repo_state_executable_now") is not False:
        raise RuntimeError("FAIL_CLOSED: R6 must remain non-executable")
    if reanchor.get("workstream_id") != R5_STEP_ID or reanchor.get("next_lawful_move") != R6_HOLD_MOVE:
        raise RuntimeError("FAIL_CLOSED: reanchor packet must preserve R6 hold")
    if scorecard.get("superiority_earned") is not False:
        raise RuntimeError("FAIL_CLOSED: supersession may not proceed if router superiority is already earned")
    if len(live_validation.get("failures", [])) != 0:
        raise RuntimeError("FAIL_CLOSED: trust-zone validation has failures")


def _authority_stack() -> Dict[str, List[str]]:
    receipt_refs = [
        "KT_PROD_CLEANROOM/reports/crucible_pressure_law_ratification_receipt.json",
        "KT_PROD_CLEANROOM/reports/adapter_lifecycle_law_ratification_receipt.json",
        "KT_PROD_CLEANROOM/reports/tournament_promotion_merge_law_ratification_receipt.json",
        "KT_PROD_CLEANROOM/reports/router_shadow_evaluation_ratification_receipt.json",
        "KT_PROD_CLEANROOM/reports/router_vs_best_adapter_proof_ratification_receipt.json",
    ]
    return {
        "current_state_authority": [
            f"b04_r{idx}_authoritative_receipt_{ref}"
            for idx, ref in enumerate(receipt_refs, start=1)
        ],
        "documentary_surfaces": [
            "KT_PROD_CLEANROOM/reports/upper_stack_ratification_readiness_receipt.json",
            "KT_PROD_CLEANROOM/reports/upper_stack_blocker_ledger.json",
            "KT_PROD_CLEANROOM/reports/router_ordered_proof_receipt.json",
            "KT_PROD_CLEANROOM/reports/router_superiority_scorecard.json",
            "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_authority_graph.json",
            "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_posture_index.json",
        ],
    }


def _build_overlay(*, root: Path, head: str, generated_utc: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.current_campaign_state_overlay.v1",
        "classification_tag": "COUNTING_CLOSURE",
        "generated_utc": generated_utc,
        "asset_role": "DERIVED_CURRENT_TRUTH_REVALIDATION_CONTROL_SURFACE",
        "supersession_class": "MATERIALIZED_FROM_CURRENT_TRUTH_ENGINE_AND_B04_STATIC_HOLD",
        "workstream_id": R5_STEP_ID,
        "repo_state": {
            "repo_root": str((root / "KT_PROD_CLEANROOM").resolve()).replace("\\", "/"),
            "current_git_branch": common.git_current_branch_name(root),
            "current_git_head": head,
            "worktree_cleanliness": "CLEAN_CURRENT_HEAD_AT_REVALIDATION_ASSET_SUPERSESSION_START",
        },
        "authority_stack": _authority_stack(),
        "current_lawful_gate_standing": {
            "inter_gate_state": "GATE_D_R5_ROUTER_PROOF_RATIFIED_STATIC_HOLD__R6_BLOCKED",
            "current_counted_gate": "Gate D",
            "current_counted_batch": R5_STEP_ID,
            "gate_c_status": "EXITED",
            "gate_d_status": "ROUTER_VS_BEST_ADAPTER_PROOF_RATIFIED_STATIC_HOLD__R6_NEXT_IN_ORDER_BLOCKED",
            "authoritative_basis": [
                "R1-R5 receipt chain is PASS.",
                "B04.R5 same-head router-versus-best-adapter proof held static canonical baseline.",
                "R6 is next in order only and blocked pending earned router superiority.",
                "This overlay is an active replay control surface derived from current canonical truth; it is not broad router/lobe authorization.",
            ],
        },
        "state_reconciliation": {
            "latest_sealed_receipts_current_state": "Gate D is settled at R5 static hold; R6 remains blocked pending earned superiority.",
            "supersession_decision": "Do not resurrect a stale historical overlay. Materialize this current overlay from truth-engine and B04 static-hold surfaces.",
            "reanchor_decision": "Allow active R1-R5 replay against settled current truth while preserving R6 hold.",
        },
        "next_counted_workstream_id": R6_STEP_ID,
        "next_counted_workstream_scope": "R6 remains next in order only. It is not executable until router superiority is earned in a lawful future proof.",
        "repo_state_executable_now": False,
        "executable_now_why": "B04.R5 is complete but router superiority was not earned; R6/lobes/commercial/comparative widening remain blocked.",
        "forbidden_inferences": [
            "learned_router_authorized",
            "multi_lobe_orchestration_authorized",
            "broad_comparative_superiority",
            "package_promotion",
            "commercial_activation",
        ],
    }


def _build_evidence(root: Path, reports_root: Path, governance_root: Path) -> Dict[str, Dict[str, str]]:
    rels = {
        "upper_stack_readiness_receipt": reports_root / "upper_stack_ratification_readiness_receipt.json",
        "upper_stack_blocker_ledger": reports_root / "upper_stack_blocker_ledger.json",
        "truth_engine_authority_graph": reports_root / "cohort0_post_f_truth_engine_authority_graph.json",
        "truth_engine_posture_index": reports_root / "cohort0_post_f_truth_engine_posture_index.json",
        "post_boundary_regrade_receipt": reports_root / "post_boundary_canonical_regrade_audit_receipt.json",
        "r1_receipt": reports_root / "crucible_pressure_law_ratification_receipt.json",
        "r2_receipt": reports_root / "adapter_lifecycle_law_ratification_receipt.json",
        "r3_receipt": reports_root / "tournament_promotion_merge_law_ratification_receipt.json",
        "r4_receipt": reports_root / "router_shadow_evaluation_ratification_receipt.json",
        "r5_receipt": reports_root / "router_vs_best_adapter_proof_ratification_receipt.json",
        "router_superiority_scorecard": reports_root / "router_superiority_scorecard.json",
        "next_counted_workstream_contract": reports_root / "next_counted_workstream_contract.json",
        "resume_blockers_receipt": reports_root / "resume_blockers_receipt.json",
        "gate_d_reanchor_packet": reports_root / "gate_d_decision_reanchor_packet.json",
        "canonical_scope_manifest": governance_root / "canonical_scope_manifest.json",
        "readiness_scope_manifest": governance_root / "readiness_scope_manifest.json",
    }
    return {key: _sha_ref(path, root=root) for key, path in rels.items()}


def _run_active_replay(root: Path) -> Dict[str, Dict[str, Any]]:
    r1_receipt = r1.build_crucible_pressure_law_receipt(root=root)
    r2_receipt = r2.build_adapter_lifecycle_law_receipt(root=root)
    r3_receipt = r3.build_tournament_promotion_merge_law_receipt(root=root)
    telemetry_path = Path(tempfile.gettempdir()) / "kt_b04_r1_r5_active_revalidation_telemetry.jsonl"
    if telemetry_path.exists():
        telemetry_path.unlink()
    r4_reports = r4.build_wave2b_shadow_reports(root=root, telemetry_path=telemetry_path)
    r4_receipt = r4.build_router_shadow_evaluation_ratification_receipt(
        root=root,
        selection_report=r4_reports["selection_report"],
        matrix_report=r4_reports["matrix_report"],
        health_report=r4_reports["health_report"],
    )
    base = {
        "selection": r4_reports["selection_report"],
        "matrix": r4_reports["matrix_report"],
        "health": r4_reports["health_report"],
        "c005": _load(
            root,
            "KT_PROD_CLEANROOM/reports/post_wave5_c005_router_ratification_receipt.json",
            label="post-wave5 c005 router ratification receipt",
        ),
    }
    shadow_matrix = ordered.build_router_shadow_eval_matrix(root=root, base=base)
    health_report = ordered.build_route_distribution_health(root=root, base=base, shadow_matrix=shadow_matrix)
    scorecard = ordered.build_router_superiority_scorecard(root=root, base=base, health_report=health_report)
    ordered_receipt = ordered.build_router_ordered_proof_receipt(
        root=root,
        base=base,
        shadow_matrix=shadow_matrix,
        health_report=health_report,
        scorecard=scorecard,
    )
    r5_receipt = r5.build_router_vs_best_adapter_proof_ratification_receipt(
        root=root,
        shadow_matrix=shadow_matrix,
        health_report=health_report,
        scorecard=scorecard,
        ordered_receipt=ordered_receipt,
    )
    return {
        "r1": r1_receipt,
        "r2": r2_receipt,
        "r3": r3_receipt,
        "r4": r4_receipt,
        "r5": r5_receipt,
    }


def _build_replay_receipt(
    *,
    generated_utc: str,
    head: str,
    replay: Dict[str, Dict[str, Any]],
    live_validation: Dict[str, Any],
) -> Dict[str, Any]:
    statuses = {key: str(value.get("status", "")).strip() for key, value in replay.items()}
    pass_all = all(status == "PASS" for status in statuses.values())
    r5_next = str(replay["r5"].get("next_lawful_move", "")).strip()
    if r5_next != R6_HOLD_MOVE:
        pass_all = False
    return {
        "schema_id": "kt.operator.b04_r1_r5_active_revalidation_replay_receipt.v1",
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
        "trust_zone_validation_status": live_validation["status"],
        "trust_zone_validation_check_count": len(live_validation.get("checks", [])),
        "trust_zone_validation_failure_count": len(live_validation.get("failures", [])),
        "claim_boundary": "This receipt proves only active R1-R5 replay readiness against the settled current overlay. It does not authorize R6, learned-router cutover, lobes, comparative claims, commercial activation, or package promotion.",
        "next_lawful_move": NEXT_MOVE if pass_all else "FIX_B04_R1_R5_ACTIVE_REVALIDATION_REPLAY_DEFECT",
    }


def run(*, reports_root: Path, governance_root: Path) -> Dict[str, Any]:
    root = repo_root()
    if common.git_current_branch_name(root) != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: must run on {REQUIRED_BRANCH}")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R1-R5 supersession run")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    if governance_root.resolve() != (root / "KT_PROD_CLEANROOM/governance").resolve():
        raise RuntimeError("FAIL_CLOSED: must read canonical governance root only")

    upper_receipt = _load(root, "KT_PROD_CLEANROOM/reports/upper_stack_ratification_readiness_receipt.json", label="upper readiness receipt")
    upper_blockers = _load(root, "KT_PROD_CLEANROOM/reports/upper_stack_blocker_ledger.json", label="upper blocker ledger")
    readiness_recommendation = _load(root, "KT_PROD_CLEANROOM/reports/upper_stack_next_ratification_lane_recommendation.json", label="upper recommendation")
    next_contract = _load(root, "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json", label="next workstream contract")
    resume = _load(root, "KT_PROD_CLEANROOM/reports/resume_blockers_receipt.json", label="resume blockers")
    reanchor = _load(root, "KT_PROD_CLEANROOM/reports/gate_d_decision_reanchor_packet.json", label="gate d reanchor")
    scorecard = _load(root, "KT_PROD_CLEANROOM/reports/router_superiority_scorecard.json", label="router superiority scorecard")
    live_validation = validate_trust_zones(root=root)
    _ensure_authorized(
        upper_receipt=upper_receipt,
        upper_blockers=upper_blockers,
        readiness_recommendation=readiness_recommendation,
        next_contract=next_contract,
        resume=resume,
        reanchor=reanchor,
        scorecard=scorecard,
        live_validation=live_validation,
    )

    generated_utc = utc_now_iso_z()
    head = common.git_rev_parse(root, "HEAD")
    overlay_path = reports_root / CURRENT_OVERLAY
    overlay = _build_overlay(root=root, head=head, generated_utc=generated_utc)
    write_json_stable(overlay_path.resolve(), overlay)
    replay = _run_active_replay(root)
    replay_receipt = _build_replay_receipt(
        generated_utc=generated_utc,
        head=head,
        replay=replay,
        live_validation=live_validation,
    )
    if replay_receipt["status"] != "PASS":
        write_json_stable((reports_root / OUTPUT_REPLAY_RECEIPT).resolve(), replay_receipt)
        raise RuntimeError("FAIL_CLOSED: active R1-R5 replay did not pass after overlay supersession")

    evidence = _build_evidence(root, reports_root.resolve(), governance_root.resolve())
    evidence["current_campaign_state_overlay"] = _sha_ref(overlay_path, root=root)
    packet = {
        "schema_id": "kt.operator.b04_r1_r5_revalidation_asset_supersession_packet.v1",
        "status": "PASS",
        "generated_utc": generated_utc,
        "current_git_head": head,
        "missing_asset_identity": {
            "path": "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json",
            "expected_schema_id": "kt.current_campaign_state_overlay.v1",
            "dependent_replay_steps": ["B04_R1", "B04_R2", "B04_R3", "B04_R4", "B04_R5"],
            "defect_class": "MISSING_ACTIVE_REVALIDATION_CONTROL_SURFACE",
        },
        "resolution_class": "MATERIALIZE_DERIVED_CURRENT_OVERLAY_AND_PATCH_SETTLED_REPLAY_CONTRACT",
        "authority_lineage": {
            "historical_overlay_restored": False,
            "derived_from_current_truth_surfaces": True,
            "truth_engine_law_changed": False,
            "trust_zone_law_changed": False,
        },
        "allowed_resolution": "Fresh overlay is derived from current truth-engine/B04 static-hold surfaces; settled replay contract accepts R5 static-hold as current canonical context for R1-R4 replay.",
        "forbidden_resolutions_preserved": [
            "no_fake_overlay_to_satisfy_tests",
            "no_router_lobe_escalation",
            "no_r6_authorization",
            "no_package_promotion",
            "no_truth_engine_law_mutation",
        ],
        "evidence_refs": evidence,
        "outputs": [CURRENT_OVERLAY, OUTPUT_PACKET, OUTPUT_RECEIPT, OUTPUT_REPLAY_RECEIPT],
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.b04_r1_r5_revalidation_asset_supersession_receipt.v1",
        "status": "PASS",
        "outcome": OUTCOME,
        "generated_utc": generated_utc,
        "current_git_head": head,
        "overlay_materialized": True,
        "active_r1_r5_replay_passed": True,
        "r6_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "next_lawful_move": NEXT_MOVE,
    }
    write_json_stable((reports_root / OUTPUT_PACKET).resolve(), packet)
    write_json_stable((reports_root / OUTPUT_RECEIPT).resolve(), receipt)
    write_json_stable((reports_root / OUTPUT_REPLAY_RECEIPT).resolve(), replay_receipt)
    return {"outcome": OUTCOME, "next_lawful_move": NEXT_MOVE}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Bind B04 R1-R5 revalidation asset supersession.")
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
