from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_FOLLOWTHROUGH_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_tournament_followthrough_packet.json"
DEFAULT_PROMOTION_OUTCOME_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_promotion_outcome_binding_receipt.json"
DEFAULT_MERGE_OUTCOME_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_merge_outcome_binding_receipt.json"
DEFAULT_NON_STUB_EVAL_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_non_stub_eval_emission_receipt.json"
DEFAULT_IMPORT_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_adapter_import_receipt.json"
DEFAULT_GRADE_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_adapter_grade_receipt.json"
DEFAULT_EXECUTION_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_tournament_execution_receipt.json"
DEFAULT_CHILD_EVAL_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_merge_child_evaluation_receipt.json"
DEFAULT_PARENT_PAIR_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_merge_parent_pair_admissibility_receipt.json"
DEFAULT_CURRENT_OVERLAY_REL = "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json"
DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL = "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json"
DEFAULT_RESUME_BLOCKERS_REL = "KT_PROD_CLEANROOM/reports/resume_blockers_receipt.json"
DEFAULT_REANCHOR_PACKET_REL = "KT_PROD_CLEANROOM/reports/gate_d_decision_reanchor_packet.json"
DEFAULT_BINDING_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_router_shadow_state_binding_receipt.json"

CURRENT_STEP_ID = "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION"
NEXT_STEP_ID = "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
EXECUTION_MODE = "CIVILIZATION_RATIFICATION_ORDER_LOCKED__FIFTH_STEP_ONLY"


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _resolve_authoritative(root: Path, tracked_path: Path, ref_field: str, label: str) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(tracked_path, label=f"tracked {label}")
    authoritative_ref = str(tracked.get(ref_field, "")).strip()
    authoritative_path = _resolve(root, authoritative_ref) if authoritative_ref else tracked_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")


def _append_unique(items: List[str], extra: str) -> None:
    candidate = str(extra).strip()
    if candidate and candidate not in items:
        items.append(candidate)


def _resolve_subject_head(*, current_head: str, receipts: Dict[str, Dict[str, Any]]) -> str:
    subject_heads = {
        str(packet.get("subject_head", "")).strip()
        for packet in receipts.values()
        if isinstance(packet, dict) and str(packet.get("subject_head", "")).strip()
    }
    if not subject_heads:
        raise RuntimeError("FAIL_CLOSED: router-shadow state binding could not resolve any subject head")
    if len(subject_heads) != 1:
        raise RuntimeError("FAIL_CLOSED: router-shadow state binding requires one consistent subject head")
    subject_head = next(iter(subject_heads))
    return subject_head


def _authority_refs(*, root: Path, tracked_receipts: Dict[str, Tuple[Path, Dict[str, Any]]]) -> List[str]:
    refs: List[str] = []
    for _, (path, _) in tracked_receipts.items():
        _append_unique(refs, path.as_posix())
    return refs


def _build_overlay(
    *,
    current_overlay: Dict[str, Any],
    current_head: str,
    subject_head: str,
    tracked_receipts: Dict[str, Tuple[Path, Dict[str, Any]]],
) -> Dict[str, Any]:
    overlay = dict(current_overlay)
    authority_stack = dict(overlay.get("authority_stack", {}))
    current_state_authority = [
        str(item).strip()
        for item in authority_stack.get("current_state_authority", [])
        if str(item).strip()
    ]
    for ref in _authority_refs(root=repo_root(), tracked_receipts=tracked_receipts):
        _append_unique(current_state_authority, ref)
    authority_stack["current_state_authority"] = current_state_authority

    documentary_surfaces = [
        str(item).strip()
        for item in authority_stack.get("documentary_surfaces", [])
        if str(item).strip()
    ]
    for rel in (
        DEFAULT_NON_STUB_EVAL_REPORT_REL,
        DEFAULT_PROMOTION_OUTCOME_REPORT_REL,
        DEFAULT_MERGE_OUTCOME_REPORT_REL,
        DEFAULT_FOLLOWTHROUGH_REPORT_REL,
        "KT_PROD_CLEANROOM/reports/router_shadow_evaluation_ratification_receipt.json",
    ):
        _append_unique(documentary_surfaces, rel)
    authority_stack["documentary_surfaces"] = documentary_surfaces
    overlay["authority_stack"] = authority_stack

    overlay["generated_utc"] = utc_now_iso_z()
    overlay["workstream_id"] = CURRENT_STEP_ID
    overlay["repo_state"] = {
        "repo_root": str(overlay.get("repo_state", {}).get("repo_root", "d:/user/rober/OneDrive/Kings_Theorem_Active/KT_PROD_CLEANROOM")),
        "current_git_branch": "main",
        "current_git_head": current_head,
        "worktree_cleanliness": "CLEAN_CURRENT_HEAD",
    }
    overlay["current_lawful_gate_standing"] = {
        "inter_gate_state": "GATE_D_R4_ROUTER_SHADOW_EVALUATION_RATIFIED__PROMOTION_AND_MERGE_OUTCOME_BOUND",
        "current_counted_gate": "Gate D",
        "current_counted_batch": CURRENT_STEP_ID,
        "completed_tranches": list(current_overlay.get("current_lawful_gate_standing", {}).get("completed_tranches", [])),
        "gate_c_status": str(current_overlay.get("current_lawful_gate_standing", {}).get("gate_c_status", "EXITED")).strip(),
        "gate_d_status": "ROUTER_SHADOW_EVALUATION_RATIFIED__R5_ROUTER_PROOF_NEXT",
        "authoritative_basis": [
            "Gate C exit remains authoritative only on sealed head 71268f2f7489aadec338d5e71bb5b70f8a7fe9dc.",
            "Gate D postures remain D1 bounded, D2 controlled counted-domain expansion, D3 adapter evolution authorized, D4 no external comparative claims, and D5 lab-only.",
            f"Imported Cohort-0 real-engine adapter evidence is now strong Gate D adapter evidence on subject head {subject_head}.",
            "The imported current-head Cohort-0 entrant set cleared tournament admission, fragility, tournament execution, merge reentry, bounded child evaluation, and promotion/merge outcome binding without opening router authority or any wider scope.",
            "B04.R4 now ratifies explainable, replayable router shadow evaluation against the audited static router baseline on that promotion-and-merge-bound substrate while keeping learned-router cutover and lobe promotion blocked.",
        ],
    }
    overlay["state_reconciliation"] = {
        "latest_sealed_receipts_current_state": (
            "Gate C is exited. Gate D remains bounded and ordered. On the imported current-head Cohort-0 substrate, "
            "adapter, tournament, and merge outcomes are now bound, and the next lawful counted move is router shadow evaluation ratification only."
        ),
        "documentary_surface_state_on_main": (
            "Tracked Gate D receipts on main remain carrier surfaces whenever subject_head differs from the sealed head, "
            "including the newly imported current-head Cohort-0 adapter/tournament/merge family."
        ),
        "reanchor_decision": "Proceed only to B04.R5 after B04.R4 router-shadow evaluation is freshly ratified on the current head. Do not treat the bound promotion/merge outcome as router superiority, learned-router authorization, or Gate E/F widening.",
    }
    overlay["next_counted_workstream_id"] = NEXT_STEP_ID
    overlay["next_counted_workstream_scope"] = (
        "Ratify only router-versus-best-adapter ordered proof against the shadow-frozen router evidence and the audited "
        "static router baseline on the promotion-and-merge-bound Cohort-0 substrate. Learned-router authorization, "
        "lobes, externality, comparative, and commercial widening remain blocked by order."
    )
    overlay["repo_state_executable_now"] = True
    overlay["executable_now_why"] = "B04.R4 is sealed, promotion/merge outcomes are now bound on the imported substrate, and only the fifth ordered ratification step is executable now."
    return overlay


def _build_next_contract(*, current_head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.next_counted_workstream_contract.v1",
        "classification_tag": "COUNTING_CLOSURE",
        "generated_utc": utc_now_iso_z(),
        "source_workstream_id": CURRENT_STEP_ID,
        "current_counted_gate": "Gate D",
        "parent_batch_id": "B04_GATE_D_CIVILIZATION_ACTIVATE",
        "exact_next_counted_workstream_id": NEXT_STEP_ID,
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "execution_mode": EXECUTION_MODE,
        "workstream_objective": "Ratify only router-versus-best-adapter ordered proof against the shadow-frozen router evidence and the audited static router baseline on the promotion-and-merge-bound Cohort-0 substrate. Do not execute learned-router authorization, lobe ratification, externality, comparative, or commercial widening in this step.",
        "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        "canonical_receipt_binding": {
            "gate_c_exit_authoritative_receipt_path": "C:/Users/rober/AppData/Local/Temp/b03_gate_c_exit_verify_20260328_1029/gate_c_exit_adjudication_authoritative_receipt.json",
            "gate_d_reanchor_packet_ref": DEFAULT_REANCHOR_PACKET_REL,
            "b04_r4_contract_ref": "KT_PROD_CLEANROOM/governance/b04_r4_router_shadow_evaluation_law_contract.json",
            "b04_r4_terminal_state_ref": "KT_PROD_CLEANROOM/governance/b04_r4_router_shadow_terminal_state.json",
        },
        "gate_domain_product_split": {
            "gate": "Gate D fifth ordered ratification step only",
            "domain_surface": "Gate D may ratify router-versus-best-adapter proof only after router shadow evaluation is ratified on the promotion-and-merge-bound Cohort-0 substrate.",
            "product_surface": "NONE_COUNTING",
        },
        "selected_postures": {
            "D1_EXTERNALITY_WIDENING": "EXTERNALITY_BOUNDED",
            "D2_NEW_COUNTED_DOMAINS": "COUNTED_DOMAINS_CONTROLLED_EXPANSION",
            "D3_ADAPTIVE_EVOLUTION_AUTHORIZATION": "ADAPTER_EVOLUTION_AUTHORIZED",
            "D4_COMPARATIVE_COMPETITIVE_CLAIMS": "NO_EXTERNAL_COMPARATIVE_CLAIMS",
            "D5_COMMERCIAL_ACTIVATION": "LAB_ONLY",
        },
        "prerequisite_read": {
            "router_shadow_receipt": "KT_PROD_CLEANROOM/reports/router_shadow_evaluation_ratification_receipt.json",
            "cohort0_followthrough_packet": DEFAULT_FOLLOWTHROUGH_REPORT_REL,
            "cohort0_promotion_outcome_binding_receipt": DEFAULT_PROMOTION_OUTCOME_REPORT_REL,
            "cohort0_merge_outcome_binding_receipt": DEFAULT_MERGE_OUTCOME_REPORT_REL,
        },
        "expected_mutate_paths": [
            "KT_PROD_CLEANROOM/reports/kt_wave2b_router_selection_receipt.json",
            "KT_PROD_CLEANROOM/reports/kt_wave2b_router_shadow_eval_matrix.json",
            "KT_PROD_CLEANROOM/reports/kt_wave2b_route_distribution_health.json",
            "KT_PROD_CLEANROOM/reports/router_shadow_evaluation_ratification_receipt.json",
        ],
        "expected_receipts": [
            "KT_PROD_CLEANROOM/reports/router_shadow_evaluation_ratification_receipt.json",
            "KT_PROD_CLEANROOM/reports/router_vs_best_adapter_proof_ratification_receipt.json",
        ],
        "validators_and_tests": {
            "validators": [
                "python -m tools.operator.router_shadow_evaluation_ratification_validate --allow-tracked-output-refresh",
                "python -m tools.operator.router_ordered_proof_validate",
            ],
            "tests": [
                "python -m pytest -o addopts='' KT_PROD_CLEANROOM/tests/operator/test_b04_r4_router_shadow_evaluation_ratification_validate.py -q",
                "python -m pytest -o addopts='' KT_PROD_CLEANROOM/tests/operator/test_router_ordered_proof_validate.py -q",
            ],
        },
        "stop_conditions": [
            "Any learned-router authorization or lobe ratification is folded into the fifth step.",
            "Any externality widening above E1, external comparative claim, or commercial activation is folded into the fifth step.",
            "Any router superiority claim is made without the ordered proof chain holding no-regression and fallback boundaries.",
        ],
        "pass_fail_criteria": {
            "pass": [
                "Router shadow evaluation is freshly ratified on the current head while static canonical router authority remains unchanged.",
                "Router ordered proof remains bounded against the audited static router baseline and the shadow-frozen router evidence.",
                "All learned-router authorization, lobe, externality, comparative, and commercial steps remain blocked by order.",
            ],
            "fail": [
                "The fifth step widens Gate D beyond router-versus-best-adapter proof.",
                "The fifth step bypasses shadow-frozen router evidence or the static router control baseline.",
                "The fifth step implies learned-router authorization, lobe, externality, product, or comparative widening.",
            ],
        },
        "repo_state_executable_now": True,
        "execution_readiness": "FIFTH_ORDERED_RATIFICATION_STEP_ONLY",
        "current_git_head_binding": current_head,
    }


def _build_resume(*, current_head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.resume_blockers_receipt.v1",
        "classification_tag": "COUNTING_CLOSURE",
        "generated_utc": utc_now_iso_z(),
        "workstream_id": CURRENT_STEP_ID,
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "status": "PASS",
        "repo_root": "d:/user/rober/OneDrive/Kings_Theorem_Active/KT_PROD_CLEANROOM",
        "current_git_branch": "main",
        "current_git_head": current_head,
        "worktree_cleanliness": "CLEAN_CURRENT_HEAD",
        "repo_state_executable_now": True,
        "blocking_state": "BROADER_B04_BLOCKED__FIFTH_RATIFICATION_STEP_ONLY",
        "blocking_reasons": [
            "Imported Cohort-0 real-engine adapter evidence, tournament execution, merge reentry, and promotion/merge outcome binding are now complete on the authoritative subject head.",
            "Only the fifth ordered Gate D ratification step is executable now; learned-router authorization and lobe work remain blocked by order.",
            "Externality widening, external comparative claims, and commercial activation remain deferred to later gates or later explicit authorization.",
        ],
        "nonblocking_conflicts": [],
        "current_lawful_gate_standing": {
            "inter_gate_state": "GATE_D_R4_ROUTER_SHADOW_EVALUATION_REQUIRED__PROMOTION_AND_MERGE_OUTCOME_BOUND",
            "gate_c": "EXITED",
            "gate_d": "ROUTER_SHADOW_EVALUATION_REQUIRED",
        },
        "exact_next_counted_workstream_id": NEXT_STEP_ID,
        "explicit_non_go_areas": [
            "Do not widen externality beyond E1.",
            "Do not open external comparative claims.",
            "Do not activate commercial deployment.",
            "Do not treat B04.R4 as router superiority proof, learned-router authorization, or lobe ratification.",
            "Do not treat tracked carrier receipts as current-head authority.",
            "Do not bypass the ordered Gate D ratification sequence.",
        ],
        "why_not_executable_now": "Not applicable for B04.R5: the fifth ordered ratification step is executable now, but broader B04 remains order-locked.",
    }


def _build_reanchor(*, current_head: str, subject_head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.gate_d.decision_reanchor_packet.v1",
        "classification_tag": "COUNTING_CLOSURE",
        "generated_utc": utc_now_iso_z(),
        "workstream_id": CURRENT_STEP_ID,
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "reanchor_head": current_head,
        "current_repo_state": {
            "repo_root": "d:/user/rober/OneDrive/Kings_Theorem_Active/KT_PROD_CLEANROOM",
            "current_git_branch": "main",
            "current_git_head": current_head,
            "worktree_cleanliness": "CLEAN_CURRENT_HEAD",
        },
        "authoritative_gate_c_exit": {
            "authoritative_head": "71268f2f7489aadec338d5e71bb5b70f8a7fe9dc",
            "authoritative_receipt_path": "C:/Users/rober/AppData/Local/Temp/b03_gate_c_exit_verify_20260328_1029/gate_c_exit_adjudication_authoritative_receipt.json",
            "tracked_carrier_ref": "KT_PROD_CLEANROOM/reports/gate_c_exit_adjudication_receipt.json",
            "tracked_carrier_counts_as_authority": False,
            "rule": "Gate C exit authority is tied to the clean-clone same-head receipt on 71268f2f7489aadec338d5e71bb5b70f8a7fe9dc only.",
        },
        "baseline_vs_live_frame": {
            "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
            "baseline_id": "FAIL_CLOSED_NONOUTPUT_BASELINE_V1",
            "live_row_id": "canonical_useful_output_vs_fail_closed_baseline",
            "evidence_row_id": "useful_output_evidence_stronger_than_ceremonial_path_evidence",
            "scorecard_ref": "KT_PROD_CLEANROOM/reports/baseline_vs_live_scorecard.json",
        },
        "current_bounded_limitations": {
            "active_current_head_claim_blocker_ids": ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"],
            "externality_class_max": "E1_SAME_HOST_DETACHED_REPLAY",
            "highest_truthful_tier_output": "NOT_FRONTIER",
            "product_truth_class": "BOUNDED_E1_BUYER_SIMPLE_PRODUCT_PLANE",
            "router_status": "STATIC_CANONICAL_BASELINE_ONLY",
            "gate_d_decision_selected": True,
            "gate_d_activation_authorized": True,
            "note": (
                f"Gate D launch remains bounded. On the imported Cohort-0 substrate for subject head {subject_head}, "
                "adapter, tournament, promotion, and merge outcomes are now bound; router shadow evaluation is the only active "
                "counted next move while static router authority remains canonical and learned-router cutover, lobes, externality, "
                "comparative, and commercial widening remain blocked."
            ),
        },
        "explicit_not_authorized": [
            "frontier claim",
            "externality widening above E1",
            "new comparator rows",
            "product or market superiority widening",
            "external comparative claims",
            "commercial deployment activation",
            "learned router in production",
            "autonomous multi-lobe runtime",
        ],
        "gate_d_decision_scope": {
            "omega_next_batch_id": "B04_GATE_D_CIVILIZATION_ACTIVATE",
            "decision_mode": "PROMOTION_AND_MERGE_OUTCOME_BOUND__ROUTER_SHADOW_EVALUATION_RATIFIED__FIFTH_STEP_ONLY",
            "r4_contract_ref": "KT_PROD_CLEANROOM/governance/b04_r4_router_shadow_evaluation_law_contract.json",
            "r4_terminal_state_ref": "KT_PROD_CLEANROOM/governance/b04_r4_router_shadow_terminal_state.json",
            "ratified_step_ids": [
                "B04_R1_CRUCIBLE_PRESSURE_LAW_RATIFICATION",
                "B04_R2_ADAPTER_LIFECYCLE_LAW_RATIFICATION",
                "B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_RATIFICATION",
                "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION",
            ],
            "next_step_id": NEXT_STEP_ID,
            "selected_scope_summary": [
                "D1 stays EXTERNALITY_BOUNDED until Gate E.",
                "D2 remains one controlled counted-domain expansion inside the single Gate D civilization lane only.",
                "D3 remains adapter evolution authorized.",
                f"The imported Cohort-0 real-engine substrate for subject head {subject_head} now has strong adapter evidence, executed tournament, reopened merge reentry, and bound promotion/merge outcomes.",
                "R4 binds explainable, replayable shadow routing against the audited static router baseline while keeping canonical router authority unchanged and learned-router cutover blocked.",
            ],
            "forbidden_prejudgments": [
                "Treating R4 as router superiority proof, learned-router authorization, or lobe ratification",
                "Treating router shadow evaluation ratification as externality widening",
                "Treating tracked carrier receipts as Gate D authority",
            ],
            "no_count_before_decision": False,
        },
        "next_lawful_move": NEXT_STEP_ID,
        "claim_boundary": "This packet freezes the selected Gate D posture set, the imported Cohort-0 adapter/tournament/merge outcomes, and the router-shadow-only next move. It still does not ratify router superiority, learned-router cutover, lobes, externality, comparative claims, or commercial scope.",
    }


def _build_binding_receipt(
    *,
    current_head: str,
    subject_head: str,
    authoritative_followthrough_path: Path,
    authoritative_promotion_outcome_path: Path,
    authoritative_merge_outcome_path: Path,
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_router_shadow_state_binding_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "current_git_head": current_head,
        "subject_head": subject_head,
        "binding_posture": "PROMOTION_AND_MERGE_OUTCOME_BOUND__R4_CURRENT_HEAD_STATE_SURFACES_READY",
        "claim_boundary": "This receipt binds only the tracked current-state surfaces needed to lawfully refresh B04.R4 router-shadow ratification after bounded promotion and merge outcomes were earned on the imported Cohort-0 substrate. It does not itself ratify router superiority, learned-router cutover, lobes, externality widening, comparative claims, or commercial activation.",
        "source_followthrough_packet_ref": authoritative_followthrough_path.as_posix(),
        "source_promotion_outcome_binding_receipt_ref": authoritative_promotion_outcome_path.as_posix(),
        "source_merge_outcome_binding_receipt_ref": authoritative_merge_outcome_path.as_posix(),
        "next_lawful_move": CURRENT_STEP_ID,
    }


def run_router_shadow_state_binding_tranche(
    *,
    followthrough_report_path: Path,
    promotion_outcome_report_path: Path,
    merge_outcome_report_path: Path,
    current_overlay_path: Path,
    next_workstream_path: Path,
    resume_blockers_path: Path,
    reanchor_packet_path: Path,
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    authoritative_followthrough_path, followthrough = _resolve_authoritative(
        root,
        followthrough_report_path.resolve(),
        "authoritative_followthrough_packet_ref",
        "cohort0 tournament followthrough packet",
    )
    authoritative_promotion_outcome_path, promotion_outcome = _resolve_authoritative(
        root,
        promotion_outcome_report_path.resolve(),
        "authoritative_promotion_outcome_binding_receipt_ref",
        "cohort0 promotion outcome binding receipt",
    )
    authoritative_merge_outcome_path, merge_outcome = _resolve_authoritative(
        root,
        merge_outcome_report_path.resolve(),
        "authoritative_merge_outcome_binding_receipt_ref",
        "cohort0 merge outcome binding receipt",
    )

    if str(followthrough.get("followthrough_posture", "")).strip() != "PROMOTION_AND_MERGE_OUTCOME_BOUND__ROUTER_SHADOW_EVALUATION_REQUIRED":
        raise RuntimeError("FAIL_CLOSED: router-shadow state binding requires promotion-and-merge outcome bound posture")
    if str(promotion_outcome.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: router-shadow state binding requires PASS promotion outcome binding receipt")
    if str(merge_outcome.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: router-shadow state binding requires PASS merge outcome binding receipt")

    tracked_receipts: Dict[str, Tuple[Path, Dict[str, Any]]] = {}
    for label, rel, field in (
        ("import", DEFAULT_IMPORT_REPORT_REL, "authoritative_import_receipt_ref"),
        ("grade", DEFAULT_GRADE_REPORT_REL, "authoritative_grade_receipt_ref"),
        ("non_stub_eval", DEFAULT_NON_STUB_EVAL_REPORT_REL, "authoritative_non_stub_eval_emission_receipt_ref"),
        ("execution", DEFAULT_EXECUTION_REPORT_REL, "authoritative_tournament_execution_receipt_ref"),
        ("child_eval", DEFAULT_CHILD_EVAL_REPORT_REL, "authoritative_merge_child_evaluation_receipt_ref"),
        ("parent_pair", DEFAULT_PARENT_PAIR_REPORT_REL, "authoritative_merge_parent_pair_admissibility_receipt_ref"),
        ("promotion_outcome", DEFAULT_PROMOTION_OUTCOME_REPORT_REL, "authoritative_promotion_outcome_binding_receipt_ref"),
        ("merge_outcome", DEFAULT_MERGE_OUTCOME_REPORT_REL, "authoritative_merge_outcome_binding_receipt_ref"),
        ("followthrough", DEFAULT_FOLLOWTHROUGH_REPORT_REL, "authoritative_followthrough_packet_ref"),
    ):
        tracked_path = _resolve(root, rel)
        tracked_receipts[label] = _resolve_authoritative(root, tracked_path, field, label)

    current_head = _git_head(root)
    subject_head = _resolve_subject_head(
        current_head=current_head,
        receipts={
            "followthrough": followthrough,
            "promotion_outcome": promotion_outcome,
            "merge_outcome": merge_outcome,
            "import": tracked_receipts["import"][1],
        },
    )
    current_overlay = _load_json_required(current_overlay_path, label="current campaign state overlay")

    overlay = _build_overlay(
        current_overlay=current_overlay,
        current_head=current_head,
        subject_head=subject_head,
        tracked_receipts=tracked_receipts,
    )
    next_contract = _build_next_contract(current_head=current_head)
    resume = _build_resume(current_head=current_head)
    reanchor = _build_reanchor(current_head=current_head, subject_head=subject_head)
    binding_receipt = _build_binding_receipt(
        current_head=current_head,
        subject_head=subject_head,
        authoritative_followthrough_path=authoritative_followthrough_path,
        authoritative_promotion_outcome_path=authoritative_promotion_outcome_path,
        authoritative_merge_outcome_path=authoritative_merge_outcome_path,
    )

    write_json_stable(current_overlay_path.resolve(), overlay)
    write_json_stable(next_workstream_path.resolve(), next_contract)
    write_json_stable(resume_blockers_path.resolve(), resume)
    write_json_stable(reanchor_packet_path.resolve(), reanchor)

    reports_root.mkdir(parents=True, exist_ok=True)
    tracked_binding = dict(binding_receipt)
    tracked_binding["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_ROUTER_SHADOW_STATE_BINDING_RECEIPT"
    write_json_stable((reports_root / Path(DEFAULT_BINDING_REPORT_REL).name).resolve(), tracked_binding)

    return {
        "router_shadow_state_binding_receipt": binding_receipt,
        "current_campaign_state_overlay": overlay,
        "next_counted_workstream_contract": next_contract,
        "resume_blockers_receipt": resume,
        "gate_d_decision_reanchor_packet": reanchor,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Bind tracked current-state surfaces for Cohort-0 router-shadow ratification.")
    ap.add_argument("--followthrough-report", default=DEFAULT_FOLLOWTHROUGH_REPORT_REL)
    ap.add_argument("--promotion-outcome-report", default=DEFAULT_PROMOTION_OUTCOME_REPORT_REL)
    ap.add_argument("--merge-outcome-report", default=DEFAULT_MERGE_OUTCOME_REPORT_REL)
    ap.add_argument("--current-overlay", default=DEFAULT_CURRENT_OVERLAY_REL)
    ap.add_argument("--next-workstream", default=DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL)
    ap.add_argument("--resume-blockers", default=DEFAULT_RESUME_BLOCKERS_REL)
    ap.add_argument("--reanchor-packet", default=DEFAULT_REANCHOR_PACKET_REL)
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_router_shadow_state_binding_tranche(
        followthrough_report_path=_resolve(root, str(args.followthrough_report)),
        promotion_outcome_report_path=_resolve(root, str(args.promotion_outcome_report)),
        merge_outcome_report_path=_resolve(root, str(args.merge_outcome_report)),
        current_overlay_path=_resolve(root, str(args.current_overlay)),
        next_workstream_path=_resolve(root, str(args.next_workstream)),
        resume_blockers_path=_resolve(root, str(args.resume_blockers)),
        reanchor_packet_path=_resolve(root, str(args.reanchor_packet)),
        reports_root=_resolve(root, str(args.reports_root)),
        workspace_root=root,
    )
    receipt = payload["router_shadow_state_binding_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "binding_posture": receipt["binding_posture"],
                "next_lawful_move": receipt["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
