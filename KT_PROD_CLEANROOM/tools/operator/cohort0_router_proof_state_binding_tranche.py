from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_R5_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/router_vs_best_adapter_proof_ratification_receipt.json"
DEFAULT_ORDERED_PROOF_REL = "KT_PROD_CLEANROOM/reports/router_ordered_proof_receipt.json"
DEFAULT_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/router_superiority_scorecard.json"
DEFAULT_SHADOW_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/router_shadow_evaluation_ratification_receipt.json"
DEFAULT_FOLLOWTHROUGH_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_tournament_followthrough_packet.json"
DEFAULT_PROMOTION_OUTCOME_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_promotion_outcome_binding_receipt.json"
DEFAULT_MERGE_OUTCOME_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_merge_outcome_binding_receipt.json"
DEFAULT_CURRENT_OVERLAY_REL = "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json"
DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL = "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json"
DEFAULT_RESUME_BLOCKERS_REL = "KT_PROD_CLEANROOM/reports/resume_blockers_receipt.json"
DEFAULT_REANCHOR_PACKET_REL = "KT_PROD_CLEANROOM/reports/gate_d_decision_reanchor_packet.json"
DEFAULT_BINDING_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_router_proof_state_binding_receipt.json"

CURRENT_STEP_ID = "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
NEXT_STEP_ID = "B04_R6_LEARNED_ROUTER_AUTHORIZATION"
HOLD_NEXT_MOVE = "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF"
EXECUTION_MODE = "R6_NEXT_IN_ORDER_BLOCKED_PENDING_EARNED_SUPERIORITY__INITIAL_R5_PROOF_COMPLETE"


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


def _append_unique(items: list[str], extra: str) -> None:
    candidate = str(extra).strip()
    if candidate and candidate not in items:
        items.append(candidate)


def _resolve_subject_head(*, current_head: str, proof_receipt: Dict[str, Any], followthrough: Dict[str, Any]) -> str:
    subject_heads = {
        str(packet.get("subject_head", "")).strip()
        for packet in (proof_receipt, followthrough)
        if isinstance(packet, dict) and str(packet.get("subject_head", "")).strip()
    }
    if not subject_heads:
        raise RuntimeError("FAIL_CLOSED: router-proof state binding could not resolve any subject head")
    if len(subject_heads) != 1:
        raise RuntimeError("FAIL_CLOSED: router-proof state binding requires one consistent subject head")
    subject_head = next(iter(subject_heads))
    return subject_head


def _build_overlay(
    *,
    current_overlay: Dict[str, Any],
    current_head: str,
    subject_head: str,
) -> Dict[str, Any]:
    overlay = dict(current_overlay)
    authority_stack = dict(overlay.get("authority_stack", {}))
    documentary_surfaces = [
        str(item).strip()
        for item in authority_stack.get("documentary_surfaces", [])
        if str(item).strip()
    ]
    for rel in (
        DEFAULT_ORDERED_PROOF_REL,
        DEFAULT_SCORECARD_REL,
        DEFAULT_R5_RECEIPT_REL,
        DEFAULT_BINDING_REPORT_REL,
    ):
        _append_unique(documentary_surfaces, rel)
    authority_stack["documentary_surfaces"] = documentary_surfaces
    overlay["authority_stack"] = authority_stack

    standing = dict(current_overlay.get("current_lawful_gate_standing", {}))
    standing["current_counted_batch"] = CURRENT_STEP_ID
    standing["inter_gate_state"] = "GATE_D_R5_ROUTER_PROOF_RATIFIED_STATIC_HOLD__R6_BLOCKED"
    standing["gate_d_status"] = "ROUTER_VS_BEST_ADAPTER_PROOF_RATIFIED_STATIC_HOLD__R6_NEXT_IN_ORDER_BLOCKED"
    standing["authoritative_basis"] = [
        "Gate C exit remains authoritative only on sealed head 71268f2f7489aadec338d5e71bb5b70f8a7fe9dc.",
        "Gate D postures remain D1 bounded, D2 controlled counted-domain expansion, D3 adapter evolution authorized, D4 no external comparative claims, and D5 lab-only.",
        f"Imported Cohort-0 real-engine adapter evidence remains strong Gate D adapter evidence on subject head {subject_head}.",
        "The imported current-head Cohort-0 entrant set cleared tournament admission, fragility, tournament execution, merge reentry, bounded child evaluation, and promotion/merge outcome binding without opening router authority or wider scope.",
        "B04.R5 now ratifies same-head router-versus-best-adapter ordered proof on the current head and holds static canonical baseline authority because router superiority was not earned.",
    ]
    overlay["current_lawful_gate_standing"] = standing

    overlay["generated_utc"] = utc_now_iso_z()
    overlay["workstream_id"] = CURRENT_STEP_ID
    overlay["repo_state"] = {
        "repo_root": str(overlay.get("repo_state", {}).get("repo_root", "d:/user/rober/OneDrive/Kings_Theorem_Active/KT_PROD_CLEANROOM")),
        "current_git_branch": "main",
        "current_git_head": current_head,
        "worktree_cleanliness": "CLEAN_CURRENT_HEAD",
    }
    overlay["state_reconciliation"] = {
        "latest_sealed_receipts_current_state": (
            "Gate C is exited. Gate D remains bounded and ordered. On the imported current-head Cohort-0 substrate, "
            "router-versus-best-adapter proof was freshly ratified on the current head and held static baseline canonical."
        ),
        "documentary_surface_state_on_main": (
            "Tracked Gate D router proof receipts on main remain carrier surfaces whenever subject_head differs from the sealed head, "
            "including the imported current-head Cohort-0 adapter, tournament, merge, and current router-proof family."
        ),
        "reanchor_decision": "Treat B04.R5 as executed and held. R6 is next in order only and remains blocked in law until router superiority is actually earned on a lawful future same-head proof.",
    }
    overlay["next_counted_workstream_id"] = NEXT_STEP_ID
    overlay["next_counted_workstream_scope"] = (
        "B04.R6 remains next in order only. It is not executable because B04.R5 did not earn router superiority on the "
        "current head. Learned-router authorization, lobes, externality, comparative, and commercial widening remain blocked."
    )
    overlay["repo_state_executable_now"] = False
    overlay["executable_now_why"] = (
        "B04.R5 executed on the current head and held static baseline canonical. R6 is next in order only but remains "
        "blocked pending an actually earned router-superiority result."
    )
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
        "workstream_objective": (
            "Hold B04.R6 as next in order only. Do not execute learned-router authorization because B04.R5 did not earn "
            "router superiority on the current head. Any future router reopening must first earn a lawful superiority result."
        ),
        "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
        "canonical_receipt_binding": {
            "r5_receipt_ref": DEFAULT_R5_RECEIPT_REL,
            "r5_terminal_state_ref": "KT_PROD_CLEANROOM/governance/b04_r5_router_vs_best_adapter_terminal_state.json",
            "gate_d_reanchor_packet_ref": DEFAULT_REANCHOR_PACKET_REL,
        },
        "gate_domain_product_split": {
            "gate": "Gate D sixth ordered step remains blocked",
            "domain_surface": "Gate D may not progress to learned-router authorization until router superiority is actually earned.",
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
            "router_shadow_receipt": DEFAULT_SHADOW_RECEIPT_REL,
            "router_ordered_proof_receipt": DEFAULT_ORDERED_PROOF_REL,
            "router_superiority_scorecard": DEFAULT_SCORECARD_REL,
            "router_vs_best_adapter_proof_receipt": DEFAULT_R5_RECEIPT_REL,
        },
        "expected_mutate_paths": [],
        "expected_receipts": [
            DEFAULT_R5_RECEIPT_REL,
        ],
        "validators_and_tests": {
            "validators": [],
            "tests": [],
        },
        "stop_conditions": [
            "Any learned-router authorization is attempted without earned router superiority.",
            "Any lobe ratification, externality widening, comparative claim, or commercial activation is inferred from B04.R5 static hold.",
            "Any tracked carrier surface is treated as fresh same-head authority after the proof head moves.",
        ],
        "pass_fail_criteria": {
            "pass": [
                "B04.R5 remains recorded as executed honestly with static baseline canonical.",
                "B04.R6 remains next in order only and blocked pending earned superiority.",
                "All wider scope remains blocked by order.",
            ],
            "fail": [
                "R6 is marked executable despite non-earned router superiority.",
                "B04.R5 static hold is narrated as learned-router authorization or wider scope opening.",
            ],
        },
        "repo_state_executable_now": False,
        "execution_readiness": "NEXT_IN_ORDER_ONLY_BLOCKED_PENDING_EARNED_SUPERIORITY",
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
        "repo_state_executable_now": False,
        "blocking_state": "B04_R5_EXECUTED_STATIC_HOLD__COUNTED_LANE_CLOSED__R6_STILL_BLOCKED_PENDING_EARNED_SUPERIORITY",
        "blocking_reasons": [
            "B04.R5 same-head router-versus-best-adapter proof executed and held static baseline canonical.",
            "Router superiority was not earned, so B04.R6 remains next in order only and blocked in law.",
            "Learned-router authorization, lobes, externality widening, comparative claims, and commercial activation remain closed.",
        ],
        "nonblocking_conflicts": [],
        "current_lawful_gate_standing": {
            "inter_gate_state": "GATE_D_R5_ROUTER_PROOF_RATIFIED_STATIC_HOLD__R6_BLOCKED",
            "gate_c": "EXITED",
            "gate_d": "R5_STATIC_HOLD__R6_BLOCKED",
        },
        "exact_next_counted_workstream_id": NEXT_STEP_ID,
        "explicit_non_go_areas": [
            "Do not authorize learned router from B04.R5 static hold.",
            "Do not open lobes, externality widening, external comparative claims, or commercial deployment.",
            "Do not treat tracked carrier receipts as same-head authority after the proof head changes.",
            "Do not bypass the ordered Gate D ratification sequence.",
        ],
        "why_not_executable_now": (
            "B04.R5 did not earn router superiority on the current head. Static baseline remains canonical, so B04.R6 is next "
            "in order only and blocked pending earned superiority proof."
        ),
    }


def _build_reanchor(*, current_head: str, subject_head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.gate_d.decision_reanchor_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "classification_tag": "COUNTING_CLOSURE",
        "claim_boundary": (
            "This packet freezes the selected Gate D posture set through B04.R5 on the imported current-head Cohort-0 substrate. "
            "Static baseline remains canonical, R6 is still blocked, and no learned-router, lobe, externality, comparative, "
            "or commercial widening is ratified here."
        ),
        "current_bounded_limitations": {
            "router_status": "STATIC_CANONICAL_BASELINE_ONLY",
            "externality_class_max": "E1_SAME_HOST_DETACHED_REPLAY",
            "highest_truthful_tier_output": "NOT_FRONTIER",
            "product_truth_class": "BOUNDED_E1_BUYER_SIMPLE_PRODUCT_PLANE",
            "gate_d_activation_authorized": True,
            "gate_d_decision_selected": True,
            "active_current_head_claim_blocker_ids": [
                "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED",
                "R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY",
            ],
            "note": (
                f"Gate D remains bounded. On the imported Cohort-0 real-engine substrate for subject head {subject_head}, adapter, tournament, promotion, merge, "
                "router shadow, and router-versus-best-adapter proof are now bound. Static router baseline remains canonical, and "
                "B04.R6 is next in order only but blocked because superiority was not earned."
            ),
        },
        "current_repo_state": {
            "current_git_branch": "main",
            "current_git_head": current_head,
            "repo_root": "d:/user/rober/OneDrive/Kings_Theorem_Active/KT_PROD_CLEANROOM",
            "worktree_cleanliness": "CLEAN_CURRENT_HEAD",
        },
        "explicit_not_authorized": [
            "learned router in production",
            "autonomous multi-lobe runtime",
            "externality widening above E1",
            "external comparative claims",
            "commercial deployment activation",
        ],
        "gate_d_decision_scope": {
            "decision_mode": "R5_ROUTER_PROOF_RATIFIED_STATIC_HOLD__R6_BLOCKED",
            "next_step_id": NEXT_STEP_ID,
            "omega_next_batch_id": "B04_GATE_D_CIVILIZATION_ACTIVATE",
            "no_count_before_decision": False,
            "forbidden_prejudgments": [
                "Treating B04.R5 static hold as learned-router authorization",
                "Treating B04.R5 static hold as lobe ratification",
                "Treating tracked carrier receipts as fresh same-head authority",
            ],
            "selected_scope_summary": [
                "D1 stays EXTERNALITY_BOUNDED until Gate E.",
                "D2 remains one controlled counted-domain expansion inside the single Gate D civilization lane only.",
                "D3 remains adapter evolution authorized.",
                f"The imported Cohort-0 real-engine substrate for subject head {subject_head} now has bound adapter, tournament, merge, and router-proof outcomes.",
                "B04.R5 held static canonical router baseline and left B04.R6 blocked pending earned superiority.",
            ],
        },
        "authoritative_gate_c_exit": {
            "authoritative_head": "71268f2f7489aadec338d5e71bb5b70f8a7fe9dc",
            "authoritative_receipt_path": "C:/Users/rober/AppData/Local/Temp/b03_gate_c_exit_verify_20260328_1029/gate_c_exit_adjudication_authoritative_receipt.json",
            "tracked_carrier_ref": "KT_PROD_CLEANROOM/reports/gate_c_exit_adjudication_receipt.json",
            "tracked_carrier_counts_as_authority": False,
            "rule": "Gate C exit authority is tied to the clean-clone same-head receipt on 71268f2f7489aadec338d5e71bb5b70f8a7fe9dc only.",
        },
        "baseline_vs_live_frame": {
            "baseline_id": "FAIL_CLOSED_NONOUTPUT_BASELINE_V1",
            "canonical_scorecard_id": "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL",
            "scorecard_ref": "KT_PROD_CLEANROOM/reports/baseline_vs_live_scorecard.json",
            "live_row_id": "canonical_useful_output_vs_fail_closed_baseline",
            "evidence_row_id": "useful_output_evidence_stronger_than_ceremonial_path_evidence",
        },
        "reopen_rule": "Satisfied lower gates may only be reopened by current regression receipt.",
        "next_lawful_move": HOLD_NEXT_MOVE,
        "reanchor_head": current_head,
        "workstream_id": CURRENT_STEP_ID,
    }


def build_binding_receipt(*, current_head: str, proof_head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_router_proof_state_binding_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "binding_posture": "R5_STATIC_HOLD__R6_NEXT_IN_ORDER_ONLY_BLOCKED",
        "carrier_surface_role": "TRACKED_CARRIER_ONLY_GATE_D_ROUTER_PROOF_STATE_BINDING_RECEIPT",
        "current_git_head": current_head,
        "subject_head": proof_head,
        "next_lawful_move": HOLD_NEXT_MOVE,
        "source_router_vs_best_adapter_proof_receipt_ref": DEFAULT_R5_RECEIPT_REL,
        "source_router_ordered_proof_receipt_ref": DEFAULT_ORDERED_PROOF_REL,
        "source_router_superiority_scorecard_ref": DEFAULT_SCORECARD_REL,
        "source_router_shadow_receipt_ref": DEFAULT_SHADOW_RECEIPT_REL,
        "source_followthrough_packet_ref": DEFAULT_FOLLOWTHROUGH_REPORT_REL,
        "source_promotion_outcome_binding_receipt_ref": DEFAULT_PROMOTION_OUTCOME_REPORT_REL,
        "source_merge_outcome_binding_receipt_ref": DEFAULT_MERGE_OUTCOME_REPORT_REL,
        "claim_boundary": (
            "This receipt binds only the tracked post-R5 static-hold control surfaces after same-head router-versus-best-adapter "
            "proof held static baseline canonical on the imported current-head Cohort-0 substrate. It does not authorize learned-router cutover, "
            "lobes, externality widening, comparative claims, or commercial activation."
        ),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bind tracked post-R5 static-hold control surfaces for the imported Cohort-0 router proof.")
    parser.add_argument("--router-proof-receipt", default=DEFAULT_R5_RECEIPT_REL)
    parser.add_argument("--router-ordered-proof-receipt", default=DEFAULT_ORDERED_PROOF_REL)
    parser.add_argument("--router-superiority-scorecard", default=DEFAULT_SCORECARD_REL)
    parser.add_argument("--router-shadow-receipt", default=DEFAULT_SHADOW_RECEIPT_REL)
    parser.add_argument("--followthrough-report", default=DEFAULT_FOLLOWTHROUGH_REPORT_REL)
    parser.add_argument("--promotion-outcome-report", default=DEFAULT_PROMOTION_OUTCOME_REPORT_REL)
    parser.add_argument("--merge-outcome-report", default=DEFAULT_MERGE_OUTCOME_REPORT_REL)
    parser.add_argument("--current-campaign-state-overlay", default=DEFAULT_CURRENT_OVERLAY_REL)
    parser.add_argument("--next-counted-workstream-contract", default=DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL)
    parser.add_argument("--resume-blockers-receipt", default=DEFAULT_RESUME_BLOCKERS_REL)
    parser.add_argument("--gate-d-decision-reanchor-packet", default=DEFAULT_REANCHOR_PACKET_REL)
    parser.add_argument("--binding-report", default=DEFAULT_BINDING_REPORT_REL)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    current_head = _git_head(root)

    proof_receipt = _load_json_required(_resolve(root, str(args.router_proof_receipt)), label="router proof receipt")
    ordered_receipt = _load_json_required(_resolve(root, str(args.router_ordered_proof_receipt)), label="router ordered proof receipt")
    scorecard = _load_json_required(_resolve(root, str(args.router_superiority_scorecard)), label="router superiority scorecard")
    shadow_receipt = _load_json_required(_resolve(root, str(args.router_shadow_receipt)), label="router shadow receipt")
    followthrough = _load_json_required(_resolve(root, str(args.followthrough_report)), label="cohort0 followthrough packet")
    promotion = _load_json_required(_resolve(root, str(args.promotion_outcome_report)), label="promotion outcome receipt")
    merge = _load_json_required(_resolve(root, str(args.merge_outcome_report)), label="merge outcome receipt")
    overlay = _load_json_required(_resolve(root, str(args.current_campaign_state_overlay)), label="current overlay")

    if str(proof_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: router proof receipt must PASS before binding post-R5 hold state")
    if str(proof_receipt.get("workstream_id", "")).strip() != CURRENT_STEP_ID:
        raise RuntimeError("FAIL_CLOSED: router proof receipt workstream must be B04.R5")
    if str(proof_receipt.get("current_git_head", "")).strip() != current_head:
        raise RuntimeError("FAIL_CLOSED: router proof receipt must be same-head on the current repository head")
    if bool(proof_receipt.get("router_proof_summary", {}).get("router_superiority_earned")) is not False:
        raise RuntimeError("FAIL_CLOSED: post-R5 hold binding only applies to non-earned router superiority outcomes")
    if str(proof_receipt.get("next_lawful_move", "")).strip() != HOLD_NEXT_MOVE:
        raise RuntimeError("FAIL_CLOSED: router proof receipt must hold B04.R6 blocked")
    if str(ordered_receipt.get("ordered_proof_outcome", "")).strip() != "PASS_HOLD_STATIC_CANONICAL_BASELINE":
        raise RuntimeError("FAIL_CLOSED: ordered proof receipt must hold static canonical baseline")
    if bool(scorecard.get("superiority_earned")) is not False:
        raise RuntimeError("FAIL_CLOSED: router superiority scorecard must remain unearned")
    if str(shadow_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: router shadow receipt must PASS before binding post-R5 hold state")
    if str(followthrough.get("followthrough_posture", "")).strip() != "PROMOTION_AND_MERGE_OUTCOME_BOUND__ROUTER_SHADOW_EVALUATION_REQUIRED":
        raise RuntimeError("FAIL_CLOSED: cohort0 followthrough packet is not on the expected pre-R5 posture")
    if str(promotion.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: promotion outcome receipt must PASS")
    if str(merge.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: merge outcome receipt must PASS")
    if str(overlay.get("next_counted_workstream_id", "")).strip() != CURRENT_STEP_ID:
        raise RuntimeError("FAIL_CLOSED: current overlay must still show B04.R5 as the executable step before hold binding")

    subject_head = _resolve_subject_head(
        current_head=current_head,
        proof_receipt=proof_receipt,
        followthrough=followthrough,
    )

    overlay_obj = _build_overlay(current_overlay=overlay, current_head=current_head, subject_head=subject_head)
    next_obj = _build_next_contract(current_head=current_head)
    resume_obj = _build_resume(current_head=current_head)
    reanchor_obj = _build_reanchor(current_head=current_head, subject_head=subject_head)
    binding_receipt = build_binding_receipt(current_head=current_head, proof_head=subject_head)

    write_json_stable(_resolve(root, str(args.current_campaign_state_overlay)), overlay_obj)
    write_json_stable(_resolve(root, str(args.next_counted_workstream_contract)), next_obj)
    write_json_stable(_resolve(root, str(args.resume_blockers_receipt)), resume_obj)
    write_json_stable(_resolve(root, str(args.gate_d_decision_reanchor_packet)), reanchor_obj)
    write_json_stable(_resolve(root, str(args.binding_report)), binding_receipt)

    print(
        json.dumps(
            {
                "status": "PASS",
                "binding_posture": binding_receipt["binding_posture"],
                "next_lawful_move": HOLD_NEXT_MOVE,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
