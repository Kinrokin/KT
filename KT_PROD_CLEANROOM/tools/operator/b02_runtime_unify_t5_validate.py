from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from tools.operator.b02_runtime_unify_t4_validate import (
    B02_T4_EXIT_GAP_REDUCTION_REL,
    B02_T4_PROMOTION_BOUNDARY_REL,
    B02_T4_RECEIPT_REL,
    EXPORT_ROOT_REL as T4_EXPORT_ROOT_REL,
    build_b02_runtime_unify_t4_outputs,
)
from tools.operator.constitutional_completion_emit import _domain2_outputs
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
EXECUTION_BOARD_REL = "KT_PROD_CLEANROOM/governance/execution_board.json"
BOUNDARY_RULES_REL = "KT_PROD_CLEANROOM/governance/runtime_integration_boundary_rules.json"

PROMOTION_RECEIPT_REL = f"{REPORT_ROOT_REL}/promotion_receipt.json"
ROLLBACK_PLAN_RECEIPT_REL = f"{REPORT_ROOT_REL}/rollback_plan_receipt.json"
RISK_LEDGER_RECEIPT_REL = f"{REPORT_ROOT_REL}/risk_ledger_receipt.json"
REVALIDATION_RECEIPT_REL = f"{REPORT_ROOT_REL}/revalidation_receipt.json"
ZONE_CROSSING_RECEIPT_REL = f"{REPORT_ROOT_REL}/zone_crossing_receipt.json"
PROMOTION_CIVILIZATION_RATIFICATION_REL = f"{REPORT_ROOT_REL}/promotion_civilization_ratification_receipt.json"
B02_T5_RECEIPT_REL = f"{REPORT_ROOT_REL}/b02_runtime_unify_t5_receipt.json"
EXPORT_ROOT_REL = "KT_PROD_CLEANROOM/exports/b02_runtime_unify_t5"

DOMAIN2_REPORT_REFS = (
    PROMOTION_RECEIPT_REL,
    ROLLBACK_PLAN_RECEIPT_REL,
    RISK_LEDGER_RECEIPT_REL,
    REVALIDATION_RECEIPT_REL,
    ZONE_CROSSING_RECEIPT_REL,
)


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _status(payload: Mapping[str, Any]) -> str:
    return str(payload.get("status", "")).strip().upper()


def _is_pass(payload: Mapping[str, Any]) -> bool:
    return _status(payload) == "PASS"


def _validated_head(payload: Mapping[str, Any]) -> str:
    for key in ("validated_head_sha", "head_sha", "current_git_head"):
        value = str(payload.get(key, "")).strip()
        if value:
            return value
    return ""


def _check_row(check_id: str, passed: bool, **details: Any) -> Dict[str, Any]:
    return {"check_id": check_id, "pass": bool(passed), **details}


def _load_current_head_domain2_receipts(*, root: Path, head: str) -> Dict[str, Dict[str, Any]]:
    outputs = _domain2_outputs(root, head)
    return {ref: outputs[ref] for ref in DOMAIN2_REPORT_REFS}


def build_promotion_civilization_ratification_receipt(
    *,
    head: str,
    execution_board: Mapping[str, Any],
    boundary_rules: Mapping[str, Any],
    t4_receipt: Mapping[str, Any],
    t4_exit_gap_reduction_receipt: Mapping[str, Any],
    t4_promotion_boundary_receipt: Mapping[str, Any],
    domain2_receipts: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Any]:
    remaining_blockers = t4_exit_gap_reduction_receipt.get("remaining_exit_blockers", [])
    only_remaining_blocker = (
        isinstance(remaining_blockers, list)
        and len(remaining_blockers) == 1
        and isinstance(remaining_blockers[0], dict)
        and str(remaining_blockers[0].get("blocker_id", "")).strip() == "PROMOTION_CIVILIZATION_RATIFIED_FALSE"
    )
    current_domain = execution_board.get("current_constitutional_domain", {})
    h1_allowed = bool((execution_board.get("program_gates") or {}).get("H1_ACTIVATION_ALLOWED"))

    refreshed_rows = []
    all_domain2_receipts_current = True
    for ref, payload in domain2_receipts.items():
        row = {
            "receipt_ref": ref,
            "status": str(payload.get("status", "")).strip(),
            "validated_head_sha": _validated_head(payload),
        }
        refreshed_rows.append(row)
        if row["status"].upper() != "PASS" or row["validated_head_sha"] != head:
            all_domain2_receipts_current = False

    zone_crossing = domain2_receipts[ZONE_CROSSING_RECEIPT_REL]
    promotion_receipt = domain2_receipts[PROMOTION_RECEIPT_REL]
    ratified_components = [str(item).strip() for item in promotion_receipt.get("ratified_components", []) if str(item).strip()]
    bounded_components_only = set(ratified_components) == {
        "crucible_registry",
        "policy_c_pressure_training",
        "tournament_engine",
        "merge_engine",
        "static_router_baseline",
        "rollback_discipline",
    }

    boundary_rules_bounded = (
        str(boundary_rules.get("remaining_b02_exit_blocker_id", "")).strip() == "PROMOTION_CIVILIZATION_RATIFIED_FALSE"
        and boundary_rules.get("router_boundary", {}).get("canonical_status") == "STATIC_CANONICAL_BASELINE_ONLY"
        and boundary_rules.get("router_boundary", {}).get("learned_router_cutover_allowed") is False
        and boundary_rules.get("router_boundary", {}).get("multi_lobe_promotion_allowed") is False
        and boundary_rules.get("promotion_boundary", {}).get("canonical_runtime_cutover_allowed") is False
        and boundary_rules.get("promotion_boundary", {}).get("generated_candidate_runtime_admissible") is False
        and boundary_rules.get("promotion_boundary", {}).get("teacher_growth_runtime_influence_allowed") is False
    )

    checks = [
        _check_row(
            "t4_exit_gap_is_only_execution_board_promotion_gate",
            _is_pass(t4_receipt) and only_remaining_blocker,
            remaining_blockers=remaining_blockers,
        ),
        _check_row(
            "execution_board_is_still_domain2_with_h1_allowed",
            h1_allowed and str(current_domain.get("domain_id", "")).strip() == "DOMAIN_2_PROMOTION_CIVILIZATION",
            current_domain=current_domain,
            h1_activation_allowed=h1_allowed,
        ),
        _check_row(
            "current_head_domain2_receipts_are_refreshed_and_pass",
            all_domain2_receipts_current,
            refreshed_rows=refreshed_rows,
        ),
        _check_row(
            "zone_crossing_receipt_proves_governance_only_no_runtime_promotion",
            _is_pass(zone_crossing)
            and _validated_head(zone_crossing) == head
            and zone_crossing.get("crossings") == [],
            crossings=zone_crossing.get("crossings", []),
        ),
        _check_row(
            "promotion_components_stay_bounded_and_static_router_only",
            bounded_components_only,
            ratified_components=ratified_components,
        ),
        _check_row(
            "runtime_integration_boundary_rules_keep_ratification_non_widening",
            boundary_rules_bounded and _is_pass(t4_promotion_boundary_receipt),
        ),
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.b02.promotion_civilization_ratification_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "validated_head_sha": head,
        "ratification_scope_class": "CURRENT_HEAD_BOUNDED_RUNTIME_ADMISSIBILITY_ONLY",
        "gate_id": "PROMOTION_CIVILIZATION_RATIFIED",
        "gate_effect": "SATISFIES_DOMAIN_2_EXIT_PREREQUISITE_ONLY",
        "claim_widening_allowed": False,
        "scope_boundary": "B02 tranche 5 binds promotion civilization to current-head bounded runtime admissibility only. It does not authorize learned-router cutover, multi-lobe promotion, tournament runtime cutover, teacher/growth activation, externality widening, or product widening.",
        "component_refs": [
            B02_T4_RECEIPT_REL,
            B02_T4_EXIT_GAP_REDUCTION_REL,
            B02_T4_PROMOTION_BOUNDARY_REL,
            BOUNDARY_RULES_REL,
            *DOMAIN2_REPORT_REFS,
        ],
        "checks": checks,
        "forbidden_claims_remaining": [
            "Do not claim learned-router or multi-lobe promotion is earned.",
            "Do not claim tournament evidence has become canonical runtime cutover.",
            "Do not claim teacher or growth surfaces are canonical runtime.",
            "Do not widen externality, product, or prestige language."
        ],
    }


def build_b02_runtime_unify_t5_receipt(
    *,
    head: str,
    execution_board: Mapping[str, Any],
    t4_receipt: Mapping[str, Any],
    ratification_receipt: Mapping[str, Any],
) -> Dict[str, Any]:
    domain2 = next(
        (
            row
            for row in execution_board.get("constitutional_domains", [])
            if isinstance(row, dict) and str(row.get("domain_id", "")).strip() == "DOMAIN_2_PROMOTION_CIVILIZATION"
        ),
        {},
    )
    domain2_blockers = [str(item).strip() for item in domain2.get("active_blockers", []) if str(item).strip()]
    board_gate_open = bool((execution_board.get("program_gates") or {}).get("PROMOTION_CIVILIZATION_RATIFIED"))
    status = "PASS" if _is_pass(t4_receipt) and _is_pass(ratification_receipt) else "FAIL"
    mismatch_prefixes = [
        f"{PROMOTION_CIVILIZATION_RATIFICATION_REL} validated_head_sha={head} !=",
        f"{PROMOTION_RECEIPT_REL} validated_head_sha={head} !=",
        f"{ROLLBACK_PLAN_RECEIPT_REL} validated_head_sha={head} !=",
        f"{RISK_LEDGER_RECEIPT_REL} validated_head_sha={head} !=",
        f"{REVALIDATION_RECEIPT_REL} validated_head_sha={head} !=",
        f"{ZONE_CROSSING_RECEIPT_REL} validated_head_sha={head} !=",
    ]
    mismatch_only_carry_forward = bool(
        status == "PASS"
        and not board_gate_open
        and len(domain2_blockers) == len(mismatch_prefixes)
        and all(any(blocker.startswith(prefix) for prefix in mismatch_prefixes) for blocker in domain2_blockers)
    )
    exit_gate_status = bool(status == "PASS" and (board_gate_open or mismatch_only_carry_forward))
    gate_c_authorized = bool(board_gate_open)
    if board_gate_open:
        resolution_path = "PATH_A_CLEAR_WITHIN_B02"
        next_lawful_move = "REASSESS_GATE_C_AUTHORIZATION_FROM_EXECUTION_BOARD"
    elif mismatch_only_carry_forward:
        resolution_path = "PATH_B_RECLASSIFY_OUT_OF_B02"
        next_lawful_move = "HOLD_GATE_C_CLOSED_CARRY_PROMOTION_CIVILIZATION_RATIFICATION_FORWARD"
    else:
        resolution_path = "UNRESOLVED"
        next_lawful_move = "SYNC_EXECUTION_BOARD_AND_REASSESS_B02_EXIT"
    earned_claims = [
        "Promotion civilization ratification is now bound to current-head bounded runtime admissibility receipts instead of remaining false by default.",
        "Current-head promotion, rollback, risk, revalidation, and zone-crossing receipts are refreshed to the runtime-unified sealed head.",
    ]
    if exit_gate_status:
        if board_gate_open:
            earned_claims.append(
                "B02 exit is now lawfully earned on the execution board without widening router, lobe, tournament-cutover, teacher/growth, externality, or product claims."
            )
        else:
            earned_claims.append(
                "B02 exit is now earned on runtime-unification truth alone; PROMOTION_CIVILIZATION_RATIFIED_FALSE is carried forward as a later-gate authoritative-subject blocker and Gate C remains closed."
            )
    else:
        earned_claims.append(
            "The ratification binder is present, but the execution board has not yet been synchronized to open the B02 exit gate."
        )
    return {
        "schema_id": "kt.b02.runtime_unify_t5_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": status,
        "tranche_id": "B02_GATE_B_RUNTIME_UNIFY_T5",
        "scope_boundary": "Fifth counted B02 tranche only. This tranche resolves whether PROMOTION_CIVILIZATION_RATIFIED_FALSE is a true B02 exit prerequisite. It binds Domain 2 ratification to current-head bounded runtime admissibility only and does not itself perform civilization widening.",
        "entry_gate_status": bool(t4_receipt.get("entry_gate_status")),
        "execution_board_gate_status": board_gate_open,
        "gate_c_authorized": gate_c_authorized,
        "resolution_path": resolution_path,
        "domain2_active_blockers": domain2_blockers,
        "exit_gate_status": exit_gate_status,
        "earned_current_head_claims": earned_claims,
        "component_refs": [
            B02_T4_RECEIPT_REL,
            PROMOTION_CIVILIZATION_RATIFICATION_REL,
            EXECUTION_BOARD_REL,
        ],
        "carried_forward_blockers": [
            {
                "blocker_id": "PROMOTION_CIVILIZATION_RATIFIED_FALSE",
                "class": "LATER_GATE_AUTHORITATIVE_SUBJECT_BLOCKER",
                "why": "Execution board ratification remains pinned to the older authoritative truth subject even though current-head bounded runtime ratification now passes."
            }
        ]
        if mismatch_only_carry_forward
        else [],
        "forbidden_claims_remaining": [
            "Do not claim Gate C is complete merely because B02 exits.",
            "Do not claim learned-router or lobe superiority.",
            "Do not claim automatic runtime cutover from tournament evidence.",
            "Do not widen externality, product, or prestige language."
        ],
        "next_lawful_move": next_lawful_move,
    }


def build_b02_runtime_unify_t5_outputs(
    *,
    root: Path,
    export_root: Path,
    c017_telemetry_path: Path,
    w1_telemetry_path: Path,
) -> Dict[str, Dict[str, Any]]:
    head = _git_head(root)
    export_root.mkdir(parents=True, exist_ok=True)
    t4_outputs = build_b02_runtime_unify_t4_outputs(
        root=root,
        export_root=(export_root / "t4_refresh").resolve(),
        c017_telemetry_path=c017_telemetry_path,
        w1_telemetry_path=w1_telemetry_path,
    )
    execution_board = load_json(root / EXECUTION_BOARD_REL)
    boundary_rules = load_json(root / BOUNDARY_RULES_REL)
    current_head_domain2_receipts = _load_current_head_domain2_receipts(root=root, head=head)
    ratification_receipt = build_promotion_civilization_ratification_receipt(
        head=head,
        execution_board=execution_board,
        boundary_rules=boundary_rules,
        t4_receipt=t4_outputs["b02_runtime_unify_t4_receipt"],
        t4_exit_gap_reduction_receipt=t4_outputs["b02_exit_gap_reduction_receipt"],
        t4_promotion_boundary_receipt=t4_outputs["b02_promotion_boundary_truth_receipt"],
        domain2_receipts=current_head_domain2_receipts,
    )
    t5_receipt = build_b02_runtime_unify_t5_receipt(
        head=head,
        execution_board=execution_board,
        t4_receipt=t4_outputs["b02_runtime_unify_t4_receipt"],
        ratification_receipt=ratification_receipt,
    )
    return {
        **t4_outputs,
        "promotion_receipt": current_head_domain2_receipts[PROMOTION_RECEIPT_REL],
        "rollback_plan_receipt": current_head_domain2_receipts[ROLLBACK_PLAN_RECEIPT_REL],
        "risk_ledger_receipt": current_head_domain2_receipts[RISK_LEDGER_RECEIPT_REL],
        "revalidation_receipt": current_head_domain2_receipts[REVALIDATION_RECEIPT_REL],
        "zone_crossing_receipt": current_head_domain2_receipts[ZONE_CROSSING_RECEIPT_REL],
        "promotion_civilization_ratification_receipt": ratification_receipt,
        "b02_runtime_unify_t5_receipt": t5_receipt,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute B02 runtime-unification tranche 5 on current head.")
    parser.add_argument("--c017-telemetry-output", default=f"{REPORT_ROOT_REL}/kt_c017_spine_carriage_telemetry.jsonl")
    parser.add_argument("--w1-telemetry-output", default=f"{REPORT_ROOT_REL}/w1_runtime_realization_telemetry.jsonl")
    parser.add_argument("--promotion-output", default=PROMOTION_RECEIPT_REL)
    parser.add_argument("--rollback-output", default=ROLLBACK_PLAN_RECEIPT_REL)
    parser.add_argument("--risk-ledger-output", default=RISK_LEDGER_RECEIPT_REL)
    parser.add_argument("--revalidation-output", default=REVALIDATION_RECEIPT_REL)
    parser.add_argument("--zone-crossing-output", default=ZONE_CROSSING_RECEIPT_REL)
    parser.add_argument("--ratification-output", default=PROMOTION_CIVILIZATION_RATIFICATION_REL)
    parser.add_argument("--receipt-output", default=B02_T5_RECEIPT_REL)
    parser.add_argument("--export-root", default=EXPORT_ROOT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    outputs = build_b02_runtime_unify_t5_outputs(
        root=root,
        export_root=_resolve(root, str(args.export_root)),
        c017_telemetry_path=_resolve(root, str(args.c017_telemetry_output)),
        w1_telemetry_path=_resolve(root, str(args.w1_telemetry_output)),
    )

    write_json_stable(_resolve(root, str(args.promotion_output)), outputs["promotion_receipt"])
    write_json_stable(_resolve(root, str(args.rollback_output)), outputs["rollback_plan_receipt"])
    write_json_stable(_resolve(root, str(args.risk_ledger_output)), outputs["risk_ledger_receipt"])
    write_json_stable(_resolve(root, str(args.revalidation_output)), outputs["revalidation_receipt"])
    write_json_stable(_resolve(root, str(args.zone_crossing_output)), outputs["zone_crossing_receipt"])
    write_json_stable(_resolve(root, str(args.ratification_output)), outputs["promotion_civilization_ratification_receipt"])
    write_json_stable(_resolve(root, str(args.receipt_output)), outputs["b02_runtime_unify_t5_receipt"])

    summary = {
        "status": outputs["b02_runtime_unify_t5_receipt"]["status"],
        "entry_gate_status": outputs["b02_runtime_unify_t5_receipt"]["entry_gate_status"],
        "execution_board_gate_status": outputs["b02_runtime_unify_t5_receipt"]["execution_board_gate_status"],
        "exit_gate_status": outputs["b02_runtime_unify_t5_receipt"]["exit_gate_status"],
        "next_lawful_move": outputs["b02_runtime_unify_t5_receipt"]["next_lawful_move"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if outputs["b02_runtime_unify_t5_receipt"]["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
