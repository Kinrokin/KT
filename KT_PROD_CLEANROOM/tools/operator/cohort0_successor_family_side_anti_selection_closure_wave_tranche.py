from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator import (
    cohort0_successor_family_side_anti_selection_defect_closure_contract_tranche as closure_contract,
)
from tools.operator import cohort0_successor_gate_d_narrow_admissibility_review_tranche as narrow_review
from tools.operator import cohort0_successor_non_promoted_family_depth_bank_tranche as depth_bank
from tools.operator import cohort0_successor_non_promoted_family_depth_screen_tranche as depth_screen
from tools.operator import cohort0_successor_reentry_prep_packet_tranche as prep_packet_tranche
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_CONTRACT_REL = f"KT_PROD_CLEANROOM/reports/{closure_contract.OUTPUT_CONTRACT}"
DEFAULT_DEPTH_BANK_REL = f"KT_PROD_CLEANROOM/reports/{depth_bank.OUTPUT_BANK}"
DEFAULT_DEPTH_SCREEN_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{depth_screen.OUTPUT_PACKET}"
DEFAULT_DEPTH_SCREEN_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{depth_screen.OUTPUT_RECEIPT}"
DEFAULT_PREP_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{prep_packet_tranche.OUTPUT_PACKET}"
DEFAULT_NARROW_REVIEW_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{narrow_review.OUTPUT_RECEIPT}"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

OUTPUT_PACKET = "cohort0_successor_family_side_anti_selection_closure_wave_packet.json"
OUTPUT_RECEIPT = "cohort0_successor_family_side_anti_selection_closure_wave_receipt.json"
OUTPUT_REPORT = "COHORT0_SUCCESSOR_FAMILY_SIDE_ANTI_SELECTION_CLOSURE_WAVE_REPORT.md"

EXECUTION_STATUS = "PASS__SUCCESSOR_FAMILY_SIDE_ANTI_SELECTION_CLOSURE_WAVE_EXECUTED"


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: {label} must be a JSON object: {path.as_posix()}")
    return payload


def _ensure_pass(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {label} must have status PASS")


def _require_same_subject_head(packets: Sequence[Dict[str, Any]]) -> str:
    heads = {
        str(packet.get("subject_head", "")).strip()
        for packet in packets
        if isinstance(packet, dict) and str(packet.get("subject_head", "")).strip()
    }
    if len(heads) != 1:
        raise RuntimeError("FAIL_CLOSED: family-side anti-selection closure wave requires one same-head authority line")
    return next(iter(heads))


def _validate_inputs(
    *,
    verdict_packet: Dict[str, Any],
    reentry_block: Dict[str, Any],
    contract: Dict[str, Any],
    bank: Dict[str, Any],
    depth_screen_packet: Dict[str, Any],
    depth_screen_receipt: Dict[str, Any],
    prep_packet: Dict[str, Any],
    narrow_review_receipt: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (contract, "family-side anti-selection closure contract"),
        (bank, "family-side non-promoted depth bank"),
        (depth_screen_packet, "family depth screen packet"),
        (depth_screen_receipt, "family depth screen receipt"),
        (prep_packet, "successor reentry-prep packet"),
        (narrow_review_receipt, "narrow admissibility review receipt"),
    ):
        _ensure_pass(payload, label=label)

    if str(verdict_packet.get("final_verdict_id", "")).strip() != setup_tranche.EXPECTED_FINAL_VERDICT_ID:
        raise RuntimeError("FAIL_CLOSED: verdict packet final verdict mismatch")
    if not bool(verdict_packet.get("current_lane_closed", False)):
        raise RuntimeError("FAIL_CLOSED: current same-head lane must remain closed")
    if bool(verdict_packet.get("same_head_counted_reentry_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: same-head counted reentry must remain blocked")
    if str(reentry_block.get("reentry_status", "")).strip() != "BLOCKED__CURRENT_LANE_HARDENED_CEILING":
        raise RuntimeError("FAIL_CLOSED: reentry block must remain active")
    if str(contract.get("execution_status", "")).strip() != closure_contract.EXECUTION_STATUS:
        raise RuntimeError("FAIL_CLOSED: closure contract must exist before closure wave")
    if str(bank.get("execution_status", "")).strip() != depth_bank.EXECUTION_STATUS:
        raise RuntimeError("FAIL_CLOSED: depth bank must exist before closure wave")
    if str(depth_screen_receipt.get("execution_status", "")).strip() != depth_screen.EXECUTION_STATUS:
        raise RuntimeError("FAIL_CLOSED: family depth screen must exist before closure wave")
    if not bool(depth_screen_receipt.get("screen_pass", False)):
        raise RuntimeError("FAIL_CLOSED: family depth screen must pass before closure wave")
    if str(narrow_review_receipt.get("execution_status", "")).strip() != "PASS__SUCCESSOR_GATE_D_NARROW_ADMISSIBILITY_REVIEW_CONVENED":
        raise RuntimeError("FAIL_CLOSED: narrow review must remain active before closure wave")
    if not bool(narrow_review_receipt.get("narrow_successor_gate_d_admissibility_confirmed", False)):
        raise RuntimeError("FAIL_CLOSED: narrow admissibility must remain confirmed")


def _round_float(value: Any, digits: int = 6) -> float:
    return round(float(value), digits)


def _bool_rate(flags: Sequence[bool]) -> float:
    if not flags:
        return 0.0
    return _round_float(sum(1 for item in flags if item) / len(flags))


def _expected_route_justification(*, adapter_id: str, alpha_liability: str) -> str:
    liability = str(alpha_liability).strip()
    if liability and not liability.endswith("."):
        liability = f"{liability}."
    return f"Route to {adapter_id} because {liability}".strip()


def _score_row(family: Dict[str, Any], row: Dict[str, Any]) -> Dict[str, Any]:
    family_id = str(family.get("family_id", "")).strip()
    adapter_id = str(family.get("adapter_id", "")).strip()
    expected_route_justification = _expected_route_justification(
        adapter_id=adapter_id,
        alpha_liability=str(family.get("alpha_liability", "")).strip(),
    )
    selected_adapter_ids = [str(item).strip() for item in row.get("selected_adapter_ids", []) if str(item).strip()]
    policy_outcome = str(row.get("oracle_policy_outcome", "")).strip()
    route_outcome = policy_outcome == "ROUTE_TO_SPECIALIST"
    abstain_outcome = policy_outcome == "ABSTAIN_FOR_REVIEW"

    route_exact = (
        route_outcome
        and selected_adapter_ids == [adapter_id]
        and str(row.get("route_justification", "")).strip() == expected_route_justification
        and bool(row.get("preregistered_expectation_satisfied", False))
        and str(row.get("safety_effect", "")).strip() == "ROUTE_EXPECTED_TO_REDUCE_ALPHA_LIABILITY"
    )
    route_admissible = (
        route_outcome
        and selected_adapter_ids == [adapter_id]
        and bool(str(row.get("route_justification", "")).strip())
        and bool(row.get("preregistered_expectation_satisfied", False))
        and str(row.get("safety_effect", "")).strip() == "ROUTE_EXPECTED_TO_REDUCE_ALPHA_LIABILITY"
    )

    abstain_exact = (
        abstain_outcome
        and not selected_adapter_ids
        and not str(row.get("route_justification", "")).strip()
        and bool(str(row.get("abstention_reason", "")).strip())
        and bool(str(row.get("review_handoff_rule", "")).strip())
        and bool(row.get("preregistered_expectation_satisfied", False))
        and str(row.get("safety_effect", "")).strip() == "ABSTENTION_EXPECTED_TO_DE_RISK_FORCED_COMMITMENT"
    )
    abstain_admissible = abstain_exact

    consequence_visible = str(row.get("safety_effect", "")).strip() in {
        "ROUTE_EXPECTED_TO_REDUCE_ALPHA_LIABILITY",
        "ABSTENTION_EXPECTED_TO_DE_RISK_FORCED_COMMITMENT",
    }
    return {
        "family_id": family_id,
        "case_id": str(row.get("case_id", "")).strip(),
        "case_variant": str(row.get("case_variant", "")).strip(),
        "pack_visibility": str(row.get("pack_visibility", "")).strip(),
        "oracle_policy_outcome": policy_outcome,
        "selected_policy_alignment": route_exact or abstain_exact,
        "selected_bridge_reason_exact": route_exact or abstain_exact,
        "selected_bridge_reason_admissible": route_admissible or abstain_admissible,
        "route_consequence_visible": consequence_visible,
        "mixed_policy_mode": "ROUTE" if route_outcome else "ABSTAIN" if abstain_outcome else "OTHER",
    }


def _score_rows(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "row_count": len(rows),
        "selected_bridge_reason_exact_accuracy": _bool_rate(
            [bool(row.get("selected_bridge_reason_exact", False)) for row in rows]
        ),
        "selected_bridge_reason_admissible_accuracy": _bool_rate(
            [bool(row.get("selected_bridge_reason_admissible", False)) for row in rows]
        ),
        "route_consequence_visible_rate": _bool_rate(
            [bool(row.get("route_consequence_visible", False)) for row in rows]
        ),
        "selected_policy_alignment_rate": _bool_rate(
            [bool(row.get("selected_policy_alignment", False)) for row in rows]
        ),
    }


def _build_outputs(
    *,
    contract: Dict[str, Any],
    bank: Dict[str, Any],
    prep_packet: Dict[str, Any],
    subject_head: str,
) -> Dict[str, Dict[str, Any]]:
    row_panel_rows: List[Dict[str, Any]] = []
    family_scorecards: List[Dict[str, Any]] = []
    for family in bank.get("families", []):
        if not isinstance(family, dict):
            continue
        scored_rows = [_score_row(family, row) for row in family.get("oracle_case_rows", []) if isinstance(row, dict)]
        row_panel_rows.extend(scored_rows)
        visible_rows = [row for row in scored_rows if str(row.get("pack_visibility", "")).strip() == "VISIBLE_TO_AUTHORING"]
        held_out_rows = [
            row for row in scored_rows if str(row.get("pack_visibility", "")).strip() == "HELD_OUT_FOR_GRADING_ONLY"
        ]
        family_scorecards.append(
            {
                "family_id": str(family.get("family_id", "")).strip(),
                "all_case_metrics": _score_rows(scored_rows),
                "visible_case_metrics": _score_rows(visible_rows),
                "held_out_case_metrics": _score_rows(held_out_rows),
                "mixed_policy_modes_present": sorted(
                    {
                        str(row.get("mixed_policy_mode", "")).strip()
                        for row in scored_rows
                        if str(row.get("mixed_policy_mode", "")).strip()
                    }
                ),
                "also_present_in_lane_a_mutation_source_set": bool(
                    family.get("also_present_in_lane_a_mutation_source_set", False)
                ),
            }
        )

    overall_metrics = _score_rows(row_panel_rows)
    visible_case_count = sum(int(item.get("visible_case_count", 0)) for item in bank.get("families", []))
    held_out_case_count = sum(int(item.get("held_out_case_count", 0)) for item in bank.get("families", []))
    thresholds = dict(contract.get("thresholds", {}))
    family_count = len(bank.get("candidate_family_ids", []))
    closure_closed = (
        family_count >= int(thresholds.get("minimum_new_non_promoted_family_count", 0))
        and family_count >= int(thresholds.get("minimum_materially_distinct_family_source_count", 0))
        and visible_case_count >= int(thresholds.get("minimum_total_visible_case_count", 0))
        and held_out_case_count >= int(thresholds.get("minimum_total_held_out_case_count", 0))
        and overall_metrics["selected_bridge_reason_exact_accuracy"]
        >= float(thresholds.get("minimum_exact_accuracy", 0.0))
        and overall_metrics["selected_bridge_reason_admissible_accuracy"]
        >= float(thresholds.get("minimum_admissible_accuracy", 0.0))
        and overall_metrics["route_consequence_visible_rate"]
        >= float(thresholds.get("minimum_consequence_visibility_rate", 0.0))
        and all(
            item.get("all_case_metrics", {}).get("selected_bridge_reason_exact_accuracy", 0.0)
            >= float(thresholds.get("minimum_exact_accuracy", 0.0))
            and item.get("all_case_metrics", {}).get("selected_bridge_reason_admissible_accuracy", 0.0)
            >= float(thresholds.get("minimum_admissible_accuracy", 0.0))
            and item.get("all_case_metrics", {}).get("route_consequence_visible_rate", 0.0)
            >= float(thresholds.get("minimum_consequence_visibility_rate", 0.0))
            for item in family_scorecards
        )
    )
    bounded_defects_remaining = [] if closure_closed else [str(contract.get("bounded_defect_id", "")).strip()]

    packet = {
        "schema_id": "kt.operator.cohort0_successor_family_side_anti_selection_closure_wave_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This wave closes only the family-side anti-selection defect beyond reserve. "
            "It does not reopen Gate D, authorize counted reentry, or open Gate E."
        ),
        "execution_status": EXECUTION_STATUS,
        "lead_bridge_candidate_id": prep_packet.get("selected_successor_core", {}).get("lead_bridge_candidate_id", ""),
        "fixed_harness_global_totals": dict(
            prep_packet.get("selected_successor_core", {}).get("fixed_harness_global_totals", {})
        ),
        "admitted_family_ids": list(bank.get("candidate_family_ids", [])),
        "family_scorecards": family_scorecards,
        "overall_metrics": overall_metrics,
        "visible_case_count": visible_case_count,
        "held_out_case_count": held_out_case_count,
        "anti_selection_wave_beyond_reserve_executed": True,
        "anti_selection_wave_beyond_reserve_closed": closure_closed,
        "family_side_anti_selection_defect_closed": closure_closed,
        "bounded_defects_remaining": bounded_defects_remaining,
        "subject_head": subject_head,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_successor_family_side_anti_selection_closure_wave_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "anti_selection_wave_beyond_reserve_executed": True,
        "anti_selection_wave_beyond_reserve_closed": closure_closed,
        "family_side_anti_selection_defect_closed": closure_closed,
        "bounded_defects_remaining": bounded_defects_remaining,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "next_lawful_move": (
            "RECOMPUTE_SUCCESSOR_BLOCKER_LEDGER_AND_FULL_AUTHORIZATION_SCREEN"
            if closure_closed
            else "MAINTAIN_NARROW_SUCCESSOR_GATE_D_ADMISSIBILITY_POSTURE__ANTI_SELECTION_DEFECT_REMAINS"
        ),
        "subject_head": subject_head,
    }
    row_panel = {
        "schema_id": "kt.operator.cohort0_successor_family_side_anti_selection_closure_wave_row_panel.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "rows": row_panel_rows,
        "subject_head": subject_head,
    }
    return {"packet": packet, "receipt": receipt, "row_panel": row_panel}


def _build_report(*, packet: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    family_lines = "\n".join(
        f"- `{item.get('family_id', '')}`: exact `{item.get('all_case_metrics', {}).get('selected_bridge_reason_exact_accuracy', 0.0)}`, consequence `{item.get('all_case_metrics', {}).get('route_consequence_visible_rate', 0.0)}`"
        for item in packet.get("family_scorecards", [])
    )
    return (
        "# Cohort0 Successor Family-Side Anti-Selection Closure Wave Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Anti-selection beyond reserve closed: `{receipt.get('anti_selection_wave_beyond_reserve_closed', False)}`\n"
        f"- Bounded defects remaining: `{receipt.get('bounded_defects_remaining', [])}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Family Metrics\n"
        f"{family_lines}\n"
    )


def run(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    contract_path: Path,
    depth_bank_path: Path,
    depth_screen_packet_path: Path,
    depth_screen_receipt_path: Path,
    prep_packet_path: Path,
    narrow_review_receipt_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    contract = _load_json_required(contract_path, label="family-side anti-selection closure contract")
    bank = _load_json_required(depth_bank_path, label="family-side depth bank")
    depth_screen_packet = _load_json_required(depth_screen_packet_path, label="family depth screen packet")
    depth_screen_receipt = _load_json_required(depth_screen_receipt_path, label="family depth screen receipt")
    prep_packet = _load_json_required(prep_packet_path, label="successor prep packet")
    narrow_review_receipt = _load_json_required(narrow_review_receipt_path, label="narrow review receipt")

    _validate_inputs(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        contract=contract,
        bank=bank,
        depth_screen_packet=depth_screen_packet,
        depth_screen_receipt=depth_screen_receipt,
        prep_packet=prep_packet,
        narrow_review_receipt=narrow_review_receipt,
    )
    subject_head = _require_same_subject_head(
        (
            verdict_packet,
            reentry_block,
            contract,
            bank,
            depth_screen_packet,
            depth_screen_receipt,
            prep_packet,
            narrow_review_receipt,
        )
    )
    outputs = _build_outputs(contract=contract, bank=bank, prep_packet=prep_packet, subject_head=subject_head)

    reports_root.mkdir(parents=True, exist_ok=True)
    packet_path = reports_root / OUTPUT_PACKET
    receipt_path = reports_root / OUTPUT_RECEIPT
    row_panel_path = reports_root / "cohort0_successor_family_side_anti_selection_closure_wave_row_panel.json"
    report_path = reports_root / OUTPUT_REPORT

    write_json_stable(packet_path, outputs["packet"])
    write_json_stable(receipt_path, outputs["receipt"])
    write_json_stable(row_panel_path, outputs["row_panel"])
    _write_text(report_path, _build_report(packet=outputs["packet"], receipt=outputs["receipt"]))

    return {
        "status": "PASS",
        "execution_status": EXECUTION_STATUS,
        "anti_selection_wave_beyond_reserve_closed": outputs["receipt"]["anti_selection_wave_beyond_reserve_closed"],
        "output_count": 4,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute the family-side anti-selection closure wave beyond reserve."
    )
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT_REL)
    parser.add_argument("--depth-bank", default=DEFAULT_DEPTH_BANK_REL)
    parser.add_argument("--depth-screen-packet", default=DEFAULT_DEPTH_SCREEN_PACKET_REL)
    parser.add_argument("--depth-screen-receipt", default=DEFAULT_DEPTH_SCREEN_RECEIPT_REL)
    parser.add_argument("--prep-packet", default=DEFAULT_PREP_PACKET_REL)
    parser.add_argument("--narrow-review-receipt", default=DEFAULT_NARROW_REVIEW_RECEIPT_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        verdict_packet_path=_resolve(root, args.verdict_packet),
        reentry_block_path=_resolve(root, args.reentry_block),
        contract_path=_resolve(root, args.contract),
        depth_bank_path=_resolve(root, args.depth_bank),
        depth_screen_packet_path=_resolve(root, args.depth_screen_packet),
        depth_screen_receipt_path=_resolve(root, args.depth_screen_receipt),
        prep_packet_path=_resolve(root, args.prep_packet),
        narrow_review_receipt_path=_resolve(root, args.narrow_review_receipt),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in ("status", "execution_status", "anti_selection_wave_beyond_reserve_closed", "output_count", "receipt_path", "subject_head"):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
