from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator import (
    cohort0_successor_family_side_anti_selection_defect_closure_contract_tranche as closure_contract,
)
from tools.operator import cohort0_successor_non_promoted_family_depth_bank_tranche as depth_bank
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_CONTRACT_REL = f"KT_PROD_CLEANROOM/reports/{closure_contract.OUTPUT_CONTRACT}"
DEFAULT_DEPTH_BANK_REL = f"KT_PROD_CLEANROOM/reports/{depth_bank.OUTPUT_BANK}"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

OUTPUT_PACKET = "cohort0_successor_non_promoted_family_depth_screen_packet.json"
OUTPUT_RECEIPT = "cohort0_successor_non_promoted_family_depth_screen_receipt.json"
OUTPUT_REPORT = "COHORT0_SUCCESSOR_NON_PROMOTED_FAMILY_DEPTH_SCREEN_REPORT.md"

EXECUTION_STATUS = "PASS__SUCCESSOR_NON_PROMOTED_FAMILY_DEPTH_SCREEN_EXECUTED"


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
        raise RuntimeError("FAIL_CLOSED: family depth screen requires one same-head authority line")
    return next(iter(heads))


def _validate_inputs(*, contract: Dict[str, Any], bank: Dict[str, Any]) -> None:
    _ensure_pass(contract, label="family-side anti-selection closure contract")
    _ensure_pass(bank, label="non-promoted family depth bank")
    if str(contract.get("execution_status", "")).strip() != closure_contract.EXECUTION_STATUS:
        raise RuntimeError("FAIL_CLOSED: family-side closure contract must exist before screen")
    if str(bank.get("execution_status", "")).strip() != depth_bank.EXECUTION_STATUS:
        raise RuntimeError("FAIL_CLOSED: depth bank must exist before screen")
    if not isinstance(bank.get("families"), list) or len(bank.get("families", [])) < 1:
        raise RuntimeError("FAIL_CLOSED: depth bank must expose family payloads")


def _screen_family(family: Dict[str, Any], contract: Dict[str, Any]) -> Dict[str, Any]:
    promoted = set(str(item).strip() for item in contract.get("promoted_family_ids", []) if str(item).strip())
    reserve = set(str(item).strip() for item in contract.get("reserve_family_ids", []) if str(item).strip())
    rejected = set(
        str(item).strip() for item in contract.get("rejected_legacy_overlap_family_ids", []) if str(item).strip()
    )
    thresholds = dict(contract.get("thresholds", {}))
    family_id = str(family.get("family_id", "")).strip()
    visible_case_count = int(family.get("visible_case_count", 0))
    held_out_case_count = int(family.get("held_out_case_count", 0))
    screen = {
        "family_id": family_id,
        "beyond_reserve_pass": family_id not in promoted and family_id not in reserve,
        "not_legacy_overlap_pass": family_id not in rejected,
        "route_bearing_pass": str(family.get("family_category", "")).strip() == "SPECIALIST_WEDGE"
        and bool(family.get("oracle_policy_outcomes_supported", [])),
        "visible_case_threshold_pass": visible_case_count
        >= int(thresholds.get("minimum_per_family_visible_case_count", 0)),
        "held_out_case_threshold_pass": held_out_case_count
        >= int(thresholds.get("minimum_per_family_held_out_case_count", 0)),
        "full_family_carrier_chain_present": all(
            bool(family.get("source_chain", {}).get(key))
            for key in (
                "route_bearing_manifest_family_row",
                "alpha_liability_registry_row",
                "single_axis_family_row",
                "targeted_hypertraining_dataset_row",
            )
        ),
        "lane_a_overlap_allowed_under_contract": (
            not bool(family.get("also_present_in_lane_a_mutation_source_set", False))
            or bool(
                contract.get("beyond_reserve_definition", {}).get(
                    "family_may_overlap_lane_a_mutation_source_set_only_if_full_family_level_carrier_chain_exists",
                    False,
                )
            )
        ),
        "case_row_count": len(family.get("oracle_case_rows", [])),
        "visible_case_count": visible_case_count,
        "held_out_case_count": held_out_case_count,
        "also_present_in_lane_a_mutation_source_set": bool(
            family.get("also_present_in_lane_a_mutation_source_set", False)
        ),
    }
    screen["screen_pass"] = all(
        bool(screen[key])
        for key in (
            "beyond_reserve_pass",
            "not_legacy_overlap_pass",
            "route_bearing_pass",
            "visible_case_threshold_pass",
            "held_out_case_threshold_pass",
            "full_family_carrier_chain_present",
            "lane_a_overlap_allowed_under_contract",
        )
    )
    return screen


def _build_outputs(*, contract: Dict[str, Any], bank: Dict[str, Any], subject_head: str) -> Dict[str, Dict[str, Any]]:
    rows = [_screen_family(item, contract) for item in bank.get("families", []) if isinstance(item, dict)]
    admitted_family_ids = [row["family_id"] for row in rows if bool(row.get("screen_pass", False))]
    total_visible_case_count = sum(int(row.get("visible_case_count", 0)) for row in rows if bool(row.get("screen_pass", False)))
    total_held_out_case_count = sum(int(row.get("held_out_case_count", 0)) for row in rows if bool(row.get("screen_pass", False)))
    thresholds = dict(contract.get("thresholds", {}))
    overall_pass = (
        len(admitted_family_ids) >= int(thresholds.get("minimum_new_non_promoted_family_count", 0))
        and len(admitted_family_ids) >= int(thresholds.get("minimum_materially_distinct_family_source_count", 0))
        and total_visible_case_count >= int(thresholds.get("minimum_total_visible_case_count", 0))
        and total_held_out_case_count >= int(thresholds.get("minimum_total_held_out_case_count", 0))
        and all(bool(row.get("screen_pass", False)) for row in rows)
    )

    packet = {
        "schema_id": "kt.operator.cohort0_successor_non_promoted_family_depth_screen_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This screen validates only whether the emitted family-side depth bank is admissible beyond reserve. "
            "It does not reopen Gate D, authorize counted reentry, or open Gate E."
        ),
        "execution_status": EXECUTION_STATUS,
        "family_rows": rows,
        "admitted_family_ids": admitted_family_ids,
        "screen_pass": overall_pass,
        "total_visible_case_count": total_visible_case_count,
        "total_held_out_case_count": total_held_out_case_count,
        "subject_head": subject_head,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_successor_non_promoted_family_depth_screen_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "screen_pass": overall_pass,
        "admitted_family_ids": admitted_family_ids,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "next_lawful_move": "EXECUTE_SUCCESSOR_FAMILY_SIDE_ANTI_SELECTION_CLOSURE_WAVE",
        "subject_head": subject_head,
    }
    return {"packet": packet, "receipt": receipt}


def _build_report(*, packet: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    row_lines = "\n".join(
        f"- `{item.get('family_id', '')}`: pass `{item.get('screen_pass', False)}`, lane-a-overlap `{item.get('also_present_in_lane_a_mutation_source_set', False)}`"
        for item in packet.get("family_rows", [])
    )
    return (
        "# Cohort0 Successor Non-Promoted Family Depth Screen Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Screen pass: `{receipt.get('screen_pass', False)}`\n"
        f"- Admitted family ids: `{receipt.get('admitted_family_ids', [])}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Family Rows\n"
        f"{row_lines}\n"
    )


def run(*, contract_path: Path, bank_path: Path, reports_root: Path) -> Dict[str, Any]:
    contract = _load_json_required(contract_path, label="family-side anti-selection closure contract")
    bank = _load_json_required(bank_path, label="non-promoted family depth bank")

    _validate_inputs(contract=contract, bank=bank)
    subject_head = _require_same_subject_head((contract, bank))
    outputs = _build_outputs(contract=contract, bank=bank, subject_head=subject_head)

    reports_root.mkdir(parents=True, exist_ok=True)
    packet_path = reports_root / OUTPUT_PACKET
    receipt_path = reports_root / OUTPUT_RECEIPT
    report_path = reports_root / OUTPUT_REPORT

    write_json_stable(packet_path, outputs["packet"])
    write_json_stable(receipt_path, outputs["receipt"])
    _write_text(report_path, _build_report(packet=outputs["packet"], receipt=outputs["receipt"]))

    return {
        "status": "PASS",
        "execution_status": EXECUTION_STATUS,
        "screen_pass": outputs["receipt"]["screen_pass"],
        "admitted_family_count": len(outputs["receipt"]["admitted_family_ids"]),
        "output_count": 3,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Screen the family-side non-promoted depth bank for beyond-reserve admissibility."
    )
    parser.add_argument("--contract", default=DEFAULT_CONTRACT_REL)
    parser.add_argument("--depth-bank", default=DEFAULT_DEPTH_BANK_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        contract_path=_resolve(root, args.contract),
        bank_path=_resolve(root, args.depth_bank),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in ("status", "execution_status", "screen_pass", "admitted_family_count", "output_count", "receipt_path", "subject_head"):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
