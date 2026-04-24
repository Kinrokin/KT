from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_dual_lane_first_execution_tranche as dual_lane
from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator import cohort0_successor_anti_selection_stress_wave_tranche as anti_selection_wave
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_ANTI_SELECTION_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{anti_selection_wave.OUTPUT_PACKET}"
DEFAULT_ANTI_SELECTION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{anti_selection_wave.OUTPUT_RECEIPT}"
DEFAULT_LANE_B_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{dual_lane.OUTPUT_LANE_B_SCORECARD}"
DEFAULT_ROUTE_BEARING_MANIFEST_REL = dual_lane.DEFAULT_ROUTE_BEARING_MANIFEST_REL
DEFAULT_ALPHA_LIABILITY_REGISTRY_REL = "KT_PROD_CLEANROOM/reports/alpha_liability_registry.json"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

OUTPUT_CONTRACT = "cohort0_successor_family_side_anti_selection_defect_closure_contract.json"
OUTPUT_RECEIPT = "cohort0_successor_family_side_anti_selection_defect_closure_contract_receipt.json"
OUTPUT_REPORT = "COHORT0_SUCCESSOR_FAMILY_SIDE_ANTI_SELECTION_DEFECT_CLOSURE_CONTRACT_REPORT.md"

EXECUTION_STATUS = "PASS__SUCCESSOR_FAMILY_SIDE_ANTI_SELECTION_DEFECT_CLOSURE_CONTRACT_AUTHORED"


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
        raise RuntimeError("FAIL_CLOSED: family-side anti-selection closure contract requires one same-head authority line")
    return next(iter(heads))


def _validate_inputs(
    *,
    verdict_packet: Dict[str, Any],
    reentry_block: Dict[str, Any],
    anti_selection_packet: Dict[str, Any],
    anti_selection_receipt: Dict[str, Any],
    lane_b_scorecard: Dict[str, Any],
    route_bearing_manifest: Dict[str, Any],
    alpha_liability_registry: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (anti_selection_packet, "anti-selection packet"),
        (anti_selection_receipt, "anti-selection receipt"),
        (lane_b_scorecard, "dual-lane lane b scorecard"),
        (route_bearing_manifest, "route-bearing stage pack manifest"),
        (alpha_liability_registry, "alpha liability registry"),
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

    if str(anti_selection_receipt.get("execution_status", "")).strip() != anti_selection_wave.EXECUTION_STATUS:
        raise RuntimeError("FAIL_CLOSED: family-side closure contract requires live anti-selection wave receipt")
    if bool(anti_selection_packet.get("anti_selection_wave_beyond_reserve_closed", False)):
        raise RuntimeError("FAIL_CLOSED: closure contract only applies while beyond-reserve anti-selection remains open")
    if anti_selection_wave.BOUNDED_DEFECT_ID not in list(anti_selection_packet.get("bounded_defects_remaining", [])):
        raise RuntimeError("FAIL_CLOSED: expected family-side anti-selection bounded defect is not active")

    if str(lane_b_scorecard.get("execution_status", "")).strip() != "PASS__LANE_B_FIRST_CONCURRENT_SCREENING_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: Lane B first concurrent family screening must exist")
    if not isinstance(route_bearing_manifest.get("family_rows"), list):
        raise RuntimeError("FAIL_CLOSED: route-bearing manifest must expose family_rows")
    if not isinstance(alpha_liability_registry.get("rows"), list):
        raise RuntimeError("FAIL_CLOSED: alpha liability registry must expose rows")


def _family_set(rows: Sequence[Dict[str, Any]], key: str) -> List[str]:
    return sorted(
        {
            str(item.get(key, "")).strip()
            for item in rows
            if isinstance(item, dict) and str(item.get(key, "")).strip()
        }
    )


def _build_outputs(
    *,
    anti_selection_packet: Dict[str, Any],
    lane_b_scorecard: Dict[str, Any],
    route_bearing_manifest: Dict[str, Any],
    alpha_liability_registry: Dict[str, Any],
    subject_head: str,
) -> Dict[str, Dict[str, Any]]:
    promoted_family_ids = _family_set(lane_b_scorecard.get("survivors", []), "family_id")
    reserve_family_ids = _family_set(lane_b_scorecard.get("reserves", []), "item_id")
    rejected_overlap_family_ids = sorted(
        {
            str(item.get("item_id", "")).strip()
            for item in lane_b_scorecard.get("rejections", [])
            if isinstance(item, dict)
            and str(item.get("disposition", "")).strip() == "REJECTED__LEGACY_ROUTE_RING_OVERLAP"
            and str(item.get("item_id", "")).strip()
        }
    )
    lane_a_source_family_ids = _family_set(
        anti_selection_packet.get("lane_a_non_promoted_mutation_scorecards", []),
        "source_family_id",
    )
    liability_rows = {
        str(item.get("family_id", "")).strip(): dict(item)
        for item in alpha_liability_registry.get("rows", [])
        if isinstance(item, dict) and str(item.get("family_id", "")).strip()
    }
    manifest_rows = {
        str(item.get("family_id", "")).strip(): dict(item)
        for item in route_bearing_manifest.get("family_rows", [])
        if isinstance(item, dict) and str(item.get("family_id", "")).strip()
    }
    candidate_family_ids = sorted(
        family_id
        for family_id, row in manifest_rows.items()
        if str(row.get("family_category", "")).strip() == "SPECIALIST_WEDGE"
        and family_id in liability_rows
        and family_id not in set(promoted_family_ids)
        and family_id not in set(reserve_family_ids)
        and family_id not in set(rejected_overlap_family_ids)
    )
    if len(candidate_family_ids) < 2:
        raise RuntimeError("FAIL_CLOSED: family-side closure contract needs at least two beyond-reserve family candidates")

    candidate_registry = []
    for family_id in candidate_family_ids:
        manifest_row = manifest_rows[family_id]
        liability_row = liability_rows[family_id]
        candidate_registry.append(
            {
                "family_id": family_id,
                "acceptance_metric": str(manifest_row.get("acceptance_metric", "")).strip(),
                "alpha_liability": str(manifest_row.get("alpha_liability", "")).strip(),
                "target_lobe_id": str(manifest_row.get("target_lobe_id", "")).strip(),
                "family_category": str(manifest_row.get("family_category", "")).strip(),
                "visible_case_count": int(manifest_row.get("visible_case_count", 0)),
                "held_out_case_count": int(manifest_row.get("held_out_case_count", 0)),
                "new_admissible_eval_family": str(liability_row.get("new_admissible_eval_family", "")).strip(),
                "primary_pressure_axis": str(liability_row.get("primary_pressure_axis", "")).strip(),
                "secondary_pressure_axis": str(liability_row.get("secondary_pressure_axis", "")).strip(),
                "expected_route_outcome": str(liability_row.get("expected_route_outcome", "")).strip(),
                "present_in_lane_a_mutation_source_set": family_id in set(lane_a_source_family_ids),
            }
        )

    thresholds = {
        "minimum_new_non_promoted_family_count": 2,
        "minimum_materially_distinct_family_source_count": 2,
        "minimum_total_visible_case_count": 8,
        "minimum_total_held_out_case_count": 2,
        "minimum_per_family_visible_case_count": 4,
        "minimum_per_family_held_out_case_count": 1,
        "minimum_exact_accuracy": 1.0,
        "minimum_admissible_accuracy": 1.0,
        "minimum_consequence_visibility_rate": 1.0,
    }

    contract = {
        "schema_id": "kt.operator.cohort0_successor_family_side_anti_selection_defect_closure_contract.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This contract defines only what counts as closing the remaining family-side anti-selection defect. "
            "It does not reopen Gate D, authorize counted reentry, or open Gate E."
        ),
        "execution_status": EXECUTION_STATUS,
        "bounded_defect_id": anti_selection_wave.BOUNDED_DEFECT_ID,
        "bounded_defect_closure_target": "FAMILY_SIDE_NON_PROMOTED_DEPTH_BEYOND_RESERVE",
        "promoted_family_ids": promoted_family_ids,
        "reserve_family_ids": reserve_family_ids,
        "rejected_legacy_overlap_family_ids": rejected_overlap_family_ids,
        "lane_a_mutation_source_family_ids": lane_a_source_family_ids,
        "candidate_family_ids": candidate_family_ids,
        "candidate_family_registry": candidate_registry,
        "thresholds": thresholds,
        "beyond_reserve_definition": {
            "family_must_not_be_promoted_on_lane_b": True,
            "family_must_not_be_lane_b_reserve": True,
            "family_must_not_be_rejected_for_legacy_route_ring_overlap": True,
            "family_may_overlap_lane_a_mutation_source_set_only_if_full_family_level_carrier_chain_exists": True,
        },
        "route_bearing_requirements": {
            "family_category_must_be": "SPECIALIST_WEDGE",
            "must_have_route_or_fail_closed_consequence_surface": True,
            "must_have_visible_and_held_out_rows": True,
            "must_have_alpha_liability_registry_row": True,
            "must_have_single_axis_and_targeted_hypertraining_support": True,
        },
        "mixed_policy_exactness_rules": {
            "route_rows": "Outcome, adapter selection, exact route justification, preregistered expectation, and route safety effect must all align.",
            "abstain_rows": "Outcome, empty adapter selection, empty route justification, explicit abstention reason, explicit review handoff rule, preregistered expectation, and abstention safety effect must all align.",
        },
        "next_lawful_move": "GENERATE_SUCCESSOR_NON_PROMOTED_FAMILY_DEPTH_BANK__BEYOND_RESERVE",
        "subject_head": subject_head,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_successor_family_side_anti_selection_defect_closure_contract_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": contract["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "bounded_defect_id": anti_selection_wave.BOUNDED_DEFECT_ID,
        "candidate_family_count": len(candidate_family_ids),
        "candidate_family_ids": candidate_family_ids,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "next_lawful_move": contract["next_lawful_move"],
        "subject_head": subject_head,
    }
    return {"contract": contract, "receipt": receipt}


def _build_report(*, contract: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    family_lines = "\n".join(
        f"- `{item.get('family_id', '')}`: `{item.get('new_admissible_eval_family', '')}`"
        for item in contract.get("candidate_family_registry", [])
    )
    return (
        "# Cohort0 Successor Family-Side Anti-Selection Defect Closure Contract Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Bounded defect id: `{receipt.get('bounded_defect_id', '')}`\n"
        f"- Candidate family count: `{receipt.get('candidate_family_count', 0)}`\n"
        f"- Candidate family ids: `{receipt.get('candidate_family_ids', [])}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Candidate Families\n"
        f"{family_lines}\n"
    )


def run(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    anti_selection_packet_path: Path,
    anti_selection_receipt_path: Path,
    lane_b_scorecard_path: Path,
    route_bearing_manifest_path: Path,
    alpha_liability_registry_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    anti_selection_packet = _load_json_required(anti_selection_packet_path, label="anti-selection packet")
    anti_selection_receipt = _load_json_required(anti_selection_receipt_path, label="anti-selection receipt")
    lane_b_scorecard = _load_json_required(lane_b_scorecard_path, label="lane b scorecard")
    route_bearing_manifest = _load_json_required(route_bearing_manifest_path, label="route-bearing stage pack manifest")
    alpha_liability_registry = _load_json_required(alpha_liability_registry_path, label="alpha liability registry")

    _validate_inputs(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        anti_selection_packet=anti_selection_packet,
        anti_selection_receipt=anti_selection_receipt,
        lane_b_scorecard=lane_b_scorecard,
        route_bearing_manifest=route_bearing_manifest,
        alpha_liability_registry=alpha_liability_registry,
    )
    subject_head = _require_same_subject_head(
        (
            verdict_packet,
            reentry_block,
            anti_selection_packet,
            anti_selection_receipt,
            lane_b_scorecard,
            route_bearing_manifest,
            alpha_liability_registry,
        )
    )

    outputs = _build_outputs(
        anti_selection_packet=anti_selection_packet,
        lane_b_scorecard=lane_b_scorecard,
        route_bearing_manifest=route_bearing_manifest,
        alpha_liability_registry=alpha_liability_registry,
        subject_head=subject_head,
    )

    reports_root.mkdir(parents=True, exist_ok=True)
    contract_path = reports_root / OUTPUT_CONTRACT
    receipt_path = reports_root / OUTPUT_RECEIPT
    report_path = reports_root / OUTPUT_REPORT

    write_json_stable(contract_path, outputs["contract"])
    write_json_stable(receipt_path, outputs["receipt"])
    _write_text(report_path, _build_report(contract=outputs["contract"], receipt=outputs["receipt"]))

    return {
        "status": "PASS",
        "execution_status": EXECUTION_STATUS,
        "candidate_family_count": outputs["receipt"]["candidate_family_count"],
        "output_count": 3,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Author the closure contract for the remaining family-side anti-selection defect."
    )
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--anti-selection-packet", default=DEFAULT_ANTI_SELECTION_PACKET_REL)
    parser.add_argument("--anti-selection-receipt", default=DEFAULT_ANTI_SELECTION_RECEIPT_REL)
    parser.add_argument("--lane-b-scorecard", default=DEFAULT_LANE_B_SCORECARD_REL)
    parser.add_argument("--route-bearing-manifest", default=DEFAULT_ROUTE_BEARING_MANIFEST_REL)
    parser.add_argument("--alpha-liability-registry", default=DEFAULT_ALPHA_LIABILITY_REGISTRY_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        verdict_packet_path=_resolve(root, args.verdict_packet),
        reentry_block_path=_resolve(root, args.reentry_block),
        anti_selection_packet_path=_resolve(root, args.anti_selection_packet),
        anti_selection_receipt_path=_resolve(root, args.anti_selection_receipt),
        lane_b_scorecard_path=_resolve(root, args.lane_b_scorecard),
        route_bearing_manifest_path=_resolve(root, args.route_bearing_manifest),
        alpha_liability_registry_path=_resolve(root, args.alpha_liability_registry),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in ("status", "execution_status", "candidate_family_count", "output_count", "receipt_path", "subject_head"):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
