from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator import (
    cohort0_successor_family_side_anti_selection_defect_closure_contract_tranche as closure_contract,
)
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_CONTRACT_REL = f"KT_PROD_CLEANROOM/reports/{closure_contract.OUTPUT_CONTRACT}"
DEFAULT_ROUTE_BEARING_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/route_bearing_stage_pack_manifest.json"
DEFAULT_ROUTE_BEARING_INDEX_REL = "KT_PROD_CLEANROOM/reports/route_bearing_stage_pack_index.json"
DEFAULT_ALPHA_LIABILITY_REGISTRY_REL = "KT_PROD_CLEANROOM/reports/alpha_liability_registry.json"
DEFAULT_ORACLE_LOCAL_EVAL_PACKET_REL = "KT_PROD_CLEANROOM/reports/oracle_router_local_eval_packet.json"
DEFAULT_SINGLE_AXIS_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/single_axis_crucible_input_manifest.json"
DEFAULT_TARGETED_HYPERTRAINING_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_stage_input_manifest.json"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

OUTPUT_BANK = "cohort0_successor_non_promoted_family_depth_bank_v1.json"
OUTPUT_RECEIPT = "cohort0_successor_non_promoted_family_depth_bank_receipt_v1.json"
OUTPUT_REPORT = "COHORT0_SUCCESSOR_NON_PROMOTED_FAMILY_DEPTH_BANK_REPORT.md"

EXECUTION_STATUS = "PASS__SUCCESSOR_NON_PROMOTED_FAMILY_DEPTH_BANK_EMITTED"


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
        raise RuntimeError("FAIL_CLOSED: non-promoted family depth bank requires one same-head authority line")
    return next(iter(heads))


def _validate_inputs(
    *,
    contract: Dict[str, Any],
    route_bearing_manifest: Dict[str, Any],
    route_bearing_index: Dict[str, Any],
    alpha_liability_registry: Dict[str, Any],
    oracle_local_eval_packet: Dict[str, Any],
    single_axis_manifest: Dict[str, Any],
    targeted_hypertraining_manifest: Dict[str, Any],
) -> None:
    for payload, label in (
        (contract, "family-side anti-selection closure contract"),
        (route_bearing_manifest, "route-bearing stage pack manifest"),
        (route_bearing_index, "route-bearing stage pack index"),
        (alpha_liability_registry, "alpha liability registry"),
        (oracle_local_eval_packet, "oracle router local eval packet"),
        (single_axis_manifest, "single-axis crucible input manifest"),
        (targeted_hypertraining_manifest, "targeted hypertraining stage input manifest"),
    ):
        _ensure_pass(payload, label=label)

    if str(contract.get("execution_status", "")).strip() != closure_contract.EXECUTION_STATUS:
        raise RuntimeError("FAIL_CLOSED: closure contract must exist before depth-bank emission")
    if not isinstance(contract.get("candidate_family_ids"), list) or len(contract.get("candidate_family_ids", [])) < 2:
        raise RuntimeError("FAIL_CLOSED: closure contract must carry at least two family candidates")
    if not isinstance(route_bearing_manifest.get("family_rows"), list):
        raise RuntimeError("FAIL_CLOSED: route-bearing manifest must expose family_rows")
    if not isinstance(route_bearing_index.get("rows"), list):
        raise RuntimeError("FAIL_CLOSED: route-bearing index must expose rows")
    if not isinstance(alpha_liability_registry.get("rows"), list):
        raise RuntimeError("FAIL_CLOSED: alpha liability registry must expose rows")
    if not isinstance(oracle_local_eval_packet.get("case_results"), list):
        raise RuntimeError("FAIL_CLOSED: oracle local eval packet must expose case_results")
    if not isinstance(single_axis_manifest.get("family_rows"), list):
        raise RuntimeError("FAIL_CLOSED: single-axis manifest must expose family_rows")
    if not isinstance(targeted_hypertraining_manifest.get("dataset_rows"), list):
        raise RuntimeError("FAIL_CLOSED: targeted hypertraining manifest must expose dataset_rows")


def _index_by_family(rows: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        family_id = str(row.get("family_id", "")).strip()
        if family_id:
            out[family_id] = dict(row)
    return out


def _family_rows(rows: Sequence[Dict[str, Any]], family_id: str) -> List[Dict[str, Any]]:
    return [
        dict(row)
        for row in rows
        if isinstance(row, dict) and str(row.get("family_id", "")).strip() == family_id
    ]


def _build_family_payload(
    *,
    family_id: str,
    contract: Dict[str, Any],
    route_bearing_manifest: Dict[str, Any],
    route_bearing_index: Dict[str, Any],
    alpha_liability_registry: Dict[str, Any],
    oracle_local_eval_packet: Dict[str, Any],
    single_axis_manifest: Dict[str, Any],
    targeted_hypertraining_manifest: Dict[str, Any],
) -> Dict[str, Any]:
    manifest_rows = _index_by_family(route_bearing_manifest.get("family_rows", []))
    liability_rows = _index_by_family(alpha_liability_registry.get("rows", []))
    single_axis_rows = _index_by_family(single_axis_manifest.get("family_rows", []))
    targeted_rows = _index_by_family(targeted_hypertraining_manifest.get("dataset_rows", []))
    manifest_row = manifest_rows.get(family_id, {})
    liability_row = liability_rows.get(family_id, {})
    single_axis_row = single_axis_rows.get(family_id, {})
    targeted_row = targeted_rows.get(family_id, {})
    if not manifest_row or not liability_row or not single_axis_row or not targeted_row:
        raise RuntimeError(f"FAIL_CLOSED: incomplete family source chain for {family_id}")

    oracle_rows = _family_rows(oracle_local_eval_packet.get("case_results", []), family_id)
    indexed_rows = _family_rows(route_bearing_index.get("rows", []), family_id)
    if not oracle_rows or not indexed_rows:
        raise RuntimeError(f"FAIL_CLOSED: missing oracle/index rows for {family_id}")

    visible_oracle_rows = [
        row for row in oracle_rows if str(row.get("pack_visibility", "")).strip() == "VISIBLE_TO_AUTHORING"
    ]
    held_out_oracle_rows = [
        row for row in oracle_rows if str(row.get("pack_visibility", "")).strip() == "HELD_OUT_FOR_GRADING_ONLY"
    ]
    return {
        "family_id": family_id,
        "family_category": str(manifest_row.get("family_category", "")).strip(),
        "acceptance_metric": str(manifest_row.get("acceptance_metric", "")).strip(),
        "alpha_liability": str(manifest_row.get("alpha_liability", "")).strip(),
        "target_lobe_id": str(manifest_row.get("target_lobe_id", "")).strip(),
        "adapter_id": str(targeted_row.get("adapter_id", "")).strip(),
        "oracle_policy_outcomes_supported": list(manifest_row.get("oracle_policy_outcomes", [])),
        "preferred_policy_outcome_default": str(single_axis_row.get("preferred_policy_outcome", "")).strip(),
        "new_admissible_eval_family": str(liability_row.get("new_admissible_eval_family", "")).strip(),
        "primary_pressure_axis": str(single_axis_row.get("primary_pressure_axis", "")).strip(),
        "secondary_pressure_axis": str(single_axis_row.get("secondary_pressure_axis", "")).strip(),
        "also_present_in_lane_a_mutation_source_set": family_id
        in set(contract.get("lane_a_mutation_source_family_ids", [])),
        "visible_case_count": len(visible_oracle_rows),
        "held_out_case_count": len(held_out_oracle_rows),
        "visible_case_ids": [str(row.get("case_id", "")).strip() for row in visible_oracle_rows],
        "held_out_case_ids": [str(row.get("case_id", "")).strip() for row in held_out_oracle_rows],
        "visible_case_variants": [str(row.get("case_variant", "")).strip() for row in visible_oracle_rows],
        "held_out_case_variants": [str(row.get("case_variant", "")).strip() for row in held_out_oracle_rows],
        "oracle_case_rows": [
            {
                "case_id": str(row.get("case_id", "")).strip(),
                "case_sha256": str(row.get("case_sha256", "")).strip(),
                "case_variant": str(row.get("case_variant", "")).strip(),
                "oracle_policy_outcome": str(row.get("oracle_policy_outcome", "")).strip(),
                "pack_visibility": str(row.get("pack_visibility", "")).strip(),
                "selected_adapter_ids": list(row.get("selected_adapter_ids", [])),
                "route_justification": str(row.get("route_justification", "")).strip(),
                "abstention_reason": str(row.get("abstention_reason", "")).strip(),
                "review_handoff_rule": str(row.get("review_handoff_rule", "")).strip(),
                "safety_effect": str(row.get("safety_effect", "")).strip(),
                "preregistered_expectation_satisfied": bool(row.get("preregistered_expectation_satisfied", False)),
            }
            for row in oracle_rows
        ],
        "indexed_case_rows": [
            {
                "case_id": str(row.get("case_id", "")).strip(),
                "case_sha256": str(row.get("case_sha256", "")).strip(),
                "case_variant": str(row.get("case_variant", "")).strip(),
                "oracle_policy_outcome": str(row.get("oracle_policy_outcome", "")).strip(),
                "pack_visibility": str(row.get("pack_visibility", "")).strip(),
            }
            for row in indexed_rows
        ],
        "source_chain": {
            "route_bearing_manifest_family_row": manifest_row,
            "alpha_liability_registry_row": liability_row,
            "single_axis_family_row": single_axis_row,
            "targeted_hypertraining_dataset_row": targeted_row,
        },
    }


def _build_outputs(
    *,
    contract: Dict[str, Any],
    route_bearing_manifest: Dict[str, Any],
    route_bearing_index: Dict[str, Any],
    alpha_liability_registry: Dict[str, Any],
    oracle_local_eval_packet: Dict[str, Any],
    single_axis_manifest: Dict[str, Any],
    targeted_hypertraining_manifest: Dict[str, Any],
    subject_head: str,
) -> Dict[str, Dict[str, Any]]:
    candidate_family_ids = [str(item).strip() for item in contract.get("candidate_family_ids", []) if str(item).strip()]
    families = [
        _build_family_payload(
            family_id=family_id,
            contract=contract,
            route_bearing_manifest=route_bearing_manifest,
            route_bearing_index=route_bearing_index,
            alpha_liability_registry=alpha_liability_registry,
            oracle_local_eval_packet=oracle_local_eval_packet,
            single_axis_manifest=single_axis_manifest,
            targeted_hypertraining_manifest=targeted_hypertraining_manifest,
        )
        for family_id in candidate_family_ids
    ]
    total_visible_case_count = sum(int(item.get("visible_case_count", 0)) for item in families)
    total_held_out_case_count = sum(int(item.get("held_out_case_count", 0)) for item in families)
    bank = {
        "schema_id": "kt.operator.cohort0_successor_non_promoted_family_depth_bank.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This bank emits only family-side non-promoted depth candidates beyond reserve. "
            "It does not reopen Gate D, authorize counted reentry, or open Gate E."
        ),
        "execution_status": EXECUTION_STATUS,
        "bounded_defect_id": contract.get("bounded_defect_id", ""),
        "candidate_family_count": len(families),
        "candidate_family_ids": candidate_family_ids,
        "total_visible_case_count": total_visible_case_count,
        "total_held_out_case_count": total_held_out_case_count,
        "families": families,
        "subject_head": subject_head,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_successor_non_promoted_family_depth_bank_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": bank["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "candidate_family_count": len(families),
        "candidate_family_ids": candidate_family_ids,
        "total_visible_case_count": total_visible_case_count,
        "total_held_out_case_count": total_held_out_case_count,
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "next_lawful_move": "SCREEN_SUCCESSOR_NON_PROMOTED_FAMILY_DEPTH_BANK__NOVELTY_ROUTE_BEARING",
        "subject_head": subject_head,
    }
    return {"bank": bank, "receipt": receipt}


def _build_report(*, bank: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    family_lines = "\n".join(
        f"- `{item.get('family_id', '')}`: visible `{item.get('visible_case_count', 0)}`, held-out `{item.get('held_out_case_count', 0)}`"
        for item in bank.get("families", [])
    )
    return (
        "# Cohort0 Successor Non-Promoted Family Depth Bank Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Candidate family count: `{receipt.get('candidate_family_count', 0)}`\n"
        f"- Total visible case count: `{receipt.get('total_visible_case_count', 0)}`\n"
        f"- Total held-out case count: `{receipt.get('total_held_out_case_count', 0)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Families\n"
        f"{family_lines}\n"
    )


def run(
    *,
    contract_path: Path,
    route_bearing_manifest_path: Path,
    route_bearing_index_path: Path,
    alpha_liability_registry_path: Path,
    oracle_local_eval_packet_path: Path,
    single_axis_manifest_path: Path,
    targeted_hypertraining_manifest_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    contract = _load_json_required(contract_path, label="family-side anti-selection closure contract")
    route_bearing_manifest = _load_json_required(route_bearing_manifest_path, label="route-bearing stage pack manifest")
    route_bearing_index = _load_json_required(route_bearing_index_path, label="route-bearing stage pack index")
    alpha_liability_registry = _load_json_required(alpha_liability_registry_path, label="alpha liability registry")
    oracle_local_eval_packet = _load_json_required(oracle_local_eval_packet_path, label="oracle local eval packet")
    single_axis_manifest = _load_json_required(single_axis_manifest_path, label="single-axis manifest")
    targeted_hypertraining_manifest = _load_json_required(
        targeted_hypertraining_manifest_path, label="targeted hypertraining manifest"
    )

    _validate_inputs(
        contract=contract,
        route_bearing_manifest=route_bearing_manifest,
        route_bearing_index=route_bearing_index,
        alpha_liability_registry=alpha_liability_registry,
        oracle_local_eval_packet=oracle_local_eval_packet,
        single_axis_manifest=single_axis_manifest,
        targeted_hypertraining_manifest=targeted_hypertraining_manifest,
    )
    subject_head = _require_same_subject_head(
        (
            contract,
            route_bearing_manifest,
            route_bearing_index,
            alpha_liability_registry,
            oracle_local_eval_packet,
            single_axis_manifest,
            targeted_hypertraining_manifest,
        )
    )

    outputs = _build_outputs(
        contract=contract,
        route_bearing_manifest=route_bearing_manifest,
        route_bearing_index=route_bearing_index,
        alpha_liability_registry=alpha_liability_registry,
        oracle_local_eval_packet=oracle_local_eval_packet,
        single_axis_manifest=single_axis_manifest,
        targeted_hypertraining_manifest=targeted_hypertraining_manifest,
        subject_head=subject_head,
    )

    reports_root.mkdir(parents=True, exist_ok=True)
    bank_path = reports_root / OUTPUT_BANK
    receipt_path = reports_root / OUTPUT_RECEIPT
    report_path = reports_root / OUTPUT_REPORT

    write_json_stable(bank_path, outputs["bank"])
    write_json_stable(receipt_path, outputs["receipt"])
    _write_text(report_path, _build_report(bank=outputs["bank"], receipt=outputs["receipt"]))

    return {
        "status": "PASS",
        "execution_status": EXECUTION_STATUS,
        "candidate_family_count": outputs["receipt"]["candidate_family_count"],
        "total_visible_case_count": outputs["receipt"]["total_visible_case_count"],
        "output_count": 3,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit the family-side non-promoted depth bank beyond reserve."
    )
    parser.add_argument("--contract", default=DEFAULT_CONTRACT_REL)
    parser.add_argument("--route-bearing-manifest", default=DEFAULT_ROUTE_BEARING_MANIFEST_REL)
    parser.add_argument("--route-bearing-index", default=DEFAULT_ROUTE_BEARING_INDEX_REL)
    parser.add_argument("--alpha-liability-registry", default=DEFAULT_ALPHA_LIABILITY_REGISTRY_REL)
    parser.add_argument("--oracle-local-eval-packet", default=DEFAULT_ORACLE_LOCAL_EVAL_PACKET_REL)
    parser.add_argument("--single-axis-manifest", default=DEFAULT_SINGLE_AXIS_MANIFEST_REL)
    parser.add_argument("--targeted-hypertraining-manifest", default=DEFAULT_TARGETED_HYPERTRAINING_MANIFEST_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        contract_path=_resolve(root, args.contract),
        route_bearing_manifest_path=_resolve(root, args.route_bearing_manifest),
        route_bearing_index_path=_resolve(root, args.route_bearing_index),
        alpha_liability_registry_path=_resolve(root, args.alpha_liability_registry),
        oracle_local_eval_packet_path=_resolve(root, args.oracle_local_eval_packet),
        single_axis_manifest_path=_resolve(root, args.single_axis_manifest),
        targeted_hypertraining_manifest_path=_resolve(root, args.targeted_hypertraining_manifest),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in ("status", "execution_status", "candidate_family_count", "total_visible_case_count", "output_count", "receipt_path", "subject_head"):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
