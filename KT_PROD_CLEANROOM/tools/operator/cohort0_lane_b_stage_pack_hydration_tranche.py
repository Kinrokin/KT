from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_dual_lane_first_execution_tranche as dual_lane
from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_DUAL_LANE_EXECUTION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{dual_lane.OUTPUT_EXECUTION_RECEIPT}"
DEFAULT_LANE_B_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{dual_lane.OUTPUT_LANE_B_SCORECARD}"
DEFAULT_ROUTE_BEARING_MANIFEST_REL = dual_lane.DEFAULT_ROUTE_BEARING_MANIFEST_REL
DEFAULT_ROUTE_BEARING_INDEX_REL = dual_lane.DEFAULT_ROUTE_BEARING_INDEX_REL
DEFAULT_ORACLE_LOCAL_EVAL_PACKET_REL = "KT_PROD_CLEANROOM/reports/oracle_router_local_eval_packet.json"
DEFAULT_SINGLE_AXIS_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/single_axis_crucible_input_manifest.json"
DEFAULT_TARGETED_HYPERTRAINING_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_stage_input_manifest.json"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

OUTPUT_HYDRATED_CASE_PACKET = "cohort0_lane_b_hydrated_stage_pack_cases.json"
OUTPUT_HYDRATION_MANIFEST = "cohort0_lane_b_stage_pack_hydration_manifest.json"
OUTPUT_HYDRATION_RECEIPT = "cohort0_lane_b_stage_pack_hydration_receipt.json"
OUTPUT_REPORT = "COHORT0_LANE_B_STAGE_PACK_HYDRATION_REPORT.md"


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
        raise RuntimeError("FAIL_CLOSED: Lane B stage-pack hydration requires one same-head authority line")
    return next(iter(heads))


def _validate_inputs(
    *,
    verdict_packet: Dict[str, Any],
    reentry_block: Dict[str, Any],
    dual_lane_execution_receipt: Dict[str, Any],
    lane_b_scorecard: Dict[str, Any],
    route_bearing_manifest: Dict[str, Any],
    route_bearing_index: Dict[str, Any],
    oracle_local_eval_packet: Dict[str, Any],
    single_axis_manifest: Dict[str, Any],
    targeted_hypertraining_manifest: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (dual_lane_execution_receipt, "dual-lane first execution receipt"),
        (lane_b_scorecard, "dual-lane lane b scorecard"),
        (route_bearing_manifest, "route-bearing stage pack manifest"),
        (route_bearing_index, "route-bearing stage pack index"),
        (oracle_local_eval_packet, "oracle router local eval packet"),
        (single_axis_manifest, "single-axis crucible input manifest"),
        (targeted_hypertraining_manifest, "targeted hypertraining stage input manifest"),
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

    if str(dual_lane_execution_receipt.get("execution_status", "")).strip() != "PASS__DUAL_LANE_FIRST_CONCURRENT_SCREENING_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: dual-lane first concurrent screening must exist")
    if bool(dual_lane_execution_receipt.get("lane_b_case_execution_available", True)):
        raise RuntimeError("FAIL_CLOSED: Lane B hydration only runs while family case execution is still unavailable")
    if bool(dual_lane_execution_receipt.get("same_head_counted_reentry_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: counted reentry must remain blocked entering Lane B hydration")
    if bool(dual_lane_execution_receipt.get("gate_d_reopened", True)):
        raise RuntimeError("FAIL_CLOSED: Gate D must remain closed entering Lane B hydration")
    if bool(dual_lane_execution_receipt.get("gate_e_open", True)):
        raise RuntimeError("FAIL_CLOSED: Gate E must remain closed entering Lane B hydration")

    if str(lane_b_scorecard.get("execution_status", "")).strip() != "PASS__LANE_B_FIRST_CONCURRENT_SCREENING_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: lane b scorecard must be first-concurrent screening output")
    if bool(lane_b_scorecard.get("stage_pack_case_execution_available", True)):
        raise RuntimeError("FAIL_CLOSED: lane b hydration expects case execution unavailable before hydration")

    if not str(route_bearing_manifest.get("authoritative_stage_pack_cases_ref", "")).strip():
        raise RuntimeError("FAIL_CLOSED: route-bearing manifest must carry authoritative stage-pack cases ref")
    if not isinstance(oracle_local_eval_packet.get("case_results"), list):
        raise RuntimeError("FAIL_CLOSED: oracle local eval packet must expose case_results")
    if not isinstance(route_bearing_index.get("rows"), list):
        raise RuntimeError("FAIL_CLOSED: route-bearing stage pack index must expose rows")
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
            out[family_id] = row
    return out


def _family_cases(rows: Sequence[Dict[str, Any]], family_id: str) -> List[Dict[str, Any]]:
    return [
        dict(row)
        for row in rows
        if isinstance(row, dict) and str(row.get("family_id", "")).strip() == family_id
    ]


def _build_family_payloads(
    *,
    lane_b_scorecard: Dict[str, Any],
    route_bearing_manifest: Dict[str, Any],
    route_bearing_index: Dict[str, Any],
    oracle_local_eval_packet: Dict[str, Any],
    single_axis_manifest: Dict[str, Any],
    targeted_hypertraining_manifest: Dict[str, Any],
) -> Dict[str, Any]:
    manifest_family_rows = _index_by_family(route_bearing_manifest.get("family_rows", []))
    single_axis_rows = _index_by_family(single_axis_manifest.get("family_rows", []))
    targeted_rows = _index_by_family(targeted_hypertraining_manifest.get("dataset_rows", []))
    oracle_rows = list(oracle_local_eval_packet.get("case_results", []))
    indexed_rows = list(route_bearing_index.get("rows", []))

    hydrated_families: List[Dict[str, Any]] = []
    for survivor in lane_b_scorecard.get("survivors", []):
        if not isinstance(survivor, dict):
            continue
        family_id = str(survivor.get("family_id", "")).strip()
        if not family_id:
            continue
        manifest_row = dict(manifest_family_rows.get(family_id, {}))
        single_axis_row = dict(single_axis_rows.get(family_id, {}))
        targeted_row = dict(targeted_rows.get(family_id, {}))
        if not manifest_row or not single_axis_row or not targeted_row:
            raise RuntimeError(f"FAIL_CLOSED: incomplete local hydration source chain for family {family_id}")

        oracle_family_cases = _family_cases(oracle_rows, family_id)
        index_family_cases = _family_cases(indexed_rows, family_id)
        if not oracle_family_cases or not index_family_cases:
            raise RuntimeError(f"FAIL_CLOSED: missing case rows for family {family_id}")

        visible_oracle_cases = [
            row for row in oracle_family_cases if str(row.get("pack_visibility", "")).strip() == "VISIBLE_TO_AUTHORING"
        ]
        held_out_oracle_cases = [
            row for row in oracle_family_cases if str(row.get("pack_visibility", "")).strip() == "HELD_OUT_FOR_GRADING_ONLY"
        ]
        if len(visible_oracle_cases) != int(survivor.get("visible_case_count", 0)):
            raise RuntimeError(f"FAIL_CLOSED: visible case count mismatch for family {family_id}")
        if len(held_out_oracle_cases) != int(survivor.get("held_out_case_count", 0)):
            raise RuntimeError(f"FAIL_CLOSED: held-out case count mismatch for family {family_id}")

        source_case_ids = [str(item).strip() for item in targeted_row.get("source_case_ids", []) if str(item).strip()]
        if sorted(source_case_ids) != sorted([str(row.get("case_id", "")).strip() for row in visible_oracle_cases]):
            raise RuntimeError(f"FAIL_CLOSED: targeted source_case_ids mismatch visible oracle cases for family {family_id}")

        hydrated_families.append(
            {
                "family_id": family_id,
                "family_category": str(manifest_row.get("family_category", "")).strip(),
                "acceptance_metric": str(manifest_row.get("acceptance_metric", "")).strip(),
                "alpha_liability": str(manifest_row.get("alpha_liability", "")).strip(),
                "target_lobe_id": str(manifest_row.get("target_lobe_id", "")).strip(),
                "adapter_id": str(targeted_row.get("adapter_id", "")).strip(),
                "preferred_policy_outcome": str(single_axis_row.get("preferred_policy_outcome", "")).strip(),
                "primary_pressure_axis": str(single_axis_row.get("primary_pressure_axis", "")).strip(),
                "secondary_pressure_axis": str(single_axis_row.get("secondary_pressure_axis", "")).strip(),
                "dataset_relpath": str(targeted_row.get("dataset_relpath", "")).strip(),
                "visible_case_count": len(visible_oracle_cases),
                "held_out_case_count": len(held_out_oracle_cases),
                "visible_case_ids": [str(row.get("case_id", "")).strip() for row in visible_oracle_cases],
                "held_out_case_ids": [str(row.get("case_id", "")).strip() for row in held_out_oracle_cases],
                "visible_case_variants": [str(row.get("case_variant", "")).strip() for row in visible_oracle_cases],
                "held_out_case_variants": [str(row.get("case_variant", "")).strip() for row in held_out_oracle_cases],
                "oracle_case_rows": [
                    {
                        "case_id": str(row.get("case_id", "")).strip(),
                        "case_sha256": str(row.get("case_sha256", "")).strip(),
                        "case_variant": str(row.get("case_variant", "")).strip(),
                        "oracle_policy_outcome": str(row.get("oracle_policy_outcome", "")).strip(),
                        "pack_visibility": str(row.get("pack_visibility", "")).strip(),
                        "selected_adapter_ids": list(row.get("selected_adapter_ids", [])),
                        "route_justification": str(row.get("route_justification", "")).strip(),
                        "safety_effect": str(row.get("safety_effect", "")).strip(),
                        "preregistered_expectation_satisfied": bool(row.get("preregistered_expectation_satisfied", False)),
                    }
                    for row in oracle_family_cases
                ],
                "indexed_case_rows": [
                    {
                        "case_id": str(row.get("case_id", "")).strip(),
                        "case_sha256": str(row.get("case_sha256", "")).strip(),
                        "case_variant": str(row.get("case_variant", "")).strip(),
                        "oracle_policy_outcome": str(row.get("oracle_policy_outcome", "")).strip(),
                        "pack_visibility": str(row.get("pack_visibility", "")).strip(),
                    }
                    for row in index_family_cases
                ],
                "hydration_sources": {
                    "route_bearing_manifest_family_row": manifest_row,
                    "single_axis_family_row": single_axis_row,
                    "targeted_hypertraining_dataset_row": {
                        "adapter_id": str(targeted_row.get("adapter_id", "")).strip(),
                        "dataset_relpath": str(targeted_row.get("dataset_relpath", "")).strip(),
                        "config_relpath": str(targeted_row.get("config_relpath", "")).strip(),
                        "visible_source_case_count": int(targeted_row.get("visible_source_case_count", 0)),
                        "excluded_held_out_case_count": int(targeted_row.get("excluded_held_out_case_count", 0)),
                        "source_case_ids": source_case_ids,
                    },
                },
            }
        )
    return {
        "hydrated_family_count": len(hydrated_families),
        "hydrated_families": hydrated_families,
    }


def _build_report(*, manifest: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    family_lines = "\n".join(
        f"- `{row.get('family_id', '')}`: visible `{row.get('visible_case_count', 0)}`, held-out `{row.get('held_out_case_count', 0)}`, adapter `{row.get('adapter_id', '')}`"
        for row in manifest.get("hydrated_families", [])
    )
    return (
        "# Cohort0 Lane B Stage Pack Hydration Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Hydrated family count: `{receipt.get('hydrated_family_count', 0)}`\n"
        f"- Hydrated visible case count: `{receipt.get('hydrated_visible_case_count', 0)}`\n"
        f"- Hydrated held-out case count: `{receipt.get('hydrated_held_out_case_count', 0)}`\n"
        f"- Stale authoritative stage-pack ref missing: `{receipt.get('stale_authoritative_stage_pack_cases_ref_missing', False)}`\n"
        f"- Lane B case execution available after hydration: `{receipt.get('lane_b_case_execution_available_after_hydration', False)}`\n"
        f"- Counted reentry admissible now: `{receipt.get('same_head_counted_reentry_admissible_now', True)}`\n"
        f"- Gate D reopened: `{receipt.get('gate_d_reopened', True)}`\n"
        f"- Gate E open: `{receipt.get('gate_e_open', True)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Hydrated Families\n"
        f"{family_lines}\n"
    )


def run(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    dual_lane_execution_receipt_path: Path,
    lane_b_scorecard_path: Path,
    route_bearing_manifest_path: Path,
    route_bearing_index_path: Path,
    oracle_local_eval_packet_path: Path,
    single_axis_manifest_path: Path,
    targeted_hypertraining_manifest_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    dual_lane_execution_receipt = _load_json_required(
        dual_lane_execution_receipt_path, label="dual-lane first execution receipt"
    )
    lane_b_scorecard = _load_json_required(lane_b_scorecard_path, label="dual-lane lane b scorecard")
    route_bearing_manifest = _load_json_required(route_bearing_manifest_path, label="route-bearing stage pack manifest")
    route_bearing_index = _load_json_required(route_bearing_index_path, label="route-bearing stage pack index")
    oracle_local_eval_packet = _load_json_required(
        oracle_local_eval_packet_path, label="oracle router local eval packet"
    )
    single_axis_manifest = _load_json_required(single_axis_manifest_path, label="single-axis crucible input manifest")
    targeted_hypertraining_manifest = _load_json_required(
        targeted_hypertraining_manifest_path, label="targeted hypertraining stage input manifest"
    )

    _validate_inputs(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        dual_lane_execution_receipt=dual_lane_execution_receipt,
        lane_b_scorecard=lane_b_scorecard,
        route_bearing_manifest=route_bearing_manifest,
        route_bearing_index=route_bearing_index,
        oracle_local_eval_packet=oracle_local_eval_packet,
        single_axis_manifest=single_axis_manifest,
        targeted_hypertraining_manifest=targeted_hypertraining_manifest,
    )
    subject_head = _require_same_subject_head(
        (
            verdict_packet,
            reentry_block,
            dual_lane_execution_receipt,
            lane_b_scorecard,
            route_bearing_manifest,
            route_bearing_index,
            oracle_local_eval_packet,
            single_axis_manifest,
            targeted_hypertraining_manifest,
        )
    )

    hydrated = _build_family_payloads(
        lane_b_scorecard=lane_b_scorecard,
        route_bearing_manifest=route_bearing_manifest,
        route_bearing_index=route_bearing_index,
        oracle_local_eval_packet=oracle_local_eval_packet,
        single_axis_manifest=single_axis_manifest,
        targeted_hypertraining_manifest=targeted_hypertraining_manifest,
    )

    stale_ref = Path(str(route_bearing_manifest.get("authoritative_stage_pack_cases_ref", "")).strip())
    stale_ref_missing = not stale_ref.is_file()
    hydrated_visible_case_count = sum(int(item.get("visible_case_count", 0)) for item in hydrated["hydrated_families"])
    hydrated_held_out_case_count = sum(int(item.get("held_out_case_count", 0)) for item in hydrated["hydrated_families"])

    case_packet = {
        "schema_id": "kt.operator.cohort0_lane_b_hydrated_stage_pack_cases.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This packet hydrates Lane B family case payload from tracked local carrier surfaces only. "
            "It does not yet execute family-level bridge/harness scoring, reopen Gate D, authorize counted reentry, "
            "or open Gate E."
        ),
        "execution_status": "PASS__LANE_B_STAGE_PACK_HYDRATION_EXECUTED",
        "hydrated_family_count": hydrated["hydrated_family_count"],
        "hydrated_families": hydrated["hydrated_families"],
        "lead_bridge_candidate_id": dual_lane.controller_tranche.LEAD_BRIDGE_ID,
        "subject_head": subject_head,
    }

    manifest = {
        "schema_id": "kt.operator.cohort0_lane_b_stage_pack_hydration_manifest.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": case_packet["claim_boundary"],
        "execution_status": "PASS__LANE_B_STAGE_PACK_HYDRATION_EXECUTED",
        "stale_authoritative_stage_pack_cases_ref": str(route_bearing_manifest.get("authoritative_stage_pack_cases_ref", "")).strip(),
        "stale_authoritative_stage_pack_cases_ref_missing": stale_ref_missing,
        "source_chain": {
            "route_bearing_manifest_path": route_bearing_manifest_path.as_posix(),
            "route_bearing_index_path": route_bearing_index_path.as_posix(),
            "oracle_local_eval_packet_path": oracle_local_eval_packet_path.as_posix(),
            "single_axis_manifest_path": single_axis_manifest_path.as_posix(),
            "targeted_hypertraining_manifest_path": targeted_hypertraining_manifest_path.as_posix(),
        },
        "hydrated_family_ids": [item["family_id"] for item in hydrated["hydrated_families"]],
        "hydrated_visible_case_count": hydrated_visible_case_count,
        "hydrated_held_out_case_count": hydrated_held_out_case_count,
        "subject_head": subject_head,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_lane_b_stage_pack_hydration_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This receipt records Lane B payload hydration only. It does not execute family-level bridge/harness scoring, "
            "reopen Gate D, authorize counted reentry, or open Gate E."
        ),
        "execution_status": "PASS__LANE_B_STAGE_PACK_HYDRATION_EXECUTED",
        "hydrated_family_count": hydrated["hydrated_family_count"],
        "hydrated_visible_case_count": hydrated_visible_case_count,
        "hydrated_held_out_case_count": hydrated_held_out_case_count,
        "stale_authoritative_stage_pack_cases_ref_missing": stale_ref_missing,
        "lane_b_case_execution_available_after_hydration": True,
        "next_lawful_move": "EXECUTE_LANE_B_FAMILY_LEVEL_BRIDGE_HARNESS_ON_HYDRATED_PAYLOAD",
        "same_head_counted_reentry_admissible_now": False,
        "gate_d_reopened": False,
        "gate_e_open": False,
        "subject_head": subject_head,
    }

    reports_root.mkdir(parents=True, exist_ok=True)
    case_packet_path = reports_root / OUTPUT_HYDRATED_CASE_PACKET
    manifest_path = reports_root / OUTPUT_HYDRATION_MANIFEST
    receipt_path = reports_root / OUTPUT_HYDRATION_RECEIPT
    report_path = reports_root / OUTPUT_REPORT

    write_json_stable(case_packet_path, case_packet)
    write_json_stable(manifest_path, manifest)
    write_json_stable(receipt_path, receipt)
    _write_text(report_path, _build_report(manifest=manifest, receipt=receipt))

    return {
        "status": "PASS",
        "execution_status": receipt["execution_status"],
        "lane_b_case_execution_available_after_hydration": receipt["lane_b_case_execution_available_after_hydration"],
        "hydrated_family_count": receipt["hydrated_family_count"],
        "hydrated_visible_case_count": receipt["hydrated_visible_case_count"],
        "output_count": 4,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Hydrate Lane B family case payload from live local carrier surfaces."
    )
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--dual-lane-execution-receipt", default=DEFAULT_DUAL_LANE_EXECUTION_RECEIPT_REL)
    parser.add_argument("--lane-b-scorecard", default=DEFAULT_LANE_B_SCORECARD_REL)
    parser.add_argument("--route-bearing-manifest", default=DEFAULT_ROUTE_BEARING_MANIFEST_REL)
    parser.add_argument("--route-bearing-index", default=DEFAULT_ROUTE_BEARING_INDEX_REL)
    parser.add_argument("--oracle-local-eval-packet", default=DEFAULT_ORACLE_LOCAL_EVAL_PACKET_REL)
    parser.add_argument("--single-axis-manifest", default=DEFAULT_SINGLE_AXIS_MANIFEST_REL)
    parser.add_argument("--targeted-hypertraining-manifest", default=DEFAULT_TARGETED_HYPERTRAINING_MANIFEST_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        verdict_packet_path=_resolve(root, args.verdict_packet),
        reentry_block_path=_resolve(root, args.reentry_block),
        dual_lane_execution_receipt_path=_resolve(root, args.dual_lane_execution_receipt),
        lane_b_scorecard_path=_resolve(root, args.lane_b_scorecard),
        route_bearing_manifest_path=_resolve(root, args.route_bearing_manifest),
        route_bearing_index_path=_resolve(root, args.route_bearing_index),
        oracle_local_eval_packet_path=_resolve(root, args.oracle_local_eval_packet),
        single_axis_manifest_path=_resolve(root, args.single_axis_manifest),
        targeted_hypertraining_manifest_path=_resolve(root, args.targeted_hypertraining_manifest),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "lane_b_case_execution_available_after_hydration",
        "hydrated_family_count",
        "hydrated_visible_case_count",
        "output_count",
        "receipt_path",
        "subject_head",
    ):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
