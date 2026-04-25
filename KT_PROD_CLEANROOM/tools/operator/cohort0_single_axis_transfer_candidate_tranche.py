from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_EXEC_MATRIX_REL = "KT_PROD_CLEANROOM/reports/single_axis_crucible_execution_matrix.json"
DEFAULT_CONTROL_VALIDATION_REL = "KT_PROD_CLEANROOM/reports/single_axis_control_validation.json"
DEFAULT_TRANSFER_ELIGIBILITY_REL = "KT_PROD_CLEANROOM/reports/single_axis_transfer_eligibility.json"
DEFAULT_EXEC_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/single_axis_crucible_execution_receipt.json"
DEFAULT_ALPHA_LIABILITY_REGISTRY_REL = "KT_PROD_CLEANROOM/reports/alpha_liability_registry.json"
DEFAULT_RESIDUAL_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_residual_alpha_dominance_packet.json"
DEFAULT_TRANSFER_GUARD_REL = "KT_PROD_CLEANROOM/reports/lab_to_counted_transfer_guard.json"

DEFAULT_TRACKED_REPORT = "single_axis_transfer_candidate_report.json"
DEFAULT_TRACKED_REFRESH = "single_axis_residual_alpha_refresh.json"
DEFAULT_TRACKED_PAIRWISE = "single_axis_pairwise_escalation_packet.json"
DEFAULT_TRACKED_RECEIPT = "single_axis_transfer_candidate_receipt.json"

POSTURE = "SINGLE_AXIS_RESULTS_DIGESTED__PAIRWISE_ELIGIBLE_SET_BOUND__COUNTED_LANE_STILL_CLOSED"
NEXT_MOVE = "AUTHOR_PAIRWISE_CRUCIBLE_INPUTS_FOR_SINGLE_AXIS_SURVIVORS__LAB_ONLY"


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
    authoritative_ref = str(tracked.get(ref_field, "")).strip() if ref_field else ""
    authoritative_path = _resolve(root, authoritative_ref) if authoritative_ref else tracked_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")


def _resolve_subject_head(*, packets: Sequence[Dict[str, Any]]) -> str:
    subject_heads = {
        str(packet.get("subject_head", "")).strip()
        for packet in packets
        if isinstance(packet, dict) and str(packet.get("subject_head", "")).strip()
    }
    if not subject_heads:
        raise RuntimeError("FAIL_CLOSED: single-axis transfer tranche could not resolve any subject head")
    if len(subject_heads) != 1:
        raise RuntimeError("FAIL_CLOSED: single-axis transfer tranche requires one consistent subject head")
    return next(iter(subject_heads))


def _index_rows(rows: Sequence[Dict[str, Any]], *, key: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: expected object row while indexing")
        row_key = str(row.get(key, "")).strip()
        if not row_key:
            raise RuntimeError(f"FAIL_CLOSED: indexed row missing key {key}")
        out[row_key] = row
    return out


def _validate_inputs(
    *,
    exec_matrix: Dict[str, Any],
    control_validation: Dict[str, Any],
    transfer_eligibility: Dict[str, Any],
    exec_receipt: Dict[str, Any],
    alpha_liability_registry: Dict[str, Any],
    residual_packet: Dict[str, Any],
    transfer_guard: Dict[str, Any],
) -> None:
    if str(exec_matrix.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: single-axis execution matrix must PASS")
    if str(control_validation.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: single-axis control validation must PASS")
    if str(transfer_eligibility.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: single-axis transfer eligibility must PASS")
    if str(exec_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: single-axis execution receipt must PASS")
    if str(alpha_liability_registry.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: alpha liability registry must PASS")
    if str(residual_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: residual alpha packet must PASS")
    if str(transfer_guard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: transfer guard must PASS")
    if not bool(control_validation.get("controls_preserved", False)):
        raise RuntimeError("FAIL_CLOSED: controls must be preserved before transfer digestion")
    if str(exec_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_PAIRWISE_CRUCIBLE_INPUTS_FOR_SINGLE_AXIS_SURVIVORS__LAB_ONLY":
        raise RuntimeError("FAIL_CLOSED: execution receipt must point to pairwise authoring for survivors")


def run_single_axis_transfer_candidate_tranche(
    *,
    exec_matrix_path: Path,
    control_validation_path: Path,
    transfer_eligibility_path: Path,
    exec_receipt_path: Path,
    alpha_liability_registry_path: Path,
    residual_packet_path: Path,
    transfer_guard_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    current_head = _git_head(root)

    authoritative_exec_matrix_path, exec_matrix = _resolve_authoritative(root, exec_matrix_path.resolve(), "authoritative_single_axis_crucible_execution_matrix_ref", "single-axis execution matrix")
    authoritative_control_validation_path, control_validation = _resolve_authoritative(root, control_validation_path.resolve(), "authoritative_single_axis_control_validation_ref", "single-axis control validation")
    authoritative_transfer_eligibility_path, transfer_eligibility = _resolve_authoritative(root, transfer_eligibility_path.resolve(), "authoritative_single_axis_transfer_eligibility_ref", "single-axis transfer eligibility")
    authoritative_exec_receipt_path, exec_receipt = _resolve_authoritative(root, exec_receipt_path.resolve(), "authoritative_single_axis_crucible_execution_receipt_ref", "single-axis execution receipt")
    authoritative_alpha_liability_registry_path, alpha_liability_registry = _resolve_authoritative(root, alpha_liability_registry_path.resolve(), "authoritative_alpha_liability_registry_ref", "alpha liability registry")
    authoritative_residual_packet_path, residual_packet = _resolve_authoritative(root, residual_packet_path.resolve(), "authoritative_cohort0_residual_alpha_dominance_packet_ref", "residual alpha packet")
    authoritative_transfer_guard_path, transfer_guard = _resolve_authoritative(root, transfer_guard_path.resolve(), "authoritative_lab_to_counted_transfer_guard_ref", "transfer guard")

    _validate_inputs(
        exec_matrix=exec_matrix,
        control_validation=control_validation,
        transfer_eligibility=transfer_eligibility,
        exec_receipt=exec_receipt,
        alpha_liability_registry=alpha_liability_registry,
        residual_packet=residual_packet,
        transfer_guard=transfer_guard,
    )

    subject_head = _resolve_subject_head(
        packets=[exec_matrix, control_validation, transfer_eligibility, exec_receipt, alpha_liability_registry, residual_packet, transfer_guard]
    )

    target_root = authoritative_root.resolve() if authoritative_root is not None else (root / "tmp" / "cohort0_single_axis_transfer_candidate").resolve()
    target_root.mkdir(parents=True, exist_ok=True)

    matrix_rows = _index_rows([row for row in exec_matrix.get("family_rows", []) if isinstance(row, dict)], key="family_id")
    transfer_rows = _index_rows([row for row in transfer_eligibility.get("rows", []) if isinstance(row, dict)], key="family_id")
    liability_rows = _index_rows([row for row in alpha_liability_registry.get("rows", []) if isinstance(row, dict)], key="family_id")

    report_rows: List[Dict[str, Any]] = []
    refresh_rows: List[Dict[str, Any]] = []
    pairwise_rows: List[Dict[str, Any]] = []

    survivor_family_ids = list(transfer_eligibility.get("survivor_family_ids", []))
    blocked_family_ids = list(transfer_eligibility.get("blocked_family_ids", []))

    for family_id, transfer_row in transfer_rows.items():
        matrix_row = matrix_rows[family_id]
        liability_row = liability_rows.get(family_id, {})
        control_family = bool(transfer_row.get("control_family", False))
        transfer_status = str(transfer_row.get("transfer_candidate_status", "")).strip()

        if control_family:
            disposition = "PRESERVE_CONTROL"
            axis_result = "CONTROL_VALIDATED"
            clarity = "CONTROL_ONLY"
        elif transfer_status == "TRANSFER_CANDIDATE_ADMISSIBLE_FOR_COUNTED_LANE":
            disposition = "PROMOTE_TO_PAIRWISE_LAB_ESCALATION"
            axis_result = "SHARPENED_ON_INTENDED_AXIS"
            clarity = "STRENGTHENED"
        else:
            disposition = "KEEP_LAB_ONLY_REVISE_SINGLE_AXIS"
            axis_result = "PARTIAL_SIGNAL_REVISE_AXIS_OR_INTENSITY"
            clarity = "STILL_WEAK"

        report_rows.append(
            {
                "family_id": family_id,
                "control_family": control_family,
                "target_lobe_id": str(transfer_row.get("target_lobe_id", "")).strip(),
                "transfer_candidate_status": transfer_status,
                "disposition": disposition,
                "sharpened_on_intended_axis": axis_result == "SHARPENED_ON_INTENDED_AXIS",
                "anti_alpha_liability_clarity": clarity,
                "route_delta_count": int(matrix_row.get("route_delta_count", 0)),
                "alpha_liability_exposed_count": int(matrix_row.get("alpha_liability_exposed_count", 0)),
                "wedge_sharpening_count": int(matrix_row.get("wedge_sharpening_count", 0)),
                "counts_as_counted_progress_now": False,
                "next_lab_action": str(transfer_row.get("next_lab_action", "")).strip(),
            }
        )

        refresh_rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": str(transfer_row.get("target_lobe_id", "")).strip(),
                "control_family": control_family,
                "alpha_should_lose_here_because": str(liability_row.get("alpha_should_lose_here_because", "")).strip(),
                "acceptance_metric": str(liability_row.get("acceptance_metric", "")).strip(),
                "single_axis_primary_pressure_axis": str(matrix_row.get("primary_pressure_axis", "")).strip(),
                "single_axis_result": axis_result,
                "anti_alpha_liability_clarity": clarity,
                "transfer_candidate_status": transfer_status,
                "route_delta_count": int(matrix_row.get("route_delta_count", 0)),
                "alpha_liability_exposed_count": int(matrix_row.get("alpha_liability_exposed_count", 0)),
                "wedge_sharpening_count": int(matrix_row.get("wedge_sharpening_count", 0)),
                "next_focus": (
                    "AUTHOR_PAIRWISE_CRUCIBLE_INPUTS"
                    if transfer_status == "TRANSFER_CANDIDATE_ADMISSIBLE_FOR_COUNTED_LANE"
                    else ("PRESERVE_CONTROL" if control_family else "REVISE_SINGLE_AXIS_AXIS_OR_INTENSITY")
                ),
            }
        )

        if (not control_family) and transfer_status == "TRANSFER_CANDIDATE_ADMISSIBLE_FOR_COUNTED_LANE":
            pairwise_rows.append(
                {
                    "family_id": family_id,
                    "target_lobe_id": str(transfer_row.get("target_lobe_id", "")).strip(),
                    "named_wedge_sharpening": str(transfer_row.get("named_wedge_sharpening", "")).strip(),
                    "named_anti_alpha_liability": str(transfer_row.get("named_anti_alpha_liability", "")).strip(),
                    "measurable_route_delta_hypothesis": str(transfer_row.get("measurable_route_delta_hypothesis", "")).strip(),
                    "new_admissible_eval_family": str(transfer_row.get("new_admissible_eval_family", "")).strip(),
                    "pairwise_authorized": True,
                    "pairwise_rationale": "Single-axis sweep satisfied the transfer guard strongly enough to justify pairwise lab escalation.",
                }
            )

    transfer_report = {
        "schema_id": "kt.operator.single_axis_transfer_candidate_report.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This report digests single-axis outcomes into hard lab-only transfer decisions. It does not reopen the counted lane.",
        "controls_preserved": bool(control_validation.get("controls_preserved", False)),
        "survivor_family_ids": survivor_family_ids,
        "blocked_family_ids": blocked_family_ids,
        "rows": report_rows,
    }
    residual_refresh = {
        "schema_id": "kt.operator.single_axis_residual_alpha_refresh.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This refresh records post-single-axis observations against the residual-alpha map. It does not replace the preregistered alpha liability registry.",
        "strengthened_family_ids": survivor_family_ids,
        "revise_family_ids": blocked_family_ids,
        "control_family_ids": [row["family_id"] for row in report_rows if row["control_family"]],
        "rows": refresh_rows,
    }
    pairwise_packet = {
        "schema_id": "kt.operator.single_axis_pairwise_escalation_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This packet authorizes only pairwise lab escalation for survivor families. Counted-lane re-entry remains blocked pending later ordered proof work.",
        "survivor_family_ids": survivor_family_ids,
        "blocked_family_ids": blocked_family_ids,
        "controls_preserved": bool(control_validation.get("controls_preserved", False)),
        "rows": pairwise_rows,
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.single_axis_transfer_candidate_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "single_axis_transfer_posture": POSTURE,
        "claim_boundary": "This receipt binds only the post-single-axis decision layer. The counted lane remains closed.",
        "survivor_family_count": len(survivor_family_ids),
        "survivor_family_ids": survivor_family_ids,
        "blocked_family_count": len(blocked_family_ids),
        "blocked_family_ids": blocked_family_ids,
        "controls_preserved": bool(control_validation.get("controls_preserved", False)),
        "next_lawful_move": NEXT_MOVE,
    }

    payloads = {
        "single_axis_transfer_candidate_report": transfer_report,
        "single_axis_residual_alpha_refresh": residual_refresh,
        "single_axis_pairwise_escalation_packet": pairwise_packet,
        "single_axis_transfer_candidate_receipt": receipt,
    }

    for name, obj in payloads.items():
        write_json_stable((target_root / f"{name}.json").resolve(), obj)

    reports_root.mkdir(parents=True, exist_ok=True)
    carrier_names = {
        "single_axis_transfer_candidate_report": ("TRACKED_CARRIER_ONLY_SINGLE_AXIS_TRANSFER_CANDIDATE_REPORT", DEFAULT_TRACKED_REPORT),
        "single_axis_residual_alpha_refresh": ("TRACKED_CARRIER_ONLY_SINGLE_AXIS_RESIDUAL_ALPHA_REFRESH", DEFAULT_TRACKED_REFRESH),
        "single_axis_pairwise_escalation_packet": ("TRACKED_CARRIER_ONLY_SINGLE_AXIS_PAIRWISE_ESCALATION_PACKET", DEFAULT_TRACKED_PAIRWISE),
        "single_axis_transfer_candidate_receipt": ("TRACKED_CARRIER_ONLY_SINGLE_AXIS_TRANSFER_CANDIDATE_RECEIPT", DEFAULT_TRACKED_RECEIPT),
    }
    for name, obj in payloads.items():
        carrier_role, tracked_name = carrier_names[name]
        tracked = dict(obj)
        tracked["carrier_surface_role"] = carrier_role
        tracked[f"authoritative_{name}_ref"] = (target_root / f"{name}.json").resolve().as_posix()
        write_json_stable((reports_root / tracked_name).resolve(), tracked)

    return payloads


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Digest executed single-axis sweeps into hard transfer decisions and survivor-only pairwise authorization.")
    ap.add_argument("--execution-matrix", default=DEFAULT_EXEC_MATRIX_REL)
    ap.add_argument("--control-validation", default=DEFAULT_CONTROL_VALIDATION_REL)
    ap.add_argument("--transfer-eligibility", default=DEFAULT_TRANSFER_ELIGIBILITY_REL)
    ap.add_argument("--execution-receipt", default=DEFAULT_EXEC_RECEIPT_REL)
    ap.add_argument("--alpha-liability-registry", default=DEFAULT_ALPHA_LIABILITY_REGISTRY_REL)
    ap.add_argument("--residual-packet", default=DEFAULT_RESIDUAL_PACKET_REL)
    ap.add_argument("--transfer-guard", default=DEFAULT_TRANSFER_GUARD_REL)
    ap.add_argument("--authoritative-root", default="")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_single_axis_transfer_candidate_tranche(
        exec_matrix_path=_resolve(root, str(args.execution_matrix)),
        control_validation_path=_resolve(root, str(args.control_validation)),
        transfer_eligibility_path=_resolve(root, str(args.transfer_eligibility)),
        exec_receipt_path=_resolve(root, str(args.execution_receipt)),
        alpha_liability_registry_path=_resolve(root, str(args.alpha_liability_registry)),
        residual_packet_path=_resolve(root, str(args.residual_packet)),
        transfer_guard_path=_resolve(root, str(args.transfer_guard)),
        authoritative_root=_resolve(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve(root, str(args.reports_root)),
        workspace_root=root,
    )
    receipt = payload["single_axis_transfer_candidate_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "single_axis_transfer_posture": receipt["single_axis_transfer_posture"],
                "survivor_family_count": receipt["survivor_family_count"],
                "next_lawful_move": receipt["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
