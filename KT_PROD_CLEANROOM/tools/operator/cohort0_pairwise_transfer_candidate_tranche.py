from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_EXEC_MATRIX_REL = "KT_PROD_CLEANROOM/reports/pairwise_crucible_execution_matrix.json"
DEFAULT_CONTROL_VALIDATION_REL = "KT_PROD_CLEANROOM/reports/pairwise_control_validation.json"
DEFAULT_PHASE_TRANSITIONS_REL = "KT_PROD_CLEANROOM/reports/pairwise_phase_transition_report.json"
DEFAULT_ROUTE_ECONOMICS_REL = "KT_PROD_CLEANROOM/reports/pairwise_route_economics_scorecard.json"
DEFAULT_TRANSFER_ELIGIBILITY_REL = "KT_PROD_CLEANROOM/reports/pairwise_transfer_eligibility.json"
DEFAULT_EXEC_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/pairwise_crucible_execution_receipt.json"
DEFAULT_SINGLE_AXIS_REFRESH_REL = "KT_PROD_CLEANROOM/reports/single_axis_residual_alpha_refresh.json"
DEFAULT_ALPHA_LIABILITY_REGISTRY_REL = "KT_PROD_CLEANROOM/reports/alpha_liability_registry.json"
DEFAULT_RESIDUAL_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_residual_alpha_dominance_packet.json"
DEFAULT_TRANSFER_GUARD_REL = "KT_PROD_CLEANROOM/reports/lab_to_counted_transfer_guard.json"

DEFAULT_TRACKED_REPORT = "pairwise_transfer_candidate_report.json"
DEFAULT_TRACKED_REFRESH = "pairwise_residual_alpha_refresh.json"
DEFAULT_TRACKED_AUGMENTATION = "pairwise_counted_lane_augmentation_packet.json"
DEFAULT_TRACKED_RECEIPT = "pairwise_transfer_candidate_receipt.json"

POSTURE = "PAIRWISE_RESULTS_DIGESTED__COUNTED_LANE_AUGMENTATION_SET_BOUND__COUNTED_LANE_STILL_CLOSED"
NEXT_MOVE_READY = "AUTHOR_RECOMPOSED_COUNTED_LANE_AUGMENTATION_TRANCHE__ORDERED_PROOF_ONLY"
NEXT_MOVE_LAB = "AUTHOR_PAIRWISE_REVISION_OR_COMPOSITE_ESCALATION_PACKET__LAB_ONLY"


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
        raise RuntimeError("FAIL_CLOSED: pairwise transfer tranche could not resolve any subject head")
    if len(subject_heads) != 1:
        raise RuntimeError("FAIL_CLOSED: pairwise transfer tranche requires one consistent subject head")
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
    phase_transitions: Dict[str, Any],
    route_economics: Dict[str, Any],
    transfer_eligibility: Dict[str, Any],
    exec_receipt: Dict[str, Any],
    single_axis_refresh: Dict[str, Any],
    alpha_liability_registry: Dict[str, Any],
    residual_packet: Dict[str, Any],
    transfer_guard: Dict[str, Any],
) -> None:
    if str(exec_matrix.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pairwise execution matrix must PASS")
    if str(control_validation.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pairwise control validation must PASS")
    if str(phase_transitions.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pairwise phase transition report must PASS")
    if str(route_economics.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pairwise route economics scorecard must PASS")
    if str(transfer_eligibility.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pairwise transfer eligibility must PASS")
    if str(exec_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pairwise execution receipt must PASS")
    if str(exec_receipt.get("next_lawful_move", "")).strip() != "DIGEST_PAIRWISE_RESULTS_AND_BIND_TRANSFER_CANDIDATES__LAB_ONLY":
        raise RuntimeError("FAIL_CLOSED: pairwise execution receipt must point to digestion")
    if str(single_axis_refresh.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: single-axis refresh must PASS")
    if str(alpha_liability_registry.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: alpha liability registry must PASS")
    if str(residual_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: residual alpha packet must PASS")
    if str(transfer_guard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: transfer guard must PASS")


def _augmentation_eval_family(liability_row: Dict[str, Any], family_id: str) -> str:
    base = str(liability_row.get("new_admissible_eval_family", "")).strip()
    if base:
        return f"{base}__PAIRWISE_TRANSFER_CANDIDATE"
    return f"{family_id}__PAIRWISE_TRANSFER_CANDIDATE"


def run_pairwise_transfer_candidate_tranche(
    *,
    exec_matrix_path: Path,
    control_validation_path: Path,
    phase_transitions_path: Path,
    route_economics_path: Path,
    transfer_eligibility_path: Path,
    exec_receipt_path: Path,
    single_axis_refresh_path: Path,
    alpha_liability_registry_path: Path,
    residual_packet_path: Path,
    transfer_guard_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    current_head = _git_head(root)

    authoritative_exec_matrix_path, exec_matrix = _resolve_authoritative(root, exec_matrix_path.resolve(), "authoritative_pairwise_crucible_execution_matrix_ref", "pairwise execution matrix")
    authoritative_control_validation_path, control_validation = _resolve_authoritative(root, control_validation_path.resolve(), "authoritative_pairwise_control_validation_ref", "pairwise control validation")
    authoritative_phase_transitions_path, phase_transitions = _resolve_authoritative(root, phase_transitions_path.resolve(), "authoritative_pairwise_phase_transition_report_ref", "pairwise phase transitions")
    authoritative_route_economics_path, route_economics = _resolve_authoritative(root, route_economics_path.resolve(), "authoritative_pairwise_route_economics_scorecard_ref", "pairwise route economics")
    authoritative_transfer_eligibility_path, transfer_eligibility = _resolve_authoritative(root, transfer_eligibility_path.resolve(), "authoritative_pairwise_transfer_eligibility_ref", "pairwise transfer eligibility")
    authoritative_exec_receipt_path, exec_receipt = _resolve_authoritative(root, exec_receipt_path.resolve(), "authoritative_pairwise_crucible_execution_receipt_ref", "pairwise execution receipt")
    authoritative_single_axis_refresh_path, single_axis_refresh = _resolve_authoritative(root, single_axis_refresh_path.resolve(), "authoritative_single_axis_residual_alpha_refresh_ref", "single-axis refresh")
    authoritative_alpha_liability_registry_path, alpha_liability_registry = _resolve_authoritative(root, alpha_liability_registry_path.resolve(), "authoritative_alpha_liability_registry_ref", "alpha liability registry")
    authoritative_residual_packet_path, residual_packet = _resolve_authoritative(root, residual_packet_path.resolve(), "authoritative_cohort0_residual_alpha_dominance_packet_ref", "residual alpha packet")
    authoritative_transfer_guard_path, transfer_guard = _resolve_authoritative(root, transfer_guard_path.resolve(), "authoritative_lab_to_counted_transfer_guard_ref", "transfer guard")

    _validate_inputs(
        exec_matrix=exec_matrix,
        control_validation=control_validation,
        phase_transitions=phase_transitions,
        route_economics=route_economics,
        transfer_eligibility=transfer_eligibility,
        exec_receipt=exec_receipt,
        single_axis_refresh=single_axis_refresh,
        alpha_liability_registry=alpha_liability_registry,
        residual_packet=residual_packet,
        transfer_guard=transfer_guard,
    )

    subject_head = _resolve_subject_head(
        packets=[
            exec_matrix,
            control_validation,
            phase_transitions,
            route_economics,
            transfer_eligibility,
            exec_receipt,
            single_axis_refresh,
            alpha_liability_registry,
            residual_packet,
            transfer_guard,
        ]
    )
    target_root = authoritative_root.resolve() if authoritative_root is not None else (root / "tmp" / "cohort0_pairwise_transfer_candidate").resolve()
    target_root.mkdir(parents=True, exist_ok=True)

    matrix_rows = _index_rows([row for row in exec_matrix.get("family_rows", []) if isinstance(row, dict)], key="family_id")
    phase_rows = _index_rows([row for row in phase_transitions.get("rows", []) if isinstance(row, dict)], key="family_id")
    econ_rows = _index_rows([row for row in route_economics.get("rows", []) if isinstance(row, dict)], key="family_id")
    transfer_rows = _index_rows([row for row in transfer_eligibility.get("rows", []) if isinstance(row, dict)], key="family_id")
    single_axis_rows = _index_rows([row for row in single_axis_refresh.get("rows", []) if isinstance(row, dict)], key="family_id")
    liability_rows = _index_rows([row for row in alpha_liability_registry.get("rows", []) if isinstance(row, dict)], key="family_id")

    controls_preserved = bool(control_validation.get("controls_preserved", False))
    report_rows: List[Dict[str, Any]] = []
    refresh_rows: List[Dict[str, Any]] = []
    augmentation_rows: List[Dict[str, Any]] = []
    ready_family_ids: List[str] = []
    lab_hold_family_ids: List[str] = []

    for family_id, transfer_row in transfer_rows.items():
        matrix_row = matrix_rows[family_id]
        phase_row = phase_rows[family_id]
        econ_row = econ_rows[family_id]
        baseline_row = single_axis_rows.get(family_id, {})
        liability_row = liability_rows.get(family_id, {})
        control_family = bool(transfer_row.get("control_family", False))

        route_delta_delta = int(matrix_row.get("route_delta_count", 0)) - int(baseline_row.get("route_delta_count", 0))
        wedge_delta = int(matrix_row.get("wedge_sharpening_count", 0)) - int(baseline_row.get("wedge_sharpening_count", 0))
        alpha_delta = int(matrix_row.get("alpha_liability_exposed_count", 0)) - int(baseline_row.get("alpha_liability_exposed_count", 0))
        contamination_detected = int(matrix_row.get("contamination_count", 0)) > 0
        provisional_ready = str(transfer_row.get("provisional_transfer_candidate_status", "")).strip() == "PROVISIONAL_TRANSFER_READY"

        if control_family:
            verdict = "CONTROL_PRESERVED"
            disposition = "PRESERVE_CONTROL"
        elif not controls_preserved:
            verdict = "PAIRWISE_DESTABILIZED_A_CONTROL__RESULT_VOID"
            disposition = "RESULT_VOID_CONTROL_DESTABILIZED"
        elif contamination_detected:
            verdict = "PAIRWISE_INVALID_DUE_TO_CONTAMINATION_OR_OVERPRESSURE"
            disposition = "RESULT_VOID_CONTAMINATION"
        elif provisional_ready and route_delta_delta > 0 and wedge_delta > 0:
            verdict = "PAIRWISE_SHARPENED_AND_TRANSFER_ELIGIBLE"
            disposition = "PROMOTE_TO_COUNTED_LANE_AUGMENTATION"
        elif route_delta_delta < 0 or wedge_delta < 0:
            verdict = "PAIRWISE_REGRESSION"
            disposition = "KEEP_IN_LAB_REGRESSION"
        elif route_delta_delta == 0 and wedge_delta == 0:
            verdict = "PAIRWISE_ADDED_NO_VALUE_OVER_SINGLE_AXIS"
            disposition = "KEEP_IN_LAB_NO_VALUE"
        else:
            verdict = "PAIRWISE_SHARPENED_FURTHER__STILL_LAB_ONLY"
            disposition = "KEEP_IN_LAB_MORE_SHARPENING"

        if verdict == "PAIRWISE_SHARPENED_AND_TRANSFER_ELIGIBLE":
            ready_family_ids.append(family_id)
            augmentation_rows.append(
                {
                    "family_id": family_id,
                    "target_lobe_id": str(transfer_row.get("target_lobe_id", "")).strip(),
                    "named_wedge_sharpening": f"PAIRWISE_SHARPENED__{str(matrix_row.get('primary_pressure_axis', '')).strip()}__X__{str(matrix_row.get('secondary_pressure_axis', '')).strip()}",
                    "named_anti_alpha_liability": str(liability_row.get("alpha_should_lose_here_because", "")).strip(),
                    "measurable_route_delta_hypothesis": f"PAIRWISE_ROUTE_DELTA_DELTA={route_delta_delta:+d}; WEDGE_DELTA={wedge_delta:+d}; ALPHA_DELTA={alpha_delta:+d}",
                    "new_admissible_eval_family": _augmentation_eval_family(liability_row, family_id),
                    "phase_transition_level_id": str(phase_row.get("transition_level_id", "")).strip(),
                    "net_route_value_score": float(econ_row.get("net_route_value_score", 0.0)),
                    "augmentation_authorized": True,
                }
            )
        elif not control_family:
            lab_hold_family_ids.append(family_id)

        report_rows.append(
            {
                "family_id": family_id,
                "control_family": control_family,
                "target_lobe_id": str(transfer_row.get("target_lobe_id", "")).strip(),
                "pairwise_verdict": verdict,
                "disposition": disposition,
                "route_delta_delta_vs_single_axis": route_delta_delta,
                "wedge_delta_vs_single_axis": wedge_delta,
                "alpha_liability_delta_vs_single_axis": alpha_delta,
                "phase_transition_detected": bool(phase_row.get("transition_detected", False)),
                "transition_level_id": str(phase_row.get("transition_level_id", "")).strip(),
                "net_route_value_score": float(econ_row.get("net_route_value_score", 0.0)),
                "counts_as_counted_progress_now": False,
            }
        )
        refresh_rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": str(transfer_row.get("target_lobe_id", "")).strip(),
                "control_family": control_family,
                "pairwise_verdict": verdict,
                "route_delta_delta_vs_single_axis": route_delta_delta,
                "wedge_delta_vs_single_axis": wedge_delta,
                "alpha_liability_delta_vs_single_axis": alpha_delta,
                "phase_transition_level_id": str(phase_row.get("transition_level_id", "")).strip(),
                "net_route_value_score": float(econ_row.get("net_route_value_score", 0.0)),
                "next_focus": (
                    "AUTHOR_COUNTED_LANE_AUGMENTATION"
                    if verdict == "PAIRWISE_SHARPENED_AND_TRANSFER_ELIGIBLE"
                    else ("PRESERVE_CONTROL" if control_family else "KEEP_IN_LAB_OR_REVISE_PAIRWISE"))
            }
        )

    next_move = NEXT_MOVE_READY if ready_family_ids else NEXT_MOVE_LAB

    transfer_report = {
        "schema_id": "kt.operator.pairwise_transfer_candidate_report.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This report digests pairwise lab results into hard transfer and hold decisions. The counted lane remains closed until a later ordered augmentation tranche runs.",
        "controls_preserved": controls_preserved,
        "ready_family_ids": ready_family_ids,
        "lab_hold_family_ids": lab_hold_family_ids,
        "rows": report_rows,
    }
    refresh = {
        "schema_id": "kt.operator.pairwise_residual_alpha_refresh.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This refresh records post-pairwise observations against the residual-alpha map. It does not by itself reopen the counted lane.",
        "ready_family_ids": ready_family_ids,
        "lab_hold_family_ids": lab_hold_family_ids,
        "rows": refresh_rows,
    }
    augmentation = {
        "schema_id": "kt.operator.pairwise_counted_lane_augmentation_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This packet binds only candidate families for a later ordered counted-lane augmentation tranche. It does not itself reopen the counted lane.",
        "ready_family_ids": ready_family_ids,
        "rows": augmentation_rows,
        "next_lawful_move": next_move,
    }
    receipt = {
        "schema_id": "kt.operator.pairwise_transfer_candidate_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "pairwise_transfer_posture": POSTURE,
        "claim_boundary": "This receipt binds only the post-pairwise decision layer. Counted-lane superiority and Gate movement remain blocked pending later ordered proof work.",
        "ready_family_count": len(ready_family_ids),
        "ready_family_ids": ready_family_ids,
        "lab_hold_family_count": len(lab_hold_family_ids),
        "lab_hold_family_ids": lab_hold_family_ids,
        "controls_preserved": controls_preserved,
        "next_lawful_move": next_move,
    }

    payloads = {
        "pairwise_transfer_candidate_report": transfer_report,
        "pairwise_residual_alpha_refresh": refresh,
        "pairwise_counted_lane_augmentation_packet": augmentation,
        "pairwise_transfer_candidate_receipt": receipt,
    }

    for name, obj in payloads.items():
        write_json_stable((target_root / f"{name}.json").resolve(), obj)

    reports_root.mkdir(parents=True, exist_ok=True)
    carrier_names = {
        "pairwise_transfer_candidate_report": ("TRACKED_CARRIER_ONLY_PAIRWISE_TRANSFER_CANDIDATE_REPORT", DEFAULT_TRACKED_REPORT),
        "pairwise_residual_alpha_refresh": ("TRACKED_CARRIER_ONLY_PAIRWISE_RESIDUAL_ALPHA_REFRESH", DEFAULT_TRACKED_REFRESH),
        "pairwise_counted_lane_augmentation_packet": ("TRACKED_CARRIER_ONLY_PAIRWISE_COUNTED_LANE_AUGMENTATION_PACKET", DEFAULT_TRACKED_AUGMENTATION),
        "pairwise_transfer_candidate_receipt": ("TRACKED_CARRIER_ONLY_PAIRWISE_TRANSFER_CANDIDATE_RECEIPT", DEFAULT_TRACKED_RECEIPT),
    }
    for name, obj in payloads.items():
        carrier_role, tracked_name = carrier_names[name]
        tracked = dict(obj)
        tracked["carrier_surface_role"] = carrier_role
        tracked[f"authoritative_{name}_ref"] = (target_root / f"{name}.json").resolve().as_posix()
        write_json_stable((reports_root / tracked_name).resolve(), tracked)

    return payloads


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Digest pairwise lab results into hard transfer decisions and counted-lane augmentation candidates while keeping the counted lane closed.")
    ap.add_argument("--execution-matrix", default=DEFAULT_EXEC_MATRIX_REL)
    ap.add_argument("--control-validation", default=DEFAULT_CONTROL_VALIDATION_REL)
    ap.add_argument("--phase-transitions", default=DEFAULT_PHASE_TRANSITIONS_REL)
    ap.add_argument("--route-economics", default=DEFAULT_ROUTE_ECONOMICS_REL)
    ap.add_argument("--transfer-eligibility", default=DEFAULT_TRANSFER_ELIGIBILITY_REL)
    ap.add_argument("--execution-receipt", default=DEFAULT_EXEC_RECEIPT_REL)
    ap.add_argument("--single-axis-refresh", default=DEFAULT_SINGLE_AXIS_REFRESH_REL)
    ap.add_argument("--alpha-liability-registry", default=DEFAULT_ALPHA_LIABILITY_REGISTRY_REL)
    ap.add_argument("--residual-packet", default=DEFAULT_RESIDUAL_PACKET_REL)
    ap.add_argument("--transfer-guard", default=DEFAULT_TRANSFER_GUARD_REL)
    ap.add_argument("--authoritative-root", default="")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_pairwise_transfer_candidate_tranche(
        exec_matrix_path=_resolve(root, str(args.execution_matrix)),
        control_validation_path=_resolve(root, str(args.control_validation)),
        phase_transitions_path=_resolve(root, str(args.phase_transitions)),
        route_economics_path=_resolve(root, str(args.route_economics)),
        transfer_eligibility_path=_resolve(root, str(args.transfer_eligibility)),
        exec_receipt_path=_resolve(root, str(args.execution_receipt)),
        single_axis_refresh_path=_resolve(root, str(args.single_axis_refresh)),
        alpha_liability_registry_path=_resolve(root, str(args.alpha_liability_registry)),
        residual_packet_path=_resolve(root, str(args.residual_packet)),
        transfer_guard_path=_resolve(root, str(args.transfer_guard)),
        authoritative_root=_resolve(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve(root, str(args.reports_root)),
        workspace_root=root,
    )
    receipt = payload["pairwise_transfer_candidate_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "pairwise_transfer_posture": receipt["pairwise_transfer_posture"],
                "ready_family_count": receipt["ready_family_count"],
                "next_lawful_move": receipt["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
