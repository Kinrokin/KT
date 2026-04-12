from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_TRANSFER_REPORT_REL = "KT_PROD_CLEANROOM/reports/single_axis_transfer_candidate_report.json"
DEFAULT_RESIDUAL_REFRESH_REL = "KT_PROD_CLEANROOM/reports/single_axis_residual_alpha_refresh.json"
DEFAULT_PAIRWISE_PACKET_REL = "KT_PROD_CLEANROOM/reports/single_axis_pairwise_escalation_packet.json"
DEFAULT_CONTROL_VALIDATION_REL = "KT_PROD_CLEANROOM/reports/single_axis_control_validation.json"
DEFAULT_TRANSFER_GUARD_REL = "KT_PROD_CLEANROOM/reports/lab_to_counted_transfer_guard.json"

DEFAULT_TRACKED_MANIFEST = "pairwise_crucible_input_manifest.json"
DEFAULT_TRACKED_REGISTRY = "pairwise_crucible_registry.json"
DEFAULT_TRACKED_LADDER = "pairwise_pressure_ladder.json"
DEFAULT_TRACKED_FAILURES = "pairwise_expected_failure_modes.json"
DEFAULT_TRACKED_CHILD_REVISION = "child_anomaly_revision_packet.json"
DEFAULT_TRACKED_RECEIPT = "pairwise_crucible_receipt.json"

POSTURE = "PAIRWISE_CRUCIBLE_INPUTS_BOUND__SURVIVOR_SET_FROZEN__COUNTED_LANE_STILL_CLOSED"
NEXT_MOVE = "EXECUTE_PAIRWISE_CRUCIBLE_SWEEPS__LAB_ONLY"
CHILD_NEXT_MOVE = "AUTHOR_REVISED_CHILD_SINGLE_AXIS_INPUTS__LAB_ONLY"

ROUTE = "ROUTE_TO_SPECIALIST"
STATIC = "STAY_STATIC_BASELINE"
ABSTAIN = "ABSTAIN_FOR_REVIEW"

PAIRWISE_BINDINGS: Dict[str, Dict[str, Any]] = {
    "P2_SIGNAL_NOISE_SEPARATION": {
        "target_lobe_id": "lobe.p2.v1",
        "primary_axis": "AMBIGUITY_NOISE_DENSITY",
        "secondary_axis": "CROSS_DOMAIN_OVERLAY",
        "expected_policy_outcome": ROUTE,
        "pairwise_hypothesis": "P2 should preserve signal separation even when noise arrives in unfamiliar domain clothing.",
    },
    "STRATEGIST_CONSEQUENCE_CHAIN": {
        "target_lobe_id": "lobe.strategist.v1",
        "primary_axis": "HOP_DEPTH",
        "secondary_axis": "TEMPORAL_DISTORTION",
        "expected_policy_outcome": ROUTE,
        "pairwise_hypothesis": "Strategist should keep consequence order intact when deep plans are also time-warped.",
    },
    "SCOUT_SPARSE_SEARCH": {
        "target_lobe_id": "lobe.scout.v1",
        "primary_axis": "SPARSE_BRANCH_BREADTH",
        "secondary_axis": "CAUSAL_BRANCHING",
        "expected_policy_outcome": ROUTE,
        "pairwise_hypothesis": "Scout should keep the target alive when sparse search is embedded in forked causal space.",
    },
    "AUDITOR_ADMISSIBILITY_FAIL_CLOSED": {
        "target_lobe_id": "lobe.auditor.v1",
        "primary_axis": "PROOF_DISCIPLINE_BURDEN",
        "secondary_axis": "ADVERSARIAL_AMBIGUITY",
        "expected_policy_outcome": ROUTE,
        "alternate_policy_outcome": ABSTAIN,
        "pairwise_hypothesis": "Auditor should keep admissibility intact when burden and plausible ambiguity compound together.",
    },
    "BETA_SECOND_ORDER_REFRAME": {
        "target_lobe_id": "lobe.beta.v1",
        "primary_axis": "PARADOX_PRESSURE",
        "secondary_axis": "CROSS_DOMAIN_OVERLAY",
        "expected_policy_outcome": ROUTE,
        "pairwise_hypothesis": "Beta should preserve the live rival frame even when paradox arrives in mixed-domain form.",
    },
    "BOUNDARY_ABSTENTION_CONTROL": {
        "target_lobe_id": "",
        "primary_axis": "AMBIGUITY_ESCALATION",
        "secondary_axis": "CONSTITUTIONAL_BOUNDARY_PRESSURE",
        "expected_policy_outcome": ABSTAIN,
        "control_family": True,
        "pairwise_hypothesis": "Abstention should remain lawful when ambiguity and constitutional burden compound.",
    },
    "STATIC_NO_ROUTE_CONTROL": {
        "target_lobe_id": "lobe.alpha.v1",
        "primary_axis": "STATIC_HOLD_STABILITY",
        "secondary_axis": "NO_REGRESSION_GUARD",
        "expected_policy_outcome": STATIC,
        "control_family": True,
        "pairwise_hypothesis": "The static path should remain stable under a mild second-axis hold check.",
    },
}

PAIRWISE_LADDER: Tuple[Dict[str, Any], ...] = (
    {"level_id": "L1", "primary_intensity": 0.45, "secondary_intensity": 0.25, "label": "LowPair"},
    {"level_id": "L2", "primary_intensity": 0.60, "secondary_intensity": 0.40, "label": "MediumPair"},
    {"level_id": "L3", "primary_intensity": 0.75, "secondary_intensity": 0.55, "label": "HighPair"},
    {"level_id": "L4", "primary_intensity": 0.90, "secondary_intensity": 0.70, "label": "ExtremePair"},
)

PROMPT_FRAMES: Tuple[Dict[str, str], ...] = (
    {"frame_id": "PRIMARY_DECISION", "task": "Produce the primary decision path while keeping both axes visible."},
    {"frame_id": "AXIS_INTERACTION", "task": "Explain how the secondary axis should intensify the named alpha liability without blurring attribution."},
    {"frame_id": "PROOF_CHECK", "task": "State what evaluator evidence would prove the wedge survived the paired stress."},
    {"frame_id": "RECOVERY_HANDOFF", "task": "Give the safest recovery or handoff if the wrong instinct appears first."},
)


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
        raise RuntimeError("FAIL_CLOSED: pairwise input tranche could not resolve any subject head")
    if len(subject_heads) != 1:
        raise RuntimeError("FAIL_CLOSED: pairwise input tranche requires one consistent subject head")
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
    transfer_report: Dict[str, Any],
    residual_refresh: Dict[str, Any],
    pairwise_packet: Dict[str, Any],
    control_validation: Dict[str, Any],
    transfer_guard: Dict[str, Any],
) -> None:
    if str(transfer_report.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: transfer candidate report must PASS")
    if str(residual_refresh.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: residual refresh must PASS")
    if str(pairwise_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pairwise escalation packet must PASS")
    if str(control_validation.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: control validation must PASS")
    if str(transfer_guard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: transfer guard must PASS")
    if not bool(control_validation.get("controls_preserved", False)):
        raise RuntimeError("FAIL_CLOSED: controls must remain preserved before pairwise authoring")
    if str(pairwise_packet.get("next_lawful_move", "")).strip() != "AUTHOR_PAIRWISE_CRUCIBLE_INPUTS_FOR_SINGLE_AXIS_SURVIVORS__LAB_ONLY":
        raise RuntimeError("FAIL_CLOSED: pairwise packet next move mismatch")


def _file_sha256(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _stage_entries(root: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rows.append(
            {
                "path": path.relative_to(root).as_posix(),
                "bytes": int(path.stat().st_size),
                "sha256": _file_sha256(path),
            }
        )
    return rows


def _write_jsonl(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")


def _pairwise_input_row(
    *,
    family_id: str,
    source_row: Dict[str, Any],
    level: Dict[str, Any],
    frame: Dict[str, str],
) -> Dict[str, Any]:
    binding = PAIRWISE_BINDINGS[family_id]
    prompt = (
        f"Family: {family_id}. Primary axis: {binding['primary_axis']} at {level['primary_intensity']:.2f}. "
        f"Secondary axis: {binding['secondary_axis']} at {level['secondary_intensity']:.2f}. "
        f"Alpha liability: {str(source_row.get('alpha_should_lose_here_because', '')).strip()} "
        f"Pairwise hypothesis: {binding['pairwise_hypothesis']} "
        f"Expected outcome: {binding['expected_policy_outcome']}. "
        f"Task: {frame['task']}"
    )
    return {
        "case_id": f"{family_id}__{level['level_id']}__{frame['frame_id']}",
        "family_id": family_id,
        "target_lobe_id": str(source_row.get("target_lobe_id", "")).strip() or str(binding.get("target_lobe_id", "")).strip(),
        "control_family": bool(binding.get("control_family", False)),
        "primary_pressure_axis": binding["primary_axis"],
        "secondary_pressure_axis": binding["secondary_axis"],
        "primary_intensity_level_id": level["level_id"],
        "primary_intensity": level["primary_intensity"],
        "secondary_intensity": level["secondary_intensity"],
        "prompt_frame_id": frame["frame_id"],
        "preferred_policy_outcome": binding["expected_policy_outcome"],
        "alternate_policy_outcome": str(binding.get("alternate_policy_outcome", "")).strip(),
        "alpha_should_lose_here_because": str(source_row.get("alpha_should_lose_here_because", "")).strip(),
        "acceptance_metric": str(source_row.get("acceptance_metric", "")).strip(),
        "pairwise_hypothesis": binding["pairwise_hypothesis"],
        "new_admissible_eval_family": str(source_row.get("new_admissible_eval_family", "")).strip(),
        "prompt": prompt,
    }


def run_pairwise_crucible_input_tranche(
    *,
    transfer_report_path: Path,
    residual_refresh_path: Path,
    pairwise_packet_path: Path,
    control_validation_path: Path,
    transfer_guard_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    current_head = _git_head(root)

    authoritative_transfer_report_path, transfer_report = _resolve_authoritative(root, transfer_report_path.resolve(), "authoritative_single_axis_transfer_candidate_report_ref", "single-axis transfer report")
    authoritative_residual_refresh_path, residual_refresh = _resolve_authoritative(root, residual_refresh_path.resolve(), "authoritative_single_axis_residual_alpha_refresh_ref", "single-axis residual refresh")
    authoritative_pairwise_packet_path, pairwise_packet = _resolve_authoritative(root, pairwise_packet_path.resolve(), "authoritative_single_axis_pairwise_escalation_packet_ref", "single-axis pairwise packet")
    authoritative_control_validation_path, control_validation = _resolve_authoritative(root, control_validation_path.resolve(), "authoritative_single_axis_control_validation_ref", "single-axis control validation")
    authoritative_transfer_guard_path, transfer_guard = _resolve_authoritative(root, transfer_guard_path.resolve(), "authoritative_lab_to_counted_transfer_guard_ref", "transfer guard")

    _validate_inputs(
        transfer_report=transfer_report,
        residual_refresh=residual_refresh,
        pairwise_packet=pairwise_packet,
        control_validation=control_validation,
        transfer_guard=transfer_guard,
    )

    subject_head = _resolve_subject_head(
        packets=[transfer_report, residual_refresh, pairwise_packet, control_validation, transfer_guard]
    )

    target_root = authoritative_root.resolve() if authoritative_root is not None else (root / "tmp" / "cohort0_pairwise_crucible_inputs").resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    inputs_root = (target_root / "pairwise_inputs").resolve()
    inputs_root.mkdir(parents=True, exist_ok=True)

    refresh_rows = _index_rows([row for row in residual_refresh.get("rows", []) if isinstance(row, dict)], key="family_id")
    survivor_family_ids = list(pairwise_packet.get("survivor_family_ids", []))
    control_family_ids = list(residual_refresh.get("control_family_ids", []))
    family_order = survivor_family_ids + control_family_ids

    manifest_rows: List[Dict[str, Any]] = []
    registry_rows: List[Dict[str, Any]] = []
    failure_rows: List[Dict[str, Any]] = []

    for family_id in family_order:
        source_row = refresh_rows[family_id]
        binding = PAIRWISE_BINDINGS[family_id]
        input_rows = [
            _pairwise_input_row(family_id=family_id, source_row=source_row, level=level, frame=frame)
            for level in PAIRWISE_LADDER
            for frame in PROMPT_FRAMES
        ]
        family_dir = (inputs_root / family_id).resolve()
        family_dir.mkdir(parents=True, exist_ok=True)
        input_path = (family_dir / "pairwise_inputs.jsonl").resolve()
        _write_jsonl(input_path, input_rows)

        manifest_rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": str(source_row.get("target_lobe_id", "")).strip() or str(binding.get("target_lobe_id", "")).strip(),
                "control_family": bool(binding.get("control_family", False)),
                "primary_pressure_axis": binding["primary_axis"],
                "secondary_pressure_axis": binding["secondary_axis"],
                "input_relpath": input_path.relative_to(target_root).as_posix(),
                "line_count": len(input_rows),
                "sha256": _file_sha256(input_path),
                "bytes": int(input_path.stat().st_size),
                "preferred_policy_outcome": binding["expected_policy_outcome"],
                "pairwise_authorized": family_id in survivor_family_ids,
            }
        )
        registry_rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": str(source_row.get("target_lobe_id", "")).strip() or str(binding.get("target_lobe_id", "")).strip(),
                "control_family": bool(binding.get("control_family", False)),
                "primary_pressure_axis": binding["primary_axis"],
                "secondary_pressure_axis": binding["secondary_axis"],
                "pairwise_hypothesis": binding["pairwise_hypothesis"],
                "expected_policy_outcome": binding["expected_policy_outcome"],
                "alternate_policy_outcome": str(binding.get("alternate_policy_outcome", "")).strip(),
                "alpha_should_lose_here_because": str(source_row.get("alpha_should_lose_here_because", "")).strip(),
                "acceptance_metric": str(source_row.get("acceptance_metric", "")).strip(),
                "pairwise_authorized": family_id in survivor_family_ids,
            }
        )
        failure_rows.append(
            {
                "family_id": family_id,
                "control_family": bool(binding.get("control_family", False)),
                "expected_pairwise_gain": "Sharpen the named wedge without destabilizing controls." if family_id in survivor_family_ids else "Preserve rightful control behavior under the added second axis.",
                "pairwise_invalidation_condition": "Result is void if controls regress or if the second axis destroys attribution.",
                "allowed_outcomes": [
                    "SHARPENED_FURTHER_STILL_LAB_ONLY",
                    "SHARPENED_AND_TRANSFER_READY",
                    "SHARPENED_BUT_CONTROL_DESTABILIZING__RESULT_VOID",
                    "NO_ADDITIONAL_GAIN",
                    "PAIRWISE_REGRESSION",
                    "CONTAMINATION_DETECTED__RESULT_VOID",
                ],
            }
        )

    pressure_ladder = {
        "schema_id": "kt.operator.pairwise_pressure_ladder.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This ladder raises exactly one secondary axis per surviving family while preserving attribution and controls.",
        "rows": [
            {
                "family_id": family_id,
                "primary_pressure_axis": PAIRWISE_BINDINGS[family_id]["primary_axis"],
                "secondary_pressure_axis": PAIRWISE_BINDINGS[family_id]["secondary_axis"],
                "levels": list(PAIRWISE_LADDER),
            }
            for family_id in family_order
        ],
    }

    manifest = {
        "schema_id": "kt.operator.pairwise_crucible_input_manifest.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This manifest binds only pairwise lab inputs for survivor families plus preserved controls. The counted lane remains closed.",
        "source_refs": {
            "single_axis_transfer_candidate_report_ref": authoritative_transfer_report_path.as_posix(),
            "single_axis_residual_alpha_refresh_ref": authoritative_residual_refresh_path.as_posix(),
            "single_axis_pairwise_escalation_packet_ref": authoritative_pairwise_packet_path.as_posix(),
            "single_axis_control_validation_ref": authoritative_control_validation_path.as_posix(),
            "lab_to_counted_transfer_guard_ref": authoritative_transfer_guard_path.as_posix(),
        },
        "survivor_family_ids": survivor_family_ids,
        "control_family_ids": control_family_ids,
        "family_rows": manifest_rows,
        "stage_file_entries": _stage_entries(target_root),
    }
    registry = {
        "schema_id": "kt.operator.pairwise_crucible_registry.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This registry defines only pairwise lab escalation objects for survivors and controls.",
        "rows": registry_rows,
    }
    expected_failures = {
        "schema_id": "kt.operator.pairwise_expected_failure_modes.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "These are preregistered pairwise outcomes and invalidation conditions for the lab lane only.",
        "rows": failure_rows,
    }
    child_revision_packet = {
        "schema_id": "kt.operator.child_anomaly_revision_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This packet blocks child from pairwise escalation and binds one revised single-axis candidate only.",
        "family_id": "CHILD_ANOMALY_PRESERVATION",
        "blocked_reason": "Single-axis exposed the liability but did not sharpen the wedge strongly enough for pairwise escalation.",
        "observed_single_axis_metrics": {
            "route_delta_count": int(refresh_rows["CHILD_ANOMALY_PRESERVATION"]["route_delta_count"]),
            "alpha_liability_exposed_count": int(refresh_rows["CHILD_ANOMALY_PRESERVATION"]["alpha_liability_exposed_count"]),
            "wedge_sharpening_count": int(refresh_rows["CHILD_ANOMALY_PRESERVATION"]["wedge_sharpening_count"]),
        },
        "revision_diagnosis": {
            "likely_failure_mode": "WEAK_PRIMARY_AXIS_OR_WEDGE_DEFINITION",
            "overpressure_detected": False,
            "control_contamination_detected": False,
            "recommended_change": "Narrow anomaly definition and rotate the primary axis toward transformation distortion.",
        },
        "revised_single_axis_candidate": {
            "primary_pressure_axis": "TRANSFORMATION_DISTORTION",
            "secondary_context_axis": "ANOMALY_CAMOUFLAGE",
            "revised_anomaly_definition": "Preserve structurally rare features when they are partially rewritten rather than merely hidden.",
            "new_admissible_eval_family": "CHILD_ANOMALY_PRESERVATION__TRANSFORMATION_DISTORTION_REVISION",
        },
        "next_lawful_move": CHILD_NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.pairwise_crucible_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "pairwise_posture": POSTURE,
        "claim_boundary": "This receipt binds only pairwise lab input authoring. The counted lane remains closed.",
        "survivor_family_count": len(survivor_family_ids),
        "survivor_family_ids": survivor_family_ids,
        "control_family_ids": control_family_ids,
        "child_revision_required": True,
        "prohibited_moves": [
            "No composite pressure yet.",
            "No counted-lane claim update from pairwise authoring alone.",
            "No child escalation into pairwise without revised single-axis evidence.",
        ],
        "verdict_grammar": [
            "SHARPENED_FURTHER_STILL_LAB_ONLY",
            "SHARPENED_AND_TRANSFER_READY",
            "SHARPENED_BUT_CONTROL_DESTABILIZING__RESULT_VOID",
            "NO_ADDITIONAL_GAIN",
            "PAIRWISE_REGRESSION",
            "CONTAMINATION_DETECTED__RESULT_VOID",
        ],
        "next_lawful_move": NEXT_MOVE,
    }

    payloads = {
        "pairwise_crucible_input_manifest": manifest,
        "pairwise_crucible_registry": registry,
        "pairwise_pressure_ladder": pressure_ladder,
        "pairwise_expected_failure_modes": expected_failures,
        "child_anomaly_revision_packet": child_revision_packet,
        "pairwise_crucible_receipt": receipt,
    }

    for name, obj in payloads.items():
        write_json_stable((target_root / f"{name}.json").resolve(), obj)

    reports_root.mkdir(parents=True, exist_ok=True)
    carrier_names = {
        "pairwise_crucible_input_manifest": ("TRACKED_CARRIER_ONLY_PAIRWISE_CRUCIBLE_INPUT_MANIFEST", DEFAULT_TRACKED_MANIFEST),
        "pairwise_crucible_registry": ("TRACKED_CARRIER_ONLY_PAIRWISE_CRUCIBLE_REGISTRY", DEFAULT_TRACKED_REGISTRY),
        "pairwise_pressure_ladder": ("TRACKED_CARRIER_ONLY_PAIRWISE_PRESSURE_LADDER", DEFAULT_TRACKED_LADDER),
        "pairwise_expected_failure_modes": ("TRACKED_CARRIER_ONLY_PAIRWISE_EXPECTED_FAILURE_MODES", DEFAULT_TRACKED_FAILURES),
        "child_anomaly_revision_packet": ("TRACKED_CARRIER_ONLY_CHILD_ANOMALY_REVISION_PACKET", DEFAULT_TRACKED_CHILD_REVISION),
        "pairwise_crucible_receipt": ("TRACKED_CARRIER_ONLY_PAIRWISE_CRUCIBLE_RECEIPT", DEFAULT_TRACKED_RECEIPT),
    }
    for name, obj in payloads.items():
        carrier_role, tracked_name = carrier_names[name]
        tracked = dict(obj)
        tracked["carrier_surface_role"] = carrier_role
        tracked[f"authoritative_{name}_ref"] = (target_root / f"{name}.json").resolve().as_posix()
        write_json_stable((reports_root / tracked_name).resolve(), tracked)

    return payloads


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Author pairwise lab inputs for single-axis survivors and bind a child revision packet.")
    ap.add_argument("--transfer-report", default=DEFAULT_TRANSFER_REPORT_REL)
    ap.add_argument("--residual-refresh", default=DEFAULT_RESIDUAL_REFRESH_REL)
    ap.add_argument("--pairwise-packet", default=DEFAULT_PAIRWISE_PACKET_REL)
    ap.add_argument("--control-validation", default=DEFAULT_CONTROL_VALIDATION_REL)
    ap.add_argument("--transfer-guard", default=DEFAULT_TRANSFER_GUARD_REL)
    ap.add_argument("--authoritative-root", default="")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_pairwise_crucible_input_tranche(
        transfer_report_path=_resolve(root, str(args.transfer_report)),
        residual_refresh_path=_resolve(root, str(args.residual_refresh)),
        pairwise_packet_path=_resolve(root, str(args.pairwise_packet)),
        control_validation_path=_resolve(root, str(args.control_validation)),
        transfer_guard_path=_resolve(root, str(args.transfer_guard)),
        authoritative_root=_resolve(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve(root, str(args.reports_root)),
        workspace_root=root,
    )
    receipt = payload["pairwise_crucible_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "pairwise_posture": receipt["pairwise_posture"],
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
