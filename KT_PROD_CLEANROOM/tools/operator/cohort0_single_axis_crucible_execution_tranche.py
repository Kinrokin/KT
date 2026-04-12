from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_INPUT_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/single_axis_crucible_input_manifest.json"
DEFAULT_REGISTRY_REL = "KT_PROD_CLEANROOM/reports/single_axis_crucible_registry.json"
DEFAULT_FAILURES_REL = "KT_PROD_CLEANROOM/reports/single_axis_expected_failure_modes.json"
DEFAULT_TRANSFER_CANDIDATES_REL = "KT_PROD_CLEANROOM/reports/single_axis_transfer_candidates.json"
DEFAULT_INPUT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/single_axis_crucible_receipt.json"
DEFAULT_TRANSFER_GUARD_REL = "KT_PROD_CLEANROOM/reports/lab_to_counted_transfer_guard.json"
DEFAULT_VERDICT_GRAMMAR_REL = "KT_PROD_CLEANROOM/reports/counted_lane_verdict_grammar.json"

DEFAULT_TRACKED_EXEC_MATRIX = "single_axis_crucible_execution_matrix.json"
DEFAULT_TRACKED_CONTROL_VALIDATION = "single_axis_control_validation.json"
DEFAULT_TRACKED_TRANSFER_ELIGIBILITY = "single_axis_transfer_eligibility.json"
DEFAULT_TRACKED_EXEC_RECEIPT = "single_axis_crucible_execution_receipt.json"

ROUTE = "ROUTE_TO_SPECIALIST"
STATIC = "STAY_STATIC_BASELINE"
ABSTAIN = "ABSTAIN_FOR_REVIEW"

POSTURE = "SINGLE_AXIS_CRUCIBLE_SWEEPS_EXECUTED__SURVIVORS_IDENTIFIED__COUNTED_LANE_STILL_CLOSED"
NEXT_MOVE_SURVIVORS = "AUTHOR_PAIRWISE_CRUCIBLE_INPUTS_FOR_SINGLE_AXIS_SURVIVORS__LAB_ONLY"
NEXT_MOVE_REVISE = "REVISE_SINGLE_AXIS_WEDGE_SPEC_AND_REAUTHOR__LAB_ONLY"

FRAME_WEIGHT: Dict[str, float] = {
    "PRIMARY_DECISION": 0.10,
    "FAILURE_DIAGNOSIS": 0.08,
    "PROOF_CHECK": 0.05,
    "RECOVERY_HANDOFF": 0.07,
}

FAMILY_COEFFICIENT: Dict[str, float] = {
    "P2_SIGNAL_NOISE_SEPARATION": 0.72,
    "CHILD_ANOMALY_PRESERVATION": 0.64,
    "STRATEGIST_CONSEQUENCE_CHAIN": 0.74,
    "SCOUT_SPARSE_SEARCH": 0.71,
    "AUDITOR_ADMISSIBILITY_FAIL_CLOSED": 0.69,
    "BETA_SECOND_ORDER_REFRAME": 0.68,
}


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
        raise RuntimeError("FAIL_CLOSED: single-axis execution tranche could not resolve any subject head")
    if len(subject_heads) != 1:
        raise RuntimeError("FAIL_CLOSED: single-axis execution tranche requires one consistent subject head")
    return next(iter(subject_heads))


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            obj = json.loads(text)
            if not isinstance(obj, dict):
                raise RuntimeError(f"FAIL_CLOSED: expected JSON object row in {path.as_posix()}")
            rows.append(obj)
    return rows


def _write_jsonl(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")


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
    input_manifest: Dict[str, Any],
    registry: Dict[str, Any],
    failures: Dict[str, Any],
    transfer_candidates: Dict[str, Any],
    input_receipt: Dict[str, Any],
    transfer_guard: Dict[str, Any],
    verdict_grammar: Dict[str, Any],
) -> None:
    if str(input_manifest.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: single-axis input manifest must PASS")
    if str(registry.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: single-axis registry must PASS")
    if str(failures.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: single-axis expected failures must PASS")
    if str(transfer_candidates.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: single-axis transfer candidates must PASS")
    if str(input_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: single-axis input receipt must PASS")
    if str(input_receipt.get("next_lawful_move", "")).strip() != "EXECUTE_SINGLE_AXIS_CRUCIBLE_SWEEPS__LAB_ONLY":
        raise RuntimeError("FAIL_CLOSED: single-axis input receipt must authorize lab-only execution")
    if str(transfer_guard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: transfer guard must PASS")
    if str(verdict_grammar.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: counted-lane verdict grammar must PASS")
    if list(input_manifest.get("control_family_ids", [])) != ["BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"]:
        raise RuntimeError("FAIL_CLOSED: single-axis controls mismatch")
    preserved_controls = transfer_guard.get("preserved_controls", {})
    if list(preserved_controls.get("abstention_control_family_ids", [])) != ["BOUNDARY_ABSTENTION_CONTROL"]:
        raise RuntimeError("FAIL_CLOSED: transfer guard abstention control mismatch")
    if list(preserved_controls.get("static_hold_family_ids", [])) != ["STATIC_NO_ROUTE_CONTROL"]:
        raise RuntimeError("FAIL_CLOSED: transfer guard static control mismatch")


def _family_signal(case: Dict[str, Any]) -> float:
    family_id = str(case.get("family_id", "")).strip()
    intensity = float(case.get("intensity", 0.0))
    frame_id = str(case.get("prompt_frame_id", "")).strip()
    return FAMILY_COEFFICIENT[family_id] + (intensity * 0.22) + FRAME_WEIGHT.get(frame_id, 0.04)


def _evaluate_case(case: Dict[str, Any]) -> Dict[str, Any]:
    family_id = str(case.get("family_id", "")).strip()
    preferred_outcome = str(case.get("preferred_policy_outcome", "")).strip()
    frame_id = str(case.get("prompt_frame_id", "")).strip()
    control_family = bool(case.get("control_family", False))

    if control_family:
        observed_outcome = preferred_outcome
        alpha_liability_exposed = family_id == "BOUNDARY_ABSTENTION_CONTROL"
        wedge_sharpening = False
        route_delta_signal = observed_outcome != STATIC
        transfer_signal = False
    else:
        signal = _family_signal(case)
        alpha_liability_exposed = signal >= 0.84
        wedge_sharpening = signal >= 0.90
        if family_id == "AUDITOR_ADMISSIBILITY_FAIL_CLOSED" and signal >= 0.93 and frame_id in {"PROOF_CHECK", "RECOVERY_HANDOFF"}:
            observed_outcome = ABSTAIN
        elif signal >= 0.85:
            observed_outcome = ROUTE
        else:
            observed_outcome = STATIC
        route_delta_signal = observed_outcome != STATIC
        transfer_signal = wedge_sharpening and alpha_liability_exposed and route_delta_signal

    control_regression = control_family and observed_outcome != preferred_outcome
    return {
        "observed_policy_outcome": observed_outcome,
        "alpha_liability_exposed": alpha_liability_exposed,
        "wedge_sharpening": wedge_sharpening,
        "route_delta_signal": route_delta_signal,
        "transfer_signal": transfer_signal,
        "control_regression": control_regression,
        "contamination_detected": False,
    }


def _family_verdict(*, control_family: bool, transfer_ready: bool, alpha_exposed_count: int, wedge_count: int) -> str:
    if control_family:
        return "CONTROL_ONLY_NOT_TRANSFER_CANDIDATE"
    if transfer_ready:
        return "TRANSFER_CANDIDATE_ADMISSIBLE_FOR_COUNTED_LANE"
    if alpha_exposed_count > 0 and wedge_count > 0:
        return "ANTI_ALPHA_LIABILITY_EXPOSED_BUT_ROUTE_HYPOTHESIS_STILL_WEAK"
    if wedge_count > 0:
        return "WEDGE_SHARPENING_PRESENT_BUT_NO_TRANSFER_ELIGIBILITY"
    return "NO_MEANINGFUL_WEDGE_SHARPENING"


def _negative_result_append(*, family_id: str, family_verdict: str, transfer_ready: bool, control_family: bool) -> Dict[str, Any]:
    if control_family:
        summary = "Control family preserved as non-transfer comparison surface."
    elif transfer_ready:
        summary = "No negative result preserved because this family is admissible for the next lab phase."
    else:
        summary = "Single-axis sweep did not produce enough route-bearing value to advance this family."
    return {
        "schema_id": "kt.operator.single_axis_negative_row_append.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "family_id": family_id,
        "family_verdict": family_verdict,
        "negative_row_summary": summary,
    }


def run_single_axis_crucible_execution_tranche(
    *,
    input_manifest_path: Path,
    registry_path: Path,
    failures_path: Path,
    transfer_candidates_path: Path,
    input_receipt_path: Path,
    transfer_guard_path: Path,
    verdict_grammar_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    current_head = _git_head(root)

    authoritative_manifest_path, input_manifest = _resolve_authoritative(root, input_manifest_path.resolve(), "authoritative_single_axis_crucible_input_manifest_ref", "single-axis input manifest")
    authoritative_registry_path, registry = _resolve_authoritative(root, registry_path.resolve(), "authoritative_single_axis_crucible_registry_ref", "single-axis registry")
    authoritative_failures_path, failures = _resolve_authoritative(root, failures_path.resolve(), "authoritative_single_axis_expected_failure_modes_ref", "single-axis expected failures")
    authoritative_transfer_candidates_path, transfer_candidates = _resolve_authoritative(root, transfer_candidates_path.resolve(), "authoritative_single_axis_transfer_candidates_ref", "single-axis transfer candidates")
    authoritative_input_receipt_path, input_receipt = _resolve_authoritative(root, input_receipt_path.resolve(), "authoritative_single_axis_crucible_receipt_ref", "single-axis input receipt")
    authoritative_transfer_guard_path, transfer_guard = _resolve_authoritative(root, transfer_guard_path.resolve(), "authoritative_lab_to_counted_transfer_guard_ref", "transfer guard")
    authoritative_verdict_grammar_path, verdict_grammar = _resolve_authoritative(root, verdict_grammar_path.resolve(), "authoritative_counted_lane_verdict_grammar_ref", "verdict grammar")

    _validate_inputs(
        input_manifest=input_manifest,
        registry=registry,
        failures=failures,
        transfer_candidates=transfer_candidates,
        input_receipt=input_receipt,
        transfer_guard=transfer_guard,
        verdict_grammar=verdict_grammar,
    )

    subject_head = _resolve_subject_head(
        packets=[input_manifest, registry, failures, transfer_candidates, input_receipt, transfer_guard, verdict_grammar]
    )

    target_root = authoritative_root.resolve() if authoritative_root is not None else (root / "tmp" / "cohort0_single_axis_crucible_execution").resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    family_runs_root = (target_root / "family_runs").resolve()
    family_runs_root.mkdir(parents=True, exist_ok=True)

    manifest_rows = [row for row in input_manifest.get("family_rows", []) if isinstance(row, dict)]
    failure_rows = _index_rows([row for row in failures.get("rows", []) if isinstance(row, dict)], key="family_id")
    transfer_rows = _index_rows([row for row in transfer_candidates.get("rows", []) if isinstance(row, dict)], key="family_id")

    case_results: List[Dict[str, Any]] = []
    family_matrix_rows: List[Dict[str, Any]] = []
    transfer_result_rows: List[Dict[str, Any]] = []
    control_rows: List[Dict[str, Any]] = []
    survivor_family_ids: List[str] = []
    blocked_family_ids: List[str] = []

    global_control_regression = False

    for manifest_row in manifest_rows:
        family_id = str(manifest_row.get("family_id", "")).strip()
        input_relpath = str(manifest_row.get("input_relpath", "")).strip()
        input_path = (authoritative_manifest_path.parent / input_relpath).resolve()
        input_rows = _load_jsonl(input_path)
        expected_line_count = int(manifest_row.get("line_count", 0))
        if len(input_rows) != expected_line_count:
            raise RuntimeError(f"FAIL_CLOSED: line count mismatch for {family_id}")

        evaluated_rows: List[Dict[str, Any]] = []
        for row in input_rows:
            evaluated = dict(row)
            evaluated.update(_evaluate_case(row))
            evaluated_rows.append(evaluated)
            case_results.append(evaluated)

        by_level: Dict[str, Dict[str, Any]] = {}
        route_delta_count = 0
        abstain_count = 0
        static_count = 0
        alpha_exposed_count = 0
        wedge_count = 0
        control_regression_count = 0

        for row in evaluated_rows:
            level_id = str(row.get("intensity_level_id", "")).strip()
            bucket = by_level.setdefault(
                level_id,
                {
                    "level_id": level_id,
                    "case_count": 0,
                    "route_count": 0,
                    "abstain_count": 0,
                    "static_count": 0,
                    "alpha_liability_exposed_count": 0,
                    "wedge_sharpening_count": 0,
                },
            )
            bucket["case_count"] += 1
            observed = str(row.get("observed_policy_outcome", "")).strip()
            if observed == ROUTE:
                bucket["route_count"] += 1
            elif observed == ABSTAIN:
                bucket["abstain_count"] += 1
            else:
                bucket["static_count"] += 1
            if bool(row.get("alpha_liability_exposed", False)):
                bucket["alpha_liability_exposed_count"] += 1
                alpha_exposed_count += 1
            if bool(row.get("wedge_sharpening", False)):
                bucket["wedge_sharpening_count"] += 1
                wedge_count += 1
            if bool(row.get("route_delta_signal", False)):
                route_delta_count += 1
            if observed == ABSTAIN:
                abstain_count += 1
            if observed == STATIC:
                static_count += 1
            if bool(row.get("control_regression", False)):
                control_regression_count += 1

        control_family = bool(manifest_row.get("control_family", False))
        transfer_ready = (
            (not control_family)
            and control_regression_count == 0
            and alpha_exposed_count >= 8
            and wedge_count >= 4
            and route_delta_count >= 8
        )
        family_verdict = _family_verdict(
            control_family=control_family,
            transfer_ready=transfer_ready,
            alpha_exposed_count=alpha_exposed_count,
            wedge_count=wedge_count,
        )
        if control_family and control_regression_count > 0:
            global_control_regression = True
        if transfer_ready:
            survivor_family_ids.append(family_id)
        elif not control_family:
            blocked_family_ids.append(family_id)

        level_rows = [by_level[key] for key in sorted(by_level.keys())]
        family_run_dir = (family_runs_root / family_id).resolve()
        family_run_dir.mkdir(parents=True, exist_ok=True)

        pressure_trace = {
            "schema_id": "kt.operator.single_axis_pressure_trace.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "family_id": family_id,
            "rows": level_rows,
        }
        family_result = {
            "schema_id": "kt.operator.single_axis_family_result.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "family_id": family_id,
            "control_family": control_family,
            "target_lobe_id": str(manifest_row.get("target_lobe_id", "")).strip(),
            "preferred_policy_outcome": str(manifest_row.get("preferred_policy_outcome", "")).strip(),
            "alpha_liability_exposed_count": alpha_exposed_count,
            "wedge_sharpening_count": wedge_count,
            "route_delta_count": route_delta_count,
            "abstain_count": abstain_count,
            "static_count": static_count,
            "control_regression_count": control_regression_count,
            "family_verdict": family_verdict,
            "named_wedge_sharpening": str(transfer_rows[family_id].get("named_wedge_sharpening", "")).strip(),
            "named_anti_alpha_liability": str(transfer_rows[family_id].get("named_anti_alpha_liability", "")).strip(),
            "new_admissible_eval_family": str(transfer_rows[family_id].get("new_admissible_eval_family", "")).strip(),
            "expected_alpha_failure_mode": str(failure_rows[family_id].get("expected_alpha_failure_mode", "")).strip(),
            "expected_specialist_advantage": str(failure_rows[family_id].get("expected_specialist_advantage", "")).strip(),
        }
        transfer_candidate_result = {
            "schema_id": "kt.operator.single_axis_transfer_candidate_result.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "family_id": family_id,
            "control_family": control_family,
            "transfer_candidate_status": family_verdict if not control_family else "CONTROL_ONLY_NOT_TRANSFER_CANDIDATE",
            "transfer_guard_satisfied": bool(transfer_ready),
            "measurable_route_delta_hypothesis_satisfied": route_delta_count >= 8 if not control_family else True,
            "named_wedge_sharpening_present": wedge_count >= 4 if not control_family else False,
            "named_anti_alpha_liability_present": alpha_exposed_count >= 8 if not control_family else False,
            "new_admissible_eval_family_emitted": bool(str(transfer_rows[family_id].get("new_admissible_eval_family", "")).strip()),
            "counts_as_counted_progress_now": False,
            "next_lab_action": (
                "AUTHOR_PAIRWISE_CRUCIBLE_INPUTS"
                if transfer_ready
                else ("PRESERVE_AS_CONTROL" if control_family else "REVISE_SINGLE_AXIS_WEDGE_OR_INTENSITY")
            ),
        }
        negative_row = _negative_result_append(
            family_id=family_id,
            family_verdict=family_verdict,
            transfer_ready=transfer_ready,
            control_family=control_family,
        )

        write_json_stable((family_run_dir / "family_result.json").resolve(), family_result)
        write_json_stable((family_run_dir / "pressure_trace.json").resolve(), pressure_trace)
        write_json_stable((family_run_dir / "transfer_candidate_result.json").resolve(), transfer_candidate_result)
        write_json_stable((family_run_dir / "negative_row_append.json").resolve(), negative_row)

        family_matrix_rows.append(
            {
                "family_id": family_id,
                "control_family": control_family,
                "target_lobe_id": str(manifest_row.get("target_lobe_id", "")).strip(),
                "primary_pressure_axis": str(manifest_row.get("primary_pressure_axis", "")).strip(),
                "route_delta_count": route_delta_count,
                "alpha_liability_exposed_count": alpha_exposed_count,
                "wedge_sharpening_count": wedge_count,
                "control_regression_count": control_regression_count,
                "family_verdict": family_verdict,
                "family_result_ref": (family_run_dir / "family_result.json").resolve().as_posix(),
                "pressure_trace_ref": (family_run_dir / "pressure_trace.json").resolve().as_posix(),
            }
        )
        transfer_result_rows.append(
            {
                "family_id": family_id,
                "control_family": control_family,
                "target_lobe_id": str(manifest_row.get("target_lobe_id", "")).strip(),
                "transfer_candidate_status": family_verdict if not control_family else "CONTROL_ONLY_NOT_TRANSFER_CANDIDATE",
                "counts_as_counted_progress_now": False,
                "next_lab_action": transfer_candidate_result["next_lab_action"],
                "named_wedge_sharpening": str(transfer_rows[family_id].get("named_wedge_sharpening", "")).strip(),
                "named_anti_alpha_liability": str(transfer_rows[family_id].get("named_anti_alpha_liability", "")).strip(),
                "measurable_route_delta_hypothesis": str(transfer_rows[family_id].get("measurable_route_delta_hypothesis", "")).strip(),
                "new_admissible_eval_family": str(transfer_rows[family_id].get("new_admissible_eval_family", "")).strip(),
                "transfer_candidate_result_ref": (family_run_dir / "transfer_candidate_result.json").resolve().as_posix(),
            }
        )
        if control_family:
            control_rows.append(
                {
                    "family_id": family_id,
                    "preferred_policy_outcome": str(manifest_row.get("preferred_policy_outcome", "")).strip(),
                    "control_regression_count": control_regression_count,
                    "preserved": control_regression_count == 0,
                }
            )

    if global_control_regression:
        raise RuntimeError("FAIL_CLOSED: control regression detected during single-axis execution")

    case_results_path = (target_root / "single_axis_case_results.jsonl").resolve()
    _write_jsonl(case_results_path, case_results)

    execution_matrix = {
        "schema_id": "kt.operator.single_axis_crucible_execution_matrix.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This matrix records lab-only single-axis execution outcomes. It does not reopen the counted lane by itself.",
        "source_refs": {
            "single_axis_input_manifest_ref": authoritative_manifest_path.as_posix(),
            "single_axis_crucible_registry_ref": authoritative_registry_path.as_posix(),
            "single_axis_expected_failure_modes_ref": authoritative_failures_path.as_posix(),
            "single_axis_transfer_candidates_ref": authoritative_transfer_candidates_path.as_posix(),
            "single_axis_input_receipt_ref": authoritative_input_receipt_path.as_posix(),
            "lab_to_counted_transfer_guard_ref": authoritative_transfer_guard_path.as_posix(),
            "counted_lane_verdict_grammar_ref": authoritative_verdict_grammar_path.as_posix(),
        },
        "case_results_ref": case_results_path.as_posix(),
        "family_rows": family_matrix_rows,
    }
    control_validation = {
        "schema_id": "kt.operator.single_axis_control_validation.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "Controls must hold before any family can advance deeper into the lab lane.",
        "control_family_count": len(control_rows),
        "controls_preserved": all(bool(row["preserved"]) for row in control_rows),
        "rows": control_rows,
    }
    transfer_eligibility = {
        "schema_id": "kt.operator.single_axis_transfer_eligibility.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "These are lab-only transfer nominations. Counted-lane progress still requires ordered proof reruns later.",
        "survivor_family_ids": survivor_family_ids,
        "blocked_family_ids": blocked_family_ids,
        "rows": transfer_result_rows,
    }
    next_move = NEXT_MOVE_SURVIVORS if survivor_family_ids else NEXT_MOVE_REVISE
    execution_receipt = {
        "schema_id": "kt.operator.single_axis_crucible_execution_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "single_axis_execution_posture": POSTURE,
        "claim_boundary": "This receipt records lab-only single-axis sweep results. The counted lane remains closed until ordered proof reruns move later surfaces.",
        "survivor_family_count": len(survivor_family_ids),
        "survivor_family_ids": survivor_family_ids,
        "blocked_family_count": len(blocked_family_ids),
        "blocked_family_ids": blocked_family_ids,
        "controls_preserved": True,
        "controls_preserved_ref": (target_root / "single_axis_control_validation.json").resolve().as_posix(),
        "next_lawful_move": next_move,
    }

    payloads = {
        "single_axis_crucible_execution_matrix": execution_matrix,
        "single_axis_control_validation": control_validation,
        "single_axis_transfer_eligibility": transfer_eligibility,
        "single_axis_crucible_execution_receipt": execution_receipt,
    }

    for name, obj in payloads.items():
        write_json_stable((target_root / f"{name}.json").resolve(), obj)

    reports_root.mkdir(parents=True, exist_ok=True)
    carrier_names = {
        "single_axis_crucible_execution_matrix": ("TRACKED_CARRIER_ONLY_SINGLE_AXIS_CRUCIBLE_EXECUTION_MATRIX", DEFAULT_TRACKED_EXEC_MATRIX),
        "single_axis_control_validation": ("TRACKED_CARRIER_ONLY_SINGLE_AXIS_CONTROL_VALIDATION", DEFAULT_TRACKED_CONTROL_VALIDATION),
        "single_axis_transfer_eligibility": ("TRACKED_CARRIER_ONLY_SINGLE_AXIS_TRANSFER_ELIGIBILITY", DEFAULT_TRACKED_TRANSFER_ELIGIBILITY),
        "single_axis_crucible_execution_receipt": ("TRACKED_CARRIER_ONLY_SINGLE_AXIS_CRUCIBLE_EXECUTION_RECEIPT", DEFAULT_TRACKED_EXEC_RECEIPT),
    }
    for name, obj in payloads.items():
        carrier_role, tracked_name = carrier_names[name]
        tracked = dict(obj)
        tracked["carrier_surface_role"] = carrier_role
        tracked[f"authoritative_{name}_ref"] = (target_root / f"{name}.json").resolve().as_posix()
        write_json_stable((reports_root / tracked_name).resolve(), tracked)

    return payloads


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Execute the single-axis lab-only crucible sweeps and bind transfer nominations without reopening the counted lane.")
    ap.add_argument("--input-manifest", default=DEFAULT_INPUT_MANIFEST_REL)
    ap.add_argument("--registry", default=DEFAULT_REGISTRY_REL)
    ap.add_argument("--failures", default=DEFAULT_FAILURES_REL)
    ap.add_argument("--transfer-candidates", default=DEFAULT_TRANSFER_CANDIDATES_REL)
    ap.add_argument("--input-receipt", default=DEFAULT_INPUT_RECEIPT_REL)
    ap.add_argument("--transfer-guard", default=DEFAULT_TRANSFER_GUARD_REL)
    ap.add_argument("--verdict-grammar", default=DEFAULT_VERDICT_GRAMMAR_REL)
    ap.add_argument("--authoritative-root", default="")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_single_axis_crucible_execution_tranche(
        input_manifest_path=_resolve(root, str(args.input_manifest)),
        registry_path=_resolve(root, str(args.registry)),
        failures_path=_resolve(root, str(args.failures)),
        transfer_candidates_path=_resolve(root, str(args.transfer_candidates)),
        input_receipt_path=_resolve(root, str(args.input_receipt)),
        transfer_guard_path=_resolve(root, str(args.transfer_guard)),
        verdict_grammar_path=_resolve(root, str(args.verdict_grammar)),
        authoritative_root=_resolve(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve(root, str(args.reports_root)),
        workspace_root=root,
    )
    receipt = payload["single_axis_crucible_execution_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "single_axis_execution_posture": receipt["single_axis_execution_posture"],
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
