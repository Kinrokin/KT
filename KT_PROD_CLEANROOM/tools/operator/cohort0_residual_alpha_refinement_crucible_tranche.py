from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_RESIDUAL_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_residual_alpha_dominance_packet.json"
DEFAULT_RESIDUAL_WEDGE_SPEC_REL = "KT_PROD_CLEANROOM/reports/cohort0_residual_alpha_dominance_wedge_spec.json"
DEFAULT_ROUTE_ECONOMICS_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_case_level_route_economics.json"
DEFAULT_SHORTCUT_TAGS_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_shortcut_resistance_tags.json"
DEFAULT_TRANSFER_GUARD_REL = "KT_PROD_CLEANROOM/reports/lab_to_counted_transfer_guard.json"
DEFAULT_VERDICT_GRAMMAR_REL = "KT_PROD_CLEANROOM/reports/counted_lane_verdict_grammar.json"

DEFAULT_TRACKED_MANIFEST = "cohort0_residual_alpha_refinement_crucible_manifest.json"
DEFAULT_TRACKED_REGISTRY = "cohort0_residual_alpha_refinement_crucible_registry.json"
DEFAULT_TRACKED_LADDER = "cohort0_residual_alpha_refinement_pressure_ladder.json"
DEFAULT_TRACKED_FAILURES = "cohort0_residual_alpha_refinement_expected_failure_modes.json"
DEFAULT_TRACKED_TRANSFER = "cohort0_residual_alpha_refinement_transfer_candidates.json"
DEFAULT_TRACKED_RECEIPT = "cohort0_residual_alpha_refinement_crucible_receipt.json"

SPECIALIST_FAMILY_IDS: Tuple[str, ...] = (
    "STRATEGIST_CONSEQUENCE_CHAIN",
    "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
    "BETA_SECOND_ORDER_REFRAME",
)
CONTROL_FAMILY_IDS: Tuple[str, ...] = (
    "BOUNDARY_ABSTENTION_CONTROL",
    "STATIC_NO_ROUTE_CONTROL",
)
FAMILY_ORDER: Tuple[str, ...] = SPECIALIST_FAMILY_IDS + CONTROL_FAMILY_IDS

ROUTE = "ROUTE_TO_SPECIALIST"
STATIC = "STAY_STATIC_BASELINE"
ABSTAIN = "ABSTAIN_FOR_REVIEW"

POSTURE = "RESIDUAL_ALPHA_REFINEMENT_CRUCIBLES_BOUND__LAB_EXECUTION_READY__COUNTED_LANE_STILL_CLOSED"
NEXT_MOVE = "EXECUTE_RESIDUAL_ALPHA_REFINEMENT_CRUCIBLES__LAB_ONLY"

PRESSURE_LADDER: Tuple[Dict[str, Any], ...] = (
    {
        "level_id": "L1",
        "label": "CalibratedRefinement",
        "primary_intensity": 0.40,
        "secondary_intensity": 0.15,
        "goal": "Preserve the already-earned wedge under mild bounded refinement pressure.",
    },
    {
        "level_id": "L2",
        "label": "ResidualProbe",
        "primary_intensity": 0.58,
        "secondary_intensity": 0.22,
        "goal": "Expose where residual alpha dominance still survives once the focal liability is pressed harder.",
    },
    {
        "level_id": "L3",
        "label": "BoundaryStress",
        "primary_intensity": 0.74,
        "secondary_intensity": 0.30,
        "goal": "Stress the wedge while preserving null-route restraint, masked survival, and control stability.",
    },
    {
        "level_id": "L4",
        "label": "CeilingProbe",
        "primary_intensity": 0.88,
        "secondary_intensity": 0.38,
        "goal": "Probe residual alpha hold without crossing into composite overload or counted-lane contamination.",
    },
)

PROMPT_FRAMES: Tuple[Dict[str, str], ...] = (
    {
        "frame_id": "PRIMARY_DECISION",
        "task": "Produce the primary decision while keeping the named residual wedge explicit and lawful.",
    },
    {
        "frame_id": "ROUTE_ECONOMICS_CHECK",
        "task": "Explain the cost of the wrong static hold, wrong route, or missed abstention on this exact residual case.",
    },
    {
        "frame_id": "SHORTCUT_RESILIENCE_CHECK",
        "task": "State which shortcut channels should fail here and what survival would prove the wedge is still real.",
    },
    {
        "frame_id": "FAIL_CLOSED_RECOVERY",
        "task": "Give the safest fail-closed recovery or handoff if the wrong instinct appears first.",
    },
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
        raise RuntimeError("FAIL_CLOSED: residual refinement tranche could not resolve any subject head")
    if len(subject_heads) != 1:
        raise RuntimeError("FAIL_CLOSED: residual refinement tranche requires one consistent subject head")
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


def _index_rows_grouped(rows: Sequence[Dict[str, Any]], *, key: str) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: expected object row while grouping")
        row_key = str(row.get(key, "")).strip()
        if not row_key:
            raise RuntimeError(f"FAIL_CLOSED: grouped row missing key {key}")
        out.setdefault(row_key, []).append(row)
    return out


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


def _family_shortcut_summary(shortcut_tags_by_family: Dict[str, Dict[str, Any]], family_id: str) -> Dict[str, Any]:
    summary = shortcut_tags_by_family.get(family_id)
    if summary is None:
        raise RuntimeError(f"FAIL_CLOSED: missing shortcut family summary for {family_id}")
    return summary


def _validate_inputs(
    *,
    residual_packet: Dict[str, Any],
    residual_wedge_spec: Dict[str, Any],
    route_economics: Dict[str, Any],
    shortcut_tags: Dict[str, Any],
    transfer_guard: Dict[str, Any],
    verdict_grammar: Dict[str, Any],
) -> None:
    if str(residual_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: residual alpha dominance packet must PASS")
    if str(residual_packet.get("next_lawful_move", "")).strip() != "AUTHOR_RESIDUAL_ALPHA_REFINEMENT_CRUCIBLES__LAB_ONLY":
        raise RuntimeError("FAIL_CLOSED: residual alpha packet next move mismatch")
    if str(residual_wedge_spec.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: residual wedge spec must PASS")
    if str(route_economics.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route economics surface must PASS")
    if str(shortcut_tags.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: shortcut resistance tags must PASS")
    if str(transfer_guard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: transfer guard must PASS")
    if str(verdict_grammar.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: counted-lane verdict grammar must PASS")

    summary = residual_packet.get("residual_alpha_dominance_summary", {})
    if not bool(summary.get("exact_path_universality_broken", False)):
        raise RuntimeError("FAIL_CLOSED: residual refinement requires universality to already be broken")
    if int(summary.get("route_distribution_delta_count", 0)) <= 0:
        raise RuntimeError("FAIL_CLOSED: residual refinement requires nonzero route deltas")

    specialist_signal_families = list(summary.get("specialist_signal_families", []))
    if specialist_signal_families != list(SPECIALIST_FAMILY_IDS):
        raise RuntimeError("FAIL_CLOSED: residual specialist family set mismatch")

    preserved_controls = transfer_guard.get("preserved_controls", {})
    if list(preserved_controls.get("abstention_control_family_ids", [])) != ["BOUNDARY_ABSTENTION_CONTROL"]:
        raise RuntimeError("FAIL_CLOSED: abstention control family mismatch")
    if list(preserved_controls.get("static_hold_family_ids", [])) != ["STATIC_NO_ROUTE_CONTROL"]:
        raise RuntimeError("FAIL_CLOSED: static hold control family mismatch")


def _allowed_verdict_ids(verdict_grammar: Dict[str, Any]) -> List[str]:
    ids: List[str] = []
    for row in verdict_grammar.get("allowed_verdicts", []):
        if not isinstance(row, dict):
            continue
        verdict_id = str(row.get("verdict_id", "")).strip()
        if verdict_id:
            ids.append(verdict_id)
    return ids


def _family_policy_outcome(row: Dict[str, Any]) -> str:
    route_case_count = int(row.get("route_case_count", 0))
    abstain_case_count = int(row.get("abstain_case_count", 0))
    target_lobe_id = str(row.get("target_lobe_id", "")).strip()
    if route_case_count == 0 and abstain_case_count > 0 and not target_lobe_id:
        return ABSTAIN
    if route_case_count == 0 and target_lobe_id == "lobe.alpha.v1":
        return STATIC
    if "AUDITOR" in str(row.get("family_id", "")).strip():
        return "ROUTE_TO_SPECIALIST_OR_ABSTAIN"
    return ROUTE


def _economics_summary(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    if not rows:
        raise RuntimeError("FAIL_CLOSED: expected at least one route-economics row")
    net_values = [float(row.get("net_policy_advantage", 0.0)) for row in rows]
    wrong_static = [float(row.get("wrong_static_hold_cost", 0.0)) for row in rows]
    wrong_route = [float(row.get("wrong_route_cost", 0.0)) for row in rows]
    missed_abstention = [float(row.get("missed_abstention_cost", 0.0)) for row in rows]
    proof_burden_saved = [float(row.get("proof_burden_saved_if_correct_policy", 0.0)) for row in rows]
    return {
        "case_count": len(rows),
        "mean_net_policy_advantage": round(sum(net_values) / len(net_values), 4),
        "minimum_net_policy_advantage": round(min(net_values), 4),
        "maximum_wrong_static_hold_cost": round(max(wrong_static), 4),
        "maximum_wrong_route_cost": round(max(wrong_route), 4),
        "maximum_missed_abstention_cost": round(max(missed_abstention), 4),
        "mean_proof_burden_saved_if_correct_policy": round(sum(proof_burden_saved) / len(proof_burden_saved), 4),
    }


def _case_profile_row(
    *,
    family_row: Dict[str, Any],
    economics_row: Dict[str, Any],
    shortcut_row: Optional[Dict[str, Any]],
    level: Dict[str, Any],
    frame: Dict[str, str],
) -> Dict[str, Any]:
    family_id = str(family_row.get("family_id", "")).strip()
    case_id = str(economics_row.get("case_id", "")).strip()
    case_role = str(economics_row.get("case_role", "")).strip()
    shortcut_channels: List[str] = []
    shortcut_status = "NO_MASKED_SHORTCUT_ROW"
    if shortcut_row is not None:
        shortcut_channels = [str(item) for item in shortcut_row.get("shortcut_channels_attacked", [])]
        shortcut_status = str(shortcut_row.get("shortcut_resistance_status", "")).strip()
    prompt = (
        f"Family: {family_id}. Source case: {case_id} ({case_role}). "
        f"Primary axis {str(family_row.get('primary_pressure_axis', '')).strip()} at {level['primary_intensity']:.2f}. "
        f"Secondary axis {str(family_row.get('secondary_pressure_axis', '')).strip()} at bounded context intensity {level['secondary_intensity']:.2f}. "
        f"Alpha liability: {str(family_row.get('alpha_liability', '')).strip()} "
        f"Residual focus: {str(family_row.get('next_focus', '')).strip()}. "
        f"Expected policy: {str(economics_row.get('expected_policy_outcome', '')).strip()}. "
        f"Wrong static hold cost: {float(economics_row.get('wrong_static_hold_cost', 0.0)):.3f}. "
        f"Wrong route cost: {float(economics_row.get('wrong_route_cost', 0.0)):.3f}. "
        f"Missed abstention cost: {float(economics_row.get('missed_abstention_cost', 0.0)):.3f}. "
        f"Shortcut channels under attack: {', '.join(shortcut_channels) if shortcut_channels else 'none on this source case'}. "
        f"Task: {frame['task']}"
    )
    return {
        "case_id": f"{case_id}__{level['level_id']}__{frame['frame_id']}",
        "source_case_id": case_id,
        "source_case_role": case_role,
        "family_id": family_id,
        "target_lobe_id": str(family_row.get("target_lobe_id", "")).strip(),
        "control_family": family_id in CONTROL_FAMILY_IDS,
        "primary_pressure_axis": str(family_row.get("primary_pressure_axis", "")).strip(),
        "secondary_pressure_axis": str(family_row.get("secondary_pressure_axis", "")).strip(),
        "intensity_level_id": level["level_id"],
        "primary_intensity": level["primary_intensity"],
        "secondary_intensity": level["secondary_intensity"],
        "pressure_goal": level["goal"],
        "prompt_frame_id": frame["frame_id"],
        "expected_policy_outcome": str(economics_row.get("expected_policy_outcome", "")).strip(),
        "alpha_liability": str(family_row.get("alpha_liability", "")).strip(),
        "residual_focus": str(family_row.get("next_focus", "")).strip(),
        "new_admissible_eval_family": str(family_row.get("new_admissible_eval_family", "")).strip(),
        "baseline_net_policy_advantage": float(economics_row.get("net_policy_advantage", 0.0)),
        "baseline_wrong_static_hold_cost": float(economics_row.get("wrong_static_hold_cost", 0.0)),
        "baseline_wrong_route_cost": float(economics_row.get("wrong_route_cost", 0.0)),
        "baseline_missed_abstention_cost": float(economics_row.get("missed_abstention_cost", 0.0)),
        "baseline_proof_burden_saved_if_correct_policy": float(economics_row.get("proof_burden_saved_if_correct_policy", 0.0)),
        "shortcut_channels_attacked": shortcut_channels,
        "shortcut_resistance_status": shortcut_status,
        "shortcut_dependency_detected": bool(shortcut_row.get("shortcut_dependency_detected", False)) if shortcut_row is not None else False,
        "transfer_guard_conditions": [
            "named_wedge_sharpening",
            "named_anti_alpha_liability",
            "measurable_route_delta_hypothesis",
            "new_admissible_eval_family",
        ],
        "prompt": prompt,
    }


def _family_case_slices(rows: Sequence[Dict[str, Any]]) -> Dict[str, List[str]]:
    out = {"route_case_ids": [], "null_route_case_ids": [], "masked_case_ids": [], "control_case_ids": []}
    for row in rows:
        case_role = str(row.get("case_role", "")).strip()
        case_id = str(row.get("case_id", "")).strip()
        if case_role == "ROUTE_CANDIDATE":
            out["route_case_ids"].append(case_id)
        elif case_role == "NULL_ROUTE_COUNTERFACTUAL":
            out["null_route_case_ids"].append(case_id)
        elif case_role == "MASKED_FORM_VARIANT":
            out["masked_case_ids"].append(case_id)
        else:
            out["control_case_ids"].append(case_id)
    return out


def run_residual_alpha_refinement_crucible_tranche(
    *,
    residual_packet_path: Path,
    residual_wedge_spec_path: Path,
    route_economics_path: Path,
    shortcut_tags_path: Path,
    transfer_guard_path: Path,
    verdict_grammar_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    current_head = _git_head(root)

    authoritative_residual_packet_path, residual_packet = _resolve_authoritative(
        root,
        residual_packet_path.resolve(),
        "authoritative_cohort0_residual_alpha_dominance_packet_ref",
        "residual alpha packet",
    )
    authoritative_residual_wedge_spec_path, residual_wedge_spec = _resolve_authoritative(
        root,
        residual_wedge_spec_path.resolve(),
        "authoritative_cohort0_residual_alpha_dominance_wedge_spec_ref",
        "residual alpha wedge spec",
    )
    authoritative_route_economics_path, route_economics = _resolve_authoritative(
        root,
        route_economics_path.resolve(),
        "authoritative_cohort0_recomposed_case_level_route_economics_ref",
        "route economics",
    )
    authoritative_shortcut_tags_path, shortcut_tags = _resolve_authoritative(
        root,
        shortcut_tags_path.resolve(),
        "authoritative_cohort0_recomposed_shortcut_resistance_tags_ref",
        "shortcut resistance tags",
    )
    authoritative_transfer_guard_path, transfer_guard = _resolve_authoritative(
        root,
        transfer_guard_path.resolve(),
        "authoritative_lab_to_counted_transfer_guard_ref",
        "transfer guard",
    )
    authoritative_verdict_grammar_path, verdict_grammar = _resolve_authoritative(
        root,
        verdict_grammar_path.resolve(),
        "authoritative_counted_lane_verdict_grammar_ref",
        "counted-lane verdict grammar",
    )

    _validate_inputs(
        residual_packet=residual_packet,
        residual_wedge_spec=residual_wedge_spec,
        route_economics=route_economics,
        shortcut_tags=shortcut_tags,
        transfer_guard=transfer_guard,
        verdict_grammar=verdict_grammar,
    )

    subject_head = _resolve_subject_head(
        packets=[residual_packet, residual_wedge_spec, route_economics, shortcut_tags, transfer_guard, verdict_grammar]
    )

    target_root = authoritative_root.resolve() if authoritative_root is not None else (root / "tmp" / "cohort0_residual_alpha_refinement_crucible_live").resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    inputs_root = (target_root / "residual_alpha_refinement_inputs").resolve()
    inputs_root.mkdir(parents=True, exist_ok=True)

    wedge_rows = _index_rows(residual_wedge_spec.get("rows", []), key="family_id")
    economics_by_family = _index_rows_grouped(route_economics.get("rows", []), key="family_id")
    shortcut_rows_by_case = _index_rows(shortcut_tags.get("rows", []), key="case_id")
    shortcut_family_summaries = _index_rows(shortcut_tags.get("family_summaries", []), key="family_id")

    manifest_rows: List[Dict[str, Any]] = []
    registry_rows: List[Dict[str, Any]] = []
    failure_rows: List[Dict[str, Any]] = []
    transfer_rows: List[Dict[str, Any]] = []

    allowed_verdict_ids = _allowed_verdict_ids(verdict_grammar)
    if "RESIDUAL_ALPHA_DOMINANCE_PRIMARY_BLOCKER" not in allowed_verdict_ids:
        raise RuntimeError("FAIL_CLOSED: verdict grammar must still allow residual-alpha blocker readings")

    for family_id in FAMILY_ORDER:
        family_row = dict(wedge_rows[family_id])
        family_economics_rows = list(economics_by_family.get(family_id, []))
        if not family_economics_rows:
            raise RuntimeError(f"FAIL_CLOSED: missing route-economics rows for {family_id}")
        shortcut_summary = _family_shortcut_summary(shortcut_family_summaries, family_id)
        if not bool(shortcut_summary.get("shortcut_resistant", False)):
            raise RuntimeError(f"FAIL_CLOSED: {family_id} is not shortcut resistant on the current sealed court")

        input_rows: List[Dict[str, Any]] = []
        for economics_row in family_economics_rows:
            source_case_id = str(economics_row.get("case_id", "")).strip()
            shortcut_row = shortcut_rows_by_case.get(source_case_id)
            for level in PRESSURE_LADDER:
                for frame in PROMPT_FRAMES:
                    input_rows.append(
                        _case_profile_row(
                            family_row=family_row,
                            economics_row=economics_row,
                            shortcut_row=shortcut_row,
                            level=level,
                            frame=frame,
                        )
                    )

        family_dir = (inputs_root / family_id).resolve()
        family_dir.mkdir(parents=True, exist_ok=True)
        input_path = (family_dir / "residual_refinement_inputs.jsonl").resolve()
        _write_jsonl(input_path, input_rows)

        case_slices = _family_case_slices(family_economics_rows)
        economics_summary = _economics_summary(family_economics_rows)

        manifest_rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": str(family_row.get("target_lobe_id", "")).strip(),
                "control_family": family_id in CONTROL_FAMILY_IDS,
                "primary_pressure_axis": str(family_row.get("primary_pressure_axis", "")).strip(),
                "secondary_pressure_axis": str(family_row.get("secondary_pressure_axis", "")).strip(),
                "input_relpath": input_path.relative_to(target_root).as_posix(),
                "line_count": len(input_rows),
                "bytes": int(input_path.stat().st_size),
                "sha256": _file_sha256(input_path),
                "route_case_ids": case_slices["route_case_ids"],
                "null_route_case_ids": case_slices["null_route_case_ids"],
                "masked_case_ids": case_slices["masked_case_ids"],
                "control_case_ids": case_slices["control_case_ids"],
                "expected_policy_outcome_family": _family_policy_outcome(family_row),
                "new_admissible_eval_family": str(family_row.get("new_admissible_eval_family", "")).strip(),
                "minimum_mean_net_policy_advantage": float(family_row.get("minimum_mean_net_policy_advantage", 0.0)),
            }
        )

        registry_rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": str(family_row.get("target_lobe_id", "")).strip(),
                "control_family": family_id in CONTROL_FAMILY_IDS,
                "family_thesis": str(family_row.get("family_thesis", "")).strip(),
                "alpha_liability": str(family_row.get("alpha_liability", "")).strip(),
                "residual_status": str(family_row.get("residual_status", "")).strip(),
                "next_focus": str(family_row.get("next_focus", "")).strip(),
                "primary_pressure_axis": str(family_row.get("primary_pressure_axis", "")).strip(),
                "secondary_pressure_axis": str(family_row.get("secondary_pressure_axis", "")).strip(),
                "shortcut_resistance_required": bool(family_row.get("shortcut_resistance_required", False)),
                "shortcut_resistance_summary": {
                    "lexical_cues": str(shortcut_summary.get("lexical_cues", "")).strip(),
                    "formatting_cues": str(shortcut_summary.get("formatting_cues", "")).strip(),
                    "domain_cues": str(shortcut_summary.get("domain_cues", "")).strip(),
                    "evidence_order": str(shortcut_summary.get("evidence_order", "")).strip(),
                    "shortcut_resistant": bool(shortcut_summary.get("shortcut_resistant", False)),
                },
                "route_economics_summary": economics_summary,
                "expected_policy_outcome_family": _family_policy_outcome(family_row),
                "transfer_guard_conditions": list(transfer_guard.get("counted_lane_stays_closed_until", [])),
                "held_out_preservation_rule": str(family_row.get("held_out_preservation_rule", "")).strip(),
                "success_condition": str(family_row.get("success_condition", "")).strip(),
                "failure_condition": str(family_row.get("failure_condition", "")).strip(),
            }
        )

        failure_rows.append(
            {
                "family_id": family_id,
                "control_family": family_id in CONTROL_FAMILY_IDS,
                "expected_failure_modes": [
                    "NO_REFINEMENT_SIGNAL",
                    "SHORTCUT_DEPENDENCY_EXPOSED",
                    "MASKED_FORM_COLLAPSE",
                    "NULL_ROUTE_RESTRAINT_REGRESSION" if family_id not in CONTROL_FAMILY_IDS else "CONTROL_PRESERVATION_REGRESSION",
                    "STRESS_TAX_INCREASE_WITHOUT_SUPERIORITY_RELEVANT_GAIN",
                    "COUNTED_LANE_CONTAMINATION_DETECTED__RESULT_VOID",
                ],
                "expected_alpha_failure_mode": str(family_row.get("alpha_liability", "")).strip(),
                "invalidates_transfer_if": [
                    "named_wedge_sharpening missing",
                    "named_anti_alpha_liability missing",
                    "route-delta hypothesis weak or negative",
                    "new admissible eval family not preserved",
                    "controls regress",
                ],
            }
        )

        transfer_rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": str(family_row.get("target_lobe_id", "")).strip(),
                "control_family": family_id in CONTROL_FAMILY_IDS,
                "transfer_candidate_status": "PENDING_REFINEMENT_EXECUTION" if family_id in SPECIALIST_FAMILY_IDS else "CONTROL_ONLY_NOT_TRANSFER_CANDIDATE",
                "named_wedge_sharpening": str(family_row.get("next_focus", "")).strip(),
                "named_anti_alpha_liability": str(family_row.get("alpha_liability", "")).strip(),
                "measurable_route_delta_hypothesis": f"{family_id}__RESIDUAL_REFINEMENT_MOVES_ROUTE_VALUE_WITHOUT_CONTROL_REGRESSION",
                "new_admissible_eval_family": str(family_row.get("new_admissible_eval_family", "")).strip(),
                "minimum_mean_net_policy_advantage_floor": float(family_row.get("minimum_mean_net_policy_advantage", 0.0)),
                "shortcut_resistance_required": bool(family_row.get("shortcut_resistance_required", False)),
                "masked_survival_floor": 1.0,
                "control_preservation_floor": 1.0,
            }
        )

    manifest = {
        "schema_id": "kt.operator.cohort0_residual_alpha_refinement_crucible_manifest.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This manifest binds only the lab-only residual-alpha refinement crucibles on the sealed augmentation court. It does not reopen the counted lane, authorize learned routing, or widen the family set.",
        "source_refs": {
            "residual_alpha_dominance_packet_ref": authoritative_residual_packet_path.as_posix(),
            "residual_alpha_dominance_wedge_spec_ref": authoritative_residual_wedge_spec_path.as_posix(),
            "recomposed_case_level_route_economics_ref": authoritative_route_economics_path.as_posix(),
            "recomposed_shortcut_resistance_tags_ref": authoritative_shortcut_tags_path.as_posix(),
            "lab_to_counted_transfer_guard_ref": authoritative_transfer_guard_path.as_posix(),
            "counted_lane_verdict_grammar_ref": authoritative_verdict_grammar_path.as_posix(),
        },
        "specialist_family_ids": list(SPECIALIST_FAMILY_IDS),
        "control_family_ids": list(CONTROL_FAMILY_IDS),
        "family_rows": manifest_rows,
        "stage_file_entries": _stage_entries(target_root),
    }

    registry = {
        "schema_id": "kt.operator.cohort0_residual_alpha_refinement_crucible_registry.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This registry defines only the lawful family-specific residual refinement crucibles. Composite overload, counted-lane crossing, and family widening remain out of scope.",
        "rows": registry_rows,
    }

    ladder = {
        "schema_id": "kt.operator.cohort0_residual_alpha_refinement_pressure_ladder.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This ladder escalates the named primary axis while holding the secondary axis to bounded contextual reinforcement. Composite overload remains prohibited.",
        "rows": [
            {
                "family_id": family_id,
                "primary_pressure_axis": str(wedge_rows[family_id].get("primary_pressure_axis", "")).strip(),
                "secondary_pressure_axis": str(wedge_rows[family_id].get("secondary_pressure_axis", "")).strip(),
                "levels": list(PRESSURE_LADDER),
            }
            for family_id in FAMILY_ORDER
        ],
    }

    expected_failures = {
        "schema_id": "kt.operator.cohort0_residual_alpha_refinement_expected_failure_modes.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "These are preregistered lab-only failure modes for residual-alpha refinement. They do not alter counted interpretation by themselves.",
        "rows": failure_rows,
    }

    transfer_candidates = {
        "schema_id": "kt.operator.cohort0_residual_alpha_refinement_transfer_candidates.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "Transfer candidate rows remain lab-only until a fresh ordered rerun moves proof objects under the transfer guard.",
        "rows": transfer_rows,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_residual_alpha_refinement_crucible_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "residual_alpha_refinement_posture": POSTURE,
        "claim_boundary": "This receipt binds only authored residual refinement crucibles on the sealed augmentation court. The counted lane remains closed and learned-router authorization remains blocked.",
        "specialist_family_ids": list(SPECIALIST_FAMILY_IDS),
        "control_family_ids": list(CONTROL_FAMILY_IDS),
        "residual_route_delta_baseline": int(residual_packet.get("proof_object_movement", {}).get("route_distribution_delta_count_current", 0)),
        "prohibited_moves": [
            "No counted-lane claim update from residual refinement authoring alone.",
            "No Kaggle or lab result may update superiority claims directly.",
            "No family widening beyond strategist, auditor, beta, and the two controls.",
            "No composite-overload escalation from this tranche.",
            "No learned-router claim or Gate E/F opening.",
        ],
        "verdict_grammar": [
            "NO_REFINEMENT_SIGNAL",
            "REFINEMENT_SIGNAL_PRESENT_BUT_LAB_ONLY",
            "TRANSFER_CANDIDATE_ADMISSIBLE_FOR_FRESH_ORDERED_RERUN",
            "MASKED_FORM_COLLAPSE__LAB_ONLY",
            "CONTROL_REGRESSION__RESULT_VOID",
            "COUNTED_LANE_CONTAMINATION_DETECTED__RESULT_VOID",
        ],
        "next_lawful_move": NEXT_MOVE,
    }

    payloads = {
        "cohort0_residual_alpha_refinement_crucible_manifest": manifest,
        "cohort0_residual_alpha_refinement_crucible_registry": registry,
        "cohort0_residual_alpha_refinement_pressure_ladder": ladder,
        "cohort0_residual_alpha_refinement_expected_failure_modes": expected_failures,
        "cohort0_residual_alpha_refinement_transfer_candidates": transfer_candidates,
        "cohort0_residual_alpha_refinement_crucible_receipt": receipt,
    }

    for name, obj in payloads.items():
        write_json_stable((target_root / f"{name}.json").resolve(), obj)

    reports_root.mkdir(parents=True, exist_ok=True)
    carrier_names = {
        "cohort0_residual_alpha_refinement_crucible_manifest": (
            "TRACKED_CARRIER_ONLY_COHORT0_RESIDUAL_ALPHA_REFINEMENT_CRUCIBLE_MANIFEST",
            DEFAULT_TRACKED_MANIFEST,
        ),
        "cohort0_residual_alpha_refinement_crucible_registry": (
            "TRACKED_CARRIER_ONLY_COHORT0_RESIDUAL_ALPHA_REFINEMENT_CRUCIBLE_REGISTRY",
            DEFAULT_TRACKED_REGISTRY,
        ),
        "cohort0_residual_alpha_refinement_pressure_ladder": (
            "TRACKED_CARRIER_ONLY_COHORT0_RESIDUAL_ALPHA_REFINEMENT_PRESSURE_LADDER",
            DEFAULT_TRACKED_LADDER,
        ),
        "cohort0_residual_alpha_refinement_expected_failure_modes": (
            "TRACKED_CARRIER_ONLY_COHORT0_RESIDUAL_ALPHA_REFINEMENT_EXPECTED_FAILURE_MODES",
            DEFAULT_TRACKED_FAILURES,
        ),
        "cohort0_residual_alpha_refinement_transfer_candidates": (
            "TRACKED_CARRIER_ONLY_COHORT0_RESIDUAL_ALPHA_REFINEMENT_TRANSFER_CANDIDATES",
            DEFAULT_TRACKED_TRANSFER,
        ),
        "cohort0_residual_alpha_refinement_crucible_receipt": (
            "TRACKED_CARRIER_ONLY_COHORT0_RESIDUAL_ALPHA_REFINEMENT_CRUCIBLE_RECEIPT",
            DEFAULT_TRACKED_RECEIPT,
        ),
    }

    for name, obj in payloads.items():
        carrier_role, tracked_name = carrier_names[name]
        tracked = dict(obj)
        tracked["carrier_surface_role"] = carrier_role
        tracked[f"authoritative_{name}_ref"] = (target_root / f"{name}.json").resolve().as_posix()
        write_json_stable((reports_root / tracked_name).resolve(), tracked)

    return payloads


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Author the lab-only residual-alpha refinement crucible packet keyed to the sealed augmentation court.")
    ap.add_argument("--residual-packet", default=DEFAULT_RESIDUAL_PACKET_REL)
    ap.add_argument("--residual-wedge-spec", default=DEFAULT_RESIDUAL_WEDGE_SPEC_REL)
    ap.add_argument("--route-economics", default=DEFAULT_ROUTE_ECONOMICS_REL)
    ap.add_argument("--shortcut-tags", default=DEFAULT_SHORTCUT_TAGS_REL)
    ap.add_argument("--transfer-guard", default=DEFAULT_TRANSFER_GUARD_REL)
    ap.add_argument("--verdict-grammar", default=DEFAULT_VERDICT_GRAMMAR_REL)
    ap.add_argument("--authoritative-root", default="")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_residual_alpha_refinement_crucible_tranche(
        residual_packet_path=_resolve(root, str(args.residual_packet)),
        residual_wedge_spec_path=_resolve(root, str(args.residual_wedge_spec)),
        route_economics_path=_resolve(root, str(args.route_economics)),
        shortcut_tags_path=_resolve(root, str(args.shortcut_tags)),
        transfer_guard_path=_resolve(root, str(args.transfer_guard)),
        verdict_grammar_path=_resolve(root, str(args.verdict_grammar)),
        authoritative_root=_resolve(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve(root, str(args.reports_root)),
        workspace_root=root,
    )
    receipt = payload["cohort0_residual_alpha_refinement_crucible_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "residual_alpha_refinement_posture": receipt["residual_alpha_refinement_posture"],
                "next_lawful_move": receipt["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
