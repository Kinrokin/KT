from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_RESIDUAL_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_residual_alpha_dominance_packet.json"
DEFAULT_RESIDUAL_WEDGE_SPEC_REL = "KT_PROD_CLEANROOM/reports/cohort0_residual_alpha_dominance_wedge_spec.json"
DEFAULT_TRANSFER_GUARD_REL = "KT_PROD_CLEANROOM/reports/lab_to_counted_transfer_guard.json"
DEFAULT_VERDICT_GRAMMAR_REL = "KT_PROD_CLEANROOM/reports/counted_lane_verdict_grammar.json"
DEFAULT_ALPHA_LIABILITY_REGISTRY_REL = "KT_PROD_CLEANROOM/reports/alpha_liability_registry.json"
DEFAULT_POLICY_REGISTRY_REL = "KT_PROD_CLEANROOM/reports/route_policy_outcome_registry.json"

DEFAULT_TRACKED_MANIFEST = "single_axis_crucible_input_manifest.json"
DEFAULT_TRACKED_REGISTRY = "single_axis_crucible_registry.json"
DEFAULT_TRACKED_LADDER = "single_axis_pressure_ladder.json"
DEFAULT_TRACKED_FAILURES = "single_axis_expected_failure_modes.json"
DEFAULT_TRACKED_TRANSFER = "single_axis_transfer_candidates.json"
DEFAULT_TRACKED_RECEIPT = "single_axis_crucible_receipt.json"

NEXT_MOVE = "EXECUTE_SINGLE_AXIS_CRUCIBLE_SWEEPS__LAB_ONLY"
POSTURE = "SINGLE_AXIS_CRUCIBLE_INPUTS_BOUND__LAB_EXECUTION_READY__COUNTED_LANE_STILL_CLOSED"

ROUTE = "ROUTE_TO_SPECIALIST"
STATIC = "STAY_STATIC_BASELINE"
ABSTAIN = "ABSTAIN_FOR_REVIEW"

AXIS_BINDINGS: Dict[str, Dict[str, Any]] = {
    "P2_SIGNAL_NOISE_SEPARATION": {
        "primary_axis": "AMBIGUITY_NOISE_DENSITY",
        "secondary_axis": "NOISE_FLOOR_CONTROL",
        "target_lobe_id": "lobe.p2.v1",
        "expected_policy_outcome": ROUTE,
        "axis_hypothesis": "As ambiguity and noise density rise, alpha should blur decisive versus decorative constraints before p2 does.",
    },
    "CHILD_ANOMALY_PRESERVATION": {
        "primary_axis": "ANOMALY_CAMOUFLAGE",
        "secondary_axis": "TRANSFORMATION_DISTORTION",
        "target_lobe_id": "lobe.child.v1",
        "expected_policy_outcome": ROUTE,
        "axis_hypothesis": "As anomalies are disguised by transformation, child should preserve them longer than alpha.",
    },
    "STRATEGIST_CONSEQUENCE_CHAIN": {
        "primary_axis": "HOP_DEPTH",
        "secondary_axis": "CAUSAL_BRANCHING",
        "target_lobe_id": "lobe.strategist.v1",
        "expected_policy_outcome": ROUTE,
        "axis_hypothesis": "As step count and branch depth rise, strategist should keep downstream order intact longer than alpha.",
    },
    "SCOUT_SPARSE_SEARCH": {
        "primary_axis": "SPARSE_BRANCH_BREADTH",
        "secondary_axis": "DISTRACTOR_CARDINALITY",
        "target_lobe_id": "lobe.scout.v1",
        "expected_policy_outcome": ROUTE,
        "axis_hypothesis": "As sparse search breadth and distractor count rise, scout should keep candidate coverage alive longer than alpha.",
    },
    "AUDITOR_ADMISSIBILITY_FAIL_CLOSED": {
        "primary_axis": "PROOF_DISCIPLINE_BURDEN",
        "secondary_axis": "CONSTITUTIONAL_BOUNDARY_PRESSURE",
        "target_lobe_id": "lobe.auditor.v1",
        "expected_policy_outcome": ROUTE,
        "alternate_policy_outcome": ABSTAIN,
        "axis_hypothesis": "As proof-discipline burden and constitutional pressure rise, auditor should either out-govern alpha or abstain lawfully before alpha overclaims.",
    },
    "BETA_SECOND_ORDER_REFRAME": {
        "primary_axis": "PARADOX_PRESSURE",
        "secondary_axis": "SECOND_ORDER_REFRAMING",
        "target_lobe_id": "lobe.beta.v1",
        "expected_policy_outcome": ROUTE,
        "axis_hypothesis": "As paradox and rival-frame pressure rise, beta should preserve the live second frame longer than alpha.",
    },
    "BOUNDARY_ABSTENTION_CONTROL": {
        "primary_axis": "AMBIGUITY_ESCALATION",
        "secondary_axis": "REVIEW_HANDOFF_REQUIREMENT",
        "target_lobe_id": "",
        "expected_policy_outcome": ABSTAIN,
        "control_family": True,
        "axis_hypothesis": "As ambiguity escalates, the lawful answer should remain abstain and review, not forced routing.",
    },
    "STATIC_NO_ROUTE_CONTROL": {
        "primary_axis": "STATIC_HOLD_STABILITY",
        "secondary_axis": "NO_REGRESSION_GUARD",
        "target_lobe_id": "lobe.alpha.v1",
        "expected_policy_outcome": STATIC,
        "control_family": True,
        "axis_hypothesis": "As benign pressure rises, the lawful answer should remain static alpha with no artificial wedge claim.",
    },
}

PRESSURE_LADDER: Tuple[Dict[str, Any], ...] = (
    {"level_id": "L1", "intensity": 0.25, "label": "Low"},
    {"level_id": "L2", "intensity": 0.45, "label": "Medium"},
    {"level_id": "L3", "intensity": 0.65, "label": "High"},
    {"level_id": "L4", "intensity": 0.85, "label": "Extreme"},
)

PROMPT_FRAMES: Tuple[Dict[str, str], ...] = (
    {"frame_id": "PRIMARY_DECISION", "task": "Produce the primary decision path while keeping the named wedge visible."},
    {"frame_id": "FAILURE_DIAGNOSIS", "task": "Explain the exact alpha-side failure mode that should appear under this pressure."},
    {"frame_id": "PROOF_CHECK", "task": "State what evaluator evidence would prove the wedge sharpened under this pressure."},
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
        raise RuntimeError("FAIL_CLOSED: single-axis crucible tranche could not resolve any subject head")
    if len(subject_heads) != 1:
        raise RuntimeError("FAIL_CLOSED: single-axis crucible tranche requires one consistent subject head")
    return next(iter(subject_heads))


def _validate_inputs(
    *,
    residual_packet: Dict[str, Any],
    residual_wedge_spec: Dict[str, Any],
    transfer_guard: Dict[str, Any],
    verdict_grammar: Dict[str, Any],
    alpha_liability_registry: Dict[str, Any],
    policy_registry: Dict[str, Any],
) -> None:
    if str(residual_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: residual alpha dominance packet must PASS")
    if str(residual_packet.get("next_lawful_move", "")).strip() != "AUTHOR_SINGLE_AXIS_CRUCIBLE_INPUTS_AND_EXECUTE_LAB_ONLY_SWEEPS":
        raise RuntimeError("FAIL_CLOSED: residual packet must point to single-axis crucible authoring")
    if str(residual_wedge_spec.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: residual wedge spec must PASS")
    if str(transfer_guard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: transfer guard must PASS")
    if str(verdict_grammar.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: counted-lane verdict grammar must PASS")
    if str(alpha_liability_registry.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: alpha liability registry must PASS")
    if str(policy_registry.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route policy registry must PASS")
    preserved_controls = transfer_guard.get("preserved_controls", {})
    if list(preserved_controls.get("abstention_control_family_ids", [])) != ["BOUNDARY_ABSTENTION_CONTROL"]:
        raise RuntimeError("FAIL_CLOSED: abstention control family mismatch")
    if list(preserved_controls.get("static_hold_family_ids", [])) != ["STATIC_NO_ROUTE_CONTROL"]:
        raise RuntimeError("FAIL_CLOSED: static hold control family mismatch")


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


def _preferred_outcome(row: Dict[str, Any]) -> str:
    status = str(row.get("residual_status", "")).strip()
    family_id = str(row.get("family_id", "")).strip()
    binding = AXIS_BINDINGS[family_id]
    if status == "FAIL_CLOSED_DE_RISKING_SIGNAL__NOT_DIRECT_SUPERIORITY":
        return ABSTAIN
    if status == "RIGHTFUL_STATIC_HOLD__CONTROL_FAMILY":
        return STATIC
    return str(binding.get("expected_policy_outcome", ROUTE))


def _input_row(
    *,
    family_row: Dict[str, Any],
    liability_row: Dict[str, Any],
    level: Dict[str, Any],
    frame: Dict[str, str],
) -> Dict[str, Any]:
    family_id = str(family_row.get("family_id", "")).strip()
    binding = AXIS_BINDINGS[family_id]
    target_lobe_id = str(binding.get("target_lobe_id", "")).strip()
    control_family = bool(binding.get("control_family", False))
    preferred_outcome = _preferred_outcome(family_row)
    prompt = (
        f"Family: {family_id}. Pressure axis: {binding['primary_axis']} at {level['label']} intensity ({level['intensity']:.2f}). "
        f"Secondary axis context: {binding['secondary_axis']}. "
        f"Alpha liability: {str(family_row.get('alpha_liability', '')).strip()} "
        f"Why alpha should lose or de-risk here: {str(liability_row.get('alpha_should_lose_here_because', '')).strip() or str(family_row.get('alpha_should_lose_here_because', '')).strip()} "
        f"Expected outcome: {preferred_outcome}. "
        f"Task: {frame['task']}"
    )
    return {
        "case_id": f"{family_id}__{level['level_id']}__{frame['frame_id']}",
        "family_id": family_id,
        "target_lobe_id": target_lobe_id,
        "control_family": control_family,
        "primary_pressure_axis": binding["primary_axis"],
        "secondary_pressure_axis": binding["secondary_axis"],
        "intensity_level_id": level["level_id"],
        "intensity": level["intensity"],
        "prompt_frame_id": frame["frame_id"],
        "preferred_policy_outcome": preferred_outcome,
        "alternate_policy_outcome": str(binding.get("alternate_policy_outcome", "")).strip(),
        "alpha_liability": str(family_row.get("alpha_liability", "")).strip(),
        "expected_alpha_failure_mode": str(family_row.get("residual_explanation", "")).strip(),
        "expected_specialist_advantage": str(family_row.get("next_focus", "")).strip(),
        "new_admissible_eval_family": str(family_row.get("new_admissible_eval_family", "")).strip() or str(liability_row.get("new_admissible_eval_family", "")).strip(),
        "held_out_preservation_rule": str(family_row.get("held_out_preservation_rule", "")).strip(),
        "transfer_eligibility_requires": [
            "named_wedge_sharpening",
            "named_anti_alpha_liability",
            "measurable_route_delta_hypothesis",
            "new_admissible_eval_family",
        ],
        "prompt": prompt,
    }


def _write_jsonl(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")


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


def _build_registry_rows(
    *,
    family_rows: Sequence[Dict[str, Any]],
    liability_rows: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for family_row in family_rows:
        family_id = str(family_row.get("family_id", "")).strip()
        binding = AXIS_BINDINGS[family_id]
        liability_row = liability_rows.get(family_id, {})
        rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": str(binding.get("target_lobe_id", "")).strip(),
                "control_family": bool(binding.get("control_family", False)),
                "primary_pressure_axis": binding["primary_axis"],
                "secondary_pressure_axis": binding["secondary_axis"],
                "pressure_axis_hypothesis": binding["axis_hypothesis"],
                "expected_alpha_failure_mode": str(family_row.get("residual_explanation", "")).strip(),
                "expected_specialist_advantage": str(family_row.get("next_focus", "")).strip(),
                "preferred_policy_outcome": _preferred_outcome(family_row),
                "alternate_policy_outcome": str(binding.get("alternate_policy_outcome", "")).strip(),
                "alpha_should_lose_here_because": str(liability_row.get("alpha_should_lose_here_because", "")).strip() or str(family_row.get("alpha_should_lose_here_because", "")).strip(),
                "acceptance_metric": str(liability_row.get("acceptance_metric", "")).strip() or str(family_row.get("acceptance_metric", "")).strip(),
                "evaluator_rules": [
                    "Check whether the named alpha liability appears under the selected single axis.",
                    "Check whether the preferred policy outcome remains lawful for this family.",
                    "Check whether control families preserve their rightful outcomes.",
                    "Check whether the result satisfies transfer-guard prerequisites without composite pressure contamination.",
                ],
                "evidence_artifact_contract": [
                    "single_axis_run_receipt.json",
                    "family_result.json",
                    "pressure_trace.json",
                    "transfer_candidate_result.json",
                    "negative_row_append.json",
                ],
                "pass_fail_thresholds": {
                    "pass": [
                        "Preferred policy outcome remains lawful at one or more ladder levels.",
                        "Expected alpha failure mode is actually exposed by the single-axis stressor.",
                        "Control families do not regress.",
                    ],
                    "fail": [
                        "No ladder level exposes the named alpha liability.",
                        "Control families regress.",
                        "Composite or off-axis pressure is mixed in before attribution is established.",
                    ],
                },
                "transfer_eligibility_fields": [
                    "named_wedge_sharpening",
                    "named_anti_alpha_liability",
                    "measurable_route_delta_hypothesis",
                    "new_admissible_eval_family",
                ],
            }
        )
    return rows


def _build_failure_rows(*, family_rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for family_row in family_rows:
        family_id = str(family_row.get("family_id", "")).strip()
        preferred = _preferred_outcome(family_row)
        rows.append(
            {
                "family_id": family_id,
                "control_family": bool(AXIS_BINDINGS[family_id].get("control_family", False)),
                "expected_alpha_failure_mode": str(family_row.get("residual_explanation", "")).strip(),
                "expected_specialist_advantage": str(family_row.get("next_focus", "")).strip(),
                "preferred_policy_outcome": preferred,
                "contamination_failure_mode": "Single-axis tranche becomes invalid if blended composite pressure enters before attribution is established.",
                "transfer_blockers_if_failed": [
                    "named_wedge_sharpening missing",
                    "named_anti_alpha_liability missing",
                    "route-delta hypothesis too weak",
                    "new admissible eval family not earned",
                ],
            }
        )
    return rows


def _build_transfer_candidates(*, family_rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for family_row in family_rows:
        family_id = str(family_row.get("family_id", "")).strip()
        control_family = bool(AXIS_BINDINGS[family_id].get("control_family", False))
        preferred = _preferred_outcome(family_row)
        eligible = not control_family
        rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": str(family_row.get("target_lobe_id", "")).strip(),
                "control_family": control_family,
                "preferred_policy_outcome": preferred,
                "transfer_candidate_status": "PENDING_SINGLE_AXIS_EXECUTION" if eligible else "CONTROL_ONLY_NOT_TRANSFER_CANDIDATE",
                "named_wedge_sharpening": str(family_row.get("next_focus", "")).strip(),
                "named_anti_alpha_liability": str(family_row.get("alpha_liability", "")).strip(),
                "measurable_route_delta_hypothesis": f"{family_id}__ROUTE_DELTA_INCREASES_WITHOUT_CONTROL_REGRESSION",
                "new_admissible_eval_family": str(family_row.get("new_admissible_eval_family", "")).strip(),
            }
        )
    return rows


def run_single_axis_crucible_input_tranche(
    *,
    residual_packet_path: Path,
    residual_wedge_spec_path: Path,
    transfer_guard_path: Path,
    verdict_grammar_path: Path,
    alpha_liability_registry_path: Path,
    policy_registry_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    current_head = _git_head(root)

    authoritative_residual_packet_path, residual_packet = _resolve_authoritative(root, residual_packet_path.resolve(), "authoritative_cohort0_residual_alpha_dominance_packet_ref", "residual alpha packet")
    authoritative_residual_wedge_spec_path, residual_wedge_spec = _resolve_authoritative(root, residual_wedge_spec_path.resolve(), "authoritative_cohort0_residual_alpha_dominance_wedge_spec_ref", "residual wedge spec")
    authoritative_transfer_guard_path, transfer_guard = _resolve_authoritative(root, transfer_guard_path.resolve(), "authoritative_lab_to_counted_transfer_guard_ref", "transfer guard")
    authoritative_verdict_grammar_path, verdict_grammar = _resolve_authoritative(root, verdict_grammar_path.resolve(), "authoritative_counted_lane_verdict_grammar_ref", "verdict grammar")
    authoritative_alpha_liability_registry_path, alpha_liability_registry = _resolve_authoritative(root, alpha_liability_registry_path.resolve(), "authoritative_alpha_liability_registry_ref", "alpha liability registry")
    authoritative_policy_registry_path, policy_registry = _resolve_authoritative(root, policy_registry_path.resolve(), "authoritative_route_policy_outcome_registry_ref", "policy registry")

    _validate_inputs(
        residual_packet=residual_packet,
        residual_wedge_spec=residual_wedge_spec,
        transfer_guard=transfer_guard,
        verdict_grammar=verdict_grammar,
        alpha_liability_registry=alpha_liability_registry,
        policy_registry=policy_registry,
    )

    subject_head = _resolve_subject_head(
        packets=[residual_packet, residual_wedge_spec, transfer_guard, verdict_grammar, alpha_liability_registry, policy_registry]
    )

    target_root = authoritative_root.resolve() if authoritative_root is not None else (root / "tmp" / "cohort0_single_axis_crucible_inputs").resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    inputs_root = (target_root / "single_axis_inputs").resolve()
    inputs_root.mkdir(parents=True, exist_ok=True)

    wedge_rows = _index_rows(residual_wedge_spec.get("rows", []), key="family_id")
    liability_rows = _index_rows(alpha_liability_registry.get("rows", []), key="family_id")

    family_order = [
        "P2_SIGNAL_NOISE_SEPARATION",
        "CHILD_ANOMALY_PRESERVATION",
        "STRATEGIST_CONSEQUENCE_CHAIN",
        "SCOUT_SPARSE_SEARCH",
        "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
        "BETA_SECOND_ORDER_REFRAME",
        "BOUNDARY_ABSTENTION_CONTROL",
        "STATIC_NO_ROUTE_CONTROL",
    ]

    family_rows: List[Dict[str, Any]] = []
    manifest_rows: List[Dict[str, Any]] = []
    for family_id in family_order:
        wedge_row = dict(wedge_rows[family_id])
        liability_row = dict(liability_rows.get(family_id, {}))
        family_rows.append(wedge_row)
        input_rows = [_input_row(family_row=wedge_row, liability_row=liability_row, level=level, frame=frame) for level in PRESSURE_LADDER for frame in PROMPT_FRAMES]
        family_dir = (inputs_root / family_id).resolve()
        family_dir.mkdir(parents=True, exist_ok=True)
        input_path = (family_dir / "single_axis_inputs.jsonl").resolve()
        _write_jsonl(input_path, input_rows)
        manifest_rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": str(wedge_row.get("target_lobe_id", "")).strip(),
                "control_family": bool(AXIS_BINDINGS[family_id].get("control_family", False)),
                "primary_pressure_axis": AXIS_BINDINGS[family_id]["primary_axis"],
                "secondary_pressure_axis": AXIS_BINDINGS[family_id]["secondary_axis"],
                "input_relpath": input_path.relative_to(target_root).as_posix(),
                "line_count": len(input_rows),
                "sha256": _file_sha256(input_path),
                "bytes": int(input_path.stat().st_size),
                "preferred_policy_outcome": _preferred_outcome(wedge_row),
                "new_admissible_eval_family": str(wedge_row.get("new_admissible_eval_family", "")).strip(),
            }
        )

    registry_rows = _build_registry_rows(family_rows=family_rows, liability_rows=liability_rows)
    failure_rows = _build_failure_rows(family_rows=family_rows)
    transfer_rows = _build_transfer_candidates(family_rows=family_rows)

    manifest = {
        "schema_id": "kt.operator.single_axis_crucible_input_manifest.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This manifest binds only one-axis-per-family crucible inputs. It does not reopen the counted lane or authorize composite pressure or learned routing.",
        "source_refs": {
            "residual_alpha_dominance_packet_ref": authoritative_residual_packet_path.as_posix(),
            "residual_alpha_dominance_wedge_spec_ref": authoritative_residual_wedge_spec_path.as_posix(),
            "lab_to_counted_transfer_guard_ref": authoritative_transfer_guard_path.as_posix(),
            "counted_lane_verdict_grammar_ref": authoritative_verdict_grammar_path.as_posix(),
            "alpha_liability_registry_ref": authoritative_alpha_liability_registry_path.as_posix(),
            "route_policy_outcome_registry_ref": authoritative_policy_registry_path.as_posix(),
        },
        "family_rows": manifest_rows,
        "control_family_ids": ["BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"],
        "stage_file_entries": _stage_entries(target_root),
    }

    registry = {
        "schema_id": "kt.operator.single_axis_crucible_registry.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This registry defines the lawful single-axis crucible objects only. It does not permit blended overload in the counted lane.",
        "rows": registry_rows,
    }
    ladder = {
        "schema_id": "kt.operator.single_axis_pressure_ladder.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This ladder raises one primary axis at a time. Composite overload remains out of scope for this tranche.",
        "rows": [
            {
                "family_id": family_id,
                "primary_pressure_axis": AXIS_BINDINGS[family_id]["primary_axis"],
                "secondary_pressure_axis": AXIS_BINDINGS[family_id]["secondary_axis"],
                "levels": list(PRESSURE_LADDER),
            }
            for family_id in family_order
        ],
    }
    expected_failures = {
        "schema_id": "kt.operator.single_axis_expected_failure_modes.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "These are preregistered expected failure modes for the single-axis lab lane only.",
        "rows": failure_rows,
    }
    transfer_candidates = {
        "schema_id": "kt.operator.single_axis_transfer_candidates.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "Transfer candidates remain pending until single-axis execution satisfies the transfer guard and counted proof objects move later.",
        "rows": transfer_rows,
    }
    receipt = {
        "schema_id": "kt.operator.single_axis_crucible_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "single_axis_posture": POSTURE,
        "claim_boundary": "This receipt binds only authored single-axis crucible inputs and lab-readiness. The counted ceiling remains unchanged.",
        "family_count": len(family_order),
        "control_family_ids": ["BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"],
        "prohibited_moves": [
            "No blended composite pressure yet.",
            "No counted-lane claim updates from authored inputs alone.",
            "No Kaggle use from this tranche by itself.",
            "No widening beyond the named eight families.",
        ],
        "verdict_grammar": [
            "NO_MEANINGFUL_WEDGE_SHARPENING",
            "WEDGE_SHARPENING_PRESENT_BUT_NO_TRANSFER_ELIGIBILITY",
            "ANTI_ALPHA_LIABILITY_EXPOSED_BUT_ROUTE_HYPOTHESIS_STILL_WEAK",
            "TRANSFER_CANDIDATE_ADMISSIBLE_FOR_COUNTED_LANE",
            "CONTAMINATION_DETECTED__RESULT_VOID",
        ],
        "next_lawful_move": NEXT_MOVE,
    }

    payloads = {
        "single_axis_crucible_input_manifest": manifest,
        "single_axis_crucible_registry": registry,
        "single_axis_pressure_ladder": ladder,
        "single_axis_expected_failure_modes": expected_failures,
        "single_axis_transfer_candidates": transfer_candidates,
        "single_axis_crucible_receipt": receipt,
    }

    for name, obj in payloads.items():
        write_json_stable((target_root / f"{name}.json").resolve(), obj)

    reports_root.mkdir(parents=True, exist_ok=True)
    carrier_names = {
        "single_axis_crucible_input_manifest": ("TRACKED_CARRIER_ONLY_SINGLE_AXIS_CRUCIBLE_INPUT_MANIFEST", DEFAULT_TRACKED_MANIFEST),
        "single_axis_crucible_registry": ("TRACKED_CARRIER_ONLY_SINGLE_AXIS_CRUCIBLE_REGISTRY", DEFAULT_TRACKED_REGISTRY),
        "single_axis_pressure_ladder": ("TRACKED_CARRIER_ONLY_SINGLE_AXIS_PRESSURE_LADDER", DEFAULT_TRACKED_LADDER),
        "single_axis_expected_failure_modes": ("TRACKED_CARRIER_ONLY_SINGLE_AXIS_EXPECTED_FAILURE_MODES", DEFAULT_TRACKED_FAILURES),
        "single_axis_transfer_candidates": ("TRACKED_CARRIER_ONLY_SINGLE_AXIS_TRANSFER_CANDIDATES", DEFAULT_TRACKED_TRANSFER),
        "single_axis_crucible_receipt": ("TRACKED_CARRIER_ONLY_SINGLE_AXIS_CRUCIBLE_RECEIPT", DEFAULT_TRACKED_RECEIPT),
    }
    for name, obj in payloads.items():
        carrier_role, tracked_name = carrier_names[name]
        tracked = dict(obj)
        tracked["carrier_surface_role"] = carrier_role
        tracked[f"authoritative_{name}_ref"] = (target_root / f"{name}.json").resolve().as_posix()
        write_json_stable((reports_root / tracked_name).resolve(), tracked)

    return payloads


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Author one-axis-per-family crucible inputs keyed to the residual alpha dominance wedge spec.")
    ap.add_argument("--residual-packet", default=DEFAULT_RESIDUAL_PACKET_REL)
    ap.add_argument("--residual-wedge-spec", default=DEFAULT_RESIDUAL_WEDGE_SPEC_REL)
    ap.add_argument("--transfer-guard", default=DEFAULT_TRANSFER_GUARD_REL)
    ap.add_argument("--verdict-grammar", default=DEFAULT_VERDICT_GRAMMAR_REL)
    ap.add_argument("--alpha-liability-registry", default=DEFAULT_ALPHA_LIABILITY_REGISTRY_REL)
    ap.add_argument("--policy-registry", default=DEFAULT_POLICY_REGISTRY_REL)
    ap.add_argument("--authoritative-root", default="")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_single_axis_crucible_input_tranche(
        residual_packet_path=_resolve(root, str(args.residual_packet)),
        residual_wedge_spec_path=_resolve(root, str(args.residual_wedge_spec)),
        transfer_guard_path=_resolve(root, str(args.transfer_guard)),
        verdict_grammar_path=_resolve(root, str(args.verdict_grammar)),
        alpha_liability_registry_path=_resolve(root, str(args.alpha_liability_registry)),
        policy_registry_path=_resolve(root, str(args.policy_registry)),
        authoritative_root=_resolve(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve(root, str(args.reports_root)),
        workspace_root=root,
    )
    receipt = payload["single_axis_crucible_receipt"]
    print(json.dumps({"status": receipt["status"], "single_axis_posture": receipt["single_axis_posture"], "next_lawful_move": receipt["next_lawful_move"]}, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
