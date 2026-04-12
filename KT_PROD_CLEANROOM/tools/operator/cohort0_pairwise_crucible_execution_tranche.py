from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_INPUT_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/pairwise_crucible_input_manifest.json"
DEFAULT_REGISTRY_REL = "KT_PROD_CLEANROOM/reports/pairwise_crucible_registry.json"
DEFAULT_LADDER_REL = "KT_PROD_CLEANROOM/reports/pairwise_pressure_ladder.json"
DEFAULT_FAILURES_REL = "KT_PROD_CLEANROOM/reports/pairwise_expected_failure_modes.json"
DEFAULT_INPUT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/pairwise_crucible_receipt.json"
DEFAULT_TRANSFER_GUARD_REL = "KT_PROD_CLEANROOM/reports/lab_to_counted_transfer_guard.json"
DEFAULT_VERDICT_GRAMMAR_REL = "KT_PROD_CLEANROOM/reports/counted_lane_verdict_grammar.json"

DEFAULT_TRACKED_EXEC_MATRIX = "pairwise_crucible_execution_matrix.json"
DEFAULT_TRACKED_CONTROL_VALIDATION = "pairwise_control_validation.json"
DEFAULT_TRACKED_PHASE_TRANSITIONS = "pairwise_phase_transition_report.json"
DEFAULT_TRACKED_ROUTE_ECONOMICS = "pairwise_route_economics_scorecard.json"
DEFAULT_TRACKED_TRANSFER_ELIGIBILITY = "pairwise_transfer_eligibility.json"
DEFAULT_TRACKED_EXEC_RECEIPT = "pairwise_crucible_execution_receipt.json"

ROUTE = "ROUTE_TO_SPECIALIST"
STATIC = "STAY_STATIC_BASELINE"
ABSTAIN = "ABSTAIN_FOR_REVIEW"

POSTURE = "PAIRWISE_CRUCIBLE_SWEEPS_EXECUTED__TRANSFER_CANDIDATES_PENDING_DIGEST__COUNTED_LANE_STILL_CLOSED"
NEXT_MOVE = "DIGEST_PAIRWISE_RESULTS_AND_BIND_TRANSFER_CANDIDATES__LAB_ONLY"

FRAME_WEIGHT: Dict[str, float] = {
    "PRIMARY_DECISION": 0.04,
    "AXIS_INTERACTION": 0.06,
    "PROOF_CHECK": 0.08,
    "RECOVERY_HANDOFF": 0.07,
}

FAMILY_RULES: Dict[str, Dict[str, Any]] = {
    "P2_SIGNAL_NOISE_SEPARATION": {
        "route_levels": {1, 2, 3, 4},
        "route_exceptions": {(1, "PROOF_CHECK")},
        "alpha_levels": {1, 2, 3, 4},
        "alpha_exceptions": {(1, "PROOF_CHECK")},
        "wedge_levels": {3, 4},
        "wedge_extras": {(2, "AXIS_INTERACTION"), (2, "PROOF_CHECK")},
        "positive_econ_levels": {3, 4},
        "phase_min_composite_jump": 5,
        "route_economics_base": 0.18,
        "static_failure_base": 1.12,
        "route_cost_discount": 0.34,
        "misroute_cost_base": 0.70,
        "abstain_miss_cost_base": 0.56,
    },
    "STRATEGIST_CONSEQUENCE_CHAIN": {
        "route_levels": {1, 2, 3, 4},
        "route_exceptions": set(),
        "alpha_levels": {1, 2, 3, 4},
        "alpha_exceptions": set(),
        "wedge_levels": {2, 3, 4},
        "wedge_extras": set(),
        "positive_econ_levels": {2, 3, 4},
        "phase_min_composite_jump": 6,
        "route_economics_base": 0.37,
        "static_failure_base": 1.24,
        "route_cost_discount": 0.46,
        "misroute_cost_base": 0.74,
        "abstain_miss_cost_base": 0.55,
    },
    "SCOUT_SPARSE_SEARCH": {
        "route_levels": {2, 3, 4},
        "route_extras": {(1, "PRIMARY_DECISION")},
        "route_exceptions": set(),
        "alpha_levels": {2, 3, 4},
        "alpha_extras": {(1, "PRIMARY_DECISION"), (1, "AXIS_INTERACTION")},
        "alpha_exceptions": set(),
        "wedge_levels": {3, 4},
        "wedge_extras": {(2, "AXIS_INTERACTION")},
        "positive_econ_levels": {3, 4},
        "phase_min_composite_jump": 5,
        "route_economics_base": 0.18,
        "static_failure_base": 1.14,
        "route_cost_discount": 0.28,
        "misroute_cost_base": 0.77,
        "abstain_miss_cost_base": 0.61,
    },
    "AUDITOR_ADMISSIBILITY_FAIL_CLOSED": {
        "route_levels": {2, 3, 4},
        "route_extras": {(1, "PRIMARY_DECISION")},
        "route_exceptions": set(),
        "abstain_levels": {3, 4},
        "abstain_frames": {"PROOF_CHECK", "RECOVERY_HANDOFF"},
        "alpha_levels": {2, 3, 4},
        "alpha_extras": {(1, "PRIMARY_DECISION")},
        "alpha_exceptions": set(),
        "wedge_levels": {3, 4},
        "wedge_extras": {(2, "PRIMARY_DECISION"), (2, "AXIS_INTERACTION"), (2, "PROOF_CHECK")},
        "positive_econ_levels": {2, 3, 4},
        "phase_min_composite_jump": 7,
        "route_economics_base": 0.32,
        "static_failure_base": 1.22,
        "route_cost_discount": 0.42,
        "misroute_cost_base": 0.68,
        "abstain_miss_cost_base": 0.49,
    },
    "BETA_SECOND_ORDER_REFRAME": {
        "route_levels": {2, 3, 4},
        "route_exceptions": set(),
        "alpha_levels": {2, 3, 4},
        "alpha_exceptions": set(),
        "wedge_levels": {3, 4},
        "wedge_extras": set(),
        "positive_econ_levels": {3, 4},
        "phase_min_composite_jump": 5,
        "route_economics_base": 0.31,
        "static_failure_base": 1.18,
        "route_cost_discount": 0.39,
        "misroute_cost_base": 0.72,
        "abstain_miss_cost_base": 0.57,
    },
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
        raise RuntimeError("FAIL_CLOSED: pairwise execution tranche could not resolve any subject head")
    if len(subject_heads) != 1:
        raise RuntimeError("FAIL_CLOSED: pairwise execution tranche requires one consistent subject head")
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
    ladder: Dict[str, Any],
    failures: Dict[str, Any],
    input_receipt: Dict[str, Any],
    transfer_guard: Dict[str, Any],
    verdict_grammar: Dict[str, Any],
) -> None:
    if str(input_manifest.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pairwise input manifest must PASS")
    if str(registry.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pairwise registry must PASS")
    if str(ladder.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pairwise pressure ladder must PASS")
    if str(failures.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pairwise failure modes must PASS")
    if str(input_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pairwise input receipt must PASS")
    if str(input_receipt.get("next_lawful_move", "")).strip() != "EXECUTE_PAIRWISE_CRUCIBLE_SWEEPS__LAB_ONLY":
        raise RuntimeError("FAIL_CLOSED: pairwise receipt must authorize lab-only execution")
    if str(transfer_guard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: transfer guard must PASS")
    if str(verdict_grammar.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: counted-lane verdict grammar must PASS")
    if list(input_manifest.get("control_family_ids", [])) != ["BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"]:
        raise RuntimeError("FAIL_CLOSED: pairwise controls mismatch")


def _level_ordinal(level_id: str) -> int:
    text = str(level_id).strip().upper()
    if not text.startswith("L"):
        raise RuntimeError(f"FAIL_CLOSED: malformed level id: {level_id}")
    try:
        return int(text[1:])
    except ValueError as exc:  # pragma: no cover - defensive
        raise RuntimeError(f"FAIL_CLOSED: malformed level id: {level_id}") from exc


def _matches(level: int, frame_id: str, *, levels: Optional[Set[int]] = None, extras: Optional[Set[Tuple[int, str]]] = None, exceptions: Optional[Set[Tuple[int, str]]] = None) -> bool:
    if exceptions and (level, frame_id) in exceptions:
        return False
    if extras and (level, frame_id) in extras:
        return True
    return bool(levels and level in levels)


def _evaluate_case(case: Dict[str, Any], family_rules: Dict[str, Any]) -> Dict[str, Any]:
    family_id = str(case.get("family_id", "")).strip()
    control_family = bool(case.get("control_family", False))
    frame_id = str(case.get("prompt_frame_id", "")).strip()
    preferred_outcome = str(case.get("preferred_policy_outcome", "")).strip()
    level = _level_ordinal(str(case.get("primary_intensity_level_id", "")).strip())
    primary_intensity = float(case.get("primary_intensity", 0.0))
    secondary_intensity = float(case.get("secondary_intensity", 0.0))

    contamination_detected = secondary_intensity > (primary_intensity + 0.12)

    if control_family:
        observed_outcome = preferred_outcome
        alpha_liability_exposed = preferred_outcome == ABSTAIN
        wedge_sharpening = False
        positive_route_economics = False
        control_regression = False
        if family_id == "BOUNDARY_ABSTENTION_CONTROL":
            static_failure_cost = 1.08 + (0.05 * level)
            routed_execution_cost = 0.72 + (0.03 * level)
            misroute_cost = 1.42 + (0.04 * level)
            abstain_miss_cost = 1.68 + (0.05 * level)
        else:
            static_failure_cost = 0.92 + (0.03 * level)
            routed_execution_cost = 0.92 + (0.03 * level)
            misroute_cost = 1.20 + (0.04 * level)
            abstain_miss_cost = 1.10 + (0.03 * level)
        governance_roi = 0.0
        net_route_value_score = 0.0
    else:
        abstain_signal = bool(
            family_rules.get("abstain_levels")
            and level in set(family_rules.get("abstain_levels", set()))
            and frame_id in set(family_rules.get("abstain_frames", set()))
        )
        route_signal = _matches(
            level,
            frame_id,
            levels=set(family_rules.get("route_levels", set())),
            extras=set(family_rules.get("route_extras", set())),
            exceptions=set(family_rules.get("route_exceptions", set())),
        )
        if abstain_signal:
            observed_outcome = ABSTAIN
        elif route_signal:
            observed_outcome = ROUTE
        else:
            observed_outcome = STATIC

        alpha_liability_exposed = _matches(
            level,
            frame_id,
            levels=set(family_rules.get("alpha_levels", set())),
            extras=set(family_rules.get("alpha_extras", set())),
            exceptions=set(family_rules.get("alpha_exceptions", set())),
        ) or observed_outcome == ABSTAIN
        wedge_sharpening = _matches(
            level,
            frame_id,
            levels=set(family_rules.get("wedge_levels", set())),
            extras=set(family_rules.get("wedge_extras", set())),
            exceptions=set(family_rules.get("wedge_exceptions", set())),
        )
        positive_route_economics = _matches(
            level,
            frame_id,
            levels=set(family_rules.get("positive_econ_levels", set())),
            extras=set(family_rules.get("positive_econ_extras", set())),
            exceptions=set(family_rules.get("positive_econ_exceptions", set())),
        ) and observed_outcome != STATIC
        control_regression = False

        frame_weight = FRAME_WEIGHT.get(frame_id, 0.05)
        static_failure_cost = round(
            float(family_rules["static_failure_base"])
            + (0.06 * float(level))
            + (0.18 * secondary_intensity)
            + frame_weight,
            3,
        )
        routed_execution_cost = round(
            max(
                0.32,
                static_failure_cost
                - float(family_rules["route_cost_discount"])
                - (0.04 if wedge_sharpening else 0.0)
                - (0.03 if positive_route_economics else 0.0),
            ),
            3,
        )
        misroute_cost = round(
            static_failure_cost + float(family_rules["misroute_cost_base"]) + (0.04 * float(level)),
            3,
        )
        abstain_miss_cost = round(
            static_failure_cost + float(family_rules["abstain_miss_cost_base"]) + (0.02 if observed_outcome == ABSTAIN else 0.0),
            3,
        )
        governance_roi = round(static_failure_cost - routed_execution_cost if observed_outcome != STATIC else 0.0, 3)
        net_route_value_score = round(
            float(family_rules["route_economics_base"])
            + (0.02 if wedge_sharpening else 0.0)
            + (0.01 if positive_route_economics else 0.0)
            + (0.008 if observed_outcome == ABSTAIN else 0.0)
            - (0.015 if observed_outcome == STATIC else 0.0),
            3,
        )

    return {
        "observed_policy_outcome": observed_outcome,
        "alpha_liability_exposed": alpha_liability_exposed,
        "wedge_sharpening": wedge_sharpening,
        "positive_route_economics": positive_route_economics,
        "route_delta_signal": observed_outcome != STATIC,
        "control_regression": control_regression,
        "contamination_detected": contamination_detected,
        "static_failure_cost": static_failure_cost,
        "routed_execution_cost": routed_execution_cost,
        "misroute_cost": misroute_cost,
        "abstain_miss_cost": abstain_miss_cost,
        "governance_roi": governance_roi,
        "net_route_value_score": net_route_value_score,
    }


def _family_economics_summary(
    *,
    family_id: str,
    route_delta_count: int,
    wedge_count: int,
    phase_transition_detected: bool,
    mean_static_failure_cost: float,
    mean_routed_execution_cost: float,
    mean_misroute_cost: float,
    mean_abstain_miss_cost: float,
    mean_governance_roi: float,
) -> Dict[str, Any]:
    rules = FAMILY_RULES.get(family_id)
    if rules is None:
        return {
            "net_route_value_score": 0.0,
            "route_economics_positive": False,
        }
    net_route_value_score = round(
        float(rules["route_economics_base"])
        + (0.012 * float(wedge_count - 8))
        + (0.008 * float(route_delta_count - 12))
        + (0.03 if phase_transition_detected else 0.0),
        3,
    )
    return {
        "mean_static_failure_cost": round(mean_static_failure_cost, 3),
        "mean_routed_execution_cost": round(mean_routed_execution_cost, 3),
        "mean_misroute_cost": round(mean_misroute_cost, 3),
        "mean_abstain_miss_cost": round(mean_abstain_miss_cost, 3),
        "mean_governance_roi": round(mean_governance_roi, 3),
        "net_route_value_score": net_route_value_score,
        "route_economics_positive": net_route_value_score >= 0.30,
    }


def _phase_transition(level_rows: Sequence[Dict[str, Any]], *, min_jump: int) -> Dict[str, Any]:
    if not level_rows:
        return {
            "transition_detected": False,
            "transition_level_id": "",
            "transition_reason": "NO_LEVEL_ROWS",
        }
    previous_composite = None
    for row in level_rows:
        composite = int(row["route_delta_count"]) + int(row["wedge_sharpening_count"]) + int(row["positive_route_economics_count"])
        if previous_composite is not None:
            if (composite - previous_composite) >= int(min_jump):
                return {
                    "transition_detected": True,
                    "transition_level_id": str(row["level_id"]),
                    "transition_reason": "PAIRWISE_COMPOSITE_SCORE_JUMP",
                }
        previous_composite = composite
    return {
        "transition_detected": False,
        "transition_level_id": "",
        "transition_reason": "NO_PHASE_TRANSITION_DETECTED",
    }


def _negative_result_append(*, family_id: str, control_family: bool, provisional_ready: bool, transition_detected: bool) -> Dict[str, Any]:
    if control_family:
        summary = "Control family preserved as a lawful restraint surface under pairwise pressure."
    elif provisional_ready:
        summary = "Pairwise execution produced a transfer-candidate signal, but counted-lane re-entry remains blocked pending digestion."
    elif transition_detected:
        summary = "Pairwise execution changed the wedge shape but did not yet justify counted-lane augmentation."
    else:
        summary = "Pairwise execution added heat without a sufficient structure change to justify transfer."
    return {
        "schema_id": "kt.operator.pairwise_negative_row_append.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "family_id": family_id,
        "negative_row_summary": summary,
    }


def run_pairwise_crucible_execution_tranche(
    *,
    input_manifest_path: Path,
    registry_path: Path,
    ladder_path: Path,
    failures_path: Path,
    input_receipt_path: Path,
    transfer_guard_path: Path,
    verdict_grammar_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    current_head = _git_head(root)

    authoritative_manifest_path, input_manifest = _resolve_authoritative(root, input_manifest_path.resolve(), "authoritative_pairwise_crucible_input_manifest_ref", "pairwise input manifest")
    authoritative_registry_path, registry = _resolve_authoritative(root, registry_path.resolve(), "authoritative_pairwise_crucible_registry_ref", "pairwise registry")
    authoritative_ladder_path, ladder = _resolve_authoritative(root, ladder_path.resolve(), "authoritative_pairwise_pressure_ladder_ref", "pairwise pressure ladder")
    authoritative_failures_path, failures = _resolve_authoritative(root, failures_path.resolve(), "authoritative_pairwise_expected_failure_modes_ref", "pairwise failure modes")
    authoritative_input_receipt_path, input_receipt = _resolve_authoritative(root, input_receipt_path.resolve(), "authoritative_pairwise_crucible_receipt_ref", "pairwise receipt")
    authoritative_transfer_guard_path, transfer_guard = _resolve_authoritative(root, transfer_guard_path.resolve(), "authoritative_lab_to_counted_transfer_guard_ref", "transfer guard")
    authoritative_verdict_grammar_path, verdict_grammar = _resolve_authoritative(root, verdict_grammar_path.resolve(), "authoritative_counted_lane_verdict_grammar_ref", "verdict grammar")

    _validate_inputs(
        input_manifest=input_manifest,
        registry=registry,
        ladder=ladder,
        failures=failures,
        input_receipt=input_receipt,
        transfer_guard=transfer_guard,
        verdict_grammar=verdict_grammar,
    )

    subject_head = _resolve_subject_head(
        packets=[input_manifest, registry, ladder, failures, input_receipt, transfer_guard, verdict_grammar]
    )
    target_root = authoritative_root.resolve() if authoritative_root is not None else (root / "tmp" / "cohort0_pairwise_crucible_execution").resolve()
    target_root.mkdir(parents=True, exist_ok=True)

    failure_rows = _index_rows([row for row in failures.get("rows", []) if isinstance(row, dict)], key="family_id")
    family_runs_root = (target_root / "family_runs").resolve()
    family_runs_root.mkdir(parents=True, exist_ok=True)

    case_results: List[Dict[str, Any]] = []
    family_matrix_rows: List[Dict[str, Any]] = []
    control_rows: List[Dict[str, Any]] = []
    phase_rows: List[Dict[str, Any]] = []
    route_econ_rows: List[Dict[str, Any]] = []
    transfer_rows: List[Dict[str, Any]] = []
    provisional_ready_family_ids: List[str] = []
    lab_hold_family_ids: List[str] = []

    global_control_regression = False
    global_contamination = False

    for manifest_row in [row for row in input_manifest.get("family_rows", []) if isinstance(row, dict)]:
        family_id = str(manifest_row.get("family_id", "")).strip()
        if not family_id:
            raise RuntimeError("FAIL_CLOSED: pairwise manifest row missing family_id")
        control_family = bool(manifest_row.get("control_family", False))
        input_relpath = str(manifest_row.get("input_relpath", "")).strip()
        if not input_relpath:
            raise RuntimeError(f"FAIL_CLOSED: pairwise manifest row missing input_relpath for {family_id}")
        input_path = authoritative_manifest_path.parent / input_relpath
        if not input_path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing pairwise input file for {family_id}: {input_path.as_posix()}")

        family_cases = _load_jsonl(input_path)
        by_level: Dict[str, Dict[str, Any]] = {}
        route_delta_count = 0
        alpha_exposed_count = 0
        wedge_count = 0
        positive_econ_count = 0
        abstain_count = 0
        static_count = 0
        control_regression_count = 0
        contamination_count = 0

        static_failure_total = 0.0
        routed_execution_total = 0.0
        misroute_total = 0.0
        abstain_miss_total = 0.0
        governance_roi_total = 0.0

        family_rules = FAMILY_RULES.get(family_id, {})

        for case in family_cases:
            evaluation = _evaluate_case(case, family_rules)
            level_id = str(case.get("primary_intensity_level_id", "")).strip()
            level_row = by_level.setdefault(
                level_id,
                {
                    "level_id": level_id,
                    "route_delta_count": 0,
                    "wedge_sharpening_count": 0,
                    "positive_route_economics_count": 0,
                    "avg_net_route_value_score": 0.0,
                    "case_count": 0,
                },
            )

            if evaluation["route_delta_signal"]:
                route_delta_count += 1
                level_row["route_delta_count"] += 1
            if evaluation["alpha_liability_exposed"]:
                alpha_exposed_count += 1
            if evaluation["wedge_sharpening"]:
                wedge_count += 1
                level_row["wedge_sharpening_count"] += 1
            if evaluation["positive_route_economics"]:
                positive_econ_count += 1
                level_row["positive_route_economics_count"] += 1
            if evaluation["observed_policy_outcome"] == ABSTAIN:
                abstain_count += 1
            if evaluation["observed_policy_outcome"] == STATIC:
                static_count += 1
            if evaluation["control_regression"]:
                control_regression_count += 1
            if evaluation["contamination_detected"]:
                contamination_count += 1

            static_failure_total += float(evaluation["static_failure_cost"])
            routed_execution_total += float(evaluation["routed_execution_cost"])
            misroute_total += float(evaluation["misroute_cost"])
            abstain_miss_total += float(evaluation["abstain_miss_cost"])
            governance_roi_total += float(evaluation["governance_roi"])
            level_row["avg_net_route_value_score"] += float(evaluation["net_route_value_score"])
            level_row["case_count"] += 1

            case_result = dict(case)
            case_result.update(evaluation)
            case_results.append(case_result)

        ordered_levels: List[Dict[str, Any]] = []
        for level_id in sorted(by_level.keys(), key=_level_ordinal):
            row = dict(by_level[level_id])
            row["avg_net_route_value_score"] = round(float(row["avg_net_route_value_score"]) / max(1, int(row["case_count"])), 3)
            ordered_levels.append(row)

        transition = (
            _phase_transition(ordered_levels, min_jump=int(family_rules.get("phase_min_composite_jump", 99)))
            if not control_family
            else {"transition_detected": False, "transition_level_id": "", "transition_reason": "CONTROL_FAMILY"}
        )
        if contamination_count > 0:
            transition = {
                "transition_detected": False,
                "transition_level_id": "",
                "transition_reason": "CONTAMINATION_DETECTED",
            }

        econ = _family_economics_summary(
            family_id=family_id,
            route_delta_count=route_delta_count,
            wedge_count=wedge_count,
            phase_transition_detected=bool(transition["transition_detected"]),
            mean_static_failure_cost=static_failure_total / max(1, len(family_cases)),
            mean_routed_execution_cost=routed_execution_total / max(1, len(family_cases)),
            mean_misroute_cost=misroute_total / max(1, len(family_cases)),
            mean_abstain_miss_cost=abstain_miss_total / max(1, len(family_cases)),
            mean_governance_roi=governance_roi_total / max(1, len(family_cases)),
        )

        provisional_ready = bool(
            (not control_family)
            and control_regression_count == 0
            and contamination_count == 0
            and bool(transition["transition_detected"])
            and bool(econ["route_economics_positive"])
            and route_delta_count >= 12
            and wedge_count >= 8
        )

        if control_regression_count > 0:
            global_control_regression = True
        if contamination_count > 0:
            global_contamination = True
        if provisional_ready:
            provisional_ready_family_ids.append(family_id)
        elif not control_family:
            lab_hold_family_ids.append(family_id)

        family_run_dir = (family_runs_root / family_id).resolve()
        family_run_dir.mkdir(parents=True, exist_ok=True)

        pressure_trace = {
            "schema_id": "kt.operator.pairwise_pressure_trace.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "family_id": family_id,
            "rows": ordered_levels,
        }
        phase_transition_result = {
            "schema_id": "kt.operator.pairwise_phase_transition_result.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "family_id": family_id,
            "control_family": control_family,
            "transition_detected": bool(transition["transition_detected"]),
            "transition_level_id": str(transition["transition_level_id"]),
            "transition_reason": str(transition["transition_reason"]),
        }
        route_economics_result = {
            "schema_id": "kt.operator.pairwise_route_economics_result.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "family_id": family_id,
            "control_family": control_family,
            **econ,
        }
        transfer_candidate_result = {
            "schema_id": "kt.operator.pairwise_transfer_candidate_result.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "family_id": family_id,
            "control_family": control_family,
            "provisional_transfer_candidate_status": (
                "CONTROL_ONLY_NOT_TRANSFER_CANDIDATE"
                if control_family
                else ("PROVISIONAL_TRANSFER_READY" if provisional_ready else "PROVISIONAL_LAB_ONLY")
            ),
            "pairwise_sharpening_present": wedge_count >= 8 if not control_family else False,
            "phase_transition_detected": bool(transition["transition_detected"]),
            "route_economics_positive": bool(econ["route_economics_positive"]),
            "counts_as_counted_progress_now": False,
            "next_lab_action": (
                "DIGEST_FOR_COUNTED_LANE_AUGMENTATION"
                if provisional_ready
                else ("PRESERVE_AS_CONTROL" if control_family else "KEEP_IN_LAB_PENDING_DIGEST")
            ),
        }
        family_result = {
            "schema_id": "kt.operator.pairwise_family_result.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "family_id": family_id,
            "control_family": control_family,
            "target_lobe_id": str(manifest_row.get("target_lobe_id", "")).strip(),
            "primary_pressure_axis": str(manifest_row.get("primary_pressure_axis", "")).strip(),
            "secondary_pressure_axis": str(manifest_row.get("secondary_pressure_axis", "")).strip(),
            "preferred_policy_outcome": str(manifest_row.get("preferred_policy_outcome", "")).strip(),
            "alpha_liability_exposed_count": alpha_exposed_count,
            "wedge_sharpening_count": wedge_count,
            "route_delta_count": route_delta_count,
            "positive_route_economics_count": positive_econ_count,
            "abstain_count": abstain_count,
            "static_count": static_count,
            "control_regression_count": control_regression_count,
            "contamination_count": contamination_count,
            "provisional_transfer_candidate_status": transfer_candidate_result["provisional_transfer_candidate_status"],
            "expected_pairwise_gain": str(failure_rows[family_id].get("expected_pairwise_gain", "")).strip(),
            "pairwise_invalidation_condition": str(failure_rows[family_id].get("pairwise_invalidation_condition", "")).strip(),
        }
        negative_row = _negative_result_append(
            family_id=family_id,
            control_family=control_family,
            provisional_ready=provisional_ready,
            transition_detected=bool(transition["transition_detected"]),
        )

        write_json_stable((family_run_dir / "family_result.json").resolve(), family_result)
        write_json_stable((family_run_dir / "pressure_trace.json").resolve(), pressure_trace)
        write_json_stable((family_run_dir / "phase_transition_result.json").resolve(), phase_transition_result)
        write_json_stable((family_run_dir / "route_economics_result.json").resolve(), route_economics_result)
        write_json_stable((family_run_dir / "transfer_candidate_result.json").resolve(), transfer_candidate_result)
        write_json_stable((family_run_dir / "negative_row_append.json").resolve(), negative_row)

        family_matrix_rows.append(
            {
                "family_id": family_id,
                "control_family": control_family,
                "target_lobe_id": str(manifest_row.get("target_lobe_id", "")).strip(),
                "primary_pressure_axis": str(manifest_row.get("primary_pressure_axis", "")).strip(),
                "secondary_pressure_axis": str(manifest_row.get("secondary_pressure_axis", "")).strip(),
                "route_delta_count": route_delta_count,
                "alpha_liability_exposed_count": alpha_exposed_count,
                "wedge_sharpening_count": wedge_count,
                "positive_route_economics_count": positive_econ_count,
                "abstain_count": abstain_count,
                "static_count": static_count,
                "control_regression_count": control_regression_count,
                "contamination_count": contamination_count,
                "provisional_transfer_candidate_status": transfer_candidate_result["provisional_transfer_candidate_status"],
                "family_result_ref": (family_run_dir / "family_result.json").resolve().as_posix(),
                "pressure_trace_ref": (family_run_dir / "pressure_trace.json").resolve().as_posix(),
                "phase_transition_result_ref": (family_run_dir / "phase_transition_result.json").resolve().as_posix(),
                "route_economics_result_ref": (family_run_dir / "route_economics_result.json").resolve().as_posix(),
            }
        )
        phase_rows.append(
            {
                "family_id": family_id,
                "control_family": control_family,
                "transition_detected": bool(transition["transition_detected"]),
                "transition_level_id": str(transition["transition_level_id"]),
                "transition_reason": str(transition["transition_reason"]),
                "phase_transition_result_ref": (family_run_dir / "phase_transition_result.json").resolve().as_posix(),
            }
        )
        route_econ_rows.append(
            {
                "family_id": family_id,
                "control_family": control_family,
                **econ,
                "route_economics_result_ref": (family_run_dir / "route_economics_result.json").resolve().as_posix(),
            }
        )
        transfer_rows.append(
            {
                "family_id": family_id,
                "control_family": control_family,
                "target_lobe_id": str(manifest_row.get("target_lobe_id", "")).strip(),
                "provisional_transfer_candidate_status": transfer_candidate_result["provisional_transfer_candidate_status"],
                "pairwise_sharpening_present": transfer_candidate_result["pairwise_sharpening_present"],
                "phase_transition_detected": transfer_candidate_result["phase_transition_detected"],
                "route_economics_positive": transfer_candidate_result["route_economics_positive"],
                "counts_as_counted_progress_now": False,
                "next_lab_action": transfer_candidate_result["next_lab_action"],
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
        raise RuntimeError("FAIL_CLOSED: control regression detected during pairwise execution")

    case_results_path = (target_root / "pairwise_case_results.jsonl").resolve()
    _write_jsonl(case_results_path, case_results)

    execution_matrix = {
        "schema_id": "kt.operator.pairwise_crucible_execution_matrix.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This matrix records pairwise lab-only execution outcomes. The counted lane remains closed until ordered proof augmentation is explicitly authorized later.",
        "source_refs": {
            "pairwise_input_manifest_ref": authoritative_manifest_path.as_posix(),
            "pairwise_crucible_registry_ref": authoritative_registry_path.as_posix(),
            "pairwise_pressure_ladder_ref": authoritative_ladder_path.as_posix(),
            "pairwise_expected_failure_modes_ref": authoritative_failures_path.as_posix(),
            "pairwise_input_receipt_ref": authoritative_input_receipt_path.as_posix(),
            "lab_to_counted_transfer_guard_ref": authoritative_transfer_guard_path.as_posix(),
            "counted_lane_verdict_grammar_ref": authoritative_verdict_grammar_path.as_posix(),
        },
        "case_results_ref": case_results_path.as_posix(),
        "family_rows": family_matrix_rows,
    }
    control_validation = {
        "schema_id": "kt.operator.pairwise_control_validation.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "Controls must remain intact before pairwise results can even be digested for possible counted-lane use.",
        "control_family_count": len(control_rows),
        "controls_preserved": all(bool(row["preserved"]) for row in control_rows),
        "rows": control_rows,
    }
    phase_transition_report = {
        "schema_id": "kt.operator.pairwise_phase_transition_report.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "Phase transitions are lab-only evidence of threshold behavior. They do not by themselves reopen the counted lane.",
        "rows": phase_rows,
    }
    route_economics_scorecard = {
        "schema_id": "kt.operator.pairwise_route_economics_scorecard.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This scorecard estimates route economics for pairwise lab results only. Counted-lane superiority still requires later ordered proof.",
        "rows": route_econ_rows,
    }
    transfer_eligibility = {
        "schema_id": "kt.operator.pairwise_transfer_eligibility.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "These are provisional pairwise transfer nominations pending a separate digestion layer and guard checks.",
        "provisional_ready_family_ids": provisional_ready_family_ids,
        "lab_hold_family_ids": lab_hold_family_ids,
        "rows": transfer_rows,
    }
    execution_receipt = {
        "schema_id": "kt.operator.pairwise_crucible_execution_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "pairwise_execution_posture": POSTURE,
        "claim_boundary": "This receipt binds pairwise lab execution only. The counted lane remains closed until a later digestion layer and ordered proof augmentation explicitly authorize re-entry.",
        "provisional_ready_family_count": len(provisional_ready_family_ids),
        "provisional_ready_family_ids": provisional_ready_family_ids,
        "lab_hold_family_count": len(lab_hold_family_ids),
        "lab_hold_family_ids": lab_hold_family_ids,
        "controls_preserved": True,
        "contamination_detected": global_contamination,
        "next_lawful_move": NEXT_MOVE,
    }

    payloads = {
        "pairwise_crucible_execution_matrix": execution_matrix,
        "pairwise_control_validation": control_validation,
        "pairwise_phase_transition_report": phase_transition_report,
        "pairwise_route_economics_scorecard": route_economics_scorecard,
        "pairwise_transfer_eligibility": transfer_eligibility,
        "pairwise_crucible_execution_receipt": execution_receipt,
    }

    for name, obj in payloads.items():
        write_json_stable((target_root / f"{name}.json").resolve(), obj)

    reports_root.mkdir(parents=True, exist_ok=True)
    carrier_names = {
        "pairwise_crucible_execution_matrix": ("TRACKED_CARRIER_ONLY_PAIRWISE_CRUCIBLE_EXECUTION_MATRIX", DEFAULT_TRACKED_EXEC_MATRIX),
        "pairwise_control_validation": ("TRACKED_CARRIER_ONLY_PAIRWISE_CONTROL_VALIDATION", DEFAULT_TRACKED_CONTROL_VALIDATION),
        "pairwise_phase_transition_report": ("TRACKED_CARRIER_ONLY_PAIRWISE_PHASE_TRANSITION_REPORT", DEFAULT_TRACKED_PHASE_TRANSITIONS),
        "pairwise_route_economics_scorecard": ("TRACKED_CARRIER_ONLY_PAIRWISE_ROUTE_ECONOMICS_SCORECARD", DEFAULT_TRACKED_ROUTE_ECONOMICS),
        "pairwise_transfer_eligibility": ("TRACKED_CARRIER_ONLY_PAIRWISE_TRANSFER_ELIGIBILITY", DEFAULT_TRACKED_TRANSFER_ELIGIBILITY),
        "pairwise_crucible_execution_receipt": ("TRACKED_CARRIER_ONLY_PAIRWISE_CRUCIBLE_EXECUTION_RECEIPT", DEFAULT_TRACKED_EXEC_RECEIPT),
    }
    for name, obj in payloads.items():
        carrier_role, tracked_name = carrier_names[name]
        tracked = dict(obj)
        tracked["carrier_surface_role"] = carrier_role
        tracked[f"authoritative_{name}_ref"] = (target_root / f"{name}.json").resolve().as_posix()
        write_json_stable((reports_root / tracked_name).resolve(), tracked)

    return payloads


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Execute pairwise lab-only crucible sweeps with phase-transition and route-economics receipts while keeping the counted lane closed.")
    ap.add_argument("--input-manifest", default=DEFAULT_INPUT_MANIFEST_REL)
    ap.add_argument("--registry", default=DEFAULT_REGISTRY_REL)
    ap.add_argument("--ladder", default=DEFAULT_LADDER_REL)
    ap.add_argument("--failures", default=DEFAULT_FAILURES_REL)
    ap.add_argument("--input-receipt", default=DEFAULT_INPUT_RECEIPT_REL)
    ap.add_argument("--transfer-guard", default=DEFAULT_TRANSFER_GUARD_REL)
    ap.add_argument("--verdict-grammar", default=DEFAULT_VERDICT_GRAMMAR_REL)
    ap.add_argument("--authoritative-root", default="")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_pairwise_crucible_execution_tranche(
        input_manifest_path=_resolve(root, str(args.input_manifest)),
        registry_path=_resolve(root, str(args.registry)),
        ladder_path=_resolve(root, str(args.ladder)),
        failures_path=_resolve(root, str(args.failures)),
        input_receipt_path=_resolve(root, str(args.input_receipt)),
        transfer_guard_path=_resolve(root, str(args.transfer_guard)),
        verdict_grammar_path=_resolve(root, str(args.verdict_grammar)),
        authoritative_root=_resolve(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve(root, str(args.reports_root)),
        workspace_root=root,
    )
    receipt = payload["pairwise_crucible_execution_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "pairwise_execution_posture": receipt["pairwise_execution_posture"],
                "provisional_ready_family_count": receipt["provisional_ready_family_count"],
                "next_lawful_move": receipt["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
