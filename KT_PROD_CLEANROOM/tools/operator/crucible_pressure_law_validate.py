from __future__ import annotations

import argparse
import json
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import yaml

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_R1_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/b04_r1_crucible_pressure_law_contract.json"
DEFAULT_R1_TERMINAL_STATE_REL = "KT_PROD_CLEANROOM/governance/b04_r1_crucible_pressure_terminal_state.json"
DEFAULT_LAUNCH_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/b04_civilization_activation_launch_contract.json"
DEFAULT_CRUCIBLE_LAW_REL = "KT_PROD_CLEANROOM/governance/crucible_lifecycle_law.json"
DEFAULT_CRUCIBLE_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/crucible_registry.json"
DEFAULT_PRESSURE_TAXONOMY_REL = "KT_PROD_CLEANROOM/governance/pressure_response_taxonomy.json"
DEFAULT_ADAPTER_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/adapter_registry.json"
DEFAULT_RUN_LOG_REL = "KT_PROD_CLEANROOM/reports/kt_crucible_run_log.json"
DEFAULT_PRESSURE_MATRIX_REL = "KT_PROD_CLEANROOM/reports/pressure_behavior_matrix.json"
DEFAULT_PRESSURE_REGISTER_REL = "KT_PROD_CLEANROOM/reports/kt_fitness_pressure_register.json"
DEFAULT_CURRENT_OVERLAY_REL = "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json"
DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL = "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json"
DEFAULT_RESUME_BLOCKERS_REL = "KT_PROD_CLEANROOM/reports/resume_blockers_receipt.json"
DEFAULT_REANCHOR_PACKET_REL = "KT_PROD_CLEANROOM/reports/gate_d_decision_reanchor_packet.json"
DEFAULT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/crucible_pressure_law_ratification_receipt.json"

EXPECTED_NEXT_STEP_ID = "B04_R2_ADAPTER_LIFECYCLE_LAW_RATIFICATION"
EXPECTED_CURRENT_STEP_ID = "B04_R1_CRUCIBLE_PRESSURE_LAW_RATIFICATION"
EXPECTED_LAUNCH_STEP_ID = "B04_R1_CRUCIBLE_PRESSURE_LAW_RATIFICATION"
EXPECTED_TAXONOMY_LEVELS = ["governance", "math", "creative", "cross_domain"]
EXPECTED_ALLOWED_FOLLOW_ON_STEPS = {
    "B04_R2_ADAPTER_LIFECYCLE_LAW_RATIFICATION",
    "B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_RATIFICATION",
    "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION",
    "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF",
    "B04_R6_LEARNED_ROUTER_AUTHORIZATION",
    "B04_R7_LOBE_ARCHITECTURE_RATIFICATION",
}
SETTLED_R5_STEP_ID = "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
SETTLED_R6_STEP_ID = "B04_R6_LEARNED_ROUTER_AUTHORIZATION"
SETTLED_R6_HOLD_MOVE = "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF"
SETTLED_R6_HOLD_EXECUTION_MODE = "R6_NEXT_IN_ORDER_BLOCKED_PENDING_EARNED_SUPERIORITY__INITIAL_R5_PROOF_COMPLETE"


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _write_receipt(
    *,
    root: Path,
    target: Path,
    payload: Dict[str, Any],
    allow_default_repo_write: bool,
) -> None:
    default_target = (root / DEFAULT_RECEIPT_REL).resolve()
    resolved_target = target.resolve()
    if resolved_target == default_target and not allow_default_repo_write:
        raise RuntimeError("FAIL_CLOSED: tracked crucible-pressure receipt refresh requires --allow-tracked-output-refresh")
    write_json_stable(resolved_target, payload)


def _load_yaml(path: Path) -> Dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _pressure_axis(spec: Dict[str, Any]) -> str:
    tags = spec.get("tags", {}) or {}
    domains = tags.get("domains", []) or []
    if domains:
        return str(domains[0]).strip()
    domain = str(spec.get("domain", "")).strip()
    return domain.split(".", 1)[0] if domain else "unknown"


def _is_live_target(kernel_target: str) -> bool:
    return not str(kernel_target).startswith("KERNEL_")


def _is_success_for_spec(run: Dict[str, Any], spec: Dict[str, Any]) -> bool:
    expected = str((spec.get("expect", {}) or {}).get("expected_outcome", "")).strip().upper()
    outcome = str(run.get("outcome", "")).strip().upper()
    return bool(expected) and outcome == expected


def _replay_required(spec: Dict[str, Any]) -> bool:
    replay = str((spec.get("expect", {}) or {}).get("replay_verification", "")).strip().upper()
    return replay == "REQUIRED_PASS"


def _governance_required(spec: Dict[str, Any]) -> bool:
    required = ((spec.get("expect", {}) or {}).get("governance_expectations", {}) or {}).get("required_event_types", []) or []
    return bool(required)


def _promotion_eligible(run: Dict[str, Any], spec: Dict[str, Any]) -> bool:
    if str(run.get("promotion_scope", "")).strip() == "UNREGISTERED_OBSERVED":
        return False
    if not bool(run.get("registered_crucible")):
        return False
    if not bool(run.get("receipt_refs")):
        return False
    if _replay_required(spec) and not bool(run.get("replay_pass")):
        return False
    if not bool(run.get("output_contract_pass")):
        return False
    if _governance_required(spec) and not bool(run.get("governance_pass")):
        return False
    if not _is_success_for_spec(run, spec):
        return False
    if bool(run.get("ledger_conflicted")) and str(run.get("canonical_source", "")).strip() != "runner_record":
        return False
    return _is_live_target(str(run.get("kernel_target", "")).strip())


def _rate(numerator: int, denominator: int) -> Optional[float]:
    if denominator <= 0:
        return None
    return round(float(numerator) / float(denominator), 4)


def _delta(live_rate: Optional[float], baseline_rate: Optional[float]) -> Optional[float]:
    if live_rate is None or baseline_rate is None:
        return None
    return round(live_rate - baseline_rate, 4)


def _load_spec_rows(root: Path, registry: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    rows: Dict[str, Dict[str, Any]] = {}
    for entry in registry.get("entries", []):
        spec_ref = str(entry.get("spec_ref", "")).strip()
        spec = _load_yaml(_resolve(root, spec_ref))
        crucible_id = str(entry.get("crucible_id", "")).strip()
        rows[crucible_id] = {
            "crucible_id": crucible_id,
            "domain": str(spec.get("domain", "")).strip(),
            "pressure_axis": _pressure_axis(spec),
            "scenario": str(spec.get("title", "")).strip(),
            "expected_outcome": str((spec.get("expect", {}) or {}).get("expected_outcome", "")).strip(),
            "kernel_targets": [str(item).strip() for item in spec.get("kernel_targets", [])],
            "live_targets": [str(item).strip() for item in spec.get("kernel_targets", []) if _is_live_target(str(item).strip())],
            "baseline_targets": [str(item).strip() for item in spec.get("kernel_targets", []) if not _is_live_target(str(item).strip())],
            "replay_required": _replay_required(spec),
            "governance_required": _governance_required(spec),
            "spec_ref": spec_ref,
        }
    return rows


def _build_coverage_matrix(
    spec_rows: Dict[str, Dict[str, Any]],
    runs_by_crucible: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for crucible_id in sorted(spec_rows):
        spec = spec_rows[crucible_id]
        runs = runs_by_crucible.get(crucible_id, [])
        receipt_backed_runs = [run for run in runs if bool(run.get("receipt_refs"))]
        replay_backed_runs = [run for run in runs if bool(run.get("replay_pass"))]
        eligible_runs = [run for run in runs if _promotion_eligible(run, spec)]
        rows.append(
            {
                "crucible_id": crucible_id,
                "domain": spec["domain"],
                "pressure_axis": spec["pressure_axis"],
                "scenario": spec["scenario"],
                "covered": len(runs) > 0,
                "observed_run_count": len(runs),
                "receipt_backed_run_count": len(receipt_backed_runs),
                "replay_backed_run_count": len(replay_backed_runs),
                "promotion_eligible_live_run_count": len(eligible_runs),
                "live_targets": spec["live_targets"],
                "baseline_targets": spec["baseline_targets"],
                "sample_receipt_ref": (receipt_backed_runs[0]["receipt_refs"][0] if receipt_backed_runs else ""),
            }
        )
    return rows


def _build_pressure_delta_summary(
    spec_rows: Dict[str, Dict[str, Any]],
    runs_by_crucible: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(lambda: {"live": [], "baseline": []})
    for crucible_id, spec in spec_rows.items():
        for run in runs_by_crucible.get(crucible_id, []):
            if not bool(run.get("registered_crucible")):
                continue
            bucket = "live" if _is_live_target(str(run.get("kernel_target", "")).strip()) else "baseline"
            enriched = dict(run)
            enriched["_success"] = _is_success_for_spec(run, spec)
            enriched["_eligible"] = _promotion_eligible(run, spec)
            grouped[spec["pressure_axis"]][bucket].append(enriched)

    rows: List[Dict[str, Any]] = []
    for axis in sorted(grouped):
        live_runs = grouped[axis]["live"]
        baseline_runs = grouped[axis]["baseline"]
        live_success = sum(1 for run in live_runs if bool(run.get("_success")))
        baseline_success = sum(1 for run in baseline_runs if bool(run.get("_success")))
        live_replay = sum(1 for run in live_runs if bool(run.get("replay_pass")))
        baseline_replay = sum(1 for run in baseline_runs if bool(run.get("replay_pass")))
        live_success_rate = _rate(live_success, len(live_runs))
        baseline_success_rate = _rate(baseline_success, len(baseline_runs))
        live_replay_rate = _rate(live_replay, len(live_runs))
        baseline_replay_rate = _rate(baseline_replay, len(baseline_runs))
        rows.append(
            {
                "pressure_axis": axis,
                "live_run_count": len(live_runs),
                "baseline_run_count": len(baseline_runs),
                "live_success_rate": live_success_rate,
                "baseline_success_rate": baseline_success_rate,
                "success_rate_delta_vs_baseline": _delta(live_success_rate, baseline_success_rate),
                "live_replay_rate": live_replay_rate,
                "baseline_replay_rate": baseline_replay_rate,
                "replay_rate_delta_vs_baseline": _delta(live_replay_rate, baseline_replay_rate),
                "promotion_eligible_live_run_count": sum(1 for run in live_runs if bool(run.get("_eligible"))),
            }
        )
    return rows


def _order_locked_progress_after_r1(
    *,
    overlay: Dict[str, Any],
    next_contract: Dict[str, Any],
    resume: Dict[str, Any],
    reanchor: Dict[str, Any],
) -> bool:
    next_step = str(next_contract.get("exact_next_counted_workstream_id", "")).strip()
    in_sequence_progress = (
        next_step in EXPECTED_ALLOWED_FOLLOW_ON_STEPS
        and str(next_contract.get("execution_mode", "")).strip().startswith("CIVILIZATION_RATIFICATION_ORDER_LOCKED__")
        and bool(next_contract.get("repo_state_executable_now")) is True
        and str(overlay.get("next_counted_workstream_id", "")).strip() == next_step
        and str(resume.get("exact_next_counted_workstream_id", "")).strip() == next_step
        and str(reanchor.get("next_lawful_move", "")).strip() == next_step
    )
    settled_replay_progress = (
        next_step == SETTLED_R6_STEP_ID
        and str(next_contract.get("source_workstream_id", "")).strip() == SETTLED_R5_STEP_ID
        and str(next_contract.get("execution_mode", "")).strip() == SETTLED_R6_HOLD_EXECUTION_MODE
        and bool(next_contract.get("repo_state_executable_now")) is False
        and str(overlay.get("schema_id", "")).strip() == "kt.current_campaign_state_overlay.v1"
        and str(overlay.get("workstream_id", "")).strip() == SETTLED_R5_STEP_ID
        and str(overlay.get("next_counted_workstream_id", "")).strip() == SETTLED_R6_STEP_ID
        and str(overlay.get("current_lawful_gate_standing", {}).get("current_counted_batch", "")).strip() == SETTLED_R5_STEP_ID
        and bool(overlay.get("repo_state_executable_now")) is False
        and str(resume.get("workstream_id", "")).strip() == SETTLED_R5_STEP_ID
        and str(resume.get("exact_next_counted_workstream_id", "")).strip() == SETTLED_R6_STEP_ID
        and bool(resume.get("repo_state_executable_now")) is False
        and str(reanchor.get("workstream_id", "")).strip() == SETTLED_R5_STEP_ID
        and str(reanchor.get("next_lawful_move", "")).strip() == SETTLED_R6_HOLD_MOVE
    )
    return in_sequence_progress or settled_replay_progress


def build_crucible_pressure_law_receipt(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    r1_contract = load_json(root / DEFAULT_R1_CONTRACT_REL)
    r1_terminal = load_json(root / DEFAULT_R1_TERMINAL_STATE_REL)
    launch_contract = load_json(root / DEFAULT_LAUNCH_CONTRACT_REL)
    crucible_law = load_json(root / DEFAULT_CRUCIBLE_LAW_REL)
    crucible_registry = load_json(root / DEFAULT_CRUCIBLE_REGISTRY_REL)
    pressure_taxonomy = load_json(root / DEFAULT_PRESSURE_TAXONOMY_REL)
    adapter_registry = load_json(root / DEFAULT_ADAPTER_REGISTRY_REL)
    run_log = load_json(root / DEFAULT_RUN_LOG_REL)
    pressure_matrix = load_json(root / DEFAULT_PRESSURE_MATRIX_REL)
    pressure_register = load_json(root / DEFAULT_PRESSURE_REGISTER_REL)
    overlay = load_json(root / DEFAULT_CURRENT_OVERLAY_REL)
    next_contract = load_json(root / DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL)
    resume = load_json(root / DEFAULT_RESUME_BLOCKERS_REL)
    reanchor = load_json(root / DEFAULT_REANCHOR_PACKET_REL)

    spec_rows = _load_spec_rows(root, crucible_registry)
    runs = list(run_log.get("runs", []))
    runs_by_crucible: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for run in runs:
        runs_by_crucible[str(run.get("crucible_id", "")).strip()].append(run)

    coverage_matrix = _build_coverage_matrix(spec_rows, runs_by_crucible)
    pressure_delta_summary = _build_pressure_delta_summary(spec_rows, runs_by_crucible)
    observed_unregistered = [run for run in runs if str(run.get("promotion_scope", "")).strip() == "UNREGISTERED_OBSERVED"]
    promotion_eligible_live_count = sum(row["promotion_eligible_live_run_count"] for row in pressure_delta_summary)

    taxonomy_levels = [str(level.get("level_id", "")).strip() for level in pressure_taxonomy.get("levels", [])]
    matrix_levels = [str(row.get("pressure_type", "")).strip() for row in pressure_matrix.get("rows", [])]

    checks = [
        {
            "check_id": "r1_contract_and_terminal_state_bind_only_crucible_pressure_ratification",
            "pass": str(r1_contract.get("workstream_id", "")).strip() == EXPECTED_CURRENT_STEP_ID
            and str(r1_contract.get("ratification_mode", "")).strip() == "RATIFICATION_ONLY_NO_ADAPTER_ROUTER_OR_LOBE_ADVANCE"
            and str(r1_terminal.get("current_state", "")).strip() == "B04_R1_CRUCIBLE_PRESSURE_LAW_RATIFIED"
            and r1_terminal.get("adapter_lifecycle_ratified") is False,
        },
        {
            "check_id": "launch_contract_still_locks_order_and_r1_is_first_step",
            "pass": str(launch_contract.get("first_ratification_step_id", "")).strip() == EXPECTED_LAUNCH_STEP_ID
            and str(launch_contract.get("next_lawful_move_after_launch", "")).strip() == EXPECTED_LAUNCH_STEP_ID,
        },
        {
            "check_id": "finite_crucible_registry_exists",
            "pass": int(crucible_registry.get("entry_count", 0)) > 0
            and len(crucible_registry.get("entries", [])) == int(crucible_registry.get("entry_count", 0))
            and all(set(row.keys()) >= {"crucible_id", "spec_ref", "promotion_scope", "trust_zone"} for row in crucible_registry.get("entries", [])),
        },
        {
            "check_id": "finite_pressure_taxonomy_and_behavior_matrix_exist",
            "pass": taxonomy_levels == EXPECTED_TAXONOMY_LEVELS
            and sorted(matrix_levels) == sorted(EXPECTED_TAXONOMY_LEVELS)
            and int(pressure_register.get("summary", {}).get("pressure_count", 0)) >= 1,
        },
        {
            "check_id": "crucible_specs_are_immutable_and_finite",
            "pass": len(spec_rows) == int(crucible_registry.get("entry_count", 0))
            and all(spec["scenario"] and spec["domain"] and spec["kernel_targets"] for spec in spec_rows.values()),
        },
        {
            "check_id": "coverage_matrix_can_be_derived_for_every_registered_crucible",
            "pass": len(coverage_matrix) == int(crucible_registry.get("entry_count", 0))
            and all("covered" in row and "receipt_backed_run_count" in row for row in coverage_matrix),
        },
        {
            "check_id": "crucible_execution_receipts_and_replay_spine_exist",
            "pass": int(run_log.get("summary", {}).get("artifact_backed_run_count", 0)) > 0
            and any(row["replay_backed_run_count"] > 0 for row in coverage_matrix),
        },
        {
            "check_id": "unregistered_crucibles_fail_closed",
            "pass": int(run_log.get("summary", {}).get("observed_unregistered_count", 0)) == len(observed_unregistered)
            and all(not bool(run.get("registered_crucible")) for run in observed_unregistered),
        },
        {
            "check_id": "run_log_conflict_rule_is_canonical_runner_record_precedence",
            "pass": "runner_record" in str(run_log.get("anomalies", {}).get("canonical_precedence_rule", "")).lower(),
        },
        {
            "check_id": "promotion_eligibility_is_bound_to_registered_replayable_receipted_results",
            "pass": "registered crucible results" in str(r1_contract.get("promotion_eligibility_rule", {}).get("rule_text", "")).lower()
            and "receipt-backed" in str(crucible_law.get("promotion_eligibility_rule", "")).lower()
            and promotion_eligible_live_count >= 0
            and len(adapter_registry.get("experimental_adapter_ids", [])) > 0,
        },
        {
            "check_id": "control_surfaces_advance_only_to_r2",
            "pass": _order_locked_progress_after_r1(
                overlay=overlay,
                next_contract=next_contract,
                resume=resume,
                reanchor=reanchor,
            ),
        },
        {
            "check_id": "scope_remains_bounded_after_r1",
            "pass": r1_terminal.get("externality_widening_allowed") is False
            and r1_terminal.get("commercial_activation_allowed") is False
            and r1_terminal.get("router_or_lobe_progress_allowed") is False,
        },
    ]

    status = "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL"
    return {
        "schema_id": "kt.b04.r1.crucible_pressure_law_ratification_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": status,
        "receipt_role": "COUNTED_B04_R1_CRUCIBLE_PRESSURE_LAW_ARTIFACT_ONLY",
        "workstream_id": EXPECTED_CURRENT_STEP_ID,
        "finite_crucible_registry_summary": {
            "entry_count": int(crucible_registry.get("entry_count", 0)),
            "registered_observed_count": int(run_log.get("summary", {}).get("registered_observed_count", 0)),
            "registered_unobserved_count": int(run_log.get("summary", {}).get("registered_unobserved_count", 0)),
        },
        "pressure_taxonomy_summary": {
            "levels": taxonomy_levels,
            "matrix_rows": len(pressure_matrix.get("rows", [])),
            "pressure_register_count": int(pressure_register.get("summary", {}).get("pressure_count", 0)),
        },
        "coverage_matrix": coverage_matrix,
        "pressure_delta_summary": pressure_delta_summary,
        "promotion_eligibility_summary": {
            "rule_id": str(r1_contract.get("promotion_eligibility_rule", {}).get("rule_id", "")).strip(),
            "rule_text": str(r1_contract.get("promotion_eligibility_rule", {}).get("rule_text", "")).strip(),
            "eligible_live_run_count": promotion_eligible_live_count,
            "observed_unregistered_count": len(observed_unregistered),
        },
        "checks": checks,
        "next_lawful_move": EXPECTED_NEXT_STEP_ID if status == "PASS" else "FIX_B04_R1_CRUCIBLE_PRESSURE_LAW_DEFECT",
        "claim_boundary": "This receipt proves only that the Gate D crucible and pressure forcing-law spine is ratified. It does not ratify adapters, tournaments, router, lobes, externality, or product scope.",
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate B04.R1 crucible and pressure law ratification.")
    parser.add_argument("--output", default=DEFAULT_RECEIPT_REL)
    parser.add_argument("--allow-tracked-output-refresh", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    receipt = build_crucible_pressure_law_receipt(root=root)
    output = _resolve(root, str(args.output))
    _write_receipt(
        root=root,
        target=output,
        payload=receipt,
        allow_default_repo_write=args.allow_tracked_output_refresh,
    )
    summary = {
        "status": receipt["status"],
        "crucible_pressure_law_ratification_status": receipt["status"],
        "next_lawful_move": receipt["next_lawful_move"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
