from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_R2_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/b04_r2_adapter_lifecycle_law_contract.json"
DEFAULT_R2_TERMINAL_STATE_REL = "KT_PROD_CLEANROOM/governance/b04_r2_adapter_lifecycle_terminal_state.json"
DEFAULT_R1_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/b04_r1_crucible_pressure_law_contract.json"
DEFAULT_R1_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/crucible_pressure_law_ratification_receipt.json"
DEFAULT_ADAPTER_LIFECYCLE_REL = "KT_PROD_CLEANROOM/governance/adapter_lifecycle_law.json"
DEFAULT_ADAPTER_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/adapter_registry.json"
DEFAULT_OPERATOR_REGISTRY_REL = "KT_PROD_CLEANROOM/reports/kt_adapter_registry.json"
DEFAULT_LINEAGE_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/kt_lineage_manifest.json"
DEFAULT_RECEIPT_LINEAGE_REL = "KT_PROD_CLEANROOM/reports/kt_receipt_lineage_register.json"
DEFAULT_UNIVERSAL_ADAPTER_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/universal_adapter_receipt.json"
DEFAULT_PROMOTION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/promotion_receipt.json"
DEFAULT_ROLLBACK_PLAN_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/rollback_plan_receipt.json"
DEFAULT_ADAPTER_RUNTIME_BOUNDARY_REL = "KT_PROD_CLEANROOM/reports/b02_adapter_runtime_boundary_receipt.json"
DEFAULT_CURRENT_OVERLAY_REL = "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json"
DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL = "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json"
DEFAULT_RESUME_BLOCKERS_REL = "KT_PROD_CLEANROOM/reports/resume_blockers_receipt.json"
DEFAULT_REANCHOR_PACKET_REL = "KT_PROD_CLEANROOM/reports/gate_d_decision_reanchor_packet.json"
DEFAULT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/adapter_lifecycle_law_ratification_receipt.json"

EXPECTED_CURRENT_STEP_ID = "B04_R2_ADAPTER_LIFECYCLE_LAW_RATIFICATION"
EXPECTED_NEXT_STEP_ID = "B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_RATIFICATION"
EXPECTED_STATE_IDS = [
    "PROPOSED",
    "REGISTERED",
    "IN_CRUCIBLE",
    "EVIDENCE_ACCUMULATING",
    "ELIGIBLE",
    "TOURNAMENT_READY",
    "PROMOTED",
    "SHADOW_ACTIVE",
    "GOVERNED_ACTIVE",
    "DEMOTED",
    "RETIRED",
    "MERGED",
]
EXPECTED_EXECUTION_MODE = "CIVILIZATION_RATIFICATION_ORDER_LOCKED__THIRD_STEP_ONLY"


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
        raise RuntimeError("FAIL_CLOSED: tracked adapter-lifecycle receipt refresh requires --allow-tracked-output-refresh")
    write_json_stable(resolved_target, payload)


def build_adapter_lifecycle_law_receipt(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    r2_contract = load_json(root / DEFAULT_R2_CONTRACT_REL)
    r2_terminal = load_json(root / DEFAULT_R2_TERMINAL_STATE_REL)
    r1_contract = load_json(root / DEFAULT_R1_CONTRACT_REL)
    r1_receipt = load_json(root / DEFAULT_R1_RECEIPT_REL)
    lifecycle_law = load_json(root / DEFAULT_ADAPTER_LIFECYCLE_REL)
    adapter_registry = load_json(root / DEFAULT_ADAPTER_REGISTRY_REL)
    operator_registry = load_json(root / DEFAULT_OPERATOR_REGISTRY_REL)
    lineage_manifest = load_json(root / DEFAULT_LINEAGE_MANIFEST_REL)
    receipt_lineage = load_json(root / DEFAULT_RECEIPT_LINEAGE_REL)
    universal_adapter_receipt = load_json(root / DEFAULT_UNIVERSAL_ADAPTER_RECEIPT_REL)
    promotion_receipt = load_json(root / DEFAULT_PROMOTION_RECEIPT_REL)
    rollback_plan_receipt = load_json(root / DEFAULT_ROLLBACK_PLAN_RECEIPT_REL)
    adapter_runtime_boundary = load_json(root / DEFAULT_ADAPTER_RUNTIME_BOUNDARY_REL)
    overlay = load_json(root / DEFAULT_CURRENT_OVERLAY_REL)
    next_contract = load_json(root / DEFAULT_NEXT_WORKSTREAM_CONTRACT_REL)
    resume = load_json(root / DEFAULT_RESUME_BLOCKERS_REL)
    reanchor = load_json(root / DEFAULT_REANCHOR_PACKET_REL)

    state_ids = [str(item).strip() for item in lifecycle_law.get("lifecycle_state_model", {}).get("state_ids", [])]
    state_definitions = lifecycle_law.get("lifecycle_state_model", {}).get("state_definitions", [])
    transition_rules = lifecycle_law.get("transition_rules", [])
    registry_rows = adapter_registry.get("adapter_rows", [])

    experimental_ids = sorted(str(item).strip() for item in adapter_registry.get("experimental_adapter_ids", []) if str(item).strip())
    ratified_ids = sorted(str(item).strip() for item in adapter_registry.get("ratified_adapter_ids", []) if str(item).strip())
    row_ids = sorted(str(row.get("adapter_id", "")).strip() for row in registry_rows if str(row.get("adapter_id", "")).strip())

    registry_state_counts = Counter(str(row.get("lifecycle_state", "")).strip() for row in registry_rows)
    experimental_rows = [row for row in registry_rows if str(row.get("registry_class", "")).strip() == "experimental"]
    ratified_rows = [row for row in registry_rows if str(row.get("registry_class", "")).strip() == "ratified"]

    lineage_entry_count = int(receipt_lineage.get("summary", {}).get("lineage_entry_count", 0))
    adapter_promotion_count = int(receipt_lineage.get("summary", {}).get("adapter_promotion_count", 0))
    admissible_learning_delta_count = len(lineage_manifest.get("admissible_learning_delta_ids", []))

    checks = [
        {
            "check_id": "r2_contract_and_terminal_state_bind_only_adapter_lifecycle_ratification",
            "pass": str(r2_contract.get("workstream_id", "")).strip() == EXPECTED_CURRENT_STEP_ID
            and str(r2_contract.get("ratification_mode", "")).strip() == "RATIFICATION_ONLY_NO_TOURNAMENT_ROUTER_OR_LOBE_ADVANCE"
            and str(r2_terminal.get("current_state", "")).strip() == "B04_R2_ADAPTER_LIFECYCLE_LAW_RATIFIED"
            and r2_terminal.get("adapter_lifecycle_ratified") is True
            and r2_terminal.get("tournament_promotion_merge_ratified") is False,
        },
        {
            "check_id": "r1_crucible_pressure_rule_is_consumed_by_lifecycle_law",
            "pass": str(lifecycle_law.get("promotion_gate_rule", {}).get("rule_id", "")).strip()
            == str(r1_contract.get("promotion_eligibility_rule", {}).get("rule_id", "")).strip()
            and str(lifecycle_law.get("promotion_gate_rule", {}).get("rule_ref", "")).strip() == DEFAULT_R1_CONTRACT_REL
            and str(lifecycle_law.get("promotion_gate_rule", {}).get("receipt_ref", "")).strip() == DEFAULT_R1_RECEIPT_REL
            and str(r1_receipt.get("status", "")).strip() == "PASS",
        },
        {
            "check_id": "finite_adapter_state_model_is_bound",
            "pass": state_ids == EXPECTED_STATE_IDS
            and len(state_definitions) == len(EXPECTED_STATE_IDS)
            and sorted(str(row.get("state_id", "")).strip() for row in state_definitions) == sorted(EXPECTED_STATE_IDS),
        },
        {
            "check_id": "all_transitions_are_receipt_or_future_step_gated",
            "pass": len(transition_rules) >= 8
            and all(str(row.get("transition_class", "")).strip() in {"RECEIPT_GATED", "FUTURE_STEP_GATED"} for row in transition_rules)
            and all(bool(row.get("required_receipts")) for row in transition_rules)
            and all(
                str(row.get("required_future_step", "")).strip()
                for row in transition_rules
                if str(row.get("transition_class", "")).strip() == "FUTURE_STEP_GATED"
            ),
        },
        {
            "check_id": "governance_registry_rows_cover_all_declared_adapters",
            "pass": sorted(experimental_ids + ratified_ids) == row_ids
            and len(registry_rows) == len(experimental_ids) + len(ratified_ids)
            and int(operator_registry.get("summary", {}).get("adapter_count", 0)) == len(registry_rows),
        },
        {
            "check_id": "experimental_rows_remain_preromotion_and_ratified_rows_do_not_exceed_promoted_ceiling",
            "pass": all(str(row.get("lifecycle_state", "")).strip() == "REGISTERED" for row in experimental_rows)
            and all(str(row.get("lifecycle_state", "")).strip() == "PROMOTED" for row in ratified_rows)
            and all(str(row.get("runtime_authority_class", "")).strip() == "NOT_RUNTIME_ADMISSIBLE" for row in experimental_rows)
            and all(str(row.get("runtime_authority_class", "")).strip() == "STATIC_BASELINE_ONLY" for row in ratified_rows)
            and lifecycle_law.get("state_ceiling", {}).get("shadow_active_allowed") is False
            and lifecycle_law.get("state_ceiling", {}).get("governed_active_allowed") is False,
        },
        {
            "check_id": "lineage_and_promotion_evidence_exist_and_are_governed",
            "pass": adapter_promotion_count > 0
            and admissible_learning_delta_count > 0
            and lineage_entry_count >= adapter_promotion_count
            and str(promotion_receipt.get("status", "")).strip() == "PASS"
            and str(rollback_plan_receipt.get("status", "")).strip() == "PASS",
        },
        {
            "check_id": "runtime_boundary_and_generated_candidate_stay_bounded",
            "pass": str(universal_adapter_receipt.get("status", "")).strip() == "PASS"
            and int(universal_adapter_receipt.get("live_adapter_count", 0)) == 2
            and str(universal_adapter_receipt.get("generated_candidate", {}).get("status", "")).strip() == "GENERATED_PROMOTABLE_CANDIDATE"
            and str(adapter_runtime_boundary.get("status", "")).strip() == "PASS",
        },
        {
            "check_id": "control_surfaces_advance_only_to_r3",
            "pass": str(next_contract.get("exact_next_counted_workstream_id", "")).strip() == EXPECTED_NEXT_STEP_ID
            and str(next_contract.get("execution_mode", "")).strip() == EXPECTED_EXECUTION_MODE
            and str(overlay.get("next_counted_workstream_id", "")).strip() == EXPECTED_NEXT_STEP_ID
            and str(resume.get("exact_next_counted_workstream_id", "")).strip() == EXPECTED_NEXT_STEP_ID
            and str(reanchor.get("next_lawful_move", "")).strip() == EXPECTED_NEXT_STEP_ID,
        },
        {
            "check_id": "scope_remains_bounded_after_r2",
            "pass": r2_terminal.get("router_progress_allowed") is False
            and r2_terminal.get("lobe_progress_allowed") is False
            and r2_terminal.get("externality_widening_allowed") is False
            and r2_terminal.get("comparative_widening_allowed") is False
            and r2_terminal.get("commercial_activation_allowed") is False,
        },
    ]

    status = "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL"
    return {
        "schema_id": "kt.b04.r2.adapter_lifecycle_law_ratification_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": status,
        "receipt_role": "COUNTED_B04_R2_ADAPTER_LIFECYCLE_LAW_ARTIFACT_ONLY",
        "workstream_id": EXPECTED_CURRENT_STEP_ID,
        "lifecycle_state_summary": {
            "state_ids": state_ids,
            "registry_state_counts": dict(sorted(registry_state_counts.items())),
            "experimental_adapter_count": len(experimental_rows),
            "ratified_adapter_count": len(ratified_rows),
            "max_authorized_state_after_r2": str(lifecycle_law.get("state_ceiling", {}).get("max_authorized_state_after_r2", "")).strip(),
        },
        "transition_summary": {
            "transition_count": len(transition_rules),
            "receipt_gated_count": sum(1 for row in transition_rules if str(row.get("transition_class", "")).strip() == "RECEIPT_GATED"),
            "future_step_gated_count": sum(1 for row in transition_rules if str(row.get("transition_class", "")).strip() == "FUTURE_STEP_GATED"),
            "blocked_future_states": list(lifecycle_law.get("state_ceiling", {}).get("states_not_yet_authorized", [])),
        },
        "lineage_summary": {
            "lineage_entry_count": lineage_entry_count,
            "adapter_promotion_count": adapter_promotion_count,
            "admissible_learning_delta_count": admissible_learning_delta_count,
        },
        "promotion_consumption_summary": {
            "rule_id": str(lifecycle_law.get("promotion_gate_rule", {}).get("rule_id", "")).strip(),
            "rule_text": str(lifecycle_law.get("promotion_gate_rule", {}).get("rule_text", "")).strip(),
            "generated_candidate_status": str(universal_adapter_receipt.get("generated_candidate", {}).get("status", "")).strip(),
            "runtime_live_adapter_count": int(universal_adapter_receipt.get("live_adapter_count", 0)),
        },
        "checks": checks,
        "next_lawful_move": EXPECTED_NEXT_STEP_ID if status == "PASS" else "FIX_B04_R2_ADAPTER_LIFECYCLE_LAW_DEFECT",
        "claim_boundary": "This receipt proves only that adapter lifecycle law, registry, lineage, and promotion-eligibility consumption are ratified under the R1 crucible-pressure spine. It does not ratify tournament, merge, router, lobes, externality, or product widening.",
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate B04.R2 adapter lifecycle law ratification.")
    parser.add_argument("--output", default=DEFAULT_RECEIPT_REL)
    parser.add_argument("--allow-tracked-output-refresh", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    receipt = build_adapter_lifecycle_law_receipt(root=root)
    output = _resolve(root, str(args.output))
    _write_receipt(
        root=root,
        target=output,
        payload=receipt,
        allow_default_repo_write=args.allow_tracked_output_refresh,
    )
    summary = {
        "status": receipt["status"],
        "adapter_lifecycle_law_ratification_status": receipt["status"],
        "next_lawful_move": receipt["next_lawful_move"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
