from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.observability import emit_toolchain_telemetry, telemetry_now_ms
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
TELEMETRY_REL = f"{REPORT_ROOT_REL}/post_wave5_c005_router_ratification_telemetry.jsonl"
RECEIPT_REL = f"{REPORT_ROOT_REL}/post_wave5_c005_router_ratification_receipt.json"

ROUTER_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/router_policy_registry.json"
ROUTER_SELECTION_REL = f"{REPORT_ROOT_REL}/kt_wave2b_router_selection_receipt.json"
ROUTER_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_wave2b_router_shadow_eval_matrix.json"
ROUTER_HEALTH_REL = f"{REPORT_ROOT_REL}/kt_wave2b_route_distribution_health.json"
C016A_SUCCESS_REL = f"{REPORT_ROOT_REL}/post_wave5_c016a_success_matrix.json"
C016B_RESILIENCE_REL = f"{REPORT_ROOT_REL}/post_wave5_c016b_resilience_pack.json"

C005_DELTA = "C005_CLOSED_BY_HONEST_STATIC_ROUTER_RATIFICATION_HOLD"
ROUTER_OBJECTIVE_ID = "ROUTER_SUPERIORITY_AND_MULTI_LOBE_PROMOTION"


def _is_pass(payload: Dict[str, Any]) -> bool:
    return str(payload.get("status", "")).strip().upper() == "PASS"


def build_c005_router_ratification_receipt(*, root: Path, telemetry_path: Path) -> Dict[str, Any]:
    started = telemetry_now_ms()
    registry = load_json((root / ROUTER_REGISTRY_REL).resolve())
    selection = load_json((root / ROUTER_SELECTION_REL).resolve())
    matrix = load_json((root / ROUTER_MATRIX_REL).resolve())
    health = load_json((root / ROUTER_HEALTH_REL).resolve())
    c016a = load_json((root / C016A_SUCCESS_REL).resolve())
    c016b = load_json((root / C016B_RESILIENCE_REL).resolve())

    provider_context = selection.get("provider_underlay_context", {})
    promotion_decision = matrix.get("promotion_decision", {})
    best_static_underlay = selection.get("best_static_provider_adapter_underlay", {})
    matrix_rows = matrix.get("rows", [])
    health_fallback_case_ids = health.get("fallback_case_ids", [])

    checks = [
        {
            "check_id": "static_ratification_scope_frozen",
            "status": "PASS" if str(registry.get("ratification_scope", "")).strip() == "STATIC_ROUTER_BASELINE_ONLY" else "FAIL",
        },
        {
            "check_id": "router_shadow_receipts_present_and_pass",
            "status": "PASS" if _is_pass(selection) and _is_pass(matrix) and _is_pass(health) else "FAIL",
        },
        {
            "check_id": "provider_underlay_bound_to_post_wave5_success",
            "status": "PASS"
            if str(provider_context.get("provider_report_ref", "")).strip() == C016A_SUCCESS_REL
            and bool(provider_context.get("same_host_live_hashed_success_proven"))
            and _is_pass(c016a)
            else "FAIL",
        },
        {
            "check_id": "provider_underlay_resilience_bound",
            "status": "PASS"
            if bool(provider_context.get("same_host_live_hashed_resilience_proven")) and _is_pass(c016b)
            else "FAIL",
        },
        {
            "check_id": "best_static_comparator_control_explicit",
            "status": "PASS"
            if bool(promotion_decision.get("canonical_router_unchanged"))
            and not bool(promotion_decision.get("learned_router_cutover_allowed"))
            and "best_static_comparator_remains_control" in promotion_decision.get("reasons", [])
            else "FAIL",
        },
        {
            "check_id": "shadow_matches_fenced_static_baseline",
            "status": "PASS"
            if float(health.get("shadow_match_rate", 0.0)) == 1.0
            and int(health.get("route_distribution_delta_count", -1)) == 0
            and all(bool(row.get("exact_path_match")) for row in matrix_rows if isinstance(row, dict))
            else "FAIL",
        },
        {
            "check_id": "fallback_evidence_preserved",
            "status": "PASS"
            if isinstance(health_fallback_case_ids, list) and bool(health_fallback_case_ids)
            else "FAIL",
        },
        {
            "check_id": "best_static_underlay_is_receipted_and_successful",
            "status": "PASS"
            if str(best_static_underlay.get("status", "")).strip() == "OK"
            and bool(str(best_static_underlay.get("adapter_id", "")).strip())
            else "FAIL",
        },
    ]

    failures = [str(row["check_id"]) for row in checks if row["status"] != "PASS"]
    status = "PASS" if not failures else "FAIL"
    exact_superiority_outcome = (
        "NOT_EARNED_SHADOW_MATCHES_STATIC_BASELINE"
        if status == "PASS"
        else "UNRESOLVED_RATIFICATION_PRECONDITIONS_FAILED"
    )
    ratification_decision = "HOLD_STATIC_CANONICAL_BASELINE" if status == "PASS" else "NO_DECISION"

    completed = telemetry_now_ms()
    emit_toolchain_telemetry(
        surface_id="tools.operator.post_wave5_c005_router_ratification_validate",
        zone="TOOLCHAIN_PROVING",
        event_type="post_wave5.c005_router_ratification",
        start_ts=started,
        end_ts=completed,
        result_status=status,
        policy_applied="post_wave5.c005.router_ratification_hold_only",
        receipt_ref=RECEIPT_REL,
        trace_id="post-wave5-c005-router-ratification",
        request_id="post_wave5_c005_router_ratification_validate",
        path=telemetry_path,
    )

    return {
        "schema_id": "kt.post_wave5.c005_router_ratification_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "c005_delta": C005_DELTA if status == "PASS" else "C005_REMAINS_OPEN_RATIFICATION_PRECONDITIONS_FAILED",
        "current_head_blocker_status": "CLOSED" if status == "PASS" else "OPEN",
        "ratification_decision": ratification_decision,
        "canonical_router_status": "STATIC_CANONICAL_BASELINE_ONLY",
        "exact_superiority_outcome": exact_superiority_outcome,
        "continuing_governed_objective": {
            "objective_id": ROUTER_OBJECTIVE_ID,
            "status": "ACTIVE_GOVERNED_ADVANCEMENT_OBJECTIVE" if status == "PASS" else "PENDING_RATIFICATION",
            "scope_boundary": "Current-head canonical closure does not abandon learned-router or multi-lobe ambition. It only means superiority was not yet earned for canonical promotion on this head.",
            "next_lawful_unlock": "Produce fenced-task superiority over the ratified static baseline with no-regression evidence before any learned-router cutover or multi-lobe promotion.",
            "abandonment_status": "NOT_ABANDONED",
        },
        "best_static_provider_adapter_underlay": best_static_underlay,
        "provider_underlay_ref": str(provider_context.get("provider_report_ref", "")).strip(),
        "provider_underlay_resilience_ref": str(provider_context.get("resilience_report_ref", "")).strip(),
        "comparison_metrics": {
            "shadow_match_rate": float(health.get("shadow_match_rate", 0.0)),
            "route_distribution_delta_count": int(health.get("route_distribution_delta_count", -1)),
            "fallback_case_ids": list(health_fallback_case_ids) if isinstance(health_fallback_case_ids, list) else [],
            "case_count": len([row for row in matrix_rows if isinstance(row, dict)]),
        },
        "checks": checks,
        "failures": failures,
        "evidence_refs": [
            ROUTER_REGISTRY_REL,
            ROUTER_SELECTION_REL,
            ROUTER_MATRIX_REL,
            ROUTER_HEALTH_REL,
            C016A_SUCCESS_REL,
            C016B_RESILIENCE_REL,
        ],
        "stronger_claim_not_made": [
            "learned_router_cutover_claimed",
            "semantic_or_learned_router_superiority_claimed",
            "multi_lobe_routing_unblocked",
            "externality_class_raised_above_E1",
            "product_or_comparative_widening_claimed",
            "router_ambition_abandoned",
        ],
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Emit the Post-Wave5 C005 router ratification decision without learned-router cutover."
    )
    parser.add_argument("--receipt-output", default=RECEIPT_REL)
    parser.add_argument("--telemetry-output", default=TELEMETRY_REL)
    return parser.parse_args(argv)


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    receipt = build_c005_router_ratification_receipt(
        root=root,
        telemetry_path=_resolve(root, str(args.telemetry_output)),
    )
    write_json_stable(_resolve(root, str(args.receipt_output)), receipt)
    print(
        json.dumps(
            {
                "c005_delta": receipt["c005_delta"],
                "ratification_decision": receipt["ratification_decision"],
                "status": receipt["status"],
            },
            sort_keys=True,
        )
    )
    return 0 if receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
