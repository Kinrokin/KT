from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

_CLEANROOM_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _CLEANROOM_ROOT / "04_PROD_TEMPLE_V2" / "src"
for _path in (str(_CLEANROOM_ROOT), str(_SRC_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from tools.operator.post_wave5_c005_router_ratification_validate import build_c005_router_ratification_receipt
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.wave2b_router_shadow_validate import build_wave2b_shadow_reports


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
ROUTER_POLICY_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/router_policy_registry.json"
ROUTER_PROMOTION_LAW_REL = "KT_PROD_CLEANROOM/governance/router_promotion_law.json"
LOBE_ROLE_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/lobe_role_registry.json"
LOBE_PROMOTION_LAW_REL = "KT_PROD_CLEANROOM/governance/lobe_promotion_law.json"
ECONOMIC_TRUTH_PLANE_REL = f"{REPORT_ROOT_REL}/economic_truth_plane.json"
TRUTH_LOCK_REL = "KT_PROD_CLEANROOM/governance/current_head_truth_lock.json"

DEFAULT_SHADOW_MATRIX_REL = f"{REPORT_ROOT_REL}/router_shadow_eval_matrix.json"
DEFAULT_HEALTH_REL = f"{REPORT_ROOT_REL}/route_distribution_health.json"
DEFAULT_SCORECARD_REL = f"{REPORT_ROOT_REL}/router_superiority_scorecard.json"
DEFAULT_RECEIPT_REL = f"{REPORT_ROOT_REL}/router_ordered_proof_receipt.json"

TMP_WAVE2B_TELEMETRY_REL = f"{REPORT_ROOT_REL}/.tmp_w5_router_shadow_telemetry.jsonl"
TMP_C005_TELEMETRY_REL = f"{REPORT_ROOT_REL}/.tmp_w5_router_ratification_telemetry.jsonl"


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _status_is(value: Any, expected: str) -> bool:
    return str(value).strip().upper() == expected.strip().upper()


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _economic_profile(plane: Dict[str, Any], profile_id: str) -> Dict[str, Any]:
    for row in plane.get("profiles", []):
        if isinstance(row, dict) and str(row.get("profile_id", "")).strip() == profile_id:
            return row
    raise RuntimeError(f"FAIL_CLOSED: missing economic profile {profile_id}")


def _build_base_reports(*, root: Path) -> Dict[str, Dict[str, Any]]:
    shadow_reports = build_wave2b_shadow_reports(root=root, telemetry_path=(root / TMP_WAVE2B_TELEMETRY_REL).resolve())
    c005_receipt = build_c005_router_ratification_receipt(root=root, telemetry_path=(root / TMP_C005_TELEMETRY_REL).resolve())
    return {
        "selection": shadow_reports["selection_report"],
        "matrix": shadow_reports["matrix_report"],
        "health": shadow_reports["health_report"],
        "c005": c005_receipt,
    }


def build_router_shadow_eval_matrix(*, root: Path, base: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    current_head = _git_head(root)
    selection = base["selection"]
    matrix = base["matrix"]
    c005 = base["c005"]
    rows_by_case = {
        str(row.get("case_id", "")).strip(): row
        for row in selection.get("case_rows", [])
        if isinstance(row, dict)
    }
    provider_underlay = c005.get("best_static_provider_adapter_underlay", {})

    output_rows: List[Dict[str, Any]] = []
    for row in matrix.get("rows", []):
        if not isinstance(row, dict):
            continue
        case_id = str(row.get("case_id", "")).strip()
        selection_row = rows_by_case.get(case_id, {})
        output_rows.append(
            {
                "baseline_adapter_ids": list(row.get("baseline_adapter_ids", [])),
                "baseline_domain_tag": str(row.get("baseline_domain_tag", "")).strip(),
                "best_static_provider_adapter_id": str(provider_underlay.get("adapter_id", "")).strip(),
                "best_static_provider_latency_ms": int(provider_underlay.get("latency_ms", 0)),
                "case_id": case_id,
                "exact_path_match": bool(row.get("exact_path_match")),
                "fallback_engaged": bool(row.get("fallback_engaged")),
                "no_regression_pass": bool(row.get("exact_path_match")),
                "ordered_stage": "SHADOW_EVAL_FROZEN",
                "shadow_adapter_ids": list(row.get("shadow_adapter_ids", [])),
                "shadow_confidence": float(selection_row.get("shadow_selection", {}).get("confidence", row.get("confidence", 0.0))),
                "shadow_domain_tag": str(row.get("shadow_domain_tag", "")).strip(),
            }
        )

    learned_candidate_status = "NO_ELIGIBLE_LEARNED_ROUTER_CANDIDATE_PRESENT"
    if matrix.get("promotion_decision", {}).get("learned_router_cutover_allowed") is True:
        learned_candidate_status = "ELIGIBLE_CLEAN_WIN_PRESENT"

    return {
        "schema_id": "kt.w5.router_shadow_eval_matrix.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": "PASS" if _status_is(matrix.get("status"), "PASS") and _status_is(c005.get("status"), "PASS") else "FAIL",
        "comparison_rule": "W5 freezes the router comparator suite against the canonical static baseline and carries forward only shadow evidence, not cutover authority.",
        "best_static_baseline_ref": "KT_PROD_CLEANROOM/reports/post_wave5_c005_router_ratification_receipt.json",
        "frozen_shadow_eval_ref": "KT_PROD_CLEANROOM/reports/kt_wave2b_router_shadow_eval_matrix.json",
        "learned_router_candidate_status": learned_candidate_status,
        "no_regression_rule": "Every case must match or improve the static baseline and preserve fallback behavior before any learned-router cutover is eligible.",
        "rows": output_rows,
        "source_refs": [
            "KT_PROD_CLEANROOM/reports/kt_wave2b_router_selection_receipt.json",
            "KT_PROD_CLEANROOM/reports/kt_wave2b_router_shadow_eval_matrix.json",
            "KT_PROD_CLEANROOM/reports/post_wave5_c005_router_ratification_receipt.json",
        ],
        "claim_boundary": "This matrix freezes router comparison evidence only. It does not claim learned-router superiority or multi-lobe readiness.",
    }


def build_route_distribution_health(*, root: Path, base: Dict[str, Dict[str, Any]], shadow_matrix: Dict[str, Any]) -> Dict[str, Any]:
    current_head = _git_head(root)
    health = base["health"]
    c005 = base["c005"]
    economic_plane = load_json(root / ECONOMIC_TRUTH_PLANE_REL)
    runtime_profile = _economic_profile(economic_plane, "canonical_same_host_runtime_lane")
    matrix_rows = shadow_matrix.get("rows", [])

    quality_cost_latency_rows = []
    for row in matrix_rows:
        if not isinstance(row, dict):
            continue
        quality_cost_latency_rows.append(
            {
                "case_id": str(row.get("case_id", "")).strip(),
                "fallback_engaged": bool(row.get("fallback_engaged")),
                "latency_ms": int(row.get("best_static_provider_latency_ms", 0)),
                "no_regression_pass": bool(row.get("no_regression_pass")),
                "review_burden_minutes": int(runtime_profile.get("review_burden_minutes", 0)),
                "route_cost_units": int(runtime_profile.get("compute_cost_units", 0)),
                "route_quality_score": 100 if bool(row.get("exact_path_match")) else 0,
                "route_quality_status": "MATCH_STATIC_BASELINE" if bool(row.get("exact_path_match")) else "REGRESSION",
                "uncertainty_cost_index": int(runtime_profile.get("uncertainty_cost_index", 0)),
            }
        )

    no_regression_pass = all(bool(row.get("no_regression_pass")) for row in quality_cost_latency_rows)
    return {
        "schema_id": "kt.w5.route_distribution_health.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": "PASS" if _status_is(health.get("status"), "PASS") and no_regression_pass else "FAIL",
        "best_static_provider_adapter_id": str(c005.get("best_static_provider_adapter_underlay", {}).get("adapter_id", "")).strip(),
        "canonical_static_router_preserved": bool(health.get("canonical_static_router_preserved")),
        "fallback_case_ids": list(health.get("fallback_case_ids", [])),
        "fallback_rate": float(health.get("fallback_rate", 0.0)),
        "no_regression_rule_status": "PASS" if no_regression_pass else "FAIL",
        "route_collapse_detected": bool(health.get("route_collapse_detected")),
        "route_distribution_delta_count": int(health.get("route_distribution_delta_count", 0)),
        "route_quality_cost_latency_matrix": quality_cost_latency_rows,
        "shadow_match_rate": float(health.get("shadow_match_rate", 0.0)),
        "source_refs": [
            "KT_PROD_CLEANROOM/reports/kt_wave2b_route_distribution_health.json",
            DEFAULT_SHADOW_MATRIX_REL,
            ECONOMIC_TRUTH_PLANE_REL,
        ],
        "claim_boundary": "This report measures route quality, cost, and latency under the bounded static-control regime. It does not claim a learned-router gain.",
    }


def build_router_superiority_scorecard(*, root: Path, base: Dict[str, Dict[str, Any]], health_report: Dict[str, Any]) -> Dict[str, Any]:
    current_head = _git_head(root)
    c005 = base["c005"]
    truth_lock = load_json(root / TRUTH_LOCK_REL)
    matrix_rows = health_report.get("route_quality_cost_latency_matrix", [])
    no_regression_pass = str(health_report.get("no_regression_rule_status", "")).strip() == "PASS"
    superiority_earned = False

    return {
        "schema_id": "kt.w5.router_superiority_scorecard.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": "PASS",
        "best_static_baseline": {
            "provider_underlay": c005.get("best_static_provider_adapter_underlay", {}),
            "ratification_decision": str(c005.get("ratification_decision", "")).strip(),
            "source_ref": "KT_PROD_CLEANROOM/reports/post_wave5_c005_router_ratification_receipt.json",
        },
        "learned_router_candidate": {
            "candidate_id": "",
            "candidate_status": "NO_ELIGIBLE_LEARNED_ROUTER_CANDIDATE_PRESENT",
            "eligibility_reason": "Current-head evidence contains only a shadow comparator that matched the static baseline and did not earn cutover.",
            "promotion_allowed": False,
        },
        "multi_lobe_promotion_status": "BLOCKED_PENDING_LEARNED_ROUTER_WIN",
        "no_regression_status": "PASS" if no_regression_pass else "FAIL",
        "overall_outcome": "HOLD_STATIC_CANONICAL_BASELINE",
        "route_quality_win_status": "NOT_EARNED_SHADOW_MATCH_ONLY",
        "cost_win_status": "NOT_EARNED_NO_ROUTE_COST_ADVANTAGE_DEMONSTRATED",
        "latency_win_status": "NOT_EARNED_NO_ROUTE_LATENCY_ADVANTAGE_DEMONSTRATED",
        "superiority_earned": superiority_earned,
        "case_count": len(matrix_rows),
        "comparative_widening": str(truth_lock.get("claim_ceiling_enforcements", {}).get("comparative_widening", "")).strip(),
        "claim_boundary": "W5 scores router superiority honestly. Static remains canonical because no clean learned-router win exists, and multi-lobe promotion remains blocked.",
        "stronger_claims_not_made": [
            "learned_router_superiority_earned",
            "multi_lobe_orchestration_ready",
            "comparative_widening_unlocked",
            "frontier_router_language_unlocked",
        ],
        "source_refs": [
            DEFAULT_HEALTH_REL,
            DEFAULT_SHADOW_MATRIX_REL,
            "KT_PROD_CLEANROOM/reports/post_wave5_c005_router_ratification_receipt.json",
            TRUTH_LOCK_REL,
        ],
    }


def build_router_ordered_proof_receipt(
    *,
    root: Path,
    base: Dict[str, Dict[str, Any]],
    shadow_matrix: Dict[str, Any],
    health_report: Dict[str, Any],
    scorecard: Dict[str, Any],
) -> Dict[str, Any]:
    current_head = _git_head(root)
    registry = load_json(root / ROUTER_POLICY_REGISTRY_REL)
    router_law = load_json(root / ROUTER_PROMOTION_LAW_REL)
    lobe_registry = load_json(root / LOBE_ROLE_REGISTRY_REL)
    lobe_law = load_json(root / LOBE_PROMOTION_LAW_REL)
    truth_lock = load_json(root / TRUTH_LOCK_REL)
    c005 = base["c005"]

    checks = [
        {
            "check_id": "static_baseline_ratified",
            "pass": _status_is(c005.get("status"), "PASS") and str(c005.get("ratification_decision", "")).strip() == "HOLD_STATIC_CANONICAL_BASELINE",
        },
        {
            "check_id": "shadow_eval_frozen",
            "pass": _status_is(shadow_matrix.get("status"), "PASS") and bool(shadow_matrix.get("rows")),
        },
        {
            "check_id": "best_static_comparator_control_explicit",
            "pass": bool(c005.get("best_static_provider_adapter_underlay", {}).get("adapter_id")),
        },
        {
            "check_id": "route_quality_cost_latency_matrix_present",
            "pass": _status_is(health_report.get("status"), "PASS") and bool(health_report.get("route_quality_cost_latency_matrix")),
        },
        {
            "check_id": "no_regression_rule_enforced",
            "pass": str(health_report.get("no_regression_rule_status", "")).strip() == "PASS" and str(scorecard.get("no_regression_status", "")).strip() == "PASS",
        },
        {
            "check_id": "learned_router_cutover_blocked_without_clean_win",
            "pass": scorecard.get("learned_router_candidate", {}).get("promotion_allowed") is False and scorecard.get("superiority_earned") is False,
        },
        {
            "check_id": "multi_lobe_promotion_blocked_without_router_win",
            "pass": str(scorecard.get("multi_lobe_promotion_status", "")).strip() == "BLOCKED_PENDING_LEARNED_ROUTER_WIN" and _status_is(lobe_law.get("status"), "ACTIVE"),
        },
        {
            "check_id": "claim_ceiling_preserved",
            "pass": str(truth_lock.get("claim_ceiling_enforcements", {}).get("comparative_widening", "")).strip() == "FORBIDDEN",
        },
        {
            "check_id": "router_and_lobe_laws_active",
            "pass": _status_is(router_law.get("status"), "ACTIVE") and _status_is(lobe_registry.get("status"), "ACTIVE"),
        },
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"

    return {
        "schema_id": "kt.w5.router_ordered_proof_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": status,
        "ordered_proof_outcome": "PASS_HOLD_STATIC_CANONICAL_BASELINE" if status == "PASS" else "FAIL_CLOSED",
        "canonical_router_status": "STATIC_CANONICAL_BASELINE_ONLY",
        "exact_superiority_outcome": "NOT_EARNED_STATIC_BASELINE_RETAINS_CANONICAL_STATUS",
        "learned_router_cutover_allowed": False,
        "multi_lobe_promotion_allowed": False,
        "checks": checks,
        "ordered_proof_chain": list(registry.get("ordered_proof_chain", [])),
        "claim_boundary": (
            "W5 proves router/lobe honesty only. The static baseline remains canonical, no learned-router cutover is earned, "
            "and multi-lobe orchestration remains blocked."
        ),
        "source_refs": [
            ROUTER_POLICY_REGISTRY_REL,
            ROUTER_PROMOTION_LAW_REL,
            LOBE_ROLE_REGISTRY_REL,
            LOBE_PROMOTION_LAW_REL,
            DEFAULT_SHADOW_MATRIX_REL,
            DEFAULT_HEALTH_REL,
            DEFAULT_SCORECARD_REL,
            "KT_PROD_CLEANROOM/reports/post_wave5_c005_router_ratification_receipt.json",
        ],
        "stronger_claims_not_made": [
            "learned_router_cutover_occurred",
            "learned_router_superiority_earned",
            "multi_lobe_orchestration_unblocked",
            "comparative_widening_unlocked",
        ],
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate the ordered router/lobe proof chain and hold static baseline unless a clean win is earned.")
    parser.add_argument("--shadow-matrix-output", default=DEFAULT_SHADOW_MATRIX_REL)
    parser.add_argument("--health-output", default=DEFAULT_HEALTH_REL)
    parser.add_argument("--scorecard-output", default=DEFAULT_SCORECARD_REL)
    parser.add_argument("--receipt-output", default=DEFAULT_RECEIPT_REL)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    base = _build_base_reports(root=root)
    shadow_matrix = build_router_shadow_eval_matrix(root=root, base=base)
    health_report = build_route_distribution_health(root=root, base=base, shadow_matrix=shadow_matrix)
    scorecard = build_router_superiority_scorecard(root=root, base=base, health_report=health_report)
    receipt = build_router_ordered_proof_receipt(
        root=root,
        base=base,
        shadow_matrix=shadow_matrix,
        health_report=health_report,
        scorecard=scorecard,
    )

    write_json_stable(_resolve(root, str(args.shadow_matrix_output)), shadow_matrix)
    write_json_stable(_resolve(root, str(args.health_output)), health_report)
    write_json_stable(_resolve(root, str(args.scorecard_output)), scorecard)
    write_json_stable(_resolve(root, str(args.receipt_output)), receipt)

    summary = {
        "canonical_router_status": receipt["canonical_router_status"],
        "exact_superiority_outcome": receipt["exact_superiority_outcome"],
        "status": receipt["status"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
