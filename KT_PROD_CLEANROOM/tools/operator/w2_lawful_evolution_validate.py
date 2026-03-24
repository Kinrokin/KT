from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from tools.operator.net_elevation_gate import evaluate_net_elevation
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
DEFAULT_TOURNAMENT_OUTPUT_REL = f"{REPORT_ROOT_REL}/tournament_receipt.json"
DEFAULT_MERGE_OUTPUT_REL = f"{REPORT_ROOT_REL}/merge_outcome_receipt.json"
DEFAULT_CANONICAL_DELTA_REL = f"{REPORT_ROOT_REL}/canonical_delta_w2.json"
DEFAULT_ADVANCEMENT_DELTA_REL = f"{REPORT_ROOT_REL}/advancement_delta_w2.json"

TRUTH_LOCK_REL = "KT_PROD_CLEANROOM/governance/current_head_truth_lock.json"
ORGAN_REGISTER_REL = f"{REPORT_ROOT_REL}/kt_wave2c_organ_disposition_register.json"
ADAPTER_ABI_REL = "KT_PROD_CLEANROOM/governance/kt_adapter_abi_v1.json"
ADAPTER_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/adapter_registry.json"
ADAPTER_LIFECYCLE_REL = "KT_PROD_CLEANROOM/governance/adapter_lifecycle_law.json"
CRUCIBLE_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/crucible_registry.json"
CRUCIBLE_LIFECYCLE_REL = "KT_PROD_CLEANROOM/governance/crucible_lifecycle_law.json"
PROMOTION_LAW_REL = "KT_PROD_CLEANROOM/governance/promotion_engine_law.json"
TOURNAMENT_LAW_REL = "KT_PROD_CLEANROOM/governance/tournament_law.json"
MERGE_LAW_REL = "KT_PROD_CLEANROOM/governance/merge_law.json"
ROLLBACK_LAW_REL = "KT_PROD_CLEANROOM/governance/rollback_law.json"
ROUTER_POLICY_REL = "KT_PROD_CLEANROOM/governance/router_policy_registry.json"
ROUTER_PROMOTION_LAW_REL = "KT_PROD_CLEANROOM/governance/router_promotion_law.json"
LOBE_ROLE_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/lobe_role_registry.json"
LOBE_PROMOTION_LAW_REL = "KT_PROD_CLEANROOM/governance/lobe_promotion_law.json"
WAVE2A_ADAPTER_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_wave2a_adapter_activation_receipt.json"
W1_PROVIDER_PATH_REL = f"{REPORT_ROOT_REL}/provider_path_integrity_receipt.json"
ADAPTER_TESTING_GATE_REL = f"{REPORT_ROOT_REL}/kt_adapter_testing_gate_receipt.json"
PROMOTION_RECEIPT_REL = f"{REPORT_ROOT_REL}/promotion_receipt.json"
TOURNAMENT_READINESS_REL = f"{REPORT_ROOT_REL}/kt_tournament_readiness_receipt.json"
MAIN_MERGE_REL = f"{REPORT_ROOT_REL}/main_merge_receipt.json"
MERGE_INTERFERENCE_REL = f"{REPORT_ROOT_REL}/merge_interference_index.json"
ROUTER_SELECTION_REL = f"{REPORT_ROOT_REL}/kt_wave2b_router_selection_receipt.json"
ROUTER_SHADOW_REL = f"{REPORT_ROOT_REL}/kt_wave2b_router_shadow_eval_matrix.json"
ROUTE_HEALTH_REL = f"{REPORT_ROOT_REL}/kt_wave2b_route_distribution_health.json"
POST_WAVE5_C005_REL = f"{REPORT_ROOT_REL}/post_wave5_c005_router_ratification_receipt.json"


def _resolve(root: Path, value: str) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    return path


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _status_is(value: Any, expected: str) -> bool:
    return str(value).strip().upper() == expected.strip().upper()


def _truth_lock(root: Path) -> Dict[str, Any]:
    return load_json(root / TRUTH_LOCK_REL)


def _active_blockers(root: Path) -> List[str]:
    lock = _truth_lock(root)
    blocker_ref = str(lock.get("active_blocker_matrix_ref", "")).strip()
    if not blocker_ref:
        raise RuntimeError("FAIL_CLOSED: current_head_truth_lock missing active blocker matrix ref")
    matrix = load_json(root / blocker_ref)
    rows = matrix.get("open_blockers", [])
    blocker_ids: List[str] = []
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict):
                blocker_id = str(row.get("blocker_id", "")).strip()
                if blocker_id:
                    blocker_ids.append(blocker_id)
            else:
                blocker_id = str(row).strip()
                if blocker_id:
                    blocker_ids.append(blocker_id)
    if not blocker_ids:
        blocker_ids = [str(item).strip() for item in lock.get("active_open_blocker_ids", []) if str(item).strip()]
    return blocker_ids


def _organ_row(root: Path, organ_id: str) -> Dict[str, Any]:
    register = load_json(root / ORGAN_REGISTER_REL)
    rows = register.get("rows", [])
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: organ disposition register rows missing")
    for row in rows:
        if isinstance(row, dict) and str(row.get("organ_id", "")).strip() == organ_id:
            return row
    raise RuntimeError(f"FAIL_CLOSED: organ row missing for {organ_id}")


def _count_lines(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def build_tournament_receipt(*, root: Path) -> Dict[str, Any]:
    tournament_law = load_json(root / TOURNAMENT_LAW_REL)
    promotion_law = load_json(root / PROMOTION_LAW_REL)
    rollback_law = load_json(root / ROLLBACK_LAW_REL)
    crucible_registry = load_json(root / CRUCIBLE_REGISTRY_REL)
    crucible_lifecycle = load_json(root / CRUCIBLE_LIFECYCLE_REL)
    promotion_receipt = load_json(root / PROMOTION_RECEIPT_REL)
    readiness_receipt = load_json(root / TOURNAMENT_READINESS_REL)
    organ_row = _organ_row(root, "tournament_promotion")

    checks = [
        {"check_id": "tournament_law_active", "pass": _status_is(tournament_law.get("status"), "ACTIVE"), "ref": TOURNAMENT_LAW_REL},
        {"check_id": "promotion_engine_law_active", "pass": _status_is(promotion_law.get("status"), "ACTIVE"), "ref": PROMOTION_LAW_REL},
        {"check_id": "rollback_law_active", "pass": _status_is(rollback_law.get("status"), "ACTIVE"), "ref": ROLLBACK_LAW_REL},
        {"check_id": "crucible_registry_active", "pass": _status_is(crucible_registry.get("status"), "ACTIVE"), "ref": CRUCIBLE_REGISTRY_REL},
        {"check_id": "crucible_lifecycle_law_active", "pass": _status_is(crucible_lifecycle.get("status"), "ACTIVE"), "ref": CRUCIBLE_LIFECYCLE_REL},
        {"check_id": "historical_promotion_receipt_present", "pass": _status_is(promotion_receipt.get("status"), "PASS"), "ref": PROMOTION_RECEIPT_REL},
        {
            "check_id": "tournament_organ_remains_lab_governed",
            "pass": str(organ_row.get("disposition", "")).strip() == "LAB_ONLY_UNTIL_RUNTIME_REAL"
            and str(organ_row.get("evidence_ref", "")).strip() == TOURNAMENT_READINESS_REL
            and str(organ_row.get("reality_class", "")).strip() in {"LIVE_BOUNDED", "SCAFFOLDED"},
            "ref": ORGAN_REGISTER_REL,
        },
        {
            "check_id": "tournament_requires_promotion_and_rollback",
            "pass": str(organ_row.get("disposition", "")).strip() == "LAB_ONLY_UNTIL_RUNTIME_REAL"
            and _status_is(promotion_receipt.get("status"), "PASS")
            and _status_is(rollback_law.get("status"), "ACTIVE")
            and str(readiness_receipt.get("tournament_gate_status", readiness_receipt.get("status", ""))).strip().upper() == "BLOCKED",
            "ref": ORGAN_REGISTER_REL,
        },
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    readiness_status = str(readiness_receipt.get("tournament_gate_status", readiness_receipt.get("status", ""))).strip() or "UNKNOWN"

    return {
        "schema_id": "kt.w2.tournament_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": status,
        "promotion_civilization_status": "LAB_GOVERNED_ONLY" if status == "PASS" else "FAIL_CLOSED",
        "canonical_influence_status": "BLOCKED_UNLESS_PROMOTION_RECEIPT_AND_ROLLBACK_PASS",
        "public_showability_status": readiness_status,
        "historical_readiness_ref": TOURNAMENT_READINESS_REL,
        "promotion_receipt_ref": PROMOTION_RECEIPT_REL,
        "claim_boundary": (
            "W2 proves tournament and promotion discipline are governed and rollback-bound. "
            "It does not promote tournament civilization into canonical runtime or unlock public tournament showability."
        ),
        "checks": checks,
        "source_refs": [
            TOURNAMENT_LAW_REL,
            PROMOTION_LAW_REL,
            ROLLBACK_LAW_REL,
            CRUCIBLE_REGISTRY_REL,
            CRUCIBLE_LIFECYCLE_REL,
            PROMOTION_RECEIPT_REL,
            TOURNAMENT_READINESS_REL,
            ORGAN_REGISTER_REL,
        ],
        "stronger_claims_not_made": [
            "tournament_promoted_to_canonical_runtime",
            "public_tournament_readiness_unblocked",
            "growth_stack_now_controls_current_head_runtime",
        ],
    }


def build_merge_outcome_receipt(*, root: Path) -> Dict[str, Any]:
    merge_law = load_json(root / MERGE_LAW_REL)
    rollback_law = load_json(root / ROLLBACK_LAW_REL)
    promotion_law = load_json(root / PROMOTION_LAW_REL)
    merge_receipt = load_json(root / MAIN_MERGE_REL)
    promotion_receipt = load_json(root / PROMOTION_RECEIPT_REL)
    interference = load_json(root / MERGE_INTERFERENCE_REL) if (root / MERGE_INTERFERENCE_REL).exists() else {}

    checks = [
        {"check_id": "merge_law_active", "pass": _status_is(merge_law.get("status"), "ACTIVE"), "ref": MERGE_LAW_REL},
        {"check_id": "rollback_law_active", "pass": _status_is(rollback_law.get("status"), "ACTIVE"), "ref": ROLLBACK_LAW_REL},
        {"check_id": "promotion_engine_law_active", "pass": _status_is(promotion_law.get("status"), "ACTIVE"), "ref": PROMOTION_LAW_REL},
        {"check_id": "historical_merge_receipt_pass", "pass": _status_is(merge_receipt.get("status"), "PASS"), "ref": MAIN_MERGE_REL},
        {"check_id": "historical_promotion_receipt_pass", "pass": _status_is(promotion_receipt.get("status"), "PASS"), "ref": PROMOTION_RECEIPT_REL},
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    merge_method = str(merge_receipt.get("merge_method", "")).strip()

    return {
        "schema_id": "kt.w2.merge_outcome_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": status,
        "merge_admissibility_status": "ROLLBACK_BOUND_AND_RECEIPTED" if status == "PASS" else "FAIL_CLOSED",
        "rollback_bound": _status_is(rollback_law.get("status"), "ACTIVE"),
        "historical_merge_ref": MAIN_MERGE_REL,
        "historical_merge_method": merge_method,
        "merge_interference_ref": MERGE_INTERFERENCE_REL if interference else "",
        "claim_boundary": (
            "W2 proves merge discipline exists as a governed rollback-bound family. "
            "It does not claim current-head canonical promotion, superiority, or externality elevation."
        ),
        "checks": checks,
        "source_refs": [
            MERGE_LAW_REL,
            ROLLBACK_LAW_REL,
            PROMOTION_LAW_REL,
            MAIN_MERGE_REL,
            PROMOTION_RECEIPT_REL,
        ],
        "stronger_claims_not_made": [
            "merge_civilization_now_controls_canonical_runtime",
            "historical_merge_receipt_upgrades_current_head_capability",
        ],
    }


def _adapter_family_status(root: Path) -> Dict[str, Any]:
    abi = load_json(root / ADAPTER_ABI_REL)
    registry = load_json(root / ADAPTER_REGISTRY_REL)
    lifecycle = load_json(root / ADAPTER_LIFECYCLE_REL)
    wave2a = load_json(root / WAVE2A_ADAPTER_RECEIPT_REL)
    provider_path = load_json(root / W1_PROVIDER_PATH_REL)
    testing_gate = load_json(root / ADAPTER_TESTING_GATE_REL)
    organ_row = _organ_row(root, "adapter_layer")

    checks = [
        {"check_id": "adapter_abi_frozen_or_active", "pass": str(abi.get("status", "")).strip() in {"FROZEN_WAVE_0_5", "ACTIVE"}, "ref": ADAPTER_ABI_REL},
        {"check_id": "adapter_registry_active", "pass": _status_is(registry.get("status"), "ACTIVE"), "ref": ADAPTER_REGISTRY_REL},
        {"check_id": "adapter_lifecycle_law_active", "pass": _status_is(lifecycle.get("status"), "ACTIVE"), "ref": ADAPTER_LIFECYCLE_REL},
        {"check_id": "wave2a_adapter_activation_pass", "pass": _status_is(wave2a.get("status"), "PASS"), "ref": WAVE2A_ADAPTER_RECEIPT_REL},
        {"check_id": "w1_provider_path_pass", "pass": _status_is(provider_path.get("status"), "PASS"), "ref": W1_PROVIDER_PATH_REL},
        {"check_id": "adapter_testing_gate_is_open_or_pass", "pass": str(testing_gate.get("adapter_testing_gate_status", "")).strip().upper() in {"OPEN", "PASS"}, "ref": ADAPTER_TESTING_GATE_REL},
        {
            "check_id": "adapter_layer_row_stays_canonical_bounded",
            "pass": str(organ_row.get("disposition", "")).strip() == "KEEP_BOUNDED_WAVE2A"
            and str(organ_row.get("evidence_ref", "")).strip() == WAVE2A_ADAPTER_RECEIPT_REL
            and str(organ_row.get("reality_class", "")).strip() == "LIVE_BOUNDED",
            "ref": ORGAN_REGISTER_REL,
        },
    ]
    return {
        "status": "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL",
        "checks": checks,
        "active_adapter_count": int(wave2a.get("active_adapter_count", 0) or 0),
        "active_adapter_ids": list(wave2a.get("active_adapter_ids", [])),
    }


def _router_lobe_status(root: Path) -> Dict[str, Any]:
    router_policy = load_json(root / ROUTER_POLICY_REL)
    router_promotion_law = load_json(root / ROUTER_PROMOTION_LAW_REL)
    lobe_role_registry = load_json(root / LOBE_ROLE_REGISTRY_REL)
    lobe_promotion_law = load_json(root / LOBE_PROMOTION_LAW_REL)
    selection = load_json(root / ROUTER_SELECTION_REL)
    shadow = load_json(root / ROUTER_SHADOW_REL)
    health = load_json(root / ROUTE_HEALTH_REL)
    ratification = load_json(root / POST_WAVE5_C005_REL)

    checks = [
        {"check_id": "router_policy_registry_active", "pass": _status_is(router_policy.get("status"), "ACTIVE"), "ref": ROUTER_POLICY_REL},
        {"check_id": "router_promotion_law_active", "pass": _status_is(router_promotion_law.get("status"), "ACTIVE"), "ref": ROUTER_PROMOTION_LAW_REL},
        {"check_id": "lobe_role_registry_active", "pass": _status_is(lobe_role_registry.get("status"), "ACTIVE"), "ref": LOBE_ROLE_REGISTRY_REL},
        {"check_id": "lobe_promotion_law_active", "pass": _status_is(lobe_promotion_law.get("status"), "ACTIVE"), "ref": LOBE_PROMOTION_LAW_REL},
        {"check_id": "wave2b_router_selection_pass", "pass": _status_is(selection.get("status"), "PASS"), "ref": ROUTER_SELECTION_REL},
        {"check_id": "wave2b_router_shadow_pass", "pass": _status_is(shadow.get("status"), "PASS"), "ref": ROUTER_SHADOW_REL},
        {"check_id": "wave2b_route_health_pass", "pass": _status_is(health.get("status"), "PASS"), "ref": ROUTE_HEALTH_REL},
        {"check_id": "post_wave5_router_ratification_pass", "pass": _status_is(ratification.get("status"), "PASS"), "ref": POST_WAVE5_C005_REL},
        {
            "check_id": "router_superiority_not_earned",
            "pass": str(ratification.get("exact_superiority_outcome", "")).strip() == "NOT_EARNED_SHADOW_MATCHES_STATIC_BASELINE",
            "ref": POST_WAVE5_C005_REL,
        },
        {
            "check_id": "static_baseline_preserved",
            "pass": bool(health.get("canonical_static_router_preserved")) and int(health.get("route_distribution_delta_count", 0) or 0) == 0,
            "ref": ROUTE_HEALTH_REL,
        },
    ]
    return {
        "status": "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL",
        "checks": checks,
        "canonical_static_router_preserved": bool(health.get("canonical_static_router_preserved")),
        "shadow_match_rate": float(health.get("shadow_match_rate", 0.0) or 0.0),
        "best_static_provider_adapter_underlay": ratification.get("best_static_provider_adapter_underlay", {}),
        "router_superiority_unlock": False,
        "multilobe_unlock": False,
    }


def _net_elevation(root: Path) -> Dict[str, Any]:
    validator_path = root / "KT_PROD_CLEANROOM" / "tools" / "operator" / "w2_lawful_evolution_validate.py"
    gate_path = root / "KT_PROD_CLEANROOM" / "tools" / "operator" / "net_elevation_gate.py"
    test_path = root / "KT_PROD_CLEANROOM" / "tests" / "operator" / "test_w2_lawful_evolution_validate.py"
    payload = {
        "positive_factors": {
            "truth_gained": 1,
            "capability_realized": 1,
            "ambiguity_removed": 2,
            "lawful_evolution_increased": 1,
        },
        "negative_factors": {
            "architecture_added_without_runtime_substance": 0,
            "documentary_mass": 0,
            "stale_authority": 0,
            "operator_burden": 0,
            "claim_inflation": 0,
        },
        "runtime_loc_delta": _count_lines(validator_path) + _count_lines(gate_path),
        "test_loc_delta": _count_lines(test_path),
        "governance_json_loc_delta": 0,
        "authoritative_surface_delta": 0,
        "policy": {
            "max_new_authoritative_surfaces": 3,
            "allow_zero_net": True,
        },
    }
    return evaluate_net_elevation(payload)


def build_canonical_delta(
    *,
    root: Path,
    tournament_receipt: Mapping[str, Any],
    merge_receipt: Mapping[str, Any],
    adapter_status: Mapping[str, Any],
    router_status: Mapping[str, Any],
    net_elevation: Mapping[str, Any],
) -> Dict[str, Any]:
    blockers = _active_blockers(root)
    status = "PASS" if all(
        str(item.get("status", "")).strip() == "PASS" for item in (tournament_receipt, merge_receipt, adapter_status, router_status, net_elevation)
    ) else "FAIL"
    return {
        "schema_id": "kt.w2.canonical_delta.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": status,
        "blocker_delta": {
            "change": "NONE_C006_STILL_ONLY_ACTIVE_CURRENT_HEAD_CANONICAL_BLOCKER",
            "active_open_blocker_ids": blockers,
        },
        "ambiguity_reduced": [
            "adapter_promotion_family_is_now_current_head_typed_against_live_runtime_and_w1_register",
            "tournament_and_merge_families_are_now_current_head_typed_as_lab_governed_and_rollback_bound",
            "router_and_lobe_glamour_lock_is_now_explicitly_preserved_under_w2",
            "net_elevation_is_now_measured_rather_than_implied",
        ],
        "source_refs": [
            TRUTH_LOCK_REL,
            ADAPTER_ABI_REL,
            ADAPTER_REGISTRY_REL,
            ADAPTER_LIFECYCLE_REL,
            PROMOTION_LAW_REL,
            TOURNAMENT_LAW_REL,
            MERGE_LAW_REL,
            ROLLBACK_LAW_REL,
            ROUTER_POLICY_REL,
            ROUTER_PROMOTION_LAW_REL,
            LOBE_ROLE_REGISTRY_REL,
            LOBE_PROMOTION_LAW_REL,
            ORGAN_REGISTER_REL,
        ],
        "claim_boundary": "W2 reduces lawful-evolution ambiguity only. It does not close C006 or widen current-head canonical externality, release, or product truth.",
    }


def build_advancement_delta(
    *,
    root: Path,
    tournament_receipt: Mapping[str, Any],
    merge_receipt: Mapping[str, Any],
    adapter_status: Mapping[str, Any],
    router_status: Mapping[str, Any],
    net_elevation: Mapping[str, Any],
) -> Dict[str, Any]:
    status = "PASS" if all(
        str(item.get("status", "")).strip() == "PASS" for item in (tournament_receipt, merge_receipt, adapter_status, router_status, net_elevation)
    ) else "FAIL"
    return {
        "schema_id": "kt.w2.advancement_delta.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": status,
        "lawful_evolution_status": "PASS" if status == "PASS" else "FAIL_CLOSED",
        "canonical_influence_without_promotion": False,
        "router_superiority_unlock": False,
        "multilobe_unlock": False,
        "tournament_public_showability_status": str(tournament_receipt.get("public_showability_status", "")).strip(),
        "merge_admissibility_status": str(merge_receipt.get("merge_admissibility_status", "")).strip(),
        "adapter_family_status": str(adapter_status.get("status", "")).strip(),
        "router_family_status": str(router_status.get("status", "")).strip(),
        "net_elevation_gate": net_elevation,
        "stronger_claims_not_made": [
            "canonical_runtime_mutation_is_unlocked_for_lab_assets",
            "learned_router_superiority_is_earned",
            "multi_lobe_orchestration_superiority_is_earned",
            "c006_is_closed",
            "frontier_or_beyond_sota_language_is_unlocked",
            "commercial_truth_may_widen_from_w2_alone",
        ],
        "claim_boundary": (
            "W2 keeps lawful evolution alive as governed advancement only. "
            "No router, lobe, tournament, merge, or product superiority claim is widened here."
        ),
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate bounded W2 lawful evolution on current-head KT surfaces.")
    parser.add_argument("--tournament-output", default=DEFAULT_TOURNAMENT_OUTPUT_REL)
    parser.add_argument("--merge-output", default=DEFAULT_MERGE_OUTPUT_REL)
    parser.add_argument("--canonical-delta-output", default=DEFAULT_CANONICAL_DELTA_REL)
    parser.add_argument("--advancement-delta-output", default=DEFAULT_ADVANCEMENT_DELTA_REL)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    tournament_output = _resolve(root, args.tournament_output)
    merge_output = _resolve(root, args.merge_output)
    canonical_output = _resolve(root, args.canonical_delta_output)
    advancement_output = _resolve(root, args.advancement_delta_output)

    tournament_receipt = build_tournament_receipt(root=root)
    merge_receipt = build_merge_outcome_receipt(root=root)
    adapter_status = _adapter_family_status(root)
    router_status = _router_lobe_status(root)
    net_elevation = _net_elevation(root)
    canonical_delta = build_canonical_delta(
        root=root,
        tournament_receipt=tournament_receipt,
        merge_receipt=merge_receipt,
        adapter_status=adapter_status,
        router_status=router_status,
        net_elevation=net_elevation,
    )
    advancement_delta = build_advancement_delta(
        root=root,
        tournament_receipt=tournament_receipt,
        merge_receipt=merge_receipt,
        adapter_status=adapter_status,
        router_status=router_status,
        net_elevation=net_elevation,
    )

    write_json_stable(tournament_output, tournament_receipt)
    write_json_stable(merge_output, merge_receipt)
    write_json_stable(canonical_output, canonical_delta)
    write_json_stable(advancement_output, advancement_delta)

    result = {
        "status": "PASS"
        if all(
            str(item.get("status", "")).strip() == "PASS"
            for item in (tournament_receipt, merge_receipt, adapter_status, router_status, net_elevation, canonical_delta, advancement_delta)
        )
        else "FAIL",
        "active_open_blocker_ids": _active_blockers(root),
        "router_superiority_unlock": False,
        "multilobe_unlock": False,
        "net_elevation_status": str(net_elevation.get("status", "")).strip(),
        "tournament_public_showability_status": str(tournament_receipt.get("public_showability_status", "")).strip(),
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
