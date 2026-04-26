from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import canonical_file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


REQUIRED_BRANCH = "authoritative/b04-r6-comparator-metric-contract"
OUTCOME = "B04_R6_LEARNED_ROUTER_COMPARATOR_AND_METRIC_CONTRACT_BOUND"
NEXT_MOVE = "AUTHOR_B04_R6_SHADOW_ROUTER_CANDIDATE_AND_INPUT_MANIFEST"

R6_BLOCKER_MOVE = "AUTHOR_B04_R6_LEARNED_ROUTER_COMPARATOR_AND_METRIC_CONTRACT"
R6_HOLD_MOVE = "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF"

OUTPUTS = {
    "contract_packet": "b04_r6_learned_router_comparator_and_metric_contract_packet.json",
    "receipt": "b04_r6_comparator_metric_contract_receipt.json",
    "validation_matrix": "b04_r6_comparator_metric_validation_matrix.json",
    "blocker_ledger": "b04_r6_comparator_metric_blocker_ledger.json",
    "comparator_matrix": "b04_r6_comparator_matrix_contract.json",
    "metric_thresholds": "b04_r6_metric_thresholds_contract.json",
    "hard_disqualifiers": "b04_r6_hard_disqualifier_contract.json",
    "evidence_requirements": "b04_r6_evidence_requirements_contract.json",
    "shadow_screen_authorization": "b04_r6_shadow_superiority_screen_authorization_contract.json",
    "shadow_input_manifest_contract": "b04_r6_shadow_screen_input_manifest_contract.json",
    "mirror_masked_invariance": "b04_r6_mirror_masked_invariance_prep_packet.json",
    "overrouting_abstention": "b04_r6_overrouting_abstention_detector_prep_packet.json",
    "static_baseline_inventory": "b04_r6_static_baseline_inventory_receipt.json",
    "r1_r5_durability_prep": "b04_r6_r1_r5_replay_durability_prep_receipt.json",
    "clean_state": "b04_r6_comparator_metric_clean_state_receipt.json",
}

FORBIDDEN_CLAIMS = [
    "r6_open",
    "learned_router_superiority_earned",
    "learned_router_cutover_authorized",
    "multi_lobe_authorized",
    "package_promotion_approved",
    "commercial_broadening",
    "external_verification_completed",
]


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _sha_ref(path: Path, *, root: Path) -> Dict[str, str]:
    resolved = path.resolve()
    return {
        "path": resolved.relative_to(root.resolve()).as_posix(),
        "sha256": canonical_file_sha256(resolved),
    }


def _base(*, generated_utc: str, head: str, status: str = "PASS") -> Dict[str, Any]:
    return {
        "status": status,
        "generated_utc": generated_utc,
        "current_git_head": head,
        "authoritative_lane": "B04_R6_LEARNED_ROUTER_COMPARATOR_AND_METRIC_CONTRACT",
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "r6_authorized": False,
        "learned_router_superiority_earned": False,
        "learned_router_cutover_authorized": False,
        "multi_lobe_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _require_dict(payload: Dict[str, Any], key: str, label: str) -> Dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise RuntimeError(f"FAIL_CLOSED: {label} must include object field {key}")
    return value


def _ensure_inputs(
    *,
    next_court: Dict[str, Any],
    blocker_ledger: Dict[str, Any],
    comparator_requirements: Dict[str, Any],
    active_replay: Dict[str, Any],
    r5_terminal: Dict[str, Any],
    scorecard: Dict[str, Any],
    live_validation: Dict[str, Any],
) -> None:
    common.ensure_pass(next_court, label="B04 R6 next court receipt")
    common.ensure_pass(blocker_ledger, label="B04 R6 blocker ledger")
    common.ensure_pass(comparator_requirements, label="B04 R6 comparator requirements packet")
    common.ensure_pass(active_replay, label="B04 R1-R5 active replay receipt")
    common.ensure_pass(scorecard, label="router superiority scorecard")
    common.ensure_pass(live_validation, label="trust-zone validation")
    if next_court.get("next_lawful_move") != R6_BLOCKER_MOVE:
        raise RuntimeError("FAIL_CLOSED: next court receipt does not authorize comparator/metric contract")
    if next_court.get("r6_authorized") is not False or next_court.get("learned_router_superiority_earned") is not False:
        raise RuntimeError("FAIL_CLOSED: next court receipt must keep R6 and superiority blocked")
    if int(blocker_ledger.get("live_blocker_count", -1)) != 1 or int(blocker_ledger.get("r6_blocker_count", -1)) != 1:
        raise RuntimeError("FAIL_CLOSED: R6 blocker ledger must honestly count one active R6 blocker")
    blocker_ids = {str(row.get("blocker_id", "")).strip() for row in blocker_ledger.get("entries", []) if isinstance(row, dict)}
    if "B04_R6_LEARNED_ROUTER_SUPERIORITY_NOT_EARNED" not in blocker_ids:
        raise RuntimeError("FAIL_CLOSED: R6 blocker ledger missing learned-router superiority blocker")
    if active_replay.get("r6_authorized") is not False or active_replay.get("router_superiority_earned") is not False:
        raise RuntimeError("FAIL_CLOSED: active replay must not authorize R6 or superiority")
    if active_replay.get("r5_next_lawful_move") != R6_HOLD_MOVE:
        raise RuntimeError("FAIL_CLOSED: active replay must preserve R5 static-hold R6 blocker")
    for key in ("r1_status", "r2_status", "r3_status", "r4_status", "r5_status"):
        if active_replay.get(key) != "PASS":
            raise RuntimeError(f"FAIL_CLOSED: active replay {key} must be PASS")
    if r5_terminal.get("router_superiority_earned") is not False or r5_terminal.get("learned_router_authorized") is not False:
        raise RuntimeError("FAIL_CLOSED: R5 terminal state must keep router superiority and learned-router authorization false")
    if r5_terminal.get("next_lawful_move") != R6_HOLD_MOVE:
        raise RuntimeError("FAIL_CLOSED: R5 terminal state must preserve R6 hold")
    if comparator_requirements.get("r6_authorized") is not False:
        raise RuntimeError("FAIL_CLOSED: comparator requirements must not authorize R6")
    if len(comparator_requirements.get("minimum_comparator_set", [])) < 3:
        raise RuntimeError("FAIL_CLOSED: comparator requirements must include at least three rows")
    if not isinstance(comparator_requirements.get("required_thresholds"), dict):
        raise RuntimeError("FAIL_CLOSED: comparator requirements must bind thresholds")
    if not isinstance(comparator_requirements.get("disqualifiers"), list) or not comparator_requirements["disqualifiers"]:
        raise RuntimeError("FAIL_CLOSED: comparator requirements must bind disqualifiers")
    best_static = _require_dict(scorecard, "best_static_baseline", "router superiority scorecard")
    learned_candidate = _require_dict(scorecard, "learned_router_candidate", "router superiority scorecard")
    if not best_static:
        raise RuntimeError("FAIL_CLOSED: best static baseline cannot be empty")
    if learned_candidate.get("promotion_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: learned-router candidate must remain non-promotable before screen")
    if scorecard.get("superiority_earned") is not False:
        raise RuntimeError("FAIL_CLOSED: scorecard must not claim superiority before contract")
    if len(live_validation.get("failures", [])) != 0:
        raise RuntimeError("FAIL_CLOSED: trust-zone validation has failures")


def _comparator_rows(scorecard: Dict[str, Any], comparator_requirements: Dict[str, Any]) -> list[Dict[str, Any]]:
    return [
        {
            "row_id": "current_canonical_static_router",
            "role": "CONTROL",
            "source": "KT_PROD_CLEANROOM/reports/router_superiority_scorecard.json",
            "binding": "static_router_remains_canonical",
            "may_win_screen": True,
        },
        {
            "row_id": "best_static_adapter_control",
            "role": "CONTROL",
            "source": comparator_requirements.get("best_static_baseline", scorecard.get("best_static_baseline", {})),
            "binding": "best approved static baseline",
            "may_win_screen": True,
        },
        {
            "row_id": "shadow_learned_router_candidate",
            "role": "CANDIDATE",
            "source": "future candidate/input manifest required before execution",
            "binding": "shadow-only learned-router candidate",
            "may_win_screen": True,
            "may_activate_live_router": False,
        },
        {
            "row_id": "abstention_static_hold_control",
            "role": "CONTROL",
            "source": "current R5 static-hold behavior",
            "binding": "candidate must preserve abstention/static fallback behavior",
            "may_win_screen": False,
        },
    ]


def _metric_contract() -> Dict[str, Dict[str, Any]]:
    return {
        "route_superiority": {
            "scoring": "ordinal_plus_hard_stops",
            "superiority": "candidate must beat both static controls on preregistered route-quality cases",
            "meaningful_movement": "candidate improves route quality without any hard-stop failure",
            "no_movement": "candidate matches static control or only shifts route distribution without outcome gain",
            "defer": "candidate evidence incomplete, comparator mutated, or input family not preregistered",
        },
        "outcome_delta": {
            "scoring": "signed_delta",
            "superiority": "candidate useful-output success exceeds best static control under same inputs",
            "hard_stop": "any useful-output regression on protected control cases",
        },
        "control_preservation": {
            "scoring": "pass_fail",
            "superiority": "not independently sufficient; all controls must pass",
            "hard_stop": "fallback/static baseline, fail-closed behavior, or R1-R5 replay condition degrades",
        },
        "abstention_quality": {
            "scoring": "pass_fail_plus_rate",
            "hard_stop": "abstention collapse or unsafe forced routing",
        },
        "overrouting_penalty": {
            "scoring": "hard_stop",
            "hard_stop": "candidate routes when static hold/abstention should dominate",
        },
        "mirror_masked_invariance": {
            "scoring": "pass_fail",
            "hard_stop": "masked, mirrored, or order-variant inputs change verdict without lawful reason",
        },
        "no_regression": {
            "scoring": "hard_stop",
            "hard_stop": "any R1-R5 pass condition, trust-zone validation, or package deferral boundary regresses",
        },
        "consequence_visibility": {
            "scoring": "pass_fail",
            "hard_stop": "receipt omits why a route was chosen, abstained, or rejected",
        },
    }


def _hard_disqualifiers() -> list[Dict[str, str]]:
    return [
        {"id": "CONTROL_DEGRADATION", "effect": "SCREEN_FAIL"},
        {"id": "ABSTENTION_COLLAPSE", "effect": "SCREEN_FAIL"},
        {"id": "MIRROR_MASKED_INVARIANCE_FAILURE", "effect": "SCREEN_FAIL"},
        {"id": "BETA_OR_HOLDOUT_CONTAMINATION", "effect": "SCREEN_FAIL"},
        {"id": "COMPARATOR_MUTATION", "effect": "SCREEN_FAIL"},
        {"id": "CHERRY_PICKED_ROUTE_FAMILIES", "effect": "SCREEN_FAIL"},
        {"id": "LEARNED_ROUTER_ACTIVATION_BEFORE_SHADOW_PROOF", "effect": "HALT_AND_BLOCK"},
        {"id": "PACKAGE_PROMOTION_OR_PRODUCT_CLAIM_WIDENING", "effect": "HALT_AND_BLOCK"},
    ]


def _allowed_outputs() -> list[str]:
    return [
        "R6_SHADOW_SUPERIORITY_SCREEN_AUTHORIZED",
        "R6_DEFERRED__CONTRACT_INCOMPLETE",
        "R6_BLOCKED__NAMED_COMPARATOR_DEFECT",
    ]


def _evidence_refs(root: Path, reports_root: Path, governance_root: Path) -> Dict[str, Dict[str, str]]:
    rels = {
        "r6_next_court_receipt": reports_root / "b04_r6_next_court_receipt.json",
        "r6_blocker_ledger": reports_root / "b04_r6_blocker_ledger.json",
        "r6_comparator_requirements": reports_root / "b04_r6_comparator_requirements_packet.json",
        "active_r1_r5_replay_receipt": reports_root / "b04_r1_r5_active_revalidation_replay_receipt.json",
        "r1_r5_replay_reproducibility": reports_root / "b04_r1_r5_replay_reproducibility_receipt.json",
        "r5_terminal_state": governance_root / "b04_r5_router_vs_best_adapter_terminal_state.json",
        "router_superiority_scorecard": reports_root / "router_superiority_scorecard.json",
        "canonical_scope_manifest": governance_root / "canonical_scope_manifest.json",
        "trust_zone_registry": governance_root / "trust_zone_registry.json",
    }
    return {key: _sha_ref(path, root=root) for key, path in rels.items()}


def _build_payloads(
    *,
    generated_utc: str,
    head: str,
    evidence_refs: Dict[str, Dict[str, str]],
    scorecard: Dict[str, Any],
    comparator_requirements: Dict[str, Any],
    live_validation: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:
    base = _base(generated_utc=generated_utc, head=head)
    comparator_rows = _comparator_rows(scorecard, comparator_requirements)
    metric_contract = _metric_contract()
    hard_disqualifiers = _hard_disqualifiers()
    screen_status = "SCREEN_CONTRACT_AUTHORIZED__EXECUTION_PENDING_CANDIDATE_INPUT_MANIFEST"
    contract_packet = {
        "schema_id": "kt.operator.b04_r6_learned_router_comparator_and_metric_contract_packet.v1",
        **base,
        "outcome": OUTCOME,
        "contract_result": screen_status,
        "screen_executable_now": False,
        "why_not_executable_now": "Current scorecard records no eligible learned-router candidate; candidate/input manifest must be bound before any shadow screen.",
        "comparator_rows": comparator_rows,
        "counting_metrics": metric_contract,
        "hard_disqualifiers": hard_disqualifiers,
        "allowed_outputs": _allowed_outputs(),
        "explicitly_not_allowed": ["R6_OPEN", "LEARNED_ROUTER_CUTOVER", "LOBE_PROMOTION", "PACKAGE_PROMOTION"],
        "evidence_refs": evidence_refs,
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.b04_r6_comparator_metric_contract_receipt.v1",
        **base,
        "outcome": OUTCOME,
        "screen_contract_authorized": True,
        "screen_executable_now": False,
        "current_live_r6_blocker_count": 1,
        "next_lawful_move": NEXT_MOVE,
    }
    validation = {
        "schema_id": "kt.operator.b04_r6_comparator_metric_validation_matrix.v1",
        **base,
        "checks": [
            {"check": "r6_blocker_count_honest", "status": "PASS"},
            {"check": "r1_r5_active_replay_pass", "status": "PASS"},
            {"check": "r5_static_hold_preserved", "status": "PASS"},
            {"check": "comparator_rows_bound", "status": "PASS"},
            {"check": "metric_thresholds_bound", "status": "PASS"},
            {"check": "hard_disqualifiers_bound", "status": "PASS"},
            {"check": "trust_zone_validation_pass", "status": live_validation.get("status")},
            {"check": "no_r6_open_claim", "status": "PASS"},
        ],
        "failures": [],
        "next_lawful_move": NEXT_MOVE,
    }
    blocker_ledger = {
        "schema_id": "kt.operator.b04_r6_comparator_metric_blocker_ledger.v1",
        **base,
        "live_blocker_count": 1,
        "r6_blocker_count": 1,
        "entries": [
            {
                "blocker_id": "B04_R6_LEARNED_ROUTER_SUPERIORITY_NOT_EARNED",
                "status": "ACTIVE_BLOCKER_RESTATED",
                "resolution_path": "Execute only a later shadow screen after candidate/input manifest is bound.",
            },
            {
                "blocker_id": "B04_R6_SHADOW_CANDIDATE_INPUT_MANIFEST_NOT_BOUND",
                "status": "NEXT_BLOCKER",
                "resolution_path": NEXT_MOVE,
            },
        ],
        "next_lawful_move": NEXT_MOVE,
    }
    comparator_matrix = {
        "schema_id": "kt.operator.b04_r6_comparator_matrix_contract.v1",
        **base,
        "rows": comparator_rows,
        "mutation_rule": "Comparator rows may not change during a counted shadow screen.",
        "next_lawful_move": NEXT_MOVE,
    }
    metric_thresholds = {
        "schema_id": "kt.operator.b04_r6_metric_thresholds_contract.v1",
        **base,
        "metrics": metric_contract,
        "aggregation_rule": "Candidate superiority requires positive route/outcome movement and zero hard-stop failures.",
        "verdicts": _allowed_outputs(),
        "next_lawful_move": NEXT_MOVE,
    }
    disqualifier_contract = {
        "schema_id": "kt.operator.b04_r6_hard_disqualifier_contract.v1",
        **base,
        "hard_disqualifiers": hard_disqualifiers,
        "effect_rule": "Any SCREEN_FAIL disqualifier blocks superiority; any HALT_AND_BLOCK disqualifier halts the lane.",
        "next_lawful_move": NEXT_MOVE,
    }
    evidence_contract = {
        "schema_id": "kt.operator.b04_r6_evidence_requirements_contract.v1",
        **base,
        "required_before_screen": [
            "active R1-R5 replay pass",
            "fixed candidate/input manifest with source hashes",
            "frozen comparator matrix",
            "frozen metric thresholds",
            "hard disqualifier contract",
            "validation matrix",
            "blocker ledger",
            "replayability receipt",
        ],
        "missing_before_execution": ["candidate/input manifest"],
        "next_lawful_move": NEXT_MOVE,
    }
    screen_auth = {
        "schema_id": "kt.operator.b04_r6_shadow_superiority_screen_authorization_contract.v1",
        **base,
        "allowed_screen_result": "R6_SHADOW_SUPERIORITY_SCREEN_AUTHORIZED",
        "screen_contract_authorized": True,
        "screen_executable_now": False,
        "screen_execution_requires_next_manifest": True,
        "r6_open": False,
        "next_lawful_move": NEXT_MOVE,
    }
    input_manifest_contract = {
        "schema_id": "kt.operator.b04_r6_shadow_screen_input_manifest_contract.v1",
        **base,
        "required_fields": [
            "candidate_id",
            "candidate_source_ref",
            "input_family_manifest",
            "holdout_boundary",
            "comparator_matrix_ref",
            "metric_thresholds_ref",
            "hard_disqualifier_ref",
        ],
        "must_be_bound_before_screen": True,
        "next_lawful_move": NEXT_MOVE,
    }
    prep_common = _base(generated_utc=generated_utc, head=head, status="PREP_ONLY")
    return {
        OUTPUTS["contract_packet"]: contract_packet,
        OUTPUTS["receipt"]: receipt,
        OUTPUTS["validation_matrix"]: validation,
        OUTPUTS["blocker_ledger"]: blocker_ledger,
        OUTPUTS["comparator_matrix"]: comparator_matrix,
        OUTPUTS["metric_thresholds"]: metric_thresholds,
        OUTPUTS["hard_disqualifiers"]: disqualifier_contract,
        OUTPUTS["evidence_requirements"]: evidence_contract,
        OUTPUTS["shadow_screen_authorization"]: screen_auth,
        OUTPUTS["shadow_input_manifest_contract"]: input_manifest_contract,
        OUTPUTS["mirror_masked_invariance"]: {
            "schema_id": "kt.operator.b04_r6_mirror_masked_invariance_prep_packet.v1",
            **prep_common,
            "prep_only": True,
            "test_families": ["masked_prompt_order", "mirrored_route_family", "null-route invariance"],
            "next_lawful_move": NEXT_MOVE,
        },
        OUTPUTS["overrouting_abstention"]: {
            "schema_id": "kt.operator.b04_r6_overrouting_abstention_detector_prep_packet.v1",
            **prep_common,
            "prep_only": True,
            "detectors": ["overrouting_rate", "unsafe_forced_route", "abstention_collapse"],
            "next_lawful_move": NEXT_MOVE,
        },
        OUTPUTS["static_baseline_inventory"]: {
            "schema_id": "kt.operator.b04_r6_static_baseline_inventory_receipt.v1",
            **base,
            "best_static_baseline": scorecard.get("best_static_baseline", {}),
            "static_baseline_remains_canonical": True,
            "next_lawful_move": NEXT_MOVE,
        },
        OUTPUTS["r1_r5_durability_prep"]: {
            "schema_id": "kt.operator.b04_r6_r1_r5_replay_durability_prep_receipt.v1",
            **prep_common,
            "r1_r5_floor_required": True,
            "r1_r5_replay_may_not_be_reopened_without_regression_receipt": True,
            "next_lawful_move": NEXT_MOVE,
        },
        OUTPUTS["clean_state"]: {
            "schema_id": "kt.operator.b04_r6_comparator_metric_clean_state_receipt.v1",
            **base,
            "current_git_branch": REQUIRED_BRANCH,
            "worktree_clean_at_lane_start": True,
            "next_lawful_move": NEXT_MOVE,
        },
    }


def run(*, reports_root: Path, governance_root: Path) -> Dict[str, Any]:
    root = repo_root()
    if common.git_current_branch_name(root) != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: must run on {REQUIRED_BRANCH}")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 comparator/metric contract run")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    if governance_root.resolve() != (root / "KT_PROD_CLEANROOM/governance").resolve():
        raise RuntimeError("FAIL_CLOSED: must read canonical governance root only")

    next_court = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_next_court_receipt.json", label="R6 next court receipt")
    blocker_ledger = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_blocker_ledger.json", label="R6 blocker ledger")
    comparator_requirements = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_comparator_requirements_packet.json", label="R6 comparator requirements")
    active_replay = _load(root, "KT_PROD_CLEANROOM/reports/b04_r1_r5_active_revalidation_replay_receipt.json", label="R1-R5 active replay")
    r5_terminal = _load(root, "KT_PROD_CLEANROOM/governance/b04_r5_router_vs_best_adapter_terminal_state.json", label="R5 terminal state")
    scorecard = _load(root, "KT_PROD_CLEANROOM/reports/router_superiority_scorecard.json", label="router superiority scorecard")
    live_validation = validate_trust_zones(root=root)
    _ensure_inputs(
        next_court=next_court,
        blocker_ledger=blocker_ledger,
        comparator_requirements=comparator_requirements,
        active_replay=active_replay,
        r5_terminal=r5_terminal,
        scorecard=scorecard,
        live_validation=live_validation,
    )

    generated_utc = utc_now_iso_z()
    head = common.git_rev_parse(root, "HEAD")
    evidence_refs = _evidence_refs(root, reports_root.resolve(), governance_root.resolve())
    payloads = _build_payloads(
        generated_utc=generated_utc,
        head=head,
        evidence_refs=evidence_refs,
        scorecard=scorecard,
        comparator_requirements=comparator_requirements,
        live_validation=live_validation,
    )
    for filename, payload in payloads.items():
        write_json_stable((reports_root / filename).resolve(), payload)
    return {"outcome": OUTCOME, "next_lawful_move": NEXT_MOVE, "output_count": len(payloads)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Bind B04 R6 learned-router comparator and metric contract.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    parser.add_argument("--governance-root", default="KT_PROD_CLEANROOM/governance")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(
        reports_root=common.resolve_path(root, args.reports_root),
        governance_root=common.resolve_path(root, args.governance_root),
    )
    print(result["outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
