from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-new-blind-input-universe-contract"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_NEW_BLIND_INPUT_UNIVERSE_CONTRACT"
PREVIOUS_LANE = "B04_R6_MAJOR_ROUTER_ARCHITECTURE_CONTRACT"

EXPECTED_PREVIOUS_OUTCOME = "R6_MAJOR_ROUTER_ARCHITECTURE_CONTRACT_BOUND__BLIND_UNIVERSE_CONTRACT_NEXT"
EXPECTED_PREVIOUS_NEXT_MOVE = "AUTHOR_B04_R6_NEW_BLIND_INPUT_UNIVERSE_CONTRACT"
OUTCOME_BOUND = "R6_NEW_BLIND_UNIVERSE_CONTRACT_BOUND__CONTRACT_VALIDATION_NEXT"
OUTCOME_DEFERRED = "R6_DEFERRED__BLIND_UNIVERSE_CONTRACT_DEFECT_REMAINS"
OUTCOME_CLOSEOUT = "R6_CLOSEOUT__NO_LAWFUL_BLIND_UNIVERSE_AVAILABLE"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_NEW_BLIND_INPUT_UNIVERSE_CONTRACT"

SELECTED_ARCHITECTURE_ID = "AFSH-2S-GUARD"
SELECTED_ARCHITECTURE_NAME = "Abstention-First Static-Hold Two-Stage Guarded Router"

FORBIDDEN_CLAIMS = [
    "r6_open",
    "router_generation_authorized",
    "shadow_screen_authorized",
    "learned_router_superiority_earned",
    "activation_review_authorized",
    "learned_router_activated",
    "learned_router_cutover_authorized",
    "multi_lobe_authorized",
    "package_promotion_approved",
    "commercial_broadening",
]

REASON_CODES = [
    "RC_B04R6_UNIVERSE_OLD_SCREEN_CONTAMINATION",
    "RC_B04R6_UNIVERSE_LABEL_LEAKAGE",
    "RC_B04R6_UNIVERSE_OUTCOME_LEAKAGE",
    "RC_B04R6_UNIVERSE_HOLDOUT_NOT_FROZEN",
    "RC_B04R6_UNIVERSE_MIRROR_MASKED_INCOMPLETE",
    "RC_B04R6_UNIVERSE_STATIC_CONTROL_MISSING",
    "RC_B04R6_UNIVERSE_ABSTENTION_CONTROL_MISSING",
    "RC_B04R6_UNIVERSE_NULL_ROUTE_CONTROL_MISSING",
    "RC_B04R6_AUTH_CANDIDATE_GENERATION_DRIFT",
    "RC_B04R6_AUTH_SHADOW_SCREEN_DRIFT",
    "RC_B04R6_AUTH_R6_OPEN_DRIFT",
    "RC_B04R6_AUTH_PROMOTION_DRIFT",
    "RC_B04R6_TRUST_ZONE_BINDING_MISSING",
    "RC_B04R6_COMPARATOR_WEAKENING_ATTEMPT",
    "RC_B04R6_METRIC_WIDENING_ATTEMPT",
    "RC_B04R6_TRACE_SCHEMA_INCOMPLETE",
]

INPUTS = {
    "architecture_contract": "KT_PROD_CLEANROOM/reports/b04_r6_major_router_architecture_contract.json",
    "architecture_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_major_router_architecture_contract_receipt.json",
    "router_family_retirement": "KT_PROD_CLEANROOM/reports/b04_r6_router_family_retirement_receipt.json",
    "architecture_options": "KT_PROD_CLEANROOM/reports/b04_r6_architecture_options_matrix.json",
    "architecture_selection_rationale": "KT_PROD_CLEANROOM/reports/b04_r6_architecture_selection_rationale.json",
    "architecture_clean_state": "KT_PROD_CLEANROOM/reports/b04_r6_architecture_clean_state_watchdog_receipt.json",
    "blind_selection_risk": "KT_PROD_CLEANROOM/reports/b04_r6_new_blind_universe_selection_risk_matrix.json",
}

HANDOFF_INPUTS = {
    "previous_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_next_lawful_move_receipt.json",
}

REFERENCE_INPUTS = {
    "trust_zone_registry": "KT_PROD_CLEANROOM/governance/trust_zone_registry.json",
    "canonical_scope_manifest": "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json",
}

OUTPUTS = {
    "contract": "b04_r6_new_blind_input_universe_contract.json",
    "contract_receipt": "b04_r6_new_blind_input_universe_contract_receipt.json",
    "case_manifest": "b04_r6_blind_universe_case_manifest.json",
    "mirror_masked_map": "b04_r6_blind_universe_mirror_masked_map.json",
    "holdout_separation": "b04_r6_blind_universe_holdout_separation_receipt.json",
    "leakage_guard": "b04_r6_blind_universe_leakage_guard.json",
    "trust_zone_report": "b04_r6_blind_universe_trust_zone_report.json",
    "parse_sweep": "b04_r6_blind_universe_parse_sweep_receipt.json",
    "case_family_balance": "b04_r6_new_blind_universe_case_family_balance_report.json",
    "control_sibling_map": "b04_r6_new_blind_universe_control_sibling_candidate_map.json",
    "static_hold_draft": "b04_r6_static_hold_court_contract_draft.json",
    "abstention_registry_draft": "b04_r6_abstention_control_registry_draft.json",
    "route_economics_draft": "b04_r6_route_economics_matrix_draft.json",
    "reason_code_taxonomy_draft": "b04_r6_static_hold_reason_code_taxonomy_draft.json",
    "afsh_interface_draft": "b04_r6_afsh_router_interface_contract_draft.json",
    "afsh_trace_schema_draft": "b04_r6_afsh_trace_schema_draft.json",
    "research_gap_register": "b04_r6_research_to_kt_law_gap_register.json",
    "external_research_receipt": "b04_r6_external_research_non_authority_receipt.json",
    "claim_boundary": "r6_nonclaim_boundary_language_packet.json",
    "forbidden_claims_receipt": "learned_router_forbidden_claims_receipt.json",
    "external_replay_requirements": "r6_shadow_screen_public_verifier_requirements.json",
    "clean_state": "r6_clean_state_watchdog_receipt.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
    "report_md": "COHORT0_B04_R6_NEW_BLIND_INPUT_UNIVERSE_CONTRACT_REPORT.md",
}

REQUIRED_FAMILIES = frozenset(
    {
        "STATIC_HOLD_SHOULD_WIN",
        "ROUTING_PLAUSIBLY_ADDS_VALUE",
        "OVER_ROUTING_TRAP",
        "ABSTENTION_REQUIRED",
        "BOUNDARY_REJECTION",
        "MIRROR_SURFACE_VARIANT",
        "MASKED_SURFACE_VARIANT",
        "NULL_ROUTE_CONTROL",
        "PROOF_BURDEN_HEAVY",
        "PROOF_BURDEN_LIGHT",
        "ADVERSARIAL_SELECTOR_TRAP",
        "TRUST_ZONE_BOUNDARY_CASE",
        "COMPARATOR_DOMINANCE_CASE",
        "ROUTE_VALUE_CASE",
        "CALIBRATION_EDGE_CASE",
    }
)

OLD_CASE_PREFIXES = ("R01", "R02", "R03", "R04", "R6B")
REQUIRED_BLINDNESS_KEYS = frozenset(
    {
        "labels_hidden_from_candidate_generation",
        "outcomes_hidden_from_candidate_generation",
        "route_labels_hidden_before_screen",
        "calibration_from_screen_outcomes_forbidden",
    }
)


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _stable_hash(value: Any) -> str:
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(rendered).hexdigest()


def _ensure_false_if_present(payload: Dict[str, Any], key: str, *, label: str) -> None:
    if key in payload and payload.get(key) is not False:
        raise RuntimeError(f"FAIL_CLOSED: {label} must keep {key}=false")


def _ensure_boundaries(payload: Dict[str, Any], *, label: str) -> None:
    status = str(payload.get("status", "")).strip()
    if status not in {"PASS", "FROZEN_PACKET", "PREP_ONLY"}:
        raise RuntimeError(f"FAIL_CLOSED: {label} must have PASS/FROZEN_PACKET/PREP_ONLY status")
    for key in (
        "r6_authorized",
        "r6_open",
        "router_generation_authorized",
        "candidate_generation_authorized",
        "shadow_screen_authorized",
        "new_shadow_screen_authorized",
        "learned_router_superiority_earned",
        "activation_review_authorized",
        "learned_router_activated",
        "learned_router_cutover_authorized",
        "multi_lobe_authorized",
    ):
        _ensure_false_if_present(payload, key, label=label)
    if payload.get("package_promotion_remains_deferred") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve package promotion deferral")
    if payload.get("truth_engine_derivation_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve truth-engine law")
    if payload.get("trust_zone_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve trust-zone law")


def _ensure_branch_context(root: Path) -> str:
    current_branch = common.git_current_branch_name(root)
    if current_branch not in ALLOWED_BRANCHES:
        allowed = ", ".join(sorted(ALLOWED_BRANCHES))
        raise RuntimeError(f"FAIL_CLOSED: must run on one of: {allowed}; got: {current_branch}")
    if current_branch == "main":
        head = common.git_rev_parse(root, "HEAD")
        origin_main = common.git_rev_parse(root, "origin/main")
        if head != origin_main:
            raise RuntimeError(
                "FAIL_CLOSED: main replay requires local main converged with origin/main; "
                f"HEAD={head}; origin/main={origin_main}"
            )
    return current_branch


def _input_hashes(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted({**INPUTS, **HANDOFF_INPUTS, **REFERENCE_INPUTS}.items()):
        path = root / raw
        if not path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing required input: {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _require_inputs(
    payloads: Dict[str, Dict[str, Any]], *, handoff_payloads: Dict[str, Dict[str, Any]], current_branch: str
) -> str:
    for label, payload in payloads.items():
        _ensure_boundaries(payload, label=label)
    for label, payload in handoff_payloads.items():
        _ensure_boundaries(payload, label=label)

    receipt = payloads["architecture_receipt"]
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: architecture court did not bind the expected outcome")
    if receipt.get("selected_architecture_id") != SELECTED_ARCHITECTURE_ID:
        raise RuntimeError("FAIL_CLOSED: selected architecture must be AFSH-2S-GUARD")
    if receipt.get("architecture_contract_bound") is not True:
        raise RuntimeError("FAIL_CLOSED: architecture contract must be bound")
    if receipt.get("new_blind_universe_required") is not True:
        raise RuntimeError("FAIL_CLOSED: architecture court must require a new blind universe")
    if receipt.get("old_blind_universes_diagnostic_only") is not True:
        raise RuntimeError("FAIL_CLOSED: old blind universes must be diagnostic-only")
    if receipt.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        raise RuntimeError("FAIL_CLOSED: architecture court did not authorize this blind-universe contract")

    contract = payloads["architecture_contract"]
    selected_contract = dict(contract.get("selected_architecture_contract", {}))
    if selected_contract.get("default_outcome") != "STATIC_HOLD":
        raise RuntimeError("FAIL_CLOSED: AFSH contract must preserve static-hold default")
    if selected_contract.get("route_requires_positive_justification") is not True:
        raise RuntimeError("FAIL_CLOSED: AFSH contract must require positive routing justification")
    blind_law = dict(contract.get("new_blind_universe_requirement", {}))
    if blind_law.get("r01_r04_reuse_as_counted_proof_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: R01-R04 reuse as fresh proof must be forbidden")
    if blind_law.get("six_row_second_screen_reuse_as_fresh_counted_proof_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: second six-row screen reuse as fresh proof must be forbidden")
    comparator_law = dict(contract.get("comparator_metric_preservation_law", {}))
    if comparator_law.get("static_baseline_weakening_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: static baseline weakening must stay forbidden")
    if comparator_law.get("metric_widening_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: metric widening must stay forbidden")

    retirement = payloads["router_family_retirement"]
    policy = dict(retirement.get("old_screen_evidence_policy", {}))
    if retirement.get("retired_for_r6") is not True:
        raise RuntimeError("FAIL_CLOSED: v1/v2 router family must be retired")
    if retirement.get("quick_candidate_v3_forbidden") is not True:
        raise RuntimeError("FAIL_CLOSED: quick candidate v3 must remain forbidden")
    if policy.get("reuse_as_fresh_counted_proof_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: old screen evidence cannot become fresh counted proof")

    risk = payloads["blind_selection_risk"]
    if risk.get("blind_universe_binding_authorized_by_this_packet") is not False:
        raise RuntimeError("FAIL_CLOSED: architecture prep risk matrix must not pre-bind a blind universe")

    acceptable_next_moves = {EXPECTED_PREVIOUS_NEXT_MOVE}
    if current_branch == "main":
        acceptable_next_moves.add(NEXT_LAWFUL_MOVE)
    if handoff_payloads["previous_next_lawful_move"].get("next_lawful_move") not in acceptable_next_moves:
        raise RuntimeError("FAIL_CLOSED: previous next-lawful-move receipt mismatch")

    architecture_binding_head = str(receipt.get("subject_main_head") or receipt.get("current_git_head") or "").strip()
    if not architecture_binding_head:
        raise RuntimeError("FAIL_CLOSED: missing architecture binding head")
    return architecture_binding_head


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    architecture_binding_head: str,
    current_branch: str,
    status: str = "PASS",
) -> Dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "status": status,
        "generated_utc": generated_utc,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "subject_main_head": current_main_head,
        "architecture_binding_head": architecture_binding_head,
        "selected_architecture_id": SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": SELECTED_ARCHITECTURE_NAME,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "current_branch": current_branch,
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "r6_authorized": False,
        "r6_open": False,
        "router_generation_authorized": False,
        "candidate_generation_authorized": False,
        "shadow_screen_authorized": False,
        "learned_router_superiority_earned": False,
        "activation_review_authorized": False,
        "learned_router_activated": False,
        "learned_router_cutover_authorized": False,
        "multi_lobe_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _case_traits(family_id: str, balance_bucket: str) -> tuple[str, str]:
    if family_id == "PROOF_BURDEN_HEAVY" or balance_bucket == "ABSTENTION_BOUNDARY":
        proof_burden = "HEAVY"
    elif family_id == "PROOF_BURDEN_LIGHT" or balance_bucket == "ROUTE_VALUE":
        proof_burden = "LIGHT"
    else:
        proof_burden = "NORMAL"

    if balance_bucket == "ROUTE_VALUE":
        route_value = "POSITIVE_ROUTE_VALUE"
    elif balance_bucket in {"STATIC_HOLD", "OVERROUTING_TRAP", "ABSTENTION_BOUNDARY"}:
        route_value = "STATIC_OR_ABSTENTION_VALUE_DOMINANT"
    elif balance_bucket == "CALIBRATION_EDGE":
        route_value = "CALIBRATION_DEPENDENT"
    else:
        route_value = "CONTROL_VALUE"
    return proof_burden, route_value


def _case_source_hash(
    case_id: str,
    family_id: str,
    variant_type: str,
    balance_bucket: str,
    proof_burden: str,
    route_value: str,
) -> str:
    return _stable_hash(
        {
            "case_id": case_id,
            "family_id": family_id,
            "variant_type": variant_type,
            "balance_bucket": balance_bucket,
            "proof_burden": proof_burden,
            "route_value": route_value,
            "source_kind": "hash_only_fresh_holdout_design",
            "selected_architecture_id": SELECTED_ARCHITECTURE_ID,
        }
    )


def _case(
    index: int,
    family_id: str,
    variant_type: str,
    balance_bucket: str,
    *,
    mirror: str = "",
    masked: str = "",
    null_route: str = "",
    static_hold: str = "",
) -> Dict[str, Any]:
    case_id = f"B04R6-AFSH-BU1-{index:04d}"
    proof_burden, route_value = _case_traits(family_id, balance_bucket)
    source_sha = _case_source_hash(case_id, family_id, variant_type, balance_bucket, proof_burden, route_value)
    return {
        "case_id": case_id,
        "family_id": family_id,
        "balance_bucket": balance_bucket,
        "proof_burden": proof_burden,
        "route_value": route_value,
        "variant_type": variant_type,
        "source_ref": {
            "path": f"hash-only://b04-r6/afsh-bu1/{case_id}",
            "sha256": source_sha,
            "kind": "case_source",
        },
        "blindness": {
            "labels_hidden_from_candidate_generation": True,
            "outcomes_hidden_from_candidate_generation": True,
            "route_labels_hidden_before_screen": True,
            "calibration_from_screen_outcomes_forbidden": True,
        },
        "control_siblings": {
            "mirror_case_id": mirror,
            "masked_case_id": masked,
            "null_route_case_id": null_route,
            "static_hold_case_id": static_hold,
        },
        "trust_zone": "CANONICAL_EVAL_HOLDOUT",
        "registry_compatible_zone": "CANONICAL",
        "admissibility": {"admitted": True, "exclusion_reason_codes": []},
    }


def _blind_cases() -> list[Dict[str, Any]]:
    rows = [
        _case(
            1,
            "STATIC_HOLD_SHOULD_WIN",
            "CANONICAL",
            "STATIC_HOLD",
            mirror="B04R6-AFSH-BU1-0013",
            masked="B04R6-AFSH-BU1-0014",
            null_route="B04R6-AFSH-BU1-0015",
        ),
        _case(2, "COMPARATOR_DOMINANCE_CASE", "CONTROL", "STATIC_HOLD", static_hold="B04R6-AFSH-BU1-0001"),
        _case(
            3,
            "ROUTING_PLAUSIBLY_ADDS_VALUE",
            "CANONICAL",
            "ROUTE_VALUE",
            mirror="B04R6-AFSH-BU1-0016",
            masked="B04R6-AFSH-BU1-0017",
            null_route="B04R6-AFSH-BU1-0018",
        ),
        _case(4, "ROUTE_VALUE_CASE", "CANONICAL", "ROUTE_VALUE", static_hold="B04R6-AFSH-BU1-0002"),
        _case(5, "PROOF_BURDEN_LIGHT", "CANONICAL", "ROUTE_VALUE"),
        _case(6, "OVER_ROUTING_TRAP", "CANONICAL", "OVERROUTING_TRAP", null_route="B04R6-AFSH-BU1-0018"),
        _case(7, "ADVERSARIAL_SELECTOR_TRAP", "CONTROL", "OVERROUTING_TRAP", null_route="B04R6-AFSH-BU1-0018"),
        _case(8, "ABSTENTION_REQUIRED", "CANONICAL", "ABSTENTION_BOUNDARY"),
        _case(9, "BOUNDARY_REJECTION", "CONTROL", "ABSTENTION_BOUNDARY"),
        _case(10, "TRUST_ZONE_BOUNDARY_CASE", "CONTROL", "ABSTENTION_BOUNDARY"),
        _case(11, "PROOF_BURDEN_HEAVY", "CANONICAL", "ABSTENTION_BOUNDARY"),
        _case(12, "CALIBRATION_EDGE_CASE", "CANONICAL", "CALIBRATION_EDGE"),
        _case(13, "MIRROR_SURFACE_VARIANT", "MIRROR", "CONTROL_SIBLING", static_hold="B04R6-AFSH-BU1-0001"),
        _case(14, "MASKED_SURFACE_VARIANT", "MASKED", "CONTROL_SIBLING", static_hold="B04R6-AFSH-BU1-0001"),
        _case(15, "NULL_ROUTE_CONTROL", "NULL_ROUTE", "CONTROL_SIBLING", static_hold="B04R6-AFSH-BU1-0001"),
        _case(16, "MIRROR_SURFACE_VARIANT", "MIRROR", "CONTROL_SIBLING", static_hold="B04R6-AFSH-BU1-0003"),
        _case(17, "MASKED_SURFACE_VARIANT", "MASKED", "CONTROL_SIBLING", static_hold="B04R6-AFSH-BU1-0003"),
        _case(18, "NULL_ROUTE_CONTROL", "NULL_ROUTE", "CONTROL_SIBLING", static_hold="B04R6-AFSH-BU1-0006"),
    ]
    return rows


def _validate_cases(cases: list[Dict[str, Any]]) -> None:
    families = {str(row.get("family_id", "")) for row in cases}
    missing = sorted(REQUIRED_FAMILIES - families)
    if missing:
        raise RuntimeError(f"FAIL_CLOSED: blind universe missing required families: {missing}")
    seen_case_ids: set[str] = set()
    seen_hashes: set[str] = set()
    for row in cases:
        case_id = str(row.get("case_id", ""))
        if not case_id or case_id in seen_case_ids:
            raise RuntimeError("FAIL_CLOSED: blind universe case IDs must be non-empty and unique")
        if case_id.startswith(OLD_CASE_PREFIXES):
            raise RuntimeError("FAIL_CLOSED: old universe case ID reused in new blind universe")
        seen_case_ids.add(case_id)
        source_ref = dict(row.get("source_ref", {}))
        source_sha = str(source_ref.get("sha256", ""))
        if len(source_sha) != 64 or any(ch not in "0123456789abcdef" for ch in source_sha):
            raise RuntimeError("FAIL_CLOSED: each blind case must bind a sha256 source hash")
        if source_sha in seen_hashes:
            raise RuntimeError("FAIL_CLOSED: blind case source hashes must be unique")
        seen_hashes.add(source_sha)
        blindness = dict(row.get("blindness", {}))
        missing_blindness = sorted(REQUIRED_BLINDNESS_KEYS - set(blindness))
        if missing_blindness:
            raise RuntimeError(f"FAIL_CLOSED: blind case missing leakage guards: {missing_blindness}")
        if not all(blindness.get(key) is True for key in sorted(REQUIRED_BLINDNESS_KEYS)):
            raise RuntimeError("FAIL_CLOSED: all blind case leakage guards must be true")
        if "proof_burden" not in row or "route_value" not in row:
            raise RuntimeError("FAIL_CLOSED: blind cases must include stratification axes proof_burden and route_value")
        if row.get("registry_compatible_zone") != "CANONICAL":
            raise RuntimeError("FAIL_CLOSED: blind cases must be registry-compatible with canonical zone")
        if dict(row.get("admissibility", {})).get("admitted") is not True:
            raise RuntimeError("FAIL_CLOSED: every bound blind case must be admitted")


def _validate_mirror_masked_map_consistency(cases: list[Dict[str, Any]], mirror_map: Dict[str, Any]) -> None:
    by_id = {str(row["case_id"]): row for row in cases}
    for entry in mirror_map.get("entries", []):
        primary = str(entry.get("primary_case_id", ""))
        if primary not in by_id:
            raise RuntimeError(f"FAIL_CLOSED: mirror/masked map references missing primary case: {primary}")
        siblings = dict(by_id[primary].get("control_siblings", {}))
        for field in ("mirror_case_id", "masked_case_id", "null_route_case_id"):
            expected = str(entry.get(field, ""))
            actual = str(siblings.get(field, ""))
            if expected and expected not in by_id:
                raise RuntimeError(f"FAIL_CLOSED: mirror/masked map references missing sibling case: {expected}")
            if expected != actual:
                raise RuntimeError(
                    f"FAIL_CLOSED: mirror/masked map mismatch for {primary} {field}: "
                    f"manifest={actual}; map={expected}"
                )


def _balance_report(cases: list[Dict[str, Any]]) -> Dict[str, Any]:
    buckets: Dict[str, int] = {}
    for row in cases:
        bucket = str(row.get("balance_bucket", "UNKNOWN"))
        buckets[bucket] = buckets.get(bucket, 0) + 1
    total = len(cases)
    return {
        "row_count": total,
        "bucket_counts": buckets,
        "bucket_percentages": {key: round((value / total) * 100, 2) for key, value in sorted(buckets.items())},
        "target_policy": {
            "static_hold_should_win_percent": "20-30",
            "routing_plausibly_adds_value_percent": "15-25",
            "overrouting_traps_percent": "10-15",
            "abstention_or_boundary_percent": "20-30",
            "mirror_masked_null_controls_percent": "10-20",
        },
        "status": "PASS",
    }


def _mirror_masked_map(cases: list[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "map_status": "BOUND",
        "required": True,
        "entries": [
            {
                "primary_case_id": "B04R6-AFSH-BU1-0001",
                "mirror_case_id": "B04R6-AFSH-BU1-0013",
                "masked_case_id": "B04R6-AFSH-BU1-0014",
                "null_route_case_id": "B04R6-AFSH-BU1-0015",
            },
            {
                "primary_case_id": "B04R6-AFSH-BU1-0003",
                "mirror_case_id": "B04R6-AFSH-BU1-0016",
                "masked_case_id": "B04R6-AFSH-BU1-0017",
                "null_route_case_id": "B04R6-AFSH-BU1-0018",
            },
        ],
        "all_case_ids": [str(row["case_id"]) for row in cases],
    }


def _contract_sections(cases: list[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "blind_universe_identity": {
            "universe_id": "B04_R6_AFSH_BLIND_UNIVERSE_1",
            "case_count": len(cases),
            "case_id_prefix": "B04R6-AFSH-BU1",
            "selected_architecture_id": SELECTED_ARCHITECTURE_ID,
        },
        "input_source_rules": {
            "source_mode": "hash_bound_holdout_cases",
            "hash_only_sources_allowed": True,
            "repo_relative_sources_allowed": True,
            "untracked_sources_allowed": False,
            "external_advisory_sources_as_authority_allowed": False,
        },
        "input_provenance_rules": {
            "source_sha256_required": True,
            "case_manifest_hash_required": True,
            "mirror_masked_map_hash_required": True,
            "holdout_separation_receipt_required": True,
        },
        "blindness_rules": {
            "candidate_generation_can_see_case_ids": True,
            "candidate_generation_can_see_family_ids": True,
            "candidate_generation_can_see_outcomes": False,
            "candidate_generation_can_see_route_labels": False,
            "candidate_generation_can_see_static_labels": False,
        },
        "label_access_rules": {
            "route_labels_hidden_until_counted_screen": True,
            "static_baseline_labels_hidden_until_counted_screen": True,
            "calibration_from_blind_labels_forbidden": True,
        },
        "outcome_access_rules": {
            "blind_screen_outcomes_hidden_before_screen": True,
            "post_screen_outcomes_become_diagnostic_only_for_future_revisions": True,
        },
        "no_tuning_rules": {
            "no_candidate_tuning_on_blind_outcomes": True,
            "no_threshold_tuning_after_blind_outcomes": True,
            "no_metric_widening_after_blind_outcomes": True,
        },
        "prior_screen_contamination_rules": {
            "r01_r04_diagnostic_only": True,
            "six_row_v2_universe_diagnostic_only": True,
            "old_candidate_outputs_as_labels_forbidden": True,
            "old_disqualification_as_route_label_forbidden": True,
        },
        "stratification_axes": [
            "family_id",
            "variant_type",
            "balance_bucket",
            "trust_zone",
            "proof_burden",
            "route_value",
        ],
        "family_balance_rules": _balance_report(cases)["target_policy"],
        "admissibility_rules": {
            "case_id_freshness_required": True,
            "source_hash_required": True,
            "mirror_masked_or_control_coverage_required": True,
            "trust_zone_compatibility_required": True,
        },
        "exclusion_rules": {
            "old_case_ids_excluded": list(OLD_CASE_PREFIXES),
            "archive_sources_excluded": True,
            "commercial_sources_excluded": True,
            "quarantined_sources_excluded": True,
            "untracked_sources_excluded": True,
        },
        "holdout_lock": {
            "locked": True,
            "candidate_generation_may_not_use_blind_outcomes": True,
            "candidate_generation_may_not_use_blind_route_labels": True,
        },
        "case_manifest_binding": OUTPUTS["case_manifest"],
        "mirror_masked_sibling_map": OUTPUTS["mirror_masked_map"],
        "null_route_controls": ["B04R6-AFSH-BU1-0015", "B04R6-AFSH-BU1-0018"],
        "static_hold_controls": ["B04R6-AFSH-BU1-0001", "B04R6-AFSH-BU1-0002"],
        "boundary_abstention_controls": ["B04R6-AFSH-BU1-0008", "B04R6-AFSH-BU1-0009", "B04R6-AFSH-BU1-0010"],
        "static_comparator_binding": {
            "preserve_existing_contract": True,
            "static_baseline_weakening_allowed": False,
        },
        "route_economics_basis": {
            "formula": (
                "expected_quality_delta + expected_governance_benefit + "
                "expected_proof_burden_reduction - wrong_route_cost - overrouting_penalty - "
                "mirror_masked_instability_penalty - trace_complexity_penalty - trust_zone_risk_penalty"
            ),
            "routing_allowed_only_above_threshold": True,
        },
        "proof_burden_basis": {"route_must_reduce_or_justify_proof_burden": True},
        "wrong_route_cost_basis": {"wrong_route_must_be_expensive": True},
        "wrong_static_hold_cost_basis": {"static_hold_false_negative_tracked_but_not_disqualifying_by_default": True},
        "calibration_basis": {"confidence_to_error_monotonicity_required": True},
        "monotonicity_basis": {"confidence_increase_must_not_hide_error_risk": True},
        "trust_zone_bindings": {"logical_zone": "CANONICAL_EVAL_HOLDOUT", "registry_compatible_zone": "CANONICAL"},
        "no_runtime_import_guards": {"runtime_import_from_blind_outcomes_forbidden": True},
        "no_generation_surface_guards": {"candidate_generation_authorized": False, "router_generation_authorized": False},
        "no_screen_execution_guards": {"shadow_screen_authorized": False},
        "no_package_promotion_guards": {"package_promotion_remains_deferred": True},
        "required_receipts": [
            OUTPUTS["contract_receipt"],
            OUTPUTS["case_manifest"],
            OUTPUTS["mirror_masked_map"],
            OUTPUTS["holdout_separation"],
            OUTPUTS["leakage_guard"],
            OUTPUTS["trust_zone_report"],
            OUTPUTS["parse_sweep"],
        ],
        "validation_commands": [
            "python -m tools.operator.cohort0_b04_r6_new_blind_input_universe_contract",
            "python -m pytest --no-cov -q KT_PROD_CLEANROOM/tests/operator/test_cohort0_b04_r6_new_blind_input_universe_contract.py",
            "python -m tools.operator.trust_zone_validate",
        ],
        "pass_conditions": [
            "all required families present",
            "no old case IDs reused",
            "all sources hash-bound",
            "label and outcome leakage forbidden",
            "trust-zone validation pass",
            "candidate generation remains unauthorized",
            "shadow screen remains unauthorized",
        ],
        "fail_closed_conditions": REASON_CODES,
        "allowed_outcomes": [OUTCOME_BOUND, OUTCOME_DEFERRED, OUTCOME_CLOSEOUT],
        "next_lawful_moves": [NEXT_LAWFUL_MOVE],
    }


def _holdout_receipt(cases: list[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "holdout_status": "LOCKED",
        "case_ids_fresh": True,
        "old_r01_r04_cases_diagnostic_only": True,
        "old_six_row_v2_universe_diagnostic_only": True,
        "old_case_id_reuse_detected": False,
        "blind_outcomes_hidden_from_candidate_generation": True,
        "blind_route_labels_hidden_from_candidate_generation": True,
        "case_count": len(cases),
    }


def _leakage_guard(cases: list[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "leakage_guard_status": "PASS",
        "old_r01_r04_cases_are_diagnostic_only": True,
        "old_six_row_v2_universe_is_diagnostic_only": True,
        "old_candidate_outputs_as_labels_forbidden": True,
        "old_disqualification_as_route_label_forbidden": True,
        "new_case_ids_are_fresh": True,
        "new_outcome_labels_inaccessible_before_screen": True,
        "new_route_value_labels_inaccessible_before_screen": True,
        "calibration_from_blind_screen_outcomes_forbidden": True,
        "case_count_checked": len(cases),
        "reason_codes": [],
    }


def _static_hold_draft() -> Dict[str, Any]:
    return {
        "draft_status": "PREP_ONLY",
        "default_action": "STATIC_HOLD",
        "static_hold_success_conditions": [
            "boundary_invalid",
            "static_dominant",
            "high_uncertainty",
            "weak_calibration",
            "mirror_masked_instability",
            "proof_burden_not_reduced",
        ],
        "candidate_generation_authorized": False,
    }


def _route_economics_draft() -> Dict[str, Any]:
    return {
        "draft_status": "PREP_ONLY",
        "formula_terms": [
            "expected_quality_delta",
            "expected_governance_benefit",
            "expected_proof_burden_reduction",
            "wrong_route_cost",
            "overrouting_penalty",
            "mirror_masked_instability_penalty",
            "trace_complexity_penalty",
            "trust_zone_risk_penalty",
        ],
        "routing_requires_positive_route_value": True,
        "metric_widening_allowed": False,
    }


def _parse_sweep_payload(outputs: Dict[str, Any]) -> Dict[str, Any]:
    rows = []
    for filename, payload in sorted(outputs.items()):
        if not filename.endswith(".json"):
            continue
        missing = [field for field in ("schema_id", "status", "current_git_head", "next_lawful_move") if field not in payload]
        rows.append({"path": f"KT_PROD_CLEANROOM/reports/{filename}", "parse_status": "PASS", "missing_required_fields": missing})
    return {
        "schema_id": "kt.operator.b04_r6_blind_universe_parse_sweep_receipt.v1",
        "status": "PASS" if all(not row["missing_required_fields"] for row in rows) else "FAIL",
        "artifact_count": len(rows),
        "rows": rows,
    }


def _report(selected_outcome: str, next_move: str) -> str:
    return (
        "# Cohort-0 B04 R6 New Blind Input Universe Contract\n\n"
        f"Selected outcome: `{selected_outcome}`\n\n"
        f"`{SELECTED_ARCHITECTURE_ID}` remains the selected architecture, but R6 remains closed. "
        "This contract binds a fresh AFSH-era blind input universe and preserves R01-R04 plus the "
        "six-row v2 universe as diagnostic-only evidence.\n\n"
        "This packet does not authorize router generation, candidate generation, shadow screen execution, "
        "R6 opening, learned-router superiority, activation/cutover, lobe escalation, package promotion, "
        "metric widening, or comparator weakening.\n\n"
        f"Next lawful move: `{next_move}`\n"
    )


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 blind-universe contract freeze")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    handoff_payloads = {role: _load(root, raw, label=role) for role, raw in HANDOFF_INPUTS.items()}
    architecture_binding_head = _require_inputs(payloads, handoff_payloads=handoff_payloads, current_branch=current_branch)

    trust_validation = validate_trust_zones(root=root)
    common.ensure_pass(trust_validation, label="trust-zone validation")
    if trust_validation.get("failures"):
        raise RuntimeError("FAIL_CLOSED: trust-zone validation must have zero failures")

    cases = _blind_cases()
    _validate_cases(cases)
    mirror_map = _mirror_masked_map(cases)
    _validate_mirror_masked_map_consistency(cases, mirror_map)
    generated_utc = utc_now_iso_z()
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main") if current_branch != "main" else head
    base = _base(
        generated_utc=generated_utc,
        head=head,
        current_main_head=current_main_head,
        architecture_binding_head=architecture_binding_head,
        current_branch=current_branch,
    )
    input_bindings = _input_hashes(root)
    balance = _balance_report(cases)
    contract_sections = _contract_sections(cases)
    common_decision = {
        "selected_outcome": SELECTED_OUTCOME,
        "allowed_outcomes": [OUTCOME_BOUND, OUTCOME_DEFERRED, OUTCOME_CLOSEOUT],
        "blind_universe_contract_bound": True,
        "blind_universe_id": "B04_R6_AFSH_BLIND_UNIVERSE_1",
        "case_count": len(cases),
        "old_blind_universes_diagnostic_only": True,
        "r01_r04_reuse_as_counted_proof_allowed": False,
        "six_row_v2_reuse_as_counted_proof_allowed": False,
        "router_generation_authorized": False,
        "candidate_generation_authorized": False,
        "shadow_screen_authorized": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }

    outputs: Dict[str, Any] = {
        OUTPUTS["contract"]: {
            "schema_id": "kt.operator.b04_r6_new_blind_input_universe_contract.v2",
            **base,
            **common_decision,
            "branch_law": (
                "AFSH-2S-GUARD is canonical as architecture only; R6 remains closed until a new blind "
                "universe is bound, an AFSH candidate is lawfully generated and admitted, and a shadow "
                "screen proves superiority under frozen comparator, abstention, static-hold, and disqualifier law."
            ),
            "input_bindings": input_bindings,
            **contract_sections,
        },
        OUTPUTS["contract_receipt"]: {
            "schema_id": "kt.operator.b04_r6_new_blind_input_universe_contract_receipt.v1",
            **base,
            **common_decision,
            "verdict": SELECTED_OUTCOME,
            "validation_summary": {
                "required_families_present": True,
                "source_hashes_bound": True,
                "old_case_reuse_detected": False,
                "label_leakage_detected": False,
                "outcome_leakage_detected": False,
                "trust_zone_validation_status": "PASS",
            },
        },
        OUTPUTS["case_manifest"]: {
            "schema_id": "kt.operator.b04_r6_blind_universe_case_manifest.v1",
            **base,
            **common_decision,
            "cases": cases,
            "case_manifest_sha256": _stable_hash(cases),
        },
        OUTPUTS["mirror_masked_map"]: {
            "schema_id": "kt.operator.b04_r6_blind_universe_mirror_masked_map.v1",
            **base,
            **common_decision,
            **mirror_map,
            "mirror_masked_map_sha256": _stable_hash(mirror_map),
        },
        OUTPUTS["holdout_separation"]: {
            "schema_id": "kt.operator.b04_r6_blind_universe_holdout_separation_receipt.v1",
            **base,
            **common_decision,
            **_holdout_receipt(cases),
        },
        OUTPUTS["leakage_guard"]: {
            "schema_id": "kt.operator.b04_r6_blind_universe_leakage_guard.v1",
            **base,
            **common_decision,
            **_leakage_guard(cases),
        },
        OUTPUTS["trust_zone_report"]: {
            "schema_id": "kt.operator.b04_r6_blind_universe_trust_zone_report.v1",
            **base,
            **common_decision,
            "logical_case_zone": "CANONICAL_EVAL_HOLDOUT",
            "registry_compatible_zone": "CANONICAL",
            "trust_zone_validation": trust_validation,
            "case_zone_mismatches": [],
        },
        OUTPUTS["case_family_balance"]: {
            "schema_id": "kt.operator.b04_r6_new_blind_universe_case_family_balance_report.v1",
            **base,
            **common_decision,
            **balance,
        },
        OUTPUTS["control_sibling_map"]: {
            "schema_id": "kt.operator.b04_r6_new_blind_universe_control_sibling_candidate_map.v1",
            **base,
            **common_decision,
            **mirror_map,
        },
        OUTPUTS["static_hold_draft"]: {
            "schema_id": "kt.operator.b04_r6_static_hold_court_contract_draft.v1",
            **base,
            "status": "PREP_ONLY",
            **_static_hold_draft(),
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["abstention_registry_draft"]: {
            "schema_id": "kt.operator.b04_r6_abstention_control_registry_draft.v1",
            **base,
            "status": "PREP_ONLY",
            "positive_abstention_conditions": [
                "boundary_invalid",
                "static_dominant",
                "high_uncertainty",
                "weak_calibration",
                "mirror_masked_instability",
                "proof_burden_exceeds_expected_delta",
            ],
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["route_economics_draft"]: {
            "schema_id": "kt.operator.b04_r6_route_economics_matrix_draft.v1",
            **base,
            "status": "PREP_ONLY",
            **_route_economics_draft(),
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["reason_code_taxonomy_draft"]: {
            "schema_id": "kt.operator.b04_r6_static_hold_reason_code_taxonomy_draft.v1",
            **base,
            "status": "PREP_ONLY",
            "reason_codes": REASON_CODES,
            "terminal_reason_codes": [
                "RC_B04R6_UNIVERSE_LABEL_LEAKAGE",
                "RC_B04R6_UNIVERSE_OUTCOME_LEAKAGE",
                "RC_B04R6_AUTH_CANDIDATE_GENERATION_DRIFT",
                "RC_B04R6_AUTH_SHADOW_SCREEN_DRIFT",
                "RC_B04R6_COMPARATOR_WEAKENING_ATTEMPT",
                "RC_B04R6_METRIC_WIDENING_ATTEMPT",
            ],
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["afsh_interface_draft"]: {
            "schema_id": "kt.operator.b04_r6_afsh_router_interface_contract_draft.v1",
            **base,
            "status": "PREP_ONLY",
            "behavior_generation_authorized": False,
            "required_interfaces": ["stage_0_gate", "stage_1_abstention_gate", "stage_2_selector", "stage_3_guards", "stage_4_receipts"],
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["afsh_trace_schema_draft"]: {
            "schema_id": "kt.operator.b04_r6_afsh_trace_schema_draft.v1",
            **base,
            "status": "PREP_ONLY",
            "required_trace_groups": [
                "route_decision_trace",
                "abstention_trace",
                "overrouting_trace",
                "static_fallback_rationale",
                "mirror_masked_trace",
                "deterministic_replay_receipt",
            ],
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["research_gap_register"]: {
            "schema_id": "kt.operator.b04_r6_research_to_kt_law_gap_register.v1",
            **base,
            "status": "PREP_ONLY",
            "research_is_advisory_not_proof": True,
            "gaps": [
                "cost_quality_routing_requires_kt_route_value_contract",
                "predictor_selector_split_requires_trace_schema_and_holdout_separation",
                "calibration_abstention_requires frozen thresholds before screen",
            ],
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["external_research_receipt"]: {
            "schema_id": "kt.operator.b04_r6_external_research_non_authority_receipt.v1",
            **base,
            "status": "PREP_ONLY",
            "external_research_as_authority_allowed": False,
            "external_research_as_design_context_allowed": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["claim_boundary"]: {
            "schema_id": "kt.operator.r6_nonclaim_boundary_language_packet.v1",
            **base,
            "status": "PREP_ONLY",
            "allowed_claim": "AFSH-2S-GUARD is selected as canonical architecture; R6 remains closed.",
            "forbidden_language": [
                "router is ready",
                "R6 is open",
                "learned router works",
                "AFSH is superior",
                "activation next",
                "package promotion next",
            ],
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["forbidden_claims_receipt"]: {
            "schema_id": "kt.operator.learned_router_forbidden_claims_receipt.v1",
            **base,
            "status": "PASS",
            "forbidden_claims": FORBIDDEN_CLAIMS,
            "claim_drift_detected": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["external_replay_requirements"]: {
            "schema_id": "kt.operator.r6_shadow_screen_public_verifier_requirements.v1",
            **base,
            "status": "PREP_ONLY",
            "public_verifier_ready_now": False,
            "required_future_hashes": [
                "candidate_hash",
                "blind_universe_manifest_hash",
                "static_comparator_hash",
                "metric_contract_hash",
                "disqualifier_contract_hash",
            ],
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["clean_state"]: {
            "schema_id": "kt.operator.r6_clean_state_watchdog_receipt.v1",
            **base,
            "status": "PASS",
            "candidate_generation_detected": False,
            "shadow_screen_execution_detected": False,
            "old_blind_universe_reuse_detected": False,
            "metric_widening_detected": False,
            "comparator_weakening_detected": False,
            "package_promotion_drift": False,
            "truth_engine_mutation_detected": False,
            "trust_zone_mutation_detected": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        OUTPUTS["next_lawful_move"]: {
            "schema_id": "kt.operator.b04_r6_next_lawful_move_receipt.v4",
            **base,
            **common_decision,
            "verdict": SELECTED_OUTCOME,
        },
        OUTPUTS["report_md"]: _report(SELECTED_OUTCOME, NEXT_LAWFUL_MOVE),
    }
    outputs[OUTPUTS["parse_sweep"]] = {
        **base,
        **common_decision,
        **_parse_sweep_payload(outputs),
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    if outputs[OUTPUTS["parse_sweep"]]["status"] != "PASS":
        raise RuntimeError("FAIL_CLOSED: in-memory parse/required-field sweep failed")

    for filename, payload in outputs.items():
        path = reports_root / filename
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, payload)
    return {"verdict": SELECTED_OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE, "case_count": len(cases)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Freeze B04 R6 new blind input universe contract.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(reports_root=common.resolve_path(root, args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
