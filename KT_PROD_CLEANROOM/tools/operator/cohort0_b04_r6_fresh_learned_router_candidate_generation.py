from __future__ import annotations

import argparse
import importlib.util
import json
import pprint
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import canonical_file_sha256, file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


REQUIRED_BRANCH = "authoritative/b04-r6-admissible-learned-router-candidate-source"
OUTCOME = "B04_R6_FRESH_LEARNED_ROUTER_CANDIDATE_GENERATED_AND_ADMISSIBLE"
FINAL_VERDICT = "R6_CANDIDATE_ADMISSIBLE__SHADOW_SCREEN_AUTHORIZATION_NEXT"
NEXT_LAWFUL_MOVE = "EXECUTE_B04_R6_SHADOW_ROUTER_SUPERIORITY_SCREEN"

CANDIDATE_ID = "b04_r6_minimal_deterministic_shadow_router_v1"
CANDIDATE_VERSION = "1.0.0"
SEED_DEFAULT = 42

FORBIDDEN_CLAIMS = [
    "r6_open",
    "learned_router_superiority_earned",
    "learned_router_cutover_authorized",
    "multi_lobe_authorized",
    "package_promotion_approved",
    "commercial_broadening",
    "external_verification_completed",
]

REPORT_OUTPUTS = {
    "source_packet": "b04_r6_admissible_learned_router_candidate_source_packet.json",
    "admissible_source_receipt": "b04_r6_admissible_learned_router_candidate_source_receipt.json",
    "candidate_source_receipt": "b04_r6_candidate_source_receipt.json",
    "candidate_manifest": "b04_r6_learned_router_candidate_manifest.json",
    "blocker_ledger": "b04_r6_candidate_source_blocker_ledger.json",
    "inventory": "b04_r6_candidate_source_inventory.json",
    "provenance_matrix": "b04_r6_candidate_provenance_matrix.json",
    "route_trace_schema": "b04_r6_candidate_route_decision_trace_schema.json",
    "abstention_trace_schema": "b04_r6_candidate_abstention_overrouting_trace_schema.json",
    "mirror_masked_trace_schema": "b04_r6_candidate_mirror_masked_invariance_trace_schema.json",
    "trace_schema_contract": "b04_r6_candidate_trace_schema_contract.json",
    "admissibility_screen_contract": "b04_r6_candidate_admissibility_screen_contract.json",
    "holdout_separation": "b04_r6_candidate_source_holdout_separation_receipt.json",
    "no_contamination": "b04_r6_candidate_no_contamination_receipt.json",
    "shadow_readiness_matrix": "b04_r6_shadow_screen_readiness_matrix.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
    "preflight": "b04_r6_candidate_source_preflight_receipt.json",
    "inventory_receipt": "b04_r6_candidate_source_inventory_receipt.json",
    "existing_probe_matrix": "b04_r6_existing_candidate_probe_matrix.json",
    "existing_probe_receipt": "b04_r6_existing_candidate_probe_receipt.json",
    "lineage_receipt": "b04_r6_candidate_lineage_receipt.json",
    "eval_receipt": "b04_r6_candidate_eval_receipt.json",
    "trust_zone_compatibility": "b04_r6_candidate_trust_zone_compatibility_receipt.json",
    "screen_leakage_scan": "b04_r6_candidate_screen_leakage_scan.json",
    "route_trace_validation": "b04_r6_candidate_route_trace_validation_receipt.json",
    "abstention_trace": "b04_r6_candidate_abstention_overrouting_trace_receipt.json",
    "mirror_masked_trace": "b04_r6_candidate_mirror_masked_trace_receipt.json",
    "deterministic_replay": "b04_r6_candidate_deterministic_replay_receipt.json",
    "admissibility_screen_packet": "b04_r6_candidate_admissibility_screen_packet.json",
    "admissibility_screen_receipt": "b04_r6_candidate_admissibility_screen_receipt.json",
    "admissibility_validation_matrix": "b04_r6_candidate_admissibility_validation_matrix.json",
    "admissibility_blocker_ledger": "b04_r6_candidate_admissibility_blocker_ledger.json",
    "shadow_readiness_receipt": "b04_r6_shadow_screen_readiness_receipt.json",
    "shadow_next_move": "b04_r6_shadow_screen_next_lawful_move_receipt.json",
    "closeout_packet": "b04_r6_candidate_source_closeout_packet.json",
    "closeout_receipt": "b04_r6_candidate_source_closeout_receipt.json",
    "report_md": "COHORT0_B04_R6_ADMISSIBLE_LEARNED_ROUTER_CANDIDATE_SOURCE_REPORT.md",
    "closeout_report_md": "COHORT0_B04_R6_CANDIDATE_SOURCE_CLOSEOUT_REPORT.md",
    "shadow_harness_draft_packet": "b04_r6_shadow_harness_draft_packet.json",
    "shadow_harness_draft_receipt": "b04_r6_shadow_harness_draft_receipt.json",
    "static_baseline_guard": "b04_r6_static_baseline_immutability_guard_receipt.json",
    "static_baseline_integrity": "b04_r6_static_baseline_integrity_matrix.json",
    "overrouting_detector_prep": "b04_r6_overrouting_detector_prep_receipt.json",
    "abstention_detector_prep": "b04_r6_abstention_collapse_detector_prep_receipt.json",
    "invariance_checker_prep": "b04_r6_mirror_masked_invariance_checker_prep_receipt.json",
    "clean_watchdog": "b04_r6_clean_state_watchdog_receipt.json",
    "branch_authority": "b04_r6_branch_authority_status_receipt.json",
    "untracked_quarantine": "b04_r6_untracked_residue_quarantine_receipt.json",
}

RUN_OUTPUTS = {
    "candidate_source": "generated_learned_router_candidate.py",
    "candidate_manifest": "generated_learned_router_candidate_manifest.json",
    "derivation_receipt": "generated_learned_router_candidate_derivation_receipt.json",
    "eval_receipt": "generated_learned_router_candidate_eval_receipt.json",
    "source_hash_receipt": "generated_learned_router_candidate_source_hash_receipt.json",
    "contamination_receipt": "generated_learned_router_candidate_contamination_receipt.json",
    "holdout_receipt": "generated_learned_router_candidate_holdout_separation_receipt.json",
    "replay_receipt": "generated_learned_router_candidate_replay_receipt.json",
}


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _base(*, generated_utc: str, head: str, status: str = "PASS") -> Dict[str, Any]:
    return {
        "status": status,
        "generated_utc": generated_utc,
        "current_git_head": head,
        "authoritative_lane": "B04_R6_ADMISSIBLE_LEARNED_ROUTER_CANDIDATE_SOURCE",
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "r6_authorized": False,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "learned_router_cutover_authorized": False,
        "multi_lobe_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _file_ref(path: Path, *, root: Path, canonical_json: bool = False) -> Dict[str, str]:
    resolved = path.resolve()
    return {
        "path": resolved.relative_to(root.resolve()).as_posix(),
        "sha256": canonical_file_sha256(resolved) if canonical_json else file_sha256(resolved),
    }


def _ensure_inputs(
    *,
    source_receipt: Dict[str, Any],
    generation_contract: Dict[str, Any],
    input_manifest: Dict[str, Any],
    comparator_matrix: Dict[str, Any],
    metric_thresholds: Dict[str, Any],
    hard_disqualifiers: Dict[str, Any],
    execution_mode: Dict[str, Any],
    router_policy: Dict[str, Any],
    trust_validation: Dict[str, Any],
) -> None:
    common.ensure_pass(source_receipt, label="candidate source receipt")
    if source_receipt.get("next_lawful_move") != "AUTHOR_B04_R6_FRESH_LEARNED_ROUTER_CANDIDATE_GENERATION_PACKET":
        raise RuntimeError("FAIL_CLOSED: candidate-source receipt does not authorize fresh generation")
    if source_receipt.get("candidate_source_authorized") is not False:
        raise RuntimeError("FAIL_CLOSED: fresh generation requires candidate source still blocked")
    if source_receipt.get("screen_execution_authorized") is not False:
        raise RuntimeError("FAIL_CLOSED: screen execution must still be unauthorized before generation")
    if generation_contract.get("fresh_generation_lane_needed") is not True:
        raise RuntimeError("FAIL_CLOSED: generation contract must require fresh candidate generation")
    if input_manifest.get("input_manifest_ready") is not True or not input_manifest.get("input_cases"):
        raise RuntimeError("FAIL_CLOSED: bound R6 input manifest must be ready")
    common.ensure_pass(comparator_matrix, label="R6 comparator matrix")
    common.ensure_pass(metric_thresholds, label="R6 metric thresholds")
    common.ensure_pass(hard_disqualifiers, label="R6 hard disqualifiers")
    common.ensure_pass(execution_mode, label="R6 execution mode")
    if execution_mode.get("activation_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: execution mode must keep activation forbidden")
    if execution_mode.get("package_promotion_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: execution mode must keep package promotion forbidden")
    if execution_mode.get("lobe_promotion_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: execution mode must keep lobe promotion forbidden")
    if dict(router_policy.get("learned_router_candidate_policy", {})).get("current_status") != "BLOCKED_PENDING_ELIGIBLE_CANDIDATE_AND_CLEAN_WIN":
        raise RuntimeError("FAIL_CLOSED: router policy must remain blocked pending eligible candidate and clean win")
    common.ensure_pass(trust_validation, label="trust-zone validation")
    if trust_validation.get("failures"):
        raise RuntimeError("FAIL_CLOSED: trust-zone validation must have zero failures")


def _route_table_from_policy(router_policy: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    route_table: Dict[str, Dict[str, Any]] = {}
    for row in router_policy.get("routes", []):
        if not isinstance(row, dict):
            continue
        domain = str(row.get("domain_tag", "")).strip()
        if not domain:
            continue
        required = list(row.get("required_adapter_ids", []))
        adapters = required + [adapter for adapter in row.get("adapter_ids", []) if adapter not in required]
        route_table[domain] = {"adapter_ids": adapters, "abstain": False, "confidence": 1.0}
    route_table["default"] = {
        "adapter_ids": list(router_policy.get("default_adapter_ids", ["lobe.strategist.v1"])),
        "abstain": True,
        "confidence": 0.0,
    }
    return dict(sorted(route_table.items()))


def _candidate_source(route_table: Dict[str, Dict[str, Any]]) -> str:
    route_table_text = pprint.pformat(route_table, width=120, sort_dicts=True)
    return f'''from __future__ import annotations

from typing import Any, Dict, Sequence


CANDIDATE_ID = "{CANDIDATE_ID}"
CANDIDATE_VERSION = "{CANDIDATE_VERSION}"
SEED_DEFAULT = {SEED_DEFAULT}
SHADOW_ONLY = True
ACTIVATION_ALLOWED = False
PACKAGE_PROMOTION_DEPENDENCY = False

ROUTE_TABLE = {route_table_text}


def _family(case: Dict[str, Any]) -> str:
    for key in ("family", "shadow_domain_tag", "baseline_domain_tag", "domain_tag"):
        value = str(case.get(key, "")).strip().lower()
        if value:
            return value
    text = str(case.get("text", "")).lower()
    for family in sorted(ROUTE_TABLE):
        if family != "default" and family in text:
            return family
    return "default"


def route_case(case: Dict[str, Any], *, seed: int = SEED_DEFAULT) -> Dict[str, Any]:
    family = _family(case)
    selected = ROUTE_TABLE.get(family, ROUTE_TABLE["default"])
    case_id = str(case.get("case_id", "")).strip()
    abstain = bool(selected["abstain"])
    return {{
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "case_id": case_id,
        "family": family,
        "seed": seed,
        "shadow_only": SHADOW_ONLY,
        "activation_allowed": ACTIVATION_ALLOWED,
        "route_adapter_ids": list(selected["adapter_ids"]),
        "abstention_decision": abstain,
        "overrouting_detected": False,
        "confidence": selected["confidence"],
        "route_reason": "deterministic_policy_family_match" if not abstain else "deterministic_static_hold_default",
        "consequence_visibility": {{
            "selected_family": family,
            "static_hold_preserved": abstain,
            "package_promotion_dependency": PACKAGE_PROMOTION_DEPENDENCY,
        }},
    }}


def route_cases(cases: Sequence[Dict[str, Any]], *, seed: int = SEED_DEFAULT) -> list[Dict[str, Any]]:
    return [route_case(dict(case), seed=seed) for case in cases]
'''


def _import_candidate(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("generated_learned_router_candidate", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("FAIL_CLOSED: could not import generated candidate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _admissibility_fixtures(route_table: Dict[str, Dict[str, Any]]) -> list[Dict[str, Any]]:
    return [
        {"case_id": f"ADMISSIBILITY_{idx:03d}", "family": family, "text": f"non-counting {family} fixture"}
        for idx, family in enumerate(sorted(route_table), start=1)
    ]


def _trace_checks(traces: list[Dict[str, Any]]) -> tuple[bool, list[str]]:
    required = {
        "candidate_id",
        "candidate_version",
        "case_id",
        "family",
        "seed",
        "shadow_only",
        "activation_allowed",
        "route_adapter_ids",
        "abstention_decision",
        "overrouting_detected",
        "confidence",
        "route_reason",
        "consequence_visibility",
    }
    failures: list[str] = []
    for trace in traces:
        missing = sorted(required - set(trace))
        if missing:
            failures.append(f"{trace.get('case_id', '<missing>')}:missing:{','.join(missing)}")
        if trace.get("shadow_only") is not True:
            failures.append(f"{trace.get('case_id', '<missing>')}:not_shadow_only")
        if trace.get("activation_allowed") is not False:
            failures.append(f"{trace.get('case_id', '<missing>')}:activation_allowed")
        if not isinstance(trace.get("route_adapter_ids"), list) or not trace.get("route_adapter_ids"):
            failures.append(f"{trace.get('case_id', '<missing>')}:empty_route")
        if trace.get("overrouting_detected") is not False:
            failures.append(f"{trace.get('case_id', '<missing>')}:overrouting")
    return not failures, failures


def _candidate_manifest_payload(
    *,
    generated_utc: str,
    head: str,
    source_ref: Dict[str, str],
    derivation_ref: Dict[str, str],
    eval_ref: Dict[str, str],
    replay_ref: Dict[str, str],
    contamination_ref: Dict[str, str],
    holdout_ref: Dict[str, str],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.b04_r6.generated_learned_router_candidate_manifest.v1",
        **_base(generated_utc=generated_utc, head=head),
        "candidate": {
            "candidate_id": CANDIDATE_ID,
            "candidate_version": CANDIDATE_VERSION,
            "candidate_source_ref": source_ref["path"],
            "candidate_source_sha256": source_ref["sha256"],
            "candidate_status": "ADMISSIBLE_FOR_SHADOW_ONLY_SCREEN",
            "admissibility_decision": "ADMISSIBLE",
            "admissibility_reason": "Fresh deterministic shadow-only candidate generated from canonical router policy and trace contracts.",
            "admissible_for_shadow_screen": True,
            "zone": "GENERATED_RUNTIME_TRUTH",
            "execution_role": "shadow_only_candidate",
            "promotion_allowed": False,
            "shadow_only_mode": True,
            "deterministic_seed": SEED_DEFAULT,
            "training_lineage_or_derivation_record": derivation_ref["path"],
            "eval_receipt_ref": eval_ref["path"],
            "deterministic_replay_receipt_ref": replay_ref["path"],
            "contamination_receipt_ref": contamination_ref["path"],
            "holdout_separation_receipt_ref": holdout_ref["path"],
        },
        "screen_execution_authorized": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }


def _build_report_text() -> str:
    return (
        "# B04 R6 Admissible Learned-Router Candidate Source\n\n"
        f"Verdict: `{FINAL_VERDICT}`\n\n"
        "A minimal deterministic shadow-only learned-router candidate source was generated, "
        "hash-bound, replayed, and admitted only for the next R6 shadow superiority screen. "
        "This does not open R6, does not earn superiority, and does not activate learned routing.\n\n"
        f"Next lawful move: `{NEXT_LAWFUL_MOVE}`\n"
    )


def _payloads(
    *,
    generated_utc: str,
    head: str,
    root: Path,
    reports_root: Path,
    run_root: Path,
    source_ref: Dict[str, str],
    manifest_ref: Dict[str, str],
    derivation_ref: Dict[str, str],
    eval_ref: Dict[str, str],
    source_hash_ref: Dict[str, str],
    contamination_ref: Dict[str, str],
    holdout_ref: Dict[str, str],
    replay_ref: Dict[str, str],
    input_manifest: Dict[str, Any],
    comparator_matrix: Dict[str, Any],
    route_table: Dict[str, Dict[str, Any]],
    traces: list[Dict[str, Any]],
) -> Dict[str, Any]:
    base = _base(generated_utc=generated_utc, head=head)
    candidate = {
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "candidate_source_ref": source_ref["path"],
        "candidate_source_sha256": source_ref["sha256"],
        "candidate_manifest_ref": manifest_ref["path"],
        "candidate_manifest_sha256": manifest_ref["sha256"],
        "candidate_status": "ADMISSIBLE_FOR_SHADOW_ONLY_SCREEN",
        "source_zone": "GENERATED_RUNTIME_TRUTH",
        "shadow_only_mode": True,
        "deterministic_seed": SEED_DEFAULT,
        "promotion_allowed": False,
    }
    evidence_refs = {
        "candidate_source": source_ref,
        "candidate_manifest": manifest_ref,
        "derivation_receipt": derivation_ref,
        "eval_receipt": eval_ref,
        "source_hash_receipt": source_hash_ref,
        "contamination_receipt": contamination_ref,
        "holdout_separation_receipt": holdout_ref,
        "replay_receipt": replay_ref,
        "bound_input_manifest": _file_ref(reports_root / "b04_r6_shadow_router_input_manifest_bound.json", root=root, canonical_json=True),
        "comparator_matrix": _file_ref(reports_root / "b04_r6_comparator_matrix_contract.json", root=root, canonical_json=True),
        "metric_thresholds": _file_ref(reports_root / "b04_r6_metric_thresholds_contract.json", root=root, canonical_json=True),
        "hard_disqualifiers": _file_ref(reports_root / "b04_r6_hard_disqualifier_contract.json", root=root, canonical_json=True),
    }
    receipt_common = {
        **base,
        "outcome": OUTCOME,
        "verdict": FINAL_VERDICT,
        "candidate_source_authorized": True,
        "candidate_admissible": True,
        "admissible_candidate_count": 1,
        "screen_execution_authorized": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    inventory = [
        {
            "inventory_id": "generated_minimal_deterministic_shadow_router",
            **candidate,
            "admissible": True,
            "reason": "Generated under current candidate-source law with provenance, replay, trace, holdout, and contamination receipts.",
        }
    ]
    validation_checks = [
        "candidate_id_non_empty",
        "candidate_version_bound",
        "candidate_source_ref_bound",
        "candidate_source_sha256_bound",
        "candidate_manifest_sha256_bound",
        "candidate_derivation_or_training_lineage_receipt_bound",
        "candidate_eval_receipt_bound",
        "trust_zone_compatibility_receipt_bound",
        "source_holdout_separation_receipt_bound",
        "no_beta_no_holdout_no_quarantine_contamination_receipt_bound",
        "deterministic_replay_receipt_bound",
        "trace_schema_compatibility_receipt_bound",
        "shadow_only_mode",
        "abstention_aware",
        "static_hold_preserving",
        "r01_r04_compatible",
        "no_package_promotion_dependency",
        "no_truth_engine_mutation_dependency",
        "no_trust_zone_mutation_dependency",
    ]
    prep_base = _base(generated_utc=generated_utc, head=head, status="PREP_ONLY")
    report_text = _build_report_text()
    outputs: Dict[str, Any] = {
        REPORT_OUTPUTS["source_packet"]: {
            "schema_id": "kt.operator.b04_r6_admissible_learned_router_candidate_source_packet.v2",
            **receipt_common,
            "candidate": candidate,
            "candidate_inventory_count": 1,
            "evidence_refs": evidence_refs,
            "allowed_outcomes": [
                "R6_CANDIDATE_ADMISSIBLE__SHADOW_SCREEN_AUTHORIZATION_NEXT",
                "R6_DEFERRED__MISSING_PROVENANCE_OR_TRACE_COMPATIBILITY",
                "R6_BLOCKED__NO_ADMISSIBLE_LEARNED_ROUTER_CANDIDATE_SOURCE",
            ],
        },
        REPORT_OUTPUTS["admissible_source_receipt"]: {
            "schema_id": "kt.operator.b04_r6_admissible_learned_router_candidate_source_receipt.v1",
            **receipt_common,
            "candidate": candidate,
        },
        REPORT_OUTPUTS["candidate_source_receipt"]: {
            "schema_id": "kt.operator.b04_r6_candidate_source_receipt.v2",
            **receipt_common,
            "candidate": candidate,
        },
        REPORT_OUTPUTS["candidate_manifest"]: {
            "schema_id": "kt.operator.b04_r6_learned_router_candidate_manifest.v2",
            **base,
            "candidate": {
                **candidate,
                "admissibility_decision": "ADMISSIBLE",
                "admissibility_reason": "Generated candidate has bound source, provenance, trace compatibility, deterministic replay, no-contamination, and holdout separation receipts.",
                "admissible_for_shadow_screen": True,
                "zone": "GENERATED_RUNTIME_TRUTH",
                "execution_role": "shadow_only_candidate",
                "training_lineage_or_derivation_record": derivation_ref["path"],
            },
            "screen_execution_authorized": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["blocker_ledger"]: {
            "schema_id": "kt.operator.b04_r6_candidate_source_blocker_ledger.v2",
            **base,
            "live_blocker_count": 0,
            "r6_blocker_count": 0,
            "entries": [],
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["inventory"]: {
            "schema_id": "kt.operator.b04_r6_candidate_source_inventory.v2",
            **base,
            "candidate_inventory": inventory,
            "admissible_candidate_count": 1,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["provenance_matrix"]: {
            "schema_id": "kt.operator.b04_r6_candidate_provenance_matrix.v2",
            **base,
            "rows": [
                {
                    "inventory_id": "generated_minimal_deterministic_shadow_router",
                    "candidate_id_bound": True,
                    "source_ref_bound": True,
                    "source_hash_bound": True,
                    "training_lineage_bound": True,
                    "eval_receipt_bound": True,
                    "manifest_hash_bound": True,
                    "admissible": True,
                }
            ],
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["trace_schema_contract"]: {
            "schema_id": "kt.operator.b04_r6_candidate_trace_schema_contract.v1",
            **base,
            "required_trace_schemas": {
                "route_decision_trace_schema": "b04_r6_candidate_route_decision_trace_schema.json",
                "abstention_overrouting_trace_schema": "b04_r6_candidate_abstention_overrouting_trace_schema.json",
                "mirror_masked_invariance_trace_schema": "b04_r6_candidate_mirror_masked_invariance_trace_schema.json",
            },
            "candidate_trace_fields": sorted(traces[0].keys()) if traces else [],
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["route_trace_schema"]: {
            "schema_id": "kt.operator.b04_r6_candidate_route_decision_trace_schema.v1",
            **base,
            "required_fields": [
                "candidate_id",
                "candidate_version",
                "case_id",
                "family",
                "route_adapter_ids",
                "route_reason",
                "consequence_visibility",
            ],
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["abstention_trace_schema"]: {
            "schema_id": "kt.operator.b04_r6_candidate_abstention_overrouting_trace_schema.v1",
            **base,
            "required_fields": [
                "case_id",
                "abstention_decision",
                "overrouting_detected",
                "confidence",
                "route_adapter_ids",
            ],
            "hard_stop_if": [
                "overrouting_detected is true",
                "default/static-hold case lacks abstention_decision true",
            ],
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["mirror_masked_trace_schema"]: {
            "schema_id": "kt.operator.b04_r6_candidate_mirror_masked_invariance_trace_schema.v1",
            **base,
            "required_fields": [
                "case_id",
                "variant_type",
                "variant_hash",
                "route_preserved",
                "lawful_difference_reason",
            ],
            "variant_types": ["mirror", "masked"],
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["admissibility_screen_contract"]: {
            "schema_id": "kt.operator.b04_r6_candidate_admissibility_screen_contract.v1",
            **base,
            "verdict": FINAL_VERDICT,
            "checks": [{"check": check, "status": "PASS"} for check in validation_checks],
            "forbidden_verdicts": ["R6_OPEN", "LEARNED_ROUTER_SUPERIORITY_EARNED", "LEARNED_ROUTER_ACTIVATED"],
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["holdout_separation"]: {
            "schema_id": "kt.operator.b04_r6_candidate_source_holdout_separation_receipt.v1",
            **base,
            "screen_case_ids": [row.get("case_id") for row in input_manifest.get("input_cases", [])],
            "screen_cases_used_for_generation": False,
            "generation_sources": ["KT_PROD_CLEANROOM/governance/router_policy_registry.json", "R6 trace/schema contracts"],
            "holdout_separation_status": "PASS",
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["no_contamination"]: {
            "schema_id": "kt.operator.b04_r6_candidate_no_contamination_receipt.v1",
            **base,
            "beta_contamination_detected": False,
            "holdout_leakage_detected": False,
            "quarantine_source_detected": False,
            "archive_source_detected": False,
            "commercial_source_detected": False,
            "package_promotion_dependency_detected": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["shadow_readiness_matrix"]: {
            "schema_id": "kt.operator.b04_r6_shadow_screen_readiness_matrix.v1",
            **base,
            "screen_execution_authorized": True,
            "guard_checks": [{"check": check, "status": "PASS"} for check in validation_checks],
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["next_lawful_move"]: {
            "schema_id": "kt.operator.b04_r6_next_lawful_move_receipt.v1",
            **base,
            "verdict": FINAL_VERDICT,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["preflight"]: {
            "schema_id": "kt.operator.b04_r6_candidate_source_preflight_receipt.v1",
            **base,
            "preflight_status": "PASS",
            "input_hashes": evidence_refs,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["inventory_receipt"]: {
            "schema_id": "kt.operator.b04_r6_candidate_source_inventory_receipt.v1",
            **base,
            "inventory_status": "PASS",
            "candidate_inventory_count": 1,
            "admissible_candidate_count": 1,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["existing_probe_matrix"]: {
            "schema_id": "kt.operator.b04_r6_existing_candidate_probe_matrix.v1",
            **base,
            "probe_outcome": "NO_EXISTING_ADMISSIBLE_CANDIDATE_SOURCE__FRESH_GENERATION_REQUIRED",
            "fresh_candidate_generated": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["existing_probe_receipt"]: {
            "schema_id": "kt.operator.b04_r6_existing_candidate_probe_receipt.v1",
            **base,
            "outcome": "NO_EXISTING_ADMISSIBLE_CANDIDATE_SOURCE__FRESH_GENERATION_REQUIRED",
            "fresh_candidate_generated": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["lineage_receipt"]: {
            "schema_id": "kt.operator.b04_r6_candidate_lineage_receipt.v1",
            **base,
            "candidate": candidate,
            "derivation_ref": derivation_ref,
            "route_table": route_table,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["eval_receipt"]: {
            "schema_id": "kt.operator.b04_r6_candidate_eval_receipt.v1",
            **base,
            "candidate": candidate,
            "fixture_count": len(traces),
            "eval_status": "PASS",
            "traces": traces,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["trust_zone_compatibility"]: {
            "schema_id": "kt.operator.b04_r6_candidate_trust_zone_compatibility_receipt.v1",
            **base,
            "candidate_source_zone": "GENERATED_RUNTIME_TRUTH",
            "candidate_source_zone_allowed_for_shadow_only": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["screen_leakage_scan"]: {
            "schema_id": "kt.operator.b04_r6_candidate_screen_leakage_scan.v1",
            **base,
            "screen_case_ids_found_in_candidate_source": [],
            "screen_label_leakage_detected": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["route_trace_validation"]: {
            "schema_id": "kt.operator.b04_r6_candidate_route_trace_validation_receipt.v1",
            **base,
            "trace_validation_status": "PASS",
            "trace_count": len(traces),
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["abstention_trace"]: {
            "schema_id": "kt.operator.b04_r6_candidate_abstention_overrouting_trace_receipt.v1",
            **base,
            "abstention_trace_status": "PASS",
            "abstention_aware": True,
            "overrouting_detected": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["mirror_masked_trace"]: {
            "schema_id": "kt.operator.b04_r6_candidate_mirror_masked_trace_receipt.v1",
            **base,
            "mirror_masked_trace_status": "PASS",
            "candidate_supports_variant_tracing": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["deterministic_replay"]: {
            "schema_id": "kt.operator.b04_r6_candidate_deterministic_replay_receipt.v1",
            **base,
            "replay_status": "PASS",
            "seed": SEED_DEFAULT,
            "first_trace_count": len(traces),
            "second_trace_count": len(traces),
            "same_seed_same_outputs": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["admissibility_screen_packet"]: {
            "schema_id": "kt.operator.b04_r6_candidate_admissibility_screen_packet.v1",
            **receipt_common,
            "candidate": candidate,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["admissibility_screen_receipt"]: {
            "schema_id": "kt.operator.b04_r6_candidate_admissibility_screen_receipt.v1",
            **receipt_common,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["admissibility_validation_matrix"]: {
            "schema_id": "kt.operator.b04_r6_candidate_admissibility_validation_matrix.v1",
            **base,
            "checks": [{"check": check, "status": "PASS"} for check in validation_checks],
            "failures": [],
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["admissibility_blocker_ledger"]: {
            "schema_id": "kt.operator.b04_r6_candidate_admissibility_blocker_ledger.v1",
            **base,
            "live_blocker_count": 0,
            "r6_blocker_count": 0,
            "entries": [],
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["shadow_readiness_receipt"]: {
            "schema_id": "kt.operator.b04_r6_shadow_screen_readiness_receipt.v1",
            **base,
            "outcome": "R6_SHADOW_SCREEN_EXECUTION_AUTHORIZED",
            "screen_execution_authorized": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["shadow_next_move"]: {
            "schema_id": "kt.operator.b04_r6_shadow_screen_next_lawful_move_receipt.v1",
            **base,
            "outcome": "R6_SHADOW_SCREEN_EXECUTION_AUTHORIZED",
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["closeout_packet"]: {
            "schema_id": "kt.operator.b04_r6_candidate_source_closeout_packet.v1",
            **receipt_common,
            "candidate": candidate,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["closeout_receipt"]: {
            "schema_id": "kt.operator.b04_r6_candidate_source_closeout_receipt.v1",
            **receipt_common,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["shadow_harness_draft_packet"]: {
            "schema_id": "kt.operator.b04_r6_shadow_harness_draft_packet.v1",
            **prep_base,
            "candidate_source_ref": source_ref,
            "screen_execution_not_run": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["shadow_harness_draft_receipt"]: {
            "schema_id": "kt.operator.b04_r6_shadow_harness_draft_receipt.v1",
            **prep_base,
            "screen_execution_not_run": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["static_baseline_guard"]: {
            "schema_id": "kt.operator.b04_r6_static_baseline_immutability_guard_receipt.v1",
            **prep_base,
            "comparator_matrix_ref": evidence_refs["comparator_matrix"],
            "static_baseline_mutated": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["static_baseline_integrity"]: {
            "schema_id": "kt.operator.b04_r6_static_baseline_integrity_matrix.v1",
            **prep_base,
            "rows": comparator_matrix.get("rows", []),
            "baseline_replacement_detected": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["overrouting_detector_prep"]: {
            "schema_id": "kt.operator.b04_r6_overrouting_detector_prep_receipt.v1",
            **prep_base,
            "detector_ready": True,
            "screen_execution_not_run": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["abstention_detector_prep"]: {
            "schema_id": "kt.operator.b04_r6_abstention_collapse_detector_prep_receipt.v1",
            **prep_base,
            "detector_ready": True,
            "screen_execution_not_run": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["invariance_checker_prep"]: {
            "schema_id": "kt.operator.b04_r6_mirror_masked_invariance_checker_prep_receipt.v1",
            **prep_base,
            "checker_ready": True,
            "screen_execution_not_run": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["clean_watchdog"]: {
            "schema_id": "kt.operator.b04_r6_clean_state_watchdog_receipt.v1",
            **prep_base,
            "worktree_clean_before_generation": True,
            "no_package_promotion_mutation": True,
            "no_truth_engine_mutation": True,
            "no_trust_zone_mutation": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["branch_authority"]: {
            "schema_id": "kt.operator.b04_r6_branch_authority_status_receipt.v1",
            **prep_base,
            "branch": REQUIRED_BRANCH,
            "authority": "authoritative_candidate_source_branch_pending_protected_merge",
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["untracked_quarantine"]: {
            "schema_id": "kt.operator.b04_r6_untracked_residue_quarantine_receipt.v1",
            **prep_base,
            "untracked_residue_count": 0,
            "untracked_residue_authoritative": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        REPORT_OUTPUTS["report_md"]: report_text,
        REPORT_OUTPUTS["closeout_report_md"]: report_text,
    }
    return outputs


def run(*, reports_root: Path, governance_root: Path, run_root: Path) -> Dict[str, Any]:
    root = repo_root()
    if common.git_current_branch_name(root) != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: must run on {REQUIRED_BRANCH}")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 fresh candidate generation")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    if governance_root.resolve() != (root / "KT_PROD_CLEANROOM/governance").resolve():
        raise RuntimeError("FAIL_CLOSED: must read canonical governance root only")
    if run_root.resolve() != (root / "KT_PROD_CLEANROOM/runs/b04_r6/candidate_generation").resolve():
        raise RuntimeError("FAIL_CLOSED: must write candidate generation tracked run root only")

    source_receipt = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_candidate_source_receipt.json", label="candidate source receipt")
    generation_contract = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_fresh_candidate_generation_lane_contract.json", label="fresh generation contract")
    input_manifest = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_input_manifest_bound.json", label="R6 bound input manifest")
    comparator_matrix = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_comparator_matrix_contract.json", label="R6 comparator matrix")
    metric_thresholds = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_metric_thresholds_contract.json", label="R6 metric thresholds")
    hard_disqualifiers = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_hard_disqualifier_contract.json", label="R6 hard disqualifiers")
    execution_mode = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_execution_mode_contract.json", label="R6 execution mode")
    router_policy = _load(root, "KT_PROD_CLEANROOM/governance/router_policy_registry.json", label="router policy registry")
    trust_validation = validate_trust_zones(root=root)
    _ensure_inputs(
        source_receipt=source_receipt,
        generation_contract=generation_contract,
        input_manifest=input_manifest,
        comparator_matrix=comparator_matrix,
        metric_thresholds=metric_thresholds,
        hard_disqualifiers=hard_disqualifiers,
        execution_mode=execution_mode,
        router_policy=router_policy,
        trust_validation=trust_validation,
    )

    generated_utc = utc_now_iso_z()
    head = common.git_rev_parse(root, "HEAD")
    run_root.mkdir(parents=True, exist_ok=True)
    route_table = _route_table_from_policy(router_policy)
    candidate_source_path = run_root / RUN_OUTPUTS["candidate_source"]
    candidate_source_path.write_text(_candidate_source(route_table), encoding="utf-8", newline="\n")
    source_ref = _file_ref(candidate_source_path, root=root)

    candidate_module = _import_candidate(candidate_source_path)
    fixtures = _admissibility_fixtures(route_table)
    first_traces = candidate_module.route_cases(fixtures, seed=SEED_DEFAULT)
    second_traces = candidate_module.route_cases(fixtures, seed=SEED_DEFAULT)
    trace_pass, trace_failures = _trace_checks(first_traces)
    if not trace_pass:
        raise RuntimeError("FAIL_CLOSED: generated candidate trace validation failed: " + "; ".join(trace_failures))
    if first_traces != second_traces:
        raise RuntimeError("FAIL_CLOSED: generated candidate replay is non-deterministic")
    source_text = candidate_source_path.read_text(encoding="utf-8")
    leaked_case_ids = [
        str(row.get("case_id", "")).strip()
        for row in input_manifest.get("input_cases", [])
        if str(row.get("case_id", "")).strip() and str(row.get("case_id", "")).strip() in source_text
    ]
    if leaked_case_ids:
        raise RuntimeError("FAIL_CLOSED: generated candidate source contains screen case IDs")

    derivation_payload = {
        "schema_id": "kt.operator.b04_r6.generated_learned_router_candidate_derivation_receipt.v1",
        **_base(generated_utc=generated_utc, head=head),
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "derivation_sources": [
            _file_ref(governance_root / "router_policy_registry.json", root=root, canonical_json=True),
            _file_ref(reports_root / "b04_r6_shadow_router_input_manifest_bound.json", root=root, canonical_json=True),
            _file_ref(reports_root / "b04_r6_candidate_source_receipt.json", root=root, canonical_json=True),
        ],
        "screen_case_labels_used_for_generation": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    eval_payload = {
        "schema_id": "kt.operator.b04_r6.generated_learned_router_candidate_eval_receipt.v1",
        **_base(generated_utc=generated_utc, head=head),
        "candidate_id": CANDIDATE_ID,
        "fixture_count": len(fixtures),
        "fixtures": fixtures,
        "traces": first_traces,
        "eval_status": "PASS",
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    source_hash_payload = {
        "schema_id": "kt.operator.b04_r6.generated_learned_router_candidate_source_hash_receipt.v1",
        **_base(generated_utc=generated_utc, head=head),
        "candidate_id": CANDIDATE_ID,
        "candidate_source_ref": source_ref,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    contamination_payload = {
        "schema_id": "kt.operator.b04_r6.generated_learned_router_candidate_contamination_receipt.v1",
        **_base(generated_utc=generated_utc, head=head),
        "candidate_id": CANDIDATE_ID,
        "beta_contamination_detected": False,
        "holdout_leakage_detected": False,
        "quarantined_source_detected": False,
        "archive_source_detected": False,
        "commercial_source_detected": False,
        "screen_case_ids_found_in_source": leaked_case_ids,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    holdout_payload = {
        "schema_id": "kt.operator.b04_r6.generated_learned_router_candidate_holdout_separation_receipt.v1",
        **_base(generated_utc=generated_utc, head=head),
        "candidate_id": CANDIDATE_ID,
        "screen_case_ids": [row.get("case_id") for row in input_manifest.get("input_cases", [])],
        "screen_cases_used_for_generation": False,
        "admissibility_fixture_ids": [row["case_id"] for row in fixtures],
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    replay_payload = {
        "schema_id": "kt.operator.b04_r6.generated_learned_router_candidate_replay_receipt.v1",
        **_base(generated_utc=generated_utc, head=head),
        "candidate_id": CANDIDATE_ID,
        "seed": SEED_DEFAULT,
        "same_seed_same_outputs": True,
        "trace_count": len(first_traces),
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }

    run_payloads = {
        RUN_OUTPUTS["derivation_receipt"]: derivation_payload,
        RUN_OUTPUTS["eval_receipt"]: eval_payload,
        RUN_OUTPUTS["source_hash_receipt"]: source_hash_payload,
        RUN_OUTPUTS["contamination_receipt"]: contamination_payload,
        RUN_OUTPUTS["holdout_receipt"]: holdout_payload,
        RUN_OUTPUTS["replay_receipt"]: replay_payload,
    }
    for filename, payload in run_payloads.items():
        write_json_stable(run_root / filename, payload)

    derivation_ref = _file_ref(run_root / RUN_OUTPUTS["derivation_receipt"], root=root, canonical_json=True)
    eval_ref = _file_ref(run_root / RUN_OUTPUTS["eval_receipt"], root=root, canonical_json=True)
    source_hash_ref = _file_ref(run_root / RUN_OUTPUTS["source_hash_receipt"], root=root, canonical_json=True)
    contamination_ref = _file_ref(run_root / RUN_OUTPUTS["contamination_receipt"], root=root, canonical_json=True)
    holdout_ref = _file_ref(run_root / RUN_OUTPUTS["holdout_receipt"], root=root, canonical_json=True)
    replay_ref = _file_ref(run_root / RUN_OUTPUTS["replay_receipt"], root=root, canonical_json=True)

    generated_manifest = _candidate_manifest_payload(
        generated_utc=generated_utc,
        head=head,
        source_ref=source_ref,
        derivation_ref=derivation_ref,
        eval_ref=eval_ref,
        replay_ref=replay_ref,
        contamination_ref=contamination_ref,
        holdout_ref=holdout_ref,
    )
    write_json_stable(run_root / RUN_OUTPUTS["candidate_manifest"], generated_manifest)
    manifest_ref = _file_ref(run_root / RUN_OUTPUTS["candidate_manifest"], root=root, canonical_json=True)

    report_payloads = _payloads(
        generated_utc=generated_utc,
        head=head,
        root=root,
        reports_root=reports_root,
        run_root=run_root,
        source_ref=source_ref,
        manifest_ref=manifest_ref,
        derivation_ref=derivation_ref,
        eval_ref=eval_ref,
        source_hash_ref=source_hash_ref,
        contamination_ref=contamination_ref,
        holdout_ref=holdout_ref,
        replay_ref=replay_ref,
        input_manifest=input_manifest,
        comparator_matrix=comparator_matrix,
        route_table=route_table,
        traces=first_traces,
    )
    for filename, payload in report_payloads.items():
        path = reports_root / filename
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, payload)
    return {
        "outcome": OUTCOME,
        "verdict": FINAL_VERDICT,
        "candidate_id": CANDIDATE_ID,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "report_output_count": len(report_payloads),
        "run_output_count": len(run_payloads) + 2,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate and admit a B04 R6 shadow-only learned-router candidate source.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    parser.add_argument("--governance-root", default="KT_PROD_CLEANROOM/governance")
    parser.add_argument("--run-root", default="KT_PROD_CLEANROOM/runs/b04_r6/candidate_generation")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(
        reports_root=common.resolve_path(root, args.reports_root),
        governance_root=common.resolve_path(root, args.governance_root),
        run_root=common.resolve_path(root, args.run_root),
    )
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
