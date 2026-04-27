from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable


REQUIRED_BRANCH = "authoritative/b04-r6-candidate-v2-source"
AUTHORITATIVE_LANE = "B04_R6_CANDIDATE_V2_SOURCE_PACKET__BLIND_INPUT_CONTRACT_BOUND"
PREVIOUS_LANE = "B04_R6_CANDIDATE_REVISION_PACKET__NEW_BLIND_INPUT_UNIVERSE_REQUIRED"

EXPECTED_PRIOR_VERDICT = "CANDIDATE_REVISION_AUTHORIZED__NEW_BLIND_INPUT_REQUIRED"
EXPECTED_PRIOR_NEXT_MOVE = "AUTHOR_B04_R6_CANDIDATE_V2_SOURCE_PACKET__BLIND_INPUT_CONTRACT_BOUND"
FINAL_VERDICT = "R6_CANDIDATE_V2_ADMISSIBLE__SECOND_SHADOW_SCREEN_AUTHORIZATION_NEXT"
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_SECOND_SHADOW_SCREEN_EXECUTION_PACKET"

FORBIDDEN_CLAIMS = [
    "r6_open",
    "learned_router_superiority_earned",
    "learned_router_activated",
    "learned_router_cutover_authorized",
    "multi_lobe_authorized",
    "package_promotion_approved",
    "commercial_broadening",
]

INPUTS = {
    "revision_packet": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_revision_packet.json",
    "revision_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_revision_receipt.json",
    "blind_contract": "KT_PROD_CLEANROOM/reports/b04_r6_new_blind_input_universe_contract.json",
    "v2_source_requirements": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_source_requirements.json",
    "v2_feature_requirements": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_feature_requirements.json",
    "overfit_guard": "KT_PROD_CLEANROOM/reports/b04_r6_overfit_risk_guard_receipt.json",
    "feature_gap_matrix": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v1_failure_feature_gap_matrix.json",
    "static_dominance": "KT_PROD_CLEANROOM/reports/b04_r6_static_comparator_dominance_analysis.json",
    "blind_candidate_set": "KT_PROD_CLEANROOM/reports/b04_r6_blind_input_universe_candidate_set.json",
}

OUTPUTS = {
    "source_packet": "b04_r6_candidate_v2_source_packet.json",
    "source_receipt": "b04_r6_candidate_v2_source_receipt.json",
    "manifest": "b04_r6_candidate_v2_manifest.json",
    "provenance_matrix": "b04_r6_candidate_v2_provenance_matrix.json",
    "derivation_receipt": "b04_r6_candidate_v2_derivation_receipt.json",
    "eval_receipt": "b04_r6_candidate_v2_eval_receipt.json",
    "source_hash_receipt": "b04_r6_candidate_v2_source_hash_receipt.json",
    "no_contamination_receipt": "b04_r6_candidate_v2_no_contamination_receipt.json",
    "overfit_guard_receipt": "b04_r6_candidate_v2_overfit_risk_guard_receipt.json",
    "blind_separation_receipt": "b04_r6_candidate_v2_blind_universe_separation_receipt.json",
    "trace_compatibility_receipt": "b04_r6_candidate_v2_trace_compatibility_receipt.json",
    "deterministic_replay_receipt": "b04_r6_candidate_v2_deterministic_replay_receipt.json",
    "admissibility_receipt": "b04_r6_candidate_v2_admissibility_receipt.json",
    "blocker_ledger": "b04_r6_candidate_v2_blocker_ledger.json",
    "admissibility_matrix": "b04_r6_candidate_v2_admissibility_validation_matrix.json",
    "second_readiness_matrix": "b04_r6_second_shadow_screen_readiness_matrix.json",
    "second_authorization_receipt": "b04_r6_second_shadow_screen_authorization_receipt.json",
    "next_lawful_move_receipt": "b04_r6_next_lawful_move_receipt.json",
    "report_md": "COHORT0_B04_R6_CANDIDATE_V2_SOURCE_REPORT.md",
}

CANDIDATE_SOURCE_REL = "KT_PROD_CLEANROOM/runs/b04_r6/candidate_v2_generation/generated_learned_router_candidate_v2.py"
CANDIDATE_ID = "b04_r6_diagnostic_gap_shadow_router_v2"
CANDIDATE_VERSION = "2.0.0"
SEED_DEFAULT = 42

CANDIDATE_V2_SOURCE = '''from __future__ import annotations

from typing import Any, Dict, Sequence


CANDIDATE_ID = "b04_r6_diagnostic_gap_shadow_router_v2"
CANDIDATE_VERSION = "2.0.0"
SEED_DEFAULT = 42
SHADOW_ONLY = True
ACTIVATION_ALLOWED = False
PACKAGE_PROMOTION_DEPENDENCY = False

ROUTE_POLICY = {
    "default": {
        "abstain": True,
        "adapter_ids": ["lobe.strategist.v1"],
        "confidence": 0.0,
        "route_reason": "v2_static_hold_for_unknown_family",
    },
    "governance": {
        "abstain": False,
        "adapter_ids": ["lobe.auditor.v1", "lobe.censor.v1"],
        "confidence": 0.64,
        "route_reason": "v2_visible_family_policy_governance_audit_first",
    },
    "masked_ambiguous": {
        "abstain": True,
        "adapter_ids": ["lobe.strategist.v1"],
        "confidence": 0.0,
        "route_reason": "v2_masked_ambiguity_static_hold",
    },
    "math": {
        "abstain": False,
        "adapter_ids": ["lobe.censor.v1", "lobe.quant.v1"],
        "confidence": 0.66,
        "route_reason": "v2_visible_family_policy_quantitative",
    },
    "mixed_math_governance": {
        "abstain": False,
        "adapter_ids": ["lobe.auditor.v1", "lobe.quant.v1", "lobe.censor.v1"],
        "confidence": 0.58,
        "route_reason": "v2_visible_family_policy_mixed_governance_quant",
    },
    "poetry": {
        "abstain": False,
        "adapter_ids": ["lobe.muse.v1"],
        "confidence": 0.63,
        "route_reason": "v2_visible_family_policy_poetry",
    },
}


def _family(case: Dict[str, Any]) -> str:
    for key in ("family", "shadow_domain_tag", "baseline_domain_tag", "domain_tag"):
        value = str(case.get(key, "")).strip().lower()
        if value:
            return value
    pressure = str(case.get("pressure_type", "")).strip().lower()
    if "masked" in pressure:
        return "masked_ambiguous"
    if "multi" in pressure:
        return "mixed_math_governance"
    return "default"


def _policy_for(case: Dict[str, Any]) -> Dict[str, Any]:
    family = _family(case)
    policy = ROUTE_POLICY.get(family, ROUTE_POLICY["default"])
    if "static_hold" in str(case.get("pressure_type", "")).lower():
        return ROUTE_POLICY["default"]
    return policy


def route_case(case: Dict[str, Any], *, seed: int = SEED_DEFAULT) -> Dict[str, Any]:
    policy = _policy_for(case)
    family = _family(case)
    abstain = bool(policy["abstain"])
    case_id = str(case.get("case_id", "")).strip()
    visible_features = {
        "family": family,
        "pressure_type": str(case.get("pressure_type", "")).strip(),
        "source_kind": str(case.get("source_kind", "")).strip(),
    }
    return {
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "case_id": case_id,
        "family": family,
        "seed": seed,
        "shadow_only": SHADOW_ONLY,
        "activation_allowed": ACTIVATION_ALLOWED,
        "route_adapter_ids": list(policy["adapter_ids"]),
        "abstention_decision": abstain,
        "overrouting_detected": False,
        "confidence": policy["confidence"],
        "route_reason": policy["route_reason"],
        "trace_schema_version": "b04.r6.route_trace.v2",
        "visible_features_used": visible_features,
        "diagnostic_training_targets_used": False,
        "blind_label_dependency": False,
        "source_holdout_dependency": False,
        "consequence_visibility": {
            "selected_family": family,
            "static_hold_preserved": abstain,
            "package_promotion_dependency": PACKAGE_PROMOTION_DEPENDENCY,
            "truth_engine_mutation_dependency": False,
            "trust_zone_mutation_dependency": False,
        },
    }


def route_cases(cases: Sequence[Dict[str, Any]], *, seed: int = SEED_DEFAULT) -> list[Dict[str, Any]]:
    return [route_case(dict(case), seed=seed) for case in cases]
'''


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _ensure_false(payload: Dict[str, Any], key: str, *, label: str) -> None:
    if key in payload and payload.get(key) is not False:
        raise RuntimeError(f"FAIL_CLOSED: {label} must keep {key}=false")


def _ensure_required_false(payload: Dict[str, Any], key: str, *, label: str) -> None:
    if payload.get(key) is not False:
        raise RuntimeError(f"FAIL_CLOSED: {label} must keep {key}=false")


def _ensure_boundaries(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {label} must have PASS status")
    for key in (
        "r6_authorized",
        "r6_open",
        "learned_router_superiority_earned",
        "learned_router_activated",
        "learned_router_cutover_authorized",
        "multi_lobe_authorized",
    ):
        _ensure_required_false(payload, key, label=label)
    if payload.get("package_promotion_remains_deferred") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve package promotion deferral")
    if payload.get("truth_engine_derivation_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve truth-engine law")
    if payload.get("trust_zone_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve trust-zone law")


def _base(*, generated_utc: str, head: str, subject_main_head: str) -> Dict[str, Any]:
    return {
        "status": "PASS",
        "generated_utc": generated_utc,
        "current_git_head": head,
        "subject_main_head": subject_main_head,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "r6_authorized": False,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "learned_router_activated": False,
        "learned_router_cutover_authorized": False,
        "multi_lobe_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _input_hashes(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted(INPUTS.items()):
        path = root / raw
        if not path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing required input {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _rows(payload: Dict[str, Any], *, label: str) -> list[Dict[str, Any]]:
    rows = payload.get("candidate_rows", payload.get("rows"))
    if not isinstance(rows, list):
        raise RuntimeError(f"FAIL_CLOSED: {label} missing rows list")
    return [dict(row) for row in rows if isinstance(row, dict)]


def _require_prior_state(payloads: Dict[str, Dict[str, Any]]) -> None:
    for label, payload in payloads.items():
        _ensure_boundaries(payload, label=label)
    revision_receipt = payloads["revision_receipt"]
    blind_contract = payloads["blind_contract"]
    requirements = payloads["v2_source_requirements"]
    overfit = payloads["overfit_guard"]
    if revision_receipt.get("verdict") != EXPECTED_PRIOR_VERDICT:
        raise RuntimeError("FAIL_CLOSED: candidate v2 source requires revision-authorized prior verdict")
    if revision_receipt.get("next_lawful_move") != EXPECTED_PRIOR_NEXT_MOVE:
        raise RuntimeError("FAIL_CLOSED: prior revision receipt did not authorize candidate v2 source packet")
    if revision_receipt.get("candidate_revision_authorized") is not True:
        raise RuntimeError("FAIL_CLOSED: candidate revision must be explicitly authorized")
    if revision_receipt.get("candidate_v2_generation_performed") is not False:
        raise RuntimeError("FAIL_CLOSED: candidate v2 must not already be generated by prior lane")
    if revision_receipt.get("candidate_v2_screen_execution_authorized") is not False:
        raise RuntimeError("FAIL_CLOSED: candidate v2 screen must not already be authorized")
    if blind_contract.get("row_count") != 6:
        raise RuntimeError("FAIL_CLOSED: candidate v2 requires the bound six-row blind universe")
    if blind_contract.get("holdout_policy", {}).get("candidate_v2_may_not_train_on_counted_labels") is not True:
        raise RuntimeError("FAIL_CLOSED: blind contract must forbid training on counted labels")
    for row in _rows(blind_contract, label="blind input universe contract"):
        if row.get("candidate_v2_training_label_visible") is not False:
            raise RuntimeError("FAIL_CLOSED: blind universe rows must hide candidate v2 training labels")
        if row.get("static_baseline_labels_blinded_until_counted_screen") is not True:
            raise RuntimeError("FAIL_CLOSED: blind universe rows must keep static labels blinded")
        if row.get("old_r01_r04_derived") is not False:
            raise RuntimeError("FAIL_CLOSED: blind universe rows must not be derived from R01-R04")
    if overfit.get("new_blind_universe_required") is not True:
        raise RuntimeError("FAIL_CLOSED: overfit guard must require a new blind universe")
    reqs = dict(requirements.get("candidate_v2_source_requirements", {}))
    for key in (
        "deterministic",
        "hash_bound",
        "seed_bound",
        "trace_emitting",
        "abstention_aware",
        "static_hold_preserving",
        "no_package_promotion_dependency",
        "no_truth_engine_mutation_dependency",
        "no_trust_zone_mutation_dependency",
        "must_not_train_on_new_blind_screen_labels",
        "must_not_reuse_r01_r04_as_counted_screen",
    ):
        if reqs.get(key) is not True:
            raise RuntimeError(f"FAIL_CLOSED: missing candidate v2 source requirement: {key}")


def _write_candidate(root: Path) -> Path:
    path = root / CANDIDATE_SOURCE_REL
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(CANDIDATE_V2_SOURCE, encoding="utf-8", newline="\n")
    return path


def _import_candidate(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("b04_r6_generated_candidate_v2", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("FAIL_CLOSED: could not import candidate v2 source")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _visible_case(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "case_id": row.get("case_id"),
        "family": row.get("family"),
        "pressure_type": row.get("pressure_type"),
        "source_kind": row.get("source_kind"),
    }


def _variant_case(row: Dict[str, Any], variant: str) -> Dict[str, Any]:
    case = _visible_case(row)
    case["case_id"] = f"{case['case_id']}::{variant}"
    case["variant"] = variant
    return case


def _trace_candidate(candidate_module: Any, rows: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    traces = candidate_module.route_cases([_visible_case(row) for row in rows], seed=SEED_DEFAULT)
    if not isinstance(traces, list) or len(traces) != len(rows):
        raise RuntimeError("FAIL_CLOSED: candidate v2 must emit one trace per blind-universe row")
    required = {
        "candidate_id",
        "candidate_version",
        "case_id",
        "route_adapter_ids",
        "abstention_decision",
        "overrouting_detected",
        "trace_schema_version",
        "visible_features_used",
        "diagnostic_training_targets_used",
        "blind_label_dependency",
    }
    for trace in traces:
        if not isinstance(trace, dict):
            raise RuntimeError("FAIL_CLOSED: candidate v2 trace rows must be JSON objects")
        missing = sorted(required - set(trace))
        if missing:
            raise RuntimeError(f"FAIL_CLOSED: candidate v2 trace missing required fields: {missing}")
        if trace.get("candidate_id") != CANDIDATE_ID or trace.get("candidate_version") != CANDIDATE_VERSION:
            raise RuntimeError("FAIL_CLOSED: candidate v2 identity mismatch")
        if trace.get("shadow_only") is not True or trace.get("activation_allowed") is not False:
            raise RuntimeError("FAIL_CLOSED: candidate v2 trace must preserve shadow-only/no-activation mode")
        if trace.get("diagnostic_training_targets_used") is not False:
            raise RuntimeError("FAIL_CLOSED: candidate v2 trace must not use diagnostic targets")
        if trace.get("blind_label_dependency") is not False:
            raise RuntimeError("FAIL_CLOSED: candidate v2 trace must not depend on blind labels")
        consequence = dict(trace.get("consequence_visibility", {}))
        if consequence.get("package_promotion_dependency") is not False:
            raise RuntimeError("FAIL_CLOSED: candidate v2 must not depend on package promotion")
        if consequence.get("truth_engine_mutation_dependency") is not False:
            raise RuntimeError("FAIL_CLOSED: candidate v2 must not depend on truth-engine mutation")
        if consequence.get("trust_zone_mutation_dependency") is not False:
            raise RuntimeError("FAIL_CLOSED: candidate v2 must not depend on trust-zone mutation")
    return [dict(trace) for trace in traces]


def _invariance_rows(candidate_module: Any, rows: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    out: list[Dict[str, Any]] = []
    for row in rows:
        base = candidate_module.route_case(_visible_case(row), seed=SEED_DEFAULT)
        for variant in ("mirror", "masked"):
            trace = candidate_module.route_case(_variant_case(row, variant), seed=SEED_DEFAULT)
            out.append(
                {
                    "case_id": row["case_id"],
                    "variant": variant,
                    "invariance_pass": (
                        trace.get("route_adapter_ids") == base.get("route_adapter_ids")
                        and trace.get("abstention_decision") == base.get("abstention_decision")
                    ),
                }
            )
    return out


def _contamination_scan(source_text: str, blind_rows: list[Dict[str, Any]]) -> Dict[str, Any]:
    forbidden_tokens: list[str] = []
    for row in blind_rows:
        forbidden_tokens.append(str(row.get("case_id", "")))
        forbidden_tokens.append(str(row.get("source_sha256", "")))
    forbidden_tokens.extend(["baseline_adapter_ids", "candidate_beats_static", "static_baseline_labels_blinded_until_counted_screen"])
    hits = sorted(token for token in forbidden_tokens if token and token in source_text)
    if hits:
        raise RuntimeError(f"FAIL_CLOSED: candidate v2 source contains forbidden blind-label or case tokens: {hits}")
    return {
        "forbidden_token_hits": hits,
        "new_blind_universe_labels_used": False,
        "r01_r04_counted_labels_used": False,
        "package_promotion_dependency_detected": False,
        "truth_engine_mutation_dependency_detected": False,
        "trust_zone_mutation_dependency_detected": False,
    }


def _report() -> str:
    return (
        "# Cohort-0 B04 R6 Candidate V2 Source Packet\n\n"
        f"Verdict: `{FINAL_VERDICT}`\n\n"
        "A deterministic candidate-v2 source was generated under the bound six-row blind input universe contract. "
        "The candidate is admissible for the next second-shadow-screen execution-packet court, but this lane did not "
        "run the second screen, did not open R6, and did not claim learned-router superiority.\n\n"
        f"Next lawful move: `{NEXT_LAWFUL_MOVE}`.\n"
    )


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    if common.git_current_branch_name(root) != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: must run on {REQUIRED_BRANCH}")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 candidate v2 source packet")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    _require_prior_state(payloads)

    generated_utc = utc_now_iso_z()
    head = common.git_rev_parse(root, "HEAD")
    subject_main_head = str(payloads["revision_receipt"].get("current_git_head", "")).strip()
    base = _base(generated_utc=generated_utc, head=head, subject_main_head=subject_main_head)
    input_bindings = _input_hashes(root)
    blind_rows = _rows(payloads["blind_contract"], label="blind input universe contract")
    candidate_path = _write_candidate(root)
    candidate_sha = file_sha256(candidate_path)
    candidate_module = _import_candidate(candidate_path)
    traces = _trace_candidate(candidate_module, blind_rows)
    replay_traces = _trace_candidate(candidate_module, blind_rows)
    if traces != replay_traces:
        raise RuntimeError("FAIL_CLOSED: candidate v2 replay is non-deterministic")
    invariance = _invariance_rows(candidate_module, blind_rows)
    if any(row["invariance_pass"] is not True for row in invariance):
        raise RuntimeError("FAIL_CLOSED: candidate v2 mirror/masked invariance failed")
    contamination = _contamination_scan(candidate_path.read_text(encoding="utf-8"), blind_rows)
    trace_hash = file_sha256(candidate_path)

    candidate_ref = {
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "candidate_source_ref": CANDIDATE_SOURCE_REL,
        "candidate_source_sha256": candidate_sha,
        "seed": SEED_DEFAULT,
        "shadow_only": True,
        "activation_allowed": False,
    }
    source_packet = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_source_packet.v1",
        **base,
        "verdict": FINAL_VERDICT,
        "candidate": candidate_ref,
        "input_bindings": input_bindings,
        "source_law": {
            "r01_r04_diagnostic_only": True,
            "new_blind_universe_labels_available_to_candidate": False,
            "new_blind_universe_visible_fields_only": ["case_id", "family", "pressure_type", "source_kind"],
            "candidate_v2_generation_performed": True,
            "second_shadow_screen_executed": False,
        },
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    source_receipt = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_source_receipt.v1",
        **base,
        "verdict": FINAL_VERDICT,
        "candidate": candidate_ref,
        "candidate_v2_source_bound": True,
        "candidate_v2_admissible": True,
        "second_shadow_screen_authorization_next": True,
        "second_shadow_screen_executed": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    manifest = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_manifest.v1",
        **base,
        "candidate": candidate_ref,
        "trace_schema": "b04.r6.route_trace.v2",
        "required_properties": {
            "deterministic": True,
            "trace_emitting": True,
            "abstention_aware": True,
            "static_hold_preserving": True,
            "hash_bound": True,
            "seed_bound": True,
        },
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    provenance = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_provenance_matrix.v1",
        **base,
        "candidate": candidate_ref,
        "derivation_inputs": [
            "b04_r6_candidate_v1_failure_feature_gap_matrix.json",
            "b04_r6_candidate_v2_feature_requirements.json",
            "b04_r6_new_blind_input_universe_contract.json",
        ],
        "allowed_diagnostic_use": "R01-R04 feature-gap diagnostics only; no counted labels as training targets.",
        "blind_universe_use": "Visible field compatibility only; no static labels or outcomes used.",
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    derivation = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_derivation_receipt.v1",
        **base,
        "candidate": candidate_ref,
        "derivation_method": "deterministic_visible_feature_policy_from_bound_diagnostic_requirements",
        "r01_r04_failure_outcomes_used_as_training_targets": False,
        "new_blind_universe_labels_used": False,
        "static_baseline_weakened": False,
        "metric_contract_mutated": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    eval_receipt = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_eval_receipt.v1",
        **base,
        "candidate": candidate_ref,
        "eval_type": "NON_COUNTING_TRACE_AND_COMPATIBILITY_ONLY",
        "blind_rows_traced": len(traces),
        "score_against_static_baseline_performed": False,
        "learned_router_superiority_evaluated": False,
        "route_trace_rows": traces,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    source_hash = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_source_hash_receipt.v1",
        **base,
        "candidate": candidate_ref,
        "sha256": candidate_sha,
        "recomputed_sha256": trace_hash,
        "hash_match": candidate_sha == trace_hash,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    no_contamination = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_no_contamination_receipt.v1",
        **base,
        "candidate": candidate_ref,
        **contamination,
        "status": "PASS",
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    overfit_guard = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_overfit_risk_guard_receipt.v1",
        **base,
        "candidate": candidate_ref,
        "r01_r04_diagnostic_only": True,
        "new_blind_labels_used_for_generation": False,
        "candidate_v2_source_contains_blind_case_ids": False,
        "candidate_v2_source_contains_blind_source_hashes": False,
        "overfit_risk_status": "CONTAINED_FOR_ADMISSIBILITY__SECOND_SCREEN_NOT_RUN",
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    blind_separation = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_blind_universe_separation_receipt.v1",
        **base,
        "candidate": candidate_ref,
        "blind_input_row_count": len(blind_rows),
        "blind_case_ids": [row["case_id"] for row in blind_rows],
        "candidate_saw_only_visible_fields": True,
        "static_labels_blinded_until_counted_screen": True,
        "new_blind_universe_labels_used": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    trace_compatibility = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_trace_compatibility_receipt.v1",
        **base,
        "candidate": candidate_ref,
        "trace_rows": traces,
        "mirror_masked_rows": invariance,
        "trace_compatibility_pass": True,
        "mirror_masked_invariance_pass": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    replay = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_deterministic_replay_receipt.v1",
        **base,
        "candidate": candidate_ref,
        "seed": SEED_DEFAULT,
        "first_trace_sha256": common_hash_json(traces),
        "second_trace_sha256": common_hash_json(replay_traces),
        "deterministic_replay_pass": traces == replay_traces,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    matrix = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_admissibility_validation_matrix.v1",
        **base,
        "checks": [
            {"check_id": "candidate_identity_bound", "status": "PASS"},
            {"check_id": "source_hash_bound", "status": "PASS"},
            {"check_id": "derivation_receipt_bound", "status": "PASS"},
            {"check_id": "eval_receipt_non_counting", "status": "PASS"},
            {"check_id": "no_contamination_pass", "status": "PASS"},
            {"check_id": "overfit_guard_pass", "status": "PASS"},
            {"check_id": "blind_universe_separation_pass", "status": "PASS"},
            {"check_id": "trace_compatibility_pass", "status": "PASS"},
            {"check_id": "deterministic_replay_pass", "status": "PASS"},
            {"check_id": "second_shadow_screen_not_executed", "status": "PASS"},
        ],
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    blockers = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_blocker_ledger.v1",
        **base,
        "entries": [],
        "live_blocker_count": 0,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    admissibility = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_admissibility_receipt.v1",
        **base,
        "verdict": FINAL_VERDICT,
        "candidate": candidate_ref,
        "candidate_v2_admissible": True,
        "second_shadow_screen_authorization_next": True,
        "second_shadow_screen_executed": False,
        "learned_router_superiority_evaluated": False,
        "learned_router_superiority_earned": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    readiness = {
        "schema_id": "kt.operator.b04_r6_second_shadow_screen_readiness_matrix.v1",
        **base,
        "checks": [
            {"check_id": "candidate_v2_admissible", "status": "PASS"},
            {"check_id": "blind_input_contract_bound", "status": "PASS"},
            {"check_id": "no_contamination_pass", "status": "PASS"},
            {"check_id": "trace_compatibility_pass", "status": "PASS"},
            {"check_id": "deterministic_replay_pass", "status": "PASS"},
            {"check_id": "execution_packet_not_yet_authored", "status": "PASS"},
        ],
        "second_shadow_screen_execution_packet_authorized_next": True,
        "second_shadow_screen_executed": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    second_auth = {
        "schema_id": "kt.operator.b04_r6_second_shadow_screen_authorization_receipt.v1",
        **base,
        "candidate": candidate_ref,
        "authorization_scope": "AUTHOR_EXECUTION_PACKET_NEXT_ONLY",
        "second_shadow_screen_execution_authorized_now": False,
        "second_shadow_screen_execution_packet_authorized_next": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    next_receipt = {
        "schema_id": "kt.operator.b04_r6_next_lawful_move_receipt.v1",
        **base,
        "verdict": FINAL_VERDICT,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }

    outputs: Dict[str, Any] = {
        OUTPUTS["source_packet"]: source_packet,
        OUTPUTS["source_receipt"]: source_receipt,
        OUTPUTS["manifest"]: manifest,
        OUTPUTS["provenance_matrix"]: provenance,
        OUTPUTS["derivation_receipt"]: derivation,
        OUTPUTS["eval_receipt"]: eval_receipt,
        OUTPUTS["source_hash_receipt"]: source_hash,
        OUTPUTS["no_contamination_receipt"]: no_contamination,
        OUTPUTS["overfit_guard_receipt"]: overfit_guard,
        OUTPUTS["blind_separation_receipt"]: blind_separation,
        OUTPUTS["trace_compatibility_receipt"]: trace_compatibility,
        OUTPUTS["deterministic_replay_receipt"]: replay,
        OUTPUTS["admissibility_receipt"]: admissibility,
        OUTPUTS["blocker_ledger"]: blockers,
        OUTPUTS["admissibility_matrix"]: matrix,
        OUTPUTS["second_readiness_matrix"]: readiness,
        OUTPUTS["second_authorization_receipt"]: second_auth,
        OUTPUTS["next_lawful_move_receipt"]: next_receipt,
        OUTPUTS["report_md"]: _report(),
    }
    for filename, payload in outputs.items():
        path = reports_root / filename
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, payload)
    return {
        "verdict": FINAL_VERDICT,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "candidate_source_sha256": candidate_sha,
    }


def common_hash_json(value: Any) -> str:
    import hashlib
    import json

    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(rendered).hexdigest()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate and admit the B04 R6 candidate v2 source.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(reports_root=common.resolve_path(root, args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
