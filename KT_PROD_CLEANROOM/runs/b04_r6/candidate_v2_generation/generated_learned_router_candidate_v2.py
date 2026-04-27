from __future__ import annotations

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
