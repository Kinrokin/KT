from __future__ import annotations

from typing import Any, Dict, Sequence


CANDIDATE_ID = "b04_r6_minimal_deterministic_shadow_router_v1"
CANDIDATE_VERSION = "1.0.0"
SEED_DEFAULT = 42
SHADOW_ONLY = True
ACTIVATION_ALLOWED = False
PACKAGE_PROMOTION_DEPENDENCY = False

ROUTE_TABLE = {'default': {'abstain': True, 'adapter_ids': ['lobe.strategist.v1'], 'confidence': 0.0},
 'governance': {'abstain': False, 'adapter_ids': ['lobe.censor.v1', 'lobe.auditor.v1'], 'confidence': 1.0},
 'math': {'abstain': False, 'adapter_ids': ['lobe.censor.v1', 'lobe.quant.v1'], 'confidence': 1.0},
 'poetry': {'abstain': False, 'adapter_ids': ['lobe.muse.v1'], 'confidence': 1.0}}


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
    return {
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
        "consequence_visibility": {
            "selected_family": family,
            "static_hold_preserved": abstain,
            "package_promotion_dependency": PACKAGE_PROMOTION_DEPENDENCY,
        },
    }


def route_cases(cases: Sequence[Dict[str, Any]], *, seed: int = SEED_DEFAULT) -> list[Dict[str, Any]]:
    return [route_case(dict(case), seed=seed) for case in cases]
