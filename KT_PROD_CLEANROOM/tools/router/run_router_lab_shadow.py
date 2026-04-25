from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


DEFAULT_POLICY_REL = "KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/ROUTER_LAB/ROUTER_SEQUENCE_LAB_POLICY_V1.json"
DEFAULT_SUITE_REL = "KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/ROUTER_LAB/ROUTER_SEQUENCE_LAB_SUITE_V1.json"
DEFAULT_ADAPTER_REGISTRY_REL = "KT_PROD_CLEANROOM/reports/kt_adapter_registry.json"


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _load_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: expected JSON object for {name}: {path.as_posix()}")
    return payload


def _tokenize(text: str) -> List[str]:
    return [token for token in re.split(r"[^a-z0-9]+", str(text).lower()) if token]


def _ordered_unique(items: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    ordered: List[str] = []
    for item in items:
        key = str(item).strip()
        if not key or key in seen:
            continue
        seen.add(key)
        ordered.append(key)
    return ordered


def _known_adapter_ids(registry: Dict[str, Any]) -> set[str]:
    adapters = registry.get("adapters", [])
    if not isinstance(adapters, list):
        raise RuntimeError("FAIL_CLOSED: adapter registry adapters list missing")
    known = {
        str(row.get("adapter_id", "")).strip()
        for row in adapters
        if isinstance(row, dict) and str(row.get("adapter_id", "")).strip()
    }
    if not known:
        raise RuntimeError("FAIL_CLOSED: adapter registry contained no adapter ids")
    return known


def _role_route_map(policy: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    routes = policy.get("role_routes", [])
    if not isinstance(routes, list) or not routes:
        raise RuntimeError("FAIL_CLOSED: lab router policy role_routes missing")
    mapped: Dict[str, Dict[str, Any]] = {}
    for row in routes:
        if not isinstance(row, dict):
            continue
        role_id = str(row.get("role_id", "")).strip()
        if role_id:
            mapped[role_id] = row
    if not mapped:
        raise RuntimeError("FAIL_CLOSED: no valid lab role routes defined")
    return mapped


def _required_roles_for_case(case: Dict[str, Any], role_map: Dict[str, Dict[str, Any]]) -> List[str]:
    explicit_roles = case.get("required_roles", [])
    if isinstance(explicit_roles, list) and explicit_roles:
        return _ordered_unique(str(item).strip() for item in explicit_roles)

    text = str(case.get("input_text", "")).strip()
    tokens = set(_tokenize(text))
    discovered: List[str] = []
    lowered = text.lower()
    for role_id, row in role_map.items():
        keywords = row.get("keywords", [])
        if not isinstance(keywords, list):
            continue
        keyword_tokens = set()
        substring_hit = False
        for keyword in keywords:
            kw = str(keyword).strip().lower()
            if not kw:
                continue
            if kw in lowered:
                substring_hit = True
            keyword_tokens.update(_tokenize(kw))
        if substring_hit or tokens.intersection(keyword_tokens):
            discovered.append(role_id)
    return _ordered_unique(discovered)


def _validate_policy_refs(*, policy: Dict[str, Any], known_adapters: set[str]) -> None:
    missing: List[str] = []
    for row in policy.get("role_routes", []):
        if not isinstance(row, dict):
            continue
        for adapter_id in list(row.get("adapter_ids", [])) + list(row.get("required_adapter_ids", [])):
            adapter = str(adapter_id).strip()
            if adapter and adapter not in known_adapters:
                missing.append(adapter)
    for adapter_id in list(policy.get("default_adapter_ids", [])) + list(policy.get("single_adapter_baselines", [])):
        adapter = str(adapter_id).strip()
        if adapter and adapter not in known_adapters:
            missing.append(adapter)
    if missing:
        raise RuntimeError(f"FAIL_CLOSED: policy references unknown adapters: {sorted(set(missing))}")


def _score_adapter_roles(*, adapter_id: str, required_roles: Sequence[str], capability_weights: Dict[str, Dict[str, float]]) -> float:
    weights = capability_weights.get(adapter_id, {})
    return round(sum(float(weights.get(role, 0.0)) for role in required_roles), 6)


def _score_sequence(*, adapter_ids: Sequence[str], required_roles: Sequence[str], capability_weights: Dict[str, Dict[str, float]]) -> float:
    total = 0.0
    for role in required_roles:
        total += max(float(capability_weights.get(adapter_id, {}).get(role, 0.0)) for adapter_id in adapter_ids)
    return round(total, 6)


def _select_route_for_case(
    *,
    case: Dict[str, Any],
    policy: Dict[str, Any],
    role_map: Dict[str, Dict[str, Any]],
    known_adapters: set[str],
) -> Dict[str, Any]:
    required_roles = _required_roles_for_case(case, role_map)
    selected_adapter_ids: List[str] = []
    role_assignments: List[Dict[str, Any]] = []

    for role_id in required_roles:
        row = role_map.get(role_id)
        if row is None:
            raise RuntimeError(f"FAIL_CLOSED: required role missing from policy: {role_id}")
        adapter_ids = _ordered_unique(
            list(row.get("adapter_ids", [])) + list(row.get("required_adapter_ids", []))
        )
        for adapter_id in adapter_ids:
            if adapter_id not in known_adapters:
                raise RuntimeError(f"FAIL_CLOSED: role route selected unknown adapter {adapter_id}")
        selected_adapter_ids.extend(adapter_ids)
        role_assignments.append(
            {
                "adapter_ids": adapter_ids,
                "keywords": list(row.get("keywords", [])),
                "role_id": role_id,
            }
        )

    selected_adapter_ids = _ordered_unique(selected_adapter_ids)
    fallback_engaged = False
    if not selected_adapter_ids:
        fallback_engaged = True
        selected_adapter_ids = _ordered_unique(str(item).strip() for item in policy.get("default_adapter_ids", []))
        if not selected_adapter_ids:
            raise RuntimeError("FAIL_CLOSED: lab router policy default adapter ids empty")
        role_assignments.append(
            {
                "adapter_ids": selected_adapter_ids,
                "keywords": [],
                "role_id": "default",
            }
        )

    return {
        "fallback_engaged": fallback_engaged,
        "required_roles": required_roles,
        "role_assignments": role_assignments,
        "selected_adapter_ids": selected_adapter_ids,
    }


def build_router_lab_shadow_report(
    *,
    root: Path,
    policy: Dict[str, Any],
    suite: Dict[str, Any],
    adapter_registry: Dict[str, Any],
) -> Dict[str, Any]:
    role_map = _role_route_map(policy)
    known_adapters = _known_adapter_ids(adapter_registry)
    _validate_policy_refs(policy=policy, known_adapters=known_adapters)

    capability_weights = {
        str(adapter_id).strip(): {
            str(role_id).strip(): float(weight)
            for role_id, weight in weights.items()
        }
        for adapter_id, weights in policy.get("capability_weights", {}).items()
        if str(adapter_id).strip() and isinstance(weights, dict)
    }
    single_adapter_baselines = _ordered_unique(str(item).strip() for item in policy.get("single_adapter_baselines", []))
    if not single_adapter_baselines:
        raise RuntimeError("FAIL_CLOSED: no single-adapter baselines configured for lab router shadow")

    cases = suite.get("cases", [])
    if not isinstance(cases, list) or not cases:
        raise RuntimeError("FAIL_CLOSED: lab router suite cases missing")

    case_rows: List[Dict[str, Any]] = []
    opportunity_case_count = 0
    for case in cases:
        if not isinstance(case, dict):
            continue
        case_id = str(case.get("case_id", "")).strip()
        if not case_id:
            raise RuntimeError("FAIL_CLOSED: lab router suite case missing case_id")

        routed = _select_route_for_case(
            case=case,
            policy=policy,
            role_map=role_map,
            known_adapters=known_adapters,
        )
        required_roles = list(routed["required_roles"])
        routed_adapter_ids = list(routed["selected_adapter_ids"])
        routed_score = _score_sequence(
            adapter_ids=routed_adapter_ids,
            required_roles=required_roles,
            capability_weights=capability_weights,
        )

        baseline_rows = []
        best_single_adapter_id = ""
        best_single_score = -1.0
        for adapter_id in single_adapter_baselines:
            score = _score_adapter_roles(
                adapter_id=adapter_id,
                required_roles=required_roles,
                capability_weights=capability_weights,
            )
            baseline_rows.append(
                {
                    "adapter_id": adapter_id,
                    "score": score,
                }
            )
            if score > best_single_score:
                best_single_score = score
                best_single_adapter_id = adapter_id

        opportunity_delta = round(routed_score - max(best_single_score, 0.0), 6)
        specialist_route_advantage = opportunity_delta > 0.0 and len(set(routed_adapter_ids)) > 1
        if specialist_route_advantage:
            opportunity_case_count += 1

        case_rows.append(
            {
                "best_single_adapter_id": best_single_adapter_id,
                "best_single_score": max(best_single_score, 0.0),
                "case_id": case_id,
                "fallback_engaged": bool(routed["fallback_engaged"]),
                "notes": str(case.get("notes", "")).strip(),
                "opportunity_delta": opportunity_delta,
                "required_roles": required_roles,
                "routed_adapter_ids": routed_adapter_ids,
                "routed_score": routed_score,
                "role_assignments": list(routed["role_assignments"]),
                "single_adapter_scores": baseline_rows,
                "specialist_route_advantage": specialist_route_advantage,
            }
        )

    return {
        "schema_id": "kt.router_lab_shadow_report.v1",
        "generated_utc": utc_now_iso_z(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "policy_ref": DEFAULT_POLICY_REL,
        "suite_ref": DEFAULT_SUITE_REL,
        "adapter_registry_ref": DEFAULT_ADAPTER_REGISTRY_REL,
        "status": "PASS",
        "claim_boundary": "This report measures lab-only routing opportunity, not counted router superiority. It cannot unlock R6, lobe authority, externality, comparative claims, or commercial activation.",
        "summary": {
            "case_count": len(case_rows),
            "fallback_case_count": sum(1 for row in case_rows if bool(row.get("fallback_engaged"))),
            "opportunity_case_count": opportunity_case_count,
            "router_advantage_visible": opportunity_case_count > 0,
        },
        "case_rows": case_rows,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a noncanonical lab-only router shadow opportunity evaluation on mixed-role tasks.")
    parser.add_argument("--policy", default=DEFAULT_POLICY_REL)
    parser.add_argument("--suite", default=DEFAULT_SUITE_REL)
    parser.add_argument("--adapter-registry", default=DEFAULT_ADAPTER_REGISTRY_REL)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    policy = _load_json_dict(_resolve(root, str(args.policy)), name="router_lab_policy")
    suite = _load_json_dict(_resolve(root, str(args.suite)), name="router_lab_suite")
    adapter_registry = _load_json_dict(_resolve(root, str(args.adapter_registry)), name="adapter_registry")

    report = build_router_lab_shadow_report(
        root=root,
        policy=policy,
        suite=suite,
        adapter_registry=adapter_registry,
    )
    output_path = _resolve(root, str(args.output))
    write_json_stable(output_path, report)
    summary = {
        "opportunity_case_count": report["summary"]["opportunity_case_count"],
        "router_advantage_visible": report["summary"]["router_advantage_visible"],
        "status": report["status"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
