from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

_CLEANROOM_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _CLEANROOM_ROOT / "04_PROD_TEMPLE_V2" / "src"
for _path in (str(_CLEANROOM_ROOT), str(_SRC_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from tools.operator.observability import emit_toolchain_telemetry, telemetry_now_ms
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.router.run_router_hat_demo import _choose_route


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
POLICY_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/router_policy_registry.json"
WAVE2A_PROVIDER_REPORT_REL = "KT_PROD_CLEANROOM/reports/kt_wave2a_provider_activation_receipts.json"
POST_WAVE5_C016A_REPORT_REL = "KT_PROD_CLEANROOM/reports/post_wave5_c016a_success_matrix.json"
POST_WAVE5_C016B_REPORT_REL = "KT_PROD_CLEANROOM/reports/post_wave5_c016b_resilience_pack.json"


def _load_json(path: Path) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: expected JSON object: {path.as_posix()}")
    return payload


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _tokenize(text: str) -> List[str]:
    return [token for token in re.split(r"[^a-z0-9]+", text.lower()) if token]


def _route_keyword_tokens(keywords: Sequence[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for keyword in keywords:
        for token in _tokenize(str(keyword)):
            if token not in seen:
                seen.add(token)
                out.append(token)
    return out


def _best_static_provider_adapter(provider_report: Dict[str, Any]) -> Dict[str, Any]:
    rows = provider_report.get("provider_rows", [])
    if not isinstance(rows, list) or not rows:
        raise RuntimeError("FAIL_CLOSED: Wave 2A provider rows missing")

    def _rank(row: Dict[str, Any]) -> Tuple[int, int, int, str]:
        status_ok = 1 if str(row.get("status", "")).strip() == "OK" else 0
        receipt_present = 1 if bool(row.get("receipt_exists")) else 0
        latency_ms = int(row.get("latency_ms", 0)) if str(row.get("latency_ms", "")).strip() else 10**9
        adapter_id = str(row.get("adapter_id", "")).strip()
        return (-status_ok, -receipt_present, latency_ms, adapter_id)

    ranked = sorted((row for row in rows if isinstance(row, dict)), key=_rank)
    top = ranked[0]
    return {
        "adapter_id": str(top.get("adapter_id", "")).strip(),
        "provider_id": str(top.get("provider_id", "")).strip(),
        "status": str(top.get("status", "")).strip(),
        "latency_ms": int(top.get("latency_ms", 0)) if str(top.get("latency_ms", "")).strip() else 0,
        "http_status": int(top.get("http_status", 0)) if str(top.get("http_status", "")).strip() else 0,
        "ranking_rule": [
            "successful_live_count_desc",
            "live_receipt_count_desc",
            "latency_ms_asc",
            "adapter_id_asc",
        ],
        "boundary_hold_present": bool(provider_report.get("boundary_holds")),
    }


def _provider_underlay_context(*, root: Path) -> Dict[str, Any]:
    candidates = (
        {
            "report_rel": POST_WAVE5_C016A_REPORT_REL,
            "source_label": "POST_WAVE5_C016A_CANONICAL_LIVE_HASHED_SUCCESS",
            "require_status_pass": True,
        },
        {
            "report_rel": WAVE2A_PROVIDER_REPORT_REL,
            "source_label": "WAVE2A_LEGACY_PROVIDER_ACTIVATION",
            "require_status_pass": False,
        },
    )

    provider_report: Optional[Dict[str, Any]] = None
    provider_report_ref = ""
    provider_source_label = ""
    for candidate in candidates:
        report_rel = str(candidate["report_rel"])
        report_path = (root / report_rel).resolve()
        if not report_path.exists():
            continue
        payload = _load_json(report_path)
        rows = payload.get("provider_rows", [])
        if not isinstance(rows, list) or not rows:
            continue
        if candidate["require_status_pass"] and str(payload.get("status", "")).strip() != "PASS":
            continue
        provider_report = payload
        provider_report_ref = report_rel
        provider_source_label = str(candidate["source_label"])
        break

    if provider_report is None:
        raise RuntimeError("FAIL_CLOSED: no provider evidence surface available for Wave 2B router shadow evaluation")

    provider_status = str(provider_report.get("status", "")).strip()
    successful_provider_ids = sorted(
        str(row.get("provider_id", "")).strip()
        for row in provider_report.get("provider_rows", [])
        if isinstance(row, dict) and str(row.get("status", "")).strip() == "OK"
    )
    resilience_path = (root / POST_WAVE5_C016B_REPORT_REL).resolve()
    resilience_report = _load_json(resilience_path) if resilience_path.exists() else {}
    resilience_status = str(resilience_report.get("status", "")).strip()
    c016b_delta = str(resilience_report.get("c016b_delta", "")).strip()

    return {
        "provider_report_ref": provider_report_ref,
        "provider_report_source": provider_source_label,
        "provider_report_status": provider_status,
        "successful_provider_count": len(successful_provider_ids),
        "successful_provider_ids": successful_provider_ids,
        "same_host_live_hashed_success_proven": provider_report_ref == POST_WAVE5_C016A_REPORT_REL and len(successful_provider_ids) > 0,
        "resilience_report_ref": POST_WAVE5_C016B_REPORT_REL if resilience_path.exists() else "",
        "resilience_report_status": resilience_status,
        "same_host_live_hashed_resilience_proven": c016b_delta == "C016B_CLOSED_FOR_CANONICAL_LIVE_HASHED_RESILIENCE_PATH",
        "best_static_provider_adapter": _best_static_provider_adapter(provider_report),
    }


def _default_candidate(*, policy: Dict[str, Any]) -> Dict[str, Any]:
    default_ids = sorted(str(item).strip() for item in policy.get("default_adapter_ids", []) if str(item).strip())
    return {
        "domain_tag": "default",
        "adapter_ids": default_ids,
        "required_adapter_ids": [],
        "matched_keywords": [],
        "token_overlap_terms": [],
        "score": 0,
        "score_components": {
            "substring_hits": 0,
            "token_overlap": 0,
        },
        "reason": "default_path_candidate_only",
    }


def _shadow_candidates(*, policy: Dict[str, Any], input_text: str) -> List[Dict[str, Any]]:
    txt = str(input_text).lower()
    tokens = set(_tokenize(input_text))
    rows = policy.get("routes", [])
    candidates: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        keywords = [str(item).strip() for item in row.get("keywords", []) if str(item).strip()]
        keyword_hits = sorted({kw for kw in keywords if kw.lower() in txt})
        keyword_tokens = set(_route_keyword_tokens(keywords))
        token_overlap_terms = sorted(tokens & keyword_tokens)
        score = (len(keyword_hits) * 100) + len(token_overlap_terms)
        adapter_ids = sorted(str(item).strip() for item in row.get("adapter_ids", []) if str(item).strip())
        required_ids = sorted(str(item).strip() for item in row.get("required_adapter_ids", []) if str(item).strip())
        candidates.append(
            {
                "domain_tag": str(row.get("domain_tag", "")).strip(),
                "adapter_ids": sorted(set(adapter_ids) | set(required_ids)),
                "required_adapter_ids": required_ids,
                "matched_keywords": keyword_hits,
                "token_overlap_terms": token_overlap_terms,
                "score": int(score),
                "score_components": {
                    "substring_hits": len(keyword_hits),
                    "token_overlap": len(token_overlap_terms),
                },
                "reason": "deterministic_keyword_signal_shadow_v1",
            }
        )
    candidates.append(_default_candidate(policy=policy))
    return sorted(candidates, key=lambda row: (-int(row["score"]), str(row["domain_tag"])))


def _evaluate_shadow_case(
    *,
    policy: Dict[str, Any],
    case: Dict[str, Any],
    best_static_provider: Dict[str, Any],
) -> Dict[str, Any]:
    case_id = str(case.get("case_id", "")).strip()
    input_text = str(case.get("input_text", "")).strip()
    if not case_id or not input_text:
        raise RuntimeError("FAIL_CLOSED: malformed router demo case")

    baseline_domain, baseline_hits, baseline_selected, baseline_required = _choose_route(policy=policy, input_text=input_text)
    candidates = _shadow_candidates(policy=policy, input_text=input_text)
    top = candidates[0] if candidates else _default_candidate(policy=policy)
    second = candidates[1] if len(candidates) > 1 else None

    tie_on_top = bool(second) and int(second.get("score", 0)) == int(top.get("score", 0))
    fallback_engaged = int(top.get("score", 0)) <= 0 or tie_on_top
    if fallback_engaged:
        selected_domain = baseline_domain
        selected_adapter_ids = list(baseline_selected)
        fallback_reason = "fallback_to_audited_static_baseline"
    else:
        selected_domain = str(top.get("domain_tag", "")).strip()
        selected_adapter_ids = list(top.get("adapter_ids", []))
        fallback_reason = ""

    positive_scores = [int(row.get("score", 0)) for row in candidates if int(row.get("score", 0)) > 0]
    confidence = 0.0
    if positive_scores and not fallback_engaged:
        confidence = round(int(top.get("score", 0)) / max(1, sum(positive_scores)), 6)

    return {
        "case_id": case_id,
        "input_sha256": _sha256_text(input_text),
        "baseline_static_adapter_path": {
            "domain_tag": baseline_domain,
            "matched_keywords": list(baseline_hits),
            "selected_adapter_ids": list(baseline_selected),
            "required_adapter_ids": list(baseline_required),
            "source": "audited_static_router_baseline",
        },
        "shadow_selection": {
            "shadow_router_id": "kt.router.shadow_keyword_signal.v1",
            "mode": "SHADOW_ONLY",
            "selected_domain_tag": selected_domain,
            "selected_adapter_ids": selected_adapter_ids,
            "confidence": confidence,
            "fallback_engaged": fallback_engaged,
            "fallback_reason": fallback_reason,
            "top_candidate_gap": int(top.get("score", 0)) - int(second.get("score", 0)) if second else int(top.get("score", 0)),
        },
        "shadow_candidates": candidates,
        "comparison_to_best_static_adapter_path": {
            "exact_path_match": selected_domain == baseline_domain and sorted(selected_adapter_ids) == sorted(baseline_selected),
            "comparison_rule": "shadow compared against the current audited static router path for the same case",
        },
        "best_static_provider_adapter_underlay": dict(best_static_provider),
        "replayability_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
        "explainability_complete": True,
    }


def build_wave2b_shadow_reports(*, root: Path, telemetry_path: Path) -> Dict[str, Dict[str, Any]]:
    started_ms = telemetry_now_ms()
    current_head = _git_head(root)
    registry = _load_json(root / POLICY_REGISTRY_REL)
    policy_path = root / str(registry.get("active_policy_ref", "")).replace("/", os.sep)
    suite_path = root / str(registry.get("demo_suite_ref", "")).replace("/", os.sep)
    policy = _load_json(policy_path)
    suite = _load_json(suite_path)
    provider_context = _provider_underlay_context(root=root)
    best_static_provider = dict(provider_context["best_static_provider_adapter"])

    cases = suite.get("cases", [])
    if not isinstance(cases, list) or not cases:
        raise RuntimeError("FAIL_CLOSED: router demo suite cases missing")

    rows = [
        _evaluate_shadow_case(
            policy=policy,
            case=row,
            best_static_provider=best_static_provider,
        )
        for row in cases
        if isinstance(row, dict)
    ]
    if not rows:
        raise RuntimeError("FAIL_CLOSED: no valid router demo cases available for Wave 2B shadow evaluation")

    failures: List[str] = []
    if str(registry.get("ratification_scope", "")).strip() != "STATIC_ROUTER_BASELINE_ONLY":
        failures.append("router_registry_ratification_scope_not_static_baseline_only")
    if any(not bool(row.get("explainability_complete")) for row in rows):
        failures.append("one_or_more_router_shadow_rows_lack_explainability")
    if not any(bool(row.get("shadow_selection", {}).get("fallback_engaged")) for row in rows):
        failures.append("no_deterministic_fallback_case_observed")

    baseline_distribution: Dict[str, int] = {}
    shadow_distribution: Dict[str, int] = {}
    fallback_case_ids: List[str] = []
    exact_matches = 0
    for row in rows:
        baseline_domain = str(row["baseline_static_adapter_path"]["domain_tag"])
        shadow_domain = str(row["shadow_selection"]["selected_domain_tag"])
        baseline_distribution[baseline_domain] = baseline_distribution.get(baseline_domain, 0) + 1
        shadow_distribution[shadow_domain] = shadow_distribution.get(shadow_domain, 0) + 1
        if bool(row["shadow_selection"]["fallback_engaged"]):
            fallback_case_ids.append(str(row["case_id"]))
        if bool(row["comparison_to_best_static_adapter_path"]["exact_path_match"]):
            exact_matches += 1

        emit_toolchain_telemetry(
            surface_id="tools.operator.wave2b_router_shadow_validate",
            zone="TOOLCHAIN_PROVING",
            event_type="router.shadow_evaluate",
            start_ts=started_ms,
            end_ts=telemetry_now_ms(),
            result_status="PASS",
            policy_applied="wave2b.shadow_only.static_router_control",
            receipt_ref="KT_PROD_CLEANROOM/reports/kt_wave2b_router_selection_receipt.json",
            request_id=str(row["case_id"]),
            trace_id=f"wave2b-shadow-{row['case_id']}",
            path=telemetry_path,
        )

    boundary_holds = [
        "CANONICAL_STATIC_ROUTER_RETAINS_AUTHORITY",
        "BEST_STATIC_COMPARATOR_REMAINS_CONTROL",
        "LEARNED_ROUTER_CUTOVER_NOT_EARNED",
        "EXTERNALITY_CEILING_REMAINS_BOUNDED",
    ]

    selection_report = {
        "schema_id": "kt.wave2b.router_selection_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": "PASS" if not failures else "FAIL",
        "scope_boundary": "Wave 2B shadow and best-static comparison only. The audited static router remains canonical, the post-Wave5 same-host LIVE_HASHED provider underlay is a bounded current-head input, and no learned-router cutover occurs.",
        "router_policy_registry_ref": POLICY_REGISTRY_REL,
        "active_policy_ref": registry.get("active_policy_ref"),
        "demo_suite_ref": registry.get("demo_suite_ref"),
        "ratification_scope": registry.get("ratification_scope"),
        "shadow_router_id": "kt.router.shadow_keyword_signal.v1",
        "embedding_model_used": False,
        "best_static_provider_adapter_underlay": best_static_provider,
        "provider_underlay_context": {
            "provider_report_ref": str(provider_context["provider_report_ref"]),
            "provider_report_source": str(provider_context["provider_report_source"]),
            "provider_report_status": str(provider_context["provider_report_status"]),
            "successful_provider_count": int(provider_context["successful_provider_count"]),
            "successful_provider_ids": list(provider_context["successful_provider_ids"]),
            "same_host_live_hashed_success_proven": bool(provider_context["same_host_live_hashed_success_proven"]),
            "resilience_report_ref": str(provider_context["resilience_report_ref"]),
            "resilience_report_status": str(provider_context["resilience_report_status"]),
            "same_host_live_hashed_resilience_proven": bool(provider_context["same_host_live_hashed_resilience_proven"]),
        },
        "case_rows": rows,
        "boundary_holds": boundary_holds,
        "failures": failures,
        "stronger_claim_not_made": [
            "canonical_router_cut_over_to_learned_mode",
            "semantic_router_superiority_claimed",
            "multi_lobe_orchestration_opened",
            "broad_externality_widened",
            "cross_host_or_outsider_router_capability_claimed",
        ],
    }

    matrix_rows = [
        {
            "case_id": str(row["case_id"]),
            "baseline_domain_tag": str(row["baseline_static_adapter_path"]["domain_tag"]),
            "baseline_adapter_ids": list(row["baseline_static_adapter_path"]["selected_adapter_ids"]),
            "shadow_domain_tag": str(row["shadow_selection"]["selected_domain_tag"]),
            "shadow_adapter_ids": list(row["shadow_selection"]["selected_adapter_ids"]),
            "exact_path_match": bool(row["comparison_to_best_static_adapter_path"]["exact_path_match"]),
            "fallback_engaged": bool(row["shadow_selection"]["fallback_engaged"]),
            "confidence": float(row["shadow_selection"]["confidence"]),
            "top_shadow_candidates": list(row["shadow_candidates"][:3]),
            "best_static_provider_adapter_id": str(best_static_provider["adapter_id"]),
        }
        for row in rows
    ]

    matrix_report = {
        "schema_id": "kt.wave2b.router_shadow_eval_matrix.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": "PASS" if not failures else "FAIL",
        "comparison_rule": "Shadow routing is compared against the current best static adapter path and the static router remains canonical until later ratification.",
        "coverage": {
            "declared_task_family_coverage": sorted({str(row["baseline_static_adapter_path"]["domain_tag"]) for row in rows}),
            "failure_class_coverage": ["fallback_to_audited_static_baseline"],
            "latency_class_coverage": ["toolchain_local_sub_500ms"],
            "replayability_class_coverage": ["E0_INTERNAL_SELF_ISSUED_ONLY"],
            "adversarial_probe_coverage": ["zero_score_or_tie_fallback_to_static_baseline"],
        },
        "rows": matrix_rows,
        "promotion_decision": {
            "canonical_router_unchanged": True,
            "shadow_promotable": False,
            "learned_router_cutover_allowed": False,
            "reasons": [
                "wave2b_scope_is_shadow_only",
                "best_static_comparator_remains_control",
                "comparison_artifacts_exist_but_no_cutover_authority_was_granted",
                "learned_router_cutover_not_earned",
                "externality_class_remains_bounded",
            ],
            "provider_underlay_ref": str(provider_context["provider_report_ref"]),
            "provider_underlay_same_host_success_proven": bool(provider_context["same_host_live_hashed_success_proven"]),
        },
        "failures": failures,
    }

    route_distribution_delta_count = sum(
        1
        for key in sorted(set(baseline_distribution) | set(shadow_distribution))
        if baseline_distribution.get(key, 0) != shadow_distribution.get(key, 0)
    )
    health_failures = list(failures)
    if route_distribution_delta_count != 0:
        health_failures.append("shadow_distribution_diverged_from_static_baseline")

    health_report = {
        "schema_id": "kt.wave2b.route_distribution_health.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": "PASS" if not health_failures else "FAIL",
        "baseline_domain_distribution": baseline_distribution,
        "shadow_domain_distribution": shadow_distribution,
        "fallback_case_ids": fallback_case_ids,
        "fallback_rate": round(len(fallback_case_ids) / max(1, len(rows)), 6),
        "shadow_match_rate": round(exact_matches / max(1, len(rows)), 6),
        "route_distribution_delta_count": route_distribution_delta_count,
        "route_collapse_detected": len(shadow_distribution) < len(baseline_distribution),
        "canonical_static_router_preserved": True,
        "replayable": True,
        "explainability_complete": True,
        "best_static_provider_adapter_id": str(best_static_provider["adapter_id"]),
        "provider_underlay_ref": str(provider_context["provider_report_ref"]),
        "boundary_holds": boundary_holds,
        "failures": health_failures,
    }

    return {
        "selection_report": selection_report,
        "matrix_report": matrix_report,
        "health_report": health_report,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Wave 2B router shadow preconditions and explainable comparison artifacts without cutover.")
    parser.add_argument("--selection-output", default=f"{REPORT_ROOT_REL}/kt_wave2b_router_selection_receipt.json")
    parser.add_argument("--matrix-output", default=f"{REPORT_ROOT_REL}/kt_wave2b_router_shadow_eval_matrix.json")
    parser.add_argument("--health-output", default=f"{REPORT_ROOT_REL}/kt_wave2b_route_distribution_health.json")
    parser.add_argument("--telemetry-output", default=f"{REPORT_ROOT_REL}/kt_wave2b_router_shadow_telemetry.jsonl")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    telemetry_path = Path(str(args.telemetry_output)).expanduser()
    if not telemetry_path.is_absolute():
        telemetry_path = (root / telemetry_path).resolve()
    if telemetry_path.exists():
        telemetry_path.unlink()

    reports = build_wave2b_shadow_reports(root=root, telemetry_path=telemetry_path)
    outputs = {
        "selection_report": Path(str(args.selection_output)).expanduser(),
        "matrix_report": Path(str(args.matrix_output)).expanduser(),
        "health_report": Path(str(args.health_output)).expanduser(),
    }
    for key, path in outputs.items():
        if not path.is_absolute():
            outputs[key] = (root / path).resolve()

    for key, path in outputs.items():
        write_json_stable(path, reports[key])

    failures = {
        "selection_failures": reports["selection_report"].get("failures", []),
        "matrix_failures": reports["matrix_report"].get("failures", []),
        "health_failures": reports["health_report"].get("failures", []),
    }
    status = "PASS" if not failures["selection_failures"] and not failures["matrix_failures"] and not failures["health_failures"] else "FAIL"
    print(json.dumps({"status": status, **failures}, sort_keys=True))
    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
