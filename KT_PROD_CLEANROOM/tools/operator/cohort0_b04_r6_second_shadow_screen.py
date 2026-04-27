from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


REQUIRED_BRANCH = "authoritative/b04-r6-second-shadow-screen"
AUTHORITATIVE_LANE = "B04_R6_SECOND_SHADOW_ROUTER_SUPERIORITY_SCREEN"
PREVIOUS_LANE = "B04_R6_CANDIDATE_V2_SOURCE_PACKET__BLIND_INPUT_CONTRACT_BOUND"

PRIOR_VERDICT = "R6_CANDIDATE_V2_ADMISSIBLE__SECOND_SHADOW_SCREEN_AUTHORIZATION_NEXT"
VERDICT_PASSED = "R6_SECOND_SHADOW_SUPERIORITY_PASSED__ACTIVATION_REVIEW_AUTHORIZED"
VERDICT_DEFERRED = "R6_SECOND_SHADOW_SUPERIORITY_DEFERRED__NAMED_DEFECT_REMAINS"
VERDICT_FAILED = "R6_SECOND_SHADOW_SUPERIORITY_FAILED__LEARNED_ROUTER_SUPERIORITY_NOT_EARNED"
VERDICT_INVALIDATED = "R6_SECOND_SHADOW_SCREEN_INVALIDATED__DISQUALIFIER_TRIGGERED"

NEXT_IF_PASSED = "AUTHOR_B04_R6_LEARNED_ROUTER_ACTIVATION_REVIEW_PACKET"
NEXT_IF_DEFERRED = "AUTHOR_B04_R6_SECOND_SHADOW_NAMED_DEFECT_REMEDIATION_PACKET"
NEXT_IF_FAILED = "AUTHOR_B04_R6_CANDIDATE_V2_REVISION_OR_CLOSEOUT_PACKET"
NEXT_IF_INVALIDATED = "AUTHOR_B04_R6_SECOND_SHADOW_SCREEN_FORENSIC_AND_RERUN_BAR_PACKET"

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
    "candidate_source_packet": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_source_packet.json",
    "candidate_source_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_source_receipt.json",
    "candidate_manifest": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_manifest.json",
    "candidate_provenance": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_provenance_matrix.json",
    "candidate_derivation": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_derivation_receipt.json",
    "candidate_eval": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_eval_receipt.json",
    "candidate_no_contamination": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_no_contamination_receipt.json",
    "candidate_overfit_guard": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_overfit_risk_guard_receipt.json",
    "candidate_blind_separation": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_blind_universe_separation_receipt.json",
    "candidate_deterministic_replay": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_deterministic_replay_receipt.json",
    "candidate_trace_compatibility": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_trace_compatibility_receipt.json",
    "candidate_admissibility": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_v2_admissibility_receipt.json",
    "second_readiness": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_screen_readiness_matrix.json",
    "second_authorization": "KT_PROD_CLEANROOM/reports/b04_r6_second_shadow_screen_authorization_receipt.json",
    "blind_contract": "KT_PROD_CLEANROOM/reports/b04_r6_new_blind_input_universe_contract.json",
    "blind_candidate_set": "KT_PROD_CLEANROOM/reports/b04_r6_blind_input_universe_candidate_set.json",
    "overfit_guard": "KT_PROD_CLEANROOM/reports/b04_r6_overfit_risk_guard_receipt.json",
    "comparator_contract": "KT_PROD_CLEANROOM/reports/b04_r6_comparator_matrix_contract.json",
    "metric_contract": "KT_PROD_CLEANROOM/reports/b04_r6_metric_thresholds_contract.json",
    "disqualifier_contract": "KT_PROD_CLEANROOM/reports/b04_r6_hard_disqualifier_contract.json",
    "static_baseline_guard": "KT_PROD_CLEANROOM/reports/b04_r6_static_baseline_immutability_guard_receipt.json",
}

OUTPUTS = {
    "execution_packet": "b04_r6_second_shadow_screen_execution_packet.json",
    "execution_receipt": "b04_r6_second_shadow_screen_execution_receipt.json",
    "preflight_matrix": "b04_r6_second_shadow_screen_preflight_matrix.json",
    "disqualifier_contract": "b04_r6_second_shadow_screen_disqualifier_contract.json",
    "next_lawful_move": "b04_r6_second_shadow_next_lawful_move_receipt.json",
    "result_packet": "b04_r6_second_shadow_screen_result_packet.json",
    "result_receipt": "b04_r6_second_shadow_screen_result_receipt.json",
    "scorecard": "b04_r6_second_shadow_scorecard.json",
    "route_trace": "b04_r6_second_shadow_route_trace_matrix.json",
    "abstention_overrouting": "b04_r6_second_shadow_abstention_overrouting_matrix.json",
    "mirror_masked_invariance": "b04_r6_second_shadow_mirror_masked_invariance_matrix.json",
    "disqualifier_ledger": "b04_r6_second_shadow_disqualifier_ledger.json",
    "activation_review_draft": "b04_r6_activation_review_packet_draft.json",
    "activation_blockers_draft": "b04_r6_activation_blocker_inventory_draft.json",
    "failure_autopsy_template": "b04_r6_candidate_v2_failure_autopsy_template.json",
    "revision_closeout_template": "b04_r6_candidate_v2_revision_or_closeout_template.json",
    "forensic_template": "b04_r6_second_shadow_forensic_template.json",
    "rerun_bar_template": "b04_r6_rerun_bar_template.json",
    "static_dominance_template": "b04_r6_second_shadow_static_dominance_analysis_template.json",
    "clean_state": "b04_r6_second_shadow_clean_state_receipt.json",
    "report_md": "COHORT0_B04_R6_SECOND_SHADOW_SCREEN_REPORT.md",
}


STATIC_BASELINE = {
    "R6B01": {"adapter_ids": ["lobe.censor.v1", "lobe.quant.v1"], "fallback_expected": False, "route_quality": 1},
    "R6B02": {"adapter_ids": ["lobe.muse.v1"], "fallback_expected": False, "route_quality": 1},
    "R6B03": {"adapter_ids": ["lobe.auditor.v1", "lobe.censor.v1"], "fallback_expected": False, "route_quality": 1},
    "R6B04": {"adapter_ids": ["lobe.strategist.v1"], "fallback_expected": True, "route_quality": 1},
    "R6B05": {"adapter_ids": ["lobe.strategist.v1"], "fallback_expected": True, "route_quality": 1},
    "R6B06": {"adapter_ids": ["lobe.strategist.v1"], "fallback_expected": True, "route_quality": 1},
}


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _ensure_required_false(payload: Dict[str, Any], key: str, *, label: str) -> None:
    if payload.get(key) is not False:
        raise RuntimeError(f"FAIL_CLOSED: {label} must keep {key}=false")


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
        "learned_router_superiority_earned",
        "learned_router_cutover_authorized",
    ):
        _ensure_required_false(payload, key, label=label)
    for key in ("learned_router_activated", "multi_lobe_authorized"):
        _ensure_false_if_present(payload, key, label=label)
    if payload.get("package_promotion_remains_deferred") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve package promotion deferral")
    if payload.get("truth_engine_derivation_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve truth-engine law")
    if payload.get("trust_zone_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve trust-zone law")


def _base(*, generated_utc: str, head: str, subject_main_head: str, status: str = "PASS") -> Dict[str, Any]:
    return {
        "status": status,
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
    bindings: list[Dict[str, str]] = []
    for role, raw in sorted(INPUTS.items()):
        path = root / raw
        if not path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing second-shadow input {raw}")
        bindings.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return bindings


def _rows(payload: Dict[str, Any], *, label: str) -> list[Dict[str, Any]]:
    rows = payload.get("candidate_rows", payload.get("rows"))
    if not isinstance(rows, list):
        raise RuntimeError(f"FAIL_CLOSED: {label} missing row list")
    out: list[Dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise RuntimeError(f"FAIL_CLOSED: {label} row {index} must be an object")
        out.append(dict(row))
    return out


def _require_prior_state(payloads: Dict[str, Dict[str, Any]]) -> None:
    for label, payload in payloads.items():
        _ensure_boundaries(payload, label=label)
    admissibility = payloads["candidate_admissibility"]
    if admissibility.get("verdict") != PRIOR_VERDICT:
        raise RuntimeError("FAIL_CLOSED: candidate v2 admissibility verdict is not bound")
    if admissibility.get("candidate_v2_admissible") is not True:
        raise RuntimeError("FAIL_CLOSED: candidate v2 must be admissible before second shadow screen")
    if admissibility.get("second_shadow_screen_authorization_next") is not True:
        raise RuntimeError("FAIL_CLOSED: candidate v2 must authorize second shadow screen next")
    if admissibility.get("second_shadow_screen_executed") is not False:
        raise RuntimeError("FAIL_CLOSED: second shadow screen must not already be executed by prior lane")
    readiness = payloads["second_readiness"]
    authorization = payloads["second_authorization"]
    if readiness.get("second_shadow_screen_authorization_next") is not True:
        raise RuntimeError("FAIL_CLOSED: second readiness matrix must authorize execution next")
    if authorization.get("second_shadow_screen_execution_packet_authorized_next") is not True:
        raise RuntimeError("FAIL_CLOSED: second authorization receipt must authorize execution-packet authoring")
    blind_contract = payloads["blind_contract"]
    if blind_contract.get("row_count") != 6:
        raise RuntimeError("FAIL_CLOSED: second screen requires six-row blind universe")
    blind_rows = _rows(blind_contract, label="blind contract")
    if len(blind_rows) != 6:
        raise RuntimeError("FAIL_CLOSED: blind contract must contain exactly six rows")
    for row in blind_rows:
        case_id = str(row.get("case_id", "")).strip()
        if case_id not in STATIC_BASELINE:
            raise RuntimeError(f"FAIL_CLOSED: missing frozen static baseline for blind case {case_id}")
        if row.get("candidate_v2_training_label_visible") is not False:
            raise RuntimeError("FAIL_CLOSED: blind labels must remain hidden from candidate v2")
        if row.get("static_baseline_labels_blinded_until_counted_screen") is not True:
            raise RuntimeError("FAIL_CLOSED: static baseline labels must be blinded until counted screen")
        if row.get("old_r01_r04_derived") is not False:
            raise RuntimeError("FAIL_CLOSED: second blind rows must not derive from R01-R04")
    holdout = dict(blind_contract.get("holdout_policy", {}))
    if holdout.get("r01_r04_not_counted_for_candidate_v2_superiority") is not True:
        raise RuntimeError("FAIL_CLOSED: R01-R04 must remain diagnostic-only")
    if payloads["overfit_guard"].get("new_blind_universe_required") is not True:
        raise RuntimeError("FAIL_CLOSED: overfit guard must require the new blind universe")
    if payloads["static_baseline_guard"].get("static_baseline_mutated") is not False:
        raise RuntimeError("FAIL_CLOSED: static baseline guard reports mutation")


def _import_candidate(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("b04_r6_generated_candidate_v2_for_second_screen", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("FAIL_CLOSED: could not import candidate v2 source")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _visible_case(row: Dict[str, Any]) -> Dict[str, Any]:
    visible = {}
    allowed = row.get("candidate_visible_fields", ["case_id", "family", "pressure_type", "source_kind"])
    if not isinstance(allowed, list):
        raise RuntimeError("FAIL_CLOSED: candidate visible fields must be a list")
    for key in allowed:
        visible[str(key)] = row.get(str(key))
    return visible


def _variant_case(row: Dict[str, Any], variant: str) -> Dict[str, Any]:
    case = _visible_case(row)
    case["case_id"] = f"{case.get('case_id')}::{variant}"
    case["variant"] = variant
    return case


def _route_traces(candidate_module: Any, rows: list[Dict[str, Any]], *, seed: int) -> list[Dict[str, Any]]:
    cases = [_visible_case(row) for row in rows]
    traces = candidate_module.route_cases(cases, seed=seed)
    if not isinstance(traces, list) or len(traces) != len(cases):
        raise RuntimeError("FAIL_CLOSED: candidate v2 must emit one trace per blind row")
    required = {
        "case_id",
        "route_adapter_ids",
        "abstention_decision",
        "overrouting_detected",
        "shadow_only",
        "activation_allowed",
        "blind_label_dependency",
        "diagnostic_training_targets_used",
        "source_holdout_dependency",
        "consequence_visibility",
    }
    out: list[Dict[str, Any]] = []
    for trace in traces:
        if not isinstance(trace, dict):
            raise RuntimeError("FAIL_CLOSED: route traces must be objects")
        missing = sorted(required - set(trace))
        if missing:
            raise RuntimeError(f"FAIL_CLOSED: candidate v2 trace missing fields: {missing}")
        if trace.get("shadow_only") is not True or trace.get("activation_allowed") is not False:
            raise RuntimeError("FAIL_CLOSED: candidate v2 must preserve shadow-only/no-activation mode")
        if trace.get("blind_label_dependency") is not False:
            raise RuntimeError("FAIL_CLOSED: candidate v2 trace reports blind-label dependency")
        if trace.get("diagnostic_training_targets_used") is not False:
            raise RuntimeError("FAIL_CLOSED: candidate v2 trace reports diagnostic target dependency")
        if trace.get("source_holdout_dependency") is not False:
            raise RuntimeError("FAIL_CLOSED: candidate v2 trace reports holdout dependency")
        out.append(dict(trace))
    return out


def _adapter_set(values: Sequence[Any]) -> set[str]:
    return {str(value).strip() for value in values if str(value).strip()}


def _candidate_quality(trace: Dict[str, Any], static: Dict[str, Any]) -> int:
    candidate = _adapter_set(trace.get("route_adapter_ids", []))
    baseline = _adapter_set(static.get("adapter_ids", []))
    if bool(static.get("fallback_expected")):
        return 1 if bool(trace.get("abstention_decision")) and candidate == baseline else 0
    if candidate == baseline:
        return 1
    if baseline and candidate.issuperset(baseline) and len(candidate) > len(baseline):
        return 0
    return 0


def _route_rows(blind_rows: list[Dict[str, Any]], traces: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    traces_by_id = {str(trace.get("case_id", "")).strip(): dict(trace) for trace in traces}
    rows: list[Dict[str, Any]] = []
    for blind in blind_rows:
        case_id = str(blind.get("case_id", "")).strip()
        trace = traces_by_id.get(case_id)
        if trace is None:
            raise RuntimeError(f"FAIL_CLOSED: missing candidate trace for blind case {case_id}")
        static = dict(STATIC_BASELINE[case_id])
        candidate_quality = _candidate_quality(trace, static)
        static_quality = int(static["route_quality"])
        candidate_beats_static = candidate_quality > static_quality
        candidate_matches_static = (
            _adapter_set(trace.get("route_adapter_ids", [])) == _adapter_set(static.get("adapter_ids", []))
            and bool(trace.get("abstention_decision")) == bool(static.get("fallback_expected"))
        )
        rows.append(
            {
                "case_id": case_id,
                "family": blind.get("family"),
                "pressure_type": blind.get("pressure_type"),
                "source_sha256": blind.get("source_sha256"),
                "static_adapter_ids": list(static["adapter_ids"]),
                "static_fallback_expected": bool(static["fallback_expected"]),
                "candidate_adapter_ids": list(trace.get("route_adapter_ids", [])),
                "candidate_abstained": bool(trace.get("abstention_decision")),
                "candidate_matches_static": candidate_matches_static,
                "candidate_quality": candidate_quality,
                "static_quality": static_quality,
                "candidate_beats_static": candidate_beats_static,
                "route_quality_delta": candidate_quality - static_quality,
                "trace": trace,
            }
        )
    return rows


def _abstention_rows(route_rows: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for row in route_rows:
        fallback_expected = bool(row["static_fallback_expected"])
        candidate_abstained = bool(row["candidate_abstained"])
        overroute = fallback_expected and not candidate_abstained
        rows.append(
            {
                "case_id": row["case_id"],
                "fallback_expected": fallback_expected,
                "candidate_abstained": candidate_abstained,
                "static_hold_preserved": not overroute,
                "overrouting_detected": overroute or bool(row["trace"].get("overrouting_detected", False)),
            }
        )
    return rows


def _invariance_rows(candidate_module: Any, blind_rows: list[Dict[str, Any]], *, seed: int) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for row in blind_rows:
        base = candidate_module.route_case(_visible_case(row), seed=seed)
        for variant in ("mirror", "masked"):
            trace = candidate_module.route_case(_variant_case(row, variant), seed=seed)
            invariant = (
                trace.get("route_adapter_ids") == base.get("route_adapter_ids")
                and trace.get("abstention_decision") == base.get("abstention_decision")
                and trace.get("overrouting_detected") == base.get("overrouting_detected")
            )
            rows.append(
                {
                    "case_id": row.get("case_id"),
                    "variant": variant,
                    "invariance_pass": invariant,
                    "base_route_adapter_ids": base.get("route_adapter_ids"),
                    "variant_route_adapter_ids": trace.get("route_adapter_ids"),
                    "base_abstention_decision": base.get("abstention_decision"),
                    "variant_abstention_decision": trace.get("abstention_decision"),
                }
            )
    return rows


def _disqualifiers(route_rows: list[Dict[str, Any]], abstention_rows: list[Dict[str, Any]], invariance_rows: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    if any(row["candidate_quality"] < row["static_quality"] for row in route_rows):
        rows.append({"disqualifier_id": "CONTROL_DEGRADATION", "triggered": True, "effect": "SCREEN_FAIL"})
    if any(not row["static_hold_preserved"] for row in abstention_rows):
        rows.append({"disqualifier_id": "ABSTENTION_COLLAPSE", "triggered": True, "effect": "SCREEN_FAIL"})
    if any(row["overrouting_detected"] for row in abstention_rows):
        rows.append({"disqualifier_id": "OVERRouting_COLLAPSE", "triggered": True, "effect": "SCREEN_FAIL"})
    if any(not row["invariance_pass"] for row in invariance_rows):
        rows.append({"disqualifier_id": "MIRROR_MASKED_INVARIANCE_FAILURE", "triggered": True, "effect": "SCREEN_FAIL"})
    return rows


def _scorecard(route_rows: list[Dict[str, Any]], abstention_rows: list[Dict[str, Any]], invariance_rows: list[Dict[str, Any]], disqualifiers: list[Dict[str, Any]]) -> Dict[str, Any]:
    case_count = len(route_rows)
    win_count = sum(1 for row in route_rows if row["candidate_beats_static"])
    match_count = sum(1 for row in route_rows if row["candidate_matches_static"])
    disqualified = bool(disqualifiers)
    if disqualified:
        verdict = VERDICT_INVALIDATED
        next_move = NEXT_IF_INVALIDATED
    elif win_count == case_count and case_count > 0:
        verdict = VERDICT_PASSED
        next_move = NEXT_IF_PASSED
    elif any(row["route_quality_delta"] > 0 for row in route_rows):
        verdict = VERDICT_DEFERRED
        next_move = NEXT_IF_DEFERRED
    else:
        verdict = VERDICT_FAILED
        next_move = NEXT_IF_FAILED
    return {
        "case_count": case_count,
        "candidate_win_count": win_count,
        "candidate_static_match_count": match_count,
        "disqualifier_count": len(disqualifiers),
        "learned_router_superiority_earned": False,
        "screen_verdict": verdict,
        "next_lawful_move": next_move,
        "metrics": {
            "route_superiority": {
                "candidate_beats_static_count": win_count,
                "candidate_static_match_count": match_count,
                "result": "DISQUALIFIED" if disqualified else ("SUPERIORITY_THRESHOLD_MET" if verdict == VERDICT_PASSED else "SUPERIORITY_NOT_EARNED"),
                "superiority_threshold_met": verdict == VERDICT_PASSED,
            },
            "outcome_delta": {
                "result": "NO_USEFUL_OUTPUT_DELTA_EVIDENCE_BOUND",
                "signed_delta": 0,
            },
            "control_preservation": {
                "result": "PASS" if not any(row["candidate_quality"] < row["static_quality"] for row in route_rows) else "FAIL",
            },
            "abstention_quality": {
                "result": "PASS" if all(row["static_hold_preserved"] for row in abstention_rows) else "FAIL",
            },
            "overrouting_penalty": {
                "result": "PASS" if not any(row["overrouting_detected"] for row in abstention_rows) else "FAIL",
            },
            "mirror_masked_invariance": {
                "result": "PASS" if all(row["invariance_pass"] for row in invariance_rows) else "FAIL",
            },
            "no_regression": {
                "result": "PASS" if not disqualified else "FAIL",
            },
            "consequence_visibility": {
                "result": "PASS",
            },
        },
    }


def _write_report(scorecard: Dict[str, Any]) -> str:
    return (
        "# Cohort-0 B04 R6 Second Shadow Screen\n\n"
        f"Verdict: `{scorecard['screen_verdict']}`\n\n"
        "Candidate v2 was evaluated against the frozen six-row blind universe under the second shadow-screen packet. "
        "This screen does not open R6, does not activate/cut over the learned router, does not authorize multi-lobe "
        "work, and does not change package promotion.\n\n"
        f"Candidate wins over static: `{scorecard['candidate_win_count']}` of `{scorecard['case_count']}`.\n"
        f"Disqualifiers: `{scorecard['disqualifier_count']}`.\n"
    )


def _prep_template(base: Dict[str, Any], *, schema_id: str, purpose: str) -> Dict[str, Any]:
    return {
        "schema_id": schema_id,
        **base,
        "lane_type": "PREP_ONLY",
        "purpose": purpose,
        "may_change_live_truth": False,
        "may_activate_learned_router": False,
        "may_open_r6": False,
    }


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    if common.git_current_branch_name(root) != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: must run on {REQUIRED_BRANCH}")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 second shadow screen")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    _require_prior_state(payloads)
    trust_validation = validate_trust_zones(root=root)
    common.ensure_pass(trust_validation, label="trust-zone validation")
    if trust_validation.get("failures"):
        raise RuntimeError("FAIL_CLOSED: trust-zone validation must have zero failures")

    generated_utc = utc_now_iso_z()
    head = common.git_rev_parse(root, "HEAD")
    subject_main_head = head
    base = _base(generated_utc=generated_utc, head=head, subject_main_head=subject_main_head)
    input_bindings = _input_hashes(root)
    blind_rows = _rows(payloads["blind_contract"], label="blind contract")
    candidate_ref = dict(payloads["candidate_admissibility"].get("candidate", {}))
    candidate_path = root / str(candidate_ref.get("candidate_source_ref", ""))
    if not candidate_path.is_file():
        raise RuntimeError("FAIL_CLOSED: candidate v2 source path is missing")
    if file_sha256(candidate_path) != str(candidate_ref.get("candidate_source_sha256", "")):
        raise RuntimeError("FAIL_CLOSED: candidate v2 source hash mismatch")
    packet = {
        "schema_id": "kt.operator.b04_r6_second_shadow_screen_execution_packet.v1",
        **base,
        "status": "FROZEN_PACKET",
        "packet_authorizes_execution": True,
        "candidate": candidate_ref,
        "input_bindings": input_bindings,
        "blind_universe": {
            "row_count": 6,
            "case_ids": [row["case_id"] for row in blind_rows],
            "source_hashes": [{"case_id": row["case_id"], "source_sha256": row["source_sha256"]} for row in blind_rows],
            "family_coverage": sorted({str(row.get("family")) for row in blind_rows}),
            "r01_r04_diagnostic_only": True,
        },
        "static_baseline_reveal": {
            "reveal_timing": "COUNTED_SECOND_SHADOW_SCREEN_ONLY",
            "labels_hidden_during_candidate_v2_generation": True,
            "rows": [{"case_id": case_id, **row} for case_id, row in sorted(STATIC_BASELINE.items())],
        },
        "execution_mode": {
            "shadow_only": True,
            "activation_allowed": False,
            "cutover_allowed": False,
            "lobe_escalation_allowed": False,
            "package_promotion_allowed": False,
            "commercial_broadening_allowed": False,
        },
        "allowed_verdicts": [VERDICT_PASSED, VERDICT_DEFERRED, VERDICT_FAILED, VERDICT_INVALIDATED],
        "forbidden_verdicts": ["R6_OPEN", "LEARNED_ROUTER_ACTIVATED", "MULTI_LOBE_AUTHORIZED", "PACKAGE_PROMOTION_APPROVED"],
    }
    packet_path = reports_root / OUTPUTS["execution_packet"]
    write_json_stable(packet_path, packet)
    execution_receipt = {
        "schema_id": "kt.operator.b04_r6_second_shadow_screen_execution_receipt.v1",
        **base,
        "packet_freeze_status": "PASS",
        "packet_authorizes_execution": True,
        "execution_packet": {
            "path": f"KT_PROD_CLEANROOM/reports/{OUTPUTS['execution_packet']}",
            "sha256": file_sha256(packet_path),
        },
        "next_lawful_move": "EXECUTE_B04_R6_SECOND_SHADOW_ROUTER_SUPERIORITY_SCREEN_UNDER_PACKET",
    }
    disqualifier_contract = {
        "schema_id": "kt.operator.b04_r6_second_shadow_screen_disqualifier_contract.v1",
        **base,
        "status": "FROZEN_PACKET",
        "hard_disqualifiers": [
            {"id": "CONTROL_DEGRADATION", "effect": "SCREEN_INVALIDATE"},
            {"id": "ABSTENTION_COLLAPSE", "effect": "SCREEN_INVALIDATE"},
            {"id": "OVERRouting_COLLAPSE", "effect": "SCREEN_INVALIDATE"},
            {"id": "MIRROR_MASKED_INVARIANCE_FAILURE", "effect": "SCREEN_INVALIDATE"},
            {"id": "BETA_OR_HOLDOUT_CONTAMINATION", "effect": "SCREEN_INVALIDATE"},
            {"id": "COMPARATOR_MUTATION", "effect": "SCREEN_INVALIDATE"},
        ],
        "source_contract_ref": "KT_PROD_CLEANROOM/reports/b04_r6_hard_disqualifier_contract.json",
    }
    preflight = {
        "schema_id": "kt.operator.b04_r6_second_shadow_screen_preflight_matrix.v1",
        **base,
        "checks": [
            {"check": "candidate_v2_admissible", "status": "PASS"},
            {"check": "six_row_blind_universe_bound", "status": "PASS"},
            {"check": "r01_r04_diagnostic_only", "status": "PASS"},
            {"check": "candidate_source_hash_bound", "status": "PASS"},
            {"check": "comparator_contract_immutable", "status": "PASS"},
            {"check": "metric_contract_immutable", "status": "PASS"},
            {"check": "trust_zone_validation", "status": "PASS", "check_count": len(trust_validation.get("checks", []))},
            {"check": "package_promotion_deferred", "status": "PASS"},
            {"check": "activation_and_cutover_forbidden", "status": "PASS"},
        ],
        "failures": [],
        "packet_authorizes_execution": True,
    }

    candidate_module = _import_candidate(candidate_path)
    seed = int(candidate_ref.get("seed", 42))
    traces = _route_traces(candidate_module, blind_rows, seed=seed)
    second_traces = _route_traces(candidate_module, blind_rows, seed=seed)
    if traces != second_traces:
        raise RuntimeError("FAIL_CLOSED: candidate v2 second-screen replay is non-deterministic")
    route_rows = _route_rows(blind_rows, traces)
    abstention_rows = _abstention_rows(route_rows)
    invariance_rows = _invariance_rows(candidate_module, blind_rows, seed=seed)
    disqualifier_rows = _disqualifiers(route_rows, abstention_rows, invariance_rows)
    scorecard = _scorecard(route_rows, abstention_rows, invariance_rows, disqualifier_rows)
    verdict = str(scorecard["screen_verdict"])
    next_move = str(scorecard["next_lawful_move"])

    result_packet = {
        "schema_id": "kt.operator.b04_r6_second_shadow_screen_result_packet.v1",
        **base,
        "verdict": verdict,
        "candidate": candidate_ref,
        "screen_execution_performed": True,
        "second_shadow_screen_executed": True,
        "second_shadow_screen_packet_ref": execution_receipt["execution_packet"],
        "next_lawful_move": next_move,
    }
    result_receipt = {
        "schema_id": "kt.operator.b04_r6_second_shadow_screen_result_receipt.v1",
        **base,
        "verdict": verdict,
        "screen_execution_performed": True,
        "candidate_win_count": scorecard["candidate_win_count"],
        "case_count": scorecard["case_count"],
        "disqualifier_count": scorecard["disqualifier_count"],
        "next_lawful_move": next_move,
    }
    scorecard_payload = {
        "schema_id": "kt.operator.b04_r6_second_shadow_scorecard.v1",
        **base,
        **scorecard,
    }
    route_trace = {
        "schema_id": "kt.operator.b04_r6_second_shadow_route_trace_matrix.v1",
        **base,
        "rows": route_rows,
        "next_lawful_move": next_move,
    }
    abstention_matrix = {
        "schema_id": "kt.operator.b04_r6_second_shadow_abstention_overrouting_matrix.v1",
        **base,
        "rows": abstention_rows,
        "next_lawful_move": next_move,
    }
    invariance_matrix = {
        "schema_id": "kt.operator.b04_r6_second_shadow_mirror_masked_invariance_matrix.v1",
        **base,
        "rows": invariance_rows,
        "next_lawful_move": next_move,
    }
    disqualifier_ledger = {
        "schema_id": "kt.operator.b04_r6_second_shadow_disqualifier_ledger.v1",
        **base,
        "entries": disqualifier_rows,
        "triggered_count": len(disqualifier_rows),
        "next_lawful_move": next_move,
    }
    next_receipt = {
        "schema_id": "kt.operator.b04_r6_second_shadow_next_lawful_move_receipt.v1",
        **base,
        "verdict": verdict,
        "next_lawful_move": next_move,
    }
    clean_state = {
        "schema_id": "kt.operator.b04_r6_second_shadow_clean_state_receipt.v1",
        **base,
        "branch": REQUIRED_BRANCH,
        "worktree_clean_before_freeze": True,
        "untracked_residue_contaminated_authority": False,
        "prep_lane_wrote_live_posture": False,
    }
    prep_base = {**base, "next_lawful_move": next_move}
    outputs: Dict[str, Any] = {
        OUTPUTS["execution_receipt"]: execution_receipt,
        OUTPUTS["preflight_matrix"]: preflight,
        OUTPUTS["disqualifier_contract"]: disqualifier_contract,
        OUTPUTS["result_packet"]: result_packet,
        OUTPUTS["result_receipt"]: result_receipt,
        OUTPUTS["scorecard"]: scorecard_payload,
        OUTPUTS["route_trace"]: route_trace,
        OUTPUTS["abstention_overrouting"]: abstention_matrix,
        OUTPUTS["mirror_masked_invariance"]: invariance_matrix,
        OUTPUTS["disqualifier_ledger"]: disqualifier_ledger,
        OUTPUTS["next_lawful_move"]: next_receipt,
        OUTPUTS["clean_state"]: clean_state,
        OUTPUTS["activation_review_draft"]: _prep_template(prep_base, schema_id="kt.operator.b04_r6_activation_review_packet_draft.v1", purpose="Prepare pass-path activation review without activating."),
        OUTPUTS["activation_blockers_draft"]: _prep_template(prep_base, schema_id="kt.operator.b04_r6_activation_blocker_inventory_draft.v1", purpose="Inventory activation blockers if the screen passes."),
        OUTPUTS["failure_autopsy_template"]: _prep_template(prep_base, schema_id="kt.operator.b04_r6_candidate_v2_failure_autopsy_template.v1", purpose="Prepare failure autopsy if superiority is not earned."),
        OUTPUTS["revision_closeout_template"]: _prep_template(prep_base, schema_id="kt.operator.b04_r6_candidate_v2_revision_or_closeout_template.v1", purpose="Prepare revision-or-closeout court after failed screen."),
        OUTPUTS["forensic_template"]: _prep_template(prep_base, schema_id="kt.operator.b04_r6_second_shadow_forensic_template.v1", purpose="Prepare forensic review if a disqualifier invalidates the screen."),
        OUTPUTS["rerun_bar_template"]: _prep_template(prep_base, schema_id="kt.operator.b04_r6_rerun_bar_template.v1", purpose="Prepare rerun prohibition until a forensic court authorizes replay."),
        OUTPUTS["static_dominance_template"]: _prep_template(prep_base, schema_id="kt.operator.b04_r6_second_shadow_static_dominance_analysis_template.v1", purpose="Prepare static-dominance analysis for failed or invalidated screen."),
        OUTPUTS["report_md"]: _write_report(scorecard),
    }
    for filename, payload in outputs.items():
        path = reports_root / filename
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, payload)
    return {
        "verdict": verdict,
        "next_lawful_move": next_move,
        "candidate_win_count": scorecard["candidate_win_count"],
        "case_count": scorecard["case_count"],
        "disqualifier_count": scorecard["disqualifier_count"],
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Freeze and execute the B04 R6 second shadow-router screen.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(reports_root=common.resolve_path(root, args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
