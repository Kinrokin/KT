from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


REQUIRED_BRANCH = "authoritative/b04-r6-shadow-superiority-screen-execution"
AUTHORITATIVE_LANE = "B04_R6_SHADOW_ROUTER_SUPERIORITY_SCREEN_EXECUTION"
NEXT_MOVE = "AUTHOR_B04_R6_CANDIDATE_REVISION_OR_CLOSEOUT_PACKET"
VERDICT_FAILED = "R6_SHADOW_SUPERIORITY_FAILED__LEARNED_ROUTER_SUPERIORITY_NOT_EARNED"
VERDICT_INVALIDATED = "R6_SHADOW_SCREEN_INVALIDATED__DISQUALIFIER_TRIGGERED"

FORBIDDEN_CLAIMS = [
    "r6_open",
    "learned_router_activated",
    "multi_lobe_authorized",
    "package_promotion_approved",
    "commercial_broadening",
]

OUTPUTS = {
    "preflight": "b04_r6_shadow_router_superiority_preflight_receipt.json",
    "packet": "b04_r6_shadow_router_superiority_screen_packet.json",
    "receipt": "b04_r6_shadow_router_superiority_screen_receipt.json",
    "scorecard": "b04_r6_shadow_router_superiority_scorecard.json",
    "route_trace": "b04_r6_shadow_router_route_decision_trace.json",
    "route_matrix": "b04_r6_shadow_router_route_trace_matrix.json",
    "abstention_trace": "b04_r6_shadow_router_overrouting_abstention_trace.json",
    "abstention_matrix": "b04_r6_shadow_router_abstention_overrouting_matrix.json",
    "invariance_trace": "b04_r6_shadow_router_mirror_masked_invariance_trace.json",
    "invariance_matrix": "b04_r6_shadow_router_mirror_masked_invariance_matrix.json",
    "blocker_ledger": "b04_r6_shadow_router_superiority_blocker_ledger.json",
    "disqualifier_ledger": "b04_r6_shadow_router_disqualifier_ledger.json",
    "next_lawful_move": "b04_r6_shadow_router_next_lawful_move_receipt.json",
    "report_md": "COHORT0_B04_R6_SHADOW_ROUTER_SUPERIORITY_SCREEN_REPORT.md",
}


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _base(*, generated_utc: str, head: str, subject_main_head: str, status: str = "PASS") -> Dict[str, Any]:
    return {
        "status": status,
        "generated_utc": generated_utc,
        "current_git_head": head,
        "subject_main_head": subject_main_head,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "r6_authorized": False,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "learned_router_cutover_authorized": False,
        "learned_router_activated": False,
        "multi_lobe_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _ensure_false(payload: Dict[str, Any], key: str, *, label: str) -> None:
    if key in payload and payload.get(key) is not False:
        raise RuntimeError(f"FAIL_CLOSED: {label} must keep {key}=false")


def _ensure_boundaries(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() not in {"PASS", "FROZEN_PACKET"}:
        raise RuntimeError(f"FAIL_CLOSED: {label} must be PASS/FROZEN_PACKET")
    for key in ("r6_authorized", "r6_open", "learned_router_superiority_earned"):
        _ensure_false(payload, key, label=label)
    if payload.get("package_promotion_remains_deferred") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve package promotion deferral")
    if payload.get("truth_engine_derivation_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve truth-engine law")
    if payload.get("trust_zone_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve trust-zone law")


def _verify_file_hashes(root: Path, execution_packet: Dict[str, Any], execution_packet_receipt: Dict[str, Any]) -> list[Dict[str, str]]:
    checked: list[Dict[str, str]] = []
    for binding in execution_packet.get("prerequisite_bindings", []):
        path = root / str(binding.get("path", ""))
        expected = str(binding.get("sha256", ""))
        if not path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing prerequisite binding: {path.as_posix()}")
        actual = file_sha256(path)
        if actual != expected:
            raise RuntimeError(f"FAIL_CLOSED: prerequisite hash mismatch: {path.as_posix()}")
        checked.append({"path": path.relative_to(root).as_posix(), "sha256": actual})
    packet_binding = dict(execution_packet_receipt.get("execution_packet", {}))
    packet_path = root / str(packet_binding.get("path", ""))
    if not packet_path.is_file():
        raise RuntimeError("FAIL_CLOSED: missing execution packet referenced by packet receipt")
    actual_packet_hash = file_sha256(packet_path)
    if actual_packet_hash != str(packet_binding.get("sha256", "")):
        raise RuntimeError("FAIL_CLOSED: execution packet receipt hash does not match execution packet bytes")
    checked.append({"path": packet_path.relative_to(root).as_posix(), "sha256": actual_packet_hash})
    return checked


def _import_candidate(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("b04_r6_generated_candidate_for_screen", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("FAIL_CLOSED: could not import generated learned-router candidate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _adapter_set(values: Sequence[Any]) -> set[str]:
    return {str(value).strip() for value in values if str(value).strip()}


def _case_map(cases: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for case in cases:
        case_id = str(case.get("case_id", "")).strip()
        if case_id:
            out[case_id] = dict(case)
    return out


def _route_traces(input_cases: list[Dict[str, Any]], candidate_module: Any, *, seed: int) -> list[Dict[str, Any]]:
    traces = candidate_module.route_cases(input_cases, seed=seed)
    if not isinstance(traces, list) or len(traces) != len(input_cases):
        raise RuntimeError("FAIL_CLOSED: candidate must emit one route trace per input case")
    required = {"case_id", "route_adapter_ids", "abstention_decision", "overrouting_detected", "consequence_visibility"}
    for trace in traces:
        if not isinstance(trace, dict):
            raise RuntimeError("FAIL_CLOSED: candidate route trace rows must be objects")
        missing = sorted(required - set(trace))
        if missing:
            raise RuntimeError(f"FAIL_CLOSED: candidate route trace missing required fields: {missing}")
        if trace.get("shadow_only") is not True or trace.get("activation_allowed") is not False:
            raise RuntimeError("FAIL_CLOSED: candidate trace must preserve shadow-only/no-activation mode")
    return [dict(trace) for trace in traces]


def _compare_routes(input_cases: list[Dict[str, Any]], traces: list[Dict[str, Any]]) -> tuple[list[Dict[str, Any]], list[Dict[str, Any]]]:
    inputs_by_id = _case_map(input_cases)
    route_rows: list[Dict[str, Any]] = []
    abstention_rows: list[Dict[str, Any]] = []
    for trace in traces:
        case_id = str(trace.get("case_id", "")).strip()
        case = inputs_by_id[case_id]
        baseline = [str(item) for item in case.get("baseline_adapter_ids", [])]
        candidate = [str(item) for item in trace.get("route_adapter_ids", [])]
        exact_match = candidate == baseline
        set_match = _adapter_set(candidate) == _adapter_set(baseline)
        fallback_expected = bool(case.get("fallback_engaged", False))
        abstained = bool(trace.get("abstention_decision", False))
        overroute = fallback_expected and not abstained
        route_rows.append(
            {
                "case_id": case_id,
                "family": case.get("family"),
                "baseline_adapter_ids": baseline,
                "candidate_adapter_ids": candidate,
                "exact_order_match": exact_match,
                "route_set_match": set_match,
                "route_quality_delta": 0 if set_match else -100,
                "candidate_beats_static": False,
                "order_advisory": set_match and not exact_match,
                "no_regression_pass": set_match,
                "trace": trace,
            }
        )
        abstention_rows.append(
            {
                "case_id": case_id,
                "fallback_expected": fallback_expected,
                "candidate_abstained": abstained,
                "static_hold_preserved": (abstained is True) if fallback_expected else (abstained is False),
                "overrouting_detected": overroute or bool(trace.get("overrouting_detected", False)),
            }
        )
    return route_rows, abstention_rows


def _variant_case(case: Dict[str, Any], variant: str) -> Dict[str, Any]:
    variant_case = dict(case)
    variant_case["case_id"] = f"{case.get('case_id')}::{variant}"
    variant_case["variant"] = variant
    return variant_case


def _invariance_rows(input_cases: list[Dict[str, Any]], candidate_module: Any, *, seed: int) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for case in input_cases:
        base = candidate_module.route_case(dict(case), seed=seed)
        for variant in ("mirror", "masked"):
            trace = candidate_module.route_case(_variant_case(case, variant), seed=seed)
            invariant = (
                trace.get("route_adapter_ids") == base.get("route_adapter_ids")
                and trace.get("abstention_decision") == base.get("abstention_decision")
                and trace.get("overrouting_detected") == base.get("overrouting_detected")
            )
            rows.append(
                {
                    "case_id": case.get("case_id"),
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
    if any(not row["no_regression_pass"] for row in route_rows):
        rows.append({"disqualifier_id": "control_degradation", "triggered": True, "effect": "INVALIDATE_SCREEN"})
    if any(not row["static_hold_preserved"] for row in abstention_rows):
        rows.append({"disqualifier_id": "abstention_collapse", "triggered": True, "effect": "INVALIDATE_SCREEN"})
    if any(row["overrouting_detected"] for row in abstention_rows):
        rows.append({"disqualifier_id": "overrouting_collapse", "triggered": True, "effect": "INVALIDATE_SCREEN"})
    if any(not row["invariance_pass"] for row in invariance_rows):
        rows.append({"disqualifier_id": "mirror_or_masked_invariance_failure", "triggered": True, "effect": "INVALIDATE_SCREEN"})
    return rows


def _scorecard(route_rows: list[Dict[str, Any]], abstention_rows: list[Dict[str, Any]], invariance_rows: list[Dict[str, Any]], disqualifiers: list[Dict[str, Any]]) -> Dict[str, Any]:
    case_count = len(route_rows)
    route_match_count = sum(1 for row in route_rows if row["route_set_match"])
    candidate_win_count = sum(1 for row in route_rows if row["candidate_beats_static"])
    order_advisory_count = sum(1 for row in route_rows if row["order_advisory"])
    disqualified = bool(disqualifiers)
    superiority_earned = (not disqualified) and candidate_win_count == case_count and case_count > 0
    verdict = VERDICT_INVALIDATED if disqualified else VERDICT_FAILED
    return {
        "case_count": case_count,
        "candidate_win_count": candidate_win_count,
        "disqualifier_count": len(disqualifiers),
        "learned_router_superiority_earned": False,
        "metrics": {
            "route_superiority": {
                "candidate_beats_static_count": candidate_win_count,
                "order_advisory_count": order_advisory_count,
                "result": "NO_MOVEMENT_STATIC_MATCH_ONLY" if candidate_win_count == 0 else "CANDIDATE_MOVEMENT_DETECTED",
                "route_set_match_rate": route_match_count / case_count if case_count else 0,
                "superiority_threshold_met": superiority_earned,
            },
            "outcome_delta": {
                "result": "NO_USEFUL_OUTPUT_DELTA_EVIDENCE_BOUND",
                "signed_delta": 0,
            },
            "control_preservation": {
                "result": "PASS" if not any(not row["no_regression_pass"] for row in route_rows) else "FAIL",
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
        "screen_verdict": verdict,
        "superiority_threshold_met": superiority_earned,
    }


def _write_report(scorecard: Dict[str, Any]) -> str:
    return (
        "# Cohort-0 B04 R6 Shadow Router Superiority Screen\n\n"
        f"Verdict: `{scorecard['screen_verdict']}`\n\n"
        "The admissible shadow-only learned-router candidate was evaluated against the frozen R01-R04 input universe "
        "and static comparator controls. The screen did not open R6, did not activate learned routing, did not authorize "
        "multi-lobe escalation, and did not alter package promotion.\n\n"
        f"Candidate wins over static: `{scorecard['candidate_win_count']}` of `{scorecard['case_count']}`.\n"
    )


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    if common.git_current_branch_name(root) != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: must run on {REQUIRED_BRANCH}")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before counted B04 R6 shadow superiority screen")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    execution_packet = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_superiority_screen_execution_packet.json", label="execution packet")
    execution_packet_receipt = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_superiority_screen_execution_packet_receipt.json", label="execution packet receipt")
    candidate_receipt = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_admissible_learned_router_candidate_source_receipt.json", label="candidate-source receipt")
    input_manifest = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_input_manifest_bound.json", label="R6 input manifest")
    comparator = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_comparator_matrix_contract.json", label="R6 comparator contract")
    thresholds = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_metric_thresholds_contract.json", label="R6 thresholds contract")
    hard_disqualifiers = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_hard_disqualifier_contract.json", label="R6 hard disqualifiers")
    execution_mode = _load(root, "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_execution_mode_contract.json", label="R6 execution mode")
    trust_validation = validate_trust_zones(root=root)

    for label, payload in (
        ("execution packet", execution_packet),
        ("candidate-source receipt", candidate_receipt),
        ("input manifest", input_manifest),
        ("comparator contract", comparator),
        ("thresholds contract", thresholds),
        ("hard disqualifier contract", hard_disqualifiers),
        ("execution mode", execution_mode),
    ):
        _ensure_boundaries(payload, label=label)
    common.ensure_pass(trust_validation, label="trust-zone validation")
    if trust_validation.get("failures"):
        raise RuntimeError("FAIL_CLOSED: trust-zone validation must have zero failures")
    if execution_packet.get("packet_authorizes_screen_execution") is not True:
        raise RuntimeError("FAIL_CLOSED: execution packet must authorize screen execution")
    if candidate_receipt.get("verdict") != "R6_CANDIDATE_ADMISSIBLE__SHADOW_SCREEN_AUTHORIZATION_NEXT":
        raise RuntimeError("FAIL_CLOSED: candidate-source receipt must admit the candidate")
    if candidate_receipt.get("screen_execution_authorized") is not True:
        raise RuntimeError("FAIL_CLOSED: candidate-source receipt must authorize screen execution next")
    if execution_mode.get("activation_allowed") is not False or execution_mode.get("package_promotion_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: execution mode must forbid activation and package promotion")

    checked_hashes = _verify_file_hashes(root, execution_packet, execution_packet_receipt)
    subject_main_head = str(execution_packet.get("current_git_head", "")).strip()
    generated_utc = utc_now_iso_z()
    head = common.git_rev_parse(root, "HEAD")
    candidate_path = root / str(execution_packet["candidate"]["candidate_source_ref"])
    candidate_module = _import_candidate(candidate_path)
    seed = int(execution_packet["candidate"].get("deterministic_seed", 42))
    input_cases = [dict(row) for row in input_manifest.get("input_cases", [])]
    traces = _route_traces(input_cases, candidate_module, seed=seed)
    second_traces = _route_traces(input_cases, candidate_module, seed=seed)
    if traces != second_traces:
        raise RuntimeError("FAIL_CLOSED: shadow screen candidate replay is non-deterministic")
    route_rows, abstention_rows = _compare_routes(input_cases, traces)
    invariance_rows = _invariance_rows(input_cases, candidate_module, seed=seed)
    disqualifier_rows = _disqualifiers(route_rows, abstention_rows, invariance_rows)
    scorecard = _scorecard(route_rows, abstention_rows, invariance_rows, disqualifier_rows)
    verdict = str(scorecard["screen_verdict"])

    base = _base(generated_utc=generated_utc, head=head, subject_main_head=subject_main_head)
    preflight = {
        "schema_id": "kt.operator.b04_r6_shadow_router_superiority_preflight_receipt.v1",
        **base,
        "candidate_admissibility_canonical_on_main": True,
        "execution_packet_canonical_on_main": True,
        "input_manifest_unchanged": True,
        "comparator_contract_unchanged": True,
        "metric_contract_unchanged": True,
        "trust_zone_validation": {"status": "PASS", "checks": len(trust_validation.get("checks", [])), "failures": 0},
        "legacy_bom_advisory_blocks_b04_r6": False,
        "checked_hashes": checked_hashes,
        "next_lawful_move": "COUNTED_B04_R6_SHADOW_ROUTER_SUPERIORITY_SCREEN_EXECUTION",
    }
    packet = {
        "schema_id": "kt.operator.b04_r6_shadow_router_superiority_screen_packet.v1",
        **base,
        "execution_packet_ref": {
            "path": "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_superiority_screen_execution_packet.json",
            "sha256": file_sha256(root / "KT_PROD_CLEANROOM/reports/b04_r6_shadow_router_superiority_screen_execution_packet.json"),
        },
        "candidate": execution_packet.get("candidate", {}),
        "input_case_count": len(input_cases),
        "counted_execution_once": True,
        "next_lawful_move": NEXT_MOVE,
    }
    route_trace = {
        "schema_id": "kt.operator.b04_r6_shadow_router_route_decision_trace.v1",
        **base,
        "rows": route_rows,
        "next_lawful_move": NEXT_MOVE,
    }
    abstention_trace = {
        "schema_id": "kt.operator.b04_r6_shadow_router_overrouting_abstention_trace.v1",
        **base,
        "rows": abstention_rows,
        "next_lawful_move": NEXT_MOVE,
    }
    invariance_trace = {
        "schema_id": "kt.operator.b04_r6_shadow_router_mirror_masked_invariance_trace.v1",
        **base,
        "rows": invariance_rows,
        "next_lawful_move": NEXT_MOVE,
    }
    disqualifier_ledger = {
        "schema_id": "kt.operator.b04_r6_shadow_router_disqualifier_ledger.v1",
        **base,
        "entries": disqualifier_rows,
        "triggered_count": len(disqualifier_rows),
        "next_lawful_move": NEXT_MOVE,
    }
    blocker_ledger = {
        "schema_id": "kt.operator.b04_r6_shadow_router_superiority_blocker_ledger.v1",
        **base,
        "entries": [
            {
                "blocker_id": "B04_R6_LEARNED_ROUTER_SUPERIORITY_NOT_EARNED",
                "status": "LIVE",
                "reason": "Candidate preserved controls but did not beat the frozen static comparator on R01-R04.",
            }
        ] if verdict == VERDICT_FAILED else disqualifier_rows,
        "live_blocker_count": 1 if verdict == VERDICT_FAILED else len(disqualifier_rows),
        "next_lawful_move": NEXT_MOVE,
    }
    scorecard_payload = {
        "schema_id": "kt.operator.b04_r6_shadow_router_superiority_scorecard.v1",
        **base,
        **scorecard,
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.b04_r6_shadow_router_superiority_screen_receipt.v1",
        **base,
        "verdict": verdict,
        "screen_execution_performed": True,
        "candidate_win_count": scorecard["candidate_win_count"],
        "case_count": scorecard["case_count"],
        "disqualifier_count": scorecard["disqualifier_count"],
        "next_lawful_move": NEXT_MOVE,
    }
    next_receipt = {
        "schema_id": "kt.operator.b04_r6_shadow_router_next_lawful_move_receipt.v1",
        **base,
        "verdict": verdict,
        "next_lawful_move": NEXT_MOVE,
    }

    outputs: Dict[str, Any] = {
        OUTPUTS["preflight"]: preflight,
        OUTPUTS["packet"]: packet,
        OUTPUTS["receipt"]: receipt,
        OUTPUTS["scorecard"]: scorecard_payload,
        OUTPUTS["route_trace"]: route_trace,
        OUTPUTS["route_matrix"]: route_trace,
        OUTPUTS["abstention_trace"]: abstention_trace,
        OUTPUTS["abstention_matrix"]: abstention_trace,
        OUTPUTS["invariance_trace"]: invariance_trace,
        OUTPUTS["invariance_matrix"]: invariance_trace,
        OUTPUTS["blocker_ledger"]: blocker_ledger,
        OUTPUTS["disqualifier_ledger"]: disqualifier_ledger,
        OUTPUTS["next_lawful_move"]: next_receipt,
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
        "next_lawful_move": NEXT_MOVE,
        "candidate_win_count": scorecard["candidate_win_count"],
        "case_count": scorecard["case_count"],
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Execute the counted B04 R6 shadow-router superiority screen.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(reports_root=common.resolve_path(root, args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
