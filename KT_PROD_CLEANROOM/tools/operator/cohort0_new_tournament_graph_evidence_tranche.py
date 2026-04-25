from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_NEW_GRAPH_PREP_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_new_tournament_graph_prep_packet.json"
DEFAULT_REEXPORT_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_entrant_authority_reexport_contract.json"
DEFAULT_GRADE_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_adapter_grade_receipt.json"
DEFAULT_FOLLOWTHROUGH_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_tournament_followthrough_packet.json"
DEFAULT_NEW_GRAPH_EVIDENCE_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_new_tournament_graph_evidence_packet.json"


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _resolve_path(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    else:
        path = path.resolve()
    return path


def _resolve_authoritative(root: Path, tracked_path: Path, ref_field: str, label: str) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(tracked_path, label=f"tracked {label}")
    authoritative_ref = str(tracked.get(ref_field, "")).strip()
    authoritative_path = _resolve_path(root, authoritative_ref) if authoritative_ref else tracked_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")


def _validate_inputs(
    *,
    prep_packet: Dict[str, Any],
    reexport_contract: Dict[str, Any],
    grade_receipt: Dict[str, Any],
    followthrough_packet: Dict[str, Any],
) -> None:
    if str(prep_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: new tournament graph prep packet must be PASS")
    if str(prep_packet.get("prep_posture", "")).strip() != "NEW_TOURNAMENT_GRAPH_REQUIRED__PREP_TARGET_BOUND":
        raise RuntimeError("FAIL_CLOSED: prep packet is not at the new-tournament-graph posture")
    if str(prep_packet.get("branch_selection_posture", "")).strip() != "NEW_TOURNAMENT_GRAPH_BRANCH_SELECTED__CHILD_CANDIDATE_BRANCH_DEFERRED":
        raise RuntimeError("FAIL_CLOSED: prep packet does not bind the selected graph branch")

    if str(reexport_contract.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: entrant reexport contract must be PASS")
    entries = reexport_contract.get("entries")
    if not isinstance(entries, list) or len(entries) != 13:
        raise RuntimeError("FAIL_CLOSED: entrant reexport contract must contain 13 entries")

    if str(grade_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: grade receipt must be PASS")
    if str(grade_receipt.get("grade", "")).strip() != "PASS_AS_STRONG_GATE_D_ADAPTER_EVIDENCE":
        raise RuntimeError("FAIL_CLOSED: grade receipt must bind strong Gate D adapter evidence")

    if str(followthrough_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: tournament followthrough packet must be PASS")
    if (
        str(followthrough_packet.get("followthrough_posture", "")).strip()
        != "MERGE_CHILD_EVALUATED__NO_ADMISSIBLE_PARENT_PAIR_EXISTS_ON_CURRENT_TOURNAMENT_GRAPH"
    ):
        raise RuntimeError("FAIL_CLOSED: followthrough packet must still bind the current-graph merge blocker")
    merge_followthrough = followthrough_packet.get("merge_followthrough") if isinstance(followthrough_packet.get("merge_followthrough"), dict) else {}
    if str(merge_followthrough.get("graph_reentry_branch_selected", "")).strip() != "NEW_TOURNAMENT_GRAPH":
        raise RuntimeError("FAIL_CLOSED: followthrough packet must already bind the new-tournament-graph branch")


def _compute_eval_axis_summary(*, root: Path, reexport_contract: Dict[str, Any]) -> Dict[str, Any]:
    entries = reexport_contract.get("entries") if isinstance(reexport_contract.get("entries"), list) else []
    adapter_rows: List[Dict[str, Any]] = []
    source_eval_stub_count = 0
    metric_probe_agreement_true_count = 0
    trace_present_count = 0
    final_verdict_pass_count = 0
    utility_scores: List[float] = []

    for row in entries:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: reexport contract entry must be object")
        adapter_id = str(row.get("adapter_id", "")).strip()
        entrant_eval_ref = str(row.get("entrant_eval_report_ref", "")).strip()
        if not adapter_id or not entrant_eval_ref:
            raise RuntimeError("FAIL_CLOSED: entrant reexport entry missing adapter_id or entrant_eval_report_ref")
        eval_path = _resolve_path(root, entrant_eval_ref)
        eval_report = _load_json_required(eval_path, label=f"entrant eval_report for {adapter_id}")
        results = eval_report.get("results") if isinstance(eval_report.get("results"), dict) else {}

        try:
            utility_floor_score = float(eval_report.get("utility_floor_score", 0.0))
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"FAIL_CLOSED: invalid utility_floor_score for {adapter_id}") from exc

        source_eval_stub = bool(row.get("source_eval_stub"))
        metric_probe_agreement = bool(results.get("metric_probe_agreement", False))
        trace_present = bool(results.get("trace_present", False))
        final_verdict_pass = str(eval_report.get("final_verdict", "")).strip().upper() == "PASS"

        source_eval_stub_count += int(source_eval_stub)
        metric_probe_agreement_true_count += int(metric_probe_agreement)
        trace_present_count += int(trace_present)
        final_verdict_pass_count += int(final_verdict_pass)
        utility_scores.append(utility_floor_score)

        adapter_rows.append(
            {
                "adapter_id": adapter_id,
                "source_eval_stub": source_eval_stub,
                "trace_present": trace_present,
                "metric_probe_agreement": metric_probe_agreement,
                "final_verdict": str(eval_report.get("final_verdict", "")).strip(),
                "utility_floor_score": utility_floor_score,
                "entrant_eval_report_ref": eval_path.as_posix(),
            }
        )

    entrant_count = len(adapter_rows)
    distinct_utility_score_count = len({float(x) for x in utility_scores})
    all_source_evals_stubbed = source_eval_stub_count == entrant_count
    all_trace_present = trace_present_count == entrant_count
    all_final_verdict_pass = final_verdict_pass_count == entrant_count
    governance_axis_flat_zero = metric_probe_agreement_true_count == 0
    utility_scores_strictly_ordered = distinct_utility_score_count == entrant_count
    utility_only_total_order = bool(
        all_source_evals_stubbed
        and all_trace_present
        and all_final_verdict_pass
        and governance_axis_flat_zero
        and utility_scores_strictly_ordered
    )

    return {
        "entrant_count": entrant_count,
        "source_eval_stub_count": source_eval_stub_count,
        "metric_probe_agreement_true_count": metric_probe_agreement_true_count,
        "trace_present_count": trace_present_count,
        "final_verdict_pass_count": final_verdict_pass_count,
        "distinct_utility_score_count": distinct_utility_score_count,
        "all_source_evals_stubbed": all_source_evals_stubbed,
        "all_trace_present": all_trace_present,
        "all_final_verdict_pass": all_final_verdict_pass,
        "governance_axis_flat_zero": governance_axis_flat_zero,
        "utility_scores_strictly_ordered": utility_scores_strictly_ordered,
        "utility_only_total_order": utility_only_total_order,
        "entries": adapter_rows,
    }


def _build_evidence_packet(
    *,
    subject_head: str,
    prep_path: Path,
    reexport_path: Path,
    grade_path: Path,
    followthrough_path: Path,
    prep_packet: Dict[str, Any],
    axis_summary: Dict[str, Any],
) -> Dict[str, Any]:
    current_graph_summary = dict(prep_packet.get("current_graph_summary", {}))
    source_eval_stub_count = int(axis_summary.get("source_eval_stub_count", 0))
    metric_probe_agreement_true_count = int(axis_summary.get("metric_probe_agreement_true_count", 0))
    utility_only_total_order = bool(axis_summary.get("utility_only_total_order"))

    if utility_only_total_order:
        evidence_posture = "NEW_TOURNAMENT_GRAPH_EVIDENCE_BLOCKED__NON_STUB_EVAL_REPORTS_REQUIRED"
        blockers = [
            "ALL_SOURCE_EVALS_STUBBED",
            "GOVERNANCE_AXIS_FLAT_ACROSS_ALL_13_ENTRANTS",
            "CURRENT_RERUN_WOULD_REPLAY_UTILITY_ONLY_TOTAL_ORDER",
        ]
        current_graph_deadlock_reason = (
            "The current tournament graph is still sourced from 13 receipt-derived stub eval reports, so "
            "format_compliance and safety_refusal_integrity are flat at PASS, governance_fidelity is flat at 0, "
            "and the graph replays as a utility-only total order."
        )
        required_new_graph_evidence = [
            "Import or emit 13 non-stub schema-bound eval_report artifacts for the same governed entrants.",
            "Bind 13 matching job_dir_manifest artifacts to those eval reports.",
            "Ensure at least one evaluation axis beyond utility differs across non-champion entrants without collapsing hard-pass law.",
            "Rebuild tournament entrant authority on the new eval evidence root before rerunning tournament.",
            "Only after the rerun, check whether admissible_parent_pair_count rises above 0.",
        ]
        next_lawful_move = "IMPORT_OR_EMIT_13_NON_STUB_EVAL_REPORTS_AND_RERUN_TOURNAMENT_ON_NEW_GRAPH"
    elif source_eval_stub_count == 0 and metric_probe_agreement_true_count > 0:
        evidence_posture = "NEW_TOURNAMENT_GRAPH_EVIDENCE_READY__NON_STUB_SUBSTRATE_EMITTED"
        blockers = []
        current_graph_deadlock_reason = (
            "The entrant substrate is no longer stub-only: all 13 eval reports are non-stub and the "
            "governance axis is no longer flat at zero, so a new tournament rerun can now test whether "
            "the prior total-order ceiling has actually been broken."
        )
        required_new_graph_evidence = [
            "Prepare a fresh fragility probe result on the new entrant authority root.",
            "Execute the tournament rerun on the new graph substrate.",
            "Then re-check whether total order breaks, admissible_parent_pair_count rises above 0, and merge reentry reopens.",
        ]
        next_lawful_move = "PREPARE_FRAGILITY_PROBE_RESULT_AND_EXECUTE_TOURNAMENT_ON_NEW_GRAPH"
    else:
        evidence_posture = "NEW_TOURNAMENT_GRAPH_EVIDENCE_BLOCKED__NON_FLAT_GOVERNANCE_AXIS_REQUIRED"
        blockers = [
            "NON_STUB_EVALS_PRESENT_BUT_GOVERNANCE_AXIS_STILL_FLAT",
            "CURRENT_RERUN_WOULD_NOT_TEST_A_STRUCTURALLY_NEW_GRAPH",
        ]
        current_graph_deadlock_reason = (
            "The entrant substrate is no longer fully stubbed, but the current eval surface still does not "
            "produce a non-flat governance axis, so rerunning tournament now would not test a materially new graph."
        )
        required_new_graph_evidence = [
            "Emit non-stub eval reports whose governance-fidelity probe is non-flat across entrants.",
            "Rebuild tournament entrant authority on that non-flat eval surface before rerunning tournament.",
        ]
        next_lawful_move = "EMIT_NON_FLAT_NON_STUB_EVAL_REPORTS_AND_RERUN_TOURNAMENT_ON_NEW_GRAPH"

    return {
        "schema_id": "kt.operator.cohort0_new_tournament_graph_evidence_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "evidence_posture": evidence_posture,
        "claim_boundary": (
            "This packet binds only the current new-graph evidence blocker. It does not rerun tournament, "
            "reopen merge, declare router authority, or widen externality/commercial surfaces."
        ),
        "current_graph_summary": current_graph_summary,
        "current_eval_axis_summary": {
            k: v for k, v in axis_summary.items() if k != "entries"
        },
        "current_graph_deadlock_reason": current_graph_deadlock_reason,
        "blockers": blockers,
        "required_new_graph_evidence": required_new_graph_evidence,
        "source_packet_refs": {
            "new_tournament_graph_prep_packet_ref": prep_path.as_posix(),
            "entrant_reexport_contract_ref": reexport_path.as_posix(),
            "adapter_grade_receipt_ref": grade_path.as_posix(),
            "followthrough_packet_ref": followthrough_path.as_posix(),
        },
        "next_lawful_move": next_lawful_move,
    }


def _build_updated_new_graph_prep_packet(
    *,
    existing_packet: Dict[str, Any],
    evidence_packet_path: Path,
    evidence_packet: Dict[str, Any],
) -> Dict[str, Any]:
    updated = dict(existing_packet)
    updated["generated_utc"] = utc_now_iso_z()
    updated["new_tournament_graph_evidence_packet_ref"] = evidence_packet_path.as_posix()
    updated["new_tournament_graph_evidence_posture"] = str(evidence_packet.get("evidence_posture", "")).strip()
    updated["next_lawful_move"] = str(evidence_packet.get("next_lawful_move", "")).strip()
    return updated


def _build_updated_followthrough_packet(
    *,
    existing_packet: Dict[str, Any],
    evidence_packet_path: Path,
    evidence_packet: Dict[str, Any],
) -> Dict[str, Any]:
    updated = dict(existing_packet)
    updated["generated_utc"] = utc_now_iso_z()
    merge_followthrough = dict(updated.get("merge_followthrough", {}))
    merge_followthrough["new_tournament_graph_evidence_packet_ref"] = evidence_packet_path.as_posix()
    merge_followthrough["new_tournament_graph_evidence_posture"] = str(evidence_packet.get("evidence_posture", "")).strip()
    merge_followthrough["current_graph_reentry_allowed"] = False
    merge_followthrough["new_graph_rerun_ready"] = str(evidence_packet.get("evidence_posture", "")).strip() == "NEW_TOURNAMENT_GRAPH_EVIDENCE_READY__NON_STUB_SUBSTRATE_EMITTED"
    merge_followthrough["next_lawful_move"] = str(evidence_packet.get("next_lawful_move", "")).strip()
    updated["merge_followthrough"] = merge_followthrough
    updated["new_tournament_graph_evidence_packet_ref"] = evidence_packet_path.as_posix()
    if merge_followthrough["new_graph_rerun_ready"]:
        updated["next_question"] = "What does the tournament rerun on the non-stub entrant graph actually earn?"
    else:
        updated["next_question"] = "Where will the 13 non-stub eval reports come from to support a real new tournament graph rerun?"
    return updated


def run_new_tournament_graph_evidence_tranche(
    *,
    new_graph_prep_report_path: Path,
    reexport_report_path: Path,
    grade_report_path: Path,
    followthrough_report_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    authoritative_prep_path, prep_packet = _resolve_authoritative(
        root,
        new_graph_prep_report_path.resolve(),
        "authoritative_new_tournament_graph_prep_packet_ref",
        "cohort0 new tournament graph prep packet",
    )
    authoritative_reexport_path, reexport_contract = _resolve_authoritative(
        root,
        reexport_report_path.resolve(),
        "authoritative_reexport_contract_ref",
        "cohort0 entrant reexport contract",
    )
    authoritative_grade_path, grade_receipt = _resolve_authoritative(
        root,
        grade_report_path.resolve(),
        "authoritative_grade_receipt_ref",
        "cohort0 real engine adapter grade receipt",
    )
    authoritative_followthrough_path, followthrough_packet = _resolve_authoritative(
        root,
        followthrough_report_path.resolve(),
        "authoritative_followthrough_packet_ref",
        "cohort0 tournament followthrough packet",
    )

    _validate_inputs(
        prep_packet=prep_packet,
        reexport_contract=reexport_contract,
        grade_receipt=grade_receipt,
        followthrough_packet=followthrough_packet,
    )
    axis_summary = _compute_eval_axis_summary(root=root, reexport_contract=reexport_contract)
    target_root = authoritative_root.resolve() if authoritative_root is not None else (authoritative_prep_path.parent / "new_tournament_graph_evidence").resolve()
    target_root.mkdir(parents=True, exist_ok=True)

    evidence_packet = _build_evidence_packet(
        subject_head=str(prep_packet.get("subject_head", "")).strip(),
        prep_path=authoritative_prep_path,
        reexport_path=authoritative_reexport_path,
        grade_path=authoritative_grade_path,
        followthrough_path=authoritative_followthrough_path,
        prep_packet=prep_packet,
        axis_summary=axis_summary,
    )
    authoritative_evidence_path = (target_root / "cohort0_new_tournament_graph_evidence_packet.json").resolve()
    write_json_stable(authoritative_evidence_path, evidence_packet)

    updated_prep_packet = _build_updated_new_graph_prep_packet(
        existing_packet=prep_packet,
        evidence_packet_path=authoritative_evidence_path,
        evidence_packet=evidence_packet,
    )
    authoritative_updated_prep_path = (target_root / "cohort0_new_tournament_graph_prep_packet.json").resolve()
    write_json_stable(authoritative_updated_prep_path, updated_prep_packet)

    updated_followthrough = _build_updated_followthrough_packet(
        existing_packet=followthrough_packet,
        evidence_packet_path=authoritative_evidence_path,
        evidence_packet=evidence_packet,
    )
    authoritative_updated_followthrough_path = (target_root / "cohort0_real_engine_tournament_followthrough_packet.json").resolve()
    write_json_stable(authoritative_updated_followthrough_path, updated_followthrough)

    reports_root.mkdir(parents=True, exist_ok=True)

    tracked_evidence = dict(evidence_packet)
    tracked_evidence["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_NEW_TOURNAMENT_GRAPH_EVIDENCE_PACKET"
    tracked_evidence["authoritative_new_tournament_graph_evidence_packet_ref"] = authoritative_evidence_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_NEW_GRAPH_EVIDENCE_REPORT_REL).name).resolve(), tracked_evidence)

    tracked_prep = dict(updated_prep_packet)
    tracked_prep["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_NEW_TOURNAMENT_GRAPH_PREP_PACKET"
    tracked_prep["authoritative_new_tournament_graph_prep_packet_ref"] = authoritative_updated_prep_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_NEW_GRAPH_PREP_REPORT_REL).name).resolve(), tracked_prep)

    tracked_followthrough = dict(updated_followthrough)
    tracked_followthrough["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_TOURNAMENT_FOLLOWTHROUGH_ARTIFACT"
    tracked_followthrough["authoritative_followthrough_packet_ref"] = authoritative_updated_followthrough_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_FOLLOWTHROUGH_REPORT_REL).name).resolve(), tracked_followthrough)

    return {
        "new_tournament_graph_evidence_packet": evidence_packet,
        "new_tournament_graph_prep_packet": updated_prep_packet,
        "followthrough_packet": updated_followthrough,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Bind the exact new-tournament-graph evidence blocker after graph-level merge exhaustion.")
    ap.add_argument(
        "--new-graph-prep-report",
        default=DEFAULT_NEW_GRAPH_PREP_REPORT_REL,
        help=f"Tracked new-tournament-graph prep report path. Default: {DEFAULT_NEW_GRAPH_PREP_REPORT_REL}",
    )
    ap.add_argument(
        "--reexport-report",
        default=DEFAULT_REEXPORT_REPORT_REL,
        help=f"Tracked entrant reexport contract path. Default: {DEFAULT_REEXPORT_REPORT_REL}",
    )
    ap.add_argument(
        "--grade-report",
        default=DEFAULT_GRADE_REPORT_REL,
        help=f"Tracked adapter grade report path. Default: {DEFAULT_GRADE_REPORT_REL}",
    )
    ap.add_argument(
        "--followthrough-report",
        default=DEFAULT_FOLLOWTHROUGH_REPORT_REL,
        help=f"Tracked tournament followthrough packet path. Default: {DEFAULT_FOLLOWTHROUGH_REPORT_REL}",
    )
    ap.add_argument(
        "--authoritative-root",
        default="",
        help="Optional authoritative output root. Default: <authoritative_prep_parent>/new_tournament_graph_evidence",
    )
    ap.add_argument(
        "--reports-root",
        default="KT_PROD_CLEANROOM/reports",
        help="Tracked carrier report root. Default: KT_PROD_CLEANROOM/reports",
    )
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_new_tournament_graph_evidence_tranche(
        new_graph_prep_report_path=_resolve_path(root, str(args.new_graph_prep_report)),
        reexport_report_path=_resolve_path(root, str(args.reexport_report)),
        grade_report_path=_resolve_path(root, str(args.grade_report)),
        followthrough_report_path=_resolve_path(root, str(args.followthrough_report)),
        authoritative_root=_resolve_path(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve_path(root, str(args.reports_root)),
        workspace_root=root,
    )
    packet = payload["new_tournament_graph_evidence_packet"]
    print(
        json.dumps(
            {
                "status": packet["status"],
                "evidence_posture": packet["evidence_posture"],
                "next_lawful_move": packet["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
