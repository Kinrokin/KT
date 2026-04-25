from __future__ import annotations

import json
from pathlib import Path

from schemas.fl3_schema_common import sha256_hex_of_obj
from tools.operator import (
    cohort0_merge_child_eval_tranche,
    cohort0_merge_parent_pair_admissibility_tranche,
    cohort0_new_tournament_graph_evidence_tranche,
    cohort0_new_tournament_graph_prep_tranche,
)

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_merge_child_eval_tranche import _run_authoritative_promotion_chain
from KT_PROD_CLEANROOM.tests.operator.test_cohort0_merge_parent_pair_admissibility_tranche import (
    _rewrite_fixture_to_total_order,
)


ROOT = Path(__file__).resolve().parents[3]


def test_cohort0_new_tournament_graph_evidence_tranche_binds_stub_eval_blocker(tmp_path: Path) -> None:
    execution_root, reports_root = _run_authoritative_promotion_chain(tmp_path)

    _ = cohort0_merge_child_eval_tranche.run_merge_child_eval_tranche(
        promotion_report_path=reports_root / "cohort0_promotion_candidate_receipt.json",
        followthrough_report_path=reports_root / "cohort0_real_engine_tournament_followthrough_packet.json",
        authoritative_root=execution_root / "merge_child_eval",
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    _rewrite_fixture_to_total_order(execution_root, reports_root)

    _ = cohort0_merge_parent_pair_admissibility_tranche.run_merge_parent_pair_admissibility_tranche(
        followthrough_report_path=reports_root / "cohort0_real_engine_tournament_followthrough_packet.json",
        promotion_report_path=reports_root / "cohort0_promotion_candidate_receipt.json",
        child_candidate_report_path=reports_root / "cohort0_merge_child_candidate_receipt.json",
        child_eval_report_path=reports_root / "cohort0_merge_child_evaluation_receipt.json",
        authoritative_root=execution_root / "merge_parent_pair_admissibility",
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    _ = cohort0_new_tournament_graph_prep_tranche.run_new_tournament_graph_prep_tranche(
        followthrough_report_path=reports_root / "cohort0_real_engine_tournament_followthrough_packet.json",
        parent_pair_report_path=reports_root / "cohort0_merge_parent_pair_admissibility_receipt.json",
        authoritative_root=execution_root / "new_tournament_graph_prep",
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    payload = cohort0_new_tournament_graph_evidence_tranche.run_new_tournament_graph_evidence_tranche(
        new_graph_prep_report_path=reports_root / "cohort0_new_tournament_graph_prep_packet.json",
        reexport_report_path=reports_root / "cohort0_entrant_authority_reexport_contract.json",
        grade_report_path=reports_root / "cohort0_real_engine_adapter_grade_receipt.json",
        followthrough_report_path=reports_root / "cohort0_real_engine_tournament_followthrough_packet.json",
        authoritative_root=execution_root / "new_tournament_graph_evidence",
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    evidence_packet = payload["new_tournament_graph_evidence_packet"]
    prep_packet = payload["new_tournament_graph_prep_packet"]
    followthrough = payload["followthrough_packet"]

    assert evidence_packet["status"] == "PASS"
    assert (
        evidence_packet["evidence_posture"]
        == "NEW_TOURNAMENT_GRAPH_EVIDENCE_BLOCKED__NON_STUB_EVAL_REPORTS_REQUIRED"
    )
    assert evidence_packet["current_eval_axis_summary"]["entrant_count"] == 13
    assert evidence_packet["current_eval_axis_summary"]["source_eval_stub_count"] == 13
    assert evidence_packet["current_eval_axis_summary"]["metric_probe_agreement_true_count"] == 0
    assert evidence_packet["current_eval_axis_summary"]["utility_only_total_order"] is True
    assert (
        evidence_packet["next_lawful_move"]
        == "IMPORT_OR_EMIT_13_NON_STUB_EVAL_REPORTS_AND_RERUN_TOURNAMENT_ON_NEW_GRAPH"
    )

    assert prep_packet["new_tournament_graph_evidence_posture"] == evidence_packet["evidence_posture"]
    assert prep_packet["next_lawful_move"] == evidence_packet["next_lawful_move"]
    assert followthrough["merge_followthrough"]["new_tournament_graph_evidence_posture"] == evidence_packet["evidence_posture"]
    assert followthrough["merge_followthrough"]["current_graph_reentry_allowed"] is False
    assert followthrough["merge_followthrough"]["next_lawful_move"] == evidence_packet["next_lawful_move"]

    tracked_evidence = json.loads(
        (reports_root / "cohort0_new_tournament_graph_evidence_packet.json").read_text(encoding="utf-8")
    )
    tracked_prep = json.loads(
        (reports_root / "cohort0_new_tournament_graph_prep_packet.json").read_text(encoding="utf-8")
    )
    tracked_followthrough = json.loads(
        (reports_root / "cohort0_real_engine_tournament_followthrough_packet.json").read_text(encoding="utf-8")
    )
    assert tracked_evidence["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_NEW_TOURNAMENT_GRAPH_EVIDENCE_PACKET"
    assert tracked_prep["next_lawful_move"] == evidence_packet["next_lawful_move"]
    assert tracked_followthrough["merge_followthrough"]["new_tournament_graph_evidence_posture"] == evidence_packet["evidence_posture"]


def test_cohort0_new_tournament_graph_evidence_tranche_flips_ready_when_non_stub_substrate_is_present(tmp_path: Path) -> None:
    execution_root, reports_root = _run_authoritative_promotion_chain(tmp_path)

    _ = cohort0_merge_child_eval_tranche.run_merge_child_eval_tranche(
        promotion_report_path=reports_root / "cohort0_promotion_candidate_receipt.json",
        followthrough_report_path=reports_root / "cohort0_real_engine_tournament_followthrough_packet.json",
        authoritative_root=execution_root / "merge_child_eval",
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    _rewrite_fixture_to_total_order(execution_root, reports_root)

    _ = cohort0_merge_parent_pair_admissibility_tranche.run_merge_parent_pair_admissibility_tranche(
        followthrough_report_path=reports_root / "cohort0_real_engine_tournament_followthrough_packet.json",
        promotion_report_path=reports_root / "cohort0_promotion_candidate_receipt.json",
        child_candidate_report_path=reports_root / "cohort0_merge_child_candidate_receipt.json",
        child_eval_report_path=reports_root / "cohort0_merge_child_evaluation_receipt.json",
        authoritative_root=execution_root / "merge_parent_pair_admissibility",
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    _ = cohort0_new_tournament_graph_prep_tranche.run_new_tournament_graph_prep_tranche(
        followthrough_report_path=reports_root / "cohort0_real_engine_tournament_followthrough_packet.json",
        parent_pair_report_path=reports_root / "cohort0_merge_parent_pair_admissibility_receipt.json",
        authoritative_root=execution_root / "new_tournament_graph_prep",
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    tracked_reexport = json.loads(
        (reports_root / "cohort0_entrant_authority_reexport_contract.json").read_text(encoding="utf-8")
    )
    authoritative_reexport = Path(str(tracked_reexport["authoritative_reexport_contract_ref"]))
    reexport_contract = json.loads(authoritative_reexport.read_text(encoding="utf-8"))
    for idx, entry in enumerate(reexport_contract["entries"], start=1):
        entry["source_eval_stub"] = False
        eval_path = Path(str(entry["entrant_eval_report_ref"]))
        eval_report = json.loads(eval_path.read_text(encoding="utf-8"))
        results = eval_report.setdefault("results", {})
        results["source_eval_stub"] = False
        results["metric_probe_agreement"] = idx % 2 == 0
        eval_report["eval_id"] = sha256_hex_of_obj(eval_report, drop_keys={"created_at", "eval_id"})
        eval_path.write_text(json.dumps(eval_report, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    authoritative_reexport.write_text(
        json.dumps(reexport_contract, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    payload = cohort0_new_tournament_graph_evidence_tranche.run_new_tournament_graph_evidence_tranche(
        new_graph_prep_report_path=reports_root / "cohort0_new_tournament_graph_prep_packet.json",
        reexport_report_path=reports_root / "cohort0_entrant_authority_reexport_contract.json",
        grade_report_path=reports_root / "cohort0_real_engine_adapter_grade_receipt.json",
        followthrough_report_path=reports_root / "cohort0_real_engine_tournament_followthrough_packet.json",
        authoritative_root=execution_root / "new_tournament_graph_evidence_ready",
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    evidence_packet = payload["new_tournament_graph_evidence_packet"]
    prep_packet = payload["new_tournament_graph_prep_packet"]
    followthrough = payload["followthrough_packet"]

    assert evidence_packet["status"] == "PASS"
    assert (
        evidence_packet["evidence_posture"]
        == "NEW_TOURNAMENT_GRAPH_EVIDENCE_READY__NON_STUB_SUBSTRATE_EMITTED"
    )
    assert evidence_packet["current_eval_axis_summary"]["source_eval_stub_count"] == 0
    assert evidence_packet["current_eval_axis_summary"]["metric_probe_agreement_true_count"] > 0
    assert evidence_packet["current_eval_axis_summary"]["utility_only_total_order"] is False
    assert evidence_packet["next_lawful_move"] == "PREPARE_FRAGILITY_PROBE_RESULT_AND_EXECUTE_TOURNAMENT_ON_NEW_GRAPH"

    assert prep_packet["new_tournament_graph_evidence_posture"] == evidence_packet["evidence_posture"]
    assert prep_packet["next_lawful_move"] == evidence_packet["next_lawful_move"]
    assert followthrough["merge_followthrough"]["new_graph_rerun_ready"] is True
    assert followthrough["merge_followthrough"]["next_lawful_move"] == evidence_packet["next_lawful_move"]
