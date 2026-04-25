from __future__ import annotations

import json
from pathlib import Path

from tools.operator import (
    cohort0_merge_child_eval_tranche,
    cohort0_merge_parent_pair_admissibility_tranche,
    cohort0_new_tournament_graph_prep_tranche,
)

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_merge_child_eval_tranche import _run_authoritative_promotion_chain
from KT_PROD_CLEANROOM.tests.operator.test_cohort0_merge_parent_pair_admissibility_tranche import (
    _rewrite_fixture_to_total_order,
)


ROOT = Path(__file__).resolve().parents[3]


def test_cohort0_new_tournament_graph_prep_tranche_selects_graph_branch_after_zero_pair_blocker(
    tmp_path: Path,
) -> None:
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

    payload = cohort0_new_tournament_graph_prep_tranche.run_new_tournament_graph_prep_tranche(
        followthrough_report_path=reports_root / "cohort0_real_engine_tournament_followthrough_packet.json",
        parent_pair_report_path=reports_root / "cohort0_merge_parent_pair_admissibility_receipt.json",
        authoritative_root=execution_root / "new_tournament_graph_prep",
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    prep_packet = payload["new_tournament_graph_prep_packet"]
    followthrough = payload["followthrough_packet"]

    assert prep_packet["status"] == "PASS"
    assert prep_packet["prep_posture"] == "NEW_TOURNAMENT_GRAPH_REQUIRED__PREP_TARGET_BOUND"
    assert prep_packet["branch_selection_posture"] == "NEW_TOURNAMENT_GRAPH_BRANCH_SELECTED__CHILD_CANDIDATE_BRANCH_DEFERRED"
    assert (
        prep_packet["next_lawful_move"]
        == "PREPARE_SCHEMA_BOUND_NEW_TOURNAMENT_GRAPH_EVIDENCE_AND_RERUN_TOURNAMENT"
    )
    assert prep_packet["current_graph_summary"]["admissible_parent_pair_count"] == 0
    assert prep_packet["current_graph_summary"]["total_order_across_all_entrants"] is True
    assert prep_packet["current_graph_summary"]["non_champion_total_order"] is True

    assert (
        followthrough["followthrough_posture"]
        == "MERGE_CHILD_EVALUATED__NO_ADMISSIBLE_PARENT_PAIR_EXISTS_ON_CURRENT_TOURNAMENT_GRAPH"
    )
    assert followthrough["merge_followthrough"]["graph_reentry_branch_selected"] == "NEW_TOURNAMENT_GRAPH"
    assert followthrough["merge_followthrough"]["child_candidate_branch_deferred"] is True
    assert followthrough["merge_followthrough"]["current_graph_reentry_allowed"] is False
    assert (
        followthrough["merge_followthrough"]["next_lawful_move"]
        == "PREPARE_SCHEMA_BOUND_NEW_TOURNAMENT_GRAPH_EVIDENCE_AND_RERUN_TOURNAMENT"
    )

    tracked_prep = json.loads(
        (reports_root / "cohort0_new_tournament_graph_prep_packet.json").read_text(encoding="utf-8")
    )
    tracked_followthrough = json.loads(
        (reports_root / "cohort0_real_engine_tournament_followthrough_packet.json").read_text(encoding="utf-8")
    )
    assert tracked_prep["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_NEW_TOURNAMENT_GRAPH_PREP_PACKET"
    assert tracked_followthrough["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_TOURNAMENT_FOLLOWTHROUGH_ARTIFACT"
    assert tracked_followthrough["merge_followthrough"]["graph_reentry_branch_selected"] == "NEW_TOURNAMENT_GRAPH"
