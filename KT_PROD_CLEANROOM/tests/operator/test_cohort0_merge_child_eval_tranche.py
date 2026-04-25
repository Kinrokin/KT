from __future__ import annotations

import json
from pathlib import Path

from tools.operator import (
    cohort0_kaggle_import_tranche,
    cohort0_merge_child_eval_tranche,
    cohort0_promotion_merge_followthrough_tranche,
    cohort0_tournament_admission_prep_tranche,
    cohort0_tournament_execution_tranche,
    cohort0_tournament_fragility_probe_tranche,
)

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import _build_fake_kaggle_zip


ROOT = Path(__file__).resolve().parents[3]


def _run_authoritative_promotion_chain(tmp_path: Path) -> tuple[Path, Path]:
    bundle_zip = tmp_path / "cohort0_hf_20260401T135716Z_FULL_ARTIFACTS.zip"
    _build_fake_kaggle_zip(bundle_zip)

    import_root = tmp_path / "import_authoritative"
    reports_root = tmp_path / "reports"
    _ = cohort0_kaggle_import_tranche.run_import_tranche(
        bundle_zip=bundle_zip,
        authoritative_root=import_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    prep_root = tmp_path / "prep_authoritative"
    _ = cohort0_tournament_admission_prep_tranche.run_tournament_prep_tranche(
        import_report_path=reports_root / "cohort0_real_engine_adapter_import_receipt.json",
        grade_report_path=reports_root / "cohort0_real_engine_adapter_grade_receipt.json",
        authoritative_root=prep_root,
        reports_root=reports_root,
        suite_id="SUITE_X",
        adversarial_suite_id="SUITE_X_ADV",
        lane_id="TEST_COHORT0_TOURNAMENT_PREP",
        supplemental_evidence_root=None,
        supplemental_evidence_zip=None,
        workspace_root=ROOT,
    )

    _ = cohort0_tournament_fragility_probe_tranche.run_tournament_fragility_probe_tranche(
        prep_report_path=reports_root / "cohort0_tournament_admission_prep_packet.json",
        authoritative_root=prep_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    _ = cohort0_tournament_admission_prep_tranche.run_tournament_prep_tranche(
        import_report_path=reports_root / "cohort0_real_engine_adapter_import_receipt.json",
        grade_report_path=reports_root / "cohort0_real_engine_adapter_grade_receipt.json",
        authoritative_root=prep_root,
        reports_root=reports_root,
        suite_id="SUITE_X",
        adversarial_suite_id="SUITE_X_ADV",
        lane_id="TEST_COHORT0_TOURNAMENT_PREP",
        supplemental_evidence_root=None,
        supplemental_evidence_zip=None,
        workspace_root=ROOT,
    )

    execution_root = tmp_path / "execution_authoritative"
    _ = cohort0_tournament_execution_tranche.run_tournament_execution_tranche(
        prep_report_path=reports_root / "cohort0_tournament_admission_prep_packet.json",
        authoritative_root=execution_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    tracked_execution = reports_root / "cohort0_tournament_execution_receipt.json"
    tracked_payload = json.loads(tracked_execution.read_text(encoding="utf-8"))
    authoritative_execution = Path(str(tracked_payload["authoritative_tournament_execution_receipt_ref"]))
    execution_payload = json.loads(authoritative_execution.read_text(encoding="utf-8"))
    tournament_result_path = Path(str(execution_payload["tournament_result_ref"]))
    tournament_result = json.loads(tournament_result_path.read_text(encoding="utf-8"))
    ranked = cohort0_promotion_merge_followthrough_tranche._rank_entrants(tournament_result)
    winner = ranked[0]
    winner_hash = str(winner["adapter_root_hash"])
    tournament_result["champion_set"] = [winner_hash]
    tournament_result_path.write_text(
        json.dumps(tournament_result, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    execution_payload["champion_count"] = 1
    execution_payload["champion_set"] = [winner_hash]
    authoritative_execution.write_text(
        json.dumps(execution_payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    _ = cohort0_promotion_merge_followthrough_tranche.run_promotion_merge_followthrough_tranche(
        execution_report_path=tracked_execution,
        authoritative_root=execution_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )
    return execution_root, reports_root


def test_cohort0_merge_child_eval_tranche_prepares_real_child_candidate_and_fail_closes_on_recommended_parent_pair(
    tmp_path: Path,
) -> None:
    execution_root, reports_root = _run_authoritative_promotion_chain(tmp_path)

    payload = cohort0_merge_child_eval_tranche.run_merge_child_eval_tranche(
        promotion_report_path=reports_root / "cohort0_promotion_candidate_receipt.json",
        followthrough_report_path=reports_root / "cohort0_real_engine_tournament_followthrough_packet.json",
        authoritative_root=execution_root / "merge_child_eval",
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    child_candidate = payload["merge_child_candidate_receipt"]
    child_eval = payload["merge_child_evaluation_receipt"]
    merge_eval = payload["merge_eval_receipt"]

    assert child_candidate["status"] == "PASS"
    assert child_candidate["candidate_posture"] == "REAL_CHILD_CANDIDATE_BOUND_TO_RECOMMENDED_PARENT_SEEDS"
    assert child_candidate["child_candidate"]["adapter_id"]
    assert len(child_candidate["recommended_parent_seeds"]) == 2

    assert child_eval["status"] == "PASS"
    assert child_eval["merge_eval_status"] == "FAIL_CLOSED"
    assert child_eval["evaluation_posture"] == "MERGE_CHILD_EVALUATED__UTILITY_GATE_FAILED_AGAINST_RECOMMENDED_PARENT_SEEDS"
    assert child_eval["next_lawful_move"] == "PREPARE_STRONGER_CHILD_CANDIDATE_OR_RESELECT_PARENT_PAIR"

    assert merge_eval["status"] == "FAIL_CLOSED"
    assert "MERGE_UTILITY_GATE_FAILED" in merge_eval.get("reason_codes", [])

    tracked_child_candidate = json.loads(
        (reports_root / "cohort0_merge_child_candidate_receipt.json").read_text(encoding="utf-8")
    )
    tracked_child_eval = json.loads(
        (reports_root / "cohort0_merge_child_evaluation_receipt.json").read_text(encoding="utf-8")
    )
    tracked_followthrough = json.loads(
        (reports_root / "cohort0_real_engine_tournament_followthrough_packet.json").read_text(encoding="utf-8")
    )
    assert tracked_child_candidate["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_MERGE_CHILD_CANDIDATE_RECEIPT"
    assert tracked_child_eval["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_MERGE_CHILD_EVALUATION_RECEIPT"
    assert tracked_followthrough["followthrough_posture"] == "MERGE_CHILD_EVALUATED__UTILITY_GATE_FAILED_AGAINST_RECOMMENDED_PARENT_SEEDS"
    assert "MERGE_UTILITY_GATE_FAILED" in tracked_followthrough["merge_followthrough"]["blockers"]
