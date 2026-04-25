from __future__ import annotations

import json
from pathlib import Path

from tools.operator import (
    cohort0_kaggle_import_tranche,
    cohort0_promotion_merge_followthrough_tranche,
    cohort0_tournament_admission_prep_tranche,
    cohort0_tournament_execution_tranche,
    cohort0_tournament_fragility_probe_tranche,
)

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import _build_fake_kaggle_zip


ROOT = Path(__file__).resolve().parents[3]


def _run_authoritative_tournament_chain(tmp_path: Path) -> tuple[Path, Path]:
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
    return execution_root, reports_root


def test_cohort0_promotion_merge_followthrough_tranche_identifies_champion_and_blocks_merge_until_child_exists(
    tmp_path: Path,
) -> None:
    execution_root, reports_root = _run_authoritative_tournament_chain(tmp_path)
    tracked_execution = reports_root / "cohort0_tournament_execution_receipt.json"
    tracked_payload = json.loads(tracked_execution.read_text(encoding="utf-8"))
    authoritative_execution = Path(str(tracked_payload["authoritative_tournament_execution_receipt_ref"]))
    execution_payload = json.loads(authoritative_execution.read_text(encoding="utf-8"))
    tournament_result = json.loads(Path(str(execution_payload["tournament_result_ref"])).read_text(encoding="utf-8"))
    ranked = cohort0_promotion_merge_followthrough_tranche._rank_entrants(tournament_result)
    winner = ranked[0]
    winner_hash = str(winner["adapter_root_hash"])
    winner_id = str(winner["adapter_id"])

    tournament_result["champion_set"] = [winner_hash]
    Path(str(execution_payload["tournament_result_ref"])).write_text(
        json.dumps(tournament_result, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    execution_payload["champion_count"] = 1
    execution_payload["champion_set"] = [winner_hash]
    authoritative_execution.write_text(
        json.dumps(execution_payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    payload = cohort0_promotion_merge_followthrough_tranche.run_promotion_merge_followthrough_tranche(
        execution_report_path=tracked_execution,
        authoritative_root=execution_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    promotion = payload["promotion_candidate_receipt"]
    followthrough = payload["followthrough_packet"]

    assert promotion["status"] == "PASS"
    assert promotion["candidate_posture"] == "UNIQUE_TOURNAMENT_CHAMPION_IDENTIFIED__MERGE_CHILD_PREP_REQUIRED"
    assert promotion["candidate"]["adapter_id"] == winner_id
    assert promotion["candidate"]["is_champion"] is True
    assert promotion["candidate"]["rank"] == 1
    assert promotion["tournament_summary"]["champion_count"] == 1

    assert followthrough["status"] == "PASS"
    assert (
        followthrough["followthrough_posture"]
        == "TOURNAMENT_EXECUTED__PROMOTION_CANDIDATE_IDENTIFIED__MERGE_CHILD_PREP_REQUIRED"
    )
    assert followthrough["promotion_followthrough"]["candidate_adapter_id"] == winner_id
    assert followthrough["merge_followthrough"]["recommended_parent_seed_count"] == 2
    assert followthrough["merge_followthrough"]["recommended_parent_seeds"][0]["adapter_id"] != winner_id
    assert followthrough["merge_followthrough"]["recommended_parent_seeds"][1]["adapter_id"] != winner_id
    assert followthrough["merge_followthrough"]["blockers"] == [
        "MERGE_CHILD_CANDIDATE_ARTIFACT_NOT_PREPARED",
        "MERGE_CHILD_EVAL_REPORT_NOT_PREPARED",
        "MERGE_MANIFEST_NOT_PREPARED",
        "MERGE_EVAL_RECEIPT_NOT_PREPARED",
        "MERGE_ROLLBACK_PLAN_NOT_PREPARED",
    ]
    assert (
        followthrough["merge_followthrough"]["next_lawful_move"]
        == "PREPARE_SCHEMA_BOUND_MERGE_CHILD_CANDIDATE_AND_CHILD_EVAL_AGAINST_RECOMMENDED_PARENT_SEEDS"
    )

    tracked_promotion = json.loads(
        (reports_root / "cohort0_promotion_candidate_receipt.json").read_text(encoding="utf-8")
    )
    tracked_followthrough = json.loads(
        (reports_root / "cohort0_real_engine_tournament_followthrough_packet.json").read_text(encoding="utf-8")
    )
    assert tracked_promotion["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_PROMOTION_CANDIDATE_RECEIPT"
    assert tracked_followthrough["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_TOURNAMENT_FOLLOWTHROUGH_ARTIFACT"


def test_cohort0_promotion_merge_followthrough_tranche_refuses_when_tournament_has_no_unique_champion(
    tmp_path: Path,
) -> None:
    execution_root, reports_root = _run_authoritative_tournament_chain(tmp_path)

    try:
        _ = cohort0_promotion_merge_followthrough_tranche.run_promotion_merge_followthrough_tranche(
            execution_report_path=reports_root / "cohort0_tournament_execution_receipt.json",
            authoritative_root=execution_root,
            reports_root=reports_root,
            workspace_root=ROOT,
        )
    except RuntimeError as exc:
        assert "exactly one tournament champion" in str(exc)
    else:
        raise AssertionError("expected followthrough tranche to fail closed without a unique champion")
