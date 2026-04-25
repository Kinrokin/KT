from __future__ import annotations

import json
from pathlib import Path

from tools.operator import (
    cohort0_kaggle_import_tranche,
    cohort0_tournament_admission_prep_tranche,
    cohort0_tournament_execution_tranche,
    cohort0_tournament_fragility_probe_tranche,
)

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import _build_fake_kaggle_zip


ROOT = Path(__file__).resolve().parents[3]


def test_cohort0_tournament_fragility_probe_and_execution_tranches_advance_from_ready_to_execution(tmp_path: Path) -> None:
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
    first_prep = cohort0_tournament_admission_prep_tranche.run_tournament_prep_tranche(
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
    assert first_prep["prep_packet"]["prep_posture"] == "TOURNAMENT_ADMISSION_READY__PENDING_FRAGILITY_AND_EXECUTION"

    fragility_payload = cohort0_tournament_fragility_probe_tranche.run_tournament_fragility_probe_tranche(
        prep_report_path=reports_root / "cohort0_tournament_admission_prep_packet.json",
        authoritative_root=prep_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )
    assert fragility_payload["fragility_probe_result"]["status"] == "PASS"
    assert len(fragility_payload["fragility_probe_result"]["evaluated_adapter_root_hashes"]) == 13

    second_prep = cohort0_tournament_admission_prep_tranche.run_tournament_prep_tranche(
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
    prep_packet = second_prep["prep_packet"]
    assert prep_packet["prep_posture"] == "TOURNAMENT_EXECUTION_READY"
    assert prep_packet["next_lawful_move"] == "EXECUTE_TOURNAMENT"
    assert prep_packet["packet_family_status"]["fragility_probe_result_prepared"] is True
    assert "FRAGILITY_PROBE_RESULT_NOT_PREPARED" not in prep_packet["blockers"]
    assert prep_packet["refs"]["fragility_probe_result_ref"].endswith("/fragility_probe_result.json")

    execution_root = tmp_path / "execution_authoritative"
    execution_payload = cohort0_tournament_execution_tranche.run_tournament_execution_tranche(
        prep_report_path=reports_root / "cohort0_tournament_admission_prep_packet.json",
        authoritative_root=execution_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )
    tournament_result = execution_payload["tournament_result"]
    execution_receipt = execution_payload["tournament_execution_receipt"]
    assert tournament_result["status"] == "PASS"
    assert execution_receipt["status"] == "PASS"
    assert execution_receipt["champion_count"] >= 1
    assert len(execution_receipt["champion_set"]) == execution_receipt["champion_count"]
    assert (execution_root / "tournament_result.json").is_file()
    assert (execution_root / "evaluation_admission_receipt.json").is_file()
    assert (execution_root / "counterpressure_plan.json").is_file()
    assert (execution_root / "break_hypothesis.json").is_file()
    assert (execution_root / "fragility_probe_result.json").is_file()

    fragility_report = json.loads((reports_root / "cohort0_tournament_fragility_probe_receipt.json").read_text(encoding="utf-8"))
    execution_report = json.loads((reports_root / "cohort0_tournament_execution_receipt.json").read_text(encoding="utf-8"))
    assert fragility_report["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_TOURNAMENT_FRAGILITY_PROBE_RECEIPT"
    assert execution_report["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_TOURNAMENT_EXECUTION_RECEIPT"


def test_cohort0_tournament_execution_tranche_refuses_before_fragility_probe_is_prepared(tmp_path: Path) -> None:
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

    try:
        _ = cohort0_tournament_execution_tranche.run_tournament_execution_tranche(
            prep_report_path=reports_root / "cohort0_tournament_admission_prep_packet.json",
            authoritative_root=tmp_path / "execution_authoritative",
            reports_root=reports_root,
            workspace_root=ROOT,
        )
    except RuntimeError as exc:
        assert "TOURNAMENT_EXECUTION_READY" in str(exc)
    else:
        raise AssertionError("expected execution tranche to fail closed before fragility probe is prepared")
