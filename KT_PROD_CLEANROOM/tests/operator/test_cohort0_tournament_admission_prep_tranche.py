from __future__ import annotations

import json
import re
from pathlib import Path

from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash
from tools.operator import cohort0_kaggle_import_tranche, cohort0_tournament_admission_prep_tranche
from tools.verification.fl3_validators import validate_schema_bound_object

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import _build_fake_kaggle_zip


ROOT = Path(__file__).resolve().parents[3]


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _parse_job_id(training_receipt: dict) -> str:
    verdict = str(training_receipt.get("training_run_verdict", "")).strip()
    match = re.search(r"\bjob_id=([0-9a-f]{64})\b", verdict)
    if not match:
        raise RuntimeError("missing job_id in training receipt verdict")
    return str(match.group(1))


def _mk_eval_report_v2(*, job_id: str, adapter_id: str, adapter_version: str, utility_floor_score: float) -> dict:
    created_at = "1970-01-01T00:00:00Z"
    rep = {
        "schema_id": "kt.factory.eval_report.v2",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.eval_report.v2.json"),
        "eval_id": "",
        "job_id": job_id,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "battery_id": "kt.eval.battery.fl4.utility_v1",
        "utility_pack_id": "UTILITY_PACK_V1",
        "utility_pack_hash": "a" * 64,
        "utility_floor_score": float(utility_floor_score),
        "utility_floor_pass": True,
        "metric_bindings": [
            {
                "metric_id": "utility_floor_score",
                "metric_version_hash": "b" * 64,
                "metric_schema_hash": "c" * 64,
                "metric_impl_hash": "d" * 64,
            }
        ],
        "metric_probes": [
            {
                "metric_id": "utility_floor_score_probe",
                "metric_impl_hash": "d" * 64,
                "delta": 0.0,
                "agreement": True,
            }
        ],
        "probe_policy": {"tolerance": 0.0, "fail_on_disagreement": True},
        "results": {
            "best_bundle_id": "B0",
            "utility_floor_score": float(utility_floor_score),
            "utility_floor_pass": True,
            "trace_required": True,
            "trace_present": True,
            "trace_coverage": 1.0,
            "trace_id": "t" * 64,
            "trace_hash": "t" * 64,
            "metric_probe_agreement": True,
        },
        "final_verdict": "PASS",
        "created_at": created_at,
    }
    rep["eval_id"] = sha256_hex_of_obj(rep, drop_keys={"created_at", "eval_id"})
    validate_schema_bound_object(rep)
    return rep


def _build_supplemental_eval_root(*, authoritative_inventory_path: Path, out_root: Path) -> None:
    inventory = json.loads(authoritative_inventory_path.read_text(encoding="utf-8"))
    entries = inventory["entries"]
    for idx, entry in enumerate(entries, start=1):
        training_receipt = json.loads(Path(str(entry["training_receipt_ref"])).read_text(encoding="utf-8"))
        eval_report = _mk_eval_report_v2(
            job_id=_parse_job_id(training_receipt),
            adapter_id=str(entry["adapter_id"]),
            adapter_version="1",
            utility_floor_score=round(0.25 + idx / 100.0, 3),
        )
        source_path = Path(str(entry["source_eval_report_path"]).lstrip("/"))
        _write_json(out_root / source_path, eval_report)


def test_cohort0_tournament_admission_prep_tranche_reexports_eval_reports_from_receipts_when_source_eval_reports_are_absent(tmp_path: Path) -> None:
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
    payload = cohort0_tournament_admission_prep_tranche.run_tournament_prep_tranche(
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

    prep_packet = payload["prep_packet"]
    reexport_contract = payload["reexport_contract"]
    assert prep_packet["status"] == "PASS"
    assert prep_packet["prep_posture"] == "TOURNAMENT_ADMISSION_READY__PENDING_FRAGILITY_AND_EXECUTION"
    assert prep_packet["next_lawful_move"] == "PREPARE_FRAGILITY_PROBE_RESULT_AND_EXECUTE_TOURNAMENT"
    assert "FRAGILITY_PROBE_RESULT_NOT_PREPARED" in prep_packet["blockers"]
    assert "ENTRANT_EVAL_REPORT_IMPORT_OR_REEXPORT_MISSING" not in prep_packet["blockers"]
    assert "ENTRANT_JOB_DIR_MANIFEST_REEXPORT_INCOMPLETE" not in prep_packet["blockers"]
    assert "ENTRANT_ROOT_HASH_BINDING_MISSING" not in prep_packet["blockers"]
    assert "TOURNAMENT_PLAN_NOT_PREPARED" not in prep_packet["blockers"]
    assert "EVALUATION_ADMISSION_PACKET_NOT_PREPARED" not in prep_packet["blockers"]
    assert reexport_contract["summary"]["reexported_train_manifest_count"] == 13
    assert reexport_contract["summary"]["reexported_training_run_manifest_count"] == 13
    assert reexport_contract["summary"]["imported_eval_report_count"] == 0
    assert reexport_contract["summary"]["reexported_eval_report_count"] == 13
    assert reexport_contract["summary"]["entrant_eval_report_count"] == 13
    assert reexport_contract["summary"]["reexported_job_dir_manifest_count"] == 13
    assert reexport_contract["summary"]["tournament_ready_entrant_dir_count"] == 13
    assert reexport_contract["summary"]["complete_tournament_entry_adapter_count"] == 13
    assert (prep_root / "cohort0_tournament_plan.json").is_file()
    assert (prep_root / "cohort0_evaluation_admission_receipt.json").is_file()
    assert reexport_contract["entries"][0]["eval_report_derivation_mode"] == "REEXPORTED_FROM_ADAPTER_EVAL_RECEIPT"
    assert reexport_contract["entries"][0]["reexported_eval_report_ref"].endswith("/eval_report.json")

    carrier_contract = json.loads((reports_root / "cohort0_entrant_authority_reexport_contract.json").read_text(encoding="utf-8"))
    carrier_prep = json.loads((reports_root / "cohort0_tournament_admission_prep_packet.json").read_text(encoding="utf-8"))
    assert carrier_contract["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_ENTRANT_REEXPORT_CONTRACT"
    assert carrier_prep["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_TOURNAMENT_ADMISSION_PREP_PACKET"


def test_cohort0_tournament_admission_prep_tranche_emits_admission_when_eval_reports_are_supplied(tmp_path: Path) -> None:
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

    supplemental_root = tmp_path / "supplemental_eval_reports"
    _build_supplemental_eval_root(
        authoritative_inventory_path=import_root / "cohort0_real_engine_adapter_inventory.json",
        out_root=supplemental_root,
    )

    prep_root = tmp_path / "prep_authoritative"
    payload = cohort0_tournament_admission_prep_tranche.run_tournament_prep_tranche(
        import_report_path=reports_root / "cohort0_real_engine_adapter_import_receipt.json",
        grade_report_path=reports_root / "cohort0_real_engine_adapter_grade_receipt.json",
        authoritative_root=prep_root,
        reports_root=reports_root,
        suite_id="SUITE_X",
        adversarial_suite_id="SUITE_X_ADV",
        lane_id="TEST_COHORT0_TOURNAMENT_PREP",
        supplemental_evidence_root=supplemental_root,
        supplemental_evidence_zip=None,
        workspace_root=ROOT,
    )

    prep_packet = payload["prep_packet"]
    reexport_contract = payload["reexport_contract"]
    assert prep_packet["status"] == "PASS"
    assert prep_packet["prep_posture"] == "TOURNAMENT_ADMISSION_READY__PENDING_FRAGILITY_AND_EXECUTION"
    assert prep_packet["next_lawful_move"] == "PREPARE_FRAGILITY_PROBE_RESULT_AND_EXECUTE_TOURNAMENT"
    assert prep_packet["packet_family_status"]["tournament_plan_emitted"] is True
    assert prep_packet["packet_family_status"]["evaluation_admission_emitted"] is True
    assert "FRAGILITY_PROBE_RESULT_NOT_PREPARED" in prep_packet["blockers"]
    assert "TOURNAMENT_PLAN_NOT_PREPARED" not in prep_packet["blockers"]
    assert "EVALUATION_ADMISSION_PACKET_NOT_PREPARED" not in prep_packet["blockers"]
    assert reexport_contract["summary"]["imported_eval_report_count"] == 13
    assert reexport_contract["summary"]["reexported_eval_report_count"] == 0
    assert reexport_contract["summary"]["entrant_eval_report_count"] == 13
    assert reexport_contract["summary"]["reexported_job_dir_manifest_count"] == 13
    assert reexport_contract["summary"]["reexported_train_manifest_count"] == 13
    assert reexport_contract["summary"]["reexported_training_run_manifest_count"] == 13
    assert reexport_contract["summary"]["tournament_ready_entrant_dir_count"] == 13
    assert reexport_contract["summary"]["complete_tournament_entry_adapter_count"] == 13
    assert (prep_root / "cohort0_tournament_plan.json").is_file()
    assert (prep_root / "cohort0_evaluation_admission_receipt.json").is_file()

    tournament_plan = json.loads((prep_root / "cohort0_tournament_plan.json").read_text(encoding="utf-8"))
    assert len(tournament_plan["entrants"]) == 13
    for entrant in tournament_plan["entrants"]:
        runner_dir = prep_root / "tournament_entrants" / entrant["adapter_root_hash"]
        assert runner_dir.is_dir()
        assert (runner_dir / "eval_report.json").is_file()
        assert (runner_dir / "job_dir_manifest.json").is_file()
    assert reexport_contract["entries"][0]["eval_report_derivation_mode"] == "IMPORTED_SOURCE_EVAL_REPORT_V2"
