from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path

from tools.operator import cohort0_targeted_hypertraining_stage_input_tranche

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT


def _init_git_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init"], cwd=str(path), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    subprocess.run(["git", "config", "user.email", "codex@example.com"], cwd=str(path), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    subprocess.run(["git", "config", "user.name", "Codex"], cwd=str(path), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    (path / "README.txt").write_text("targeted hypertraining tranche test\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.txt"], cwd=str(path), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(path), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def test_targeted_hypertraining_stage_input_tranche_binds_six_lobe_pack(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspace"
    _init_git_repo(workspace_root)

    kt_stage_root = tmp_path / "KT_FORGE_STAGE"
    reports_root = workspace_root / "reports"
    authoritative_root = workspace_root / "authoritative"
    stage_root = kt_stage_root / "kaggle_stage_pack" / "kt-targeted-hypertraining-stage"
    mirror_root = kt_stage_root / "input_root_targeted_hypertraining"
    zip_path = kt_stage_root / "kaggle_stage_pack" / "kt-targeted-hypertraining-stage.zip"
    stage_manifest_path = kt_stage_root / "kaggle_stage_pack" / "cohort0_targeted_hypertraining_stage_pack_manifest.json"
    build_receipt_path = kt_stage_root / "kaggle_stage_pack" / "cohort0_targeted_hypertraining_stage_input_build_receipt.json"
    readme_path = kt_stage_root / "kaggle_stage_pack" / "TARGETED_HYPERTRAINING_README.txt"

    payload = cohort0_targeted_hypertraining_stage_input_tranche.run_targeted_hypertraining_stage_input_tranche(
        oracle_receipt_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "oracle_router_local_receipt.json",
        oracle_scorecard_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "oracle_router_local_scorecard.json",
        stage_pack_manifest_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "route_bearing_stage_pack_manifest.json",
        alpha_manifest_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "alpha_should_lose_here_manifest.json",
        forge_registry_path=ROOT / "KT_PROD_CLEANROOM" / "tools" / "operator" / "config" / "forge_cohort0_registry.json",
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        stage_root=stage_root,
        mirror_input_root=mirror_root,
        zip_path=zip_path,
        stage_manifest_path=stage_manifest_path,
        receipt_path=build_receipt_path,
        readme_path=readme_path,
        force=True,
        workspace_root=workspace_root,
    )

    manifest = payload["cohort0_targeted_hypertraining_stage_input_manifest"]
    index = payload["cohort0_targeted_hypertraining_stage_input_index"]
    kaggle_packet = payload["cohort0_targeted_hypertraining_kaggle_packet"]
    receipt = payload["cohort0_targeted_hypertraining_stage_input_receipt"]

    assert manifest["status"] == "PASS"
    assert manifest["stage_input_posture"] == "SIX_LOBE_TARGETED_STAGE_INPUTS_BOUND__KAGGLE_HYPERTRAINING_READY__COUNTED_LANE_STILL_CLOSED"
    assert manifest["target_lobe_ids"] == cohort0_targeted_hypertraining_stage_input_tranche.TARGET_LOBE_IDS
    assert len(manifest["dataset_rows"]) == 6
    assert all(row["line_count"] == 192 for row in manifest["dataset_rows"])

    assert index["status"] == "PASS"
    assert index["dataset_count"] == 6

    assert kaggle_packet["status"] == "PASS"
    assert kaggle_packet["trainer_module"] == "tools.training.phase2_train"
    assert [row["shard_id"] for row in kaggle_packet["recommended_shards"]] == ["SHARD_01", "SHARD_02", "SHARD_03"]
    assert kaggle_packet["all_in_one_window"] == {
        "start_index": 1,
        "end_index": 6,
        "target_lobe_ids": cohort0_targeted_hypertraining_stage_input_tranche.TARGET_LOBE_IDS,
    }
    first_command = kaggle_packet["recommended_shards"][0]["commands"][0]["command_template"]
    assert "tools.training.phase2_train" in first_command
    assert "--allow-legacy" in first_command

    assert receipt["status"] == "PASS"
    assert receipt["next_lawful_move"] == "EXECUTE_TARGETED_HYPERTRAINING_ON_KAGGLE_FOR_ORACLE_POSITIVE_LOBES"
    assert receipt["target_lobe_ids"] == cohort0_targeted_hypertraining_stage_input_tranche.TARGET_LOBE_IDS

    targeted_manifest = json.loads((stage_root / "datasets" / "cohort0_targeted_hypertraining_dataset_manifest.json").read_text(encoding="utf-8"))
    assert targeted_manifest["status"] == "PASS"
    assert len(targeted_manifest["entries"]) == 6
    assert (stage_root / "contracts" / "kaggle_packet.json").is_file()
    assert (stage_root / "contracts" / "stage_freeze_boundary.json").is_file()
    assert readme_path.is_file()
    assert zip_path.is_file()

    with zipfile.ZipFile(zip_path) as zf:
        members = set(zf.namelist())
    assert "kt-targeted-hypertraining-stage/datasets/cohort0_targeted_hypertraining_dataset_manifest.json" in members
    assert "kt-targeted-hypertraining-stage/configs/lobe.p2.v1.targeted_hypertraining_config.json" in members
    assert "kt-targeted-hypertraining-stage/datasets/lobe.auditor.v1/failures.jsonl" in members
    assert "kt-targeted-hypertraining-stage/contracts/stage_freeze_boundary.json" in members

    tracked_receipt = json.loads((reports_root / "cohort0_targeted_hypertraining_stage_input_receipt.json").read_text(encoding="utf-8"))
    assert tracked_receipt["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_TARGETED_HYPERTRAINING_STAGE_INPUT_RECEIPT"
