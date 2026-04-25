from __future__ import annotations

import json
import zipfile
from pathlib import Path

from tools.operator import cohort0_targeted_hypertraining_import_tranche


ROOT = Path(__file__).resolve().parents[3]


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _sha256_file(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _bundle_bytes_for(adapter_id: str) -> bytes:
    payload = {"adapter_id": adapter_id, "weights": "x" * 4096}
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def _make_stage_contracts(root: Path) -> tuple[Path, Path, Path, Path, list[str]]:
    target_ids = [
        "lobe.p2.v1",
        "lobe.child.v1",
        "lobe.strategist.v1",
        "lobe.beta.v1",
        "lobe.scout.v1",
        "lobe.auditor.v1",
    ]
    stage_root = root / "stage"
    manifest_path = root / "cohort0_targeted_hypertraining_stage_input_manifest.json"
    kaggle_packet_path = root / "cohort0_targeted_hypertraining_kaggle_packet.json"
    freeze_boundary_path = root / "stage_freeze_boundary.json"
    receipt_path = root / "cohort0_targeted_hypertraining_stage_input_receipt.json"

    dataset_rows = []
    freeze_rows = []
    for idx, adapter_id in enumerate(target_ids, start=1):
        dataset_path = stage_root / "datasets" / adapter_id / "failures.jsonl"
        config_path = stage_root / "configs" / f"{adapter_id}.targeted_hypertraining_config.json"
        dataset_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        dataset_path.write_text(json.dumps({"adapter_id": adapter_id, "row": idx}, sort_keys=True) + "\n", encoding="utf-8")
        config_path.write_text(json.dumps({"adapter_id": adapter_id, "seed": 5000 + idx}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        dataset_rows.append(
            {
                "adapter_id": adapter_id,
                "family_id": f"FAMILY_{idx}",
                "config_relpath": f"configs/{adapter_id}.targeted_hypertraining_config.json",
                "dataset_relpath": f"datasets/{adapter_id}/failures.jsonl",
                "sha256": _sha256_file(dataset_path),
                "line_count": 1,
            }
        )
        freeze_rows.append(
            {
                "adapter_id": adapter_id,
                "config_relpath": f"configs/{adapter_id}.targeted_hypertraining_config.json",
                "config_sha256": _sha256_file(config_path),
                "dataset_relpath": f"datasets/{adapter_id}/failures.jsonl",
                "dataset_sha256": _sha256_file(dataset_path),
                "family_id": f"FAMILY_{idx}",
                "line_count": 1,
            }
        )

    _write_json(manifest_path, {"schema_id": "kt.operator.cohort0_targeted_hypertraining_stage_input_manifest.v1", "current_git_head": "freeze-head-1", "dataset_rows": dataset_rows})
    _write_json(
        kaggle_packet_path,
        {
            "schema_id": "kt.operator.cohort0_targeted_hypertraining_kaggle_packet.v1",
            "current_git_head": "freeze-head-1",
            "execution_mode": "KAGGLE_GPU_HEAVY_TARGETED_SIX_LOBE",
            "all_in_one_window": {"start_index": 1, "end_index": 6, "target_lobe_ids": target_ids},
        },
    )
    _write_json(
        freeze_boundary_path,
        {
            "schema_id": "kt.operator.cohort0_targeted_hypertraining_stage_freeze_boundary.v1",
            "current_git_head": "freeze-head-1",
            "dataset_rows": freeze_rows,
            "contract_hashes": {"dataset_manifest": _sha256_file(manifest_path), "kaggle_packet": _sha256_file(kaggle_packet_path)},
        },
    )
    _write_json(
        receipt_path,
        {
            "schema_id": "kt.operator.cohort0_targeted_hypertraining_stage_input_receipt.v1",
            "status": "PASS",
            "current_git_head": "freeze-head-1",
            "subject_head": "subject-head-1",
            "stage_input_posture": "SIX_LOBE_TARGETED_STAGE_INPUTS_BOUND__KAGGLE_HYPERTRAINING_READY__COUNTED_LANE_STILL_CLOSED",
            "target_lobe_ids": target_ids,
        },
    )
    return receipt_path, manifest_path, kaggle_packet_path, freeze_boundary_path, target_ids


def _build_fake_targeted_zip(path: Path, *, stage_manifest_path: Path, kaggle_packet_path: Path, freeze_boundary_path: Path, target_ids: list[str]) -> None:
    manifest = json.loads(stage_manifest_path.read_text(encoding="utf-8"))
    stage_rows = {row["adapter_id"]: row for row in manifest["dataset_rows"]}
    freeze = json.loads(freeze_boundary_path.read_text(encoding="utf-8"))
    freeze_rows = {row["adapter_id"]: row for row in freeze["dataset_rows"]}
    build_root = path.parent / "build"
    bundle_root = build_root / "cohort0_targeted_hypertraining"
    bundle_root.mkdir(parents=True, exist_ok=True)
    artifact_hashes = []
    for idx, adapter_id in enumerate(target_ids, start=1):
        adapter_root = bundle_root / "adapters" / adapter_id
        adapter_root.mkdir(parents=True, exist_ok=True)
        artifact_path = adapter_root / "adapter_bundle.zip"
        with zipfile.ZipFile(artifact_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("adapter_model.safetensors", _bundle_bytes_for(adapter_id))
        artifact_sha = _sha256_file(artifact_path)
        artifact_bytes = int(artifact_path.stat().st_size)
        dataset_sha = str(stage_rows[adapter_id]["sha256"])
        _write_json(adapter_root / "adapter_training_receipt.json", {"adapter_id": adapter_id, "artifact_bytes": artifact_bytes, "artifact_path": f"/kaggle/working/{adapter_id}/adapter_bundle.zip", "artifact_sha256": artifact_sha, "base_model_root_hash": f"{idx:064x}"[-64:], "base_snapshot_id": "COHORT0_STAGED_BASE_SNAPSHOT_V1", "created_at": "2026-04-12T18:38:36Z", "dataset_bytes": 128, "dataset_relpath": stage_rows[adapter_id]["dataset_relpath"], "dataset_sha256": dataset_sha, "engine": "hf_lora", "hf_lora": {"trainer": "tools.training.phase2_train"}, "output_name": adapter_id, "schema_id": "kt.operator.forge_cohort0.adapter_training_receipt.unbound.v1", "seed": 5100 + idx, "status": "PASS", "training_mode": "lora"})
        _write_json(adapter_root / "adapter_reload_receipt.json", {"adapter_id": adapter_id, "artifact_path": f"/kaggle/working/{adapter_id}/adapter_bundle.zip", "artifact_sha256": artifact_sha, "created_at": "2026-04-12T18:38:36Z", "reloaded_member_count": 3, "schema_id": "kt.operator.forge_cohort0.adapter_reload_receipt.unbound.v1", "status": "PASS"})
        _write_json(adapter_root / "adapter_eval_receipt.json", {"adapter_id": adapter_id, "artifact_path": f"/kaggle/working/{adapter_id}/adapter_bundle.zip", "artifact_sha256": artifact_sha, "baseline_eval_score": 0.20 + idx / 100.0, "created_at": "2026-04-12T18:38:36Z", "eval_case_count": 1, "holdout_pack_path": "/kaggle/working/pack.json", "holdout_pack_sha256": "e" * 64, "promotion_ready_artifacts_present": True, "schema_id": "kt.operator.forge_cohort0.adapter_eval_receipt.unbound.v1", "source_eval_final_verdict": "PASS", "source_eval_report_path": f"/kaggle/working/{adapter_id}/eval_report.json", "source_eval_stub": False, "status": "PASS"})
        _write_json(adapter_root / "eval_report.json", {"schema_id": "kt.factory.eval_report.v2", "adapter_id": adapter_id, "adapter_version": "1", "battery_id": "kt.eval.battery.fl4.adapter_bundle_probe_v1", "created_at": "2026-04-12T18:38:44Z", "eval_id": f"eval-{idx}", "final_verdict": "PASS", "job_id": f"{idx:064x}"[-64:], "results": {"metric_probe_agreement": True, "trace_present": True, "trace_required": True, "source_eval_stub": False, "param_count": 5111808}, "utility_floor_pass": True, "utility_floor_score": 0.60 + idx / 100.0})
        _write_json(adapter_root / "job_dir_manifest.json", {"schema_id": "kt.factory.job_dir_manifest.v1", "job_id": f"{idx:064x}"[-64:], "adapter_id": adapter_id})
        _write_json(adapter_root / "train_manifest.json", {"schema_id": "kt.factory.train_manifest.v1", "job_id": f"{idx:064x}"[-64:], "adapter_id": adapter_id})
        _write_json(adapter_root / "train_receipt.json", {"status": "PASS", "adapter_id": adapter_id})
        _write_json(adapter_root / "training_config.json", {"adapter_id": adapter_id, "config_sha256": freeze_rows[adapter_id]["config_sha256"]})
        _write_json(adapter_root / "training_report.json", {"status": "PASS", "adapter_id": adapter_id})
        _write_json(adapter_root / "training_run_manifest.PASS.json", {"status": "PASS", "adapter_id": adapter_id})
        _write_json(adapter_root / "dataset_hash_manifest.json", {"adapter_id": adapter_id, "dataset_sha256": dataset_sha})
        _write_json(adapter_root / "reasoning_trace.json", {"adapter_id": adapter_id, "trace_present": True})
        (adapter_root / "verdict.txt").write_text("PASS\n", encoding="utf-8")
        artifact_hashes.append({"adapter_id": adapter_id, "artifact_relpath": f"adapters/{adapter_id}/adapter_bundle.zip", "artifact_sha256": artifact_sha, "dataset_sha256": dataset_sha})

    _write_json(bundle_root / "adapter_registry.json", {"status": "PASS"})
    _write_json(bundle_root / "adapter_lineage_manifest.json", {"status": "PASS"})
    _write_json(bundle_root / "discovery_receipt.json", {"status": "PASS"})
    _write_json(bundle_root / "preflight_receipt.json", {"status": "PASS"})
    _write_json(bundle_root / "run_manifest.json", {"adapter_ids": target_ids, "artifact_hashes": artifact_hashes, "base_snapshot_id": "COHORT0_STAGED_BASE_SNAPSHOT_V1", "created_at": "2026-04-12T18:38:44Z", "mode": "targeted_hypertraining", "receipt_list": [], "registry_id": "KT_OPERATOR_FORGE_COHORT0_TARGETED_HYPERTRAINING_V1", "repo_head": "subject-head-1", "schema_id": "kt.operator.forge_cohort0.run_manifest.unbound.v1", "subject_head": "subject-head-1", "verdict": "PASS"})
    _write_json(bundle_root / "run_summary.json", {"adapter_count": 6, "fail_count": 0, "mode": "targeted_hypertraining", "pass_count": 6, "registry_id": "KT_OPERATOR_FORGE_COHORT0_TARGETED_HYPERTRAINING_V1", "status": "PASS"})
    _write_json(bundle_root / "targeted_hypertraining_run_receipt.json", {"status": "PASS", "adapter_count": 6, "repo_head": "subject-head-1", "registry_id": "KT_OPERATOR_FORGE_COHORT0_TARGETED_HYPERTRAINING_V1", "run_summary_status": "PASS", "run_manifest_verdict": "PASS"})
    _write_json(bundle_root / "stage_hash_validation_receipt.json", {"schema_id": "kt.operator.targeted_hypertraining.stage_hash_validation_receipt.v1", "status": "PASS", "created_at": "2026-04-12T18:38:35Z", "current_git_head": "freeze-head-1", "subject_head": "subject-head-1", "dataset_manifest_sha256": _sha256_file(stage_manifest_path), "freeze_boundary_sha256": _sha256_file(freeze_boundary_path), "kaggle_packet_sha256": _sha256_file(kaggle_packet_path), "rows": [{"adapter_id": adapter_id, "config_path": f"/kaggle/input/{adapter_id}.json", "config_sha256": freeze_rows[adapter_id]["config_sha256"], "dataset_path": f"/kaggle/input/{adapter_id}.jsonl", "dataset_sha256": freeze_rows[adapter_id]["dataset_sha256"], "line_count": 1} for adapter_id in target_ids]})
    training_inputs = bundle_root / "training_inputs"
    training_inputs.mkdir(parents=True, exist_ok=True)
    transcripts = bundle_root / "transcripts"
    transcripts.mkdir(parents=True, exist_ok=True)
    for adapter_id in target_ids:
        _write_json(training_inputs / f"{adapter_id}.json", {"adapter_id": adapter_id})
        (transcripts / f"{adapter_id}.phase2_train.log").write_text("log\n", encoding="utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(bundle_root.rglob("*")):
            zf.write(p, p.relative_to(build_root).as_posix())


def test_targeted_hypertraining_import_tranche_imports_real_six_lobe_bundle(tmp_path: Path) -> None:
    receipt_path, manifest_path, kaggle_packet_path, freeze_boundary_path, target_ids = _make_stage_contracts(tmp_path / "contracts")
    bundle_zip = tmp_path / "cohort0_targeted_hypertraining_six_lobe_FULL_ARTIFACTS.zip"
    _build_fake_targeted_zip(bundle_zip, stage_manifest_path=manifest_path, kaggle_packet_path=kaggle_packet_path, freeze_boundary_path=freeze_boundary_path, target_ids=target_ids)
    authoritative_root = tmp_path / "authoritative"
    reports_root = tmp_path / "reports"
    payload = cohort0_targeted_hypertraining_import_tranche.run_targeted_hypertraining_import_tranche(bundle_zip=bundle_zip, authoritative_root=authoritative_root, reports_root=reports_root, stage_input_receipt_path=receipt_path, stage_manifest_path=manifest_path, dataset_manifest_path=manifest_path, kaggle_packet_path=kaggle_packet_path, freeze_boundary_path=freeze_boundary_path, workspace_root=ROOT)
    assert payload["import_receipt"]["status"] == "PASS"
    assert payload["grade_receipt"]["grade"] == "PASS_AS_STRONGER_CYCLE_TARGETED_HYPERTRAINING_EVIDENCE"
    assert payload["followthrough_packet"]["followthrough_posture"] == "TARGETED_HYPERTRAINING_IMPORTED__COMPOSITE_13_ENTRANT_SUBSTRATE_REQUIRED"
    assert payload["followthrough_packet"]["composite_substrate_requirement"]["required_total_entrant_count"] == 13
    assert payload["followthrough_packet"]["imported_targeted_lobe_ids"] == target_ids
    tracked = json.loads((reports_root / "cohort0_targeted_hypertraining_import_receipt.json").read_text(encoding="utf-8"))
    assert tracked["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_TARGETED_HYPERTRAINING_IMPORT_RECEIPT"
