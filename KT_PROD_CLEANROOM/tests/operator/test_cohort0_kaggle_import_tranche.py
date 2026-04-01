from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path

from tools.operator import cohort0_kaggle_import_tranche


ROOT = Path(__file__).resolve().parents[3]


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _sha256_file(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_head() -> str:
    return subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()


def _authoritative_ids() -> list[str]:
    reg = json.loads((ROOT / "KT_PROD_CLEANROOM" / "governance" / "adapter_registry.json").read_text(encoding="utf-8"))
    return list(reg["experimental_adapter_ids"]) + list(reg["ratified_adapter_ids"])


def _bundle_bytes_for(adapter_id: str) -> bytes:
    payload = {"adapter_id": adapter_id, "weights": "x" * 4096}
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def _build_fake_kaggle_zip(path: Path, *, stub_engine: bool = False) -> None:
    head = _git_head()
    adapter_ids = _authoritative_ids()
    build_root = path.parent / "build"
    bundle_root = build_root / "cohort0_hf_20260401T135716Z"
    full_root = bundle_root / "cohort0_full_hf"
    dry_root = bundle_root / "dry_run"
    smoke_root = bundle_root / "smoke_alpha_hf"

    for root in (full_root, dry_root, smoke_root):
        root.mkdir(parents=True, exist_ok=True)

    _write_json(bundle_root / "forge_cohort0_registry_hf_lora.json", {"registry_id": "KT_OPERATOR_FORGE_COHORT0_V1"})
    _write_json(dry_root / "discovery_receipt.json", {"status": "PASS"})
    _write_json(dry_root / "preflight_receipt.json", {"status": "PASS"})
    _write_json(dry_root / "adapter_registry.json", {"status": "PASS"})
    _write_json(dry_root / "adapter_lineage_manifest.json", {"status": "PASS"})
    _write_json(dry_root / "run_summary.json", {"status": "PASS", "adapter_count": 0})
    _write_json(dry_root / "run_manifest.json", {"verdict": "PASS", "adapter_ids": [], "artifact_hashes": [], "receipt_list": []})

    _write_json(smoke_root / "discovery_receipt.json", {"status": "PASS"})
    _write_json(smoke_root / "preflight_receipt.json", {"status": "PASS"})
    _write_json(smoke_root / "adapter_registry.json", {"status": "PASS"})
    _write_json(smoke_root / "adapter_lineage_manifest.json", {"status": "PASS"})
    _write_json(smoke_root / "run_summary.json", {"status": "PASS", "adapter_count": 1})
    _write_json(smoke_root / "run_manifest.json", {"verdict": "PASS", "adapter_ids": [adapter_ids[0]], "artifact_hashes": [], "receipt_list": []})

    artifact_hashes = []
    receipt_list = []
    for idx, adapter_id in enumerate(adapter_ids, start=1):
        adapter_root = full_root / "adapters" / adapter_id
        adapter_root.mkdir(parents=True, exist_ok=True)
        bundle = adapter_root / "adapter_bundle.zip"
        with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("adapter_model.safetensors", _bundle_bytes_for(adapter_id))
        bundle_sha = _sha256_file(bundle)
        bundle_bytes = int(bundle.stat().st_size)

        training = {
            "adapter_id": adapter_id,
            "artifact_bytes": bundle_bytes,
            "artifact_path": f"/kaggle/working/KT_FORGE_STAGE/artifacts/cohort0_hf_20260401T135716Z/cohort0_full_hf/adapters/{adapter_id}/adapter_bundle.zip",
            "artifact_sha256": bundle_sha,
            "base_model_dir": "/kaggle/working/base_model",
            "base_model_root_hash": "a" * 64,
            "base_snapshot_id": "COHORT0_STAGED_BASE_SNAPSHOT_V1",
            "base_snapshot_root_hash": "b" * 64,
            "created_at": "2026-04-01T13:58:39Z",
            "dataset_bytes": 78,
            "dataset_relpath": f"datasets/{adapter_id}/failures.jsonl",
            "dataset_sha256": f"{idx:064x}"[-64:],
            "engine": "stub" if stub_engine else "hf_lora",
            "hf_lora": None if stub_engine else {
                "batch_size": 1,
                "lora_alpha": 16,
                "lora_dropout": 0.0,
                "lora_rank": 4,
                "loss_last": 1.0,
                "lr": 0.001,
                "seq_len": 8,
                "steps": 1,
                "target_modules": ["c_attn", "c_proj", "c_fc"],
            },
            "output_name": adapter_id,
            "schema_id": "kt.operator.forge_cohort0.adapter_training_receipt.unbound.v1",
            "seed": 100 + idx,
            "source_base_model_manifest_path": f"/kaggle/working/KT/KT_PROD_CLEANROOM/exports/_runs/KT_FORGE_COHORT0_INTERNAL/cohort0_full_hf/{adapter_id}/base_model_hash_manifest.json",
            "source_eval_report_path": f"/kaggle/working/KT/KT_PROD_CLEANROOM/exports/_runs/KT_FORGE_COHORT0_INTERNAL/cohort0_full_hf/{adapter_id}/eval_report.json",
            "source_train_manifest_path": f"/kaggle/working/KT/KT_PROD_CLEANROOM/exports/_runs/KT_FORGE_COHORT0_INTERNAL/cohort0_full_hf/{adapter_id}/train_manifest.json",
            "source_training_run_manifest_path": f"/kaggle/working/KT/KT_PROD_CLEANROOM/exports/_runs/KT_FORGE_COHORT0_INTERNAL/cohort0_full_hf/{adapter_id}/training_run_manifest.PASS.json",
            "source_verdict_path": f"/kaggle/working/KT/KT_PROD_CLEANROOM/exports/_runs/KT_FORGE_COHORT0_INTERNAL/cohort0_full_hf/{adapter_id}/verdict.txt",
            "status": "PASS",
            "training_mode": "head_only" if stub_engine else "lora",
            "training_run_verdict": "KT_RAPID_LORA_PASS",
        }
        reload = {
            "adapter_id": adapter_id,
            "artifact_path": training["artifact_path"],
            "artifact_sha256": bundle_sha,
            "created_at": "2026-04-01T13:58:39Z",
            "reloaded_member_count": 1,
            "schema_id": "kt.operator.forge_cohort0.adapter_reload_receipt.unbound.v1",
            "status": "PASS",
        }
        eval_receipt = {
            "adapter_id": adapter_id,
            "artifact_path": training["artifact_path"],
            "artifact_sha256": bundle_sha,
            "baseline_eval_score": round(0.2 + idx / 1000.0, 3),
            "created_at": "2026-04-01T13:58:39Z",
            "eval_case_count": 0 if stub_engine else 6,
            "holdout_pack_path": "/kaggle/working/KT/KT-Codex/packs/KT_CORE_PRESSURE_PACK_v1/pack_manifest.json",
            "holdout_pack_sha256": "c" * 64,
            "promotion_ready_artifacts_present": True,
            "schema_id": "kt.operator.forge_cohort0.adapter_eval_receipt.unbound.v1",
            "source_eval_final_verdict": "PASS",
            "source_eval_report_path": training["source_eval_report_path"],
            "source_eval_stub": True,
            "status": "PASS",
        }
        _write_json(adapter_root / "adapter_training_receipt.json", training)
        _write_json(adapter_root / "adapter_reload_receipt.json", reload)
        _write_json(adapter_root / "adapter_eval_receipt.json", eval_receipt)

        artifact_hashes.append(
            {
                "adapter_id": adapter_id,
                "artifact_relpath": f"adapters/{adapter_id}/adapter_bundle.zip",
                "artifact_sha256": bundle_sha,
                "dataset_sha256": training["dataset_sha256"],
            }
        )
        receipt_list.extend(
            [
                f"adapters/{adapter_id}/adapter_training_receipt.json",
                f"adapters/{adapter_id}/adapter_reload_receipt.json",
                f"adapters/{adapter_id}/adapter_eval_receipt.json",
            ]
        )
        _write_json(full_root / "training_inputs" / f"{adapter_id}.train_config.json", {"adapter_id": adapter_id})
        transcript = full_root / "transcripts" / f"{adapter_id}.rapid_lora_loop.log"
        transcript.parent.mkdir(parents=True, exist_ok=True)
        transcript.write_text("rapid lora log\n", encoding="utf-8")

    _write_json(full_root / "adapter_registry.json", {"status": "PASS"})
    _write_json(full_root / "discovery_receipt.json", {"status": "PASS"})
    _write_json(full_root / "preflight_receipt.json", {"status": "PASS"})
    _write_json(full_root / "adapter_lineage_manifest.json", {"status": "PASS"})
    _write_json(
        full_root / "run_summary.json",
        {
            "adapter_count": 13,
            "created_at": "2026-04-01T13:58:39Z",
            "fail_count": 0,
            "mode": "full",
            "pass_count": 13,
            "registry_id": "KT_OPERATOR_FORGE_COHORT0_V1",
            "schema_id": "kt.operator.forge_cohort0.run_summary.unbound.v1",
            "status": "PASS",
        },
    )
    _write_json(
        full_root / "run_manifest.json",
        {
            "adapter_ids": adapter_ids,
            "artifact_hashes": artifact_hashes,
            "receipt_list": receipt_list,
            "registry_id": "KT_OPERATOR_FORGE_COHORT0_V1",
            "base_snapshot_id": "COHORT0_STAGED_BASE_SNAPSHOT_V1",
            "repo_head": head,
            "verdict": "PASS",
        },
    )
    _write_json(
        full_root / "kaggle_real_engine_gate.json",
        {
            "status": "PASS",
            "run_root": "/kaggle/working/KT_FORGE_STAGE/artifacts/cohort0_hf_20260401T135716Z/cohort0_full_hf",
            "adapter_count": 13,
            "repo_head": head,
            "registry_id": "KT_OPERATOR_FORGE_COHORT0_V1",
            "base_snapshot_id": "COHORT0_STAGED_BASE_SNAPSHOT_V1",
            "mode": "full",
            "engines": "stub_only" if stub_engine else "hf_lora_only",
        },
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(bundle_root.rglob("*")):
            zf.write(p, p.relative_to(build_root).as_posix())


def test_cohort0_kaggle_import_tranche_builds_receipts_and_followthrough(tmp_path: Path) -> None:
    bundle_zip = tmp_path / "cohort0_hf_20260401T135716Z_FULL_ARTIFACTS.zip"
    _build_fake_kaggle_zip(bundle_zip)

    authoritative_root = tmp_path / "authoritative"
    reports_root = tmp_path / "reports"
    payload = cohort0_kaggle_import_tranche.run_import_tranche(
        bundle_zip=bundle_zip,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    assert payload["import_receipt"]["status"] == "PASS"
    assert payload["grade_receipt"]["grade"] == "PASS_AS_STRONG_GATE_D_ADAPTER_EVIDENCE"
    assert payload["grade_receipt"]["ratification_effects"]["closes_open_defect_sanctioned_forge_is_stubbed"] is True
    assert payload["followthrough_packet"]["followthrough_posture"] == "CARRIER_READY__TOURNAMENT_ENTRY_AUTHORITY_BLOCKED"
    assert "ENTRANT_EVAL_REPORT_IMPORT_MISSING" in payload["followthrough_packet"]["tournament_followthrough"]["blockers"]
    assert "ENTRANT_JOB_DIR_MANIFEST_IMPORT_MISSING" in payload["followthrough_packet"]["tournament_followthrough"]["blockers"]
    assert (reports_root / "cohort0_real_engine_adapter_import_receipt.json").is_file()
    assert (reports_root / "cohort0_real_engine_adapter_grade_receipt.json").is_file()
    assert (reports_root / "cohort0_real_engine_tournament_followthrough_packet.json").is_file()


def test_cohort0_kaggle_import_tranche_rejects_stub_engine_bundle(tmp_path: Path) -> None:
    bundle_zip = tmp_path / "cohort0_stub_20260401T135716Z_FULL_ARTIFACTS.zip"
    _build_fake_kaggle_zip(bundle_zip, stub_engine=True)

    authoritative_root = tmp_path / "authoritative"
    reports_root = tmp_path / "reports"
    try:
        _ = cohort0_kaggle_import_tranche.run_import_tranche(
            bundle_zip=bundle_zip,
            authoritative_root=authoritative_root,
            reports_root=reports_root,
            workspace_root=ROOT,
        )
    except RuntimeError as exc:
        assert "training engine must be hf_lora" in str(exc)
    else:
        raise AssertionError("expected stub-engine bundle to fail closed")
