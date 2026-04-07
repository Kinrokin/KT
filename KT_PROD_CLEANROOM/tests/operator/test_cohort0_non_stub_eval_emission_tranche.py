from __future__ import annotations

import io
import json
import tempfile
import zipfile
from pathlib import Path

import pytest

from tools.operator import cohort0_kaggle_import_tranche, cohort0_non_stub_eval_emission_tranche

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import (
    ROOT,
    _authoritative_ids,
    _git_head,
    _sha256_file,
    _write_json,
)


def _real_bundle_bytes(*, adapter_id: str, idx: int) -> bytes:
    torch = pytest.importorskip("torch")
    _ = pytest.importorskip("safetensors")
    from safetensors.torch import save_file

    if idx <= 8:
        tensor = torch.full((16,), 0.02 * idx, dtype=torch.float32)
    else:
        tensor = torch.zeros(16, dtype=torch.float32)
        tensor[0] = 0.3 + (0.05 * (idx - 8))
        tensor[1] = 0.1 * ((idx - 8) % 2)

    with tempfile.TemporaryDirectory() as td:
        safetensors_path = Path(td) / "adapter_model.safetensors"
        save_file({"lora_A.weight": tensor.reshape(4, 4)}, str(safetensors_path))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("README.md", f"adapter {adapter_id}\n")
            zf.writestr(
                "adapter_config.json",
                json.dumps(
                    {
                        "base_model_name_or_path": "sha256:" + ("a" * 64),
                        "lora_alpha": 16,
                        "r": 4,
                        "target_modules": ["c_attn", "c_proj", "c_fc"],
                        "task_type": "CAUSAL_LM",
                    },
                    indent=2,
                    sort_keys=True,
                ),
            )
            zf.writestr("adapter_model.safetensors", safetensors_path.read_bytes())
        return buf.getvalue()


def _build_real_kaggle_zip(path: Path) -> None:
    head = _git_head()
    adapter_ids = _authoritative_ids()
    build_root = path.parent / "build_real"
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
        bundle.write_bytes(_real_bundle_bytes(adapter_id=adapter_id, idx=idx))
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
            "engine": "hf_lora",
            "hf_lora": {
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
            "training_mode": "lora",
            "training_run_verdict": (
                "KT_RAPID_LORA_PASS "
                f"cmd=train engine=hf_lora "
                f"job_id={f'{idx:064x}'[-64:]} "
                f"out_dir=/kaggle/working/KT/KT_PROD_CLEANROOM/exports/_runs/KT_FORGE_COHORT0_INTERNAL/cohort0_full_hf/{adapter_id}"
            ),
        }
        reload = {
            "adapter_id": adapter_id,
            "artifact_path": training["artifact_path"],
            "artifact_sha256": bundle_sha,
            "created_at": "2026-04-01T13:58:39Z",
            "reloaded_member_count": 3,
            "schema_id": "kt.operator.forge_cohort0.adapter_reload_receipt.unbound.v1",
            "status": "PASS",
        }
        eval_receipt = {
            "adapter_id": adapter_id,
            "artifact_path": training["artifact_path"],
            "artifact_sha256": bundle_sha,
            "baseline_eval_score": round(0.2 + idx / 1000.0, 3),
            "created_at": "2026-04-01T13:58:39Z",
            "eval_case_count": 6,
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
            "engines": "hf_lora_only",
        },
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(bundle_root.rglob("*")):
            zf.write(p, p.relative_to(build_root).as_posix())


def test_cohort0_non_stub_eval_emission_tranche_emits_13_schema_bound_eval_reports(tmp_path: Path) -> None:
    bundle_zip = tmp_path / "cohort0_hf_20260401T135716Z_FULL_ARTIFACTS.zip"
    _build_real_kaggle_zip(bundle_zip)

    import_root = tmp_path / "import_authoritative"
    reports_root = tmp_path / "reports"
    _ = cohort0_kaggle_import_tranche.run_import_tranche(
        bundle_zip=bundle_zip,
        authoritative_root=import_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    emission_root = tmp_path / "non_stub_eval_authoritative"
    payload = cohort0_non_stub_eval_emission_tranche.run_non_stub_eval_emission_tranche(
        import_report_path=reports_root / "cohort0_real_engine_adapter_import_receipt.json",
        authoritative_root=emission_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    receipt = payload["non_stub_eval_emission_receipt"]
    assert receipt["status"] == "PASS"
    assert receipt["entry_count"] == 13
    assert 0 < receipt["metric_probe_agreement_true_count"] < 13
    assert receipt["source_stub_origin_count"] == 13
    assert receipt["next_lawful_move"] == "REEMIT_TOURNAMENT_PREP_WITH_SUPPLEMENTAL_NON_STUB_EVALS"

    first_entry = receipt["entries"][0]
    eval_report = json.loads(Path(str(first_entry["eval_report_ref"])).read_text(encoding="utf-8"))
    assert eval_report["schema_id"] == "kt.factory.eval_report.v2"
    assert eval_report["battery_id"] == "kt.eval.battery.fl4.adapter_bundle_probe_v1"
    assert eval_report["final_verdict"] == "PASS"
    assert eval_report["results"]["source_eval_stub"] is False
    assert eval_report["results"]["source_eval_stub_origin"] is True

    tracked = json.loads((reports_root / "cohort0_non_stub_eval_emission_receipt.json").read_text(encoding="utf-8"))
    assert tracked["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_NON_STUB_EVAL_EMISSION_RECEIPT"
