from __future__ import annotations

import io
import json
import os
import zipfile
from pathlib import Path

from tools.operator import cohort0_stronger_cycle_chaos_a_execution_tranche


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _bundle_bytes(adapter_id: str) -> bytes:
    data = (f"{adapter_id}\n" * 200).encode("utf-8")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("adapter_metadata.json", json.dumps({"adapter_id": adapter_id}, indent=2))
        zf.writestr("weights.bin", data)
    return buf.getvalue()


def test_cohort0_stronger_cycle_chaos_a_execution_tranche_binds_existing_run_root(tmp_path: Path) -> None:
    root = _repo_root()
    current_head = cohort0_stronger_cycle_chaos_a_execution_tranche._git_head(root)

    stage_input_root = tmp_path / "stage_input"
    base_snapshot = stage_input_root / "snapshots" / "cohort0" / "base_snapshot"
    base_snapshot.mkdir(parents=True, exist_ok=True)
    (base_snapshot / "SNAPSHOT.txt").write_text("snapshot\n", encoding="utf-8")

    dataset_entries = []
    adapter_ids = [
        "lobe.alpha.v1",
        "lobe.architect.v1",
        "lobe.beta.v1",
        "lobe.child.v1",
        "lobe.critic.v1",
        "lobe.p1.v1",
        "lobe.p2.v1",
        "lobe.scout.v1",
        "lobe.auditor.v1",
        "lobe.censor.v1",
        "lobe.muse.v1",
        "lobe.quant.v1",
        "lobe.strategist.v1",
    ]
    for adapter_id in adapter_ids:
        dataset_path = stage_input_root / "datasets" / adapter_id / "failures.jsonl"
        dataset_path.parent.mkdir(parents=True, exist_ok=True)
        dataset_path.write_text("{\"text\":\"hello\"}\n", encoding="utf-8")
        dataset_entries.append({"adapter_id": adapter_id, "dataset_relpath": f"datasets/{adapter_id}/failures.jsonl"})
    _write_json(stage_input_root / "datasets" / "cohort0_dataset_manifest.json", {"entries": dataset_entries})

    base_model_dir = tmp_path / "base_model"
    base_model_dir.mkdir(parents=True, exist_ok=True)
    (base_model_dir / "config.json").write_text(json.dumps({"architectures": ["GPT2LMHeadModel"]}), encoding="utf-8")
    (base_model_dir / "model.safetensors").write_bytes(b"0" * 2048)

    authoritative_evidence_root = tmp_path / "evidence_authoritative"
    chaos_a_root = authoritative_evidence_root / "chaos_round_a"
    chaos_a_root.mkdir(parents=True, exist_ok=True)
    chaos_a_contract_path = chaos_a_root / "chaos_round_a_execution_contract.json"
    chaos_a_registry_path = chaos_a_root / "forge_cohort0_registry_hf_lora.json"
    _write_json(
        chaos_a_contract_path,
        {
            "status": "PASS",
            "stage_id": "CHAOS_ROUND_A__ALL_13_SHARED_PRESSURE",
            "registry_ref": chaos_a_registry_path.resolve().as_posix(),
        },
    )
    _write_json(
        chaos_a_registry_path,
        {
            "schema_id": "kt.operator.forge_cohort0_registry.unbound.v1",
            "expected_adapter_count": 13,
        },
    )
    evidence_packet = {
        "status": "PASS",
        "subject_head": "1969bb63e99797e2377840ed053504f755ad0f56",
        "evidence_posture": "STRONGER_CYCLE_EVIDENCE_READY__CHAOS_A_HYPERTRAINING_CHAOS_B_BOUND",
        "next_lawful_move": "EXECUTE_CHAOS_A_ON_NEW_AUTHORITATIVE_HEAD_WITH_REAL_STAGE_INPUTS",
        "stage_asset_refs": {
            "chaos_round_a_contract_ref": chaos_a_contract_path.resolve().as_posix(),
            "chaos_round_a_registry_ref": chaos_a_registry_path.resolve().as_posix(),
        },
    }
    authoritative_evidence_path = authoritative_evidence_root / "cohort0_stronger_cycle_evidence_packet.json"
    _write_json(authoritative_evidence_path, evidence_packet)
    reports_root = tmp_path / "reports"
    tracked_evidence_path = reports_root / "cohort0_stronger_cycle_evidence_packet.json"
    _write_json(
        tracked_evidence_path,
        {
            **evidence_packet,
            "carrier_surface_role": "TRACKED_CARRIER_ONLY_GATE_D_STRONGER_CYCLE_EVIDENCE_PACKET",
            "authoritative_stronger_cycle_evidence_packet_ref": authoritative_evidence_path.resolve().as_posix(),
        },
    )

    external_artifact_root = tmp_path / "external_artifacts"
    existing_run_root = external_artifact_root / "cohort0_stronger_cycle_chaos_a"
    (existing_run_root / "adapters").mkdir(parents=True, exist_ok=True)

    artifact_hashes = []
    receipt_list = []
    for idx, adapter_id in enumerate(adapter_ids, start=1):
        adapter_root = existing_run_root / "adapters" / adapter_id
        adapter_root.mkdir(parents=True, exist_ok=True)
        bundle = adapter_root / "adapter_bundle.zip"
        bundle_bytes = _bundle_bytes(adapter_id)
        bundle.write_bytes(bundle_bytes)
        bundle_sha = __import__("hashlib").sha256(bundle_bytes).hexdigest()
        training = {
            "adapter_id": adapter_id,
            "artifact_path": bundle.resolve().as_posix(),
            "artifact_sha256": bundle_sha,
            "artifact_bytes": len(bundle_bytes),
            "dataset_relpath": f"datasets/{adapter_id}/failures.jsonl",
            "dataset_sha256": f"{idx:064x}"[-64:],
            "engine": "hf_lora",
            "training_mode": "lora",
            "seed": 1000 + idx,
            "status": "PASS",
        }
        reload = {
            "adapter_id": adapter_id,
            "artifact_path": bundle.resolve().as_posix(),
            "artifact_sha256": bundle_sha,
            "reloaded_member_count": 2,
            "status": "PASS",
        }
        eval_receipt = {
            "adapter_id": adapter_id,
            "artifact_path": bundle.resolve().as_posix(),
            "artifact_sha256": bundle_sha,
            "eval_case_count": 5,
            "baseline_eval_score": 0.5,
            "source_eval_stub": True,
            "status": "PASS",
        }
        _write_json(adapter_root / "adapter_training_receipt.json", training)
        _write_json(adapter_root / "adapter_reload_receipt.json", reload)
        _write_json(adapter_root / "adapter_eval_receipt.json", eval_receipt)
        artifact_hashes.append({"adapter_id": adapter_id, "artifact_sha256": bundle_sha, "artifact_relpath": f"adapters/{adapter_id}/adapter_bundle.zip"})
        receipt_list.extend(
            [
                f"adapters/{adapter_id}/adapter_training_receipt.json",
                f"adapters/{adapter_id}/adapter_reload_receipt.json",
                f"adapters/{adapter_id}/adapter_eval_receipt.json",
            ]
        )

    _write_json(existing_run_root / "discovery_receipt.json", {"status": "PASS"})
    _write_json(existing_run_root / "preflight_receipt.json", {"status": "PASS"})
    _write_json(existing_run_root / "adapter_registry.json", {"status": "PASS"})
    _write_json(existing_run_root / "adapter_lineage_manifest.json", {"status": "PASS"})
    _write_json(existing_run_root / "run_summary.json", {"status": "PASS", "adapter_count": 13, "fail_count": 0, "registry_id": "KT_OPERATOR_FORGE_COHORT0_STRONGER_CYCLE_CHAOS_A_V1"})
    _write_json(existing_run_root / "run_manifest.json", {"verdict": "PASS", "adapter_ids": adapter_ids, "artifact_hashes": artifact_hashes, "receipt_list": receipt_list})

    authoritative_root = tmp_path / "authoritative"
    payload = cohort0_stronger_cycle_chaos_a_execution_tranche.run_chaos_a_execution_tranche(
        evidence_packet_path=tracked_evidence_path,
        stage_input_root=stage_input_root,
        base_model_dir=base_model_dir,
        external_artifact_root=external_artifact_root,
        existing_run_root=existing_run_root,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=root,
    )
    receipt = payload["chaos_a_execution_receipt"]
    assert receipt["status"] == "PASS"
    assert receipt["execution_posture"] == "CHAOS_A_EXECUTED__INDIVIDUAL_HYPERTRAINING_REQUIRED"
    assert receipt["adapter_count"] == 13
    assert receipt["source_eval_stub_count"] == 13
    assert receipt["next_lawful_move"] == "EXECUTE_13_INDIVIDUAL_HYPERTRAINING_LANES_ON_CHAOS_A_SUBSTRATE"

    authoritative_receipt = json.loads((authoritative_root / "cohort0_stronger_cycle_chaos_a_execution_receipt.json").read_text(encoding="utf-8"))
    tracked_receipt = json.loads((reports_root / "cohort0_stronger_cycle_chaos_a_execution_receipt.json").read_text(encoding="utf-8"))

    assert authoritative_receipt["status"] == "PASS"
    assert authoritative_receipt["subject_head"] == current_head
    assert authoritative_receipt["same_head_distinct_from_proof_line"] is True
    assert authoritative_receipt["source_eval_stub_count"] == 13
    assert authoritative_receipt["chaos_a_run_root"] == existing_run_root.resolve().as_posix()
    assert authoritative_receipt["next_lawful_move"] == "EXECUTE_13_INDIVIDUAL_HYPERTRAINING_LANES_ON_CHAOS_A_SUBSTRATE"
    assert tracked_receipt["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_STRONGER_CYCLE_CHAOS_A_EXECUTION_RECEIPT"
    assert tracked_receipt["authoritative_chaos_a_execution_receipt_ref"] == (authoritative_root / "cohort0_stronger_cycle_chaos_a_execution_receipt.json").resolve().as_posix()
