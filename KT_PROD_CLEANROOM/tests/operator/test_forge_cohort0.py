from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src"))
sys.path.insert(0, str(ROOT / "KT_PROD_CLEANROOM"))

from tools.operator import forge_cohort0  # noqa: E402


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_registry(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _materialize_input_root(*, input_root: Path, registry: dict) -> None:
    base_snapshot = input_root / str(registry["base_snapshot_relpath"])
    base_snapshot.mkdir(parents=True, exist_ok=True)
    (base_snapshot / "SNAPSHOT.txt").write_text("cohort0 staged base snapshot\n", encoding="utf-8")

    entries: list[dict] = []
    for idx, row in enumerate(registry["adapters"], start=1):
        ds_path = input_root / str(row["dataset_relpath"])
        ds_path.parent.mkdir(parents=True, exist_ok=True)
        ds_path.write_text(
            json.dumps({"adapter_id": row["adapter_id"], "failure_id": f"F{idx:02d}", "note": "fixture"}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        entries.append(
            {
                "adapter_id": row["adapter_id"],
                "dataset_relpath": row["dataset_relpath"],
                "sha256": _sha256_file(ds_path),
            }
        )

    _write_json(input_root / str(registry["dataset_manifest_relpath"]), {"entries": entries})


def _materialize_base_model_dir(model_dir: Path) -> None:
    transformers = pytest.importorskip("transformers")
    _ = pytest.importorskip("torch")
    _ = pytest.importorskip("peft")

    from transformers import GPT2Config, GPT2LMHeadModel

    model_dir.mkdir(parents=True, exist_ok=True)
    cfg = GPT2Config(vocab_size=64, n_positions=32, n_ctx=32, n_embd=32, n_layer=1, n_head=1)
    model = GPT2LMHeadModel(cfg)
    model.save_pretrained(model_dir, safe_serialization=True)


def test_forge_cohort0_dry_run_discovers_all_13(tmp_path: Path) -> None:
    registry_path = ROOT / "KT_PROD_CLEANROOM" / "tools" / "operator" / "config" / "forge_cohort0_registry.json"
    registry = _load_registry(registry_path)
    input_root = (tmp_path / "input_root").resolve()
    artifact_root = (tmp_path / "artifact_root").resolve()
    _materialize_input_root(input_root=input_root, registry=registry)

    rc = forge_cohort0.main(
        [
            "--registry",
            str(registry_path),
            "--input-root",
            str(input_root),
            "--artifact-root",
            str(artifact_root),
            "--mode",
            "dry-run",
            "--run-label",
            "dryrun",
        ]
    )
    assert rc == 0

    run_root = artifact_root / "dryrun"
    discovery = json.loads((run_root / "discovery_receipt.json").read_text(encoding="utf-8"))
    preflight = json.loads((run_root / "preflight_receipt.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_root / "run_manifest.json").read_text(encoding="utf-8"))

    assert discovery["resolved_adapter_count"] == 13
    assert preflight["adapter_count"] == 13
    assert manifest["verdict"] == "PASS"
    assert manifest["artifact_hashes"] == []


def test_forge_cohort0_smoke_emits_artifact_and_receipts(tmp_path: Path) -> None:
    registry_path = ROOT / "KT_PROD_CLEANROOM" / "tools" / "operator" / "config" / "forge_cohort0_registry.json"
    registry = _load_registry(registry_path)
    input_root = (tmp_path / "input_root").resolve()
    artifact_root = (tmp_path / "artifact_root").resolve()
    _materialize_input_root(input_root=input_root, registry=registry)

    rc = forge_cohort0.main(
        [
            "--registry",
            str(registry_path),
            "--input-root",
            str(input_root),
            "--artifact-root",
            str(artifact_root),
            "--mode",
            "smoke",
            "--adapter-id",
            "lobe.alpha.v1",
            "--run-label",
            "smoke",
        ]
    )
    assert rc == 0

    run_root = artifact_root / "smoke"
    assert (run_root / "adapters" / "lobe.alpha.v1" / "adapter_bundle.zip").is_file()
    training = json.loads((run_root / "adapters" / "lobe.alpha.v1" / "adapter_training_receipt.json").read_text(encoding="utf-8"))
    reload = json.loads((run_root / "adapters" / "lobe.alpha.v1" / "adapter_reload_receipt.json").read_text(encoding="utf-8"))
    eval_receipt = json.loads((run_root / "adapters" / "lobe.alpha.v1" / "adapter_eval_receipt.json").read_text(encoding="utf-8"))
    summary = json.loads((run_root / "run_summary.json").read_text(encoding="utf-8"))

    assert training["status"] == "PASS"
    assert reload["status"] == "PASS"
    assert eval_receipt["status"] == "PASS"
    assert summary["status"] == "PASS"
    assert summary["adapter_count"] == 1


def test_forge_cohort0_rejects_repo_local_artifact_root(tmp_path: Path, capsys) -> None:
    registry_path = ROOT / "KT_PROD_CLEANROOM" / "tools" / "operator" / "config" / "forge_cohort0_registry.json"
    registry = _load_registry(registry_path)
    input_root = (tmp_path / "input_root").resolve()
    _materialize_input_root(input_root=input_root, registry=registry)

    repo_local_artifact_root = ROOT / "KT_PROD_CLEANROOM" / "exports" / "_runs" / "_forge_cohort0_forbidden"
    rc = forge_cohort0.main(
        [
            "--registry",
            str(registry_path),
            "--input-root",
            str(input_root),
            "--artifact-root",
            str(repo_local_artifact_root),
            "--mode",
            "dry-run",
            "--run-label",
            "forbidden",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 2
    assert "outside the repo tree" in captured.out


def test_forge_cohort0_rejects_non_13_registry(tmp_path: Path, capsys) -> None:
    registry_path = ROOT / "KT_PROD_CLEANROOM" / "tools" / "operator" / "config" / "forge_cohort0_registry.json"
    registry = _load_registry(registry_path)
    registry["adapters"] = registry["adapters"][:-1]
    registry["expected_adapter_count"] = 13

    bad_registry_path = (tmp_path / "bad_registry.json").resolve()
    _write_json(bad_registry_path, registry)

    input_root = (tmp_path / "input_root").resolve()
    artifact_root = (tmp_path / "artifact_root").resolve()
    _materialize_input_root(input_root=input_root, registry=_load_registry(registry_path))

    rc = forge_cohort0.main(
        [
            "--registry",
            str(bad_registry_path),
            "--input-root",
            str(input_root),
            "--artifact-root",
            str(artifact_root),
            "--mode",
            "dry-run",
            "--run-label",
            "badcount",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 2
    assert "exactly 13 adapters" in captured.out


def test_forge_cohort0_smoke_hf_lora_emits_real_engine_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    registry_path = ROOT / "KT_PROD_CLEANROOM" / "tools" / "operator" / "config" / "forge_cohort0_registry.json"
    registry = _load_registry(registry_path)
    registry["adapters"][0]["training_params"]["engine"] = "hf_lora"
    registry["adapters"][0]["training_params"]["training_mode"] = "lora"

    custom_registry_path = (tmp_path / "hf_registry.json").resolve()
    _write_json(custom_registry_path, registry)

    input_root = (tmp_path / "input_root").resolve()
    artifact_root = (tmp_path / "artifact_root").resolve()
    model_dir = (tmp_path / "base_model").resolve()
    _materialize_input_root(input_root=input_root, registry=registry)
    _materialize_base_model_dir(model_dir)

    monkeypatch.setenv("KT_SEAL_MODE", "1")
    monkeypatch.setenv(
        "PYTHONPATH",
        str(ROOT / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src") + os.pathsep + str(ROOT / "KT_PROD_CLEANROOM"),
    )
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")

    rc = forge_cohort0.main(
        [
            "--registry",
            str(custom_registry_path),
            "--input-root",
            str(input_root),
            "--artifact-root",
            str(artifact_root),
            "--mode",
            "smoke",
            "--adapter-id",
            "lobe.alpha.v1",
            "--base-model-dir",
            str(model_dir),
            "--enable-real-engine",
            "--run-label",
            "hf_smoke",
        ]
    )
    assert rc == 0

    run_root = artifact_root / "hf_smoke"
    bundle = run_root / "adapters" / "lobe.alpha.v1" / "adapter_bundle.zip"
    training = json.loads((run_root / "adapters" / "lobe.alpha.v1" / "adapter_training_receipt.json").read_text(encoding="utf-8"))
    reload = json.loads((run_root / "adapters" / "lobe.alpha.v1" / "adapter_reload_receipt.json").read_text(encoding="utf-8"))
    eval_receipt = json.loads((run_root / "adapters" / "lobe.alpha.v1" / "adapter_eval_receipt.json").read_text(encoding="utf-8"))

    assert bundle.is_file()
    assert bundle.stat().st_size > 1024
    assert training["status"] == "PASS"
    assert training["engine"] == "hf_lora"
    assert training["training_mode"] == "lora"
    assert training["artifact_bytes"] > 1024
    assert isinstance(training.get("hf_lora"), dict)
    assert reload["status"] == "PASS"
    assert reload["reloaded_member_count"] > 0
    assert eval_receipt["status"] == "PASS"
    assert eval_receipt["eval_case_count"] > 0


def test_forge_cohort0_rejects_hf_lora_without_real_engine_enable(tmp_path: Path, capsys) -> None:
    registry_path = ROOT / "KT_PROD_CLEANROOM" / "tools" / "operator" / "config" / "forge_cohort0_registry.json"
    registry = _load_registry(registry_path)
    registry["adapters"][0]["training_params"]["engine"] = "hf_lora"
    registry["adapters"][0]["training_params"]["training_mode"] = "lora"

    custom_registry_path = (tmp_path / "hf_registry_fail.json").resolve()
    _write_json(custom_registry_path, registry)

    input_root = (tmp_path / "input_root").resolve()
    artifact_root = (tmp_path / "artifact_root").resolve()
    _materialize_input_root(input_root=input_root, registry=registry)

    rc = forge_cohort0.main(
        [
            "--registry",
            str(custom_registry_path),
            "--input-root",
            str(input_root),
            "--artifact-root",
            str(artifact_root),
            "--mode",
            "smoke",
            "--adapter-id",
            "lobe.alpha.v1",
            "--run-label",
            "hf_fail",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 2
    assert "--enable-real-engine required" in captured.out
