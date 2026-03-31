from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

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
