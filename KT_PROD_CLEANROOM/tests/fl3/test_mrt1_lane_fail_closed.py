from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.fl3_schema_common import sha256_hex_of_obj  # noqa: E402
from schemas.schema_files import schema_version_hash  # noqa: E402
from tools.verification.cohort0_manufacture import derive_canonical_13_lobes  # noqa: E402
from tools.verification.fl3_validators import load_fl3_canonical_runtime_paths, validate_schema_bound_object  # noqa: E402


def _canonical_json(obj: object) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _root_hash(files: List[Dict[str, Any]]) -> str:
    cleaned = [
        {"path": str(f.get("path", "")).replace("\\", "/"), "sha256": str(f.get("sha256", "")), "bytes": int(f.get("bytes", 0) or 0)}
        for f in files
    ]
    cleaned = sorted(cleaned, key=lambda e: e["path"])
    canon = json.dumps(cleaned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


def _mrt1_roots(repo_root: Path) -> Tuple[Path, Path]:
    paths = load_fl3_canonical_runtime_paths(repo_root=repo_root)
    shadow = repo_root / str(paths["exports_shadow_mrt1_root"])
    promoted = repo_root / str(paths["exports_adapters_mrt1_root"])
    return shadow.resolve(), promoted.resolve()


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_canonical_json(obj), encoding="utf-8", newline="\n")


def _mk_minimal_mrt1_run_dir(*, repo_root: Path, adapter_id: str, adapter_version: str, request_id: str) -> Path:
    shadow_root, _ = _mrt1_roots(repo_root)
    run_dir = (shadow_root / "_runs_test" / adapter_id / adapter_version / request_id).resolve()
    if run_dir.exists():
        shutil.rmtree(run_dir, ignore_errors=True)
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def _mk_train_request(*, adapter_id: str, adapter_version: str, role_id: str, pinned_sha: str) -> Dict[str, Any]:
    req: Dict[str, Any] = {
        "schema_id": "kt.phase2_train_request.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.phase2_train_request.v1.json"),
        "schema_version": 1,
        "train_request_id": "",
        "work_order_id": "PHASE2_OP_A_GOVERNED_LEARNING_UNLOCK",
        "pinned_sha": pinned_sha,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "role_id": role_id,
        "training_mode": "lora_mrt1",
        "base_model": {"model_id": "dummy_base", "local_path": "/offline/base/model"},
        "dataset_manifest_ref": {"path": "/offline/dataset.jsonl", "sha256": "b" * 64},
        "seed": 0,
        "device": "cpu",
        "output": {
            "export_root_shadow": "KT_PROD_CLEANROOM/exports/adapters_mrt1_shadow/_runs_test",
            "export_root_promoted": "KT_PROD_CLEANROOM/exports/adapters_mrt1",
        },
        "created_at": "2026-01-01T00:00:00Z",
    }
    req["train_request_id"] = sha256_hex_of_obj(req, drop_keys={"train_request_id", "created_at"})
    validate_schema_bound_object(req)
    return req


def _mk_weight_manifest(*, adapter_id: str, adapter_version: str, run_dir: Path) -> Dict[str, Any]:
    # Manifest is content-hash surface for promotion: excludes request/receipt/manifest itself.
    excluded = {"train_request.json", "train_receipt.json", "adapter_weight_manifest.json"}
    file_entries: List[Dict[str, Any]] = []
    for p in sorted([x for x in run_dir.rglob("*") if x.is_file() and x.name not in excluded], key=lambda x: x.as_posix()):
        rel = p.relative_to(run_dir).as_posix()
        file_entries.append({"path": rel, "sha256": _sha256_file(p), "bytes": int(p.stat().st_size)})
    file_entries = sorted(file_entries, key=lambda e: e["path"])
    rh = _root_hash(file_entries)
    manifest: Dict[str, Any] = {
        "schema_id": "kt.adapter_weight_artifact_manifest.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.adapter_weight_artifact_manifest.v1.json"),
        "schema_version": 1,
        "manifest_id": "",
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "training_mode": "lora_mrt1",
        "base_model_id": "dummy_base",
        "root_hash": rh,
        "files": file_entries,
        "created_at": "2026-01-01T00:00:00Z",
    }
    manifest["manifest_id"] = sha256_hex_of_obj(manifest, drop_keys={"manifest_id", "created_at"})
    validate_schema_bound_object(manifest)
    return manifest


def _mk_train_receipt(*, adapter_id: str, adapter_version: str, pinned_sha: str, req: Dict[str, Any], manifest: Dict[str, Any], run_dir_rel: str) -> Dict[str, Any]:
    receipt: Dict[str, Any] = {
        "schema_id": "kt.phase2_train_receipt.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.phase2_train_receipt.v1.json"),
        "schema_version": 1,
        "train_receipt_id": "",
        "train_request_id": str(req["train_request_id"]),
        "pinned_sha": pinned_sha,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "training_mode": "lora_mrt1",
        "status": "PASS",
        "failure_reason": None,
        "base_model": dict(req["base_model"]),
        "dataset_manifest_ref": dict(req["dataset_manifest_ref"]),
        "output_package": {"shadow_dir": run_dir_rel, "promoted_dir": None, "content_hash": str(manifest["root_hash"])},
        "artifact_manifest_ref": {
            "path": f"{run_dir_rel}/adapter_weight_manifest.json",
            "sha256": str(manifest["manifest_id"]),
        },
        "io_guard_receipt_glob": "io_guard_receipt*.json",
        "created_at": "2026-01-01T00:00:00Z",
    }
    receipt["train_receipt_id"] = sha256_hex_of_obj(receipt, drop_keys={"train_receipt_id", "created_at"})
    validate_schema_bound_object(receipt)
    return receipt


def _env_for_guard(*, repo_root: Path, allowed_roots: List[Path], receipt_path: Path) -> Dict[str, str]:
    env = dict(os.environ)
    env["KT_LIVE"] = "0"
    env["KT_IO_GUARD"] = "1"
    env["KT_IO_GUARD_DENY_NETWORK"] = "1"
    env["KT_IO_GUARD_ALLOWED_WRITE_ROOTS"] = json.dumps([str(p.resolve()) for p in allowed_roots])
    env["KT_IO_GUARD_RECEIPT_PATH"] = str(receipt_path.resolve())

    # Subprocesses won't inherit the in-process FL3 bootstrap sys.path changes.
    # Ensure `python -m tools...` is importable and schema/validators resolve without relying on external PYTHONPATH.
    src_root = (repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src").resolve()
    cleanroom_root = (repo_root / "KT_PROD_CLEANROOM").resolve()
    env["PYTHONPATH"] = os.pathsep.join([str(src_root), str(cleanroom_root)])
    env["PYTHONNOUSERSITE"] = "1"
    return env


def test_mrt1_promotion_rejects_extra_file_not_in_manifest(tmp_path: Path) -> None:
    repo_root = _REPO_ROOT
    shadow_root, promoted_root = _mrt1_roots(repo_root)

    adapter_id = "lobe.architect.v1"
    adapter_version = "testv1"
    pinned_sha = "0" * 40
    req = _mk_train_request(adapter_id=adapter_id, adapter_version=adapter_version, role_id="ARCHITECT", pinned_sha=pinned_sha)
    request_id = str(req["train_request_id"])

    run_dir = _mk_minimal_mrt1_run_dir(repo_root=repo_root, adapter_id=adapter_id, adapter_version=adapter_version, request_id=request_id)
    run_dir_rel = str(run_dir.relative_to(repo_root).as_posix())

    # Create minimal hashed artifacts.
    (run_dir / "trainer_config.json").write_text(_canonical_json({"kind": "cfg"}), encoding="utf-8", newline="\n")
    (run_dir / "eval_report.json").write_text(_canonical_json({"kind": "eval"}), encoding="utf-8", newline="\n")
    (run_dir / "adapter_config.json").write_text(_canonical_json({"kind": "adapter_cfg"}), encoding="utf-8", newline="\n")
    (run_dir / "adapter_model.safetensors").write_bytes(b"dummy-weights")

    manifest = _mk_weight_manifest(adapter_id=adapter_id, adapter_version=adapter_version, run_dir=run_dir)
    _write_json(run_dir / "adapter_weight_manifest.json", manifest)
    _write_json(run_dir / "train_request.json", req)
    receipt = _mk_train_receipt(
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        pinned_sha=pinned_sha,
        req=req,
        manifest=manifest,
        run_dir_rel=run_dir_rel,
    )
    _write_json(run_dir / "train_receipt.json", receipt)

    # Add an extra file not in manifest and not an allowed sidecar.
    (run_dir / "unexpected.txt").write_text("nope\n", encoding="utf-8", newline="\n")

    out = tmp_path / "promotion_receipt.json"
    receipt_path = tmp_path / "io_guard_receipt.json"
    env = _env_for_guard(repo_root=repo_root, allowed_roots=[tmp_path, shadow_root, promoted_root], receipt_path=receipt_path)

    p = subprocess.run(
        [sys.executable, "-m", "tools.verification.phase2_promote_mrt1", "--train-receipt", str(run_dir / "train_receipt.json"), "--out", str(out)],
        cwd=str(repo_root),
        env=env,
        capture_output=True,
        text=True,
    )
    assert p.returncode != 0, p.stdout + "\n" + p.stderr
    assert "FAIL_CLOSED" in (p.stdout + p.stderr)

    # Cleanup
    shutil.rmtree(run_dir, ignore_errors=True)


def test_mrt1_promotion_rejects_forbidden_extension(tmp_path: Path) -> None:
    repo_root = _REPO_ROOT
    shadow_root, promoted_root = _mrt1_roots(repo_root)

    adapter_id = "lobe.architect.v1"
    adapter_version = "testv2"
    pinned_sha = "0" * 40
    req = _mk_train_request(adapter_id=adapter_id, adapter_version=adapter_version, role_id="ARCHITECT", pinned_sha=pinned_sha)
    request_id = str(req["train_request_id"])

    run_dir = _mk_minimal_mrt1_run_dir(repo_root=repo_root, adapter_id=adapter_id, adapter_version=adapter_version, request_id=request_id)
    run_dir_rel = str(run_dir.relative_to(repo_root).as_posix())

    (run_dir / "trainer_config.json").write_text(_canonical_json({"kind": "cfg"}), encoding="utf-8", newline="\n")
    (run_dir / "eval_report.json").write_text(_canonical_json({"kind": "eval"}), encoding="utf-8", newline="\n")
    (run_dir / "adapter_config.json").write_text(_canonical_json({"kind": "adapter_cfg"}), encoding="utf-8", newline="\n")
    (run_dir / "adapter_model.safetensors").write_bytes(b"dummy-weights")
    # Forbidden extension, but included in manifest -> must fail in promote.
    (run_dir / "weights.bin").write_bytes(b"forbidden")

    manifest = _mk_weight_manifest(adapter_id=adapter_id, adapter_version=adapter_version, run_dir=run_dir)
    _write_json(run_dir / "adapter_weight_manifest.json", manifest)
    _write_json(run_dir / "train_request.json", req)
    receipt = _mk_train_receipt(
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        pinned_sha=pinned_sha,
        req=req,
        manifest=manifest,
        run_dir_rel=run_dir_rel,
    )
    _write_json(run_dir / "train_receipt.json", receipt)

    out = tmp_path / "promotion_receipt.json"
    receipt_path = tmp_path / "io_guard_receipt.json"
    env = _env_for_guard(repo_root=repo_root, allowed_roots=[tmp_path, shadow_root, promoted_root], receipt_path=receipt_path)

    p = subprocess.run(
        [sys.executable, "-m", "tools.verification.phase2_promote_mrt1", "--train-receipt", str(run_dir / "train_receipt.json"), "--out", str(out)],
        cwd=str(repo_root),
        env=env,
        capture_output=True,
        text=True,
    )
    assert p.returncode != 0, p.stdout + "\n" + p.stderr
    assert "FAIL_CLOSED" in (p.stdout + p.stderr)

    shutil.rmtree(run_dir, ignore_errors=True)


def test_mrt1_snapshot_builder_emits_13_active_entries(tmp_path: Path) -> None:
    repo_root = _REPO_ROOT
    _, promoted_root = _mrt1_roots(repo_root)

    adapter_version = "testv3"
    pinned_sha = "0" * 40
    lobes = derive_canonical_13_lobes(role_weights=json.loads((repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "ROLE_FITNESS_WEIGHTS.json").read_text(encoding="utf-8")))

    created_dirs: List[Path] = []
    try:
        for s in lobes:
            adapter_id = s.adapter_id
            req = _mk_train_request(adapter_id=adapter_id, adapter_version=adapter_version, role_id=s.role_id, pinned_sha=pinned_sha)
            request_id = str(req["train_request_id"])
            # Build a minimal promoted package directly (no promote step).
            pkg_dir = (promoted_root / adapter_id / adapter_version / ("c" * 64)).resolve()
            if pkg_dir.exists():
                shutil.rmtree(pkg_dir, ignore_errors=True)
            pkg_dir.mkdir(parents=True, exist_ok=False)
            created_dirs.append(pkg_dir)

            # Hashed artifacts
            (pkg_dir / "trainer_config.json").write_text(_canonical_json({"kind": "cfg"}), encoding="utf-8", newline="\n")
            (pkg_dir / "eval_report.json").write_text(_canonical_json({"kind": "eval"}), encoding="utf-8", newline="\n")
            (pkg_dir / "adapter_config.json").write_text(_canonical_json({"kind": "adapter_cfg"}), encoding="utf-8", newline="\n")
            (pkg_dir / "adapter_model.safetensors").write_bytes(b"dummy-weights")

            # Manifest/root_hash must match promoted dir content hash
            manifest = _mk_weight_manifest(adapter_id=adapter_id, adapter_version=adapter_version, run_dir=pkg_dir)
            # Force content-hash dir name to match manifest.root_hash
            content_hash = str(manifest["root_hash"])
            target = pkg_dir.parent / content_hash
            pkg_dir.rename(target)
            pkg_dir = target

            _write_json(pkg_dir / "adapter_weight_manifest.json", manifest)
            _write_json(pkg_dir / "train_request.json", req)
            run_dir_rel = f"KT_PROD_CLEANROOM/exports/adapters_mrt1_shadow/_runs_test/{adapter_id}/{adapter_version}/{request_id}"
            receipt = _mk_train_receipt(
                adapter_id=adapter_id,
                adapter_version=adapter_version,
                pinned_sha=pinned_sha,
                req=req,
                manifest=manifest,
                run_dir_rel=run_dir_rel,
            )
            _write_json(pkg_dir / "train_receipt.json", receipt)

        out = tmp_path / "runtime_registry.mrt1.snapshot.json"
        env = dict(os.environ)
        src_root = (repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src").resolve()
        cleanroom_root = (repo_root / "KT_PROD_CLEANROOM").resolve()
        env["PYTHONPATH"] = os.pathsep.join([str(src_root), str(cleanroom_root)])
        env["PYTHONNOUSERSITE"] = "1"
        p = subprocess.run(
            [sys.executable, "-m", "tools.verification.mrt1_build_runtime_registry_snapshot", "--adapter-version", adapter_version, "--out", str(out)],
            cwd=str(repo_root),
            env=env,
            capture_output=True,
            text=True,
        )
        assert p.returncode == 0, p.stdout + "\n" + p.stderr

        snap = json.loads(out.read_text(encoding="utf-8"))
        entries = snap["adapters"]["entries"]
        assert isinstance(entries, list)
        assert len(entries) == 13
        for e in entries:
            assert e.get("status") == "ACTIVE"
            assert set(e.get("constraints") or []) == {"MRT1_LORA", "OFFLINE_ONLY", "NO_NETWORK"}
    finally:
        for d in created_dirs:
            # remove content_hash dir (parent is adapter_version)
            try:
                shutil.rmtree(d.parent, ignore_errors=True)
            except Exception:
                pass
