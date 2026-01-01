from __future__ import annotations

import json
import socket
import tempfile
import unittest
from pathlib import Path

import sys


def _add_teacher_to_syspath() -> None:
    # .../tools/growth/teacher_factory/tests/test_teacher_factory.py -> .../tools/growth/teacher_factory
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))


_add_teacher_to_syspath()

from curriculum_compiler import compile_bundle  # noqa: E402
from curriculum_registry import register_signed_package  # noqa: E402
from curriculum_signer import sign_package, verify_signature  # noqa: E402
from teacher_schemas import CurriculumPackageSchema, TeacherInputBundleSchema, TeacherSchemaError  # noqa: E402


def _write_runtime_registry(path: Path) -> None:
    payload = {
        "registry_version": "1",
        "canonical_entry": {"module": "kt.entrypoint", "callable": "invoke"},
        "canonical_spine": {"module": "core.spine", "callable": "run"},
        "state_vault": {"jsonl_path": "_runtime_artifacts/state_vault.jsonl"},
        "runtime_import_roots": ["core", "kt"],
        "organs_by_root": {"core": "Spine", "kt": "Entry Point"},
        "import_truth_matrix": {"Entry Point": ["Entry Point", "Spine"]},
        "dry_run": {"no_network": True, "providers_enabled": False},
    }
    path.write_text(json.dumps(payload, ensure_ascii=True), encoding="utf-8")


def _write_run_record(path: Path, crucible_id: str, run_id: str, outcome: str) -> None:
    payload = {"crucible_id": crucible_id, "run_id": run_id, "outcome": outcome}
    path.write_text(json.dumps(payload, ensure_ascii=True), encoding="utf-8")


def _write_epoch_manifest(path: Path, epoch_id: str, epoch_hash: str) -> None:
    payload = {"epoch_id": epoch_id, "epoch_hash": epoch_hash, "kernel_identity": {"kernel_target": "V2_SOVEREIGN"}}
    path.write_text(json.dumps(payload, ensure_ascii=True), encoding="utf-8")


def _write_bundle(path: Path, registry_path: Path, manifest_path: Path, run_path: Path) -> None:
    payload = {
        "schema_id": "teacher.bundle",
        "schema_version_hash": TeacherInputBundleSchema.SCHEMA_VERSION_HASH,
        "runtime_registry_path": str(registry_path),
        "epoch_manifest_paths": [str(manifest_path)],
        "run_record_paths": [str(run_path)],
        "extract_types": ["EPOCH_MANIFEST", "RUN_RECORD"],
        "bounds": {"max_examples": 16, "max_instructions": 16, "max_constraints": 16},
    }
    path.write_text(json.dumps(payload, ensure_ascii=True), encoding="utf-8")


class TestTeacherFactory(unittest.TestCase):
    def test_raw_runtime_paths_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            registry_path = td_path / "runtime_registry.json"
            _write_runtime_registry(registry_path)
            manifest_path = td_path / "epoch_manifest.json"
            _write_epoch_manifest(manifest_path, "E1", "h" * 64)
            run_path = td_path / "stdout.json"
            _write_run_record(run_path, "C1", "R1", "PASS")
            bundle_path = td_path / "bundle.json"
            _write_bundle(bundle_path, registry_path, manifest_path, run_path)
            with self.assertRaises(TeacherSchemaError):
                TeacherInputBundleSchema.from_dict(json.loads(bundle_path.read_text(encoding="utf-8")))

    def test_deterministic_compile(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            registry_path = td_path / "runtime_registry.json"
            _write_runtime_registry(registry_path)
            manifest_path = td_path / "epoch_manifest.json"
            _write_epoch_manifest(manifest_path, "E1", "h" * 64)
            run_path = td_path / "run.json"
            _write_run_record(run_path, "C1", "R1", "PASS")
            bundle_path = td_path / "bundle.json"
            _write_bundle(bundle_path, registry_path, manifest_path, run_path)

            a = compile_bundle(bundle_path)
            b = compile_bundle(bundle_path)
            self.assertEqual(a.package_hash, b.package_hash)
            CurriculumPackageSchema.validate(a.package.to_dict())

    def test_signature_verification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            registry_path = td_path / "runtime_registry.json"
            _write_runtime_registry(registry_path)
            manifest_path = td_path / "epoch_manifest.json"
            _write_epoch_manifest(manifest_path, "E1", "h" * 64)
            run_path = td_path / "run.json"
            _write_run_record(run_path, "C1", "R1", "PASS")
            bundle_path = td_path / "bundle.json"
            _write_bundle(bundle_path, registry_path, manifest_path, run_path)

            compiled = compile_bundle(bundle_path)
            signed = sign_package(package=compiled.package)
            self.assertTrue(verify_signature(package=compiled.package, signature=signed.signature))

    def test_append_only_registry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            registry_path = td_path / "registry.jsonl"
            registry_path.write_text("", encoding="utf-8")

            registry_json = td_path / "runtime_registry.json"
            _write_runtime_registry(registry_json)
            manifest_path = td_path / "epoch_manifest.json"
            _write_epoch_manifest(manifest_path, "E1", "h" * 64)
            run_path = td_path / "run.json"
            _write_run_record(run_path, "C1", "R1", "PASS")
            bundle_path = td_path / "bundle.json"
            _write_bundle(bundle_path, registry_json, manifest_path, run_path)

            compiled = compile_bundle(bundle_path)
            signed = sign_package(package=compiled.package)
            register_signed_package(package=compiled.package, signature=signed.signature, registry_path=registry_path)
            size1 = registry_path.stat().st_size
            register_signed_package(package=compiled.package, signature=signed.signature, registry_path=registry_path)
            size2 = registry_path.stat().st_size
            self.assertGreater(size2, size1)

    def test_no_network_access(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            registry_path = td_path / "runtime_registry.json"
            _write_runtime_registry(registry_path)
            manifest_path = td_path / "epoch_manifest.json"
            _write_epoch_manifest(manifest_path, "E1", "h" * 64)
            run_path = td_path / "run.json"
            _write_run_record(run_path, "C1", "R1", "PASS")
            bundle_path = td_path / "bundle.json"
            _write_bundle(bundle_path, registry_path, manifest_path, run_path)

            original_socket = socket.socket
            socket.socket = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no network"))
            try:
                compiled = compile_bundle(bundle_path)
                self.assertIsNotNone(compiled.package_hash)
            finally:
                socket.socket = original_socket


if __name__ == "__main__":
    raise SystemExit(unittest.main())

