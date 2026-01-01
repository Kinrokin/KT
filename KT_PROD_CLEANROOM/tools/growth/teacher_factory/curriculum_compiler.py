from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import yaml

from teacher_schemas import (
    CurriculumDraftSchema,
    CurriculumPackageSchema,
    TeacherInputBundleSchema,
    TeacherSchemaError,
    sha256_json,
)


@dataclass(frozen=True)
class CompiledPackage:
    package: CurriculumPackageSchema
    package_hash: str


def _load_bundle(path: Path) -> TeacherInputBundleSchema:
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        payload = yaml.safe_load(raw)
    elif path.suffix.lower() == ".json":
        payload = json.loads(raw)
    else:
        raise TeacherSchemaError("bundle must be .json or .yaml (fail-closed)")
    return TeacherInputBundleSchema.from_dict(payload)


def _canonical_registry_hash(registry_obj: Dict[str, object]) -> str:
    obj = {
        "registry_version": registry_obj.get("registry_version"),
        "canonical_entry": registry_obj.get("canonical_entry"),
        "canonical_spine": registry_obj.get("canonical_spine"),
        "state_vault": registry_obj.get("state_vault"),
        "runtime_import_roots": registry_obj.get("runtime_import_roots"),
        "organs_by_root": registry_obj.get("organs_by_root"),
        "import_truth_matrix": registry_obj.get("import_truth_matrix"),
        "dry_run": registry_obj.get("dry_run"),
    }
    return sha256_json(obj)


def _load_runtime_registry_hash(path: Path) -> str:
    raw = path.read_text(encoding="utf-8")
    registry_obj = json.loads(raw)
    if not isinstance(registry_obj, dict):
        raise TeacherSchemaError("runtime registry must be a JSON object (fail-closed)")
    return _canonical_registry_hash(registry_obj)


def _load_json(path: Path) -> Dict[str, object]:
    raw = path.read_text(encoding="utf-8")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise TeacherSchemaError(f"{path.as_posix()} must be JSON object (fail-closed)")
    return obj


def _hash_run_record(run_record: Dict[str, object]) -> str:
    obj = {
        "crucible_id": run_record.get("crucible_id"),
        "run_id": run_record.get("run_id"),
        "outcome": run_record.get("outcome"),
    }
    return sha256_json(obj)


def _hash_epoch_manifest(manifest: Dict[str, object]) -> str:
    obj = {
        "epoch_id": manifest.get("epoch_id"),
        "epoch_hash": manifest.get("epoch_hash"),
        "kernel_identity": manifest.get("kernel_identity"),
    }
    return sha256_json(obj)


def compile_bundle(bundle_path: Path) -> CompiledPackage:
    bundle = _load_bundle(bundle_path)
    payload = bundle.to_dict()

    runtime_registry_path = Path(payload["runtime_registry_path"]).resolve()
    runtime_registry_hash = _load_runtime_registry_hash(runtime_registry_path)

    max_examples = int(payload["bounds"]["max_examples"])
    max_instructions = int(payload["bounds"]["max_instructions"])
    max_constraints = int(payload["bounds"]["max_constraints"])

    examples: List[str] = []
    instructions: List[str] = []
    constraints: List[str] = []

    # Only consume allowed extract types.
    extract_types = set(payload.get("extract_types") or [])
    if "RUN_RECORD" in extract_types:
        for p in payload.get("run_record_paths") or []:
            run_record = _load_json(Path(p))
            if len(examples) < max_examples:
                examples.append(_hash_run_record(run_record))

    if "EPOCH_MANIFEST" in extract_types:
        for p in payload.get("epoch_manifest_paths") or []:
            manifest = _load_json(Path(p))
            if len(constraints) < max_constraints:
                constraints.append(_hash_epoch_manifest(manifest))

    # No instructions unless explicitly provided by extract type (kept empty by default).
    instructions = instructions[:max_instructions]

    draft_payload = {
        "schema_id": CurriculumDraftSchema.SCHEMA_ID,
        "schema_version_hash": CurriculumDraftSchema.SCHEMA_VERSION_HASH,
        "examples": examples,
        "instructions": instructions,
        "constraints": constraints,
    }
    CurriculumDraftSchema.validate(draft_payload)

    package_id = sha256_json(
        {
            "runtime_registry_hash": runtime_registry_hash,
            "examples": sorted(examples),
            "instructions": sorted(instructions),
            "constraints": sorted(constraints),
        }
    )

    package_payload = {
        "schema_id": CurriculumPackageSchema.SCHEMA_ID,
        "schema_version_hash": CurriculumPackageSchema.SCHEMA_VERSION_HASH,
        "package_id": package_id,
        "runtime_registry_hash": runtime_registry_hash,
        "examples": examples,
        "instructions": instructions,
        "constraints": constraints,
    }
    CurriculumPackageSchema.validate(package_payload)
    package_hash = CurriculumPackageSchema.compute_package_hash(package_payload)
    return CompiledPackage(package=CurriculumPackageSchema.from_dict(package_payload), package_hash=package_hash)
