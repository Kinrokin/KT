from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Mapping, Set


class DistillSchemaError(ValueError):
    pass


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def sha256_json(obj: Any) -> str:
    return sha256_text(_canonical_json(obj))


def _reject_unknown_keys(payload: Mapping[str, Any], *, allowed: Iterable[str], name: str) -> None:
    unknown = set(payload.keys()) - set(allowed)
    if unknown:
        raise DistillSchemaError(f"{name} contains unknown keys: {sorted(unknown)} (fail-closed)")


def _require_dict(value: Any, *, name: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise DistillSchemaError(f"{name} must be an object (fail-closed)")
    return dict(value)


def _require_list(value: Any, *, name: str) -> List[Any]:
    if not isinstance(value, list):
        raise DistillSchemaError(f"{name} must be a list (fail-closed)")
    return list(value)


def _require_str(value: Any, *, name: str, min_len: int = 0, max_len: int = 256) -> str:
    if not isinstance(value, str):
        raise DistillSchemaError(f"{name} must be a string (fail-closed)")
    if not (min_len <= len(value) <= max_len):
        raise DistillSchemaError(f"{name} length out of bounds (fail-closed)")
    return value


def _require_int(value: Any, *, name: str, lo: int, hi: int) -> int:
    if not isinstance(value, int):
        raise DistillSchemaError(f"{name} must be an integer (fail-closed)")
    if not (lo <= value <= hi):
        raise DistillSchemaError(f"{name} out of bounds (fail-closed)")
    return value


def _require_hex64(value: Any, *, name: str) -> str:
    s = _require_str(value, name=name, min_len=64, max_len=64)
    try:
        int(s, 16)
    except Exception:
        raise DistillSchemaError(f"{name} must be hex (fail-closed)")
    return s


@dataclass(frozen=True)
class DistillationConfigSchema:
    schema: str
    schema_version: int
    config_id: str
    max_exemplars: int
    toolchain: Dict[str, str]
    config_hash: str

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "DistillationConfigSchema":
        payload = _require_dict(data, name="DistillationConfig")
        _reject_unknown_keys(payload, allowed={"schema", "schema_version", "config_id", "max_exemplars", "toolchain", "config_hash"}, name="DistillationConfig")
        if payload.get("schema") != "kt.distill.config":
            raise DistillSchemaError("schema mismatch (fail-closed)")
        schema_version = _require_int(payload.get("schema_version"), name="schema_version", lo=1, hi=1)
        config_id = _require_str(payload.get("config_id"), name="config_id", min_len=1, max_len=80)
        max_exemplars = _require_int(payload.get("max_exemplars"), name="max_exemplars", lo=1, hi=100_000)
        toolchain = _require_dict(payload.get("toolchain"), name="toolchain")
        _reject_unknown_keys(toolchain, allowed={"name", "version", "notes"}, name="toolchain")
        _require_str(toolchain.get("name"), name="toolchain.name", min_len=1, max_len=64)
        _require_str(toolchain.get("version", "unknown"), name="toolchain.version", min_len=0, max_len=64)
        _require_str(toolchain.get("notes", ""), name="toolchain.notes", min_len=0, max_len=256)
        config_hash = _require_hex64(payload.get("config_hash"), name="config_hash")
        computed = sha256_json({k: payload[k] for k in payload.keys() if k != "config_hash"})
        if computed != config_hash:
            raise DistillSchemaError("config_hash mismatch (fail-closed)")
        return DistillationConfigSchema(
            schema="kt.distill.config",
            schema_version=schema_version,
            config_id=config_id,
            max_exemplars=max_exemplars,
            toolchain=toolchain,
            config_hash=config_hash,
        )

    @staticmethod
    def make(*, config_id: str, max_exemplars: int, toolchain: Mapping[str, str]) -> "DistillationConfigSchema":
        payload = {
            "schema": "kt.distill.config",
            "schema_version": 1,
            "config_id": config_id,
            "max_exemplars": max_exemplars,
            "toolchain": dict(toolchain),
        }
        payload["config_hash"] = sha256_json(payload)
        return DistillationConfigSchema.from_dict(payload)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "config_id": self.config_id,
            "max_exemplars": self.max_exemplars,
            "toolchain": dict(self.toolchain),
            "config_hash": self.config_hash,
        }


@dataclass(frozen=True)
class TrainingRunManifestSchema:
    schema: str
    schema_version: int
    run_id: str
    config_hash: str
    warehouse_manifest_path: str
    exemplar_ids: List[str]
    exemplar_hashes: List[str]
    run_hash: str

    @staticmethod
    def make(
        *,
        run_id: str,
        config: DistillationConfigSchema,
        warehouse_manifest_path: str,
        exemplar_ids: List[str],
        exemplar_hashes: List[str],
    ) -> "TrainingRunManifestSchema":
        payload = {
            "schema": "kt.distill.run_manifest",
            "schema_version": 1,
            "run_id": run_id,
            "config_hash": config.config_hash,
            "warehouse_manifest_path": warehouse_manifest_path,
            "exemplar_ids": list(exemplar_ids),
            "exemplar_hashes": list(exemplar_hashes),
        }
        payload["run_hash"] = sha256_json(payload)
        return TrainingRunManifestSchema.from_dict(payload)

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "TrainingRunManifestSchema":
        payload = _require_dict(data, name="TrainingRunManifest")
        _reject_unknown_keys(
            payload,
            allowed={"schema", "schema_version", "run_id", "config_hash", "warehouse_manifest_path", "exemplar_ids", "exemplar_hashes", "run_hash"},
            name="TrainingRunManifest",
        )
        if payload.get("schema") != "kt.distill.run_manifest":
            raise DistillSchemaError("schema mismatch (fail-closed)")
        _require_int(payload.get("schema_version"), name="schema_version", lo=1, hi=1)
        run_id = _require_hex64(payload.get("run_id"), name="run_id")
        config_hash = _require_hex64(payload.get("config_hash"), name="config_hash")
        warehouse_manifest_path = _require_str(payload.get("warehouse_manifest_path"), name="warehouse_manifest_path", min_len=1, max_len=512)
        exemplar_ids = _require_list(payload.get("exemplar_ids"), name="exemplar_ids")
        exemplar_ids_s = [_require_hex64(x, name="exemplar_ids[]") for x in exemplar_ids]
        exemplar_hashes = _require_list(payload.get("exemplar_hashes"), name="exemplar_hashes")
        exemplar_hashes_s = [_require_hex64(x, name="exemplar_hashes[]") for x in exemplar_hashes]
        if len(exemplar_ids_s) != len(exemplar_hashes_s):
            raise DistillSchemaError("ids/hashes length mismatch (fail-closed)")
        run_hash = _require_hex64(payload.get("run_hash"), name="run_hash")
        computed = sha256_json({k: payload[k] for k in payload.keys() if k != "run_hash"})
        if computed != run_hash:
            raise DistillSchemaError("run_hash mismatch (fail-closed)")
        return TrainingRunManifestSchema(
            schema="kt.distill.run_manifest",
            schema_version=1,
            run_id=run_id,
            config_hash=config_hash,
            warehouse_manifest_path=warehouse_manifest_path,
            exemplar_ids=exemplar_ids_s,
            exemplar_hashes=exemplar_hashes_s,
            run_hash=run_hash,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "config_hash": self.config_hash,
            "warehouse_manifest_path": self.warehouse_manifest_path,
            "exemplar_ids": list(self.exemplar_ids),
            "exemplar_hashes": list(self.exemplar_hashes),
            "run_hash": self.run_hash,
        }


@dataclass(frozen=True)
class ModelArtifactSchema:
    schema: str
    schema_version: int
    artifact_id: str
    run_hash: str
    artifact_type: str
    artifact_hash: str

    @staticmethod
    def make(*, run_manifest: TrainingRunManifestSchema, artifact_type: str = "MODEL_ARTIFACT_METADATA") -> "ModelArtifactSchema":
        artifact_type = _require_str(artifact_type, name="artifact_type", min_len=1, max_len=64)
        payload = {
            "schema": "kt.distill.model_artifact",
            "schema_version": 1,
            "artifact_id": sha256_json({"run_hash": run_manifest.run_hash, "artifact_type": artifact_type}),
            "run_hash": run_manifest.run_hash,
            "artifact_type": artifact_type,
        }
        payload["artifact_hash"] = sha256_json(payload)
        return ModelArtifactSchema.from_dict(payload)

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "ModelArtifactSchema":
        payload = _require_dict(data, name="ModelArtifact")
        _reject_unknown_keys(payload, allowed={"schema", "schema_version", "artifact_id", "run_hash", "artifact_type", "artifact_hash"}, name="ModelArtifact")
        if payload.get("schema") != "kt.distill.model_artifact":
            raise DistillSchemaError("schema mismatch (fail-closed)")
        _require_int(payload.get("schema_version"), name="schema_version", lo=1, hi=1)
        artifact_id = _require_hex64(payload.get("artifact_id"), name="artifact_id")
        run_hash = _require_hex64(payload.get("run_hash"), name="run_hash")
        artifact_type = _require_str(payload.get("artifact_type"), name="artifact_type", min_len=1, max_len=64)
        artifact_hash = _require_hex64(payload.get("artifact_hash"), name="artifact_hash")
        computed = sha256_json({k: payload[k] for k in payload.keys() if k != "artifact_hash"})
        if computed != artifact_hash:
            raise DistillSchemaError("artifact_hash mismatch (fail-closed)")
        return ModelArtifactSchema(
            schema="kt.distill.model_artifact",
            schema_version=1,
            artifact_id=artifact_id,
            run_hash=run_hash,
            artifact_type=artifact_type,
            artifact_hash=artifact_hash,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "artifact_id": self.artifact_id,
            "run_hash": self.run_hash,
            "artifact_type": self.artifact_type,
            "artifact_hash": self.artifact_hash,
        }

