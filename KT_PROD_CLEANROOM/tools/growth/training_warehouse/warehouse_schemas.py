from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple


class WarehouseSchemaError(ValueError):
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
        raise WarehouseSchemaError(f"{name} contains unknown keys: {sorted(unknown)} (fail-closed)")


def _require_dict(value: Any, *, name: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise WarehouseSchemaError(f"{name} must be an object (fail-closed)")
    return dict(value)


def _require_list(value: Any, *, name: str) -> List[Any]:
    if not isinstance(value, list):
        raise WarehouseSchemaError(f"{name} must be a list (fail-closed)")
    return list(value)


def _require_str(value: Any, *, name: str, min_len: int = 0, max_len: int = 4096) -> str:
    if not isinstance(value, str):
        raise WarehouseSchemaError(f"{name} must be a string (fail-closed)")
    if not (min_len <= len(value) <= max_len):
        raise WarehouseSchemaError(f"{name} length out of bounds (fail-closed)")
    return value


def _require_bool(value: Any, *, name: str) -> bool:
    if not isinstance(value, bool):
        raise WarehouseSchemaError(f"{name} must be a bool (fail-closed)")
    return bool(value)


def _require_int(value: Any, *, name: str, lo: int, hi: int) -> int:
    if not isinstance(value, int):
        raise WarehouseSchemaError(f"{name} must be an integer (fail-closed)")
    if not (lo <= value <= hi):
        raise WarehouseSchemaError(f"{name} out of bounds (fail-closed)")
    return value


def _require_hex64(value: Any, *, name: str) -> str:
    s = _require_str(value, name=name, min_len=64, max_len=64)
    try:
        int(s, 16)
    except Exception:
        raise WarehouseSchemaError(f"{name} must be hex (fail-closed)")
    return s


ALLOWED_LICENSES: Set[str] = {"INTERNAL_ONLY", "UNKNOWN"}


@dataclass(frozen=True)
class ExtractionPolicySchema:
    policy_id: str
    allow_raw_text: bool
    max_text_bytes: int

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "ExtractionPolicySchema":
        payload = _require_dict(data, name="ExtractionPolicy")
        _reject_unknown_keys(payload, allowed={"policy_id", "allow_raw_text", "max_text_bytes"}, name="ExtractionPolicy")
        policy_id = _require_str(payload.get("policy_id"), name="policy_id", min_len=1, max_len=80)
        allow_raw_text = _require_bool(payload.get("allow_raw_text"), name="allow_raw_text")
        max_text_bytes = _require_int(payload.get("max_text_bytes"), name="max_text_bytes", lo=0, hi=256_000)
        return ExtractionPolicySchema(policy_id=policy_id, allow_raw_text=allow_raw_text, max_text_bytes=max_text_bytes)

    def to_dict(self) -> Dict[str, Any]:
        return {"policy_id": self.policy_id, "allow_raw_text": self.allow_raw_text, "max_text_bytes": self.max_text_bytes}


@dataclass(frozen=True)
class TrainingExemplarSchema:
    schema: str
    schema_version: int
    exemplar_id: str
    kernel_target: str
    epoch_id: str
    crucible_id: str
    run_id: str
    provenance: Dict[str, str]
    extraction_justification: str
    license: str
    usage_flags: Dict[str, bool]
    content: Dict[str, Any]
    exemplar_hash: str

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "TrainingExemplarSchema":
        payload = _require_dict(data, name="TrainingExemplar")
        _reject_unknown_keys(
            payload,
            allowed={
                "schema",
                "schema_version",
                "exemplar_id",
                "kernel_target",
                "epoch_id",
                "crucible_id",
                "run_id",
                "provenance",
                "extraction_justification",
                "license",
                "usage_flags",
                "content",
                "exemplar_hash",
            },
            name="TrainingExemplar",
        )
        if payload.get("schema") != "kt.training.exemplar":
            raise WarehouseSchemaError("schema mismatch (fail-closed)")
        schema_version = _require_int(payload.get("schema_version"), name="schema_version", lo=1, hi=1)
        exemplar_id = _require_hex64(payload.get("exemplar_id"), name="exemplar_id")
        kernel_target = _require_str(payload.get("kernel_target"), name="kernel_target", min_len=1, max_len=32)
        epoch_id = _require_str(payload.get("epoch_id"), name="epoch_id", min_len=1, max_len=128)
        crucible_id = _require_str(payload.get("crucible_id"), name="crucible_id", min_len=1, max_len=80)
        run_id = _require_hex64(payload.get("run_id"), name="run_id")

        provenance = _require_dict(payload.get("provenance"), name="provenance")
        # Provenance is metadata-only; bound keys.
        _reject_unknown_keys(
            provenance,
            allowed={"artifacts_dir", "replay_head_hash", "record_count", "governance_types"},
            name="provenance",
        )
        for k, v in provenance.items():
            if k == "record_count":
                _require_int(v, name="provenance.record_count", lo=0, hi=10_000_000)
            else:
                _require_str(v, name=f"provenance.{k}", min_len=0, max_len=2048)

        extraction_justification = _require_str(
            payload.get("extraction_justification"), name="extraction_justification", min_len=1, max_len=1024
        )
        license_val = _require_str(payload.get("license"), name="license", min_len=1, max_len=64)
        if license_val not in ALLOWED_LICENSES:
            raise WarehouseSchemaError("license not allowed (fail-closed)")

        usage_flags = _require_dict(payload.get("usage_flags"), name="usage_flags")
        _reject_unknown_keys(usage_flags, allowed={"allow_training", "allow_distillation"}, name="usage_flags")
        allow_training = _require_bool(usage_flags.get("allow_training"), name="usage_flags.allow_training")
        allow_distillation = _require_bool(usage_flags.get("allow_distillation"), name="usage_flags.allow_distillation")

        content = _require_dict(payload.get("content"), name="content")
        # Fail-closed: require a small, explicit allowlist of top-level content keys.
        _reject_unknown_keys(content, allowed={"prompt", "expected_outcome", "notes"}, name="content")
        prompt = _require_str(content.get("prompt"), name="content.prompt", min_len=0, max_len=32_768)
        expected_outcome = _require_str(content.get("expected_outcome"), name="content.expected_outcome", min_len=1, max_len=32)
        notes = _require_str(content.get("notes", ""), name="content.notes", min_len=0, max_len=4000)
        _ = (prompt, expected_outcome, notes)

        exemplar_hash = _require_hex64(payload.get("exemplar_hash"), name="exemplar_hash")
        computed = sha256_json({k: payload[k] for k in payload.keys() if k != "exemplar_hash"})
        if computed != exemplar_hash:
            raise WarehouseSchemaError("exemplar_hash mismatch (fail-closed)")

        return TrainingExemplarSchema(
            schema="kt.training.exemplar",
            schema_version=schema_version,
            exemplar_id=exemplar_id,
            kernel_target=kernel_target,
            epoch_id=epoch_id,
            crucible_id=crucible_id,
            run_id=run_id,
            provenance=provenance,
            extraction_justification=extraction_justification,
            license=license_val,
            usage_flags={"allow_training": allow_training, "allow_distillation": allow_distillation},
            content={"prompt": prompt, "expected_outcome": expected_outcome, "notes": notes},
            exemplar_hash=exemplar_hash,
        )

    @staticmethod
    def make(
        *,
        kernel_target: str,
        epoch_id: str,
        crucible_id: str,
        run_id: str,
        provenance: Mapping[str, Any],
        extraction_justification: str,
        license: str,
        usage_flags: Mapping[str, bool],
        content: Mapping[str, Any],
    ) -> "TrainingExemplarSchema":
        exemplar_id = sha256_json(
            {
                "kernel_target": kernel_target,
                "epoch_id": epoch_id,
                "crucible_id": crucible_id,
                "run_id": run_id,
                "provenance": dict(provenance),
                "content": dict(content),
            }
        )
        payload = {
            "schema": "kt.training.exemplar",
            "schema_version": 1,
            "exemplar_id": exemplar_id,
            "kernel_target": kernel_target,
            "epoch_id": epoch_id,
            "crucible_id": crucible_id,
            "run_id": run_id,
            "provenance": dict(provenance),
            "extraction_justification": extraction_justification,
            "license": license,
            "usage_flags": dict(usage_flags),
            "content": dict(content),
        }
        exemplar_hash = sha256_json(payload)
        payload["exemplar_hash"] = exemplar_hash
        return TrainingExemplarSchema.from_dict(payload)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "exemplar_id": self.exemplar_id,
            "kernel_target": self.kernel_target,
            "epoch_id": self.epoch_id,
            "crucible_id": self.crucible_id,
            "run_id": self.run_id,
            "provenance": dict(self.provenance),
            "extraction_justification": self.extraction_justification,
            "license": self.license,
            "usage_flags": dict(self.usage_flags),
            "content": dict(self.content),
            "exemplar_hash": self.exemplar_hash,
        }


@dataclass(frozen=True)
class WarehouseManifestSchema:
    schema: str
    schema_version: int
    exemplar_id: str
    exemplar_hash: str
    bytes: int

    @staticmethod
    def from_exemplar(*, exemplar: TrainingExemplarSchema, bytes_len: int) -> "WarehouseManifestSchema":
        bytes_len = int(bytes_len)
        if bytes_len < 0:
            raise WarehouseSchemaError("bytes negative (fail-closed)")
        return WarehouseManifestSchema(
            schema="kt.training.warehouse.manifest_record",
            schema_version=1,
            exemplar_id=exemplar.exemplar_id,
            exemplar_hash=exemplar.exemplar_hash,
            bytes=bytes_len,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "exemplar_id": self.exemplar_id,
            "exemplar_hash": self.exemplar_hash,
            "bytes": self.bytes,
        }
