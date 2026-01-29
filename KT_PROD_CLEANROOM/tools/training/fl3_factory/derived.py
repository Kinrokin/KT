from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Tuple

from tools.training.fl3_factory.io import read_json_object, write_schema_object
from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import sha256_bytes, sha256_json, sha256_text
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object


@dataclass(frozen=True)
class DerivedArtifacts:
    immune_snapshot: Dict[str, Any]
    epigenetic_summary: Dict[str, Any]
    fitness_region: Dict[str, Any]


def _schema_hash(schema_file: str) -> str:
    from schemas.schema_files import schema_version_hash  # type: ignore

    return schema_version_hash(schema_file)


def build_immune_snapshot(*, parent_hash: str, paradox: int = 0, trace_viol: int = 0, schema_viol: int = 0) -> Dict[str, Any]:
    record = {
        "schema_id": "kt.immune_snapshot.v1",
        "schema_version_hash": _schema_hash("fl3/kt.immune_snapshot.v1.json"),
        "snapshot_id": "",
        "immune_events_total": int(paradox + trace_viol + schema_viol),
        "counts": {"paradox_event": int(paradox), "trace_violation": int(trace_viol), "schema_violation": int(schema_viol)},
        "parent_hash": parent_hash,
        "created_at": utc_now_z(),
    }
    record["snapshot_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "snapshot_id"}})
    validate_schema_bound_object(record)
    return record


def build_epigenetic_summary(*, parent_hash: str) -> Dict[str, Any]:
    record = {
        "schema_id": "kt.epigenetic_summary.v1",
        "schema_version_hash": _schema_hash("fl3/kt.epigenetic_summary.v1.json"),
        "summary_id": "",
        "paradox_survival_count": 0,
        "recovery_efficiency": 0.0,
        "lineage_weight": 0.0,
        "signed_by": "meta_evaluator_key",
        "parent_hash": parent_hash,
        "created_at": utc_now_z(),
    }
    record["summary_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "summary_id"}})
    validate_schema_bound_object(record)
    return record


def _load_fitness_policy(*, repo_root: Path) -> Dict[str, Any]:
    policy_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FL3_FITNESS_POLICY.json"
    if not policy_path.exists():
        raise FL3ValidationError(f"Missing fitness policy (fail-closed): {policy_path.as_posix()}")
    policy = read_json_object(policy_path)
    validate_schema_bound_object(policy)
    return policy


def compute_fitness_region(
    *,
    policy: Dict[str, Any],
    signal_quality: Dict[str, Any],
    immune_snapshot: Dict[str, Any],
) -> str:
    risk = float(signal_quality.get("risk_estimate", 1.0))
    strikes = int(signal_quality.get("governance_strikes", 999))
    risk_max = float(policy["risk_max"])
    strikes_max = int(policy["governance_strikes_max"])
    min_immune = int(policy.get("min_immune_events", 0))
    immune_total = int(immune_snapshot.get("immune_events_total", 0))

    if strikes > strikes_max or risk >= risk_max:
        return "C"
    if immune_total < min_immune:
        return "B"
    return "A"


def build_fitness_region(
    *,
    adapter_version: str,
    signal_quality_hash: str,
    immune_snapshot_hash: str,
    epigenetic_summary_hash: str,
    derivation_policy_hash: str,
    parent_hash: str,
    fitness_region: str,
) -> Dict[str, Any]:
    record = {
        "schema_id": "kt.fitness_region.v1",
        "schema_version_hash": _schema_hash("fl3/kt.fitness_region.v1.json"),
        "fitness_id": "",
        "adapter_version": adapter_version,
        "derived_from": {
            "signal_quality_hash": signal_quality_hash,
            "immune_snapshot_hash": immune_snapshot_hash,
            "epigenetic_summary_hash": epigenetic_summary_hash,
        },
        "fitness_region": fitness_region,
        "derivation_policy_hash": derivation_policy_hash,
        "parent_hash": parent_hash,
        "created_at": utc_now_z(),
    }
    record["fitness_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "fitness_id"}})
    validate_schema_bound_object(record)
    return record


def build_shadow_adapter_manifest(
    *,
    adapter_version: str,
    weights_path: Path,
    parent_hash: str,
) -> Dict[str, Any]:
    if weights_path.suffix.lower() != ".safetensors":
        raise FL3ValidationError("Shadow weights must be stored as .safetensors (fail-closed)")
    checksum = sha256_bytes(weights_path.read_bytes())
    record = {
        "schema_id": "kt.shadow_adapter_manifest.v1",
        "schema_version_hash": _schema_hash("fl3/kt.shadow_adapter_manifest.v1.json"),
        "shadow_id": "",
        "adapter_version": adapter_version,
        "storage_format": "safetensors",
        "checksum": checksum,
        "fitness_region": "B",
        "signed_by": "meta_evaluator_key",
        "parent_hash": parent_hash,
        "created_at": utc_now_z(),
    }
    record["shadow_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "shadow_id"}})
    validate_schema_bound_object(record)
    return record


def derive_and_write(
    *,
    repo_root: Path,
    job_dir: Path,
    job: Dict[str, Any],
    signal_quality_path: Path,
    parent_hash: str,
) -> Tuple[DerivedArtifacts, Dict[str, Any]]:
    signal = read_json_object(signal_quality_path)
    validate_schema_bound_object(signal)
    policy = _load_fitness_policy(repo_root=repo_root)
    policy_hash = sha256_json(policy)

    immune = build_immune_snapshot(parent_hash=parent_hash, paradox=0, trace_viol=0, schema_viol=0)
    epi = build_epigenetic_summary(parent_hash=parent_hash)
    region = compute_fitness_region(policy=policy, signal_quality=signal, immune_snapshot=immune)
    signal_hash = sha256_json(signal)
    immune_hash = sha256_json(immune)
    epi_hash = sha256_json(epi)
    fitness = build_fitness_region(
        adapter_version=str(job["adapter_version"]),
        signal_quality_hash=signal_hash,
        immune_snapshot_hash=immune_hash,
        epigenetic_summary_hash=epi_hash,
        derivation_policy_hash=policy_hash,
        parent_hash=parent_hash,
        fitness_region=region,
    )

    immune_path = job_dir / "immune_snapshot.json"
    epi_path = job_dir / "epigenetic_summary.json"
    fitness_path = job_dir / "fitness_region.json"
    _ = write_schema_object(path=immune_path, obj=immune)
    _ = write_schema_object(path=epi_path, obj=epi)
    _ = write_schema_object(path=fitness_path, obj=fitness)

    return DerivedArtifacts(immune_snapshot=immune, epigenetic_summary=epi, fitness_region=fitness), {"policy_hash": policy_hash}
