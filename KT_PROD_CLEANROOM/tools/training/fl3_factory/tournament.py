from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import sha256_json
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object


def build_blind_pack(*, job_id: str, items: list[dict]) -> Dict[str, Any]:
    from schemas.schema_files import schema_version_hash  # type: ignore

    record = {
        "schema_id": "kt.blind_judgement_pack.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.blind_judgement_pack.v1.json"),
        "pack_id": "",
        "job_id": job_id,
        "items": items,
        "created_at": utc_now_z(),
    }
    record["pack_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "pack_id"}})
    return record


def build_reveal_mapping(
    *,
    job_id: str,
    mappings: dict[str, dict],
    sealed: bool,
    verdict_ref: Optional[str],
) -> Dict[str, Any]:
    from schemas.schema_files import schema_version_hash  # type: ignore

    record = {
        "schema_id": "kt.reveal_mapping.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.reveal_mapping.v1.json"),
        "mapping_id": "",
        "job_id": job_id,
        "sealed": bool(sealed),
        "verdict_ref": verdict_ref,
        "mappings": mappings,
        "created_at": utc_now_z(),
    }
    record["mapping_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "mapping_id"}})
    return record


def unseal_reveal_mapping(
    *,
    job_dir: Path,
    sealed_mapping: Dict[str, Any],
    verdict_ref: str,
) -> Dict[str, Any]:
    """
    Fail-closed unsealing: the verdict must exist on disk before revealing identity.
    """
    if not (job_dir / verdict_ref).exists():
        raise FL3ValidationError("Cannot unseal reveal mapping before verdict exists (fail-closed)")
    if sealed_mapping.get("sealed") is not True:
        raise FL3ValidationError("Expected sealed reveal mapping (fail-closed)")
    mappings = sealed_mapping.get("mappings")
    if not isinstance(mappings, dict):
        raise FL3ValidationError("reveal mappings invalid (fail-closed)")
    return build_reveal_mapping(
        job_id=str(sealed_mapping.get("job_id")),
        mappings=mappings,
        sealed=False,
        verdict_ref=verdict_ref,
    )


def build_tournament_manifest(*, job_id: str, blind_pack_ref: str, reveal_mapping_ref: str) -> Dict[str, Any]:
    from schemas.schema_files import schema_version_hash  # type: ignore

    record = {
        "schema_id": "kt.tournament_manifest.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.tournament_manifest.v1.json"),
        "tournament_id": "",
        "job_id": job_id,
        "blind_pack_ref": blind_pack_ref,
        "reveal_mapping_ref": reveal_mapping_ref,
        "created_at": utc_now_z(),
    }
    record["tournament_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "tournament_id"}})
    return record


def blind_items_from_dataset(dataset: Dict[str, Any]) -> list[dict]:
    """
    Derive blind items from a dataset in a way that forbids identity fields.
    Each item is strictly {prompt_hash, candidate_hash}.
    """
    rows = dataset.get("rows")
    if not isinstance(rows, list):
        raise FL3ValidationError("dataset.rows invalid (fail-closed)")
    items: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            raise FL3ValidationError("dataset row must be object (fail-closed)")
        prompt_hash = row.get("prompt_hash")
        cand_hash = row.get("candidate_hash")
        if not isinstance(prompt_hash, str) or not isinstance(cand_hash, str):
            raise FL3ValidationError("dataset row missing prompt_hash/candidate_hash (fail-closed)")
        items.append({"prompt_hash": prompt_hash, "candidate_hash": cand_hash})
    return items


def validate_tournament_artifacts(*, blind_pack: Dict[str, Any], sealed_mapping: Dict[str, Any], manifest: Dict[str, Any]) -> None:
    # Schema-level enforcement is the primary defense against identity leakage.
    validate_schema_bound_object(blind_pack)
    validate_schema_bound_object(sealed_mapping)
    validate_schema_bound_object(manifest)
    if sealed_mapping.get("sealed") is not True:
        raise FL3ValidationError("sealed mapping must have sealed=true (fail-closed)")

