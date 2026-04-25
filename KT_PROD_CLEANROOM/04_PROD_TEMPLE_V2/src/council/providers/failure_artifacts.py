from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict


def _canonical_json(obj: Dict[str, object]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class FailureArtifact:
    artifact_id: str
    artifact_ref: str
    payload: Dict[str, object]
    path: Path


def write_failure_artifact(
    *,
    export_root: Path,
    surface_id: str,
    error_class: str,
    bounded_reason: str,
    input_hash: str,
    context_hash: str,
    policy_profile: str,
    budget_profile: str,
    replay_pack_ref: str,
    severity: str,
    operator_visibility: str = "OPERATOR_VISIBLE",
    signature_or_receipt_ref: str = "",
    wave_id: str = "WAVE_2A_ADAPTER_ABI_AND_PROVIDER_ACTIVATION",
) -> FailureArtifact:
    base = {
        "surface_id": str(surface_id).strip(),
        "wave_id": str(wave_id).strip(),
        "error_class": str(error_class).strip(),
        "bounded_reason": str(bounded_reason).strip(),
        "input_hash": str(input_hash).strip(),
        "context_hash": str(context_hash).strip(),
        "policy_profile": str(policy_profile).strip(),
        "budget_profile": str(budget_profile).strip(),
        "replay_pack_ref": str(replay_pack_ref).strip(),
        "operator_visibility": str(operator_visibility).strip(),
        "severity": str(severity).strip(),
        "signature_or_receipt_ref": str(signature_or_receipt_ref).strip(),
    }
    artifact_id = _sha256_text(_canonical_json(base))
    payload: Dict[str, object] = {
        "failure_id": artifact_id,
        "timestamp": "1970-01-01T00:00:00Z",
        **base,
    }
    path = export_root / "failure_artifacts" / f"{artifact_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_canonical_json(payload), encoding="utf-8")
    return FailureArtifact(
        artifact_id=artifact_id,
        artifact_ref=path.as_posix(),
        payload=payload,
        path=path,
    )
