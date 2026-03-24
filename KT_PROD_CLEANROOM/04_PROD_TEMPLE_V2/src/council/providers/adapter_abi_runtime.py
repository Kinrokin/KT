from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List


ALLOWED_EXECUTION_MODES = {"DRY_RUN", "SHADOW", "LIVE", "ADVERSARIAL"}
ALLOWED_STATUSES = {"ACTIVE", "DEPRECATED", "REVOKED"}
LEGACY_PROVIDER_MAP = {
    "openai": "council.openai.live_hashed.v1",
    "openrouter": "council.openrouter.live_hashed.v1",
}
REQUIRED_FIELDS = (
    "adapter_id",
    "adapter_kind",
    "version",
    "execution_mode",
    "policy_profile",
    "budget_profile",
    "provenance_requirements",
    "challenge_hooks",
    "provider_id",
    "timeout_ms",
    "retry_policy",
    "circuit_breaker_policy",
    "rate_limit_profile",
    "replayability_class",
    "status",
    "io_schema_ref",
)


class AdapterAbiError(RuntimeError):
    pass


@dataclass(frozen=True)
class AdapterManifest:
    adapter_id: str
    adapter_kind: str
    version: str
    execution_mode: str
    policy_profile: str
    budget_profile: str
    provenance_requirements: tuple[str, ...]
    challenge_hooks: tuple[str, ...]
    provider_id: str
    timeout_ms: int
    retry_policy: Dict[str, Any]
    circuit_breaker_policy: Dict[str, Any]
    rate_limit_profile: Dict[str, Any]
    replayability_class: str
    status: str
    io_schema_ref: str
    request_type_allowlist: tuple[str, ...]
    manifest_path: Path


def temple_root() -> Path:
    return Path(__file__).resolve().parents[3]


def adapter_export_root() -> Path:
    return temple_root() / "exports" / "adapters"


def derive_legacy_adapter_id(*, provider_id: str) -> str:
    adapter_id = LEGACY_PROVIDER_MAP.get(str(provider_id).strip())
    if not adapter_id:
        raise AdapterAbiError(f"provider_id has no active adapter binding (fail-closed): {provider_id!r}")
    return adapter_id


def load_active_adapter_manifests() -> Dict[str, AdapterManifest]:
    manifests: Dict[str, AdapterManifest] = {}
    root = adapter_export_root()
    if not root.exists():
        raise AdapterAbiError(f"adapter export root missing (fail-closed): {root.as_posix()}")
    for manifest_path in sorted(root.rglob("adapter_manifest.json")):
        payload = _read_manifest(manifest_path)
        manifest = _parse_manifest(payload=payload, manifest_path=manifest_path)
        if manifest.status != "ACTIVE":
            continue
        if manifest.adapter_id in manifests:
            raise AdapterAbiError(f"duplicate adapter_id discovered (fail-closed): {manifest.adapter_id!r}")
        manifests[manifest.adapter_id] = manifest
    return manifests


def load_adapter_manifest(*, adapter_id: str) -> AdapterManifest:
    manifests = load_active_adapter_manifests()
    manifest = manifests.get(str(adapter_id).strip())
    if manifest is None:
        raise AdapterAbiError(f"adapter_id not found in active adapter manifests (fail-closed): {adapter_id!r}")
    return manifest


def resolve_live_adapter(*, adapter_id: str, request_type: str, provider_id: str = "") -> AdapterManifest:
    manifest = load_adapter_manifest(adapter_id=adapter_id)
    if manifest.execution_mode != "LIVE":
        raise AdapterAbiError(f"adapter execution_mode is not LIVE (fail-closed): {manifest.execution_mode!r}")
    if request_type not in manifest.request_type_allowlist:
        raise AdapterAbiError(f"request_type not allowlisted for adapter (fail-closed): {request_type!r}")
    if provider_id and provider_id != manifest.provider_id:
        raise AdapterAbiError("provider_id does not match adapter manifest binding (fail-closed)")
    return manifest


def _read_manifest(path: Path) -> Dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise AdapterAbiError(f"unable to load adapter manifest (fail-closed): {path.as_posix()}") from exc
    if not isinstance(payload, dict):
        raise AdapterAbiError(f"adapter manifest must be object (fail-closed): {path.as_posix()}")
    return payload


def _parse_manifest(*, payload: Dict[str, Any], manifest_path: Path) -> AdapterManifest:
    missing = [field for field in REQUIRED_FIELDS if field not in payload]
    if missing:
        raise AdapterAbiError(f"adapter manifest missing required fields (fail-closed): {sorted(missing)}")

    adapter_id = _require_non_empty_str(payload, "adapter_id")
    adapter_kind = _require_non_empty_str(payload, "adapter_kind")
    version = _require_non_empty_str(payload, "version")
    execution_mode = _require_non_empty_str(payload, "execution_mode")
    policy_profile = _require_non_empty_str(payload, "policy_profile")
    budget_profile = _require_non_empty_str(payload, "budget_profile")
    provider_id = _require_non_empty_str(payload, "provider_id")
    replayability_class = _require_non_empty_str(payload, "replayability_class")
    status = _require_non_empty_str(payload, "status")
    io_schema_ref = _require_non_empty_str(payload, "io_schema_ref")
    timeout_ms = payload.get("timeout_ms")
    if not isinstance(timeout_ms, int) or timeout_ms <= 0 or timeout_ms > 120_000:
        raise AdapterAbiError("adapter timeout_ms invalid (fail-closed)")
    if execution_mode not in ALLOWED_EXECUTION_MODES:
        raise AdapterAbiError("adapter execution_mode invalid (fail-closed)")
    if status not in ALLOWED_STATUSES:
        raise AdapterAbiError("adapter status invalid (fail-closed)")

    provenance_requirements = tuple(_require_str_list(payload, "provenance_requirements"))
    challenge_hooks = tuple(_require_str_list(payload, "challenge_hooks"))
    request_type_allowlist = tuple(_require_str_list(payload, "request_type_allowlist"))
    retry_policy = _require_dict(payload, "retry_policy")
    circuit_breaker_policy = _require_dict(payload, "circuit_breaker_policy")
    rate_limit_profile = _require_dict(payload, "rate_limit_profile")

    return AdapterManifest(
        adapter_id=adapter_id,
        adapter_kind=adapter_kind,
        version=version,
        execution_mode=execution_mode,
        policy_profile=policy_profile,
        budget_profile=budget_profile,
        provenance_requirements=provenance_requirements,
        challenge_hooks=challenge_hooks,
        provider_id=provider_id,
        timeout_ms=timeout_ms,
        retry_policy=retry_policy,
        circuit_breaker_policy=circuit_breaker_policy,
        rate_limit_profile=rate_limit_profile,
        replayability_class=replayability_class,
        status=status,
        io_schema_ref=io_schema_ref,
        request_type_allowlist=request_type_allowlist,
        manifest_path=manifest_path,
    )


def _require_non_empty_str(payload: Dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise AdapterAbiError(f"{field} must be non-empty string (fail-closed)")
    return value.strip()


def _require_str_list(payload: Dict[str, Any], field: str) -> List[str]:
    value = payload.get(field)
    if not isinstance(value, list) or not value:
        raise AdapterAbiError(f"{field} must be non-empty list of strings (fail-closed)")
    out: List[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise AdapterAbiError(f"{field} must be non-empty list of strings (fail-closed)")
        out.append(item.strip())
    return sorted(_unique(out))


def _require_dict(payload: Dict[str, Any], field: str) -> Dict[str, Any]:
    value = payload.get(field)
    if not isinstance(value, dict) or not value:
        raise AdapterAbiError(f"{field} must be non-empty object (fail-closed)")
    return dict(value)


def _unique(items: Iterable[str]) -> Iterable[str]:
    seen = set()
    for item in items:
        if item not in seen:
            seen.add(item)
            yield item
