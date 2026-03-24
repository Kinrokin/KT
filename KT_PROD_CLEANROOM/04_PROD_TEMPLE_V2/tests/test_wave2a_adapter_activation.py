from __future__ import annotations

import json
from pathlib import Path

import pytest

from council.providers.adapter_abi_runtime import (
    AdapterAbiError,
    adapter_export_root,
    load_active_adapter_manifests,
    resolve_live_adapter,
)


def _runtime_registry_path() -> Path:
    return Path(__file__).resolve().parents[1] / "docs" / "RUNTIME_REGISTRY.json"


def test_wave2a_active_adapter_manifests_load_expected_ids() -> None:
    manifests = load_active_adapter_manifests()
    assert sorted(manifests) == [
        "council.openai.live_hashed.v1",
        "council.openrouter.live_hashed.v1",
    ]
    for manifest in manifests.values():
        assert manifest.execution_mode == "LIVE"
        assert manifest.status == "ACTIVE"
        assert manifest.request_type_allowlist == ("analysis", "healthcheck")
        assert manifest.manifest_path.is_relative_to(adapter_export_root())


def test_wave2a_runtime_registry_entries_match_active_manifests() -> None:
    registry = json.loads(_runtime_registry_path().read_text(encoding="utf-8"))
    entries = registry["adapters"]["entries"]
    entry_ids = sorted(row["adapter_id"] for row in entries if row["status"] == "ACTIVE")
    manifest_ids = sorted(load_active_adapter_manifests())
    assert entry_ids == manifest_ids


def test_wave2a_resolve_live_adapter_rejects_request_type_outside_allowlist() -> None:
    with pytest.raises(AdapterAbiError):
        resolve_live_adapter(
            adapter_id="council.openai.live_hashed.v1",
            request_type="forbidden_request_type",
            provider_id="openai",
        )
