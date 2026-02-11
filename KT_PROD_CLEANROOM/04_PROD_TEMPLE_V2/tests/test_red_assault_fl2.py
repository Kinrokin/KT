from __future__ import annotations

from pathlib import Path


def _import_modules():
    import sys

    repo_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str((repo_root / "src").resolve()))
    from core.routing_receipts import build_adapter_invocation, build_routing_record  # noqa: E402
    from core.runtime_registry import RuntimeRegistryError, _parse_adapters_spec  # noqa: E402
    from schemas.adapter_entry_schema import ADAPTER_ENTRY_SCHEMA_ID, ADAPTER_ENTRY_SCHEMA_VERSION_HASH  # noqa: E402
    from schemas.schema_registry import validate_object_with_binding  # noqa: E402

    return (
        repo_root,
        build_routing_record,
        build_adapter_invocation,
        validate_object_with_binding,
        RuntimeRegistryError,
        _parse_adapters_spec,
        ADAPTER_ENTRY_SCHEMA_ID,
        ADAPTER_ENTRY_SCHEMA_VERSION_HASH,
    )


def test_red_assault_forged_srr_id_rejected(tmp_path: Path) -> None:
    (
        _,
        build_routing_record,
        _build_adapter_invocation,
        validate_object_with_binding,
        *_rest,
    ) = _import_modules()
    vault_path = tmp_path / "_runtime_artifacts" / "state_vault.jsonl"
    rr = build_routing_record(
        runtime_registry_hash="0" * 64,
        spine_run_hash="1" * 64,
        task_context_hash="2" * 64,
        task_context_ref="vault://task_context/" + ("3" * 64),
        request_hash="4" * 64,
        plan_hash="5" * 64,
        status="OK",
        mode="DRY_RUN",
        vault_path=vault_path,
        candidates=[],
        chosen_adapter={"adapter_id": "none", "adapter_version": "0"},
    )
    forged = dict(rr.record)
    forged["routing_record_id"] = "f" * 64  # does not match hash surface
    try:
        validate_object_with_binding(forged)
        assert False, "forged SRR accepted (broken)"
    except Exception:
        pass


def test_red_assault_forged_air_id_rejected(tmp_path: Path) -> None:
    (
        _,
        build_routing_record,
        build_adapter_invocation,
        validate_object_with_binding,
        *_rest,
    ) = _import_modules()
    vault_path = tmp_path / "_runtime_artifacts" / "state_vault.jsonl"
    rr = build_routing_record(
        runtime_registry_hash="0" * 64,
        spine_run_hash="1" * 64,
        task_context_hash="2" * 64,
        task_context_ref="vault://task_context/" + ("3" * 64),
        request_hash="4" * 64,
        plan_hash="5" * 64,
        status="OK",
        mode="DRY_RUN",
        vault_path=vault_path,
        candidates=[],
        chosen_adapter={"adapter_id": "none", "adapter_version": "0"},
    )
    air = build_adapter_invocation(
        routing_record_hash=rr.record_hash,
        task_context_hash="2" * 64,
        input_hash="6" * 64,
        output_hash=None,
        status="DRY_RUN",
        vault_path=vault_path,
    )
    forged = dict(air.record)
    forged["invocation_id"] = "e" * 64  # does not match hash surface
    try:
        validate_object_with_binding(forged)
        assert False, "forged AIR accepted (broken)"
    except Exception:
        pass


def test_red_assault_registry_path_traversal_rejected() -> None:
    (
        _,
        _build_routing_record,
        _build_adapter_invocation,
        _validate_object_with_binding,
        RuntimeRegistryError,
        _parse_adapters_spec,
        ADAPTER_ENTRY_SCHEMA_ID,
        ADAPTER_ENTRY_SCHEMA_VERSION_HASH,
    ) = _import_modules()

    bad = {
        "registry_schema_id": "kt.adapters.registry.v1",
        "allowed_export_roots": ["exports/adapters"],
        "entries": [
            {
                "schema_id": ADAPTER_ENTRY_SCHEMA_ID,
                "schema_version_hash": ADAPTER_ENTRY_SCHEMA_VERSION_HASH,
                "adapter_id": "lobe.architect.v1",
                "version": "1.0.0",
                "base_model": "mistral-7b",
                "artifact_path": "../escape",
                "artifact_hash": "0" * 64,
                "capabilities": ["code"],
                "constraints": ["no_network"],
                "training_receipt_ref": "vault://train/" + ("1" * 64),
                "evaluation_receipt_ref": "vault://eval/" + ("2" * 64),
                "status": "ACTIVE",
            }
        ],
    }
    try:
        _ = _parse_adapters_spec(bad)
        assert False, "path traversal accepted (broken)"
    except RuntimeRegistryError:
        pass

