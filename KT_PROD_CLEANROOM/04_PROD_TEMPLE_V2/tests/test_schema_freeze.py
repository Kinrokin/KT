from __future__ import annotations

import json
from pathlib import Path
import sys


def _add_src_to_syspath() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    src_root = repo_root / "src"
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

from schemas.adapter_invocation_schema import (  # noqa: E402
    ADAPTER_INVOCATION_SCHEMA_ID,
    ADAPTER_INVOCATION_SCHEMA_VERSION_HASH,
    validate_adapter_invocation,
)
from schemas.adapter_entry_schema import (  # noqa: E402
    ADAPTER_ENTRY_SCHEMA_ID,
    ADAPTER_ENTRY_SCHEMA_VERSION_HASH,
    validate_adapter_entry,
)
from schemas.evaluator_battery_manifest_schema import (  # noqa: E402
    EVALUATOR_BATTERY_MANIFEST_SCHEMA_ID,
    EVALUATOR_BATTERY_MANIFEST_SCHEMA_VERSION_HASH,
    validate_evaluator_battery_manifest,
)
from schemas.evaluator_result_schema import (  # noqa: E402
    EVALUATOR_RESULT_SCHEMA_ID,
    EVALUATOR_RESULT_SCHEMA_VERSION_HASH,
    validate_evaluator_result,
)
from schemas.routing_record_schema import (  # noqa: E402
    ROUTING_RECORD_SCHEMA_ID,
    ROUTING_RECORD_SCHEMA_VERSION_HASH,
    validate_routing_record,
)
from schemas.runtime_registry_schema import (  # noqa: E402
    RUNTIME_REGISTRY_SCHEMA_ID,
    RUNTIME_REGISTRY_SCHEMA_VERSION_HASH,
    validate_runtime_registry,
)
from schemas.schema_files import schema_path, schema_version_hash  # noqa: E402
from schemas.task_context_schema import (  # noqa: E402
    TASK_CONTEXT_SCHEMA_ID,
    TASK_CONTEXT_SCHEMA_VERSION_HASH,
    validate_task_context,
)


SCHEMA_FILES = [
    "kt.routing.srr.v1.json",
    "kt.routing.air.v1.json",
    "kt.runtime.adapter_entry.v1.json",
    "kt.runtime.registry.v1.json",
    "kt.task_context.v1.json",
    "kt.evaluator.battery_manifest.v1.json",
    "kt.evaluator.result.v1.json",
]


def _hash_file(name: str) -> str:
    return (schema_path(name.replace(".json", ".hash"))).read_text(encoding="utf-8").strip()


def test_schema_hash_files_match() -> None:
    for name in SCHEMA_FILES:
        assert schema_version_hash(name) == _hash_file(name)


def test_srr_schema_validates() -> None:
    record = {
        "schema_id": ROUTING_RECORD_SCHEMA_ID,
        "schema_version_hash": ROUTING_RECORD_SCHEMA_VERSION_HASH,
        "routing_record_id": "",
        "runtime_registry_hash": "b" * 64,
        "spine_run_hash": "c" * 64,
        "task_context_hash": "d" * 64,
        "task_context_ref": "vault://context/" + ("d" * 64),
        "request_hash": "e" * 64,
        "plan_hash": "f" * 64,
        "candidates": [
            {"adapter_id": "alpha", "adapter_version": "1"},
            {"adapter_id": "beta", "adapter_version": "2"},
        ],
        "chosen_adapter": {"adapter_id": "alpha", "adapter_version": "1"},
        "router_reason": "council.plan",
        "router_confidence": 0.5,
        "governor_verdict": {
            "policy": "PolicyC",
            "verdict": "DRY_RUN",
            "risk_score": 0.0,
            "verdict_hash": "1" * 64,
        },
        "parent_routing_record": None,
        "status": "DRY_RUN",
        "created_at": "2026-01-01T00:00:00Z",
    }
    # routing_record_id must match canonical hash surface (created_at excluded).
    import hashlib, json  # noqa: E402

    payload = {k: v for k, v in record.items() if k not in {"created_at", "routing_record_id"}}
    record["routing_record_id"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    validate_routing_record(record)


def test_air_schema_validates() -> None:
    record = {
        "schema_id": ADAPTER_INVOCATION_SCHEMA_ID,
        "schema_version_hash": ADAPTER_INVOCATION_SCHEMA_VERSION_HASH,
        "invocation_id": "",
        "routing_record_hash": "b" * 64,
        "adapter_id": "council.dry_run",
        "adapter_version": "0",
        "task_context_hash": "c" * 64,
        "input_hash": "d" * 64,
        "output_hash": None,
        "governor_verdict_hash": None,
        "evaluator_verdict": "SKIPPED",
        "duration_ms": 0,
        "token_usage": {"prompt": 0, "completion": 0, "total": 0},
        "status": "DRY_RUN",
        "created_at": "2026-01-01T00:00:00Z",
    }
    # invocation_id must match canonical hash surface (created_at excluded).
    import hashlib, json  # noqa: E402

    payload = {k: v for k, v in record.items() if k not in {"created_at", "invocation_id"}}
    record["invocation_id"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    validate_adapter_invocation(record)


def test_task_context_schema_validates() -> None:
    payload = {
        "schema_id": TASK_CONTEXT_SCHEMA_ID,
        "schema_version_hash": TASK_CONTEXT_SCHEMA_VERSION_HASH,
        "task_id": "a" * 64,
        "domain_tags": ["code", "safety"],
        "risk_class": "LOW",
        "constraints": ["no_runtime_mutation"],
        "epoch_context": {"epoch_id": "EPOCH_X", "profile": "GOVERNANCE"},
        "input_refs": ["vault://input/abc"],
    }
    validate_task_context(payload)


def test_evaluator_schema_validates() -> None:
    manifest = {
        "schema_id": EVALUATOR_BATTERY_MANIFEST_SCHEMA_ID,
        "schema_version_hash": EVALUATOR_BATTERY_MANIFEST_SCHEMA_VERSION_HASH,
        "battery_id": "kt.eval.battery.v1",
        "tests": ["determinism_smoke", "no_hidden_mutation", "schema_validity"],
        "ordering": "stable",
        "pass_rule": "ALL_PASS",
    }
    validate_evaluator_battery_manifest(manifest)
    result = {
        "schema_id": EVALUATOR_RESULT_SCHEMA_ID,
        "schema_version_hash": EVALUATOR_RESULT_SCHEMA_VERSION_HASH,
        "adapter_id": "lobe.architect.v1",
        "adapter_version": "1.0.0",
        "battery_id": "kt.eval.battery.v1",
        "results": {"schema_validity": "PASS"},
        "final_verdict": "PASS",
    }
    validate_evaluator_result(result)


def test_runtime_registry_schema_validates() -> None:
    registry_path = Path(__file__).resolve().parents[1] / "docs" / "RUNTIME_REGISTRY.json"
    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    assert payload["schema_id"] == RUNTIME_REGISTRY_SCHEMA_ID
    assert payload["schema_version_hash"] == RUNTIME_REGISTRY_SCHEMA_VERSION_HASH
    validate_runtime_registry(payload)


def test_adapter_entry_schema_validates() -> None:
    entry = {
        "schema_id": ADAPTER_ENTRY_SCHEMA_ID,
        "schema_version_hash": ADAPTER_ENTRY_SCHEMA_VERSION_HASH,
        "adapter_id": "lobe.architect.v1",
        "version": "1.0.0",
        "base_model": "mistral-7b",
        "artifact_path": "exports/adapters/lobe_architect/v1",
        "artifact_hash": "a" * 64,
        "capabilities": ["code", "reasoning"],
        "constraints": ["no_network"],
        "training_receipt_ref": "vault://train/abc",
        "evaluation_receipt_ref": "vault://eval/abc",
        "status": "ACTIVE",
    }
    validate_adapter_entry(entry)
