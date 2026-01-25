from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys


def _add_src_to_syspath() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    src_root = repo_root / "src"
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

from core.routing_receipts import (  # noqa: E402
    build_adapter_invocation,
    build_routing_record,
)


def _hash_payload(payload: dict) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_routing_record_hash_excludes_created_at_and_id(tmp_path: Path) -> None:
    vault_path = tmp_path / "state_vault.jsonl"
    record = build_routing_record(
        runtime_registry_hash="0" * 64,
        spine_run_hash="1" * 64,
        task_context_hash="2" * 64,
        task_context_ref="vault://context/2" * 8,
        request_hash="3" * 64,
        plan_hash="4" * 64,
        status="OK",
        mode="DRY_RUN",
        vault_path=vault_path,
        candidates=[
            {"adapter_id": "b", "adapter_version": "2"},
            {"adapter_id": "a", "adapter_version": "1"},
        ],
    )
    payload = dict(record.record)
    payload.pop("created_at", None)
    payload.pop("routing_record_id", None)
    assert record.record["routing_record_id"] == _hash_payload(payload)
    assert record.record_path.parent == vault_path.parent / "routing_records"
    assert record.record["candidates"][0]["adapter_id"] == "a"


def test_adapter_invocation_hash_excludes_created_at_and_id(tmp_path: Path) -> None:
    vault_path = tmp_path / "state_vault.jsonl"
    invocation = build_adapter_invocation(
        routing_record_hash="a" * 64,
        task_context_hash="b" * 64,
        input_hash="c" * 64,
        output_hash="d" * 64,
        status="DRY_RUN",
        vault_path=vault_path,
    )
    payload = dict(invocation.record)
    payload.pop("created_at", None)
    payload.pop("invocation_id", None)
    assert invocation.record["invocation_id"] == _hash_payload(payload)
    assert invocation.record_path.parent == vault_path.parent / "adapter_invocations"
