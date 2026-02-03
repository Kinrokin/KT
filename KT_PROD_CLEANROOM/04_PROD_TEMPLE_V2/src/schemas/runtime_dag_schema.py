from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_canonical_json_bytes,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
    validate_short_string,
)
from schemas.schema_files import schema_version_hash


RUNTIME_DAG_SCHEMA_ID = "kt.runtime_dag.v1"
RUNTIME_DAG_SCHEMA_FILE = "fl3/kt.runtime_dag.v1.json"
RUNTIME_DAG_SCHEMA_VERSION_HASH = schema_version_hash(RUNTIME_DAG_SCHEMA_FILE)

_REQ_ORDER = (
    "schema_id",
    "schema_version_hash",
    "dag_id",
    "work_order_id",
    "nodes",
    "edges",
    "receipts",
    "artifacts",
    "created_at",
)
_REQ: Set[str] = set(_REQ_ORDER)
_ALLOWED: Set[str] = set(_REQ_ORDER)


def validate_runtime_dag(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="runtime DAG")
    enforce_max_fields(entry, max_fields=128)
    require_keys(entry, required=_REQ)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=256 * 1024)

    if entry.get("schema_id") != RUNTIME_DAG_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != RUNTIME_DAG_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "dag_id")
    validate_hex_64(entry, "work_order_id")
    validate_short_string(entry, "created_at", max_len=64)

    nodes = entry.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise SchemaValidationError("nodes must be a non-empty list (fail-closed)")
    for idx, n in enumerate(nodes):
        nd = require_dict(n, name=f"nodes[{idx}]")
        if set(nd.keys()) != {"node_id", "classification"}:
            raise SchemaValidationError("node entry keys mismatch (fail-closed)")
        validate_short_string(nd, "node_id", max_len=64)
        validate_short_string(nd, "classification", max_len=64)

    edges = entry.get("edges")
    if not isinstance(edges, list) or not edges:
        raise SchemaValidationError("edges must be a non-empty list (fail-closed)")
    for idx, e in enumerate(edges):
        ed = require_dict(e, name=f"edges[{idx}]")
        if set(ed.keys()) != {"src", "dst"}:
            raise SchemaValidationError("edge entry keys mismatch (fail-closed)")
        validate_short_string(ed, "src", max_len=64)
        validate_short_string(ed, "dst", max_len=64)

    receipts = entry.get("receipts")
    if not isinstance(receipts, list):
        raise SchemaValidationError("receipts must be a list (fail-closed)")

    artifacts = entry.get("artifacts")
    if not isinstance(artifacts, list):
        raise SchemaValidationError("artifacts must be a list (fail-closed)")
    for idx, a in enumerate(artifacts):
        ad = require_dict(a, name=f"artifacts[{idx}]")
        if set(ad.keys()) != {"relpath", "sha256"}:
            raise SchemaValidationError("artifact entry keys mismatch (fail-closed)")
        validate_short_string(ad, "relpath", max_len=256)
        validate_hex_64(ad, "sha256")

