from __future__ import annotations

from typing import Any, Dict, List, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
)
from schemas.fl3_schema_common import ensure_sorted_str_list, sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_TEMPORAL_LINEAGE_GRAPH_SCHEMA_ID = "kt.temporal_lineage_graph.v1"
FL3_TEMPORAL_LINEAGE_GRAPH_SCHEMA_FILE = "fl3/kt.temporal_lineage_graph.v1.json"
FL3_TEMPORAL_LINEAGE_GRAPH_SCHEMA_VERSION_HASH = schema_version_hash(FL3_TEMPORAL_LINEAGE_GRAPH_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "graph_id",
    "nodes",
    "edges",
    "parent_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "graph_id"}


def validate_fl3_temporal_lineage_graph(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 temporal lineage graph")
    enforce_max_fields(entry, max_fields=256)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_TEMPORAL_LINEAGE_GRAPH_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_TEMPORAL_LINEAGE_GRAPH_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")
    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "graph_id")
    validate_hex_64(entry, "parent_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    nodes = ensure_sorted_str_list(entry.get("nodes"), field="nodes")
    edges = entry.get("edges")
    if not isinstance(edges, list):
        raise SchemaValidationError("edges must be a list (fail-closed)")
    for e in edges:
        ed = require_dict(e, name="edge")
        require_keys(ed, required={"from", "to"})
        reject_unknown_keys(ed, allowed={"from", "to"})
        if ed["from"] not in nodes or ed["to"] not in nodes:
            raise SchemaValidationError("edge endpoints must reference nodes (fail-closed)")
    # stable ordering: edges sorted by from,to
    edge_pairs: List[str] = [f"{e['from']}->{e['to']}" for e in edges]
    if edge_pairs != sorted(edge_pairs):
        raise SchemaValidationError("edges must be sorted (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("graph_id") != expected:
        raise SchemaValidationError("graph_id does not match canonical hash surface (fail-closed)")

