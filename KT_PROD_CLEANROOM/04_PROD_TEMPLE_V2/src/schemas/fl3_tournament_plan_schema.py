from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
    validate_short_string,
)
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_TOURNAMENT_PLAN_SCHEMA_ID = "kt.tournament_plan.v1"
FL3_TOURNAMENT_PLAN_SCHEMA_FILE = "fl3/kt.tournament_plan.v1.json"
FL3_TOURNAMENT_PLAN_SCHEMA_VERSION_HASH = schema_version_hash(FL3_TOURNAMENT_PLAN_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "tournament_plan_id",
    "base_model_id",
    "suite_id",
    "suite_root_hash",
    "decode_policy_id",
    "decode_cfg_hash",
    "tournament_mode",
    "epsilon",
    "entrants",
    "seed",
    "created_at",
)
_OPTIONAL_ORDER = ("notes",)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)
_HASH_DROP_KEYS = {"created_at", "tournament_plan_id"}
_ALLOWED_MODES = {"round_robin_v1", "single_elim_v1", "double_elim_v1"}


def _validate_entrants(value: Any) -> List[Dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise SchemaValidationError("entrants must be a non-empty list (fail-closed)")
    out: List[Dict[str, str]] = []
    for item in value:
        row = require_dict(item, name="entrants[]")
        require_keys(row, required={"adapter_root_hash", "adapter_id", "adapter_version"})
        reject_unknown_keys(row, allowed={"adapter_root_hash", "adapter_id", "adapter_version"})
        validate_hex_64(row, "adapter_root_hash")
        adapter_id = str(row.get("adapter_id", "")).strip()
        adapter_version = str(row.get("adapter_version", "")).strip()
        if not adapter_id or not adapter_version:
            raise SchemaValidationError("entrants[].adapter_id/adapter_version must be non-empty (fail-closed)")
        validate_short_string({"adapter_id": adapter_id}, "adapter_id", max_len=128)
        validate_short_string({"adapter_version": adapter_version}, "adapter_version", max_len=64)
        out.append(
            {
                "adapter_root_hash": str(row["adapter_root_hash"]),
                "adapter_id": adapter_id,
                "adapter_version": adapter_version,
            }
        )
    hashes = [r["adapter_root_hash"] for r in out]
    if hashes != sorted(hashes):
        raise SchemaValidationError("entrants must be sorted by adapter_root_hash (fail-closed)")
    if len(set(hashes)) != len(hashes):
        raise SchemaValidationError("entrants adapter_root_hash values must be unique (fail-closed)")
    return out


def _expected_seed(*, base_model_id: str, suite_id: str, entrant_hashes: List[str]) -> str:
    payload = base_model_id + "|" + suite_id + "|" + "|".join(entrant_hashes)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def validate_fl3_tournament_plan(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="tournament_plan")
    enforce_max_fields(entry, max_fields=128)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_TOURNAMENT_PLAN_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_TOURNAMENT_PLAN_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "tournament_plan_id")
    validate_hex_64(entry, "suite_root_hash")
    validate_hex_64(entry, "decode_cfg_hash")
    validate_hex_64(entry, "seed")
    validate_created_at_utc_z(entry.get("created_at"))

    base_model_id = str(entry.get("base_model_id", "")).strip()
    suite_id = str(entry.get("suite_id", "")).strip()
    decode_policy_id = str(entry.get("decode_policy_id", "")).strip()
    if not base_model_id or not suite_id or not decode_policy_id:
        raise SchemaValidationError("base_model_id/suite_id/decode_policy_id must be non-empty (fail-closed)")
    validate_short_string({"base_model_id": base_model_id}, "base_model_id", max_len=128)
    validate_short_string({"suite_id": suite_id}, "suite_id", max_len=128)
    validate_short_string({"decode_policy_id": decode_policy_id}, "decode_policy_id", max_len=128)

    mode = str(entry.get("tournament_mode", "")).strip()
    if mode not in _ALLOWED_MODES:
        raise SchemaValidationError("tournament_mode invalid (fail-closed)")

    eps = entry.get("epsilon")
    if not isinstance(eps, (int, float)):
        raise SchemaValidationError("epsilon must be number (fail-closed)")
    if float(eps) < 0.0 or float(eps) > 1.0:
        raise SchemaValidationError("epsilon out of range (fail-closed)")

    entrants = _validate_entrants(entry.get("entrants"))
    entrant_hashes = [e["adapter_root_hash"] for e in entrants]
    expected_seed = _expected_seed(base_model_id=base_model_id, suite_id=suite_id, entrant_hashes=entrant_hashes)
    if str(entry.get("seed")) != expected_seed:
        raise SchemaValidationError("seed does not match canonical seed derivation (fail-closed)")

    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("tournament_plan_id") != expected:
        raise SchemaValidationError("tournament_plan_id does not match canonical hash surface (fail-closed)")


