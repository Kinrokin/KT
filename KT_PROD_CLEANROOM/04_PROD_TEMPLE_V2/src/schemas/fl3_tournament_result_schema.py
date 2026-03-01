from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

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


FL3_TOURNAMENT_RESULT_SCHEMA_ID = "kt.tournament_result.v1"
FL3_TOURNAMENT_RESULT_SCHEMA_FILE = "fl3/kt.tournament_result.v1.json"
FL3_TOURNAMENT_RESULT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_TOURNAMENT_RESULT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "tournament_result_id",
    "tournament_plan_id",
    "status",
    "base_model_id",
    "suite_id",
    "decode_policy_id",
    "tournament_mode",
    "epsilon",
    "entrants",
    "champion_set",
    "dominance_pairs",
    "created_at",
)
_OPTIONAL_ORDER = ("reason_codes", "notes")
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)
_HASH_DROP_KEYS = {"created_at", "tournament_result_id"}
_ALLOWED_STATUS = {"PASS", "FAIL_CLOSED"}
_ALLOWED_MODES = {"round_robin_v1", "single_elim_v1", "double_elim_v1"}


def _validate_reason_codes(value: Any, *, required: bool) -> List[str]:
    if value is None:
        if required:
            raise SchemaValidationError("reason_codes missing (fail-closed)")
        return []
    if not isinstance(value, list):
        raise SchemaValidationError("reason_codes must be list (fail-closed)")
    out: List[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise SchemaValidationError("reason_codes entries must be non-empty strings (fail-closed)")
        out.append(item.strip())
    if out != sorted(out):
        raise SchemaValidationError("reason_codes must be sorted (fail-closed)")
    if len(set(out)) != len(out):
        raise SchemaValidationError("reason_codes must be unique (fail-closed)")
    if required and not out:
        raise SchemaValidationError("FAIL_CLOSED requires non-empty reason_codes (fail-closed)")
    return out


def _validate_entrants(value: Any) -> Tuple[List[Dict[str, str]], List[str]]:
    if not isinstance(value, list) or not value:
        raise SchemaValidationError("entrants must be non-empty list (fail-closed)")
    out: List[Dict[str, str]] = []
    for item in value:
        row = require_dict(item, name="entrants[]")
        require_keys(row, required={"adapter_root_hash", "adapter_id", "adapter_version"})
        reject_unknown_keys(row, allowed={"adapter_root_hash", "adapter_id", "adapter_version"})
        validate_hex_64(row, "adapter_root_hash")
        adapter_id = str(row.get("adapter_id", "")).strip()
        adapter_version = str(row.get("adapter_version", "")).strip()
        if not adapter_id or not adapter_version:
            raise SchemaValidationError("entrants[].adapter_id/adapter_version missing (fail-closed)")
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
    return out, hashes


def _validate_champion_set(value: Any, *, entrant_hashes: Set[str], status: str) -> List[str]:
    if not isinstance(value, list):
        raise SchemaValidationError("champion_set must be list (fail-closed)")
    out: List[str] = []
    for item in value:
        if not isinstance(item, str):
            raise SchemaValidationError("champion_set entries must be strings (fail-closed)")
        h = item.strip()
        if not h:
            raise SchemaValidationError("champion_set entries must be non-empty (fail-closed)")
        validate_hex_64({"h": h}, "h")
        if h not in entrant_hashes:
            raise SchemaValidationError("champion_set contains non-entrant adapter (fail-closed)")
        out.append(h)
    if out != sorted(out):
        raise SchemaValidationError("champion_set must be sorted (fail-closed)")
    if len(set(out)) != len(out):
        raise SchemaValidationError("champion_set must be unique (fail-closed)")
    if status == "PASS" and not out:
        raise SchemaValidationError("PASS requires non-empty champion_set (fail-closed)")
    return out


def _validate_dominance_pairs(value: Any, *, entrant_hashes: Set[str]) -> List[Dict[str, str]]:
    if not isinstance(value, list):
        raise SchemaValidationError("dominance_pairs must be list (fail-closed)")
    out: List[Dict[str, str]] = []
    for item in value:
        row = require_dict(item, name="dominance_pairs[]")
        require_keys(row, required={"dominant_adapter_root_hash", "dominated_adapter_root_hash"})
        reject_unknown_keys(row, allowed={"dominant_adapter_root_hash", "dominated_adapter_root_hash"})
        validate_hex_64(row, "dominant_adapter_root_hash")
        validate_hex_64(row, "dominated_adapter_root_hash")
        dom = str(row["dominant_adapter_root_hash"])
        sub = str(row["dominated_adapter_root_hash"])
        if dom == sub:
            raise SchemaValidationError("dominance pair must not be self-dominance (fail-closed)")
        if dom not in entrant_hashes or sub not in entrant_hashes:
            raise SchemaValidationError("dominance pair contains non-entrant adapter (fail-closed)")
        out.append({"dominant_adapter_root_hash": dom, "dominated_adapter_root_hash": sub})
    keypairs = [(r["dominant_adapter_root_hash"], r["dominated_adapter_root_hash"]) for r in out]
    if keypairs != sorted(keypairs):
        raise SchemaValidationError("dominance_pairs must be sorted (fail-closed)")
    if len(set(keypairs)) != len(keypairs):
        raise SchemaValidationError("dominance_pairs must be unique (fail-closed)")
    return out


def validate_fl3_tournament_result(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="tournament_result")
    enforce_max_fields(entry, max_fields=2048)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_TOURNAMENT_RESULT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_TOURNAMENT_RESULT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "tournament_result_id")
    validate_hex_64(entry, "tournament_plan_id")
    validate_created_at_utc_z(entry.get("created_at"))

    status = str(entry.get("status", "")).strip().upper()
    if status not in _ALLOWED_STATUS:
        raise SchemaValidationError("status invalid (fail-closed)")

    mode = str(entry.get("tournament_mode", "")).strip()
    if mode not in _ALLOWED_MODES:
        raise SchemaValidationError("tournament_mode invalid (fail-closed)")

    eps = entry.get("epsilon")
    if not isinstance(eps, (int, float)):
        raise SchemaValidationError("epsilon must be number (fail-closed)")
    if float(eps) < 0.0 or float(eps) > 1.0:
        raise SchemaValidationError("epsilon out of range (fail-closed)")

    base_model_id = str(entry.get("base_model_id", "")).strip()
    suite_id = str(entry.get("suite_id", "")).strip()
    decode_policy_id = str(entry.get("decode_policy_id", "")).strip()
    if not base_model_id or not suite_id or not decode_policy_id:
        raise SchemaValidationError("base_model_id/suite_id/decode_policy_id missing (fail-closed)")
    validate_short_string({"base_model_id": base_model_id}, "base_model_id", max_len=128)
    validate_short_string({"suite_id": suite_id}, "suite_id", max_len=128)
    validate_short_string({"decode_policy_id": decode_policy_id}, "decode_policy_id", max_len=128)

    _entrants, hashes = _validate_entrants(entry.get("entrants"))
    hset = set(hashes)

    _ = _validate_reason_codes(entry.get("reason_codes"), required=(status == "FAIL_CLOSED"))
    _ = _validate_champion_set(entry.get("champion_set"), entrant_hashes=hset, status=status)
    _ = _validate_dominance_pairs(entry.get("dominance_pairs"), entrant_hashes=hset)

    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("tournament_result_id") != expected:
        raise SchemaValidationError("tournament_result_id does not match canonical hash surface (fail-closed)")


