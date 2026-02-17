from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from tools.training.fl3_factory.manifests import sha256_file as sha256_file_canonical
from tools.verification.attestation_hmac import env_key_name_for_key_id, verify_hmac_signoff
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object


def _is_truthy_env(name: str) -> bool:
    return str(os.environ.get(name, "")).strip().lower() in {"1", "true", "yes", "on"}


def _read_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"FAIL_CLOSED: unreadable JSON {name}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"FAIL_CLOSED: {name} must be a JSON object: {path.as_posix()}")
    return obj


def load_suite_registry(*, path: Path) -> Dict[str, Any]:
    obj = _read_json_dict(path, name="suite_registry")
    try:
        validate_schema_bound_object(obj)
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"FAIL_CLOSED: suite registry schema invalid: {path.as_posix()} :: {exc}") from exc
    if obj.get("schema_id") != "kt.suite_registry.v1":
        raise FL3ValidationError("FAIL_CLOSED: suite registry schema_id mismatch")
    return obj


def find_suite_entry(*, registry: Dict[str, Any], suite_id: str, suite_root_hash: str) -> Optional[Dict[str, Any]]:
    suites = registry.get("suites") if isinstance(registry.get("suites"), list) else []
    for row in suites:
        if not isinstance(row, dict):
            continue
        if str(row.get("suite_id", "")).strip() != str(suite_id).strip():
            continue
        if str(row.get("suite_root_hash", "")).strip() != str(suite_root_hash).strip():
            continue
        return row
    return None


def suite_definition_hash_ok(*, repo_root: Path, suite_definition_ref: str, suite_root_hash: str) -> Tuple[bool, str]:
    """
    Enforce suite-definition locality + hash binding.

    EPIC_16 doctrine: suite definitions are constitutional measurement artifacts and must live
    under KT_PROD_CLEANROOM/AUDITS/.
    """
    ref = str(suite_definition_ref).replace("\\", "/").strip()
    if not ref:
        return False, "suite_definition_ref missing"
    if Path(ref).is_absolute():
        return False, "suite_definition_ref must be repo-relative (fail-closed)"
    if not ref.startswith("KT_PROD_CLEANROOM/AUDITS/"):
        return False, "suite_definition_ref must be under KT_PROD_CLEANROOM/AUDITS/ (fail-closed)"

    suite_path = (repo_root / ref).resolve()
    try:
        if not suite_path.is_relative_to(repo_root):
            return False, "suite_definition_ref escapes repo root (fail-closed)"
    except AttributeError:
        # Python <3.9 fallback (not expected here).
        pass

    if not suite_path.exists():
        return False, f"missing suite definition at {suite_path.as_posix()}"
    got = sha256_file_canonical(suite_path)
    if got != str(suite_root_hash).strip():
        return False, f"suite_root_hash mismatch expected={suite_root_hash} got={got}"

    # EPIC_30: suite definitions must be schema-bound measurement artifacts (no fixture escape hatch).
    try:
        obj = _read_json_dict(suite_path, name="suite_definition")
        validate_schema_bound_object(obj)
    except Exception as exc:  # noqa: BLE001
        return False, f"suite definition schema invalid (fail-closed): {exc}"
    if str(obj.get("schema_id", "")).strip() != "kt.suite_definition.v1":
        return False, "suite definition schema_id mismatch (fail-closed)"
    return True, ""


def verify_suite_authorization(*, registry: Dict[str, Any], suite_entry: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Verifies that suite authorization is sufficient for the current lane.

    - In canonical lane (KT_CANONICAL_LANE=1): require registry.attestation_mode==HMAC and verify HMAC signoffs using env keys.
    - In non-canonical lanes: require >=2 signoffs and correct payload_hash binding, but do not require keys.
    """
    canonical_lane = _is_truthy_env("KT_CANONICAL_LANE")
    mode = str(registry.get("attestation_mode", "")).strip().upper()
    signoffs = suite_entry.get("signoffs") if isinstance(suite_entry.get("signoffs"), list) else []
    if len(signoffs) < 2:
        return False, "suite authorization requires >=2 signoffs"

    expected_payload_hash = str(suite_entry.get("authorization_payload_hash", "")).strip()
    if not expected_payload_hash or len(expected_payload_hash) != 64:
        return False, "suite authorization payload hash missing/invalid"

    for s in signoffs:
        if not isinstance(s, dict):
            return False, "suite signoff must be object"
        if str(s.get("payload_hash", "")).strip() != expected_payload_hash:
            return False, "suite signoff payload_hash mismatch (fail-closed)"

    if canonical_lane:
        if mode != "HMAC":
            return False, "canonical lane requires HMAC suite registry attestation_mode"
        for s in signoffs:
            key_id = str(s.get("key_id", "")).strip()
            if not key_id:
                return False, "suite signoff missing key_id"
            env_name = env_key_name_for_key_id(key_id)
            key_val = os.environ.get(env_name)
            if not key_val:
                return False, f"missing {env_name} for suite auth HMAC verification"
            ok, err = verify_hmac_signoff(signoff=s, key_bytes=key_val.encode("utf-8"))
            if not ok:
                return False, f"suite signoff HMAC verification failed: {err or 'unknown_error'}"

    return True, ""
