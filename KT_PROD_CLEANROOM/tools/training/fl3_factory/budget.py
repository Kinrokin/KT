from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from typing import Any, Dict, Optional

from tools.training.fl3_factory.io import read_json_object, write_schema_object
from tools.training.fl3_factory.lockfile import exclusive_lock
from tools.verification.fl3_canonical import canonical_json, sha256_text
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object


class FL3BudgetError(FL3ValidationError):
    """Budget/lock/unlock violations. Used for distinct exit codes (fail-closed)."""


def default_budget_state_path(repo_root: Path) -> Path:
    # Runtime-mutating state must live under exports (ignored), not under repo-tracked AUDITS.
    return (
        repo_root
        / "KT_PROD_CLEANROOM"
        / "exports"
        / "adapters_shadow"
        / "_factory_state"
        / "FL3_GLOBAL_BUDGET_STATE.json"
    )


def _lock_path_for_budget_state(budget_state_path: Path) -> Path:
    # Per-state lock file keeps tests isolated and prevents cross-job interference.
    return budget_state_path.with_suffix(budget_state_path.suffix + ".lock")


def load_budget_state(path: Path) -> Dict[str, Any]:
    obj = read_json_object(path)
    validate_schema_bound_object(obj)
    if obj.get("schema_id") != "kt.global_budget_state.v1":
        raise FL3BudgetError("budget state schema_id mismatch (fail-closed)")
    return obj


def budget_state_payload_hash(state: Dict[str, Any]) -> str:
    # Hash the canonical JSON form of the state object.
    return sha256_text(canonical_json(state))


def verify_human_signoff(signoff: Dict[str, Any], *, payload_hash: str) -> None:
    # key is provided via env var: KT_FL3_HMAC_KEY_<key_id>
    key_id = signoff.get("key_id")
    if not isinstance(key_id, str) or not key_id.strip():
        raise FL3BudgetError("signoff.key_id invalid (fail-closed)")
    env_name = f"KT_FL3_HMAC_KEY_{key_id}"
    secret = os.environ.get(env_name)
    if secret is None:
        raise FL3BudgetError(f"Missing HMAC key for signoff (fail-closed): {env_name}")
    expected = hmac.new(secret.encode("utf-8"), payload_hash.encode("utf-8"), hashlib.sha256).hexdigest()
    if signoff.get("hmac_signature") != expected:
        raise FL3BudgetError("signoff signature mismatch (fail-closed)")


def verify_unlock_artifact(unlock: Dict[str, Any], *, payload_hash: str) -> None:
    validate_schema_bound_object(unlock)
    if unlock.get("schema_id") != "kt.global_unlock.v1":
        raise FL3BudgetError("unlock schema_id mismatch (fail-closed)")
    if unlock.get("payload_hash") != payload_hash:
        raise FL3BudgetError("unlock payload_hash mismatch (fail-closed)")
    signoffs = unlock.get("signoffs")
    if not isinstance(signoffs, list) or len(signoffs) < 2:
        raise FL3BudgetError("unlock signoffs must be >=2 (fail-closed)")
    key_ids = set()
    for s in signoffs:
        if not isinstance(s, dict):
            raise FL3BudgetError("unlock signoff must be object (fail-closed)")
        validate_schema_bound_object(s)
        if s.get("schema_id") != "kt.human_signoff.v1":
            raise FL3BudgetError("unlock signoff schema_id mismatch (fail-closed)")
        verify_human_signoff(s, payload_hash=payload_hash)
        key_ids.add(s.get("key_id"))
    if len(key_ids) < 2:
        raise FL3BudgetError("unlock requires two distinct signers (fail-closed)")


def ensure_budget_state_initialized(*, repo_root: Path, budget_state_path: Path) -> None:
    if budget_state_path.exists():
        return
    # Copy immutable seed from AUDITS into runtime state location.
    seed_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FL3_GLOBAL_BUDGET_STATE.json"
    if not seed_path.exists():
        raise FL3BudgetError(f"Missing budget seed file (fail-closed): {seed_path.as_posix()}")
    seed_obj = read_json_object(seed_path)
    validate_schema_bound_object(seed_obj)
    if seed_obj.get("schema_id") != "kt.global_budget_state.v1":
        raise FL3BudgetError("Budget seed schema_id mismatch (fail-closed)")
    budget_state_path.parent.mkdir(parents=True, exist_ok=True)
    _ = write_schema_object(path=budget_state_path, obj=seed_obj)


def unlock_if_needed(
    *,
    repo_root: Path,
    budget_state_path: Path,
    unlock_artifact_path: Optional[Path],
    lock_timeout_s: float = 5.0,
) -> Dict[str, Any]:
    lock_path = _lock_path_for_budget_state(budget_state_path)
    with exclusive_lock(lock_path, timeout_s=lock_timeout_s):
        ensure_budget_state_initialized(repo_root=repo_root, budget_state_path=budget_state_path)
        state = load_budget_state(budget_state_path)
        if state.get("lock_state") != "LOCKED":
            return state
        if unlock_artifact_path is None:
            raise FL3BudgetError("global lock is LOCKED and no unlock artifact provided (fail-closed)")
        unlock_obj = read_json_object(unlock_artifact_path)
        payload_hash = budget_state_payload_hash(state)
        verify_unlock_artifact(unlock_obj, payload_hash=payload_hash)
        # Apply unlock.
        state["lock_state"] = "OPEN"
        state["last_t1_failure"] = None
        _ = write_schema_object(path=budget_state_path, obj=state)
        return state


def record_job_started(*, repo_root: Path, budget_state_path: Path, lock_timeout_s: float = 5.0) -> Dict[str, Any]:
    lock_path = _lock_path_for_budget_state(budget_state_path)
    with exclusive_lock(lock_path, timeout_s=lock_timeout_s):
        ensure_budget_state_initialized(repo_root=repo_root, budget_state_path=budget_state_path)
        state = load_budget_state(budget_state_path)
        if state.get("lock_state") != "OPEN":
            raise FL3BudgetError("global lock is LOCKED (fail-closed)")
        jobs_run = state.get("jobs_run")
        if not isinstance(jobs_run, int) or jobs_run < 0:
            raise FL3BudgetError("budget state jobs_run invalid (fail-closed)")
        state["jobs_run"] = jobs_run + 1
        _ = write_schema_object(path=budget_state_path, obj=state)
        return state


def record_t1_failure(
    *,
    repo_root: Path,
    budget_state_path: Path,
    failure_id: str,
    lock_timeout_s: float = 5.0,
) -> Dict[str, Any]:
    if not isinstance(failure_id, str) or len(failure_id) < 8:
        raise FL3BudgetError("failure_id invalid (fail-closed)")
    lock_path = _lock_path_for_budget_state(budget_state_path)
    with exclusive_lock(lock_path, timeout_s=lock_timeout_s):
        ensure_budget_state_initialized(repo_root=repo_root, budget_state_path=budget_state_path)
        state = load_budget_state(budget_state_path)
        state["lock_state"] = "LOCKED"
        state["last_t1_failure"] = failure_id
        _ = write_schema_object(path=budget_state_path, obj=state)
        return state

