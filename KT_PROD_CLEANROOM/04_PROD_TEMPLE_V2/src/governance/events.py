from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set


@dataclass(frozen=True)
class GovernanceEventError(ValueError):
    message: str

    def __str__(self) -> str:
        return self.message


GOVERNANCE_ORGAN_ID = "Governance"

GOV_EVENT_TYPES: Set[str] = {
    "GOV_ALLOW",
    "GOV_DENY",
    "GOV_VETO",
    "GOV_POLICY_APPLY",
    "GOV_CRISIS_ENTER",
    "GOV_CRISIS_EXIT",
    "POLICY_C_DRIFT_WARN",
    "POLICY_C_DRIFT_FAIL",
}

DECISIONS: Set[str] = {"ALLOW", "DENY", "VETO"}

# Conservative identifier format to prevent leaking raw content.
_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,64}$")
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_id(value: Any, *, name: str) -> str:
    if not isinstance(value, str):
        raise GovernanceEventError(f"{name} must be a string")
    if not _ID_RE.match(value):
        raise GovernanceEventError(f"{name} must match {_ID_RE.pattern} (fail-closed)")
    return value


def _require_hex64(value: Any, *, name: str) -> str:
    if not isinstance(value, str):
        raise GovernanceEventError(f"{name} must be a string")
    if not _HEX_64_RE.match(value):
        raise GovernanceEventError(f"{name} must be 64 lowercase hex chars")
    return value


def assert_event_type_allowed(event_type: str) -> None:
    if event_type not in GOV_EVENT_TYPES:
        raise GovernanceEventError("Unknown governance event_type (fail-closed)")


def assert_governance_organ_id(organ_id: str) -> None:
    if organ_id != GOVERNANCE_ORGAN_ID:
        raise GovernanceEventError("organ_id mismatch for governance events (fail-closed)")


def build_inputs_envelope(
    *,
    policy_id: str,
    policy_version_hash: str,
    subject_hash: str,
    context_hash: str,
    rule_id: Optional[str] = None,
) -> Dict[str, Any]:
    env: Dict[str, Any] = {
        "policy_id": _require_id(policy_id, name="policy_id"),
        "policy_version_hash": _require_hex64(policy_version_hash, name="policy_version_hash"),
        "subject_hash": _require_hex64(subject_hash, name="subject_hash"),
        "context_hash": _require_hex64(context_hash, name="context_hash"),
    }
    if rule_id is not None:
        env["rule_id"] = _require_id(rule_id, name="rule_id")
    return env


def build_outputs_envelope(
    *,
    decision: str,
    obligations_hash: Optional[str] = None,
    crisis_mode: Optional[str] = None,
) -> Dict[str, Any]:
    if decision not in DECISIONS:
        raise GovernanceEventError("decision must be one of ALLOW/DENY/VETO")
    env: Dict[str, Any] = {"decision": decision}
    if obligations_hash is not None:
        env["obligations_hash"] = _require_hex64(obligations_hash, name="obligations_hash")
    if crisis_mode is not None:
        env["crisis_mode"] = _require_id(crisis_mode, name="crisis_mode")
    return env


def compute_envelope_hash(envelope: Dict[str, Any]) -> str:
    # Envelope is never persisted; only its sha256 hash is stored (hash-only).
    if not isinstance(envelope, dict):
        raise GovernanceEventError("Envelope must be a JSON object (dict)")
    # Hard bound to prevent hidden payloads: small object only.
    if len(envelope) > 8:
        raise GovernanceEventError("Envelope exceeds max field count (fail-closed)")
    encoded = _canonical_json(envelope).encode("utf-8")
    if len(encoded) > 2048:
        raise GovernanceEventError("Envelope exceeds max bytes (fail-closed)")
    return _sha256_text(encoded.decode("utf-8"))
