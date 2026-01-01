from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator, Tuple

from governance.events import GOV_EVENT_TYPES, GOVERNANCE_ORGAN_ID, GovernanceEventError
from memory.replay import StateVaultReplayError, validate_state_vault_chain


class GovernanceAuditError(RuntimeError):
    pass


def _iter_jsonl(path: Path) -> Iterator[Tuple[int, dict]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.rstrip("\n")
            if not line:
                raise GovernanceAuditError(f"Empty JSONL line at line {line_no}")
            try:
                obj = json.loads(line)
            except Exception as exc:
                raise GovernanceAuditError(f"JSON parse error at line {line_no}: {exc.__class__.__name__}")
            if not isinstance(obj, dict):
                raise GovernanceAuditError(f"Non-object JSON at line {line_no}")
            yield line_no, obj


def audit_governance_events(path: Path) -> int:
    # First, prove vault integrity (hash chain + schema validation).
    try:
        validate_state_vault_chain(path)
    except StateVaultReplayError as exc:
        raise GovernanceAuditError(str(exc))

    # Then, apply governance-specific event-type allowlist.
    count = 0
    for line_no, obj in _iter_jsonl(path):
        if obj.get("organ_id") != GOVERNANCE_ORGAN_ID:
            continue
        event_type = obj.get("event_type")
        if not isinstance(event_type, str):
            raise GovernanceAuditError(f"Missing/invalid event_type at line {line_no} (fail-closed)")
        if event_type not in GOV_EVENT_TYPES:
            raise GovernanceAuditError(f"Unknown governance event_type at line {line_no} (fail-closed)")
        count += 1
    return count

