from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from governance.events import (
    GOVERNANCE_ORGAN_ID,
    GovernanceEventError,
    assert_event_type_allowed,
    assert_governance_organ_id,
    compute_envelope_hash,
)
from memory.state_vault import StateVault, StateVaultCorruptionError, StateVaultWriteError


@dataclass(frozen=True)
class GovernanceLogError(RuntimeError):
    message: str

    def __str__(self) -> str:
        return self.message


def log_governance_event(
    *,
    vault: StateVault,
    event_type: str,
    inputs_envelope: Dict[str, Any],
    outputs_envelope: Dict[str, Any],
    crisis_mode: Optional[str] = None,
) -> None:
    try:
        assert_event_type_allowed(event_type)
        assert_governance_organ_id(GOVERNANCE_ORGAN_ID)
        inputs_hash = compute_envelope_hash(inputs_envelope)
        outputs_hash = compute_envelope_hash(outputs_envelope)
    except GovernanceEventError as exc:
        raise GovernanceLogError(str(exc))

    try:
        vault.append(
            event_type=event_type,
            organ_id=GOVERNANCE_ORGAN_ID,
            inputs_hash=inputs_hash,
            outputs_hash=outputs_hash,
            crisis_mode=crisis_mode,
        )
    except (StateVaultWriteError, StateVaultCorruptionError) as exc:
        # Fail-closed: inability to persist governance is a Constitutional Crisis.
        raise GovernanceLogError(str(exc))

