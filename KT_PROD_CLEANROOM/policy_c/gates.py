from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from core.runtime_registry import PolicyCDriftSpec
from memory.state_vault import StateVault
from policy_c.drift_guard import DriftReport, emit_governance_for_drift, evaluate_drift, hash_tensor
from policy_c.pressure_tensor import PressureTensor


@dataclass(frozen=True)
class GateResult:
    status: str
    receipts: List[str]
    drift_report: DriftReport


def run_drift_gate(
    *,
    epoch_id: str,
    baseline_epoch_id: str,
    baseline_tensor: PressureTensor,
    current_tensor: PressureTensor,
    invariant_violations: int,
    thresholds: PolicyCDriftSpec,
    vault: Optional[StateVault] = None,
) -> GateResult:
    report = evaluate_drift(
        epoch_id=epoch_id,
        baseline_epoch_id=baseline_epoch_id,
        baseline_tensor=baseline_tensor,
        current_tensor=current_tensor,
        invariant_violations=invariant_violations,
        thresholds=thresholds,
    )
    receipts = [report.report_hash()]
    if vault is not None:
        emit_governance_for_drift(
            report=report,
            vault=vault,
            pressure_tensor_hash=hash_tensor(current_tensor),
            baseline_tensor_hash=hash_tensor(baseline_tensor),
        )
        if report.drift_class in {"WARN", "FAIL"}:
            receipts.append(f"governance:{report.drift_class.lower()}")

    status = "FAIL" if report.drift_class == "FAIL" else "PASS"
    return GateResult(status=status, receipts=receipts, drift_report=report)
