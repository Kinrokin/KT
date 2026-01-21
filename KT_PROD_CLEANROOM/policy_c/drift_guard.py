from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.runtime_registry import PolicyCDriftSpec
from governance.event_logger import log_governance_event
from governance.events import build_inputs_envelope, build_outputs_envelope
from memory.state_vault import StateVault
from policy_c.pressure_tensor import PressureTensor


@dataclass(frozen=True)
class DriftReport:
    epoch_id: str
    baseline_epoch_id: str
    pressure_delta_l2: float
    pressure_delta_max: float
    invariant_violations: int
    drift_class: str
    reason_codes: List[str]
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "epoch_id": self.epoch_id,
            "baseline_epoch_id": self.baseline_epoch_id,
            "pressure_delta_l2": self.pressure_delta_l2,
            "pressure_delta_max": self.pressure_delta_max,
            "invariant_violations": self.invariant_violations,
            "drift_class": self.drift_class,
            "reason_codes": list(self.reason_codes),
            "timestamp": self.timestamp,
        }

    def report_hash(self) -> str:
        return _sha256_text(_canonical_json(self.to_dict()))


def compute_pressure_deltas(
    *,
    baseline: PressureTensor,
    current: PressureTensor,
) -> Tuple[float, float]:
    base = baseline.pressure_contributions()
    curr = current.pressure_contributions()
    axes = sorted(set(base.keys()) | set(curr.keys()))
    diffs: List[float] = []
    for axis in axes:
        diffs.append(float(curr.get(axis, 0.0)) - float(base.get(axis, 0.0)))
    l2 = math.sqrt(sum(d * d for d in diffs))
    max_delta = max((abs(d) for d in diffs), default=0.0)
    return l2, max_delta


def evaluate_drift(
    *,
    epoch_id: str,
    baseline_epoch_id: str,
    baseline_tensor: PressureTensor,
    current_tensor: PressureTensor,
    invariant_violations: int,
    thresholds: PolicyCDriftSpec,
) -> DriftReport:
    l2, max_delta = compute_pressure_deltas(baseline=baseline_tensor, current=current_tensor)
    reason_codes: List[str] = []

    if invariant_violations > 0:
        drift_class = "FAIL"
        reason_codes.append("INVARIANT_VIOLATION")
    elif l2 > thresholds.l2_fail or max_delta > thresholds.max_fail:
        drift_class = "FAIL"
        if l2 > thresholds.l2_fail:
            reason_codes.append("L2_FAIL")
        if max_delta > thresholds.max_fail:
            reason_codes.append("MAX_FAIL")
    elif l2 > thresholds.l2_warn:
        drift_class = "WARN"
        reason_codes.append("L2_WARN")
    else:
        drift_class = "PASS"

    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return DriftReport(
        epoch_id=epoch_id,
        baseline_epoch_id=baseline_epoch_id,
        pressure_delta_l2=round(l2, 6),
        pressure_delta_max=round(max_delta, 6),
        invariant_violations=int(invariant_violations),
        drift_class=drift_class,
        reason_codes=reason_codes,
        timestamp=timestamp,
    )


def emit_governance_for_drift(
    *,
    report: DriftReport,
    vault: StateVault,
    pressure_tensor_hash: str,
    baseline_tensor_hash: str,
) -> None:
    if report.drift_class not in {"WARN", "FAIL"}:
        return
    event_type = "POLICY_C_DRIFT_WARN" if report.drift_class == "WARN" else "POLICY_C_DRIFT_FAIL"
    report_hash = report.report_hash()
    inputs = build_inputs_envelope(
        policy_id="p.v2.policy_c.drift",
        policy_version_hash=report_hash,
        subject_hash=pressure_tensor_hash,
        context_hash=baseline_tensor_hash,
        rule_id="r.v2.policy_c.drift.v1",
    )
    decision = "ALLOW" if report.drift_class == "WARN" else "DENY"
    outputs = build_outputs_envelope(decision=decision, obligations_hash=report_hash)
    log_governance_event(vault=vault, event_type=event_type, inputs_envelope=inputs, outputs_envelope=outputs)


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_tensor(tensor: PressureTensor) -> str:
    return _sha256_text(_canonical_json(tensor.pressure_contributions()))
