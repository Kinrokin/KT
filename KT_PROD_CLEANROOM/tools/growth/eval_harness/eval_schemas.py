from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple


class EvalSchemaError(ValueError):
    pass


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def sha256_json(obj: Any) -> str:
    return sha256_text(_canonical_json(obj))


def _reject_unknown_keys(payload: Mapping[str, Any], *, allowed: Iterable[str], name: str) -> None:
    unknown = set(payload.keys()) - set(allowed)
    if unknown:
        raise EvalSchemaError(f"{name} contains unknown keys: {sorted(unknown)} (fail-closed)")


def _require_dict(value: Any, *, name: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise EvalSchemaError(f"{name} must be an object (fail-closed)")
    return dict(value)


def _require_list(value: Any, *, name: str) -> List[Any]:
    if not isinstance(value, list):
        raise EvalSchemaError(f"{name} must be a list (fail-closed)")
    return list(value)


def _require_str(value: Any, *, name: str, min_len: int = 1, max_len: int = 256) -> str:
    if not isinstance(value, str):
        raise EvalSchemaError(f"{name} must be a string (fail-closed)")
    if not (min_len <= len(value) <= max_len):
        raise EvalSchemaError(f"{name} length out of bounds (fail-closed)")
    return value


def _require_int(value: Any, *, name: str, lo: int, hi: int) -> int:
    if not isinstance(value, int):
        raise EvalSchemaError(f"{name} must be an integer (fail-closed)")
    if not (lo <= value <= hi):
        raise EvalSchemaError(f"{name} out of bounds (fail-closed)")
    return value


def _require_float(value: Any, *, name: str, lo: float, hi: float) -> float:
    if not isinstance(value, (float, int)):
        raise EvalSchemaError(f"{name} must be a number (fail-closed)")
    value = float(value)
    if not (lo <= value <= hi):
        raise EvalSchemaError(f"{name} out of bounds (fail-closed)")
    return value


def _validate_hex64(value: str, *, name: str) -> None:
    if len(value) != 64:
        raise EvalSchemaError(f"{name} must be 64 hex chars (fail-closed)")
    try:
        int(value, 16)
    except Exception:
        raise EvalSchemaError(f"{name} must be hex (fail-closed)")


def _reject_raw_paths(paths: Iterable[str]) -> None:
    for p in paths:
        lowered = p.lower()
        if any(tok in lowered for tok in ("stdout", "stderr", "trace", "prompt", "chain-of-thought", "cot", "log")):
            raise EvalSchemaError("Raw runtime content referenced (fail-closed)")


ALLOWED_METRICS = {"pass_rate", "fail_rate"}


@dataclass(frozen=True)
class BenchmarkCaseSchema:
    case_id: str
    domain: str
    objective: str
    input_refs: Tuple[str, ...]
    expected_metrics: Dict[str, float]
    metric_weights: Dict[str, float]
    bounds: Dict[str, int]
    provenance_refs: Tuple[str, ...]

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "BenchmarkCaseSchema":
        payload = _require_dict(data, name="BenchmarkCase")
        _reject_unknown_keys(
            payload,
            allowed={
                "case_id",
                "domain",
                "objective",
                "input_refs",
                "expected_metrics",
                "metric_weights",
                "bounds",
                "provenance_refs",
            },
            name="BenchmarkCase",
        )
        case_id = _require_str(payload.get("case_id"), name="case_id", max_len=80)
        domain = _require_str(payload.get("domain"), name="domain", max_len=64)
        objective = _require_str(payload.get("objective"), name="objective", min_len=0, max_len=256)

        input_refs = tuple(_require_list(payload.get("input_refs"), name="input_refs"))
        input_refs = tuple(_require_str(x, name="input_refs[]", max_len=512) for x in input_refs)
        _reject_raw_paths(input_refs)

        expected_metrics = _require_dict(payload.get("expected_metrics"), name="expected_metrics")
        metric_weights = _require_dict(payload.get("metric_weights", {}), name="metric_weights")

        for name, val in expected_metrics.items():
            name = _require_str(name, name="metric_name", max_len=64)
            if name not in ALLOWED_METRICS:
                raise EvalSchemaError(f"metric {name} not allowed (fail-closed)")
            _require_float(val, name=f"expected_metrics[{name}]", lo=0.0, hi=1.0)
        for name, val in metric_weights.items():
            name = _require_str(name, name="metric_weight_name", max_len=64)
            if name not in expected_metrics:
                raise EvalSchemaError("metric_weights must be subset of expected_metrics (fail-closed)")
            _require_float(val, name=f"metric_weights[{name}]", lo=0.0, hi=1.0)

        bounds = _require_dict(payload.get("bounds"), name="bounds")
        _reject_unknown_keys(bounds, allowed={"max_inputs", "max_outputs"}, name="bounds")
        _require_int(bounds.get("max_inputs", 16), name="bounds.max_inputs", lo=0, hi=16)
        _require_int(bounds.get("max_outputs", 16), name="bounds.max_outputs", lo=0, hi=16)

        provenance_refs = tuple(_require_list(payload.get("provenance_refs"), name="provenance_refs"))
        provenance_refs = tuple(_require_str(x, name="provenance_refs[]", max_len=512) for x in provenance_refs)
        _reject_raw_paths(provenance_refs)

        return BenchmarkCaseSchema(
            case_id=case_id,
            domain=domain,
            objective=objective,
            input_refs=input_refs,
            expected_metrics={str(k): float(v) for k, v in expected_metrics.items()},
            metric_weights={str(k): float(v) for k, v in metric_weights.items()},
            bounds=bounds,
            provenance_refs=provenance_refs,
        )


@dataclass(frozen=True)
class BenchmarkSuiteSchema:
    suite_id: str
    suite_version: int
    kernel_identity: Dict[str, str]
    cases: Tuple[BenchmarkCaseSchema, ...]
    regression_threshold: float
    suite_hash: str

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "BenchmarkSuiteSchema":
        payload = _require_dict(data, name="BenchmarkSuite")
        _reject_unknown_keys(
            payload,
            allowed={"suite_id", "suite_version", "kernel_identity", "cases", "regression_threshold"},
            name="BenchmarkSuite",
        )
        suite_id = _require_str(payload.get("suite_id"), name="suite_id", max_len=80)
        suite_version = _require_int(payload.get("suite_version", 1), name="suite_version", lo=1, hi=1_000)
        kernel_identity = _require_dict(payload.get("kernel_identity"), name="kernel_identity")
        _require_str(kernel_identity.get("kernel_target"), name="kernel_identity.kernel_target", max_len=32)
        _require_str(kernel_identity.get("kernel_build_id", "unknown"), name="kernel_identity.kernel_build_id", max_len=128)

        case_list = _require_list(payload.get("cases"), name="cases")
        if len(case_list) == 0:
            raise EvalSchemaError("cases must not be empty (fail-closed)")
        cases = tuple(BenchmarkCaseSchema.from_dict(c) for c in case_list)

        regression_threshold = _require_float(payload.get("regression_threshold", 0.0), name="regression_threshold", lo=0.0, hi=1.0)
        suite_hash = compute_suite_hash(
            suite_id=suite_id,
            suite_version=suite_version,
            kernel_identity=kernel_identity,
            cases=cases,
            regression_threshold=regression_threshold,
        )
        return BenchmarkSuiteSchema(
            suite_id=suite_id,
            suite_version=suite_version,
            kernel_identity=kernel_identity,
            cases=cases,
            regression_threshold=regression_threshold,
            suite_hash=suite_hash,
        )


def compute_suite_hash(
    *,
    suite_id: str,
    suite_version: int,
    kernel_identity: Dict[str, str],
    cases: Iterable[BenchmarkCaseSchema],
    regression_threshold: float,
) -> str:
    obj = {
        "suite_id": suite_id,
        "suite_version": suite_version,
        "kernel_identity": kernel_identity,
        "cases": [
            {
                "case_id": c.case_id,
                "domain": c.domain,
                "objective": c.objective,
                "input_refs": list(c.input_refs),
                "expected_metrics": c.expected_metrics,
                "metric_weights": c.metric_weights,
                "bounds": c.bounds,
                "provenance_refs": list(c.provenance_refs),
            }
            for c in cases
        ],
        "regression_threshold": regression_threshold,
    }
    return sha256_json(obj)


@dataclass(frozen=True)
class BenchmarkRunSchema:
    run_id: str
    suite_hash: str
    epoch_ids: Tuple[str, ...]
    kernel_identity: Dict[str, str]

    @staticmethod
    def build(*, suite_hash: str, epoch_ids: Iterable[str], kernel_identity: Dict[str, str]) -> "BenchmarkRunSchema":
        epoch_ids = tuple(epoch_ids)
        if not epoch_ids:
            raise EvalSchemaError("epoch_ids must not be empty (fail-closed)")
        for eid in epoch_ids:
            _require_str(eid, name="epoch_id", max_len=80)
        run_id = sha256_json({"suite_hash": suite_hash, "epoch_ids": list(epoch_ids), "kernel_identity": kernel_identity})
        return BenchmarkRunSchema(run_id=run_id, suite_hash=suite_hash, epoch_ids=epoch_ids, kernel_identity=kernel_identity)


@dataclass(frozen=True)
class BenchmarkResultSchema:
    run: BenchmarkRunSchema
    per_case_scores: Dict[str, float]
    aggregate_score: float
    regression_flag: bool
    provenance_refs: Tuple[str, ...]


@dataclass(frozen=True)
class LearningDeltaSchema:
    delta_id: str
    baseline_run_id: str
    candidate_run_id: str
    per_metric_deltas: Dict[str, float]
    confidence: float
    suite_hash: str
    provenance_refs: Tuple[str, ...]

    @staticmethod
    def build(
        *,
        baseline_run_id: str,
        candidate_run_id: str,
        per_metric_deltas: Dict[str, float],
        confidence: float,
        suite_hash: str,
        provenance_refs: Iterable[str],
    ) -> "LearningDeltaSchema":
        _require_str(baseline_run_id, name="baseline_run_id", max_len=128)
        _require_str(candidate_run_id, name="candidate_run_id", max_len=128)
        for k, v in per_metric_deltas.items():
            _require_str(k, name="metric_name", max_len=64)
            _require_float(v, name=f"per_metric_deltas[{k}]", lo=-1.0, hi=1.0)
        confidence = _require_float(confidence, name="confidence", lo=0.0, hi=1.0)
        suite_hash = _require_str(suite_hash, name="suite_hash", min_len=64, max_len=64)
        _validate_hex64(suite_hash, name="suite_hash")

        refs = tuple(_require_str(x, name="provenance_ref", max_len=512) for x in provenance_refs)
        _reject_raw_paths(refs)

        delta_id = sha256_json(
            {
                "baseline_run_id": baseline_run_id,
                "candidate_run_id": candidate_run_id,
                "per_metric_deltas": per_metric_deltas,
                "suite_hash": suite_hash,
                "provenance_refs": list(refs),
            }
        )
        return LearningDeltaSchema(
            delta_id=delta_id,
            baseline_run_id=baseline_run_id,
            candidate_run_id=candidate_run_id,
            per_metric_deltas=per_metric_deltas,
            confidence=confidence,
            suite_hash=suite_hash,
            provenance_refs=refs,
        )
