from __future__ import annotations

import json
import math
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple


class EvalPlusSchemaError(ValueError):
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
        raise EvalPlusSchemaError(f"{name} contains unknown keys: {sorted(unknown)} (fail-closed)")


def _require_dict(value: Any, *, name: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise EvalPlusSchemaError(f"{name} must be an object (fail-closed)")
    return dict(value)


def _require_list(value: Any, *, name: str) -> List[Any]:
    if not isinstance(value, list):
        raise EvalPlusSchemaError(f"{name} must be a list (fail-closed)")
    return list(value)


def _require_str(value: Any, *, name: str, min_len: int = 1, max_len: int = 256) -> str:
    if not isinstance(value, str):
        raise EvalPlusSchemaError(f"{name} must be a string (fail-closed)")
    if not (min_len <= len(value) <= max_len):
        raise EvalPlusSchemaError(f"{name} length out of bounds (fail-closed)")
    return value


def _require_int(value: Any, *, name: str, lo: int, hi: int) -> int:
    if not isinstance(value, int):
        raise EvalPlusSchemaError(f"{name} must be an integer (fail-closed)")
    if not (lo <= value <= hi):
        raise EvalPlusSchemaError(f"{name} out of bounds (fail-closed)")
    return value


def _require_float(value: Any, *, name: str, lo: float, hi: float) -> float:
    if not isinstance(value, (float, int)):
        raise EvalPlusSchemaError(f"{name} must be a number (fail-closed)")
    value = float(value)
    if not (lo <= value <= hi):
        raise EvalPlusSchemaError(f"{name} out of bounds (fail-closed)")
    return value


def _require_hex64(value: Any, *, name: str) -> str:
    s = _require_str(value, name=name, min_len=64, max_len=64)
    try:
        int(s, 16)
    except Exception:
        raise EvalPlusSchemaError(f"{name} must be hex (fail-closed)")
    return s


def _normalized_entropy(counts: Mapping[str, int]) -> float:
    items = [(k, v) for k, v in counts.items() if isinstance(k, str) and isinstance(v, int) and v > 0]
    if not items:
        return 0.0
    total = sum(v for _, v in items)
    if total <= 0:
        return 0.0
    probs = [v / total for _, v in items]
    h = -sum(p * math.log(p, 2) for p in probs if p > 0)
    max_h = math.log(len(probs), 2) if len(probs) > 1 else 1.0
    return float(h / max_h) if max_h > 0 else 0.0


ALLOWED_OUTCOMES: Set[str] = {"PASS", "FAIL", "REFUSE", "INFEASIBLE", "ERROR"}
ALLOWED_PARADOX_AXES: Set[str] = {"pass_rate", "replay_consistency", "governance_entropy", "refusal_ratio"}
ALLOWED_DRIFT_AXES: Set[str] = {f"delta_{a}" for a in sorted(ALLOWED_PARADOX_AXES)}


@dataclass(frozen=True)
class ParadoxMetricVectorSchema:
    axes: Dict[str, float]
    support: Dict[str, int]
    vector_hash: str

    @staticmethod
    def from_parts(*, axes: Mapping[str, float], support: Mapping[str, int]) -> "ParadoxMetricVectorSchema":
        ax: Dict[str, float] = {}
        for k, v in dict(axes).items():
            k = _require_str(k, name="paradox.axes.key", max_len=64)
            if k not in ALLOWED_PARADOX_AXES:
                raise EvalPlusSchemaError(f"paradox axis not allowed: {k} (fail-closed)")
            ax[k] = _require_float(v, name=f"paradox.axes[{k}]", lo=0.0, hi=1.0)

        sup: Dict[str, int] = {}
        for k, v in dict(support).items():
            k = _require_str(k, name="paradox.support.key", max_len=64)
            if k not in ALLOWED_OUTCOMES and k not in {"total", "replay_verified", "governance_events"}:
                raise EvalPlusSchemaError(f"paradox support key not allowed: {k} (fail-closed)")
            sup[k] = _require_int(v, name=f"paradox.support[{k}]", lo=0, hi=10_000_000)

        vector_hash = sha256_json({"axes": ax, "support": sup})
        return ParadoxMetricVectorSchema(axes=ax, support=sup, vector_hash=vector_hash)

    def to_dict(self) -> Dict[str, Any]:
        return {"axes": dict(self.axes), "support": dict(self.support), "vector_hash": self.vector_hash}

    @staticmethod
    def validate(data: Mapping[str, Any]) -> None:
        payload = _require_dict(data, name="ParadoxMetricVector")
        _reject_unknown_keys(payload, allowed={"axes", "support", "vector_hash"}, name="ParadoxMetricVector")
        axes = _require_dict(payload.get("axes"), name="axes")
        support = _require_dict(payload.get("support"), name="support")
        for k, v in axes.items():
            if k not in ALLOWED_PARADOX_AXES:
                raise EvalPlusSchemaError("axis not allowed (fail-closed)")
            _require_float(v, name=f"axes[{k}]", lo=0.0, hi=1.0)
        for k, v in support.items():
            _require_str(k, name="support.key", max_len=64)
            _require_int(v, name=f"support[{k}]", lo=0, hi=10_000_000)
        _require_hex64(payload.get("vector_hash"), name="vector_hash")
        if sha256_json({"axes": axes, "support": support}) != payload.get("vector_hash"):
            raise EvalPlusSchemaError("vector_hash mismatch (fail-closed)")


@dataclass(frozen=True)
class DriftMetricVectorSchema:
    axes: Dict[str, float]
    drift_hash: str

    @staticmethod
    def from_vectors(*, baseline: ParadoxMetricVectorSchema, candidate: ParadoxMetricVectorSchema) -> "DriftMetricVectorSchema":
        axes: Dict[str, float] = {}
        for key in sorted(ALLOWED_PARADOX_AXES):
            b = float(baseline.axes.get(key, 0.0))
            c = float(candidate.axes.get(key, 0.0))
            axes[f"delta_{key}"] = float(min(1.0, abs(c - b)))
        drift_hash = sha256_json({"axes": axes, "baseline": baseline.vector_hash, "candidate": candidate.vector_hash})
        return DriftMetricVectorSchema(axes=axes, drift_hash=drift_hash)

    def to_dict(self) -> Dict[str, Any]:
        return {"axes": dict(self.axes), "drift_hash": self.drift_hash}

    @staticmethod
    def validate(data: Mapping[str, Any]) -> None:
        payload = _require_dict(data, name="DriftMetricVector")
        _reject_unknown_keys(payload, allowed={"axes", "drift_hash"}, name="DriftMetricVector")
        axes = _require_dict(payload.get("axes"), name="axes")
        for k, v in axes.items():
            if k not in ALLOWED_DRIFT_AXES:
                raise EvalPlusSchemaError("drift axis not allowed (fail-closed)")
            _require_float(v, name=f"axes[{k}]", lo=0.0, hi=1.0)
        _require_hex64(payload.get("drift_hash"), name="drift_hash")


@dataclass(frozen=True)
class GoldenZoneSchema:
    metric: str
    min: float
    max: float
    score: float
    verdict: str

    @staticmethod
    def evaluate(*, metric: str, score: float, min_val: float, max_val: float) -> "GoldenZoneSchema":
        metric = _require_str(metric, name="golden.metric", max_len=64)
        min_val = _require_float(min_val, name="golden.min", lo=0.0, hi=1.0)
        max_val = _require_float(max_val, name="golden.max", lo=0.0, hi=1.0)
        if min_val > max_val:
            raise EvalPlusSchemaError("golden zone min > max (fail-closed)")
        score = _require_float(score, name="golden.score", lo=0.0, hi=1.0)
        if score < min_val:
            verdict = "UNDER_RANGE"
        elif score > max_val:
            verdict = "OVER_RANGE"
        else:
            verdict = "WITHIN_RANGE"
        return GoldenZoneSchema(metric=metric, min=min_val, max=max_val, score=score, verdict=verdict)

    def to_dict(self) -> Dict[str, Any]:
        return {"metric": self.metric, "min": self.min, "max": self.max, "score": self.score, "verdict": self.verdict}

    @staticmethod
    def validate(data: Mapping[str, Any]) -> None:
        payload = _require_dict(data, name="GoldenZone")
        _reject_unknown_keys(payload, allowed={"metric", "min", "max", "score", "verdict"}, name="GoldenZone")
        _require_str(payload.get("metric"), name="metric", max_len=64)
        mn = _require_float(payload.get("min"), name="min", lo=0.0, hi=1.0)
        mx = _require_float(payload.get("max"), name="max", lo=0.0, hi=1.0)
        if mn > mx:
            raise EvalPlusSchemaError("min > max (fail-closed)")
        _require_float(payload.get("score"), name="score", lo=0.0, hi=1.0)
        _require_str(payload.get("verdict"), name="verdict", max_len=32)


@dataclass(frozen=True)
class ExtendedBenchmarkResultSchema:
    schema: str
    schema_version: int
    epoch_id: str
    kernel_identity: Dict[str, str]
    paradox: ParadoxMetricVectorSchema
    drift: Optional[DriftMetricVectorSchema]
    golden_zone: GoldenZoneSchema
    result_hash: str
    status: str

    @staticmethod
    def from_parts(
        *,
        epoch_id: str,
        kernel_identity: Mapping[str, str],
        paradox: ParadoxMetricVectorSchema,
        drift: Optional[DriftMetricVectorSchema],
        golden_zone: GoldenZoneSchema,
    ) -> "ExtendedBenchmarkResultSchema":
        epoch_id = _require_str(epoch_id, name="epoch_id", max_len=128)
        kid = _require_dict(kernel_identity, name="kernel_identity")
        _require_str(kid.get("kernel_target"), name="kernel_identity.kernel_target", max_len=32)
        _require_str(kid.get("kernel_build_id", "unknown"), name="kernel_identity.kernel_build_id", max_len=128)

        status = "PASS" if golden_zone.verdict == "WITHIN_RANGE" else "FAIL_CLOSED"
        core = {
            "schema": "kt.eval_plus.result",
            "schema_version": 1,
            "epoch_id": epoch_id,
            "kernel_identity": kid,
            "paradox": paradox.to_dict(),
            "drift": drift.to_dict() if drift else None,
            "golden_zone": golden_zone.to_dict(),
            "status": status,
        }
        result_hash = sha256_json(core)
        return ExtendedBenchmarkResultSchema(
            schema=core["schema"],
            schema_version=1,
            epoch_id=epoch_id,
            kernel_identity=kid,
            paradox=paradox,
            drift=drift,
            golden_zone=golden_zone,
            result_hash=result_hash,
            status=status,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "epoch_id": self.epoch_id,
            "kernel_identity": dict(self.kernel_identity),
            "paradox": self.paradox.to_dict(),
            "drift": self.drift.to_dict() if self.drift else None,
            "golden_zone": self.golden_zone.to_dict(),
            "status": self.status,
            "result_hash": self.result_hash,
        }

    @staticmethod
    def validate(data: Mapping[str, Any]) -> None:
        payload = _require_dict(data, name="ExtendedBenchmarkResult")
        _reject_unknown_keys(
            payload,
            allowed={"schema", "schema_version", "epoch_id", "kernel_identity", "paradox", "drift", "golden_zone", "status", "result_hash"},
            name="ExtendedBenchmarkResult",
        )
        if payload.get("schema") != "kt.eval_plus.result":
            raise EvalPlusSchemaError("schema mismatch (fail-closed)")
        _require_int(payload.get("schema_version"), name="schema_version", lo=1, hi=1)
        _require_str(payload.get("epoch_id"), name="epoch_id", max_len=128)
        kid = _require_dict(payload.get("kernel_identity"), name="kernel_identity")
        _require_str(kid.get("kernel_target"), name="kernel_target", max_len=32)
        _require_str(kid.get("kernel_build_id", "unknown"), name="kernel_build_id", max_len=128)
        ParadoxMetricVectorSchema.validate(_require_dict(payload.get("paradox"), name="paradox"))
        drift = payload.get("drift")
        if drift is not None:
            DriftMetricVectorSchema.validate(_require_dict(drift, name="drift"))
        GoldenZoneSchema.validate(_require_dict(payload.get("golden_zone"), name="golden_zone"))
        _require_str(payload.get("status"), name="status", max_len=32)
        _require_hex64(payload.get("result_hash"), name="result_hash")
        # Verify hash integrity (bind the full record excluding the hash field).
        computed = sha256_json({k: payload[k] for k in payload.keys() if k != "result_hash"})
        if computed != payload.get("result_hash"):
            raise EvalPlusSchemaError("result_hash mismatch (fail-closed)")


def compute_paradox_vector(
    *,
    outcomes: Mapping[str, int],
    replay_verified: int,
    replay_total: int,
    governance_types: Mapping[str, int],
) -> ParadoxMetricVectorSchema:
    total = sum(int(v) for v in outcomes.values() if isinstance(v, int) and v >= 0)
    total = max(0, total)
    pass_rate = float(outcomes.get("PASS", 0) / total) if total else 0.0
    refusal_ratio = float(outcomes.get("REFUSE", 0) / total) if total else 0.0
    replay_consistency = float(replay_verified / replay_total) if replay_total else 0.0
    gov_entropy = _normalized_entropy(governance_types)
    return ParadoxMetricVectorSchema.from_parts(
        axes={
            "pass_rate": pass_rate,
            "refusal_ratio": refusal_ratio,
            "replay_consistency": replay_consistency,
            "governance_entropy": gov_entropy,
        },
        support={"total": total, "replay_verified": replay_verified, "governance_events": sum(governance_types.values())},
    )
