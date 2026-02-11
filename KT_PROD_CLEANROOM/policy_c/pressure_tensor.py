from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Mapping

SCHEMA_ID = "kt.policy_c.pressure_tensor.v1"

ALLOWED_AXES = ("time", "universe", "language", "hop", "step", "paradox", "puzzle")
ALLOWED_RULES = ("weighted_sum", "max", "sum")


@dataclass(frozen=True)
class PressureTensor:
    axes: Mapping[str, Dict[str, Any]]
    projection: Mapping[str, Any]
    invariants: Mapping[str, Any]

    @staticmethod
    def from_dict(raw: Dict[str, Any]) -> "PressureTensor":
        _validate_tensor(raw)
        return PressureTensor(
            axes=dict(raw["axes"]),
            projection=dict(raw["projection"]),
            invariants=dict(raw["invariants"]),
        )

    def pressure_contributions(self) -> Dict[str, float]:
        return _compute_contributions(self.axes, self.projection)

    def pressure_scalar(self) -> float:
        return _compute_scalar(self.axes, self.projection)

    def projection_hash(self) -> str:
        return _sha256_text(_canonical_json(_normalize_tensor(self)))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _format_float(value: float) -> str:
    return f"{value:.6f}"


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _normalize_tensor(tensor: PressureTensor) -> Dict[str, Any]:
    axes: Dict[str, Any] = {}
    for axis in sorted(tensor.axes.keys()):
        cfg = tensor.axes[axis]
        axes[axis] = {
            "enabled": bool(cfg["enabled"]),
            "intensity": _format_float(float(cfg["intensity"])),
        }

    projection = dict(tensor.projection)
    weights = projection.get("weights") or {}
    normalized_weights: Dict[str, str] = {}
    if isinstance(weights, dict):
        for axis in sorted(weights.keys()):
            normalized_weights[axis] = _format_float(float(weights[axis]))

    normalized_projection = {
        "rule": projection["rule"],
        "weights": normalized_weights,
        "clamp_min": _format_float(float(projection["clamp_min"])),
        "clamp_max": _format_float(float(projection["clamp_max"])),
    }

    return {
        "schema_id": SCHEMA_ID,
        "axes": axes,
        "projection": normalized_projection,
        "invariants": dict(tensor.invariants),
    }


def _validate_tensor(raw: Dict[str, Any]) -> None:
    if not isinstance(raw, dict):
        raise ValueError("pressure tensor must be an object (fail-closed)")
    if set(raw.keys()) != {"schema_id", "axes", "projection", "invariants"}:
        raise ValueError("pressure tensor must contain only schema_id, axes, projection, invariants (fail-closed)")
    if raw.get("schema_id") != SCHEMA_ID:
        raise ValueError("pressure tensor schema_id mismatch (fail-closed)")

    axes = raw.get("axes")
    if not isinstance(axes, dict) or not axes:
        raise ValueError("axes must be a non-empty object (fail-closed)")
    for axis, cfg in axes.items():
        if axis not in ALLOWED_AXES:
            raise ValueError(f"axis not allowlisted: {axis!r} (fail-closed)")
        if not isinstance(cfg, dict) or set(cfg.keys()) != {"intensity", "enabled"}:
            raise ValueError("axis config must contain intensity, enabled only (fail-closed)")
        intensity = cfg.get("intensity")
        enabled = cfg.get("enabled")
        if not isinstance(enabled, bool):
            raise ValueError("axis.enabled must be boolean (fail-closed)")
        if not isinstance(intensity, (int, float)):
            raise ValueError("axis.intensity must be numeric (fail-closed)")
        if intensity < 0.0 or intensity > 1.0:
            raise ValueError("axis.intensity out of bounds [0,1] (fail-closed)")

    projection = raw.get("projection")
    if not isinstance(projection, dict):
        raise ValueError("projection must be an object (fail-closed)")
    if set(projection.keys()) != {"rule", "weights", "clamp_min", "clamp_max"}:
        raise ValueError("projection must contain rule, weights, clamp_min, clamp_max (fail-closed)")
    rule = projection.get("rule")
    if rule not in ALLOWED_RULES:
        raise ValueError("projection.rule not allowlisted (fail-closed)")

    weights = projection.get("weights")
    if not isinstance(weights, dict):
        raise ValueError("projection.weights must be an object (fail-closed)")
    for axis, weight in weights.items():
        if axis not in ALLOWED_AXES:
            raise ValueError(f"projection.weights axis not allowlisted: {axis!r} (fail-closed)")
        if not isinstance(weight, (int, float)):
            raise ValueError("projection.weights values must be numeric (fail-closed)")
        if weight < 0.0 or weight > 1.0:
            raise ValueError("projection.weights values out of bounds [0,1] (fail-closed)")

    clamp_min = projection.get("clamp_min")
    clamp_max = projection.get("clamp_max")
    if not isinstance(clamp_min, (int, float)) or not isinstance(clamp_max, (int, float)):
        raise ValueError("projection clamp bounds must be numeric (fail-closed)")
    if clamp_min < 0.0 or clamp_max > 1.0 or clamp_min > clamp_max:
        raise ValueError("projection clamp bounds invalid (fail-closed)")

    if rule == "weighted_sum":
        missing = [axis for axis in axes.keys() if axis not in weights]
        if missing:
            raise ValueError(f"projection.weights missing axes: {missing} (fail-closed)")

    invariants = raw.get("invariants")
    if not isinstance(invariants, dict) or set(invariants.keys()) != {"reversible", "isolated", "no_cross_axis_bleed"}:
        raise ValueError("invariants must contain reversible, isolated, no_cross_axis_bleed (fail-closed)")
    if not all(isinstance(invariants[k], bool) for k in invariants.keys()):
        raise ValueError("invariants values must be booleans (fail-closed)")
    if invariants.get("no_cross_axis_bleed") is not True:
        raise ValueError("no_cross_axis_bleed must be true (fail-closed)")


def _compute_contributions(axes: Mapping[str, Dict[str, Any]], projection: Mapping[str, Any]) -> Dict[str, float]:
    rule = projection["rule"]
    weights = projection.get("weights", {})
    contributions: Dict[str, float] = {}
    for axis, cfg in axes.items():
        intensity = float(cfg["intensity"]) if cfg["enabled"] else 0.0
        if rule == "weighted_sum":
            weight = float(weights[axis])
            contributions[axis] = intensity * weight
        else:
            contributions[axis] = intensity
    return contributions


def _compute_scalar(axes: Mapping[str, Dict[str, Any]], projection: Mapping[str, Any]) -> float:
    rule = projection["rule"]
    contributions = _compute_contributions(axes, projection)
    if not contributions:
        scalar = 0.0
    elif rule == "max":
        scalar = max(contributions.values())
    else:
        scalar = sum(contributions.values())

    clamp_min = float(projection["clamp_min"])
    clamp_max = float(projection["clamp_max"])
    if scalar < clamp_min:
        return clamp_min
    if scalar > clamp_max:
        return clamp_max
    return scalar


def single_axis_sweep(tensor: PressureTensor, *, axis: str, intensity: float) -> PressureTensor:
    if axis not in tensor.axes:
        raise ValueError(f"axis not present in tensor: {axis!r} (fail-closed)")
    if intensity < 0.0 or intensity > 1.0:
        raise ValueError("intensity out of bounds [0,1] (fail-closed)")
    axes = {k: dict(v) for k, v in tensor.axes.items()}
    axes[axis]["intensity"] = float(intensity)
    payload = {
        "schema_id": SCHEMA_ID,
        "axes": axes,
        "projection": dict(tensor.projection),
        "invariants": dict(tensor.invariants),
    }
    return PressureTensor.from_dict(payload)
