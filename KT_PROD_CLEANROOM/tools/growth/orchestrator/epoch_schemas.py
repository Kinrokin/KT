from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


class EpochSchemaError(ValueError):
    pass


KERNEL_V2_SOVEREIGN = "V2_SOVEREIGN"
KERNEL_V1_ARCHIVAL = "V1_ARCHIVAL"
KERNEL_TARGETS = {KERNEL_V2_SOVEREIGN, KERNEL_V1_ARCHIVAL}

RUNNER_TEMPLATE_C019 = "C019_RUNNER_V1"
RUNNER_TEMPLATES = {RUNNER_TEMPLATE_C019}


def _reject_unknown_keys(payload: Mapping[str, Any], *, allowed: Iterable[str], name: str) -> None:
    unknown = set(payload.keys()) - set(allowed)
    if unknown:
        raise EpochSchemaError(f"{name} contains unknown keys: {sorted(unknown)} (fail-closed)")


def _require_dict(value: Any, *, name: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise EpochSchemaError(f"{name} must be an object (fail-closed)")
    return dict(value)


def _require_list(value: Any, *, name: str) -> List[Any]:
    if not isinstance(value, list):
        raise EpochSchemaError(f"{name} must be a list (fail-closed)")
    return list(value)


def _require_str(value: Any, *, name: str, min_len: int = 1, max_len: int = 256) -> str:
    if not isinstance(value, str):
        raise EpochSchemaError(f"{name} must be a string (fail-closed)")
    if not (min_len <= len(value) <= max_len):
        raise EpochSchemaError(f"{name} length out of bounds (fail-closed)")
    return value


def _require_int(value: Any, *, name: str, lo: int, hi: int) -> int:
    if not isinstance(value, int):
        raise EpochSchemaError(f"{name} must be an integer (fail-closed)")
    if not (lo <= value <= hi):
        raise EpochSchemaError(f"{name} out of bounds (fail-closed)")
    return value


def _require_enum(value: Any, *, name: str, allowed: Iterable[str]) -> str:
    value = _require_str(value, name=name)
    if value not in allowed:
        raise EpochSchemaError(f"{name} must be one of {sorted(allowed)} (fail-closed)")
    return value


@dataclass(frozen=True)
class KernelIdentity:
    kernel_target: str
    kernel_build_id: str
    kernel_fingerprint: Optional[str] = None

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "KernelIdentity":
        payload = _require_dict(data, name="kernel_identity")
        _reject_unknown_keys(
            payload,
            allowed={"kernel_target", "kernel_build_id", "kernel_fingerprint"},
            name="kernel_identity",
        )
        kernel_target = _require_enum(payload.get("kernel_target"), name="kernel_identity.kernel_target", allowed=KERNEL_TARGETS)
        kernel_build_id = _require_str(payload.get("kernel_build_id", "unknown"), name="kernel_identity.kernel_build_id", min_len=1, max_len=128)
        kernel_fingerprint = payload.get("kernel_fingerprint")
        if kernel_fingerprint is not None:
            kernel_fingerprint = _require_str(kernel_fingerprint, name="kernel_identity.kernel_fingerprint", min_len=1, max_len=128)
        return KernelIdentity(kernel_target=kernel_target, kernel_build_id=kernel_build_id, kernel_fingerprint=kernel_fingerprint)

    def to_dict(self) -> Dict[str, Any]:
        out = {"kernel_target": self.kernel_target, "kernel_build_id": self.kernel_build_id}
        if self.kernel_fingerprint is not None:
            out["kernel_fingerprint"] = self.kernel_fingerprint
        return out


@dataclass(frozen=True)
class RunnerConfig:
    template_id: str
    args: Tuple[str, ...] = ()

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "RunnerConfig":
        payload = _require_dict(data, name="runner_config")
        _reject_unknown_keys(payload, allowed={"template_id", "args"}, name="runner_config")
        template_id = _require_enum(payload.get("template_id"), name="runner_config.template_id", allowed=RUNNER_TEMPLATES)
        args_list = _require_list(payload.get("args", []), name="runner_config.args")
        args: List[str] = []
        for idx, arg in enumerate(args_list):
            arg = _require_str(arg, name=f"runner_config.args[{idx}]", min_len=1, max_len=256)
            if arg.startswith("--"):
                raise EpochSchemaError("runner_config.args must be positional only (fail-closed)")
            args.append(arg)
        return RunnerConfig(template_id=template_id, args=tuple(args))

    def to_dict(self) -> Dict[str, Any]:
        return {"template_id": self.template_id, "args": list(self.args)}


@dataclass(frozen=True)
class EpochBudgets:
    per_crucible_timeout_ms: int
    per_crucible_rss_mb: int
    epoch_wall_clock_ms: int
    max_concurrency: int

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "EpochBudgets":
        payload = _require_dict(data, name="budgets")
        _reject_unknown_keys(
            payload,
            allowed={"per_crucible_timeout_ms", "per_crucible_rss_mb", "epoch_wall_clock_ms", "max_concurrency"},
            name="budgets",
        )
        per_crucible_timeout_ms = _require_int(payload.get("per_crucible_timeout_ms", 30_000), name="budgets.per_crucible_timeout_ms", lo=50, hi=30_000)
        per_crucible_rss_mb = _require_int(payload.get("per_crucible_rss_mb", 1536), name="budgets.per_crucible_rss_mb", lo=64, hi=1536)
        epoch_wall_clock_ms = _require_int(payload.get("epoch_wall_clock_ms", 300_000), name="budgets.epoch_wall_clock_ms", lo=500, hi=3_600_000)
        max_concurrency = _require_int(payload.get("max_concurrency", 1), name="budgets.max_concurrency", lo=1, hi=1)
        return EpochBudgets(
            per_crucible_timeout_ms=per_crucible_timeout_ms,
            per_crucible_rss_mb=per_crucible_rss_mb,
            epoch_wall_clock_ms=epoch_wall_clock_ms,
            max_concurrency=max_concurrency,
        )

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class StopConditions:
    max_failures: int

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "StopConditions":
        payload = _require_dict(data, name="stop_conditions")
        _reject_unknown_keys(payload, allowed={"max_failures"}, name="stop_conditions")
        max_failures = _require_int(payload.get("max_failures", 0), name="stop_conditions.max_failures", lo=0, hi=1_000)
        return StopConditions(max_failures=max_failures)

    def to_dict(self) -> Dict[str, Any]:
        return {"max_failures": self.max_failures}


@dataclass(frozen=True)
class EpochPlan:
    epoch_id: str
    kernel_identity: KernelIdentity
    crucible_order: Tuple[str, ...]
    crucible_specs: Dict[str, str]
    budgets: EpochBudgets
    runner_config: RunnerConfig
    stop_conditions: StopConditions
    seed: int

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "EpochPlan":
        payload = _require_dict(data, name="epoch_plan")
        _reject_unknown_keys(
            payload,
            allowed={
                "epoch_id",
                "kernel_identity",
                "crucible_order",
                "crucible_specs",
                "budgets",
                "runner_config",
                "stop_conditions",
                "seed",
            },
            name="epoch_plan",
        )
        epoch_id = _require_str(payload.get("epoch_id"), name="epoch_id", min_len=1, max_len=80)
        kernel_identity = KernelIdentity.from_dict(_require_dict(payload.get("kernel_identity"), name="kernel_identity"))
        crucible_order_list = _require_list(payload.get("crucible_order"), name="crucible_order")
        crucible_order: List[str] = []
        for idx, item in enumerate(crucible_order_list):
            crucible_order.append(_require_str(item, name=f"crucible_order[{idx}]", min_len=1, max_len=80))
        if len(set(crucible_order)) != len(crucible_order):
            raise EpochSchemaError("crucible_order contains duplicates (fail-closed)")

        crucible_specs_obj = _require_dict(payload.get("crucible_specs"), name="crucible_specs")
        crucible_specs: Dict[str, str] = {}
        for key, val in crucible_specs_obj.items():
            key = _require_str(key, name="crucible_specs key", min_len=1, max_len=80)
            val = _require_str(val, name=f"crucible_specs[{key}]", min_len=1, max_len=512)
            crucible_specs[key] = val

        missing = [cid for cid in crucible_order if cid not in crucible_specs]
        if missing:
            raise EpochSchemaError(f"crucible_specs missing entries for: {missing} (fail-closed)")

        budgets = EpochBudgets.from_dict(_require_dict(payload.get("budgets"), name="budgets"))
        runner_config = RunnerConfig.from_dict(_require_dict(payload.get("runner_config"), name="runner_config"))
        stop_conditions = StopConditions.from_dict(_require_dict(payload.get("stop_conditions"), name="stop_conditions"))
        seed = _require_int(payload.get("seed", 0), name="seed", lo=0, hi=2**31 - 1)

        return EpochPlan(
            epoch_id=epoch_id,
            kernel_identity=kernel_identity,
            crucible_order=tuple(crucible_order),
            crucible_specs=crucible_specs,
            budgets=budgets,
            runner_config=runner_config,
            stop_conditions=stop_conditions,
            seed=seed,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "epoch_id": self.epoch_id,
            "kernel_identity": self.kernel_identity.to_dict(),
            "crucible_order": list(self.crucible_order),
            "crucible_specs": dict(self.crucible_specs),
            "budgets": self.budgets.to_dict(),
            "runner_config": self.runner_config.to_dict(),
            "stop_conditions": self.stop_conditions.to_dict(),
            "seed": self.seed,
        }
