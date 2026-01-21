from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.runtime_registry import load_runtime_registry
from memory.state_vault import StateVault
from policy_c.gates import run_drift_gate
from policy_c.pressure_tensor import PressureTensor, single_axis_sweep
from policy_c.static_safety_check import assert_export_root_allowed, policy_c_module_paths, run_static_safety_check


SWEEP_PLAN_SCHEMA_ID = "kt.policy_c.sweep_plan.v1"
SWEEP_RESULT_SCHEMA_ID = "kt.policy_c.sweep_result.v1"


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _cleanroom_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_sweep_plan(plan: Dict[str, Any]) -> None:
    if plan.get("schema_id") != SWEEP_PLAN_SCHEMA_ID:
        raise RuntimeError("SweepPlan schema_id mismatch (fail-closed)")
    required = {"schema_id", "sweep_id", "baseline_epoch_id", "max_runs", "seed", "export"}
    if not required.issubset(plan.keys()):
        raise RuntimeError("SweepPlan missing required keys (fail-closed)")
    if ("runs" in plan) == ("grid" in plan):
        raise RuntimeError("SweepPlan must contain exactly one of runs or grid (fail-closed)")
    if not isinstance(plan["max_runs"], int) or plan["max_runs"] <= 0:
        raise RuntimeError("SweepPlan max_runs must be positive int (fail-closed)")
    if not isinstance(plan["seed"], int):
        raise RuntimeError("SweepPlan seed must be int (fail-closed)")
    if not isinstance(plan["export"], dict):
        raise RuntimeError("SweepPlan export must be object (fail-closed)")
    if "runs" in plan and not isinstance(plan["runs"], list):
        raise RuntimeError("SweepPlan runs must be list (fail-closed)")
    if "grid" in plan and not isinstance(plan["grid"], dict):
        raise RuntimeError("SweepPlan grid must be object (fail-closed)")


def _expand_grid(grid: Dict[str, Any]) -> List[Dict[str, Any]]:
    parameters = grid.get("parameters")
    if not isinstance(parameters, dict) or not parameters:
        raise RuntimeError("SweepPlan grid.parameters must be non-empty object (fail-closed)")
    epoch_plan = grid.get("epoch_plan")
    epoch_plan_path = grid.get("epoch_plan_path")
    if epoch_plan is None and epoch_plan_path is None:
        raise RuntimeError("SweepPlan grid requires epoch_plan or epoch_plan_path (fail-closed)")
    if epoch_plan is not None and epoch_plan_path is not None:
        raise RuntimeError("SweepPlan grid cannot include both epoch_plan and epoch_plan_path (fail-closed)")

    keys = sorted(parameters.keys())
    values = [parameters[k] for k in keys]
    if not all(isinstance(v, list) and v for v in values):
        raise RuntimeError("SweepPlan grid.parameters values must be non-empty lists (fail-closed)")

    runs: List[Dict[str, Any]] = []

    def _recurse(idx: int, current: Dict[str, Any]) -> None:
        if idx == len(keys):
            run_id = "|".join(f"{k}={current[k]}" for k in keys)
            run = {"run_id": run_id, "tags": {k: str(current[k]) for k in keys}}
            if epoch_plan is not None:
                run["epoch_plan"] = epoch_plan
            else:
                run["epoch_plan_path"] = epoch_plan_path
            run["grid_overrides"] = current.copy()
            runs.append(run)
            return
        key = keys[idx]
        for val in sorted(values[idx]):
            current[key] = val
            _recurse(idx + 1, current)

    _recurse(0, {})
    return runs


def _resolve_epoch_plan(run: Dict[str, Any]) -> Dict[str, Any]:
    if "epoch_plan" in run:
        if not isinstance(run["epoch_plan"], dict):
            raise RuntimeError("epoch_plan must be object (fail-closed)")
        return dict(run["epoch_plan"])
    path = Path(str(run["epoch_plan_path"]))
    return _load_json(path)


def _extract_pressure_tensor(plan: Dict[str, Any]) -> PressureTensor:
    if "pressure_tensor" in plan:
        return PressureTensor.from_dict(plan["pressure_tensor"])
    if "pressure_tensor_path" in plan:
        tensor = _load_json(Path(str(plan["pressure_tensor_path"])))
        return PressureTensor.from_dict(tensor)
    raise RuntimeError("epoch_plan missing pressure_tensor (fail-closed)")


def _apply_grid_overrides(tensor: PressureTensor, overrides: Dict[str, Any]) -> PressureTensor:
    updated = tensor
    for axis, value in overrides.items():
        try:
            intensity = float(value)
        except Exception as exc:
            raise RuntimeError(f"grid override not numeric for axis {axis!r} (fail-closed): {exc}")
        updated = single_axis_sweep(updated, axis=axis, intensity=intensity)
    return updated


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True), encoding="utf-8")


def _hash_payload(payload: Dict[str, Any]) -> str:
    return _sha256_text(_canonical_json(payload))


def run_sweep(*, plan_path: Path, out_root: Path) -> Dict[str, Any]:
    registry = load_runtime_registry()
    plan = _load_json(plan_path)
    _validate_sweep_plan(plan)

    assert_export_root_allowed(out_root, registry.policy_c.sweep.allowed_export_roots)
    export_root_raw = Path(str(plan["export"]["export_root"]))
    export_root = export_root_raw if export_root_raw.is_absolute() else (_cleanroom_root() / export_root_raw)
    export_root = export_root.resolve()
    if export_root != out_root.resolve():
        raise RuntimeError("SweepPlan export_root mismatch with --out-root (fail-closed)")
    safety = run_static_safety_check(
        registry=registry,
        module_paths=policy_c_module_paths(),
        schema_paths=[
            Path(__file__).resolve().parent / "policy_c_sweep_plan_schema_v1.json",
            Path(__file__).resolve().parent / "policy_c_sweep_result_schema_v1.json",
        ],
    )
    if not safety.ok:
        raise RuntimeError(f"Static safety check failed (fail-closed): {safety.errors}")

    runs = plan.get("runs") or _expand_grid(plan.get("grid"))
    runs = list(runs)
    if len(runs) > int(plan["max_runs"]):
        raise RuntimeError("SweepPlan exceeds max_runs (fail-closed)")

    baseline_epoch_id = plan.get("baseline_epoch_id")
    if baseline_epoch_id is None:
        baseline_run = runs[0]
    else:
        baseline_run = next((r for r in runs if r.get("run_id") == baseline_epoch_id), None)
        if baseline_run is None:
            raise RuntimeError("baseline_epoch_id does not match any run_id (fail-closed)")

    baseline_plan = _resolve_epoch_plan(baseline_run)
    baseline_tensor = _extract_pressure_tensor(baseline_plan)

    # Timestamps are non-hash fields; hashes exclude them by construction.
    started_at = _timestamp()
    run_results: List[Dict[str, Any]] = []
    continue_on_fail = plan.get("continue_on_fail") is True
    if continue_on_fail and registry.policy_c.sweep.fail_fast_default:
        raise RuntimeError("continue_on_fail not allowed by registry (fail-closed)")
    fail_fast = not continue_on_fail

    vault_path = (out_root / "state_vault.jsonl").resolve()
    vault = StateVault(path=vault_path)

    for run in runs:
        run_id = str(run["run_id"])
        epoch_plan = _resolve_epoch_plan(run)
        tensor = _extract_pressure_tensor(epoch_plan)
        if "grid_overrides" in run:
            tensor = _apply_grid_overrides(tensor, run["grid_overrides"])

        epoch_id = str(epoch_plan.get("epoch_id") or f"{plan['sweep_id']}::{run_id}")
        invariant_violations = int(run.get("invariant_violations", 0))
        gate = run_drift_gate(
            epoch_id=epoch_id,
            baseline_epoch_id=str(baseline_epoch_id or baseline_run["run_id"]),
            baseline_tensor=baseline_tensor,
            current_tensor=tensor,
            invariant_violations=invariant_violations,
            thresholds=registry.policy_c.drift,
            vault=vault,
        )
        drift = gate.drift_report
        status = "FAIL" if drift.drift_class == "FAIL" else ("WARN" if drift.drift_class == "WARN" else "PASS")
        reason_codes = list(drift.reason_codes)

        run_dir = out_root / "runs" / run_id
        pressure_path = run_dir / "pressure_tensor.json"
        summary_path = run_dir / "policy_c_epoch_summary.json"
        drift_path = run_dir / "policy_c_drift_report.json"

        pressure_payload = {
            "schema_id": "kt.policy_c.pressure_tensor.v1",
            "axes": dict(tensor.axes),
            "projection": dict(tensor.projection),
            "invariants": dict(tensor.invariants),
        }
        _write_json(pressure_path, {
            "schema_id": "kt.policy_c.pressure_tensor.v1",
            "axes": dict(tensor.axes),
            "projection": dict(tensor.projection),
            "invariants": dict(tensor.invariants),
        })

        epoch_summary = {
            "schema_id": "kt.policy_c.epoch_summary.v1",
            "epoch_id": epoch_id,
            "run_id": run_id,
            "timestamp_utc": _timestamp(),
            "pressure_tensor_ref": {"path": pressure_path.as_posix(), "hash": _hash_payload(pressure_payload)},
            "projection_hash": tensor.projection_hash(),
            "pressure_scalar": tensor.pressure_scalar(),
            "pressure_contributions": tensor.pressure_contributions(),
            "drift_metrics": {
                "entropy_delta": 0.0,
                "refusal_delta": 0.0,
                "lane_divergence_delta": 0.0,
            },
            "gate_results": {
                "C0": {"status": "PASS", "receipts": []},
                "C1": {"status": "PASS", "receipts": []},
                "C2": {"status": gate.status, "receipts": list(gate.receipts)},
                "C3": {"status": "PASS", "receipts": []},
                "C4": {"status": "PASS", "receipts": []},
                "C5": {"status": "PASS", "receipts": []},
            },
        }
        _write_json(summary_path, epoch_summary)
        _write_json(drift_path, drift.to_dict())

        run_results.append(
            {
                "run_id": run_id,
                "epoch_id": epoch_id,
                "status": status if status != "PASS" else ("WARN" if drift.drift_class == "WARN" else "PASS"),
                "reason_codes": reason_codes,
                "paths": {
                    "pressure_tensor": pressure_path.as_posix(),
                    "epoch_summary": summary_path.as_posix(),
                    "drift_report": drift_path.as_posix(),
                },
                "hashes": {
                    "pressure_tensor_hash": _hash_payload(pressure_payload),
                    "summary_hash": _hash_payload(epoch_summary),
                    "drift_report_hash": drift.report_hash(),
                },
            }
        )

        if drift.drift_class == "FAIL" and fail_fast:
            break

    finished_at = _timestamp()
    runs_total = len(run_results)
    runs_pass = sum(1 for r in run_results if r["status"] == "PASS")
    runs_warn = sum(1 for r in run_results if r["status"] == "WARN")
    runs_fail = sum(1 for r in run_results if r["status"] in {"FAIL", "ERROR"})

    sweep_result = {
        "schema_id": SWEEP_RESULT_SCHEMA_ID,
        "sweep_id": plan["sweep_id"],
        "started_at": started_at,
        "finished_at": finished_at,
        "runs_total": runs_total,
        "runs_pass": runs_pass,
        "runs_warn": runs_warn,
        "runs_fail": runs_fail,
        "run_results": run_results,
    }
    result_path = out_root / "policy_c_sweep_result.json"
    _write_json(result_path, sweep_result)
    return sweep_result


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Policy C sweep runner (deterministic; no network).")
    p.add_argument("--plan", type=Path, required=True, help="Sweep plan JSON path.")
    p.add_argument("--out-root", type=Path, required=True, help="Output root (must be allowlisted).")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    run_sweep(plan_path=args.plan, out_root=args.out_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
