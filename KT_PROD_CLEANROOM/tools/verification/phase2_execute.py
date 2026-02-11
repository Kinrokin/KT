from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.verification.strict_json import load_no_dupes


class Phase2Error(RuntimeError):
    pass


def _repo_root_from(this_file: Path) -> Path:
    p = this_file.resolve()
    for parent in [p] + list(p.parents):
        if (parent / "KT_PROD_CLEANROOM").exists():
            return parent
    raise Phase2Error("Unable to locate repo root (missing KT_PROD_CLEANROOM/) (fail-closed)")


def _bootstrap_syspath(*, repo_root: Path) -> None:
    """
    Phase 2 executor must be runnable via `python -m tools.verification.phase2_execute`
    without relying on callers to pre-set PYTHONPATH.
    """
    src_root = (repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src").resolve()
    cleanroom_root = (repo_root / "KT_PROD_CLEANROOM").resolve()
    for p in (str(src_root), str(cleanroom_root)):
        if p not in sys.path:
            sys.path.insert(0, p)


def _canonical_json(obj: object) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_canonical_json(obj), encoding="utf-8", newline="\n")


def _sha256_json(obj: object) -> str:
    from tools.verification.fl3_canonical import sha256_json  # type: ignore

    return sha256_json(obj)


def _validate_schema_bound_object(payload: Any) -> None:
    from schemas.schema_registry import validate_object_with_binding  # type: ignore

    validate_object_with_binding(payload)


def _assert_out_dir_is_safe(*, repo_root: Path, out_dir: Path) -> None:
    """
    CPU Cohort A invariant: runtime outputs must not mutate tracked repo state.

    Allow either:
    - an out_dir outside repo_root, or
    - a repo-local out_dir under `KT_PROD_CLEANROOM/exports/**` (CI and preflight run outputs live here).

    Fail closed for out_dir targets under code / law / tests surfaces.
    """
    rr = repo_root.resolve()
    od = out_dir.resolve()

    # Always forbid out_dir within code/law/test trees.
    forbidden_roots = [
        rr / ".git",
        rr / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2",
        rr / "KT_PROD_CLEANROOM" / "tools",
        rr / "KT_PROD_CLEANROOM" / "tests",
        rr / "KT_PROD_CLEANROOM" / "AUDITS",
        rr / "KT_PROD_CLEANROOM" / "exports" / "law",
        rr / "KT_PROD_CLEANROOM" / "exports" / "node_registry",
    ]
    for fr in forbidden_roots:
        try:
            od.relative_to(fr.resolve())
        except Exception:
            continue
        raise Phase2Error(f"FAIL_CLOSED: --out-dir points into forbidden repo surface: {fr.as_posix()}")

    # If out_dir is inside repo_root, require it to be under KT_PROD_CLEANROOM/exports/**.
    try:
        od.relative_to(rr)
    except Exception:
        return

    exports_root = (rr / "KT_PROD_CLEANROOM" / "exports").resolve()
    try:
        od.relative_to(exports_root)
    except Exception:
        raise Phase2Error("FAIL_CLOSED: --out-dir inside repo must be under KT_PROD_CLEANROOM/exports/**")


def _install_io_guard(*, out_dir: Path) -> Any:
    from tools.verification.io_guard import IOGuard, IOGuardConfig  # type: ignore

    receipt_path = out_dir / "io_guard_receipt.json"
    cfg = IOGuardConfig(
        allowed_write_roots=(out_dir.resolve(),),
        deny_network=True,
        receipt_path=receipt_path,
    )
    return IOGuard(cfg)


def _load_work_order(*, work_order_path: Path) -> Dict[str, Any]:
    obj = load_no_dupes(work_order_path)
    if not isinstance(obj, dict):
        raise Phase2Error("Phase 2 work order must be a JSON object (fail-closed)")
    return obj


def _validate_work_order(work_order: Dict[str, Any]) -> None:
    _validate_schema_bound_object(work_order)
    if work_order.get("schema_id") != "kt.phase2_work_order.v1":
        raise Phase2Error("schema_id mismatch (fail-closed): expected kt.phase2_work_order.v1")


def _require_env_vars(*, required: Dict[str, str]) -> None:
    for k, expected in sorted(required.items()):
        actual = os.environ.get(k)
        if actual is None:
            raise Phase2Error(f"FAIL_CLOSED: required env var missing: {k}")
        if str(actual) != str(expected):
            raise Phase2Error(f"FAIL_CLOSED: required env var mismatch: {k}")


def _enforce_offline_mode(*, offline_required: bool) -> None:
    if not offline_required:
        return
    if os.environ.get("KT_LIVE") != "0":
        raise Phase2Error("FAIL_CLOSED: offline_mode_required but KT_LIVE != 0")


def _validate_required_refs(*, repo_root: Path, required_refs: Dict[str, Any]) -> None:
    # Fail-closed: these are part of the governed execution surface.
    phase1c_executor = required_refs.get("phase1c_executor")
    law_bundle_file = required_refs.get("law_bundle_file")
    if not isinstance(phase1c_executor, str) or not phase1c_executor.strip():
        raise Phase2Error("FAIL_CLOSED: inputs.required_refs.phase1c_executor missing/invalid")
    if not isinstance(law_bundle_file, str) or not law_bundle_file.strip():
        raise Phase2Error("FAIL_CLOSED: inputs.required_refs.law_bundle_file missing/invalid")

    p1 = (repo_root / phase1c_executor).resolve()
    if not p1.exists():
        raise Phase2Error(f"FAIL_CLOSED: phase1c_executor missing: {phase1c_executor}")
    p2 = (repo_root / law_bundle_file).resolve()
    if not p2.exists():
        raise Phase2Error(f"FAIL_CLOSED: law_bundle_file missing: {law_bundle_file}")


def _build_dry_run_plan(*, work_order: Dict[str, Any]) -> Dict[str, Any]:
    inputs = work_order.get("inputs", {})
    runtime_env = {}
    if isinstance(inputs, dict):
        runtime_env = inputs.get("runtime_environment", {}) if isinstance(inputs.get("runtime_environment", {}), dict) else {}

    deliverables = work_order.get("deliverables", {})
    required_runtime_outputs: List[str] = []
    if isinstance(deliverables, dict):
        rro = deliverables.get("required_runtime_outputs", [])
        if isinstance(rro, list):
            required_runtime_outputs = [str(x) for x in rro if isinstance(x, str)]

    wp_summaries: List[Dict[str, Any]] = []
    wps = work_order.get("work_packages", [])
    if isinstance(wps, list):
        for wp in wps:
            if not isinstance(wp, dict):
                continue
            wp_id = wp.get("wp_id")
            intent = wp.get("intent")
            actions = wp.get("actions")
            if not isinstance(wp_id, str) or not isinstance(intent, str) or not isinstance(actions, list):
                continue
            acts: List[Dict[str, str]] = []
            for a in actions:
                if not isinstance(a, dict):
                    continue
                aid = a.get("action_id")
                aname = a.get("action")
                if isinstance(aid, str) and isinstance(aname, str):
                    acts.append({"action_id": aid, "action": aname})
            wp_summaries.append(
                {
                    "wp_id": wp_id,
                    "intent": intent,
                    "actions": acts,
                    # CPU Cohort A: planning only. No training/promotion/seal execution allowed here.
                    "execution": {"mode": "DRY_RUN_ONLY", "will_execute": False},
                }
            )

    plan: Dict[str, Any] = {
        "kind": "phase2_dry_run_plan",
        "work_order_binding": {
            "schema_id": str(work_order.get("schema_id", "")),
            "schema_version_hash": str(work_order.get("schema_version_hash", "")),
            "work_order_id": str(work_order.get("work_order_id", "")),
        },
        "offline_mode_required": bool(runtime_env.get("offline_mode_required", False)),
        "required_runtime_outputs": sorted(required_runtime_outputs),
        "work_packages": wp_summaries,
        # Explicitly state what this plan does NOT do in CPU Cohort A.
        "cpu_cohort_a_forbidden_actions": [
            "training_execution",
            "promotion_execution",
            "seal_execution",
            "canonical_index_mutation",
        ],
        "gpu_handoff_contract": {
            "not_on_cpu": True,
            "notes": "CPU Cohort A only validates and plans; no training/promotion/seal is executed.",
        },
    }
    plan["plan_id"] = _sha256_json({k: v for k, v in plan.items() if k != "plan_id"})
    return plan


def _build_dry_run_receipts(*, plan: Dict[str, Any], validations: Dict[str, Any]) -> Dict[str, Any]:
    obj: Dict[str, Any] = {
        "kind": "phase2_dry_run_receipts",
        "plan_id": str(plan.get("plan_id", "")),
        "plan_sha256": _sha256_json(plan),
        "validations": validations,
    }
    obj["receipts_id"] = _sha256_json({k: v for k, v in obj.items() if k != "receipts_id"})
    return obj


def run_dry_run(*, repo_root: Path, work_order_path: Path, out_dir: Path) -> int:
    _assert_out_dir_is_safe(repo_root=repo_root, out_dir=out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    work_order = _load_work_order(work_order_path=work_order_path)
    _validate_work_order(work_order)

    inputs = work_order.get("inputs", {})
    if not isinstance(inputs, dict):
        raise Phase2Error("FAIL_CLOSED: work order inputs missing/invalid")
    required_refs = inputs.get("required_refs", {})
    if not isinstance(required_refs, dict):
        raise Phase2Error("FAIL_CLOSED: inputs.required_refs missing/invalid")
    runtime_env = inputs.get("runtime_environment", {})
    if not isinstance(runtime_env, dict):
        raise Phase2Error("FAIL_CLOSED: inputs.runtime_environment missing/invalid")

    env_required = runtime_env.get("environment_vars_required", {})
    if not isinstance(env_required, dict) or not env_required:
        raise Phase2Error("FAIL_CLOSED: inputs.runtime_environment.environment_vars_required missing/invalid")

    _enforce_offline_mode(offline_required=bool(runtime_env.get("offline_mode_required", False)))
    _require_env_vars(required={str(k): str(v) for k, v in env_required.items()})
    _validate_required_refs(repo_root=repo_root, required_refs=required_refs)

    # Enforce offline + write sandboxing for the duration of dry-run output emission.
    with _install_io_guard(out_dir=out_dir):
        plan = _build_dry_run_plan(work_order=work_order)
        validations = {
            "work_order_validated": True,
            "offline_mode_enforced": bool(runtime_env.get("offline_mode_required", False)),
            "required_refs_validated": True,
            "env_vars_required": sorted(env_required.keys()),
        }
        receipts = _build_dry_run_receipts(plan=plan, validations=validations)

        _write_json(out_dir / "phase2_dry_run_plan.json", plan)
        _write_json(out_dir / "phase2_dry_run_receipts.json", receipts)

    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Phase 2 executor (CPU Cohort A: control-plane dry-run only; fail-closed).")
    ap.add_argument("--work-order", required=True, help="Path to kt.phase2_work_order.v1.json")
    ap.add_argument("--out-dir", required=True, help="Output directory (must be outside repo_root)")
    ap.add_argument("--mode", choices=["dry-run", "execute"], default="dry-run", help="CPU Cohort A only supports dry-run.")
    args = ap.parse_args(list(argv) if argv is not None else None)

    repo_root = _repo_root_from(Path(__file__))
    _bootstrap_syspath(repo_root=repo_root)

    work_order_path = Path(args.work_order)
    out_dir = Path(args.out_dir)

    if args.mode != "dry-run":
        raise Phase2Error("FAIL_CLOSED: Phase 2 execute mode is disabled in CPU Cohort A (no training/promotion/seal)")

    return run_dry_run(repo_root=repo_root, work_order_path=work_order_path, out_dir=out_dir)


if __name__ == "__main__":
    raise SystemExit(main())
