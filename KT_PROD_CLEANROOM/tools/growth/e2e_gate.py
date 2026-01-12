from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


SCHEMA_ID = "kt.e2e_gate"
SCHEMA_VERSION = "1.0"

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from KT_PROD_CLEANROOM.tools.growth.orchestrator.epoch_orchestrator import (
    preflight_epoch,
    run_epoch_from_plan,
)

@dataclass(frozen=True)
class StepResult:
    step_id: str
    status: str  # PASS | FAIL
    details: Dict[str, Any]


def _repo_root() -> Path:
    # .../KT_PROD_CLEANROOM/tools/growth/e2e_gate.py -> repo root
    return _REPO_ROOT


def _cleanroom_root() -> Path:
    # .../KT_PROD_CLEANROOM/tools/growth/e2e_gate.py -> KT_PROD_CLEANROOM
    return Path(__file__).resolve().parents[2]


def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(_repo_root().resolve()).as_posix()
    except Exception:
        return path.as_posix()


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _epoch_artifacts_root() -> Path:
    return _cleanroom_root() / "tools" / "growth" / "artifacts" / "epochs"


def _salvage_root() -> Path:
    return _cleanroom_root() / "tools" / "growth" / "artifacts" / "salvage"


def _snapshot_epoch_dirs() -> List[Path]:
    root = _epoch_artifacts_root()
    if not root.exists():
        return []
    return sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name)


def _diff_new_dirs(before: Sequence[Path], after: Sequence[Path]) -> List[Path]:
    before_set = {p.resolve() for p in before}
    return [p for p in after if p.resolve() not in before_set]


def _run(
    *,
    args: List[str],
    cwd: Path,
    env_overrides: Dict[str, str],
    timeout_s: int,
    verbose: bool,
) -> Tuple[int, str, str]:
    env = dict(os.environ)
    env.update(env_overrides)

    proc = subprocess.run(
        args,
        cwd=str(cwd),
        env=env,
        text=True,
        capture_output=not verbose,
        timeout=timeout_s,
    )

    if verbose:
        # In verbose mode, subprocess output streams directly to this process.
        return proc.returncode, "", ""

    return proc.returncode, proc.stdout, proc.stderr


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="KT E2E acceptance gate (tooling-only; deterministic; fail-closed).")
    p.add_argument(
        "--milestone-plan",
        default="KT_PROD_CLEANROOM/tools/growth/orchestrator/examples/EPOCH_PASS_PAIR_SEED.json",
        help="Path to milestone epoch plan (default: EPOCH_PASS_PAIR_SEED.json).",
    )
    p.add_argument(
        "--pressure-plan",
        default="KT_PROD_CLEANROOM/tools/growth/orchestrator/examples/EPOCH_NEXT_AUTO.json",
        help="Path to pressure epoch plan (default: EPOCH_NEXT_AUTO.json).",
    )
    p.add_argument(
        "--pressure-runs",
        type=int,
        default=5,
        help="Number of pressure epochs to run (default: 5).",
    )
    p.add_argument(
        "--out",
        default="",
        help="Write JSON report to path (optional).",
    )
    p.add_argument(
        "--timeout-s",
        type=int,
        default=1200,
        help="Per subprocess timeout in seconds (default: 1200).",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Stream subprocess stdout/stderr (not recommended; can be noisy).",
    )
    return p.parse_args(argv)


def _require_single_new_epoch(before: Sequence[Path]) -> Tuple[Path, Dict[str, Any]]:
    after = _snapshot_epoch_dirs()
    new_dirs = _diff_new_dirs(before, after)
    if len(new_dirs) != 1:
        raise RuntimeError(f"Expected exactly 1 new epoch dir, found {len(new_dirs)}: {[p.name for p in new_dirs]}")
    epoch_dir = new_dirs[0]
    summary_path = epoch_dir / "epoch_summary.json"
    if not summary_path.exists():
        raise RuntimeError(f"Missing epoch_summary.json: {_rel(summary_path)}")
    return epoch_dir, _read_json(summary_path)


def _epoch_verdict(summary: Dict[str, Any]) -> Dict[str, Any]:
    runs = summary.get("runs") or []
    passed = sum(1 for r in runs if (r.get("outcome") == "PASS"))
    total = len(runs)
    failed_closed = sum(1 for r in runs if (r.get("outcome") == "FAIL_CLOSED"))
    failed = sum(1 for r in runs if (r.get("outcome") == "FAIL"))
    return {
        "crucibles_total": total,
        "crucibles_passed": passed,
        "crucibles_failed_closed": failed_closed,
        "crucibles_failed": failed,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    start = time.time()
    repo_root = _repo_root()
    cleanroom_root = _cleanroom_root()

    provider_audit = cleanroom_root / "tools" / "growth" / "providers" / "provider_audit.py"

    steps: List[StepResult] = []

    env_overrides = {
        # Ensure we don't accidentally trip LIVE guard during an E2E gate.
        # (This gate is for DRY_RUN / sealed growth lane only.)
        "KT_LIVE": "0",
        "KT_LIVE_PROOF": "",
        "KT_EXECUTION_LANE": os.environ.get("KT_EXECUTION_LANE", ""),
    }

    # Step 1: Provider audit (hard gate)
    rc, out, err = _run(
        args=[str(Path(sys.executable).resolve()), str(provider_audit)],
        cwd=repo_root,
        env_overrides=env_overrides,
        timeout_s=args.timeout_s,
        verbose=args.verbose,
    )
    provider_report: Dict[str, Any] = {}
    if rc == 0:
        if not args.verbose:
            provider_report = json.loads(out) if out.strip() else {}
        steps.append(StepResult("provider_audit", "PASS", {"report": provider_report}))
    else:
        steps.append(
            StepResult(
                "provider_audit",
                "FAIL",
                {"exit_code": rc, "stdout": out[:2000], "stderr": err[:2000]},
            )
        )
        _emit_report(args, repo_root, cleanroom_root, steps, start)
        return 2

    milestone_plan = Path(args.milestone_plan)
    pressure_plan = Path(args.pressure_plan)
    os.environ.update(env_overrides)

    # Step 2: Milestone preflight (hard gate)
    rc = preflight_epoch(milestone_plan, resume=False, artifacts_root=None, auto_bump=True)
    if rc != 0:
        steps.append(
            StepResult(
                "milestone_preflight",
                "FAIL",
                {"exit_code": rc},
            )
        )
        _emit_report(args, repo_root, cleanroom_root, steps, start)
        return 2
    steps.append(StepResult("milestone_preflight", "PASS", {}))

    # Step 3: Milestone run (hard gate)
    before = _snapshot_epoch_dirs()
    try:
        run_epoch_from_plan(plan_path=milestone_plan, resume=False, mode="salvage")
    except Exception as exc:
        steps.append(
            StepResult(
                "milestone_run",
                "FAIL",
                {"error": str(exc)},
            )
        )
        _emit_report(args, repo_root, cleanroom_root, steps, start)
        return 2

    milestone_epoch_dir, milestone_summary = _require_single_new_epoch(before)
    milestone_counts = _epoch_verdict(milestone_summary)
    milestone_ok = milestone_counts["crucibles_passed"] == milestone_counts["crucibles_total"] and milestone_counts["crucibles_total"] > 0
    steps.append(
        StepResult(
            "milestone_run",
            "PASS" if milestone_ok else "FAIL",
            {
                "epoch_dir": _rel(milestone_epoch_dir),
                "epoch_id": milestone_summary.get("epoch_id"),
                "epoch_hash": milestone_summary.get("epoch_hash"),
                "kernel_identity": milestone_summary.get("kernel_identity"),
                **milestone_counts,
            },
        )
    )
    if not milestone_ok:
        _emit_report(args, repo_root, cleanroom_root, steps, start)
        return 2

    # Step 4: Pressure runs (observational; must remain OPERATIONAL under COVERAGE_SEED)
    pressure_results: List[Dict[str, Any]] = []
    for i in range(args.pressure_runs):
        before = _snapshot_epoch_dirs()
        try:
            run_epoch_from_plan(plan_path=pressure_plan, resume=False, mode="salvage")
        except Exception as exc:
            steps.append(
                StepResult(
                    "pressure_run",
                    "FAIL",
                    {"index": i + 1, "error": str(exc)},
                )
            )
            _emit_report(args, repo_root, cleanroom_root, steps, start)
            return 2

        epoch_dir, summary = _require_single_new_epoch(before)
        counts = _epoch_verdict(summary)
        operational = counts["crucibles_passed"] >= 1 and counts["crucibles_total"] > 0
        pressure_results.append(
            {
                "index": i + 1,
                "epoch_dir": _rel(epoch_dir),
                "epoch_id": summary.get("epoch_id"),
                "epoch_hash": summary.get("epoch_hash"),
                **counts,
                "operational": operational,
            }
        )
        if not operational:
            steps.append(StepResult("pressure_runs", "FAIL", {"failed_index": i + 1, "run": pressure_results[-1]}))
            _emit_report(args, repo_root, cleanroom_root, steps, start)
            return 2

    steps.append(StepResult("pressure_runs", "PASS", {"runs": pressure_results}))

    _emit_report(args, repo_root, cleanroom_root, steps, start)
    return 0


def _emit_report(args: argparse.Namespace, repo_root: Path, cleanroom_root: Path, steps: List[StepResult], start_ts: float) -> None:
    report = {
        "schema": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "status": "PASS" if all(s.status == "PASS" for s in steps) else "FAIL",
        "repo_root": _rel(repo_root),
        "cleanroom_root": _rel(cleanroom_root),
        "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_ts)),
        "ended_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time())),
        "steps": [{"step_id": s.step_id, "status": s.status, "details": s.details} for s in steps],
    }
    text = json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8", newline="\n")
    else:
        print(text)


if __name__ == "__main__":
    raise SystemExit(main())
