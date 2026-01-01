from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import yaml

from checkpoint_store import CheckpointRecord, append_checkpoint, completed_crucible_ids
from epoch_budget import assert_budget_ok, validate_crucible_budgets
from epoch_manifest import build_manifest
from epoch_schemas import EpochPlan, EpochSchemaError, RUNNER_TEMPLATE_C019


@dataclass(frozen=True)
class RunnerResult:
    exit_code: Optional[int]
    was_killed: bool
    kill_reason: Optional[str]
    duration_ms: int
    peak_rss_bytes: Optional[int]
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool


@dataclass(frozen=True)
class CrucibleRunSummary:
    crucible_id: str
    crucible_path: str
    run_id: Optional[str]
    outcome: str
    notes: Optional[str]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _load_plan(path: Path) -> EpochPlan:
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        payload = yaml.safe_load(raw)
    elif path.suffix.lower() == ".json":
        payload = json.loads(raw)
    else:
        raise EpochSchemaError("epoch plan must be .json or .yaml (fail-closed)")
    return EpochPlan.from_dict(payload)


def _read_crucible(path: Path) -> Dict[str, object]:
    from crucible_loader import load_crucible

    loaded = load_crucible(path)
    return {
        "spec": loaded.spec,
        "hash": loaded.crucible_spec_hash,
        "budgets": loaded.spec.budgets,
    }


def _runner_command(*, crucible_path: Path, kernel_target: str, seed: int) -> Tuple[List[str], Path]:
    repo_root = _repo_root()
    runner = repo_root / "tools" / "growth" / "crucible_runner.py"
    cmd = [
        str(Path(sys.executable).resolve()),
        str(runner),
        "--crucible",
        str(crucible_path.resolve()),
        "--kernel",
        kernel_target,
        "--seed",
        str(seed),
    ]
    return cmd, repo_root


def _run_subprocess_capped(
    *,
    command: List[str],
    cwd: Path,
    env: Dict[str, str],
    time_ms: int,
    kill_grace_ms: int,
    stdout_max_bytes: int,
    stderr_max_bytes: int,
    memory_max_mb: int,
) -> RunnerResult:
    start = time.monotonic()
    proc = subprocess.Popen(
        command,
        cwd=str(cwd),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )

    stdout_buf = bytearray()
    stderr_buf = bytearray()
    stdout_truncated = threading.Event()
    stderr_truncated = threading.Event()
    kill_event = threading.Event()

    def _reader(handle, *, max_bytes: int, sink: bytearray, truncated: threading.Event) -> None:
        try:
            while True:
                chunk = handle.read(8192)
                if not chunk:
                    return
                if len(sink) + len(chunk) > max_bytes:
                    remaining = max_bytes - len(sink)
                    if remaining > 0:
                        sink.extend(chunk[:remaining])
                    truncated.set()
                    kill_event.set()
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    return
                sink.extend(chunk)
        except Exception:
            return

    t_out = threading.Thread(
        target=_reader,
        args=(proc.stdout,),
        kwargs={"max_bytes": stdout_max_bytes, "sink": stdout_buf, "truncated": stdout_truncated},
        daemon=True,
    )
    t_err = threading.Thread(
        target=_reader,
        args=(proc.stderr,),
        kwargs={"max_bytes": stderr_max_bytes, "sink": stderr_buf, "truncated": stderr_truncated},
        daemon=True,
    )

    ps_proc = None
    try:
        import psutil

        ps_proc = psutil.Process(proc.pid)
    except Exception:
        ps_proc = None

    peak_rss: Optional[int] = None
    was_killed = False
    kill_reason: Optional[str] = None

    timeout_s = time_ms / 1000.0
    grace_s = max(0.0, (kill_grace_ms - time_ms) / 1000.0)

    try:
        t_out.start()
        t_err.start()

        while True:
            rc = proc.poll()
            if rc is not None:
                break

            elapsed = time.monotonic() - start
            if elapsed >= timeout_s:
                was_killed = True
                kill_reason = "TIMEOUT"
                try:
                    proc.terminate()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=grace_s)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                break

            if kill_event.is_set():
                was_killed = True
                kill_reason = "OUTPUT_LIMIT"
                break

            if ps_proc is not None:
                try:
                    rss = ps_proc.memory_info().rss
                    peak_rss = rss if peak_rss is None else max(peak_rss, rss)
                    if rss > (memory_max_mb * 1024 * 1024):
                        was_killed = True
                        kill_reason = "MEMORY_LIMIT"
                        try:
                            proc.kill()
                        except Exception:
                            pass
                        break
                except Exception:
                    pass

            time.sleep(0.02)
    finally:
        end = time.monotonic()
        duration_ms = int((end - start) * 1000)
        try:
            proc.wait(timeout=1)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

        t_out.join(timeout=1)
        t_err.join(timeout=1)
        for handle in (proc.stdout, proc.stderr):
            try:
                if handle is not None:
                    handle.close()
            except Exception:
                pass

    return RunnerResult(
        exit_code=proc.poll(),
        was_killed=was_killed,
        kill_reason=kill_reason,
        duration_ms=duration_ms,
        peak_rss_bytes=peak_rss,
        stdout=bytes(stdout_buf),
        stderr=bytes(stderr_buf),
        stdout_truncated=stdout_truncated.is_set(),
        stderr_truncated=stderr_truncated.is_set(),
    )


def _write_once(path: Path, text: str) -> None:
    if path.exists():
        raise EpochSchemaError(f"Refusing to overwrite existing file: {path.as_posix()} (fail-closed)")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _safe_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def run_epoch(
    plan_path: Path,
    *,
    resume: bool = True,
    artifacts_root: Optional[Path] = None,
    runner_cmd_override: Optional[Callable[[Path, str, int], Tuple[List[str], Path]]] = None,
) -> Dict[str, object]:
    plan = _load_plan(plan_path)
    if plan.runner_config.template_id != RUNNER_TEMPLATE_C019:
        raise EpochSchemaError("runner_config.template_id not allowed (fail-closed)")
    if plan.runner_config.args:
        raise EpochSchemaError("runner_config.args must be empty for C019_RUNNER_V1 (fail-closed)")

    repo_root = _repo_root()
    crucibles_root = repo_root / "tools" / "growth" / "crucibles"
    sys_path_root = crucibles_root
    sys.path.insert(0, str(sys_path_root))

    crucible_specs: Dict[str, Dict[str, object]] = {}
    for cid in plan.crucible_order:
        rel = Path(plan.crucible_specs[cid])
        crucible_path = (repo_root / rel).resolve() if not rel.is_absolute() else rel
        if not crucible_path.exists():
            raise EpochSchemaError(f"Crucible spec missing: {crucible_path.as_posix()} (fail-closed)")
        crucible_specs[cid] = _read_crucible(crucible_path)

    # Budget validation against plan caps
    for cid, data in crucible_specs.items():
        budgets = data["budgets"]
        result = validate_crucible_budgets(
            epoch_budgets=plan.budgets,
            crucible_time_ms=budgets.time_ms,
            crucible_rss_mb=budgets.runner_memory_max_mb,
        )
        assert_budget_ok(result)

    # Build manifest and epoch hash
    spec_hashes = {cid: crucible_specs[cid]["hash"] for cid in plan.crucible_order}
    manifest = build_manifest(plan, crucible_spec_hashes=spec_hashes)

    base_root = artifacts_root if artifacts_root is not None else (repo_root / "tools" / "growth" / "artifacts" / "epochs")
    epoch_root = base_root / plan.epoch_id
    epoch_root.mkdir(parents=True, exist_ok=True)
    manifest_path = epoch_root / "epoch_manifest.json"
    if not manifest_path.exists():
        _write_once(manifest_path, json.dumps(manifest.to_dict(), sort_keys=True, indent=2, ensure_ascii=True))
    else:
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        if existing.get("epoch_hash") != manifest.epoch_hash:
            raise EpochSchemaError("Existing epoch_manifest hash mismatch (fail-closed)")

    checkpoint_path = epoch_root / "checkpoint.json"
    completed = completed_crucible_ids(checkpoint_path) if resume else set()

    start_epoch = time.monotonic()
    failures = 0
    runs: List[CrucibleRunSummary] = []

    for cid in plan.crucible_order:
        crucible_path = Path(plan.crucible_specs[cid])
        crucible_path = (repo_root / crucible_path).resolve() if not crucible_path.is_absolute() else crucible_path

        run_dir = epoch_root / cid
        run_record_path = run_dir / "run_record.json"
        stdout_path = run_dir / "stdout.json"
        stderr_path = run_dir / "stderr.log"

        if cid in completed:
            if not run_record_path.exists():
                raise EpochSchemaError(f"Checkpoint indicates done but run record missing for {cid} (fail-closed)")
            # Skip already-completed crucible.
            runs.append(
                CrucibleRunSummary(
                    crucible_id=cid,
                    crucible_path=str(crucible_path),
                    run_id=None,
                    outcome="SKIPPED_RESUME",
                    notes="resume_skip",
                )
            )
            continue

        elapsed_ms = int((time.monotonic() - start_epoch) * 1000)
        if elapsed_ms > plan.budgets.epoch_wall_clock_ms:
            _write_once(
                run_record_path,
                json.dumps(
                    {
                        "crucible_id": cid,
                        "crucible_path": str(crucible_path),
                        "outcome": "FAIL_CLOSED",
                        "notes": "epoch_timeout",
                    },
                    sort_keys=True,
                    indent=2,
                    ensure_ascii=True,
                ),
            )
            append_checkpoint(checkpoint_path, CheckpointRecord(crucible_id=cid, run_id="N/A", outcome="FAIL_CLOSED", status="DONE"))
            runs.append(
                CrucibleRunSummary(
                    crucible_id=cid,
                    crucible_path=str(crucible_path),
                    run_id=None,
                    outcome="FAIL_CLOSED",
                    notes="epoch_timeout",
                )
            )
            failures += 1
            break

        if runner_cmd_override is not None:
            cmd, cwd = runner_cmd_override(crucible_path, plan.kernel_identity.kernel_target, plan.seed)
        else:
            cmd, cwd = _runner_command(crucible_path=crucible_path, kernel_target=plan.kernel_identity.kernel_target, seed=plan.seed)
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        budgets = crucible_specs[cid]["budgets"]
        time_cap_ms = min(plan.budgets.per_crucible_timeout_ms, budgets.time_ms)
        mem_cap_mb = min(plan.budgets.per_crucible_rss_mb, budgets.runner_memory_max_mb)

        result = _run_subprocess_capped(
            command=cmd,
            cwd=cwd,
            env=env,
            time_ms=time_cap_ms,
            kill_grace_ms=min(time_cap_ms + 500, budgets.kernel_timeout_kill_ms),
            stdout_max_bytes=budgets.stdout_max_bytes,
            stderr_max_bytes=budgets.stderr_max_bytes,
            memory_max_mb=mem_cap_mb,
        )

        run_dir.mkdir(parents=True, exist_ok=True)
        stdout_text = _safe_decode(result.stdout)
        stderr_text = _safe_decode(result.stderr)
        _write_once(stdout_path, stdout_text)
        _write_once(stderr_path, stderr_text)

        outcome = "PASS"
        notes: Optional[str] = None
        run_id: Optional[str] = None

        try:
            runner_obj = json.loads(stdout_text) if stdout_text.strip() else None
        except Exception:
            runner_obj = None

        if result.was_killed:
            outcome = "FAIL_CLOSED"
            notes = f"killed:{result.kill_reason}"
        elif not isinstance(runner_obj, list) or not runner_obj:
            outcome = "FAIL_CLOSED"
            notes = "runner_output_invalid"
        else:
            rec = runner_obj[0]
            run_id = rec.get("run_id") if isinstance(rec, dict) else None
            if rec.get("outcome") != "PASS":
                outcome = "FAIL_CLOSED"
                notes = f"runner_outcome:{rec.get('outcome')}"

        _write_once(
            run_record_path,
            json.dumps(
                {
                    "crucible_id": cid,
                    "crucible_path": str(crucible_path),
                    "run_id": run_id,
                    "outcome": outcome,
                    "notes": notes,
                },
                sort_keys=True,
                indent=2,
                ensure_ascii=True,
            ),
        )

        append_checkpoint(checkpoint_path, CheckpointRecord(crucible_id=cid, run_id=run_id or "N/A", outcome=outcome, status="DONE"))
        runs.append(CrucibleRunSummary(crucible_id=cid, crucible_path=str(crucible_path), run_id=run_id, outcome=outcome, notes=notes))

        if outcome != "PASS":
            failures += 1
            if failures > plan.stop_conditions.max_failures:
                break

    summary_path = epoch_root / "epoch_summary.json"
    summary_obj = {
        "epoch_id": plan.epoch_id,
        "epoch_hash": manifest.epoch_hash,
        "kernel_identity": plan.kernel_identity.to_dict(),
        "runs": [asdict(r) for r in runs],
    }
    _write_once(summary_path, json.dumps(summary_obj, sort_keys=True, indent=2, ensure_ascii=True))

    return summary_obj


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="C018 Epoch Orchestrator (tooling-only)")
    p.add_argument("--epoch", required=True, help="Path to epoch plan (.json or .yaml)")
    p.add_argument("--resume", action="store_true", help="Resume from checkpoint if present")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    summary = run_epoch(Path(args.epoch), resume=args.resume)
    print(json.dumps(summary, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
