from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import yaml

# Ensure repo root on sys.path for absolute imports (tooling-only).
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from tools.growth.providers.live_guard import enforce_live_guard
enforce_live_guard()

from checkpoint_store import CheckpointRecord, append_checkpoint, completed_crucible_ids
from epoch_budget import assert_budget_ok, validate_crucible_budgets
from epoch_manifest import build_manifest
from epoch_schemas import EpochPlan, EpochSchemaError, RUNNER_TEMPLATE_C019
from tools.growth.coverage.coverage_validator import CoverageValidator


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
    return _REPO_ROOT


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


def _runner_command(
    *, crucible_path: Path, kernel_target: str, seed: int, ruleset_path: Optional[Path]
) -> Tuple[List[str], Path]:
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
    if ruleset_path is not None:
        cmd.extend(["--ruleset", str(ruleset_path.resolve())])
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


def _validator(ruleset_path: Optional[Path] = None) -> CoverageValidator:
    if ruleset_path is None:
        ruleset_path = _repo_root() / "tools" / "growth" / "coverage" / "ROTATION_RULESET_V1.json"
    return CoverageValidator(ruleset_path)


def _ruleset_path_for_profile(profile: str) -> Path:
    # Profile-to-ruleset mapping:
    # - COVERAGE: strict rotation/coverage enforcement
    # - other profiles (including COVERAGE_MILESTONE, COVERAGE_SEED, GOVERNANCE, PARADOX): bootstrap thresholds
    #   (integrity checks remain strict: fields, IDs, receipts)
    name = "ROTATION_RULESET_V1.json" if profile == "COVERAGE" else "ROTATION_RULESET_BOOTSTRAP_V1.json"
    return _repo_root() / "tools" / "growth" / "coverage" / name


def _load_kernel_capabilities() -> Dict[str, Dict[str, object]]:
    path = _repo_root() / "tools" / "growth" / "crucibles" / "kernel_capabilities.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise EpochSchemaError("kernel_capabilities.yaml must be a mapping (fail-closed)")
    caps: Dict[str, Dict[str, object]] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            raise EpochSchemaError("kernel_capabilities.yaml invalid shape (fail-closed)")
        caps[key] = dict(value)
    return caps


def _expectations_summary(crucible_spec: object) -> Dict[str, object]:
    expect = getattr(crucible_spec, "expect", None)
    if expect is None:
        return {}

    expected_outcome = getattr(expect, "expected_outcome", None)
    replay_verification = getattr(expect, "replay_verification", None)
    gov = getattr(expect, "governance_expectations", None)
    required_event_types = list(getattr(gov, "required_event_types", ()) or ()) if gov is not None else []

    return {
        "expected_outcome": expected_outcome,
        "replay_verification": replay_verification,
        "governance_required_event_types": required_event_types,
    }


def _preflight_expectation_conflicts(*, crucible_id: str, expect: Dict[str, object]) -> List[str]:
    expected_outcome = expect.get("expected_outcome")
    replay = expect.get("replay_verification")
    if expected_outcome != "PASS" and replay == "REQUIRED_PASS":
        return [
            f"EXPECTATION_CONFLICT: {crucible_id}: expected_outcome={expected_outcome} with replay_verification=REQUIRED_PASS cannot PASS (fail-closed)"
        ]
    return []


def _preflight_kernel_capability_mismatches(
    *,
    crucible_id: str,
    epoch_profile: str,
    kernel_target: str,
    expect: Dict[str, object],
    caps: Dict[str, Dict[str, object]],
) -> Tuple[List[str], List[str]]:
    blocks: List[str] = []
    warns: List[str] = []

    strict = epoch_profile in {"COVERAGE", "COVERAGE_MILESTONE"}
    kernel = caps.get(kernel_target, {})

    supports_governance = bool(kernel.get("governance_events", False))
    supports_replay = bool(kernel.get("replay_verification", False))

    if expect.get("governance_required_event_types") and not supports_governance:
        msg = (
            f"KERNEL_CAPABILITY_MISMATCH: {crucible_id}: governance required_event_types present, "
            f"but kernel_target={kernel_target} has governance_events=false"
        )
        (blocks if strict else warns).append(msg)

    if expect.get("replay_verification") == "REQUIRED_PASS" and not supports_replay:
        msg = (
            f"KERNEL_CAPABILITY_MISMATCH: {crucible_id}: replay_verification=REQUIRED_PASS, "
            f"but kernel_target={kernel_target} has replay_verification=false"
        )
        (blocks if strict else warns).append(msg)

    return blocks, warns


def _epoch_id_has_run_suffix(epoch_id: str) -> bool:
    return bool(re.search(r"_RUN\d+$", epoch_id))


def preflight_epoch(
    plan_path: Path,
    *,
    resume: bool,
    artifacts_root: Optional[Path],
    auto_bump: bool,
) -> int:
    plan = _load_plan(plan_path)
    if plan.runner_config.template_id != RUNNER_TEMPLATE_C019:
        print("# PREFLIGHT: BLOCK")
        print("- runner_config.template_id not allowed (fail-closed)")
        return 2

    repo_root = _repo_root()
    crucibles_root = repo_root / "tools" / "growth" / "crucibles"
    sys.path.insert(0, str(crucibles_root))

    crucible_specs: Dict[str, Dict[str, object]] = {}
    for cid in plan.crucible_order:
        rel = Path(plan.crucible_specs[cid])
        crucible_path = (repo_root / rel).resolve() if not rel.is_absolute() else rel
        if not crucible_path.exists():
            print("# PREFLIGHT: BLOCK")
            print(f"- Crucible spec missing: {crucible_path.as_posix()} (fail-closed)")
            return 2
        crucible_specs[cid] = _read_crucible(crucible_path)

    base_root = artifacts_root if artifacts_root is not None else (repo_root / "tools" / "growth" / "artifacts" / "epochs")

    blocks: List[str] = []
    warns: List[str] = []

    if not _epoch_id_has_run_suffix(plan.epoch_id):
        warns.append(f"IMMUTABILITY_WARN: epoch_id {plan.epoch_id} has no _RUN<N> suffix; auto-bump will append _RUN1")

    epoch_root = base_root / plan.epoch_id
    manifest_path = epoch_root / "epoch_manifest.json"
    if manifest_path.exists() and not auto_bump:
        blocks.append(f"IMMUTABILITY_BLOCK: epoch_id {plan.epoch_id} already exists and --no-auto-bump set")
    if (not resume and _epoch_root_has_payload(epoch_root)) and not auto_bump:
        blocks.append(f"IMMUTABILITY_BLOCK: epoch_id {plan.epoch_id} has prior payload and --no-auto-bump set")

    caps = _load_kernel_capabilities()
    if plan.kernel_identity.kernel_target not in caps:
        warns.append(
            f"KERNEL_CAPABILITY_WARN: kernel_target={plan.kernel_identity.kernel_target} missing from kernel_capabilities.yaml"
        )

    for cid, data in crucible_specs.items():
        expect = _expectations_summary(data["spec"])
        blocks.extend(_preflight_expectation_conflicts(crucible_id=cid, expect=expect))
        cap_blocks, cap_warns = _preflight_kernel_capability_mismatches(
            crucible_id=cid,
            epoch_profile=plan.epoch_profile,
            kernel_target=plan.kernel_identity.kernel_target,
            expect=expect,
            caps=caps,
        )
        blocks.extend(cap_blocks)
        warns.extend(cap_warns)

    if blocks:
        print("# PREFLIGHT: BLOCK")
        for line in blocks:
            print(f"- {line}")
        if warns:
            print("# PREFLIGHT: WARN")
            for line in warns:
                print(f"- {line}")
        return 2

    print("# PREFLIGHT: PASS")
    if warns:
        print("# PREFLIGHT: WARN")
        for line in warns:
            print(f"- {line}")
    return 0

def _epoch_root_has_payload(epoch_root: Path) -> bool:
    # Any existing file other than epoch_manifest.json indicates prior execution.
    if not epoch_root.exists():
        return False
    for p in epoch_root.rglob("*"):
        if not p.is_file():
            continue
        if p.name == "epoch_manifest.json":
            continue
        return True
    return False

def _parse_epoch_base(epoch_id: str) -> str:
    if "_RUN" in epoch_id:
        base, _, tail = epoch_id.rpartition("_RUN")
        try:
            int(tail)
            return base
        except Exception:
            return epoch_id
    return epoch_id


def _next_epoch_id_from_disk(epoch_id: str, epochs_root: Path) -> Tuple[str, int]:
    base = _parse_epoch_base(epoch_id)
    max_run = 0
    if epochs_root.exists():
        for p in epochs_root.iterdir():
            if not p.is_dir():
                continue
            name = p.name
            if not name.startswith(base + "_RUN"):
                continue
            tail = name[len(base) + 4 :]
            try:
                max_run = max(max_run, int(tail))
            except Exception:
                continue
    return f"{base}_RUN{max_run + 1}", max_run


def run_epoch(
    plan_path: Path,
    *,
    resume: bool = True,
    artifacts_root: Optional[Path] = None,
    runner_cmd_override: Optional[Callable[[Path, str, int], Tuple[List[str], Path]]] = None,
    salvage: bool = False,
    salvage_out_root: Optional[Path] = None,
    ruleset_path: Optional[Path] = None,
    auto_bump: bool = True,
    quiet: bool = False,
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

    # Build manifest and epoch hash (auto-bump on collision if enabled).
    spec_hashes = {cid: crucible_specs[cid]["hash"] for cid in plan.crucible_order}
    base_root = artifacts_root if artifacts_root is not None else (repo_root / "tools" / "growth" / "artifacts" / "epochs")

    manifest = build_manifest(plan, crucible_spec_hashes=spec_hashes)
    bump_count = 0
    original_epoch_id = plan.epoch_id
    while True:
        epoch_root = base_root / plan.epoch_id
        epoch_root.mkdir(parents=True, exist_ok=True)
        manifest_path = epoch_root / "epoch_manifest.json"
        if not resume and _epoch_root_has_payload(epoch_root):
            if not auto_bump:
                raise EpochSchemaError("Epoch artifacts already exist (fail-closed)")
            new_epoch_id, latest_run = _next_epoch_id_from_disk(plan.epoch_id, base_root)
            plan = dataclasses.replace(plan, epoch_id=new_epoch_id)
            manifest = build_manifest(plan, crucible_spec_hashes=spec_hashes)
            bump_count += 1
            if bump_count > 1000:
                raise EpochSchemaError("Auto-bump exceeded 1000 attempts (fail-closed)")
            continue
        if not manifest_path.exists():
            _write_once(manifest_path, json.dumps(manifest.to_dict(), sort_keys=True, indent=2, ensure_ascii=True))
            break
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        if existing.get("epoch_hash") == manifest.epoch_hash:
            break
        if not auto_bump:
            raise EpochSchemaError("Existing epoch_manifest hash mismatch (fail-closed)")
        new_epoch_id, latest_run = _next_epoch_id_from_disk(plan.epoch_id, base_root)
        plan = dataclasses.replace(plan, epoch_id=new_epoch_id)
        manifest = build_manifest(plan, crucible_spec_hashes=spec_hashes)
        bump_count += 1
        if bump_count > 1000:
            raise EpochSchemaError("Auto-bump exceeded 1000 attempts (fail-closed)")
    if bump_count > 0:
        if not quiet:
            print(f"AUTO-BUMP: epoch_id {original_epoch_id} -> {plan.epoch_id} (latest RUN={latest_run})", file=sys.stderr)

    checkpoint_path = epoch_root / "checkpoint.json"
    completed = completed_crucible_ids(checkpoint_path) if resume else set()

    start_epoch = time.monotonic()
    failures = 0
    runs: List[CrucibleRunSummary] = []

    profile = getattr(plan, "epoch_profile", "COVERAGE")
    selected_ruleset_path = ruleset_path if ruleset_path is not None else _ruleset_path_for_profile(profile)

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
            cmd, cwd = _runner_command(
                crucible_path=crucible_path,
                kernel_target=plan.kernel_identity.kernel_target,
                seed=plan.seed,
                ruleset_path=selected_ruleset_path,
            )
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

        # Copy micro_steps.json from the crucible run directory if present (tooling-only, non-gating).
        if run_id:
            micro_src = (
                _repo_root()
                / "tools"
                / "growth"
                / "artifacts"
                / "c019_runs"
                / plan.kernel_identity.kernel_target
                / run_id
                / "micro_steps.json"
            )
            micro_dst = run_dir / "micro_steps.json"
            if micro_src.exists():
                _write_once(micro_dst, micro_src.read_text(encoding="utf-8"))

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

    # --- Epoch verdict (profile-aware; tooling-only observability) ---
    profile = getattr(plan, "epoch_profile", "COVERAGE")
    crucibles_passed = sum(1 for r in runs if r.outcome == "PASS")
    crucibles_total = len(runs)
    crucibles_failed_closed = sum(1 for r in runs if r.outcome == "FAIL_CLOSED")
    crucibles_failed_other = sum(1 for r in runs if r.outcome not in {"PASS", "FAIL_CLOSED", "SKIPPED_RESUME"})
    crucibles_failed = crucibles_failed_closed + crucibles_failed_other

    if profile in {"COVERAGE", "COVERAGE_MILESTONE"}:
        epoch_verdict = "PASS" if (crucibles_total > 0 and crucibles_passed == crucibles_total and crucibles_failed == 0) else "FAIL"
    elif profile == "COVERAGE_SEED":
        epoch_verdict = "OPERATIONAL" if crucibles_passed >= 1 else "NOT_OPERATIONAL"
    else:
        # Non-gating profiles (e.g., GOVERNANCE/PARADOX): completion is still meaningful even if all crucibles fail-closed.
        epoch_verdict = "COMPLETE"

    summary_path = epoch_root / "epoch_summary.json"
    summary_obj = {
        "epoch_id": plan.epoch_id,
        "epoch_profile": profile,
        "epoch_verdict": epoch_verdict,
        "crucibles_total": crucibles_total,
        "crucibles_passed": crucibles_passed,
        "crucibles_failed_closed": crucibles_failed_closed,
        "crucibles_failed": crucibles_failed,
        "epoch_hash": manifest.epoch_hash,
        "kernel_identity": plan.kernel_identity.to_dict(),
        "runs": [asdict(r) for r in runs],
    }
    _write_once(summary_path, json.dumps(summary_obj, sort_keys=True, indent=2, ensure_ascii=True))

    # Emit epoch coverage from real crucible coverage (fail-closed).
    validator = _validator(selected_ruleset_path)
    # Aggregate observed data from crucible coverage files.
    cov_list: List[Dict[str, Any]] = []
    for cid in plan.crucible_order:
        run = next((r for r in runs if r.crucible_id == cid and r.run_id), None)
        if run is None or run.run_id is None:
            raise EpochSchemaError(f"Missing run_id for {cid}; cannot aggregate coverage (fail-closed)")
        cov_path = _repo_root() / "tools" / "growth" / "artifacts" / "c019_runs" / plan.kernel_identity.kernel_target / run.run_id / "crucible_coverage.json"
        if not cov_path.exists():
            raise EpochSchemaError(f"Missing crucible coverage for {cid} at {cov_path.as_posix()} (fail-closed)")
        cov_list.append(json.loads(cov_path.read_text(encoding="utf-8")))

    domains, subs, micros, ventures, modes, modalities, tools = set(), set(), set(), set(), set(), set(), set()
    cross_edges = 0
    paradox_events = 0
    seq_all: List[str] = []
    domain_freq: Dict[str, int] = {}
    for cov in cov_list:
        obs = cov.get("observed", {})
        domains.update(obs.get("domains") or [])
        subs.update(obs.get("subdomains") or [])
        micros.update(obs.get("microdomains") or [])
        ventures.update(obs.get("ventures") or [])
        modes.update(obs.get("reasoning_modes") or [])
        modalities.update(obs.get("modalities") or [])
        tools.update(obs.get("tools") or [])
        counts = obs.get("counts", {})
        cross_edges += counts.get("cross_domain_edges", 0) or 0
        paradox_events += counts.get("paradox_events", 0) or 0
        seq = cov.get("sequence") or []
        seq_all.extend(seq)
        # frequency from sequence
        for d in seq:
            domain_freq[d] = domain_freq.get(d, 0) + 1

    total_steps = sum(domain_freq.values())
    top_share = (max(domain_freq.values()) / total_steps) if total_steps else 0.0
    top5_share = (sum(sorted(domain_freq.values(), reverse=True)[:5]) / total_steps) if total_steps else 0.0
    # simple entropy
    import math
    entropy = 0.0
    if total_steps:
        for v in domain_freq.values():
            p = v / total_steps
            entropy -= p * math.log(p, 2)

    coverage = {
        "schema_version": "EPOCH_COVERAGE_V1",
        "epoch_id": plan.epoch_id,
        "epoch_hash": manifest.epoch_hash,
        "kernel_target": plan.kernel_identity.kernel_target,
        "observed": {
            "domains": sorted(domains),
            "subdomains": sorted(subs),
            "microdomains": sorted(micros),
            "ventures": sorted(ventures),
            "reasoning_modes": sorted(modes),
            "modalities": sorted(modalities),
            "tools": sorted(tools),
            "counts": {
                "unique_domains": len(domains),
                "unique_subdomains": len(subs),
                "unique_microdomains": len(micros),
                "cross_domain_edges": cross_edges,
                "mean_graph_distance": 0,
                "max_graph_distance": 0,
                "paradox_events": paradox_events,
            },
            "dominance": {
                "top_domain_share": top_share,
                "top_5_domain_share": top5_share,
                "entropy_domains": entropy,
            },
        },
        "sequence": seq_all,
        "proof": {
            "receipts": [
                {"type": "TRACE_HEAD_HASH", "sha256": manifest.epoch_hash},
                {"type": "LEDGER_ENTRY_HASH", "sha256": manifest.epoch_hash},
            ],
            "fail_closed": True,
        },
        "verdict": {"coverage_pass": None, "rotation_pass": None, "notes": None},
    }


    cov_path = epoch_root / "epoch_coverage.json"
    _write_once(cov_path, json.dumps(coverage, sort_keys=True, indent=2, ensure_ascii=True))
    profile = getattr(plan, "epoch_profile", "COVERAGE")
    verdict = validator.validate_epoch(coverage)
    if profile in {"COVERAGE", "COVERAGE_MILESTONE"}:
        if verdict.get("verdict") != validator.codes["PASS"]:
            raise EpochSchemaError(f"EPOCH COVERAGE FAIL: {verdict}")
    elif profile == "COVERAGE_SEED":
        verdict["non_gating"] = True
    else:
        verdict["non_gating"] = True

    # --- Phase 3: Motion/Transition Emitters ---
    try:
        from tools.growth.coverage.motion_metrics import (
            compute_transitions,
            compute_motion_metrics,
            emit_transitions_json,
            emit_motion_metrics_json,
        )
        # Build epoch sequence from crucible coverage
        epoch_sequence = seq_all
        epoch_tag_index: Dict[str, Dict[str, List[str]]] = {
            dom: {"domains": [dom], "subdomains": [], "microdomains": []} for dom in epoch_sequence
        }
        transitions = compute_transitions(epoch_sequence, epoch_tag_index)
        metrics = compute_motion_metrics(epoch_sequence, epoch_tag_index)
        emit_transitions_json(str(epoch_root / "transitions.json"), transitions)
        emit_motion_metrics_json(str(epoch_root / "motion_metrics.json"), metrics)
    except Exception as exc:
        raise EpochSchemaError(f"EPOCH_MOTION_EMIT_FAIL: {exc}")

    # --- Phase 4: Non-gating salvage (optional) ---
    if salvage:
        salvage_status = {"status": "FAIL", "error": "not-run"}
        try:
            salvage_base = salvage_out_root if salvage_out_root is not None else (_repo_root() / "tools" / "growth" / "artifacts" / "salvage")
            salvage_out = salvage_base / plan.epoch_id
            cmd = [
                str(Path(sys.executable).resolve()),
                "KT_PROD_CLEANROOM/tools/growth/salvage/salvage_extractor.py",
                "--epoch-artifact-root",
                str(epoch_root),
                "--out",
                str(salvage_out),
            ]
            if quiet:
                proc = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            else:
                proc = subprocess.run(cmd, check=True)
            salvage_status = {"status": "OK", "out": str(salvage_out)}
        except Exception as exc:  # noqa: BLE001 tooling-only
            salvage_status = {"status": "FAIL", "error": str(exc)}
        (epoch_root / "salvage_status.json").write_text(json.dumps(salvage_status, indent=2), encoding="utf-8", newline="\n")

    return summary_obj


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="C018 Epoch Orchestrator (tooling-only)")
    p.add_argument("--epoch", required=True, help="Path to epoch plan (.json or .yaml)")
    p.add_argument("--resume", action="store_true", help="Resume from checkpoint if present")
    p.add_argument("--preflight", action="store_true", help="Doctor mode: validate plan+crucibles and exit (no execution)")
    p.add_argument(
        "--summary-only",
        action="store_true",
        help="Print only a single EPOCH VERDICT line (suppresses JSON output).",
    )
    p.add_argument(
        "--salvage",
        action="store_true",
        help="Run non-gating salvage extraction after epoch completion",
    )
    p.add_argument(
        "--salvage-out-root",
        default="KT_PROD_CLEANROOM/tools/growth/artifacts/salvage",
        help="Base directory for salvage outputs (default: tools/growth/artifacts/salvage)",
    )
    p.add_argument(
        "--no-auto-bump",
        action="store_true",
        help="Disable automatic epoch_id bumping on write-once collisions",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    if args.preflight:
        return preflight_epoch(Path(args.epoch), resume=args.resume, artifacts_root=None, auto_bump=not args.no_auto_bump)
    summary = run_epoch(
        Path(args.epoch),
        resume=args.resume,
        salvage=args.salvage,
        salvage_out_root=Path(args.salvage_out_root),
        auto_bump=not args.no_auto_bump,
        quiet=args.summary_only,
    )
    epoch_id = summary.get("epoch_id", "UNKNOWN")
    profile = summary.get("epoch_profile", "UNKNOWN")
    verdict = summary.get("epoch_verdict", "UNKNOWN")
    passed = summary.get("crucibles_passed", "?")
    total = summary.get("crucibles_total", "?")

    verdict_line = f"EPOCH VERDICT: {verdict} ({profile}) — crucibles_passed={passed}/{total} — epoch_id={epoch_id}"
    if args.summary_only:
        print(verdict_line)
    else:
        # Preserve JSON-only stdout for existing tooling; print verdict to stderr for humans.
        print(verdict_line, file=sys.stderr)
        print(json.dumps(summary, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
