from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil

from crucible_dsl_schemas import (
    KERNEL_V1_ARCHIVAL,
    KERNEL_V2_SOVEREIGN,
    OUTCOME_FAIL,
    OUTCOME_INFEASIBLE,
    OUTCOME_PASS,
    OUTCOME_REFUSE,
    REPLAY_NOT_APPLICABLE,
    REPLAY_REQUIRED_FAIL,
    REPLAY_REQUIRED_PASS,
    CrucibleBudgets,
    CrucibleExpect,
    CrucibleSchemaError,
    budgets_hash,
    run_id as compute_run_id,
)
from crucible_loader import LoadedCrucible, compute_prompt_hash, load_crucible


class RunnerError(RuntimeError):
    pass


@dataclass(frozen=True)
class KernelRunResult:
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
class CrucibleRunRecord:
    run_id: str
    crucible_id: str
    kernel_target: str
    kernel_command: List[str]
    kernel_workdir: str
    crucible_spec_hash: str
    prompt_hash: str
    seed: int
    budgets: Dict[str, Any]
    budgets_hash: str
    timestamp_utc: str
    outcome: str
    output_contract_pass: bool
    replay_status: str
    replay_pass: Optional[bool]
    governance_status: str
    governance_pass: Optional[bool]
    artifacts_dir: str
    notes: Optional[str] = None


def _utc_now_iso_z() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _repo_root() -> Path:
    # .../KT_PROD_CLEANROOM/tools/growth/crucibles/crucible_runner.py -> .../KT_PROD_CLEANROOM
    return Path(__file__).resolve().parents[3]


def _growth_root() -> Path:
    return _repo_root() / "tools" / "growth"


def _v2_kernel_root() -> Path:
    return _repo_root() / "04_PROD_TEMPLE_V2"


def _v1_kernel_root() -> Path:
    # Workspace root inferred relative to cleanroom.
    return _repo_root().parents[0] / "KT_TEMPLE_ROOT"


def _load_v2_registry_state_vault_relpath() -> str:
    path = _v2_kernel_root() / "docs" / "RUNTIME_REGISTRY.json"
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RunnerError(f"Unable to read V2 runtime registry JSON (fail-closed): {exc.__class__.__name__}")
    if not isinstance(obj, dict):
        raise RunnerError("V2 runtime registry must be an object (fail-closed)")
    state_vault = obj.get("state_vault")
    if not isinstance(state_vault, dict):
        raise RunnerError("V2 runtime registry missing state_vault (fail-closed)")
    rel = state_vault.get("jsonl_path")
    if not isinstance(rel, str) or not rel or len(rel) > 512:
        raise RunnerError("V2 runtime registry state_vault.jsonl_path invalid (fail-closed)")
    return rel.replace("\\", "/")


def _reader_thread(
    pipe,  # type: ignore[type-arg]
    *,
    max_bytes: int,
    sink: bytearray,
    truncated: threading.Event,
    kill_event: threading.Event,
    proc: subprocess.Popen,  # type: ignore[type-arg]
) -> None:
    try:
        while True:
            chunk = pipe.read(4096)
            if not chunk:
                return
            if kill_event.is_set():
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


def _run_subprocess_capped(
    *,
    command: List[str],
    cwd: Path,
    env: Dict[str, str],
    stdin_bytes: bytes,
    time_ms: int,
    kill_grace_ms: int,
    stdout_max_bytes: int,
    stderr_max_bytes: int,
    memory_max_mb: int,
) -> KernelRunResult:
    start = time.monotonic()
    proc = subprocess.Popen(
        command,
        cwd=str(cwd),
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )

    stdout_buf = bytearray()
    stderr_buf = bytearray()
    stdout_truncated = threading.Event()
    stderr_truncated = threading.Event()
    kill_event = threading.Event()

    t_out = threading.Thread(
        target=_reader_thread,
        args=(proc.stdout,),
        kwargs={"max_bytes": stdout_max_bytes, "sink": stdout_buf, "truncated": stdout_truncated, "kill_event": kill_event, "proc": proc},
        daemon=True,
    )
    t_err = threading.Thread(
        target=_reader_thread,
        args=(proc.stderr,),
        kwargs={"max_bytes": stderr_max_bytes, "sink": stderr_buf, "truncated": stderr_truncated, "kill_event": kill_event, "proc": proc},
        daemon=True,
    )

    ps_proc: Optional[psutil.Process]
    try:
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

        try:
            if proc.stdin is not None:
                proc.stdin.write(stdin_bytes)
                proc.stdin.close()
        except Exception:
            pass

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

        for handle in (proc.stdout, proc.stderr, proc.stdin):
            try:
                if handle is not None:
                    handle.close()
            except Exception:
                pass

    return KernelRunResult(
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


def _v2_harness_code() -> str:
    return (
        "import importlib, json, socket, sys\n"
        "from pathlib import Path\n"
        "kernel_root = Path(sys.argv[1]).resolve()\n"
        "artifact_root = Path(sys.argv[2]).resolve()\n"
        "sys.path.insert(0, str(kernel_root / 'src'))\n"
        "from core import runtime_registry as rr\n"
        "registry = rr.load_runtime_registry()\n"
        "orig_loader = rr.load_runtime_registry\n"
        "orig_root = rr._v2_repo_root\n"
        "rr._v2_repo_root = lambda: artifact_root\n"
        "rr.load_runtime_registry = lambda: registry\n"
        "orig_socket = socket.socket\n"
        "orig_create = socket.create_connection\n"
        "def _deny(*_a, **_k):\n"
        "    raise RuntimeError('Network call attempted (fail-closed)')\n"
        "socket.socket = _deny\n"
        "socket.create_connection = _deny\n"
        "try:\n"
        "    env = json.loads(sys.stdin.read())\n"
        "    if not isinstance(env, dict) or set(env.keys()) != {'input'} or not isinstance(env.get('input'), str):\n"
        "        raise RuntimeError('Invalid envelope (must be {\"input\": <string>})')\n"
        "    from core.invariants_gate import CONSTITUTION_VERSION_HASH\n"
        "    from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH\n"
        "    ctx = {\n"
        "        'envelope': env,\n"
        "        'schema_id': RUNTIME_CONTEXT_SCHEMA_ID,\n"
        "        'schema_version_hash': RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,\n"
        "        'constitution_version_hash': CONSTITUTION_VERSION_HASH,\n"
        "    }\n"
        "    entry = importlib.import_module('kt.entrypoint')\n"
        "    result = entry.invoke(ctx)\n"
        "    print(json.dumps(result, ensure_ascii=True))\n"
        "finally:\n"
        "    rr.load_runtime_registry = orig_loader\n"
        "    rr._v2_repo_root = orig_root\n"
        "    socket.socket = orig_socket\n"
        "    socket.create_connection = orig_create\n"
    )


def _v1_harness_code() -> str:
    return (
        "import json, sys\n"
        "from pathlib import Path\n"
        "kernel_root = Path(sys.argv[1]).resolve()\n"
        "sys.path.insert(0, str(kernel_root / 'src'))\n"
        "env = json.loads(sys.stdin.read())\n"
        "if not isinstance(env, dict) or set(env.keys()) != {'input'} or not isinstance(env.get('input'), str):\n"
        "    raise SystemExit(2)\n"
        "from kt import entrypoint as ep\n"
        "sys.exit(ep.main(['--json', json.dumps(env, ensure_ascii=True)]))\n"
    )


def _kernel_command(*, kernel_target: str, artifact_root: Path) -> Tuple[List[str], Path]:
    if kernel_target == KERNEL_V2_SOVEREIGN:
        kernel_root = _v2_kernel_root()
        code = _v2_harness_code()
    elif kernel_target == KERNEL_V1_ARCHIVAL:
        kernel_root = _v1_kernel_root()
        code = _v1_harness_code()
    else:
        raise RunnerError(f"Unknown kernel_target (fail-closed): {kernel_target}")

    if not kernel_root.exists():
        raise RunnerError(f"Kernel root missing (fail-closed): {kernel_root.as_posix()}")

    cmd = [sys.executable, "-c", code, str(kernel_root), str(artifact_root)]
    return cmd, kernel_root


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _safe_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _check_output_contract(
    *,
    stdout_text: str,
    must_be_json: bool,
    required_keys: Tuple[str, ...],
    forbidden_substrings: Tuple[str, ...],
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    for s in forbidden_substrings:
        if s in stdout_text:
            return False, None, f"forbidden_substring:{s}"

    if not must_be_json:
        return True, None, None

    try:
        obj = json.loads(stdout_text)
    except Exception as exc:
        return False, None, f"json_parse_error:{exc.__class__.__name__}"
    if not isinstance(obj, dict):
        return False, None, "json_root_not_object"

    for k in required_keys:
        if k not in obj:
            return False, obj, f"missing_key:{k}"
    return True, obj, None


def _expected_outcome_matches(expect_outcome: str, output_obj: Optional[Dict[str, Any]]) -> bool:
    if output_obj is None:
        return False
    status = output_obj.get("status")
    if expect_outcome == OUTCOME_PASS:
        return status in {"OK", "PASS"}
    if expect_outcome == OUTCOME_REFUSE:
        return status in {"REFUSE", "CONSTITUTIONAL_CRISIS", "FAIL_CLOSED", "ERROR"}
    if expect_outcome == OUTCOME_INFEASIBLE:
        return status in {"INFEASIBLE"}
    if expect_outcome == OUTCOME_FAIL:
        return status in {"FAIL_CLOSED", "CONSTITUTIONAL_CRISIS", "ERROR"}
    return False


def run_crucible_once(
    *,
    loaded: LoadedCrucible,
    kernel_target: str,
    seed: int,
    artifacts_dir: Path,
    ledger_path: Path,
    prompt_override: Optional[str] = None,
    budgets_override: Optional[Dict[str, Any]] = None,
    expect_override: Optional[Dict[str, Any]] = None,
) -> CrucibleRunRecord:
    spec = loaded.spec

    if spec.input.redaction_policy != "ALLOW_RAW_IN_CRUCIBLE":
        raise RunnerError("HASH_ONLY_CRUCIBLE requires an external prompt store; not implemented (fail-closed)")

    prompt = prompt_override if prompt_override is not None else spec.input.prompt
    prompt_hash = compute_prompt_hash(prompt)

    budgets_payload = spec.budgets.to_dict()
    if budgets_override:
        budgets_payload.update(budgets_override)
    budgets_obj = CrucibleBudgets.from_dict(budgets_payload)
    budgets_hash_hex = budgets_hash(budgets_obj)

    expect_payload = spec.expect.to_dict()
    if expect_override:
        expect_payload = expect_override
    expect_obj = CrucibleExpect.from_dict(expect_payload)

    rid = compute_run_id(
        kernel_target=kernel_target,
        crucible_spec_hash_hex=loaded.crucible_spec_hash,
        prompt_hash_hex=prompt_hash,
        seed=seed,
        budgets_hash_hex=budgets_hash_hex,
    )

    run_root = artifacts_dir / kernel_target / rid
    run_root.mkdir(parents=True, exist_ok=True)

    # Snapshot the exact spec file used (byte-preserving text snapshot).
    _write_text(run_root / "crucible_spec.snapshot.yaml", loaded.raw_text)

    envelope = {"input": prompt}
    envelope_json = json.dumps(envelope, ensure_ascii=True).encode("utf-8")

    cmd, kernel_root = _kernel_command(kernel_target=kernel_target, artifact_root=run_root)

    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    started = _utc_now_iso_z()

    result = _run_subprocess_capped(
        command=cmd,
        cwd=run_root,
        env=env,
        stdin_bytes=envelope_json,
        time_ms=budgets_obj.time_ms,
        kill_grace_ms=budgets_obj.kernel_timeout_kill_ms,
        stdout_max_bytes=budgets_obj.stdout_max_bytes,
        stderr_max_bytes=budgets_obj.stderr_max_bytes,
        memory_max_mb=budgets_obj.runner_memory_max_mb,
    )

    stdout_text = _safe_decode(result.stdout).strip()
    stderr_text = _safe_decode(result.stderr)

    _write_text(run_root / "stderr.log", stderr_text)
    _write_text(run_root / "stdout.json", (stdout_text + "\n") if stdout_text else "")

    if result.was_killed:
        outcome = OUTCOME_FAIL
        output_contract_pass = False
        output_obj = None
        notes = f"killed:{result.kill_reason}"
    else:
        output_contract_pass, output_obj, notes = _check_output_contract(
            stdout_text=stdout_text,
            must_be_json=expect_obj.output_contract.must_be_json,
            required_keys=expect_obj.output_contract.required_keys,
            forbidden_substrings=expect_obj.output_contract.forbidden_substrings,
        )
        outcome = (
            expect_obj.expected_outcome
            if output_contract_pass and _expected_outcome_matches(expect_obj.expected_outcome, output_obj)
            else OUTCOME_FAIL
        )

        if outcome == OUTCOME_INFEASIBLE and expect_obj.expected_infeasibility_token:
            tok = (output_obj or {}).get("infeasibility_token")
            if tok != expect_obj.expected_infeasibility_token:
                outcome = OUTCOME_FAIL

        if outcome == OUTCOME_REFUSE and expect_obj.expected_refusal_code:
            code = (output_obj or {}).get("refusal_code")
            if code != expect_obj.expected_refusal_code:
                outcome = OUTCOME_FAIL

    # Thermodynamics / external budgets: enforce runner caps deterministically (fail-closed).
    # This is not kernel-internal metering; it is proof that the harness did not exceed the declared run caps.
    te = expect_obj.thermo_expectations
    budget_verdict = "OVER_BUDGET_HALT" if result.was_killed else "WITHIN_BUDGET"
    if te.must_enforce_budget:
        if te.expected_budget_verdict != "BUDGET_NOT_ASSERTED" and budget_verdict != te.expected_budget_verdict:
            outcome = OUTCOME_FAIL
        if budget_verdict != "WITHIN_BUDGET":
            outcome = OUTCOME_FAIL
    else:
        if te.expected_budget_verdict != "BUDGET_NOT_ASSERTED":
            # If an explicit verdict is requested without enforcement, treat as invalid spec (fail-closed).
            outcome = OUTCOME_FAIL
            notes = (notes + ";thermo_expectations_inconsistent") if notes else "thermo_expectations_inconsistent"

    # Replay verification: for V2, validate the run vault; for V1 archival, fail-closed unless NOT_APPLICABLE.
    replay_status = expect_obj.replay_verification
    replay_pass: Optional[bool] = None
    if replay_status == REPLAY_NOT_APPLICABLE:
        replay_pass = None
    elif kernel_target == KERNEL_V1_ARCHIVAL:
        # Archival replay verification is not implemented. If a crucible requires replay proof against V1,
        # treat it as UNVERIFIABLE and fail closed.
        replay_pass = None
        if replay_status != REPLAY_NOT_APPLICABLE:
            replay_pass = False
            outcome = OUTCOME_FAIL
            _write_text(
                run_root / "replay_report.json",
                json.dumps(
                    {
                        "status": "UNVERIFIABLE",
                        "kernel_target": KERNEL_V1_ARCHIVAL,
                        "reason": "archival_replay_verification_unavailable",
                    },
                    ensure_ascii=True,
                )
                + "\n",
            )
    else:
        vault_rel = _load_v2_registry_state_vault_relpath()
        vault_path = (run_root / Path(vault_rel)).resolve()
        replay_cmd = [
            sys.executable,
            "-c",
            (
                "import json, sys\n"
                "from pathlib import Path\n"
                "p = Path(sys.argv[1]).resolve()\n"
                "sys.path.insert(0, sys.argv[2])\n"
                "from memory.replay import validate_state_vault_chain\n"
                "try:\n"
                "    r = validate_state_vault_chain(p)\n"
                "    out = {'status':'PASS','record_count':r.record_count,'head_hash':r.head_hash}\n"
                "except Exception as exc:\n"
                "    out = {'status':'FAIL','error_type':exc.__class__.__name__,'error':str(exc)}\n"
                "print(json.dumps(out, ensure_ascii=True))\n"
            ),
            str(vault_path),
            str((kernel_root / "src").resolve()),
        ]
        replay_res = _run_subprocess_capped(
            command=replay_cmd,
            cwd=run_root,
            env=env,
            stdin_bytes=b"",
            time_ms=min(10_000, budgets_obj.time_ms),
            kill_grace_ms=min(10_500, budgets_obj.kernel_timeout_kill_ms),
            stdout_max_bytes=64_000,
            stderr_max_bytes=64_000,
            memory_max_mb=budgets_obj.runner_memory_max_mb,
        )
        replay_out = _safe_decode(replay_res.stdout).strip()
        _write_text(run_root / "replay_report.json", (replay_out + "\n") if replay_out else "")
        try:
            replay_obj = json.loads(replay_out) if replay_out else {}
        except Exception:
            replay_obj = {}
        replay_pass = bool(replay_obj.get("status") == "PASS")
        if replay_status == REPLAY_REQUIRED_PASS and not replay_pass:
            outcome = OUTCOME_FAIL
        if replay_status == REPLAY_REQUIRED_FAIL and replay_pass:
            outcome = OUTCOME_FAIL

    # Governance expectations: verifiable for V2 via state vault; archival runs are marked UNVERIFIABLE.
    governance_status = "UNVERIFIABLE"
    governance_pass: Optional[bool] = None
    if kernel_target == KERNEL_V2_SOVEREIGN:
        vault_rel = _load_v2_registry_state_vault_relpath()
        vault_path = (run_root / Path(vault_rel)).resolve()
        gov_cmd = [
            sys.executable,
            "-c",
            (
                "import json, sys\n"
                "from pathlib import Path\n"
                "p = Path(sys.argv[1]).resolve()\n"
                "sys.path.insert(0, sys.argv[2])\n"
                "from governance.events import GOVERNANCE_ORGAN_ID\n"
                "types = []\n"
                "count = 0\n"
                "with p.open('r', encoding='utf-8') as h:\n"
                "    for raw in h:\n"
                "        obj = json.loads(raw)\n"
                "        if obj.get('organ_id') != GOVERNANCE_ORGAN_ID:\n"
                "            continue\n"
                "        et = obj.get('event_type')\n"
                "        if isinstance(et, str):\n"
                "            types.append(et)\n"
                "            count += 1\n"
                "out = {'count':count,'types':sorted(set(types))}\n"
                "print(json.dumps(out, ensure_ascii=True))\n"
            ),
            str(vault_path),
            str((kernel_root / "src").resolve()),
        ]
        gov_res = _run_subprocess_capped(
            command=gov_cmd,
            cwd=run_root,
            env=env,
            stdin_bytes=b"",
            time_ms=min(10_000, budgets_obj.time_ms),
            kill_grace_ms=min(10_500, budgets_obj.kernel_timeout_kill_ms),
            stdout_max_bytes=64_000,
            stderr_max_bytes=64_000,
            memory_max_mb=budgets_obj.runner_memory_max_mb,
        )
        gov_out = _safe_decode(gov_res.stdout).strip()
        _write_text(run_root / "governance_report.json", (gov_out + "\n") if gov_out else "")
        try:
            gov_obj = json.loads(gov_out) if gov_out else {}
        except Exception:
            gov_obj = {}
        event_types = set(gov_obj.get("types") or [])
        count = int(gov_obj.get("count") or 0)

        ge = expect_obj.governance_expectations
        governance_pass = True
        if count < ge.event_count_min or count > ge.event_count_max:
            governance_pass = False
        if ge.required_event_types and not set(ge.required_event_types).issubset(event_types):
            governance_pass = False
        if ge.forbidden_event_types and set(ge.forbidden_event_types).intersection(event_types):
            governance_pass = False
        governance_status = "VERIFIED"
        if governance_pass is False:
            outcome = OUTCOME_FAIL
    else:
        ge = expect_obj.governance_expectations
        if ge.required_event_types or ge.forbidden_event_types or ge.event_count_min or ge.event_count_max:
            governance_status = "UNVERIFIABLE_ARCHIVAL"
            outcome = OUTCOME_FAIL
            notes = (notes + ";governance_unverifiable") if notes else "governance_unverifiable"

    record = CrucibleRunRecord(
        run_id=rid,
        crucible_id=spec.crucible_id,
        kernel_target=kernel_target,
        kernel_command=cmd,
        kernel_workdir=str(run_root),
        crucible_spec_hash=loaded.crucible_spec_hash,
        prompt_hash=prompt_hash,
        seed=seed,
        budgets=budgets_obj.to_dict(),
        budgets_hash=budgets_hash_hex,
        timestamp_utc=started,
        outcome=outcome,
        output_contract_pass=output_contract_pass,
        replay_status=replay_status,
        replay_pass=replay_pass,
        governance_status=governance_status,
        governance_pass=governance_pass,
        artifacts_dir=str(run_root.relative_to(_repo_root())),
        notes=notes,
    )

    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_obj = {
        "run_id": record.run_id,
        "crucible_id": record.crucible_id,
        "kernel_target": record.kernel_target,
        "crucible_spec_hash": record.crucible_spec_hash,
        "prompt_hash": record.prompt_hash,
        "seed": record.seed,
        "budgets_hash": record.budgets_hash,
        "outcome": record.outcome,
        "output_contract_pass": record.output_contract_pass,
        "replay_status": record.replay_status,
        "replay_pass": record.replay_pass,
        "governance_status": record.governance_status,
        "governance_pass": record.governance_pass,
        "artifacts_dir": record.artifacts_dir,
    }
    with ledger_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(ledger_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")

    _write_text(run_root / "runner_record.json", json.dumps(asdict(record), sort_keys=True, indent=2, ensure_ascii=True) + "\n")

    return record


def run_crucible_file(path: Path, *, seed: int = 0) -> List[CrucibleRunRecord]:
    loaded = load_crucible(path)
    repo_root = _repo_root()
    artifacts_dir = repo_root / "tools" / "growth" / "artifacts" / "c019_runs"
    ledger_path = repo_root / "tools" / "growth" / "ledgers" / "c019_crucible_runs.jsonl"

    records: List[CrucibleRunRecord] = []
    for kernel_target in loaded.spec.kernel_targets:
        records.append(
            run_crucible_once(
                loaded=loaded,
                kernel_target=kernel_target,
                seed=seed,
                artifacts_dir=artifacts_dir,
                ledger_path=ledger_path,
            )
        )

    for variant in loaded.spec.variants:
        for kernel_target in loaded.spec.kernel_targets:
            records.append(
                run_crucible_once(
                    loaded=loaded,
                    kernel_target=kernel_target,
                    seed=seed,
                    artifacts_dir=artifacts_dir,
                    ledger_path=ledger_path,
                    prompt_override=variant.input_prompt,
                    budgets_override=variant.budgets_override.to_dict() if variant.budgets_override is not None else None,
                    expect_override=variant.expect_override.to_dict() if variant.expect_override is not None else None,
                )
            )
    return records
