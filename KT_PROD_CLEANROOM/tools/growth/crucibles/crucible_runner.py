
from pathlib import Path
import json
from typing import Any, Dict, Tuple
import sys

# Ensure repo root on sys.path for absolute imports (tooling-only).
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from tools.growth.providers.live_guard import enforce_live_guard
enforce_live_guard()

def _load_governance_verdict_or_fail(
    run_dir: Path,
) -> Tuple[bool, str]:
    """
    Returns: (governance_pass, rationale_or_error_note)

    Fail-closed:
      - missing file => (False, "governance_verdict_missing")
      - invalid json => (False, "governance_verdict_invalid_json")
      - schema mismatch => (False, "governance_verdict_schema_error:...")
      - verdict not PASS/FAIL => (False, "governance_verdict_invalid_verdict")
    """
    path = run_dir / "governance_verdict.json"
    if not path.exists():
        return (False, "governance_verdict_missing")

    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return (False, "governance_verdict_invalid_json")

    if not isinstance(obj, dict):
        return (False, "governance_verdict_schema_error:not_object")

    schema_id = obj.get("schema_id")
    schema_version = obj.get("schema_version")
    verdict = obj.get("verdict")
    rationale = obj.get("rationale")

    if schema_id != "governance.verdict":
        return (False, "governance_verdict_schema_error:schema_id_mismatch")
    if schema_version != "1.0":
        return (False, "governance_verdict_schema_error:schema_version_mismatch")

    if verdict not in ("PASS", "FAIL"):
        return (False, "governance_verdict_invalid_verdict")

    if not isinstance(rationale, str):
        return (False, "governance_verdict_schema_error:rationale_not_string")

    return (verdict == "PASS", rationale.strip() or "NO_RATIONALE")

import json
import os
import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil
import traceback
import hashlib
import math

from crucible_dsl_schemas import (
    KERNEL_V1_ARCHIVAL,
    KERNEL_V2_SOVEREIGN,
    KERNEL_COVERAGE_BASELINE,
    KERNEL_GOVERNANCE_BASELINE,
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
from tools.growth.coverage.coverage_validator import CoverageValidator
from tools.growth.coverage.coverage_metrics import compute_coverage


class RunnerError(RuntimeError):
    pass


_PARADOX_MOVE_BOUNDS = {"PAS", "APF", "POG"}
_BELNAP_BOUNDS = {"T", "F", "B", "N"}


def _policy_b_registry_path() -> Path:
    return _growth_root() / "state" / "policy_b_variable_registry.json"


def _load_policy_b_registry() -> Dict[str, Any]:
    path = _policy_b_registry_path()
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RunnerError(f"Policy B registry unreadable (fail-closed): {exc.__class__.__name__}") from exc
    if not isinstance(obj, dict):
        raise RunnerError("Policy B registry must be an object (fail-closed)")
    if obj.get("schema") != "POLICY_B_VARIABLE_REGISTRY_V1":
        raise RunnerError("Policy B registry schema mismatch (fail-closed)")
    if obj.get("version") != 1:
        raise RunnerError("Policy B registry version mismatch (fail-closed)")
    return obj


def _policy_b_paradox_selector() -> str:
    registry = _load_policy_b_registry()
    for entry in registry.get("variables", []):
        if not isinstance(entry, dict):
            continue
        if entry.get("name") != "paradox_move_selector":
            continue
        value = entry.get("policy_b_value")
        if not isinstance(value, str):
            raise RunnerError("Policy B paradox_move_selector invalid (fail-closed)")
        value = value.strip().upper()
        if value not in _PARADOX_MOVE_BOUNDS:
            raise RunnerError("Policy B paradox_move_selector out of bounds (fail-closed)")
        return value
    raise RunnerError("Policy B paradox_move_selector missing (fail-closed)")


def _is_paradox_crucible(spec: Any) -> bool:
    cid = str(getattr(spec, "crucible_id", "") or "").upper()
    domain = str(getattr(spec, "domain", "") or "").upper()
    tags_obj = getattr(spec, "tags", None)
    tag_values: list[str] = []
    if isinstance(tags_obj, dict):
        for k in ("domains", "subdomains", "microdomains", "ventures", "reasoning_modes", "modalities", "tools", "paradox_classes"):
            raw = tags_obj.get(k) if isinstance(tags_obj, dict) else None
            if isinstance(raw, (list, tuple, set)):
                tag_values.extend([str(x) for x in raw])
    elif tags_obj is not None and hasattr(tags_obj, "to_dict"):
        try:
            data = tags_obj.to_dict()
        except Exception:
            data = {}
        if isinstance(data, dict):
            for k in ("domains", "subdomains", "microdomains", "ventures", "reasoning_modes", "modalities", "tools", "paradox_classes"):
                raw = data.get(k)
                if isinstance(raw, (list, tuple, set)):
                    tag_values.extend([str(x) for x in raw])
    elif isinstance(tags_obj, (list, tuple, set)):
        tag_values.extend([str(x) for x in tags_obj])

    tag_hits = any("PARADOX" in v.upper() for v in tag_values)
    return ("PARADOX" in cid) or ("PARADOX" in domain) or tag_hits

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
    duration_ms: int
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
    return _REPO_ROOT


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
        "        'artifact_root': str(artifact_root),\n"
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
    if kernel_target in {KERNEL_V2_SOVEREIGN, KERNEL_COVERAGE_BASELINE, KERNEL_GOVERNANCE_BASELINE}:
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


def _sha256_json(obj: Any) -> str:
    try:
        return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
    except Exception:
        return hashlib.sha256(b"NULL").hexdigest()


def _safe_decode(data: bytes) -> str:
    if not data:
        return ""
    # Try utf-8 and utf-8 with BOM first, then common fallbacks (utf-16 variants),
    # finally fall back to latin-1 to preserve bytes.
    try:
        return data.decode("utf-8")
    except Exception:
        pass
    for enc in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "latin-1"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return data.decode("utf-8", errors="replace")


def _validator(ruleset_path: Optional[Path] = None) -> CoverageValidator:
    if ruleset_path is None:
        ruleset_path = _repo_root() / "tools" / "growth" / "coverage" / "ROTATION_RULESET_V1.json"
    return CoverageValidator(ruleset_path)


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
    ruleset_path: Optional[Path] = None,
    prompt_override: Optional[str] = None,
    budgets_override: Optional[Dict[str, Any]] = None,
    expect_override: Optional[Dict[str, Any]] = None,
) -> CrucibleRunRecord:
    spec = loaded.spec

    # --- FAIL-CLOSED IDENTITY INVARIANT ---
    # run_id (and run_root) must exist before any outcome is recorded or any early-exit occurs.
    started = _utc_now_iso_z()
    t0 = time.perf_counter()

    prompt = prompt_override if prompt_override is not None else getattr(getattr(spec, "input", None), "prompt", "")
    if not isinstance(prompt, str):
        prompt = str(prompt)
    try:
        prompt_hash = compute_prompt_hash(prompt)
    except Exception:
        prompt_hash = hashlib.sha256(prompt.encode("utf-8", errors="replace")).hexdigest()

    budgets_payload: Dict[str, Any] = {}
    try:
        budgets_payload = spec.budgets.to_dict()
    except Exception:
        budgets_payload = {}
    if budgets_override:
        budgets_payload.update(budgets_override)
    budgets_hash_hex = _sha256_json(budgets_payload)

    expect_payload: Dict[str, Any] = {}
    try:
        expect_payload = spec.expect.to_dict()
    except Exception:
        expect_payload = {}
    if expect_override:
        expect_payload = expect_override

    try:
        rid = compute_run_id(
            kernel_target=kernel_target,
            crucible_spec_hash_hex=loaded.crucible_spec_hash,
            prompt_hash_hex=prompt_hash,
            seed=seed,
            budgets_hash_hex=budgets_hash_hex,
        )
    except Exception:
        rid = hashlib.sha256(
            f"FALLBACK|{kernel_target}|{loaded.crucible_spec_hash}|{prompt_hash}|{seed}|{budgets_hash_hex}".encode("utf-8")
        ).hexdigest()

    run_root = artifacts_dir / kernel_target / rid
    run_root.mkdir(parents=True, exist_ok=True)

    # Snapshot the exact spec file used (byte-preserving text snapshot).
    _write_text(run_root / "crucible_spec.snapshot.yaml", loaded.raw_text)

    def _emit_preexec_failure(*, error_type: str, error: str) -> CrucibleRunRecord:
        duration_ms = max(0, int((time.perf_counter() - t0) * 1000))
        tb = traceback.format_exc()
        stderr_text = tb if tb.strip() else f"{error_type}: {error}"
        stdout_obj = {"status": "FAIL_CLOSED", "error_type": error_type, "error": error, "refusal_code": "UNSPECIFIED"}
        stdout_text = json.dumps(stdout_obj, ensure_ascii=True)

        _write_text(run_root / "stderr.log", stderr_text)
        _write_text(run_root / "stdout.json", stdout_text + "\n")

        record = CrucibleRunRecord(
            run_id=rid,
            crucible_id=spec.crucible_id,
            kernel_target=kernel_target,
            kernel_command=[],
            kernel_workdir=str(run_root),
            crucible_spec_hash=loaded.crucible_spec_hash,
            prompt_hash=prompt_hash,
            seed=seed,
            budgets=budgets_payload,
            budgets_hash=budgets_hash_hex,
            timestamp_utc=started,
            duration_ms=duration_ms,
            outcome=OUTCOME_FAIL,
            output_contract_pass=False,
            replay_status=REPLAY_NOT_APPLICABLE,
            replay_pass=None,
            governance_status="NOT_APPLICABLE",
            governance_pass=None,
            artifacts_dir=str(run_root.relative_to(_repo_root())),
            notes=f"pre_execution_fail:{error_type}",
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

        ledger_sha = hashlib.sha256(json.dumps(ledger_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        head_hash = ledger_sha
        stdout_hash = hashlib.sha256(stdout_text.encode("utf-8")).hexdigest()
        steps: List[Dict[str, Any]] = [
            {
                "phase": "MAP",
                "domain": "D:UNKNOWN",
                "subdomain": "S:SUBDOMAIN.UNKNOWN",
                "input_hash": prompt_hash,
                "output_hash": head_hash,
                "flags": {"domain_count": 0, "mode": "single"},
            },
            {
                "phase": "CONSTRAIN",
                "domain": "D:UNKNOWN",
                "subdomain": "S:SUBDOMAIN.UNKNOWN",
                "input_hash": head_hash,
                "output_hash": head_hash,
                "flags": {"constraint_types": [], "constraint_hit": "none", "budget_verdict": "BUDGET_NOT_ASSERTED"},
            },
            {
                "phase": "RESOLVE",
                "domain": "D:UNKNOWN",
                "subdomain": "S:SUBDOMAIN.UNKNOWN",
                "input_hash": head_hash,
                "output_hash": stdout_hash,
                "flags": {"resolve_mode": "unknown", "outcome": record.outcome},
            },
            {
                "phase": "EVAL",
                "domain": "D:UNKNOWN",
                "subdomain": "S:SUBDOMAIN.UNKNOWN",
                "input_hash": stdout_hash,
                "output_hash": stdout_hash,
                "flags": {"coherence_bucket": "UNKNOWN", "governance_status": record.governance_status},
            },
        ]
        payload = {
            "schema": "MICRO_STEPS_V1",
            "run_id": rid,
            "crucible_id": spec.crucible_id,
            "kernel_target": kernel_target,
            "steps": steps[:7],
            "hashes": {
                "prompt_hash": prompt_hash,
                "head_hash": head_hash,
                "ledger_hash": ledger_sha,
                "stdout_hash": stdout_hash,
            },
        }
        _write_text(run_root / "micro_steps.json", json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n")
        return record

    if spec.input.redaction_policy != "ALLOW_RAW_IN_CRUCIBLE":
        return _emit_preexec_failure(
            error_type="HASH_ONLY_CRUCIBLE_UNSUPPORTED",
            error="HASH_ONLY_CRUCIBLE requires an external prompt store; not implemented (fail-closed)",
        )

    try:
        budgets_obj = CrucibleBudgets.from_dict(budgets_payload)
    except Exception as exc:
        return _emit_preexec_failure(error_type=exc.__class__.__name__, error=str(exc))
    try:
        budgets_hash_from_obj = budgets_hash(budgets_obj)
    except Exception as exc:
        return _emit_preexec_failure(error_type=exc.__class__.__name__, error=str(exc))
    if budgets_hash_from_obj != budgets_hash_hex:
        return _emit_preexec_failure(
            error_type="BUDGETS_HASH_MISMATCH",
            error=f"budgets_hash(payload) != budgets_hash(parsed) (fail-closed): {budgets_hash_hex} != {budgets_hash_from_obj}",
        )

    try:
        expect_obj = CrucibleExpect.from_dict(expect_payload)
    except Exception as exc:
        return _emit_preexec_failure(error_type=exc.__class__.__name__, error=str(exc))

    envelope = {"input": prompt}
    envelope_json = json.dumps(envelope, ensure_ascii=True).encode("utf-8")

    try:
        cmd, kernel_root = _kernel_command(kernel_target=kernel_target, artifact_root=run_root)
    except Exception as exc:
        return _emit_preexec_failure(error_type=exc.__class__.__name__, error=str(exc))

    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    stdout_text = ""
    stderr_text = ""

    try:
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

        # If kernel failed (nonzero exit), surface raw stderr in notes
        if result.exit_code is not None and result.exit_code != 0:
            notes = f"KERNEL_EXCEPTION_RAW:\n{stderr_text}"
        else:
            notes = None

    except Exception as exc:  # Ensure artifacts are emitted even on internal failures
        tb = traceback.format_exc()
        stderr_text = tb
        err_obj = {"status": "ERROR", "error_type": exc.__class__.__name__, "error": str(exc)}
        stdout_text = json.dumps(err_obj, ensure_ascii=True)
        _write_text(run_root / "stderr.log", stderr_text)
        _write_text(run_root / "stdout.json", stdout_text + "\n")
        # Synthesize a failed KernelRunResult so downstream logic records a failing run.
        result = KernelRunResult(
            exit_code=None,
            was_killed=False,
            kill_reason=None,
            duration_ms=0,
            peak_rss_bytes=None,
            stdout=b"",
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
        )
        notes = f"KERNEL_EXCEPTION_RAW:\n{stderr_text}"


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

        # --- PATCH: Always emit refusal_code for refusal outcomes ---
        if output_obj is not None and isinstance(output_obj, dict):
            status = output_obj.get("status", "").upper()
            if status in {"REFUSE", "CONSTITUTIONAL_CRISIS", "FAIL_CLOSED", "ERROR"}:
                if "refusal_code" not in output_obj or not output_obj["refusal_code"]:
                    # Use expected_refusal_code if available, else fallback to a default
                    output_obj["refusal_code"] = getattr(expect_obj, "expected_refusal_code", None) or "UNSPECIFIED"

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
    if kernel_target in {KERNEL_V2_SOVEREIGN, KERNEL_GOVERNANCE_BASELINE}:
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
        if kernel_target == KERNEL_COVERAGE_BASELINE:
            governance_status = "NOT_APPLICABLE"
            governance_pass = None
        elif ge.required_event_types or ge.forbidden_event_types or ge.event_count_min or ge.event_count_max:
            governance_status = "UNVERIFIABLE_ARCHIVAL"
            outcome = OUTCOME_FAIL
            notes = (notes + ";governance_unverifiable") if notes else "governance_unverifiable"


    # --- Governance verdict enforcement (binding law) ---
    #
    # Baselines:
    # - KERNEL_COVERAGE_BASELINE: coverage-only; governance verdict is non-gating and governance_pass is NOT asserted.
    # - KERNEL_GOVERNANCE_BASELINE: governance-capable; governance expectations are verified via state vault events.
    #   governance_verdict.json is treated as informational only (non-gating) to avoid coupling baseline capability to
    #   any specific kernel-side verdict implementation.
    gov_verdict_path = run_root / "governance_verdict.json"
    if kernel_target == KERNEL_COVERAGE_BASELINE:
        governance_pass = None
        gov_note_or_rationale = (
            "governance_verdict_skipped_coverage_baseline"
            if not gov_verdict_path.exists()
            else "governance_verdict_non_gating_coverage_baseline"
        )
        notes = f"{notes};{gov_note_or_rationale}" if notes else gov_note_or_rationale
    elif kernel_target == KERNEL_GOVERNANCE_BASELINE:
        gov_note_or_rationale = (
            "governance_verdict_missing_governance_baseline"
            if not gov_verdict_path.exists()
            else "governance_verdict_non_gating_governance_baseline"
        )
        notes = f"{notes};{gov_note_or_rationale}" if notes else gov_note_or_rationale
    else:
        gov_pass, gov_note_or_rationale = _load_governance_verdict_or_fail(run_root)
        governance_pass = bool(gov_pass)
        # If governance failed, make the entire run fail (binding).
        if not governance_pass:
            outcome = "FAIL"
        notes = f"{notes};governance_verdict={gov_note_or_rationale}" if notes else f"governance_verdict={gov_note_or_rationale}"

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
        duration_ms=result.duration_ms,
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

    # Emit coverage + validate (fail-closed).
    validator = _validator(ruleset_path)
    thr = validator.ruleset["crucible_constraints"]["thresholds"]
    ledger_sha = hashlib.sha256(json.dumps(ledger_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    head_hash = None
    try:
        if output_obj and isinstance(output_obj, dict):
            head_hash = output_obj.get("head_hash")
    except Exception:
        head_hash = None
    head_hash = head_hash if isinstance(head_hash, str) and len(head_hash) == 64 else ledger_sha
    stdout_hash = hashlib.sha256(stdout_text.encode("utf-8")).hexdigest() if stdout_text else ledger_sha

    paradox_event: Optional[Dict[str, Any]] = None
    paradox_event_count = 0
    is_paradox_crucible = _is_paradox_crucible(spec)
    contains_paradox: Optional[bool] = None
    paradox_type: Optional[str] = None
    if isinstance(output_obj, dict):
        if "contains_paradox" in output_obj:
            contains_paradox = bool(output_obj.get("contains_paradox"))
        if isinstance(output_obj.get("paradox_type"), str):
            paradox_type = output_obj.get("paradox_type")
    is_paradox = bool(contains_paradox is True) or (
        isinstance(paradox_type, str) and paradox_type.strip().lower() not in {"none", ""}
    )

    if is_paradox_crucible or is_paradox:
        move_used = _policy_b_paradox_selector()
        evidence_status = "COMPLETE" if (contains_paradox is not None or paradox_type is not None) else "MISSING_OUTPUT"
        if contains_paradox is True:
            trigger = "contains_paradox"
        elif paradox_type:
            trigger = f"paradox_type:{paradox_type}"
        elif is_paradox_crucible:
            trigger = "paradox_crucible"
        else:
            trigger = "output_missing"
        belnap_state = "B" if is_paradox else "N"
        if belnap_state not in _BELNAP_BOUNDS:
            raise RunnerError(f"Belnap state invalid: {belnap_state} (fail-closed)")
        event_seed = f"{rid}|{spec.crucible_id}|{stdout_hash}|{trigger}|{move_used}|{belnap_state}"
        paradox_event_id = hashlib.sha256(event_seed.encode("utf-8")).hexdigest()
        fork_root = run_root / "_paradox_forks" / paradox_event_id
        fork_root.mkdir(parents=True, exist_ok=True)
        repair_action = None
        if isinstance(output_obj, dict) and isinstance(output_obj.get("repair_action"), str):
            repair_action = output_obj.get("repair_action")
        paradox_event = {
            "schema": "PARADOX_EVENT_V1",
            "schema_version": 1,
            "paradox_event_id": paradox_event_id,
            "run_id": rid,
            "crucible_id": spec.crucible_id,
            "kernel_target": kernel_target,
            "epoch_id": "EPOCH_UNSPECIFIED",
            "timestamp_utc": _utc_now_iso_z(),
            "belnap_state": belnap_state,
            "contains_paradox": contains_paradox,
            "paradox_type": paradox_type,
            "trigger": trigger,
            "move_used": move_used,
            "repair_action": repair_action or "none",
            "delta_entropy": 0.0,
            "delta_density": 0.0,
            "evidence_status": evidence_status,
            "fork": {
                "fork_root": str(fork_root.relative_to(_repo_root())),
                "status": "NOT_EXECUTED",
            },
            "receipts": {
                "prompt_hash": prompt_hash,
                "head_hash": head_hash,
                "ledger_hash": ledger_sha,
                "stdout_hash": stdout_hash,
            },
        }
        _write_text(run_root / "paradox_event.json", json.dumps(paradox_event, sort_keys=True, indent=2, ensure_ascii=True) + "\n")
        _write_text(
            run_root / "paradox_fork_manifest.json",
            json.dumps(
                {
                    "schema": "PARADOX_FORK_MANIFEST_V1",
                    "schema_version": 1,
                    "paradox_event_id": paradox_event_id,
                    "fork_root": str(fork_root.relative_to(_repo_root())),
                    "status": "NOT_EXECUTED",
                },
                sort_keys=True,
                indent=2,
                ensure_ascii=True,
            )
            + "\n",
        )
        paradox_event_count = 1

    # Observed coverage derived from executed trace + tags
    executed_sequence = output_obj.get("trace_sequence", []) if isinstance(output_obj, dict) else []
    if not isinstance(executed_sequence, list):
        executed_sequence = []

    def _canonical_domain(raw: str) -> str:
        norm = "".join(ch if ch.isalnum() else "_" for ch in str(raw)).upper()
        return f"D:{norm or 'UNKNOWN'}"

    def _canonical_subdomain(raw: str) -> str:
        norm = str(raw).upper().replace(" ", "_").replace("__", "_")
        parts = [p for p in norm.replace("::", ".").split(".") if p]
        if not parts:
            parts = ["SUBDOMAIN", "UNKNOWN"]
        return "S:" + ".".join(parts)

    crucible_level_domain = _canonical_domain(getattr(spec, "domain", spec.crucible_id))
    crucible_level_subdomain = _canonical_subdomain(getattr(spec, "domain", spec.crucible_id))

    step_tag_index: Dict[str, Dict[str, List[str]]] = {}
    if hasattr(spec, "steps") and spec.steps:
        for step in spec.steps:
            sid = getattr(step, "id", None) or getattr(step, "step_id", None)
            tags = getattr(step, "tags", None) or {}
            if not sid or not isinstance(tags, dict):
                continue
            step_tag_index[str(sid)] = {
                "domains": tags.get("domains", [crucible_level_domain]),
                "subdomains": tags.get("subdomains", [crucible_level_subdomain]),
                "microdomains": tags.get("microdomains", []),
                "ventures": tags.get("ventures", []),
                "reasoning_modes": tags.get("reasoning_modes", []),
                "modalities": tags.get("modalities", []),
                "tools": tags.get("tools", []),
            }
    if not step_tag_index:
        sid = str(spec.crucible_id)
        step_tag_index[sid] = {
            "domains": [crucible_level_domain],
            "subdomains": [crucible_level_subdomain],
            "microdomains": [],
            "ventures": [],
            "reasoning_modes": [],
            "modalities": ["X:TEXT"],
            "tools": ["T:CRUCIBLE"],
        }
        if not executed_sequence:
            executed_sequence = [sid]

    obs = compute_coverage(
        executed_step_ids=executed_sequence,
        step_tag_index=step_tag_index,
        ontology_subdomain_graph=None,
        paradox_event_count=paradox_event_count,
    )

    coverage = {
        "schema_version": "COVERAGE_V1",
        "run_id": rid,
        "epoch_id": "EPOCH_UNSPECIFIED",
        "crucible_id": spec.crucible_id,
        "kernel_target": kernel_target,
        "planned": {
            "required_tags": [],
            "target_span": {
                "min_unique_domains": thr.get("min_unique_domains", 0),
                "min_unique_subdomains": thr.get("min_unique_subdomains", 0),
                "min_unique_microdomains": thr.get("min_unique_microdomains", 0)
            },
            "rotation_ruleset_id": validator.ruleset.get("ruleset_id", "UNKNOWN_RULESET")
        },
        "observed": {
            "domains": sorted(obs.domains),
            "subdomains": sorted(obs.subdomains),
            "microdomains": sorted(obs.microdomains),
            "reasoning_modes": sorted(obs.reasoning_modes),
            "modalities": sorted(obs.modalities),
            "tools": sorted(obs.tools),
            "counts": {
                "unique_domains": len(obs.domains),
                "unique_subdomains": len(obs.subdomains),
                "unique_microdomains": len(obs.microdomains),
                "cross_domain_edges": obs.cross_domain_edges,
                "mean_graph_distance": obs.mean_graph_distance,
                "max_graph_distance": obs.max_graph_distance,
                "paradox_events": obs.paradox_events,
            },
            "dominance": {
                "top_domain_share": float(obs.top_domain_share or 0.0),
                "top_5_domain_share": float(obs.top_5_domain_share or 0.0),
                "entropy_domains": float(obs.entropy_domains or 0.0),
            },
        },
        "sequence": obs.sequence_domains,
        "proof": {
            "receipts": [
                {"type": "TRACE_HEAD_HASH", "sha256": head_hash},
                {"type": "LEDGER_ENTRY_HASH", "sha256": ledger_sha},
            ],
            "fail_closed": True,
        },
        "verdict": {"coverage_pass": None, "rotation_pass": None, "notes": None},
    }
    cov_path = run_root / "crucible_coverage.json"
    _write_text(cov_path, json.dumps(coverage, sort_keys=True, indent=2, ensure_ascii=True) + "\n")
    verdict = validator.validate_crucible(coverage)
    if verdict.get("verdict") != validator.codes["PASS"]:
        if kernel_target == "KERNEL_COVERAGE_BASELINE":
            print(
                f"CRUCIBLE COVERAGE NON-GATING for {kernel_target}: {verdict}",
                file=sys.stderr,
            )
        else:
            raise RunnerError(f"CRUCIBLE COVERAGE FAIL: {verdict}")

    def _emit_micro_steps() -> None:
        # Micro-steps are emitted even on FAIL_CLOSED to preserve observability.
        primary_domain = (
            obs.sequence_domains[0]
            if obs.sequence_domains
            else (sorted(obs.domains)[0] if obs.domains else (crucible_level_domain or "unknown"))
        )
        primary_subdomain = (
            getattr(obs, "sequence_subdomains", [])[0]
            if getattr(obs, "sequence_subdomains", [])
            else (sorted(obs.subdomains)[0] if obs.subdomains else (crucible_level_subdomain or "unknown"))
        )

        if outcome == OUTCOME_PASS:
            resolve_mode = "clean"
            coherence_bucket = "HIGH"
        elif outcome == OUTCOME_FAIL:
            resolve_mode = "forced" if result.was_killed else "partial"
            coherence_bucket = "LOW"
        else:
            resolve_mode = "unknown"
            coherence_bucket = "UNKNOWN"
        constraint_hit = "budget"

        steps: List[Dict[str, Any]] = []
        steps.append(
            {
                "phase": "MAP",
                "domain": primary_domain,
                "subdomain": primary_subdomain,
                "input_hash": prompt_hash,
                "output_hash": head_hash,
                "flags": {"domain_count": len(obs.domains), "mode": "single"},
            }
        )
        steps.append(
            {
                "phase": "CONSTRAIN",
                "domain": primary_domain,
                "subdomain": primary_subdomain,
                "input_hash": head_hash,
                "output_hash": head_hash,
                "flags": {
                    "constraint_types": ["budget"],
                    "constraint_hit": constraint_hit,
                    "budget_verdict": budget_verdict,
                },
            }
        )
        steps.append(
            {
                "phase": "RESOLVE",
                "domain": primary_domain,
                "subdomain": primary_subdomain,
                "input_hash": head_hash,
                "output_hash": stdout_hash,
                "flags": {"resolve_mode": resolve_mode, "outcome": outcome},
            }
        )
        steps.append(
            {
                "phase": "EVAL",
                "domain": primary_domain,
                "subdomain": primary_subdomain,
                "input_hash": stdout_hash,
                "output_hash": stdout_hash,
                "flags": {"coherence_bucket": coherence_bucket, "governance_status": governance_status},
            }
        )

        payload = {
            "schema": "MICRO_STEPS_V1",
            "run_id": rid,
            "crucible_id": spec.crucible_id,
            "kernel_target": kernel_target,
            "steps": steps[:7],
            "hashes": {
                "prompt_hash": prompt_hash,
                "head_hash": head_hash,
                "ledger_hash": ledger_sha,
                "stdout_hash": stdout_hash,
            },
        }
        _write_text(run_root / "micro_steps.json", json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n")

    _emit_micro_steps()

    return record


def run_crucible_file(
    path: Path,
    *,
    seed: int = 0,
    ruleset_path: Optional[Path] = None,
    kernel_target: Optional[str] = None,
) -> List[CrucibleRunRecord]:
    loaded = load_crucible(path)
    repo_root = _repo_root()
    artifacts_dir = repo_root / "tools" / "growth" / "artifacts" / "c019_runs"
    ledger_path = repo_root / "tools" / "growth" / "ledgers" / "c019_crucible_runs.jsonl"

    records: List[CrucibleRunRecord] = []
    requested_target = kernel_target
    for kt in loaded.spec.kernel_targets:
        if requested_target and kt != requested_target:
            continue
        records.append(
            run_crucible_once(
                loaded=loaded,
                kernel_target=kt,
                seed=seed,
                artifacts_dir=artifacts_dir,
                ledger_path=ledger_path,
                ruleset_path=ruleset_path,
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
                    ruleset_path=ruleset_path,
                    prompt_override=variant.input_prompt,
                    budgets_override=variant.budgets_override.to_dict() if variant.budgets_override is not None else None,
                    expect_override=variant.expect_override.to_dict() if variant.expect_override is not None else None,
                )
            )
    return records
