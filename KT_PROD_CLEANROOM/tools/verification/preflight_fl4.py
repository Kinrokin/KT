from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import platform
import hashlib
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from schemas.schema_files import schema_version_hash
from tools.training.fl3_factory.hashing import sha256_file_normalized
from tools.verification.fl3_canonical import repo_root_from, sha256_json
from tools.verification.fl3_validators import FL3ValidationError, load_fl3_canonical_runtime_paths, validate_schema_bound_object
from tools.verification.io_guard import IOGuard, IOGuardConfig
from tools.verification.watcher_spc_validators import (
    assert_runtime_registry_has_no_watcher_spc,
    validate_watcher_spc_artifacts_if_present,
)


def _run(cmd: List[str], *, cwd: Path, env: Dict[str, str], out_path: Optional[Path] = None) -> Tuple[int, str]:
    p = subprocess.run(cmd, cwd=str(cwd), env=env, text=True, capture_output=True)
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(p.stdout + p.stderr, encoding="utf-8")
    if p.returncode != 0:
        raise SystemExit(f"FAIL: {' '.join(cmd)} rc={p.returncode}")
    return p.returncode, (p.stdout + p.stderr)


def _append_transcript(path: Path, *, cmd: List[str], rc: int, output: str) -> None:
    # Transcript is evidence, not a determinism surface. Keep it explicit and append-only.
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    lines.append("CMD: " + " ".join(cmd))
    lines.append(f"RC: {rc}")
    if output.strip():
        lines.append("OUTPUT:")
        lines.append(output.rstrip())
    lines.append("")
    path.write_text(path.read_text(encoding="utf-8") + "\n".join(lines) + "\n" if path.exists() else "\n".join(lines) + "\n", encoding="utf-8")


def _git_status_clean(repo_root: Path) -> None:
    out = subprocess.check_output(["git", "status", "--porcelain"], cwd=str(repo_root), text=True)
    if out.strip():
        raise SystemExit(f"FAIL: repo is not clean (git status --porcelain non-empty):\n{out}")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _assert_evidence_pack_complete(*, out_dir: Path) -> None:
    required_top = (
        "command_transcript.txt",
        "pip_freeze.txt",
        "seal_doctrine.md",
        "env_lock.json",
        "io_guard_receipt.json",
        "supported_platforms.json",
        "determinism_contract.json",
        "law_bundle_hash.txt",
        "law_bundle.json",
        "growth_e2e_gate_report.json",
        "behavioral_growth_summary.json",
        "meta_evaluator_receipt.json",
        "red_assault_report.json",
        "rollback_drill_report.json",
        "canary_artifact_pre.json",
        "canary_artifact_rerun.json",
        "canary_artifact_post_promotion.json",
        "metabolism_proof.json",
        "replay_from_receipts_report.json",
        "preflight_summary.json",
    )
    required_job_dir = (
        "job.json",
        "phase_trace.json",
        "dataset.json",
        "eval_report.json",
        "signal_quality.json",
        "judgement.json",
        "promotion.json",
        "hash_manifest.json",
        "job_dir_manifest.json",
    )

    missing: List[str] = []
    for name in required_top:
        p = out_dir / name
        if not p.exists():
            missing.append(name)
        elif p.is_file() and p.stat().st_size == 0:
            missing.append(name + " (empty)")

    evidence_job_dir = out_dir / "job_dir"
    if not evidence_job_dir.exists():
        missing.append("job_dir/ (missing)")
    else:
        for name in required_job_dir:
            p = evidence_job_dir / name
            if not p.exists():
                missing.append(f"job_dir/{name}")
            elif p.is_file() and p.stat().st_size == 0:
                missing.append(f"job_dir/{name} (empty)")

    # Behavioral growth certificate (fail-closed).
    growth_dir = out_dir / "behavioral_growth"
    if not growth_dir.exists():
        missing.append("behavioral_growth/ (missing)")
    else:
        required_growth = (
            "H0.json",
            "E.json",
            "H1.json",
            "growth_protocol.json",
            "scores_H0.json",
            "scores_H1.json",
            "state_event.json",
            "growth_claim.json",
            "_tmp/state_payloads/ (missing)",
            "_tmp/state_ledger.jsonl",
        )
        for name in required_growth:
            if name.endswith("/ (missing)"):
                d = growth_dir / name.replace("/ (missing)", "")
                if not d.exists():
                    missing.append(f"behavioral_growth/{name}")
                continue
            p = growth_dir / name
            if not p.exists():
                missing.append(f"behavioral_growth/{name}")
            elif p.is_file() and p.stat().st_size == 0:
                missing.append(f"behavioral_growth/{name} (empty)")

    # Promotion is conditional; if promotion was attempted, its report must exist.
    promotion_report = out_dir / "promotion_report.json"
    if promotion_report.exists() and promotion_report.stat().st_size == 0:
        missing.append("promotion_report.json (empty)")

    if missing:
        raise SystemExit("FAIL: evidence pack incomplete (fail-closed):\n" + "\n".join("- " + m for m in sorted(missing)))


def _enforce_env_lock(*, repo_root: Path, env_for_subprocess: Dict[str, str], out_dir: Path) -> Dict[str, Any]:
    from tools.verification.strict_json import DuplicateKeyError, load_no_dupes

    lock_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FL4_ENV_LOCK.json"
    if not lock_path.exists():
        raise SystemExit(f"FAIL: missing env lock contract (fail-closed): {lock_path.as_posix()}")
    try:
        lock = load_no_dupes(lock_path)
    except DuplicateKeyError as e:
        raise SystemExit(f"FAIL: env lock JSON has duplicate keys (fail-closed): {e}")
    if not isinstance(lock, dict):
        raise SystemExit("FAIL: env lock contract must be JSON object (fail-closed)")
    validate_schema_bound_object(lock)

    required: Dict[str, str] = dict(lock.get("required") or {})
    forbidden: Dict[str, str] = dict(lock.get("forbidden") or {})
    forbidden_prefixes: List[str] = list(lock.get("forbidden_prefixes") or [])
    allow_extra: List[str] = list(lock.get("allow_extra") or [])

    host_env = os.environ

    def _write_env_mismatch_receipt(*, reason: str, details: Dict[str, Any]) -> None:
        payload = {
            "schema_id": "kt.env_mismatch_receipt.v1",
            "reason": reason,
            "details": details,
        }
        (out_dir / "env_mismatch_receipt.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

    # Forbidden keys/prefixes apply to the host environment (fail-closed).
    for k in forbidden.keys():
        if k in host_env:
            _write_env_mismatch_receipt(reason="forbidden_key_present", details={"key": k, "value": str(host_env.get(k))})
            raise SystemExit(f"FAIL: forbidden env var present (fail-closed): {k}")
    for prefix in forbidden_prefixes:
        for k in host_env.keys():
            if k.startswith(prefix):
                _write_env_mismatch_receipt(reason="forbidden_prefix_present", details={"key": k, "prefix": prefix})
                raise SystemExit(f"FAIL: forbidden env var prefix present (fail-closed): {k}")

    # Required keys must exist on the host env and match exactly (strict host contract).
    for k, v in required.items():
        if k not in host_env:
            _write_env_mismatch_receipt(reason="required_key_missing", details={"key": k, "expected": v})
            raise SystemExit(f"FAIL: required env var missing (fail-closed): {k} expected {v!r}")
        if str(host_env.get(k)) != v:
            _write_env_mismatch_receipt(reason="required_key_mismatch", details={"key": k, "got": str(host_env.get(k)), "expected": v})
            raise SystemExit(f"FAIL: required env var mismatch (fail-closed): {k}={host_env.get(k)!r} expected {v!r}")
        env_for_subprocess[k] = v

    # Seal lane: prevent drift in key namespaces (KT/PYTHON/TRANSFORMERS/TOKENIZERS).
    tracked_prefixes = ("KT_", "PYTHON", "TRANSFORMERS_", "TOKENIZERS_")
    required_set = set(required.keys())
    allow_set = set(allow_extra)
    for k in host_env.keys():
        if k.startswith(tracked_prefixes) and k not in required_set and k not in allow_set:
            _write_env_mismatch_receipt(reason="undeclared_tracked_env", details={"key": k})
            raise SystemExit(f"FAIL: undeclared env var in tracked namespace (fail-closed): {k}")

    # Evidence copy (schema-bound) for offline audit.
    (out_dir / "env_lock.json").write_text(
        json.dumps(lock, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return lock


def _mk_min_contract(repo_root: Path) -> Dict[str, Any]:
    run_job_rel = "KT_PROD_CLEANROOM/tools/training/fl3_factory/run_job.py"
    ep = {"run_job": {"path": run_job_rel, "sha256": sha256_file_normalized(repo_root / run_job_rel)}}

    # Canonical outputs for the FL4 factory lane.
    allowed_out = sorted(
        [
            "kt.factory.jobspec.v1",
            "kt.factory.dataset.v1",
            "kt.reasoning_trace.v1",
            "kt.factory.judgement.v1",
            "kt.factory.train_manifest.v1",
            # MRT-0 hypothesis generator output (schema-bound records in hypotheses/).
            "kt.policy_bundle.v1",
            "kt.factory.eval_report.v2",
            "kt.signal_quality.v1",
            "kt.immune_snapshot.v1",
            "kt.epigenetic_summary.v1",
            "kt.fitness_region.v1",
            "kt.factory.promotion.v1",
            "kt.factory.phase_trace.v1",
            "kt.hash_manifest.v1",
            "kt.factory.job_dir_manifest.v1",
        ]
    )

    c: Dict[str, Any] = {
        "schema_id": "kt.factory.organ_contract.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.organ_contract.v1.json"),
        "contract_id": "",
        "entrypoints": ep,
        "allowed_base_models": ["mistral-7b"],
        "allowed_training_modes": ["head_only"],
        "allowed_output_schemas": allowed_out,
        "allowed_export_roots": [
            "KT_PROD_CLEANROOM/exports/adapters",
            "KT_PROD_CLEANROOM/exports/adapters_shadow",
        ],
        "created_at": "1970-01-01T00:00:00Z",
    }
    c["contract_id"] = sha256_json({k: v for k, v in c.items() if k not in {"created_at", "contract_id"}})
    validate_schema_bound_object(c)
    return c


def _mk_jobspec(*, export_shadow_root: str, export_promoted_root: str, mode: str) -> Dict[str, Any]:
    job: Dict[str, Any] = {
        "schema_id": "kt.factory.jobspec.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.jobspec.v1.json"),
        "job_id": "",
        "adapter_id": "fl4.mrt0.factory_lane.v1",
        "adapter_version": "1",
        "role": "ARCHITECT",
        "mode": mode,
        "run_kind": "STANDARD",
        "base_model_id": "mistral-7b",
        "training_mode": "head_only",
        "seed": 42,
        "export_shadow_root": export_shadow_root,
        "export_promoted_root": export_promoted_root,
    }
    job["job_id"] = sha256_json({k: v for k, v in job.items() if k != "job_id"})
    validate_schema_bound_object(job)
    return job


def _load_hash_manifest_root_hash(job_dir: Path) -> str:
    hm = json.loads((job_dir / "hash_manifest.json").read_text(encoding="utf-8"))
    if not isinstance(hm, dict):
        raise SystemExit("FAIL: hash_manifest.json not a JSON object (fail-closed)")
    validate_schema_bound_object(hm)
    root = str(hm.get("root_hash") or "")
    if len(root) != 64:
        raise SystemExit("FAIL: hash_manifest.root_hash missing/invalid (fail-closed)")
    return root


def _mk_metabolism_proof(*, base_job_id: str, perturbations: List[Dict[str, str]]) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "schema_id": "kt.metabolism_proof.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.metabolism_proof.v1.json"),
        "proof_id": "",
        "base_job_id": base_job_id,
        "perturbations": perturbations,
        "assertions": {
            "all_schema_valid": True,
            "roots_distinct": True,
        },
        "created_at": "1970-01-01T00:00:00Z",
    }
    record["proof_id"] = sha256_json({k: v for k, v in record.items() if k not in {"proof_id", "created_at"}})
    validate_schema_bound_object(record)
    return record


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="FL4 preflight runner (canonical factory lane, MRT-0).")
    ap.add_argument("--out-dir", default="", help="Write evidence under this directory (default: exports/_runs/FL4_SEAL/<ts>/).")
    ap.add_argument("--registry-path", default="", help="Runtime registry path (default: from FL3_CANONICAL_RUNTIME_PATHS.json).")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = repo_root_from(Path(__file__))

    _git_status_clean(repo_root)
    py_exe = sys.executable

    # Canonical Python surface for cleanroom.
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src") + os.pathsep + str(
        repo_root / "KT_PROD_CLEANROOM"
    )
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")

    paths = load_fl3_canonical_runtime_paths(repo_root=repo_root)
    reg_path = str(args.registry_path or paths["runtime_registry_path"])
    reg_file = Path(reg_path)
    if not reg_file.is_absolute():
        reg_file = repo_root / reg_file
    assert_runtime_registry_has_no_watcher_spc(registry_path=reg_file.resolve())

    # Supported platforms / determinism scope: fail closed if current platform is out of scope.
    supported = json.loads((repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FL4_SUPPORTED_PLATFORMS.json").read_text("utf-8"))
    validate_schema_bound_object(supported)
    os_claim = str(supported.get("os", ""))
    py_claim = str(supported.get("python", ""))
    host_os = platform.system().lower()
    if "linux" not in os_claim.lower() or host_os != "linux":
        raise SystemExit(f"FAIL: preflight must run on linux to match supported_platforms.os (got {platform.system()})")
    if not (sys.version_info.major == 3 and 10 <= sys.version_info.minor < 12):
        raise SystemExit(f"FAIL: preflight python version out of supported_platforms.python scope (got {sys.version.split()[0]})")
    container_digest = supported.get("container_image_sha256")
    if container_digest is not None:
        witness = os.environ.get("KT_CONTAINER_IMAGE_SHA256", "")
        if witness != container_digest:
            raise SystemExit("FAIL: container binding declared but KT_CONTAINER_IMAGE_SHA256 witness missing/mismatched (fail-closed)")

    # Evidence root (ignored by git via exports/**).
    if args.out_dir:
        out_dir = (repo_root / args.out_dir).resolve()
    else:
        import datetime

        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        out_dir = (repo_root / "KT_PROD_CLEANROOM" / "exports" / "adapters_shadow" / "_runs" / "FL4_SEAL" / ts).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    transcript_path = out_dir / "command_transcript.txt"
    # Seal lane: force all temp usage under the evidence root to avoid undeclared filesystem I/O.
    tmp_dir = (out_dir / "_tmp").resolve()
    tmp_dir.mkdir(parents=True, exist_ok=True)
    # Do not mutate the host env; only constrain subprocess env and this process' tempfile root.
    env["TMPDIR"] = tmp_dir.as_posix()
    env["TMP"] = tmp_dir.as_posix()
    env["TEMP"] = tmp_dir.as_posix()
    tempfile.tempdir = str(tmp_dir)

    # Phase 0: doctrine + execution surface contract (evidence, then enforce).
    doctrine_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FL4_SEAL_DOCTRINE.md"
    if not doctrine_path.exists():
        raise SystemExit(f"FAIL: missing FL4 seal doctrine (fail-closed): {doctrine_path.as_posix()}")
    (out_dir / "seal_doctrine.md").write_text(doctrine_path.read_text(encoding="utf-8"), encoding="utf-8")
    doctrine_hash = _sha256_file(doctrine_path)

    env_lock = _enforce_env_lock(repo_root=repo_root, env_for_subprocess=env, out_dir=out_dir)
    # Seal mode applies to all subprocesses launched by this preflight lane.
    env["KT_SEAL_MODE"] = "1"

    # Evidence: record the exact python environment used for the seal run.
    rc, out = _run([py_exe, "-m", "pip", "freeze"], cwd=repo_root, env=env)
    (out_dir / "pip_freeze.txt").write_text(out if out.endswith("\n") else out + "\n", encoding="utf-8")
    _append_transcript(transcript_path, cmd=[py_exe, "-m", "pip", "freeze"], rc=rc, output=out)

    # Seal lane I/O guard: fail-closed on network attempts and on writes outside allowlisted roots.
    exports_shadow = (repo_root / str(paths["exports_shadow_root"])).resolve()
    exports_adapters = (repo_root / str(paths["exports_adapters_root"])).resolve()
    allowed_write_roots = [
        out_dir.resolve(),
        exports_shadow,
        exports_adapters,
    ]
    # Propagate to subprocesses via sitecustomize (KT_PROD_CLEANROOM/sitecustomize.py).
    env["KT_IO_GUARD"] = "1"
    env["KT_IO_GUARD_DENY_NETWORK"] = "1"
    env["KT_IO_GUARD_ALLOWED_WRITE_ROOTS"] = json.dumps([p.as_posix() for p in allowed_write_roots], sort_keys=True)
    env["KT_IO_GUARD_RECEIPT_PATH"] = (out_dir / "io_guard_receipt.json").as_posix()

    # Full seal lane (tests + verifiers + growth + canary + factory + promotion) under fail-closed I/O guard.
    with IOGuard(
        IOGuardConfig(
            allowed_write_roots=tuple(allowed_write_roots),
            deny_network=True,
            receipt_path=out_dir / "io_guard_receipt.json",
        )
    ):
        # 1) Whole-KT test battery
        rc, out = _run(
            [py_exe, "-m", "pytest", "-p", "no:cacheprovider", "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests", "-q"],
            cwd=repo_root,
            env=env,
            out_path=out_dir / "pytest_temple.log",
        )
        _append_transcript(
            transcript_path,
            cmd=[py_exe, "-m", "pytest", "-p", "no:cacheprovider", "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests", "-q"],
            rc=rc,
            output=out,
        )
        rc, out = _run(
            [py_exe, "-m", "pytest", "-p", "no:cacheprovider", "KT_PROD_CLEANROOM/tests", "-q"],
            cwd=repo_root,
            env=env,
            out_path=out_dir / "pytest_cleanroom.log",
        )
        _append_transcript(transcript_path, cmd=[py_exe, "-m", "pytest", "-p", "no:cacheprovider", "KT_PROD_CLEANROOM/tests", "-q"], rc=rc, output=out)

        # 2) Governance verifiers
        rc, out = _run(
            [py_exe, "-m", "tools.verification.fl3_meta_evaluator", "--write-receipt", str(out_dir / "meta_evaluator_receipt.json")],
            cwd=repo_root,
            env=env,
            out_path=out_dir / "meta_evaluator.log",
        )
        _append_transcript(transcript_path, cmd=[py_exe, "-m", "tools.verification.fl3_meta_evaluator", "--write-receipt", str(out_dir / "meta_evaluator_receipt.json")], rc=rc, output=out)
        rc, out = _run([py_exe, "-m", "tools.verification.fl3_red_assault", "--out", str(out_dir / "red_assault_report.json")], cwd=repo_root, env=env)
        _append_transcript(transcript_path, cmd=[py_exe, "-m", "tools.verification.fl3_red_assault", "--out", str(out_dir / "red_assault_report.json")], rc=rc, output=out)
        rc, out = _run(
            [
                py_exe,
                "-m",
                "tools.verification.fl3_rollback_drill",
                "--registry-path",
                reg_path,
                "--out",
                str(out_dir / "rollback_drill_report.json"),
            ],
            cwd=repo_root,
            env=env,
        )
        _append_transcript(transcript_path, cmd=[py_exe, "-m", "tools.verification.fl3_rollback_drill", "--registry-path", reg_path, "--out", str(out_dir / "rollback_drill_report.json")], rc=rc, output=out)

        # 3) FL3 pressure growth gate (required by protocol; fail-closed on any failure).
        growth_report = out_dir / "growth_e2e_gate_report.json"
        growth_cmd = [py_exe, "-m", "tools.verification.growth_e2e_gate", "--pressure-runs", "1", "--out", str(growth_report)]
        p = subprocess.run(growth_cmd, cwd=str(repo_root), env=env, text=True, capture_output=True)
        (out_dir / "growth_e2e_gate.log").write_text(p.stdout + p.stderr, encoding="utf-8")
        _append_transcript(transcript_path, cmd=growth_cmd, rc=p.returncode, output=p.stdout + p.stderr)
        if not growth_report.exists():
            raise SystemExit("FAIL_CLOSED: growth_e2e_gate did not create growth_e2e_gate_report.json (fail-closed)")
        if p.returncode != 0:
            raise SystemExit(f"FAIL_CLOSED: growth_e2e_gate rc={p.returncode} (fail-closed)")

        # 3b) Behavioral growth certificate (deterministic; fail-closed).
        bg_dir = (out_dir / "behavioral_growth").resolve()
        bg_cmd = [
            py_exe,
            "-m",
            "tools.verification.fl4_behavioral_growth",
            "--out-dir",
            str(bg_dir),
            "--seed",
            "0",
            "--min-delta",
            "0.4",
            "--max-p-value",
            "0.01",
        ]
        rc, out = _run(bg_cmd, cwd=repo_root, env=env, out_path=out_dir / "behavioral_growth.log")
        _append_transcript(transcript_path, cmd=bg_cmd, rc=rc, output=out)
        (out_dir / "behavioral_growth_summary.json").write_text(out if out.endswith("\n") else out + "\n", encoding="utf-8", newline="\n")

        # 4) Build ephemeral organ contract and run determinism canary + one sovereign job.
        contract = _mk_min_contract(repo_root)
        contract_path = out_dir / "organ_contract.json"
        contract_path.write_text(json.dumps(contract, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

        # Determinism canary: run twice (rerun determinism proof) before promotion.
        canary_pre = out_dir / "canary_artifact_pre.json"
        canary_rerun = out_dir / "canary_artifact_rerun.json"

        rc, out = _run(
            [
                py_exe,
                "-m",
                "tools.verification.fl4_determinism_canary",
                "--organ-contract",
                str(contract_path),
                "--out",
                str(canary_pre),
            ],
            cwd=repo_root,
            env=env,
        )
        _append_transcript(transcript_path, cmd=[py_exe, "-m", "tools.verification.fl4_determinism_canary", "--organ-contract", str(contract_path), "--out", str(canary_pre)], rc=rc, output=out)

        rc, out = _run(
            [
                py_exe,
                "-m",
                "tools.verification.fl4_determinism_canary",
                "--organ-contract",
                str(contract_path),
                "--out",
                str(canary_rerun),
            ],
            cwd=repo_root,
            env=env,
        )
        _append_transcript(transcript_path, cmd=[py_exe, "-m", "tools.verification.fl4_determinism_canary", "--organ-contract", str(contract_path), "--out", str(canary_rerun)], rc=rc, output=out)

        pre_obj = json.loads(canary_pre.read_text(encoding="utf-8"))
        rerun_obj = json.loads(canary_rerun.read_text(encoding="utf-8"))
        validate_schema_bound_object(pre_obj)
        validate_schema_bound_object(rerun_obj)
        if pre_obj.get("hash_manifest_root_hash") != rerun_obj.get("hash_manifest_root_hash"):
            raise SystemExit("FAIL: determinism rerun mismatch (canary root hash differs, fail-closed)")

        # Run one sovereign factory job (expected to produce PROMOTE decision, then promote atomically).
        export_shadow_root = str(paths["exports_shadow_root"]).replace("\\", "/").rstrip("/") + "/_runs/FL4_SEAL"
        export_promoted_root = str(paths["exports_adapters_root"]).replace("\\", "/").rstrip("/") + "/_runs/FL4_SEAL"
        job = _mk_jobspec(export_shadow_root=export_shadow_root, export_promoted_root=export_promoted_root, mode="SOVEREIGN")
        job_path = out_dir / "job.json"
        job_path.write_text(json.dumps(job, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

        rc, out = _run(
            [py_exe, "-m", "tools.training.fl3_factory.run_job", "--job", str(job_path), "--organ-contract", str(contract_path)],
            cwd=repo_root,
            env=env,
            out_path=out_dir / "factory_job.log",
        )
        _append_transcript(transcript_path, cmd=[py_exe, "-m", "tools.training.fl3_factory.run_job", "--job", str(job_path), "--organ-contract", str(contract_path)], rc=rc, output=out)

        job_dir = (repo_root / export_shadow_root / job["job_id"]).resolve()
        if not job_dir.exists():
            raise SystemExit(f"FAIL: expected job_dir missing (fail-closed): {job_dir.as_posix()}")

        # Verify the job_dir explicitly.
        rc, out = _run([py_exe, "-m", "tools.verification.fl3_meta_evaluator", "--verify-job-dir", str(job_dir)], cwd=repo_root, env=env)
        _append_transcript(transcript_path, cmd=[py_exe, "-m", "tools.verification.fl3_meta_evaluator", "--verify-job-dir", str(job_dir)], rc=rc, output=out)

        # Metabolism proof (MRT-0): controlled perturbations must produce different hash-manifest roots.
        base_root = _load_hash_manifest_root_hash(job_dir)
        pert_runs: List[Dict[str, str]] = []

        # Perturbation A: dataset/hypothesis seed + 1.
        job_a = dict(job)
        job_a["seed"] = int(job_a["seed"]) + 1
        job_a["job_id"] = sha256_json({k: v for k, v in job_a.items() if k != "job_id"})
        job_a_path = out_dir / "job_perturb_seed_plus_1.json"
        job_a_path.write_text(json.dumps(job_a, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
        rc, out = _run([py_exe, "-m", "tools.training.fl3_factory.run_job", "--job", str(job_a_path), "--organ-contract", str(contract_path)], cwd=repo_root, env=env)
        _append_transcript(transcript_path, cmd=[py_exe, "-m", "tools.training.fl3_factory.run_job", "--job", str(job_a_path), "--organ-contract", str(contract_path)], rc=rc, output=out)
        job_a_dir = (repo_root / export_shadow_root / job_a["job_id"]).resolve()
        rc, out = _run([py_exe, "-m", "tools.verification.fl3_meta_evaluator", "--verify-job-dir", str(job_a_dir)], cwd=repo_root, env=env)
        _append_transcript(transcript_path, cmd=[py_exe, "-m", "tools.verification.fl3_meta_evaluator", "--verify-job-dir", str(job_a_dir)], rc=rc, output=out)
        pert_runs.append({"name": "seed_plus_1", "job_id": str(job_a["job_id"]), "hash_manifest_root_hash": _load_hash_manifest_root_hash(job_a_dir)})

        # Perturbation B: role variant (semantic axis) while keeping seed constant.
        job_b = dict(job)
        job_b["role"] = "CRITIC"
        job_b["job_id"] = sha256_json({k: v for k, v in job_b.items() if k != "job_id"})
        job_b_path = out_dir / "job_perturb_role_critic.json"
        job_b_path.write_text(json.dumps(job_b, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
        rc, out = _run([py_exe, "-m", "tools.training.fl3_factory.run_job", "--job", str(job_b_path), "--organ-contract", str(contract_path)], cwd=repo_root, env=env)
        _append_transcript(transcript_path, cmd=[py_exe, "-m", "tools.training.fl3_factory.run_job", "--job", str(job_b_path), "--organ-contract", str(contract_path)], rc=rc, output=out)
        job_b_dir = (repo_root / export_shadow_root / job_b["job_id"]).resolve()
        rc, out = _run([py_exe, "-m", "tools.verification.fl3_meta_evaluator", "--verify-job-dir", str(job_b_dir)], cwd=repo_root, env=env)
        _append_transcript(transcript_path, cmd=[py_exe, "-m", "tools.verification.fl3_meta_evaluator", "--verify-job-dir", str(job_b_dir)], rc=rc, output=out)
        pert_runs.append({"name": "role_critic", "job_id": str(job_b["job_id"]), "hash_manifest_root_hash": _load_hash_manifest_root_hash(job_b_dir)})

        roots = [base_root] + [r["hash_manifest_root_hash"] for r in pert_runs]
        if len(set(roots)) != len(roots):
            raise SystemExit("FAIL: metabolism proof failed; perturbations did not change hash_manifest root (fail-closed)")

        metabolism_proof = _mk_metabolism_proof(base_job_id=str(job["job_id"]), perturbations=pert_runs)
        (out_dir / "metabolism_proof.json").write_text(json.dumps(metabolism_proof, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

        # Promote if decision is PROMOTE.
        promotion = json.loads((job_dir / "promotion.json").read_text(encoding="utf-8"))
        if isinstance(promotion, dict) and promotion.get("decision") == "PROMOTE":
            _run(
                [
                    py_exe,
                    "-m",
                    "tools.verification.fl4_promote",
                    "--job-dir",
                    str(job_dir),
                    "--canary-artifact",
                    str(canary_pre),
                    "--out",
                    str(out_dir / "promotion_report.json"),
                ],
                cwd=repo_root,
                env=env,
            )

        # Post-promotion determinism canary (fresh process) must still match.
        canary_post = out_dir / "canary_artifact_post_promotion.json"
        rc, out = _run(
            [
                py_exe,
                "-m",
                "tools.verification.fl4_determinism_canary",
                "--organ-contract",
                str(contract_path),
                "--out",
                str(canary_post),
            ],
            cwd=repo_root,
            env=env,
        )
        _append_transcript(transcript_path, cmd=[py_exe, "-m", "tools.verification.fl4_determinism_canary", "--organ-contract", str(contract_path), "--out", str(canary_post)], rc=rc, output=out)
        post_obj = json.loads(canary_post.read_text(encoding="utf-8"))
        validate_schema_bound_object(post_obj)
        if pre_obj.get("hash_manifest_root_hash") != post_obj.get("hash_manifest_root_hash"):
            raise SystemExit("FAIL: post-promotion canary mismatch (fail-closed)")

        # Copy canonical artifacts into the evidence root for simple offline review.
        # This does not affect determinism; it is audit packaging.
        evidence_dir = out_dir / "job_dir"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        for name in (
            "job.json",
            "phase_trace.json",
            "dataset.json",
            "reasoning_trace.json",
            "train_manifest.json",
            "eval_report.json",
            "signal_quality.json",
            "judgement.json",
            "promotion.json",
            "hash_manifest.json",
            "job_dir_manifest.json",
            "immune_snapshot.json",
            "epigenetic_summary.json",
            "fitness_region.json",
        ):
            src = job_dir / name
            if src.exists():
                (evidence_dir / name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

        # Copy global contracts/law pins into evidence.
        (out_dir / "determinism_contract.json").write_text((repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FL4_DETERMINISM_CONTRACT.json").read_text(encoding="utf-8"), encoding="utf-8")
        (out_dir / "supported_platforms.json").write_text((repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FL4_SUPPORTED_PLATFORMS.json").read_text(encoding="utf-8"), encoding="utf-8")
        (out_dir / "law_bundle_hash.txt").write_text((repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.sha256").read_text(encoding="utf-8"), encoding="utf-8")
        (out_dir / "law_bundle.json").write_text((repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.json").read_text(encoding="utf-8"), encoding="utf-8")

        # Persist a compact summary for proof packaging.
        try:
            out_dir_rel = out_dir.relative_to(repo_root).as_posix()
        except ValueError:
            # Seal/evidence output directories are allowed to live outside the repo root (e.g. Kaggle /kaggle/working).
            # This is an audit packaging detail and must not fail the preflight lane.
            out_dir_rel = out_dir.as_posix()
        summary = {
            "schema_id": "kt.fl4.preflight_summary.v1",
            "schema_version_hash": schema_version_hash("fl3/kt.fl4.preflight_summary.v1.json"),
            "git_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(repo_root), text=True).strip(),
            "out_dir": out_dir_rel,
            "registry_path": reg_path,
            "job_id": job["job_id"],
            "job_dir": job_dir.as_posix(),
            "evidence_job_dir": (out_dir / "job_dir").as_posix(),
            "seal_doctrine_sha256": doctrine_hash,
            "env_lock_id": str(env_lock.get("env_lock_id")),
            "fl3_pressure_growth_gate": {"executed": True, "receipt": "growth_e2e_gate_report.json"},
        }
        try:
            bg_obj = json.loads((out_dir / "behavioral_growth_summary.json").read_text(encoding="utf-8"))
            if isinstance(bg_obj, dict):
                summary["behavioral_growth"] = bg_obj
        except Exception:
            pass
        promotion_report = out_dir / "promotion_report.json"
        if promotion_report.exists():
            try:
                pr = json.loads(promotion_report.read_text(encoding="utf-8"))
                if isinstance(pr, dict):
                    if "promoted_dir" in pr:
                        summary["promoted_dir"] = str(pr.get("promoted_dir"))
                    if "promoted_index_path" in pr:
                        summary["promoted_index_path"] = str(pr.get("promoted_index_path"))
            except Exception:
                pass
        validate_schema_bound_object(summary)
        (out_dir / "preflight_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

        # 5) Replay from receipts (deterministic; fail-closed). This is a verifier, not a seal run.
        replay_report = out_dir / "replay_from_receipts_report.json"
        rc, out = _run(
            [py_exe, "-m", "tools.verification.fl4_replay_from_receipts", "--evidence-dir", str(out_dir), "--out", str(replay_report)],
            cwd=repo_root,
            env=env,
            out_path=out_dir / "replay_from_receipts.log",
        )
        _append_transcript(
            transcript_path,
            cmd=[py_exe, "-m", "tools.verification.fl4_replay_from_receipts", "--evidence-dir", str(out_dir), "--out", str(replay_report)],
            rc=rc,
            output=out,
        )

        # 6) Watcher/SPC NCON enforcement (conditional; fail-closed if malformed artifacts are present).
        validate_watcher_spc_artifacts_if_present(evidence_dir=out_dir)

        # Evidence pack completeness contract (fail-closed).
        _assert_evidence_pack_complete(out_dir=out_dir)

        # Seal lane must leave repo clean (fail-closed).
        _git_status_clean(repo_root)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
