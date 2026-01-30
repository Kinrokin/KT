from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import platform
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from schemas.schema_files import schema_version_hash
from tools.training.fl3_factory.hashing import sha256_file_normalized
from tools.verification.fl3_canonical import repo_root_from, sha256_json
from tools.verification.fl3_validators import FL3ValidationError, load_fl3_canonical_runtime_paths, validate_schema_bound_object


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


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="FL4 preflight runner (canonical factory lane, MRT-0).")
    ap.add_argument("--out-dir", default="", help="Write evidence under this directory (default: exports/_runs/FL4_SEAL/<ts>/).")
    ap.add_argument("--registry-path", default="", help="Runtime registry path (default: from FL3_CANONICAL_RUNTIME_PATHS.json).")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = repo_root_from(Path(__file__))

    _git_status_clean(repo_root)

    # Canonical Python surface for cleanroom.
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src") + os.pathsep + str(
        repo_root / "KT_PROD_CLEANROOM"
    )
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")

    paths = load_fl3_canonical_runtime_paths(repo_root=repo_root)
    reg_path = str(args.registry_path or paths["runtime_registry_path"])

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

    # 1) Whole-KT test battery
    rc, out = _run(
        ["python", "-m", "pytest", "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests", "-q"],
        cwd=repo_root,
        env=env,
        out_path=out_dir / "pytest_temple.log",
    )
    _append_transcript(transcript_path, cmd=["python", "-m", "pytest", "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests", "-q"], rc=rc, output=out)
    rc, out = _run(["python", "-m", "pytest", "KT_PROD_CLEANROOM/tests", "-q"], cwd=repo_root, env=env, out_path=out_dir / "pytest_cleanroom.log")
    _append_transcript(transcript_path, cmd=["python", "-m", "pytest", "KT_PROD_CLEANROOM/tests", "-q"], rc=rc, output=out)

    # 2) Governance verifiers
    rc, out = _run(
        ["python", "-m", "tools.verification.fl3_meta_evaluator", "--write-receipt", str(out_dir / "meta_evaluator_receipt.json")],
        cwd=repo_root,
        env=env,
        out_path=out_dir / "meta_evaluator.log",
    )
    _append_transcript(transcript_path, cmd=["python", "-m", "tools.verification.fl3_meta_evaluator", "--write-receipt", str(out_dir / "meta_evaluator_receipt.json")], rc=rc, output=out)
    rc, out = _run(["python", "-m", "tools.verification.fl3_red_assault", "--out", str(out_dir / "red_assault_report.json")], cwd=repo_root, env=env)
    _append_transcript(transcript_path, cmd=["python", "-m", "tools.verification.fl3_red_assault", "--out", str(out_dir / "red_assault_report.json")], rc=rc, output=out)
    rc, out = _run(
        [
            "python",
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
    _append_transcript(transcript_path, cmd=["python", "-m", "tools.verification.fl3_rollback_drill", "--registry-path", reg_path, "--out", str(out_dir / "rollback_drill_report.json")], rc=rc, output=out)

    # 3) Growth lane E2E gate (canonical wrapper)
    rc, out = _run(
        ["python", "-m", "tools.verification.growth_e2e_gate", "--pressure-runs", "1", "--out", str(out_dir / "growth_e2e_gate_report.json")],
        cwd=repo_root,
        env=env,
    )
    _append_transcript(transcript_path, cmd=["python", "-m", "tools.verification.growth_e2e_gate", "--pressure-runs", "1", "--out", str(out_dir / "growth_e2e_gate_report.json")], rc=rc, output=out)

    # 4) Build ephemeral organ contract and run determinism canary + one sovereign job.
    contract = _mk_min_contract(repo_root)
    contract_path = out_dir / "organ_contract.json"
    contract_path.write_text(json.dumps(contract, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

    # Determinism canary (must PASS; blocks promotion otherwise).
    rc, out = _run(
        [
            "python",
            "-m",
            "tools.verification.fl4_determinism_canary",
            "--organ-contract",
            str(contract_path),
            "--out",
            str(out_dir / "canary_artifact.json"),
        ],
        cwd=repo_root,
        env=env,
    )
    _append_transcript(transcript_path, cmd=["python", "-m", "tools.verification.fl4_determinism_canary", "--organ-contract", str(contract_path), "--out", str(out_dir / "canary_artifact.json")], rc=rc, output=out)

    # Run one sovereign factory job (expected to produce PROMOTE decision, then promote atomically).
    export_shadow_root = str(paths["exports_shadow_root"]).replace("\\", "/").rstrip("/") + "/_runs/FL4_SEAL"
    export_promoted_root = str(paths["exports_adapters_root"]).replace("\\", "/").rstrip("/") + "/_runs/FL4_SEAL"
    job = _mk_jobspec(export_shadow_root=export_shadow_root, export_promoted_root=export_promoted_root, mode="SOVEREIGN")
    job_path = out_dir / "job.json"
    job_path.write_text(json.dumps(job, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

    rc, out = _run(
        ["python", "-m", "tools.training.fl3_factory.run_job", "--job", str(job_path), "--organ-contract", str(contract_path)],
        cwd=repo_root,
        env=env,
        out_path=out_dir / "factory_job.log",
    )
    _append_transcript(transcript_path, cmd=["python", "-m", "tools.training.fl3_factory.run_job", "--job", str(job_path), "--organ-contract", str(contract_path)], rc=rc, output=out)

    job_dir = (repo_root / export_shadow_root / job["job_id"]).resolve()
    if not job_dir.exists():
        raise SystemExit(f"FAIL: expected job_dir missing (fail-closed): {job_dir.as_posix()}")

    # Verify the job_dir explicitly.
    rc, out = _run(["python", "-m", "tools.verification.fl3_meta_evaluator", "--verify-job-dir", str(job_dir)], cwd=repo_root, env=env)
    _append_transcript(transcript_path, cmd=["python", "-m", "tools.verification.fl3_meta_evaluator", "--verify-job-dir", str(job_dir)], rc=rc, output=out)

    # Promote if decision is PROMOTE.
    promotion = json.loads((job_dir / "promotion.json").read_text(encoding="utf-8"))
    if isinstance(promotion, dict) and promotion.get("decision") == "PROMOTE":
        _run(
            [
                "python",
                "-m",
                "tools.verification.fl4_promote",
                "--job-dir",
                str(job_dir),
                "--canary-artifact",
                str(out_dir / "canary_artifact.json"),
                "--out",
                str(out_dir / "promotion_report.json"),
            ],
            cwd=repo_root,
            env=env,
        )

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
        "git_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(repo_root), text=True).strip(),
        "out_dir": out_dir_rel,
        "registry_path": reg_path,
        "job_id": job["job_id"],
    }
    (out_dir / "preflight_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
