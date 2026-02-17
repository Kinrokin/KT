from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.verification.fl3_canonical import repo_root_from
from tools.verification.fl3_meta_evaluator import compute_law_bundle_hash, load_law_bundle
from tools.verification.fl3_validators import FL3ValidationError
from tools.verification.worm_write import write_text_worm


def _utc_now_basic_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _run(
    *,
    repo_root: Path,
    cmd: Sequence[str],
    env: Dict[str, str],
) -> Tuple[int, str]:
    p = subprocess.run(
        list(cmd),
        cwd=str(repo_root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    out = p.stdout or ""
    return int(p.returncode), out


def _git_status_clean(*, repo_root: Path) -> None:
    out = subprocess.check_output(["git", "status", "--porcelain=v1"], cwd=str(repo_root), text=True)
    if out.strip():
        raise FL3ValidationError("FAIL_CLOSED: repo is not clean")


def _law_bundle_verify_obj(*, repo_root: Path) -> Dict[str, Any]:
    bundle = load_law_bundle(repo_root=repo_root)
    computed = compute_law_bundle_hash(repo_root=repo_root, bundle=bundle)
    sha_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.sha256"
    pinned = sha_path.read_text(encoding="utf-8").strip() if sha_path.exists() else ""
    return {
        "computed_law_bundle_hash": computed,
        "pinned_law_bundle_hash": pinned,
        "match": computed == pinned,
    }


def _is_expected_ci_meta_fail(output: str) -> bool:
    o = (output or "").lower()
    return "kt_hmac_key_signer" in o or "missing kt_hmac_key_signer" in o or "missing kt_hmac" in o


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Run full KT sweep audit harness and write WORM logs under a run root.")
    ap.add_argument(
        "--run-root",
        default="",
        help="Run root directory. Default: KT_PROD_CLEANROOM/exports/_runs/KT_V1_CLOSURE/<ts>/",
    )
    ap.add_argument(
        "--sweep-id",
        default="",
        help="Optional sweep id used as a subdir name under run_root/sweeps/. Default: UTC timestamp.",
    )
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = repo_root_from(Path(__file__))

    run_root = Path(str(args.run_root).strip()) if str(args.run_root).strip() else Path(
        "KT_PROD_CLEANROOM/exports/_runs/KT_V1_CLOSURE"
    ) / _utc_now_basic_z()
    if not run_root.is_absolute():
        run_root = (repo_root / run_root).resolve()
    run_root.mkdir(parents=True, exist_ok=True)

    sweep_id = str(args.sweep_id).strip() or _utc_now_basic_z()
    sweep_dir = (run_root / "sweeps" / sweep_id).resolve()
    sweep_dir.mkdir(parents=True, exist_ok=True)

    _git_status_clean(repo_root=repo_root)

    base_env = os.environ.copy()
    base_env["PYTHONPATH"] = str(repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src") + os.pathsep + str(
        repo_root / "KT_PROD_CLEANROOM"
    )
    base_env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")

    steps: List[Dict[str, Any]] = []

    def run_step(name: str, cmd: Sequence[str], *, env: Dict[str, str]) -> None:
        rc, out = _run(repo_root=repo_root, cmd=cmd, env=env)
        write_text_worm(
            path=sweep_dir / f"{name}.log",
            text=out if out.endswith("\n") else out + "\n",
            label=f"sweep:{name}.log",
        )
        steps.append({"name": name, "cmd": list(cmd), "rc": rc})
        if rc != 0:
            raise FL3ValidationError(f"FAIL_CLOSED: step failed: {name} rc={rc}")

    # Pytest batteries must run outside canonical-lane constraints (CI-safe).
    run_step("pytest_cleanroom", ["python", "-m", "pytest", "-q", "KT_PROD_CLEANROOM/tests"], env=dict(base_env))
    run_step("pytest_temple", ["python", "-m", "pytest", "-q", "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests"], env=dict(base_env))
    run_step(
        "pytest_verification",
        ["python", "-m", "pytest", "-q", "KT_PROD_CLEANROOM/tools/verification/tests"],
        env=dict(base_env),
    )

    # Meta-evaluator CI simulation: canonical lane flagged but no keys must be available.
    ci_env = dict(base_env)
    ci_env["KT_CANONICAL_LANE"] = "1"
    ci_env["KT_ATTESTATION_MODE"] = "NONE"
    ci_env.pop("KT_HMAC_KEY_SIGNER_A", None)
    ci_env.pop("KT_HMAC_KEY_SIGNER_B", None)
    rc_ci, out_ci = _run(repo_root=repo_root, cmd=["python", "-m", "tools.verification.fl3_meta_evaluator"], env=ci_env)
    write_text_worm(
        path=sweep_dir / "meta_evaluator_ci_sim.log",
        text=out_ci if out_ci.endswith("\n") else out_ci + "\n",
        label="sweep:meta_evaluator_ci_sim.log",
    )
    steps.append({"name": "meta_evaluator_ci_sim", "cmd": ["python", "-m", "tools.verification.fl3_meta_evaluator"], "rc": rc_ci})
    if rc_ci == 0 or not _is_expected_ci_meta_fail(out_ci):
        raise FL3ValidationError("FAIL_CLOSED: CI meta-evaluator simulation did not fail as expected (keys must be absent in CI)")

    # Meta-evaluator local seal lane: canonical lane with HMAC keys must PASS.
    seal_env = dict(base_env)
    seal_env["KT_CANONICAL_LANE"] = "1"
    seal_env["KT_ATTESTATION_MODE"] = "HMAC"
    run_step("meta_evaluator_canonical", ["python", "-m", "tools.verification.fl3_meta_evaluator"], env=seal_env)

    # Law bundle recompute must match pin.
    law_verify = _law_bundle_verify_obj(repo_root=repo_root)
    write_text_worm(
        path=sweep_dir / "law_bundle_verify.json",
        text=json.dumps(law_verify, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        label="sweep:law_bundle_verify.json",
    )
    if not bool(law_verify.get("match")):
        raise FL3ValidationError("FAIL_CLOSED: law bundle recompute mismatch vs LAW_BUNDLE_FL3.sha256")

    # Receipt validation (if EPIC_23 tool exists).
    validate_cmd = ["python", "-m", "tools.verification.validate_receipts", "--out-dir", str(sweep_dir)]
    tool_path = repo_root / "KT_PROD_CLEANROOM" / "tools" / "verification" / "validate_receipts.py"
    if not tool_path.exists():
        write_text_worm(
            path=sweep_dir / "validate_receipts.NOT_PRESENT",
            text="NOT_PRESENT\n",
            label="sweep:validate_receipts.NOT_PRESENT",
        )
        steps.append({"name": "validate_receipts", "cmd": validate_cmd, "rc": None})
    else:
        rc_val, out_val = _run(repo_root=repo_root, cmd=validate_cmd, env=dict(base_env))
        write_text_worm(
            path=sweep_dir / "validate_receipts.log",
            text=out_val if out_val.endswith("\n") else out_val + "\n",
            label="sweep:validate_receipts.log",
        )
        steps.append({"name": "validate_receipts", "cmd": validate_cmd, "rc": rc_val})
        if rc_val != 0:
            raise FL3ValidationError("FAIL_CLOSED: receipt validation failed")

    summary = {"status": "PASS", "run_root": run_root.as_posix(), "sweep_id": sweep_id, "steps": steps}
    write_text_worm(
        path=sweep_dir / "sweep_summary.json",
        text=json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        label="sweep:sweep_summary.json",
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FL3ValidationError as exc:
        raise SystemExit(str(exc)) from exc
