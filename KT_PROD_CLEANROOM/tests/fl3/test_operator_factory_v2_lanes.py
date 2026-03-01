from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from tools.verification.seal_mode_test_roots import group_root, unique_run_dir


def _py_env(repo_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["KT_SEAL_MODE"] = "1"
    env["PYTHONPATH"] = str(repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src") + os.pathsep + str(
        repo_root / "KT_PROD_CLEANROOM"
    )
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def _run(cmd: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd), env=env, text=True, capture_output=True)


def _load_json(path: Path) -> dict:
    obj = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(obj, dict)
    return obj


def _assert_delivery_bundle(run_dir: Path) -> None:
    assert (run_dir / "reports" / "one_line_verdict.txt").is_file()
    assert (run_dir / "evidence" / "run_protocol.json").is_file()
    assert (run_dir / "evidence" / "RUN_PROTOCOL.md").is_file()
    assert (run_dir / "evidence" / "secret_scan_report.json").is_file()
    assert (run_dir / "evidence" / "replay.sh").is_file()
    assert (run_dir / "evidence" / "replay.ps1").is_file()
    assert (run_dir / "delivery" / "delivery_manifest.json").is_file()
    assert (run_dir / "delivery" / "delivery_lint_report.json").is_file()

    secret = _load_json(run_dir / "evidence" / "secret_scan_report.json")
    assert secret.get("status") == "PASS"

    lint = _load_json(run_dir / "delivery" / "delivery_lint_report.json")
    assert lint.get("status") == "PASS"

    zips = list((run_dir / "delivery").glob("*.zip"))
    assert zips, "missing delivery zip under run_dir/delivery/"


def test_operator_factory_v2_lanes_smoke(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    env = _py_env(repo_root)

    base = group_root(repo_root=repo_root, group="operator_factory_v2")

    # 1) Overlay apply (baseline for continuous governance).
    overlay_run = unique_run_dir(parent=base, label="overlay_apply")
    r_overlay = _run(
        [
            "python",
            "-m",
            "tools.operator.kt_cli",
            "--profile",
            "v1",
            "--run-root",
            str(overlay_run),
            "--allow-dirty",
            "overlay-apply",
            "--overlay-id",
            "domain.fintech.v1",
            "--target-lane",
            "certify",
        ],
        cwd=repo_root,
        env=env,
    )
    assert r_overlay.returncode == 0, r_overlay.stdout + r_overlay.stderr
    _assert_delivery_bundle(overlay_run)
    assert (overlay_run / "reports" / "overlay_resolution.json").is_file()
    assert (overlay_run / "reports" / "overlay_diff.json").is_file()
    assert (overlay_run / "reports" / "overlay_effect_summary.json").is_file()

    # 2) Red assault (factory pack).
    ra_run = unique_run_dir(parent=base, label="red_assault")
    r_ra = _run(
        [
            "python",
            "-m",
            "tools.operator.kt_cli",
            "--profile",
            "v1",
            "--run-root",
            str(ra_run),
            "--allow-dirty",
            "red-assault",
            "--pack-id",
            "fl3_factory_v1",
            "--pressure-level",
            "low",
            "--sample-count",
            "1",
            "--seed",
            "0",
        ],
        cwd=repo_root,
        env=env,
    )
    assert r_ra.returncode == 0, r_ra.stdout + r_ra.stderr
    _assert_delivery_bundle(ra_run)
    assert (ra_run / "reports" / "red_assault_summary.json").is_file()
    assert (ra_run / "reports" / "failure_taxonomy.json").is_file()
    assert (ra_run / "reports" / "top_failures.jsonl").is_file()

    # 3) Continuous governance (diff against overlay baseline).
    cg_run = unique_run_dir(parent=base, label="continuous_gov")
    r_cg = _run(
        [
            "python",
            "-m",
            "tools.operator.kt_cli",
            "--profile",
            "v1",
            "--run-root",
            str(cg_run),
            "--allow-dirty",
            "continuous-gov",
            "--baseline-run",
            str(overlay_run),
            "--window",
            "",
            "--thresholds",
            "{}",
        ],
        cwd=repo_root,
        env=env,
    )
    assert r_cg.returncode == 0, r_cg.stdout + r_cg.stderr
    _assert_delivery_bundle(cg_run)
    assert (cg_run / "reports" / "drift_report.json").is_file()
    assert (cg_run / "reports" / "regression_report.json").is_file()
    assert (cg_run / "reports" / "trend_snapshot.json").is_file()
    assert (cg_run / "reports" / "diff_summary.md").is_file()

    # 4) Forge lane (stub training + MVE-1 + Titan gates).
    failures = tmp_path / "failures.jsonl"
    failures.write_text('{"failure_id":"F1","note":"stub"}\n', encoding="utf-8")
    forge_run = unique_run_dir(parent=base, label="forge")
    r_forge = _run(
        [
            "python",
            "-m",
            "tools.operator.kt_cli",
            "--profile",
            "v1",
            "--run-root",
            str(forge_run),
            "--allow-dirty",
            "forge",
            "--failure-source",
            str(failures),
            "--holdout-pack",
            str(repo_root / "KT-Codex" / "packs" / "KT_CORE_PRESSURE_PACK_v1" / "pack_manifest.json"),
            "--train-config",
            '{"job_id":"forge_test","training_mode":"head_only"}',
            "--adapter-id",
            "ADAPTER_FORGE_TEST_V1",
            "--seed",
            "7",
            "--engine",
            "stub",
        ],
        cwd=repo_root,
        env=env,
    )
    assert r_forge.returncode == 0, r_forge.stdout + r_forge.stderr
    _assert_delivery_bundle(forge_run)
    assert (forge_run / "forge" / "train_config.json").is_file()
    assert (forge_run / "forge" / "train_data_manifest.json").is_file()
    assert (forge_run / "forge" / "adapter_metadata.json").is_file()
    assert (forge_run / "forge" / "before_after_metrics.json").is_file()
    assert (forge_run / "forge" / "promotion_gate.json").is_file()
    assert (forge_run / "reports" / "forge_summary.json").is_file()
