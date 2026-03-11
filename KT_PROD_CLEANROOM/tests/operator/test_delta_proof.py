from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = ROOT / "04_PROD_TEMPLE_V2" / "src"
sys.path.insert(0, str(SRC_ROOT))
sys.path.insert(0, str(ROOT))

from tools.verification.seal_mode_test_roots import write_root


def _py_env(repo_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [
            str(repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src"),
            str(repo_root / "KT_PROD_CLEANROOM"),
        ]
    )
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    env["KT_SEAL_MODE"] = "1"
    return env


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_delta_proof_computes_deltas_and_emits_delivery(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    root = write_root(repo_root=repo_root) / "delta_proof" / f"{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    root.mkdir(parents=True, exist_ok=False)

    baseline = root / "baseline"
    post = root / "post"
    for r in (baseline, post):
        (r / "reports").mkdir(parents=True, exist_ok=True)
        (r / "evidence").mkdir(parents=True, exist_ok=True)
        (r / "delivery").mkdir(parents=True, exist_ok=True)
        _write_json(r / "evidence" / "secret_scan_report.json", {"status": "PASS"})
        _write_json(r / "delivery" / "delivery_lint_report.json", {"status": "PASS"})
        (r / "verdict.txt").write_text("OK\n", encoding="utf-8")

    _write_json(
        baseline / "reports" / "failure_taxonomy.json",
        {"schema_id": "kt.operator.serious_layer.red_assault.failure_taxonomy.unbound.v1", "counts_by_severity": {"HIGH": 2, "LOW": 1}, "counts_by_class": {"a": 2}},
    )
    _write_json(
        post / "reports" / "failure_taxonomy.json",
        {"schema_id": "kt.operator.serious_layer.red_assault.failure_taxonomy.unbound.v1", "counts_by_severity": {"HIGH": 1, "LOW": 1}, "counts_by_class": {"a": 1}},
    )
    _write_json(baseline / "reports" / "red_assault_summary.json", {"pack_id": "serious_v1", "pressure_level": "l4", "seed": 1337})
    _write_json(post / "reports" / "red_assault_summary.json", {"pack_id": "serious_v1", "pressure_level": "l4", "seed": 1337})

    out_run = root / "out"
    out_run.mkdir(parents=True, exist_ok=False)

    env = _py_env(repo_root)
    p = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.delta_proof",
            "--profile",
            "v1",
            "--allow-dirty",
            "--run-root",
            str(out_run),
            "--baseline-run",
            str(baseline),
            "--post-run",
            str(post),
            "--allow-mismatch",
        ],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p.returncode == 0, p.stdout + "\n" + p.stderr
    report_path = out_run / "reports" / "delta_proof.json"
    assert report_path.exists()
    assert (out_run / "delivery" / "delivery_manifest.json").exists()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    expected_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(repo_root), env=env, text=True).strip()
    expected_branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=str(repo_root), env=env, text=True).strip()
    assert report["validated_head_sha"] == expected_head
    assert report["branch_ref"] == expected_branch
    assert report["scope"] == "candidate_tracked_worktree_delta_accounting_only"
    assert report["published_head_authority_claimed"] is False


def test_delta_proof_fails_closed_on_probe_bundle_mismatch(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    root = write_root(repo_root=repo_root) / "delta_proof" / f"mismatch_{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    root.mkdir(parents=True, exist_ok=False)

    baseline = root / "baseline"
    post = root / "post"
    for r in (baseline, post):
        (r / "reports").mkdir(parents=True, exist_ok=True)
        (r / "evidence").mkdir(parents=True, exist_ok=True)
        (r / "delivery").mkdir(parents=True, exist_ok=True)
        _write_json(r / "evidence" / "secret_scan_report.json", {"status": "PASS"})
        _write_json(r / "delivery" / "delivery_lint_report.json", {"status": "PASS"})
        (r / "verdict.txt").write_text("OK\n", encoding="utf-8")

    _write_json(
        baseline / "reports" / "failure_taxonomy.json",
        {"schema_id": "kt.operator.serious_layer.red_assault.failure_taxonomy.unbound.v1", "counts_by_severity": {"HIGH": 1}, "counts_by_class": {"x": 1}},
    )
    _write_json(
        post / "reports" / "failure_taxonomy.json",
        {"schema_id": "kt.operator.serious_layer.red_assault.failure_taxonomy.unbound.v1", "counts_by_severity": {"HIGH": 0}, "counts_by_class": {"x": 0}},
    )
    _write_json(
        baseline / "reports" / "red_assault_summary.json",
        {
            "pack_id": "serious_v1",
            "pressure_level": "l4",
            "seed": 1337,
            "probe_pack_id": "probe_pack.fintech.hashref.v1",
            "probe_payload_bundle_sha256": "aaa",
            "probe_engine": "stub",
        },
    )
    _write_json(
        post / "reports" / "red_assault_summary.json",
        {
            "pack_id": "serious_v1",
            "pressure_level": "l4",
            "seed": 1337,
            "probe_pack_id": "probe_pack.fintech.hashref.v1",
            "probe_payload_bundle_sha256": "bbb",
            "probe_engine": "stub",
        },
    )

    out_run = root / "out"
    out_run.mkdir(parents=True, exist_ok=False)

    env = _py_env(repo_root)
    p = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.delta_proof",
            "--profile",
            "v1",
            "--allow-dirty",
            "--run-root",
            str(out_run),
            "--baseline-run",
            str(baseline),
            "--post-run",
            str(post),
        ],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p.returncode != 0
    assert "baseline/post mismatch" in (p.stdout + p.stderr)
