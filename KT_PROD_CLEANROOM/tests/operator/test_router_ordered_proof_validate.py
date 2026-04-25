from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_router_ordered_proof_cli_holds_static_baseline(tmp_path: Path) -> None:
    root = _repo_root()
    expected_head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    matrix_path = tmp_path / "matrix.json"
    health_path = tmp_path / "health.json"
    scorecard_path = tmp_path / "scorecard.json"
    receipt_path = tmp_path / "receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.router_ordered_proof_validate",
            "--shadow-matrix-output",
            str(matrix_path),
            "--health-output",
            str(health_path),
            "--scorecard-output",
            str(scorecard_path),
            "--receipt-output",
            str(receipt_path),
        ],
        cwd=str(root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["status"] == "PASS"
    assert payload["canonical_router_status"] == "STATIC_CANONICAL_BASELINE_ONLY"
    assert payload["exact_superiority_outcome"] == "NOT_EARNED_STATIC_BASELINE_RETAINS_CANONICAL_STATUS"

    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    health = json.loads(health_path.read_text(encoding="utf-8"))
    scorecard = json.loads(scorecard_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

    assert matrix["status"] == "PASS"
    assert matrix["current_git_head"] == expected_head
    assert matrix["subject_head"] == expected_head
    assert health["status"] == "PASS"
    assert health["current_git_head"] == expected_head
    assert health["subject_head"] == expected_head
    assert scorecard["status"] == "PASS"
    assert scorecard["current_git_head"] == expected_head
    assert scorecard["subject_head"] == expected_head
    assert scorecard["superiority_earned"] is False
    assert scorecard["learned_router_candidate"]["promotion_allowed"] is False
    assert scorecard["multi_lobe_promotion_status"] == "BLOCKED_PENDING_LEARNED_ROUTER_WIN"
    assert health["no_regression_rule_status"] == "PASS"
    assert len(health["route_quality_cost_latency_matrix"]) == 4
    assert receipt["status"] == "PASS"
    assert receipt["current_git_head"] == expected_head
    assert receipt["subject_head"] == expected_head
    assert receipt["learned_router_cutover_allowed"] is False
    assert receipt["multi_lobe_promotion_allowed"] is False
