from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.titanium_common import repo_root  # noqa: E402
from tools.operator.wave2b_router_shadow_validate import build_wave2b_shadow_reports  # noqa: E402


def test_wave2b_router_shadow_reports_preserve_static_baseline() -> None:
    root = repo_root()
    telemetry_path = root / "KT_PROD_CLEANROOM" / "reports" / ".tmp_wave2b_router_shadow_test.jsonl"
    if telemetry_path.exists():
        telemetry_path.unlink()
    reports = build_wave2b_shadow_reports(root=root, telemetry_path=telemetry_path)

    selection = reports["selection_report"]
    matrix = reports["matrix_report"]
    health = reports["health_report"]

    assert selection["status"] == "PASS"
    assert matrix["status"] == "PASS"
    assert health["status"] == "PASS"
    assert selection["current_git_head"] == selection["subject_head"]
    assert matrix["current_git_head"] == matrix["subject_head"]
    assert health["current_git_head"] == health["subject_head"]
    assert selection["current_git_head"] == matrix["current_git_head"] == health["current_git_head"]
    assert selection["ratification_scope"] == "STATIC_ROUTER_BASELINE_ONLY"
    assert selection["embedding_model_used"] is False
    assert selection["provider_underlay_context"]["provider_report_ref"] == "KT_PROD_CLEANROOM/reports/post_wave5_c016a_success_matrix.json"
    assert selection["provider_underlay_context"]["same_host_live_hashed_success_proven"] is True
    assert selection["provider_underlay_context"]["same_host_live_hashed_resilience_proven"] is True
    assert matrix["promotion_decision"]["canonical_router_unchanged"] is True
    assert matrix["promotion_decision"]["learned_router_cutover_allowed"] is False
    assert "remote_provider_auth_success_remains_unproven" not in matrix["promotion_decision"]["reasons"]
    assert health["canonical_static_router_preserved"] is True
    assert health["route_distribution_delta_count"] == 0
    assert "R04" in health["fallback_case_ids"]
    assert health["shadow_match_rate"] == 1.0
    assert selection["best_static_provider_adapter_underlay"]["adapter_id"] == "council.openrouter.live_hashed.v1"
    assert selection["best_static_provider_adapter_underlay"]["status"] == "OK"
    assert "REMOTE_PROVIDER_AUTH_DID_NOT_YIELD_SUCCESSFUL_CURRENT_HEAD_INFERENCE" not in selection["boundary_holds"]
    assert "REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED" not in selection["boundary_holds"]


def test_wave2b_router_shadow_cli_writes_artifacts(tmp_path: Path) -> None:
    root = repo_root()
    selection_path = tmp_path / "selection.json"
    matrix_path = tmp_path / "matrix.json"
    health_path = tmp_path / "health.json"
    telemetry_path = tmp_path / "telemetry.jsonl"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")

    proc = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.wave2b_router_shadow_validate",
            "--selection-output",
            str(selection_path),
            "--matrix-output",
            str(matrix_path),
            "--health-output",
            str(health_path),
            "--telemetry-output",
            str(telemetry_path),
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
    assert selection_path.exists()
    assert matrix_path.exists()
    assert health_path.exists()
    assert telemetry_path.exists()
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    health = json.loads(health_path.read_text(encoding="utf-8"))
    assert selection["current_git_head"] == selection["subject_head"]
    assert matrix["current_git_head"] == matrix["subject_head"]
    assert health["current_git_head"] == health["subject_head"]
