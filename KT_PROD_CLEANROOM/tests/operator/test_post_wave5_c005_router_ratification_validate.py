from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.post_wave5_c005_router_ratification_validate import (  # noqa: E402
    C005_DELTA,
    build_c005_router_ratification_receipt,
)
from tools.operator.titanium_common import repo_root  # noqa: E402


def test_post_wave5_c005_router_ratification_receipt_holds_static_baseline() -> None:
    root = repo_root()
    telemetry_path = root / "KT_PROD_CLEANROOM" / "reports" / ".tmp_post_wave5_c005_router_ratification.jsonl"
    if telemetry_path.exists():
        telemetry_path.unlink()

    receipt = build_c005_router_ratification_receipt(root=root, telemetry_path=telemetry_path)

    assert receipt["status"] == "PASS"
    assert receipt["c005_delta"] == C005_DELTA
    assert receipt["current_head_blocker_status"] == "CLOSED"
    assert receipt["ratification_decision"] == "HOLD_STATIC_CANONICAL_BASELINE"
    assert receipt["exact_superiority_outcome"] == "NOT_EARNED_SHADOW_MATCHES_STATIC_BASELINE"
    assert receipt["continuing_governed_objective"]["objective_id"] == "ROUTER_SUPERIORITY_AND_MULTI_LOBE_PROMOTION"
    assert receipt["continuing_governed_objective"]["status"] == "ACTIVE_GOVERNED_ADVANCEMENT_OBJECTIVE"
    assert receipt["continuing_governed_objective"]["abandonment_status"] == "NOT_ABANDONED"
    assert receipt["provider_underlay_ref"] == "KT_PROD_CLEANROOM/reports/post_wave5_c016a_success_matrix.json"
    assert receipt["provider_underlay_resilience_ref"] == "KT_PROD_CLEANROOM/reports/post_wave5_c016b_resilience_pack.json"
    assert receipt["comparison_metrics"]["shadow_match_rate"] == 1.0
    assert receipt["comparison_metrics"]["route_distribution_delta_count"] == 0
    assert "R04" in receipt["comparison_metrics"]["fallback_case_ids"]
    check_rows = {row["check_id"]: row["status"] for row in receipt["checks"]}
    assert all(status == "PASS" for status in check_rows.values())
    assert receipt["best_static_provider_adapter_underlay"]["status"] == "OK"
    assert receipt["best_static_provider_adapter_underlay"]["adapter_id"] == "council.openrouter.live_hashed.v1"


def test_post_wave5_c005_router_ratification_cli_writes_receipt(tmp_path: Path) -> None:
    root = repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")

    receipt_path = tmp_path / "receipt.json"
    telemetry_path = tmp_path / "telemetry.jsonl"

    proc = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.post_wave5_c005_router_ratification_validate",
            "--receipt-output",
            str(receipt_path),
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
    assert payload["c005_delta"] == C005_DELTA
    assert payload["ratification_decision"] == "HOLD_STATIC_CANONICAL_BASELINE"
    assert receipt_path.exists()
    assert telemetry_path.exists()
