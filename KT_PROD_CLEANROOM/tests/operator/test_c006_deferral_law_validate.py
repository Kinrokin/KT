from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_c006_deferral_law_cli_binds_e1_ceilings_into_live_surfaces(tmp_path: Path) -> None:
    root = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    blocker_matrix_path = tmp_path / "blocker_matrix.json"
    remaining_gap_path = tmp_path / "remaining_gap.json"
    final_claim_matrix_path = tmp_path / "final_claim_matrix.json"
    truth_map_path = tmp_path / "truth_map.json"
    heartbeat_path = tmp_path / "heartbeat.json"
    deferral_status_path = tmp_path / "deferral_status.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.c006_deferral_law_validate",
            "--blocker-matrix-output",
            str(blocker_matrix_path),
            "--remaining-gap-output",
            str(remaining_gap_path),
            "--final-claim-matrix-output",
            str(final_claim_matrix_path),
            "--truth-map-output",
            str(truth_map_path),
            "--heartbeat-output",
            str(heartbeat_path),
            "--deferral-status-output",
            str(deferral_status_path),
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
    assert payload["active_deferred_blocker_ids"] == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"]
    assert payload["externality_class_max"] == "E1_SAME_HOST_DETACHED_REPLAY"
    assert payload["comparative_widening"] == "FORBIDDEN"
    assert payload["commercial_widening"] == "FORBIDDEN"
    assert payload["reentry_condition_satisfied"] is False

    blocker_matrix = json.loads(blocker_matrix_path.read_text(encoding="utf-8"))
    remaining_gap = json.loads(remaining_gap_path.read_text(encoding="utf-8"))
    final_claim_matrix = json.loads(final_claim_matrix_path.read_text(encoding="utf-8"))
    truth_map = json.loads(truth_map_path.read_text(encoding="utf-8"))
    heartbeat = json.loads(heartbeat_path.read_text(encoding="utf-8"))
    deferral_status = json.loads(deferral_status_path.read_text(encoding="utf-8"))

    blocker_row = blocker_matrix["open_blockers"][0]
    assert blocker_row["blocker_id"] == "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"
    assert blocker_row["state"] == "OPEN_DEFERRED_RESOURCE_CONSTRAINT"
    assert blocker_row["deferral_status"] == "DEFERRED_RESOURCE_CONSTRAINT"
    assert blocker_row["current_externality_ceiling"] == "E1_SAME_HOST_DETACHED_REPLAY"
    assert blocker_row["comparative_widening"] == "FORBIDDEN"
    assert blocker_row["commercial_widening"] == "FORBIDDEN"

    gap_row = remaining_gap["rows"][0]
    assert gap_row["status"] == "DEFERRED_RESOURCE_CONSTRAINT"
    assert gap_row["current_externality_ceiling"] == "E1_SAME_HOST_DETACHED_REPLAY"

    assert final_claim_matrix["claim_ceiling_overrides"]["externality_class_max"] == "E1_SAME_HOST_DETACHED_REPLAY"
    assert final_claim_matrix["claim_ceiling_overrides"]["comparative_widening"] == "FORBIDDEN"
    assert final_claim_matrix["claim_ceiling_overrides"]["commercial_widening"] == "FORBIDDEN"

    assert "c006_deferred_resource_constraint_active" in truth_map["open_stop_gates"]
    assert truth_map["claim_ceiling_overrides"]["externality_class_max"] == "E1_SAME_HOST_DETACHED_REPLAY"

    assert heartbeat["status"] == "PASS"
    assert heartbeat["deferral_status"] == "DEFERRED_RESOURCE_CONSTRAINT"
    assert heartbeat["machine_effective_state"]["blocker_state"] == "OPEN_DEFERRED_RESOURCE_CONSTRAINT"
    assert heartbeat["machine_effective_state"]["externality_class_max"] == "E1_SAME_HOST_DETACHED_REPLAY"
    assert heartbeat["blocked_claim_ceilings_still_enforced"] is True
    assert heartbeat["second_host_return_present"] is False

    assert deferral_status["status"] == "PASS"
    assert deferral_status["blocker_id"] == "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"
    assert deferral_status["deferral_status"] == "DEFERRED_RESOURCE_CONSTRAINT"
    assert deferral_status["machine_effective_state"]["externality_class_max"] == "E1_SAME_HOST_DETACHED_REPLAY"
    assert deferral_status["blocked_claim_ceilings_still_enforced"] is True
    assert deferral_status["second_host_return_present"] is False
