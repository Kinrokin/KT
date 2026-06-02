from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_trajectory_momentum_injects_friction() -> None:
    log = read_json(ROOT / "reports" / "v17_7_trajectory_momentum_log.json")
    horizon = read_json(ROOT / "reports" / "v17_7_1_horizon_simulator_receipt.json")
    assert log["theta_path"] == ["v17_5", "v17_7"]
    assert "freeze_replay_only" in log["friction_actions"]
    assert horizon["inject_friction"] is True
