from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_post_wave5_terminalization_emits_truthful_state_registers(tmp_path: Path) -> None:
    root = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    freeze_path = tmp_path / "freeze.json"
    organ_path = tmp_path / "organ.json"
    tools_path = tmp_path / "tools.json"
    growth_path = tmp_path / "growth.json"
    truth_path = tmp_path / "truth.json"
    telemetry_path = tmp_path / "telemetry.jsonl"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.post_wave5_runtime_organ_terminalization_validate",
            "--freeze-output",
            str(freeze_path),
            "--organ-output",
            str(organ_path),
            "--tools-output",
            str(tools_path),
            "--growth-output",
            str(growth_path),
            "--truth-matrix-output",
            str(truth_path),
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
    assert payload["remaining_open_blockers"] == [
        "C005_ROUTER_AMBITION_EXCEEDS_IMPLEMENTATION",
        "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED",
    ]

    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    assert [row["blocker_id"] for row in freeze["closed_blockers"]] == [
        "C007_REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED",
        "C016A_AUTHENTICATED_LIVE_PROVIDER_SUCCESS_NOT_YET_PROVEN",
        "C016B_AUTHENTICATED_LIVE_PROVIDER_RESILIENCE_NOT_YET_PROVEN",
    ]

    organ = json.loads(organ_path.read_text(encoding="utf-8"))
    rows = {row["organ_id"]: row for row in organ["rows"]}
    assert rows["core.fail_closed_dispatch_stack"]["terminal_state"] == "CORE_LIVE"
    assert rows["memory.state_vault_and_replay"]["terminal_state"] == "CORE_LIVE"
    assert rows["thermodynamics.budget_engine"]["terminal_state"] == "CORE_LIVE"
    assert rows["thermodynamics.budget_meters"]["terminal_state"] == "LIVE_BOUNDED"
    assert rows["temporal"]["terminal_state"] == "LIVE_BOUNDED"
    assert rows["multiverse"]["terminal_state"] == "LIVE_BOUNDED"
    assert rows["paradox"]["terminal_state"] == "LIVE_BOUNDED"
    assert rows["cognition"]["terminal_state"] == "LIVE_BOUNDED"
    assert rows["council"]["terminal_state"] == "LIVE_BOUNDED"
    assert rows["router_static_baseline"]["terminal_state"] == "LIVE_BOUNDED"

    tools = json.loads(tools_path.read_text(encoding="utf-8"))
    assert all(row["tool_state"] == "TOOL_VERIFIED" for row in tools["rows"])

    growth = json.loads(growth_path.read_text(encoding="utf-8"))
    assert all(row["terminal_state"] == "LAB_GOVERNED" for row in growth["rows"])

    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    assert truth["remaining_open_blockers"] == [
        "C005_ROUTER_AMBITION_EXCEEDS_IMPLEMENTATION",
        "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED",
    ]
    assert "C006 externality upgrade remains forbidden." in truth["forbidden_claims_remaining"]
