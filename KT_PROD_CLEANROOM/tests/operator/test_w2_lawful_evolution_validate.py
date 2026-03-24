from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_w2_lawful_evolution_cli_emits_bounded_outputs(tmp_path: Path) -> None:
    root = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    tournament_path = tmp_path / "tournament.json"
    merge_path = tmp_path / "merge.json"
    canonical_delta_path = tmp_path / "canonical_delta.json"
    advancement_delta_path = tmp_path / "advancement_delta.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.w2_lawful_evolution_validate",
            "--tournament-output",
            str(tournament_path),
            "--merge-output",
            str(merge_path),
            "--canonical-delta-output",
            str(canonical_delta_path),
            "--advancement-delta-output",
            str(advancement_delta_path),
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
    assert payload["active_open_blocker_ids"] == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"]
    assert payload["router_superiority_unlock"] is False
    assert payload["multilobe_unlock"] is False
    assert payload["net_elevation_status"] == "PASS"

    tournament = json.loads(tournament_path.read_text(encoding="utf-8"))
    merge = json.loads(merge_path.read_text(encoding="utf-8"))
    canonical_delta = json.loads(canonical_delta_path.read_text(encoding="utf-8"))
    advancement_delta = json.loads(advancement_delta_path.read_text(encoding="utf-8"))

    assert tournament["status"] == "PASS"
    assert tournament["promotion_civilization_status"] == "LAB_GOVERNED_ONLY"
    assert tournament["canonical_influence_status"] == "BLOCKED_UNLESS_PROMOTION_RECEIPT_AND_ROLLBACK_PASS"
    assert tournament["public_showability_status"] == "BLOCKED"

    assert merge["status"] == "PASS"
    assert merge["merge_admissibility_status"] == "ROLLBACK_BOUND_AND_RECEIPTED"
    assert merge["rollback_bound"] is True

    assert canonical_delta["status"] == "PASS"
    assert canonical_delta["blocker_delta"]["active_open_blocker_ids"] == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"]
    assert canonical_delta["blocker_delta"]["change"] == "NONE_C006_STILL_ONLY_ACTIVE_CURRENT_HEAD_CANONICAL_BLOCKER"

    assert advancement_delta["status"] == "PASS"
    assert advancement_delta["canonical_influence_without_promotion"] is False
    assert advancement_delta["router_superiority_unlock"] is False
    assert advancement_delta["multilobe_unlock"] is False
    assert advancement_delta["net_elevation_gate"]["status"] == "PASS"
    assert advancement_delta["net_elevation_gate"]["negative_factors"]["claim_inflation"] == 0
