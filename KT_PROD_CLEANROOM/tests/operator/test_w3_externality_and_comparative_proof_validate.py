from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_w3_externality_and_comparative_proof_cli_emits_bounded_outputs(tmp_path: Path) -> None:
    root = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    e2_path = tmp_path / "e2.json"
    atlas_path = tmp_path / "atlas.json"
    scorecard_path = tmp_path / "scorecard.json"
    canonical_delta_path = tmp_path / "canonical_delta.json"
    advancement_delta_path = tmp_path / "advancement_delta.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.w3_externality_and_comparative_proof_validate",
            "--e2-output",
            str(e2_path),
            "--capability-atlas-output",
            str(atlas_path),
            "--competitive-scorecard-output",
            str(scorecard_path),
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
    assert "release_readiness_not_proven" in payload["current_truth_posture_open_blocker_ids"]
    assert payload["e2_outcome"] == "NOT_EARNED_PENDING_SECOND_HOST_RETURN"
    assert payload["comparative_widening_unlock"] is False
    assert payload["commercial_widening_unlock"] is False

    e2_receipt = json.loads(e2_path.read_text(encoding="utf-8"))
    capability_atlas = json.loads(atlas_path.read_text(encoding="utf-8"))
    scorecard = json.loads(scorecard_path.read_text(encoding="utf-8"))
    canonical_delta = json.loads(canonical_delta_path.read_text(encoding="utf-8"))
    advancement_delta = json.loads(advancement_delta_path.read_text(encoding="utf-8"))

    assert e2_receipt["status"] == "PASS"
    assert e2_receipt["e2_outcome"] == "NOT_EARNED_PENDING_SECOND_HOST_RETURN"
    assert e2_receipt["detached_verifier_outsider_usability_status"] == "PASS_BOUNDED_E1_ONLY"
    assert e2_receipt["second_host_return_present"] is False

    assert capability_atlas["schema_id"] == "kt.capability_atlas.v1"
    assert capability_atlas["status"] == "PASS"
    assert any(row["surface_id"] == "router" for row in capability_atlas["topology"])
    assert any(row["surface_id"] == "detached_verifier_externality_lane" for row in capability_atlas["topology"])

    assert scorecard["status"] == "PASS"
    assert scorecard["comparative_widening_status"] == "BLOCKED_PENDING_C006_AND_E2"
    assert scorecard["comparative_widening_unlock"] is False

    assert canonical_delta["status"] == "PASS"
    assert canonical_delta["blocker_delta"]["active_open_blocker_ids"] == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"]
    assert "release_activation_not_executed" in canonical_delta["blocker_delta"]["current_truth_posture_open_blocker_ids"]
    assert canonical_delta["blocker_delta"]["change"] == "NONE_C006_STILL_OPEN_PENDING_FRESH_SECOND_HOST_RETURN"

    assert advancement_delta["status"] == "PASS"
    assert advancement_delta["detached_verifier_outsider_usability_status"] == "PASS_BOUNDED_E1_ONLY"
    assert advancement_delta["e2_outcome"] == "NOT_EARNED_PENDING_SECOND_HOST_RETURN"
    assert advancement_delta["comparative_widening_unlock"] is False
    assert advancement_delta["commercial_widening_unlock"] is False
