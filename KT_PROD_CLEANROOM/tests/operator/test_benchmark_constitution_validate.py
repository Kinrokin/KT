from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_benchmark_constitution_cli_emits_canonical_comparator_bundle(tmp_path: Path) -> None:
    root = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    negative_path = tmp_path / "negative.json"
    receipt_path = tmp_path / "receipt.json"
    constitution_path = tmp_path / "kt_benchmark_constitution_v1.json"
    registry_path = tmp_path / "kt_comparator_registry.json"
    manifest_path = tmp_path / "benchmark_manifest.json"
    scorer_path = tmp_path / "scorer_registry.json"
    scorecard_path = tmp_path / "baseline_vs_live_scorecard.json"
    bundle_path = tmp_path / "frozen_eval_scorecard_bundle.json"
    replay_path = tmp_path / "comparator_replay_receipt.json"
    binding_path = tmp_path / "canonical_scorecard_binding_receipt.json"
    alias_path = tmp_path / "scorecard_alias_retirement_receipt.json"
    detachment_path = tmp_path / "competitive_scorecard_validator_detachment_receipt.json"
    write_scope_path = tmp_path / "validator_write_scope_enforcement_receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.benchmark_constitution_validate",
            "--negative-ledger-output",
            str(negative_path),
            "--receipt-output",
            str(receipt_path),
            "--benchmark-constitution-output",
            str(constitution_path),
            "--comparator-registry-output",
            str(registry_path),
            "--benchmark-manifest-output",
            str(manifest_path),
            "--scorer-registry-output",
            str(scorer_path),
            "--baseline-scorecard-output",
            str(scorecard_path),
            "--frozen-eval-bundle-output",
            str(bundle_path),
            "--comparator-replay-output",
            str(replay_path),
            "--canonical-binding-receipt-output",
            str(binding_path),
            "--alias-retirement-receipt-output",
            str(alias_path),
            "--detachment-receipt-output",
            str(detachment_path),
            "--write-scope-receipt-output",
            str(write_scope_path),
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
    assert payload["tranche_id"] == "B03_T3_COMPETITIVE_SCORECARD_VALIDATOR_DETACHMENT"
    assert payload["canonical_scorecard_id"] == "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL"

    negative = json.loads(negative_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    constitution = json.loads(constitution_path.read_text(encoding="utf-8"))
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    scorer = json.loads(scorer_path.read_text(encoding="utf-8"))
    scorecard = json.loads(scorecard_path.read_text(encoding="utf-8"))
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    replay = json.loads(replay_path.read_text(encoding="utf-8"))
    binding = json.loads(binding_path.read_text(encoding="utf-8"))
    alias = json.loads(alias_path.read_text(encoding="utf-8"))
    detachment = json.loads(detachment_path.read_text(encoding="utf-8"))
    write_scope = json.loads(write_scope_path.read_text(encoding="utf-8"))

    assert negative["status"] == "PASS"
    assert len(negative["rows"]) >= 5
    assert receipt["status"] == "PASS"
    assert constitution["current_git_head"]
    assert registry["current_repo_head"] == constitution["current_git_head"]
    assert manifest["status"] == "ACTIVE"
    assert scorer["status"] == "ACTIVE"
    assert scorecard["status"] == "PASS"
    assert bundle["status"] == "PASS"
    assert replay["status"] == "PASS"
    assert binding["status"] == "PASS"
    assert alias["status"] == "PASS"
    assert detachment["status"] == "PASS"
    assert write_scope["status"] == "PASS"
    assert scorecard["canonical_scorecard_id"] == "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL"
    assert scorecard["canonical_receipt_binding"]["baseline_vs_live_scorecard_ref"].endswith("baseline_vs_live_scorecard.json")
    assert receipt["canonical_scorecard_id"] == "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL"
    assert binding["canonical_scorecard_id"] == "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL"
    assert alias["authoritative_scorecard_ref"].endswith("baseline_vs_live_scorecard.json")
    assert detachment["retired_alias_ref"].endswith("competitive_scorecard.json")
    assert all(row["pass"] for row in detachment["checks"])
    assert "KT_PROD_CLEANROOM/reports/competitive_scorecard.json" not in scorecard["measurement_scope"]["allowed_measured_surfaces"]
    assert "KT_PROD_CLEANROOM/reports/competitive_scorecard.json" in scorecard["measurement_scope"]["forbidden_measured_surfaces"]
    assert "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/cognitive_engine.py" in scorecard["measurement_scope"]["forbidden_measured_surfaces"]
