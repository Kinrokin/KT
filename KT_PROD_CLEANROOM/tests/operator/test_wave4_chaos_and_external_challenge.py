from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def test_wave4_validator_runs_and_stays_bounded(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root) + os.pathsep + str(root / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    receipt = tmp_path / "wave4_receipt.json"
    chaos = tmp_path / "wave4_chaos.json"
    protocol = tmp_path / "wave4_protocol.json"
    public_challenge = tmp_path / "wave4_public_challenge.json"
    externality = tmp_path / "wave4_externality.json"
    dispositions = tmp_path / "wave4_dispositions.json"
    formal = tmp_path / "wave4_formal.json"
    telemetry = tmp_path / "wave4_telemetry.jsonl"
    export_root = tmp_path / "exports"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.wave4_chaos_and_external_challenge_validate",
            "--receipt-output",
            str(receipt),
            "--chaos-output",
            str(chaos),
            "--protocol-output",
            str(protocol),
            "--public-challenge-output",
            str(public_challenge),
            "--externality-output",
            str(externality),
            "--dispositions-output",
            str(dispositions),
            "--formal-output",
            str(formal),
            "--telemetry-output",
            str(telemetry),
            "--export-root",
            str(export_root),
        ],
        cwd=str(root.parent),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["status"] == "PASS"
    assert payload["challenge_channel_used"] == "SIGNED_JSON_BUNDLE_DOCUMENTED_CHANNEL_V1"
    assert payload["externality_classes_earned"] == [
        "E0_INTERNAL_SELF_ISSUED_ONLY",
        "E1_SAME_HOST_DETACHED_REPLAY",
    ]

    receipt_payload = json.loads(receipt.read_text(encoding="utf-8"))
    assert receipt_payload["status"] == "PASS"
    assert "C005_ROUTER_AMBITION_EXCEEDS_IMPLEMENTATION" in receipt_payload["remaining_open_contradictions"]
    assert "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED" in receipt_payload["remaining_open_contradictions"]
    assert "C007_REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED" in receipt_payload["remaining_open_contradictions"]
    assert "independent_hostile_replay_confirmed" in receipt_payload["stronger_claim_not_made"]

    public_payload = json.loads(public_challenge.read_text(encoding="utf-8"))
    assert public_payload["challenge_window_status"] == "OPEN_NO_EXTERNAL_FINDINGS_YET"
    assert public_payload["externality_ceiling_after_wave4"] == "E1_SAME_HOST_DETACHED_REPLAY"

    externality_payload = json.loads(externality.read_text(encoding="utf-8"))
    assert externality_payload["status"] == "PASS"
    assert "E2_CROSS_HOST_FRIENDLY_REPLAY" in externality_payload["not_earned_classes"]
    assert "E4_PUBLIC_CHALLENGE_SURVIVAL" in externality_payload["not_earned_classes"]

    formal_payload = json.loads(formal.read_text(encoding="utf-8"))
    assert formal_payload["status"] == "PASS"
    check_ids = {row["check_id"] for row in formal_payload["checks"]}
    assert "claim_compiler_monotonicity" in check_ids
    assert "externality_class_consistency" in check_ids
