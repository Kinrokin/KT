from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.titanium_common import repo_root  # noqa: E402
from tools.operator.wave2c_organ_realization_validate import build_wave2c_reports  # noqa: E402


def test_wave2c_reports_preserve_bounded_scope() -> None:
    root = repo_root()
    telemetry_path = root / "KT_PROD_CLEANROOM" / "reports" / ".tmp_wave2c_organ_telemetry.jsonl"
    export_root = root / "KT_PROD_CLEANROOM" / "exports" / ".tmp_wave2c_organ_realization"
    reports = build_wave2c_reports(root=root, telemetry_path=telemetry_path, export_root=export_root)

    suite_report = reports["suite_report"]
    cognition = reports["cognition_report"]
    paradox = reports["paradox_report"]
    temporal = reports["temporal_report"]
    multiverse = reports["multiverse_report"]
    council = reports["council_report"]
    maturity = reports["maturity_report"]
    disposition = reports["disposition_report"]

    assert suite_report["status"] == "PASS"
    for report in (cognition, paradox, temporal, multiverse, council):
        assert report["status"] == "PASS"
        assert report["proof_contracts"]["benchmark_pack_present"] is True
        assert report["proof_contracts"]["challenge_pack_present"] is True
        assert report["proof_contracts"]["failure_artifact_present"] is True
        assert report["proof_contracts"]["telemetry_present"] is True
        assert report["spine_integration"]["status"] == "BLOCKED"
        assert report["spine_integration"]["blocked_reason"] == "runtime_context_input_string_exceeds_max_string_len"
        assert "canonical_spine_carriage_claimed_despite_input_limit" in report["stronger_claim_not_made"]

    assert maturity["status"] == "PASS"
    assert "CANONICAL_SPINE_INPUT_CEILING_BLOCKS_FULL_ORGAN_PAYLOAD_CARRIAGE" in maturity["boundary_holds"]
    assert any(row["organ_id"] == "router" and row["disposition"] == "KEEP_STATIC_CANONICAL_BASELINE" for row in maturity["rows"])
    assert any(row["organ_id"] == "tournament_promotion" and row["disposition"] == "LAB_ONLY_UNTIL_RUNTIME_REAL" for row in maturity["rows"])

    assert disposition["schema_id"] == "kt.wave2c.organ_disposition_register.v1"
    assert "learned_router_cutover_occurred" in disposition["stronger_claim_not_made"]
    assert "product_language_widened" in disposition["stronger_claim_not_made"]


def test_wave2c_cli_writes_artifacts(tmp_path: Path) -> None:
    root = repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    suite_path = tmp_path / "suite.json"
    cognition_path = tmp_path / "cognition.json"
    paradox_path = tmp_path / "paradox.json"
    temporal_path = tmp_path / "temporal.json"
    multiverse_path = tmp_path / "multiverse.json"
    council_path = tmp_path / "council.json"
    maturity_path = tmp_path / "maturity.json"
    disposition_path = tmp_path / "disposition.json"
    telemetry_path = tmp_path / "telemetry.jsonl"
    export_root = tmp_path / "exports"

    proc = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.wave2c_organ_realization_validate",
            "--suite-output",
            str(suite_path),
            "--cognition-output",
            str(cognition_path),
            "--paradox-output",
            str(paradox_path),
            "--temporal-output",
            str(temporal_path),
            "--multiverse-output",
            str(multiverse_path),
            "--council-output",
            str(council_path),
            "--maturity-output",
            str(maturity_path),
            "--disposition-output",
            str(disposition_path),
            "--telemetry-output",
            str(telemetry_path),
            "--export-root",
            str(export_root),
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
    for path in (
        suite_path,
        cognition_path,
        paradox_path,
        temporal_path,
        multiverse_path,
        council_path,
        maturity_path,
        disposition_path,
    ):
        assert path.exists()
