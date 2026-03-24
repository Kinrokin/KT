from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_w1_runtime_realization_cli_emits_bounded_outputs(tmp_path: Path) -> None:
    root = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    mvcr_path = tmp_path / "mvcr.json"
    useful_output_path = tmp_path / "useful_output.json"
    provider_path = tmp_path / "provider_path.json"
    organ_register_path = tmp_path / "organ_register.json"
    organ_dependency_path = tmp_path / "organ_dependency.json"
    canonical_delta_path = tmp_path / "canonical_delta.json"
    advancement_delta_path = tmp_path / "advancement_delta.json"
    telemetry_path = tmp_path / "runtime_telemetry.jsonl"
    export_root = tmp_path / "exports"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.w1_runtime_realization_validate",
            "--mvcr-output",
            str(mvcr_path),
            "--useful-output-output",
            str(useful_output_path),
            "--provider-path-output",
            str(provider_path),
            "--organ-register-output",
            str(organ_register_path),
            "--organ-dependency-output",
            str(organ_dependency_path),
            "--canonical-delta-output",
            str(canonical_delta_path),
            "--advancement-delta-output",
            str(advancement_delta_path),
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
    assert payload["active_open_blocker_ids"] == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"]
    assert payload["runtime_realism_glamour_unlock"] is False
    assert payload["runtime_claim_compiler_status"] == "PASS"

    mvcr = json.loads(mvcr_path.read_text(encoding="utf-8"))
    useful_output = json.loads(useful_output_path.read_text(encoding="utf-8"))
    provider_integrity = json.loads(provider_path.read_text(encoding="utf-8"))
    organ_register = json.loads(organ_register_path.read_text(encoding="utf-8"))
    organ_dependency = json.loads(organ_dependency_path.read_text(encoding="utf-8"))
    canonical_delta = json.loads(canonical_delta_path.read_text(encoding="utf-8"))
    advancement_delta = json.loads(advancement_delta_path.read_text(encoding="utf-8"))

    assert mvcr["status"] == "PASS"
    assert mvcr["runtime_claim_compilation"]["status"] == "PASS"
    assert mvcr["runtime_realism_threshold"]["status"] == "PASS"
    assert mvcr["runtime_realism_threshold"]["glamour_unlock"] is False
    assert mvcr["active_open_blocker_ids"] == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"]
    assert mvcr["runtime_claim_compilation"]["deferred_blocker_ids"] == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"]
    assert mvcr["runtime_claim_compilation"]["externality_class_max"] == "E1_SAME_HOST_DETACHED_REPLAY"
    assert mvcr["runtime_claim_compilation"]["comparative_widening"] == "FORBIDDEN"
    assert mvcr["runtime_claim_compilation"]["commercial_widening"] == "FORBIDDEN"
    assert "SECOND_HOST_RETURN_FILE_PLUS_VALIDATOR_PASS" in mvcr["runtime_claim_compilation"]["deferred_reentry_condition"]

    assert useful_output["status"] == "PASS"
    assert any(row["benchmark_id"] == "useful_output_evidence_stronger_than_ceremonial_path_evidence" and row["pass"] for row in useful_output["rows"])

    assert provider_integrity["status"] == "PASS"
    assert set(provider_integrity["same_host_live_hashed_provider_ids"]) == {"openai", "openrouter"}

    rows = organ_register["rows"]
    organ_ids = {row["organ_id"] for row in rows}
    assert "memory" in organ_ids
    assert "claim_compiler" in organ_ids
    for row in rows:
        for field in ("validator", "receipt", "claim_ceiling", "promotion_rule", "rollback_rule", "owner", "zone", "plane"):
            assert field in row
            assert str(row[field]).strip()

    claim_compiler_row = next(row for row in rows if row["organ_id"] == "claim_compiler")
    assert claim_compiler_row["receipt"].endswith("mvcr_live_execution_receipt.json")
    assert claim_compiler_row["validator"] == "python -m tools.operator.w1_runtime_realization_validate"

    memory_row = next(row for row in rows if row["organ_id"] == "memory")
    assert memory_row["zone"] == "CANONICAL"
    assert memory_row["plane"] == "GENERATED_RUNTIME_TRUTH"

    assert organ_dependency["status"] == "PASS"
    assert organ_dependency["missing_organs"] == []
    assert organ_dependency["rows_missing_required_columns"] == []

    assert canonical_delta["status"] == "PASS"
    assert canonical_delta["blocker_delta"]["active_open_blocker_ids"] == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"]

    assert advancement_delta["status"] == "PASS"
    assert advancement_delta["glamour_unlock"] is False
    assert telemetry_path.exists()
