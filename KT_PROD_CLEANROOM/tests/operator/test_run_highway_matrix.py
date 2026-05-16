from __future__ import annotations

import json

from tools.operator import highway_common as highway


def test_run_highway_matrix_emits_consolidated_receipt_and_static_artifacts(tmp_path):
    matrix = highway.run_highway_matrix(tmp_path)
    assert matrix["artifact_id"] == "HIGHWAY_MATRIX_RECEIPT"
    assert matrix["mode"] == "PREP_ONLY"
    assert matrix["authority_verdict"] == "BLOCKED"
    assert matrix["posture_conflict_count"] == 0
    assert matrix["final_label"] == highway.FINAL_LABEL
    assert (tmp_path / "exports/_truth/current/highway_matrix_receipt.json").exists()
    assert (tmp_path / "governance/highway_superlane_registry_v1.json").exists()
    assert (tmp_path / "schemas/highway_matrix_receipt.schema.json").exists()


def test_json_schema_validation_passes_for_highway_governance_artifacts(tmp_path):
    highway.generate_static_artifacts(tmp_path)
    result = highway.json_schema_validate_highway_files(tmp_path)
    assert result["status"] == "PASS"
    assert result["failures"] == []


def test_matrix_receipt_json_parses(tmp_path):
    highway.run_highway_matrix(tmp_path)
    payload = json.loads((tmp_path / "exports/_truth/current/highway_matrix_receipt.json").read_text(encoding="utf-8"))
    assert payload["next_lawful_action"].startswith("Protected merge PR #200")
