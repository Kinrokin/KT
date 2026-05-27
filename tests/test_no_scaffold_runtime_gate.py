from __future__ import annotations

import json
from pathlib import Path

from g32_test_utils import load_json
from v13_admission_common import no_scaffold_gate_for_dir


def test_repo_side_no_scaffold_gate_is_spec_not_fake_pass() -> None:
    receipt = load_json("reports/no_scaffold_runtime_gate_receipt.json")

    assert receipt["schema_id"] == "kt.no_scaffold_runtime_gate.v1"
    assert receipt["gate_pass"] is False
    assert receipt["status"] == "SPEC_READY_RUNTIME_MEASUREMENT_REQUIRED"
    assert receipt["claim_ceiling_preserved"] is True


def test_no_scaffold_gate_fails_empty_or_scaffold_runtime(tmp_path: Path) -> None:
    (tmp_path / "benchmark_predictions.jsonl").write_text("", encoding="utf-8")
    (tmp_path / "signal_density_matrix.jsonl").write_text("", encoding="utf-8")
    (tmp_path / "route_regret_matrix.jsonl").write_text("", encoding="utf-8")
    scaffold = {
        "schema_id": "kt.test",
        "status": "SCAFFOLD_EMITTED_NOT_EARNED",
        "requires_followup_measurement": True,
    }
    for name in [
        "benchmark_scorecard.json",
        "formal_math_specialist_router_receipt.json",
        "adapter_isolation_receipt.json",
        "failure_confession_receipt.json",
        "success_admissibility_receipt.json",
        "self_deception_risk_scorecard.json",
    ]:
        (tmp_path / name).write_text(json.dumps(scaffold), encoding="utf-8")

    receipt = no_scaffold_gate_for_dir(tmp_path)

    assert receipt["gate_pass"] is False
    assert receipt["scorecards_measured"] is False
