from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.runtime_experiment_registry_compile import (  # noqa: E402
    BEHAVIOR_DELTA_REL,
    CRUCIBLE_LEDGER_REL,
    LEGACY_TRAIN_REPORT_REL,
    PROMOTED_INDEX_REL,
    PROOFRUNBUNDLE_INDEX_REL,
    build_step9_outputs,
)
from tools.operator.titanium_common import load_json, repo_root  # noqa: E402


TARGET_RUN_ID = "44509da7d1f2133fc57c1d7fa59dce57bd72250c761913a5340bd3242c78f01e"


def test_step9_outputs_cover_governed_experiment_scope() -> None:
    root = repo_root()
    outputs = build_step9_outputs(root=root, generated_utc="2026-03-14T00:00:00Z")

    promoted_index = load_json(root / PROMOTED_INDEX_REL)
    proof_bundle_index = load_json(root / PROOFRUNBUNDLE_INDEX_REL)
    ledger_rows = [
        json.loads(line)
        for line in (root / CRUCIBLE_LEDGER_REL).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    observed_crucibles = {str(row["crucible_id"]).strip() for row in ledger_rows}

    expected_experiment_count = len(observed_crucibles) + len(promoted_index["entries"]) + len(proof_bundle_index["bundles"]) + 2
    experiments = outputs["kt_experiment_registry"]["experiments"]
    deltas = outputs["kt_learning_delta_register"]["learning_deltas"]

    assert outputs["kt_experiment_registry"]["summary"]["experiment_count"] == expected_experiment_count
    assert len(experiments) == expected_experiment_count
    assert len(deltas) == len(promoted_index["entries"]) + 2

    for row in experiments:
        assert row["config_refs"], row["experiment_id"]
        assert row["metric_refs"], row["experiment_id"]
        assert row["verdict_refs"], row["experiment_id"]
        assert row["receipt_refs"], row["experiment_id"]
        assert row["lineage_refs"], row["experiment_id"]

    for row in deltas:
        assert row["backing_experiment_id"], row["delta_id"]
        assert row["lineage_complete"] is True, row["delta_id"]

    exclusions = {row["artifact_ref"] for row in outputs["kt_lineage_manifest"]["learning_delta_exclusions"]}
    assert BEHAVIOR_DELTA_REL in exclusions
    assert LEGACY_TRAIN_REPORT_REL in exclusions
    assert outputs["kt_runtime_event_schema"]["schemas"]
    assert outputs["kt_execution_trace_schema"]["schemas"]
    assert outputs["kt_fitness_pressure_register"]["pressures"]


def test_step9_crucible_precedence_prefers_runner_record_over_conflicted_ledger_rows() -> None:
    root = repo_root()
    outputs = build_step9_outputs(root=root, generated_utc="2026-03-14T00:00:00Z")
    row = next(entry for entry in outputs["kt_crucible_run_log"]["runs"] if entry["run_id"] == TARGET_RUN_ID)

    assert row["canonical_source"] == "runner_record"
    assert row["ledger_conflicted"] is True
    assert row["outcome"] == "FAIL"
    assert row["governance_pass"] is False
