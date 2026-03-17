from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import tools.operator.runtime_experiment_registry_compile as runtime_experiment_registry_compile_module  # noqa: E402
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


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")


def _configure_step9_local_only_fixtures(root: Path) -> tuple[Path, Path]:
    fixture_root = root / "tmp" / "test_runtime_experiment_registry_compile"
    ledger_path = fixture_root / "c019_crucible_runs.jsonl"
    promoted_index_path = fixture_root / "promoted_index.json"

    run_root = fixture_root / "artifacts" / TARGET_RUN_ID
    _write_json(
        run_root / "runner_record.json",
        {
            "crucible_id": "CRU-GOV-HONESTY-01",
            "governance_pass": False,
            "kernel_target": "V2_SOVEREIGN",
            "outcome": "FAIL",
            "output_contract_pass": False,
            "replay_pass": True,
            "run_id": TARGET_RUN_ID,
        },
    )
    _write_json(run_root / "governance_verdict.json", {"verdict": "FAIL"})
    _write_json(run_root / "crucible_coverage.json", {"verdict": "OBSERVED"})
    _write_json(run_root / "replay_report.json", {"status": "PASS"})

    _write_jsonl(
        ledger_path,
        [
            {
                "artifacts_dir": run_root.resolve().as_posix(),
                "crucible_id": "CRU-GOV-HONESTY-01",
                "governance_pass": True,
                "kernel_target": "V2_SOVEREIGN",
                "outcome": "PASS",
                "output_contract_pass": True,
                "replay_pass": True,
                "run_id": TARGET_RUN_ID,
            },
            {
                "artifacts_dir": run_root.resolve().as_posix(),
                "crucible_id": "CRU-GOV-HONESTY-01",
                "governance_pass": False,
                "kernel_target": "V2_SOVEREIGN",
                "outcome": "FAIL",
                "output_contract_pass": False,
                "replay_pass": True,
                "run_id": TARGET_RUN_ID,
            },
        ],
    )

    adapter_root = fixture_root / "exports" / "adapters" / "fixture_adapter" / "1" / "fixturehash"
    _write_json(adapter_root / "promoted_manifest.json", {"adapter_id": "fixture.adapter", "content_hash": "fixturehash"})
    _write_json(adapter_root / "job.json", {"job_id": "fixture-job"})
    _write_json(adapter_root / "eval_report.json", {"final_verdict": "PASS"})
    _write_json(adapter_root / "fitness_region.json", {"fitness_region": "FIT"})
    _write_json(adapter_root / "training_admission_receipt.json", {"decision": "PASS"})
    _write_json(adapter_root / "promotion.json", {"decision": "PROMOTED"})
    _write_json(adapter_root / "train_manifest.json", {"schema_id": "fixture.train_manifest"})
    _write_json(adapter_root / "phase_trace.json", {"schema_id": "fixture.phase_trace"})
    _write_json(
        promoted_index_path,
        {
            "created_at": "1970-01-01T00:00:00Z",
            "entries": [
                {
                    "adapter_id": "fixture.adapter",
                    "adapter_version": "1",
                    "content_hash": "fixturehash",
                    "promoted_manifest_ref": (adapter_root / "promoted_manifest.json").resolve().as_posix(),
                }
            ],
        },
    )

    runtime_experiment_registry_compile_module.CRUCIBLE_LEDGER_REL = ledger_path.resolve().as_posix()
    runtime_experiment_registry_compile_module.PROMOTED_INDEX_REL = promoted_index_path.resolve().as_posix()
    return ledger_path, promoted_index_path


def test_step9_outputs_cover_governed_experiment_scope() -> None:
    root = repo_root()
    ledger_path, promoted_index_path = _configure_step9_local_only_fixtures(root)
    outputs = build_step9_outputs(root=root, generated_utc="2026-03-14T00:00:00Z")

    promoted_index = load_json(promoted_index_path)
    proof_bundle_index = load_json(root / PROOFRUNBUNDLE_INDEX_REL)
    ledger_rows = [
        json.loads(line)
        for line in ledger_path.read_text(encoding="utf-8").splitlines()
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
    _configure_step9_local_only_fixtures(root)
    outputs = build_step9_outputs(root=root, generated_utc="2026-03-14T00:00:00Z")
    row = next(entry for entry in outputs["kt_crucible_run_log"]["runs"] if entry["run_id"] == TARGET_RUN_ID)

    assert row["canonical_source"] == "runner_record"
    assert row["ledger_conflicted"] is True
    assert row["outcome"] == "FAIL"
    assert row["governance_pass"] is False
