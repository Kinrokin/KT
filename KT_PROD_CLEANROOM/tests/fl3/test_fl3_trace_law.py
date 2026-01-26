from __future__ import annotations

import json
from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.schema_files import schema_version_hash  # noqa: E402
from tools.training.fl3_factory.promote import decide_promotion  # noqa: E402
from tools.training.fl3_factory.trace import build_reasoning_trace  # noqa: E402
from tools.verification.fl3_validators import FL3ValidationError  # noqa: E402


def test_fl3_no_trace_no_promotion(tmp_path: Path) -> None:
    job = {
        "schema_id": "kt.factory.jobspec.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.jobspec.v1.json"),
        "job_id": "0" * 64,
        "adapter_id": "lobe.architect.v1",
        "adapter_version": "1",
        "role": "ARCHITECT",
        "mode": "SOVEREIGN",
        "run_kind": "STANDARD",
        "base_model_id": "mistral-7b",
        "training_mode": "head_only",
        "seed": 42,
        "export_shadow_root": "KT_PROD_CLEANROOM/exports/adapters_shadow/_tests",
        "export_promoted_root": "KT_PROD_CLEANROOM/exports/adapters/_tests",
    }
    eval_report = {
        "schema_id": "kt.factory.eval_report.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.eval_report.v1.json"),
        "eval_id": "e" * 64,
        "job_id": job["job_id"],
        "adapter_id": job["adapter_id"],
        "adapter_version": job["adapter_version"],
        "battery_id": "kt.eval.battery.fl3.smoke.v1",
        "results": {"trace_required": True, "trace_coverage": 1.0},
        "final_verdict": "PASS",
        "created_at": "2026-01-01T00:00:00Z",
    }

    decision = decide_promotion(job=job, eval_report=eval_report, trace_path=tmp_path / "missing_trace.json")
    assert decision == "REJECT"


def test_fl3_trace_hash_mismatch_fails_closed(tmp_path: Path) -> None:
    job_id = "1" * 64
    trace = build_reasoning_trace(job_id=job_id, final_output_hash="2" * 64)

    p = tmp_path / "trace.json"
    p.write_text(json.dumps(trace, indent=2, sort_keys=True), encoding="utf-8")

    # Tamper with final_output_hash without updating trace_id.
    tampered = json.loads(p.read_text(encoding="utf-8"))
    tampered["final_output_hash"] = "3" * 64
    p.write_text(json.dumps(tampered, indent=2, sort_keys=True), encoding="utf-8")

    job = {
        "mode": "SOVEREIGN",
    }
    eval_report = {
        "final_verdict": "PASS",
        "results": {"trace_required": True, "trace_coverage": 1.0, "trace_id": trace["trace_id"]},
    }
    with pytest.raises(FL3ValidationError):
        _ = decide_promotion(job=job, eval_report=eval_report, trace_path=p)

