from __future__ import annotations

import json
from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from tools.verification.fl4_replay_from_receipts import ReplayError, replay_from_evidence_dir  # noqa: E402


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")


def test_replay_from_receipts_passes_on_consistent_eval_report(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    job_dir = evidence / "job_dir"
    _write_json(
        job_dir / "eval_report.json",
        {
            "utility_floor_pass": True,
            "probe_policy": {"tolerance": 0.0, "fail_on_disagreement": True},
            "metric_probes": [{"delta": 0.0, "agreement": True}],
            "final_verdict": "PASS",
        },
    )
    _write_json(job_dir / "promotion.json", {"decision": "PROMOTE"})

    report = replay_from_evidence_dir(evidence_dir=evidence)
    assert report["status"] == "PASS"
    assert report["computed"]["promotion_decision"] == "PROMOTE"
    assert report["computed"]["final_eval_verdict"] == "PASS"


def test_replay_from_receipts_fails_closed_on_inconsistent_eval_report(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    job_dir = evidence / "job_dir"
    _write_json(
        job_dir / "eval_report.json",
        {
            "utility_floor_pass": True,
            "probe_policy": {"tolerance": 0.0, "fail_on_disagreement": True},
            "metric_probes": [{"delta": 0.0, "agreement": False}],
            "final_verdict": "PASS",
        },
    )
    _write_json(job_dir / "promotion.json", {"decision": "NO_PROMOTE"})

    with pytest.raises(ReplayError):
        replay_from_evidence_dir(evidence_dir=evidence)

