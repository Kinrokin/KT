from __future__ import annotations

from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from tools.verification.preflight_fl4 import _assert_evidence_pack_complete  # noqa: E402


def _touch(path: Path, content: str = "x\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_evidence_pack_completeness_contract_passes_minimal(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"

    # top-level required files
    for name in (
        "command_transcript.txt",
        "pip_freeze.txt",
        "seal_doctrine.md",
        "env_lock.json",
        "io_guard_receipt.json",
        "supported_platforms.json",
        "determinism_contract.json",
        "law_bundle_hash.txt",
        "law_bundle.json",
        "growth_e2e_gate_report.json",
        "meta_evaluator_receipt.json",
        "red_assault_report.json",
        "rollback_drill_report.json",
        "canary_artifact_pre.json",
        "canary_artifact_rerun.json",
        "canary_artifact_post_promotion.json",
        "metabolism_proof.json",
        "preflight_summary.json",
    ):
        _touch(out_dir / name)

    # required evidence job dir files
    for name in (
        "job.json",
        "phase_trace.json",
        "dataset.json",
        "eval_report.json",
        "signal_quality.json",
        "judgement.json",
        "promotion.json",
        "hash_manifest.json",
        "job_dir_manifest.json",
    ):
        _touch(out_dir / "job_dir" / name)

    _assert_evidence_pack_complete(out_dir=out_dir)


def test_evidence_pack_completeness_contract_fails_on_missing(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    _touch(out_dir / "command_transcript.txt")
    _touch(out_dir / "preflight_summary.json")
    _touch(out_dir / "job_dir" / "job.json")

    with pytest.raises(SystemExit):
        _assert_evidence_pack_complete(out_dir=out_dir)
