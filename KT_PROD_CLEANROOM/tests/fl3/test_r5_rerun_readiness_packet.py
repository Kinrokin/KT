from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.router.run_r5_rerun_readiness_packet import (  # noqa: E402
    build_r5_rerun_readiness_packet,
    main,
)


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _write_job_dir(*, job_dir: Path, adapter_id: str, bundle_rows: list[dict]) -> None:
    _write_json(
        job_dir / "job.json",
        {
            "job_id": f"{adapter_id}.job",
            "adapter_id": adapter_id,
            "adapter_version": "1",
        },
    )
    bundle_path = job_dir / "hypotheses" / "policy_bundles.jsonl"
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_path.write_text(
        "\n".join(json.dumps(row, sort_keys=True, ensure_ascii=True) for row in bundle_rows) + "\n",
        encoding="utf-8",
    )
    _write_json(
        job_dir / "train_manifest.json",
        {
            "output_bundle": {
                "artifact_path": bundle_path.as_posix(),
            }
        },
    )


def _scorecard_suite() -> dict:
    return {
        "cases": [
            {
                "case_id": "LAB_E02",
                "task_text": "Research the evidence, summarize the tradeoffs, and write a calibrated recommendation.",
                "required_terms": ["research", "tradeoffs", "recommendation"],
                "preferred_genotype": {
                    "prompt_transform_style": "clarify_first",
                    "reasoning_directive": "evidence_first",
                    "scoring_bias": "calibration",
                    "uncertainty_policy": "explicit_calibration",
                },
                "weights": {
                    "prompt_transform_style": 1.0,
                    "reasoning_directive": 2.0,
                    "scoring_bias": 1.5,
                    "uncertainty_policy": 1.5,
                },
            }
        ]
    }


def _tie_suite() -> dict:
    return {
        "cases": [
            {
                "case_id": "LAB_TIE_R01",
                "pattern_family": "LAB_TIE_R01",
                "single_case_baseline": {
                    "task_text": "Research the evidence, summarize the tradeoffs, and write a calibrated recommendation.",
                    "required_terms": ["research", "tradeoffs", "recommendation"],
                    "preferred_genotype": {
                        "prompt_transform_style": "clarify_first",
                        "reasoning_directive": "evidence_first",
                        "scoring_bias": "calibration",
                        "uncertainty_policy": "explicit_calibration",
                    },
                    "weights": {
                        "prompt_transform_style": 1.0,
                        "reasoning_directive": 2.0,
                        "scoring_bias": 1.5,
                        "uncertainty_policy": 1.5,
                    },
                },
                "stages": [
                    {
                        "stage_id": "research",
                        "task_text": "Research the evidence and surface the tradeoffs.",
                        "required_terms": ["research", "tradeoffs"],
                        "preferred_genotype": {
                            "prompt_transform_style": "structured_outline",
                            "reasoning_directive": "evidence_first",
                            "scoring_bias": "precision",
                            "uncertainty_policy": "explicit_calibration",
                        },
                        "weights": {
                            "prompt_transform_style": 1.0,
                            "reasoning_directive": 2.0,
                            "scoring_bias": 1.5,
                            "uncertainty_policy": 1.5,
                        },
                    },
                    {
                        "stage_id": "recommend",
                        "task_text": "Write the calibrated recommendation and defend the decision.",
                        "required_terms": ["recommendation", "decision"],
                        "preferred_genotype": {
                            "prompt_transform_style": "clarify_first",
                            "reasoning_directive": "bullet_proof",
                            "scoring_bias": "calibration",
                            "uncertainty_policy": "explicit_calibration",
                        },
                        "weights": {
                            "prompt_transform_style": 1.0,
                            "reasoning_directive": 2.0,
                            "scoring_bias": 1.5,
                            "uncertainty_policy": 1.5,
                        },
                    },
                ],
            }
        ]
    }


def _write_primary_entrants(tmp_path: Path) -> tuple[Path, Path]:
    math_job_dir = tmp_path / "math_entrant"
    code_job_dir = tmp_path / "code_entrant"
    _write_job_dir(
        job_dir=math_job_dir,
        adapter_id="lobe.math.specialist.v1",
        bundle_rows=[
            {
                "bundle_id": "math_research",
                "genotype": {
                    "guardrail_strength": "permissive",
                    "prompt_transform_style": "structured_outline",
                    "reasoning_directive": "evidence_first",
                    "scoring_bias": "precision",
                    "uncertainty_policy": "explicit_calibration",
                },
            },
            {
                "bundle_id": "math_summary",
                "genotype": {
                    "guardrail_strength": "permissive",
                    "prompt_transform_style": "clarify_first",
                    "reasoning_directive": "minimal_chain",
                    "scoring_bias": "calibration",
                    "uncertainty_policy": "explicit_calibration",
                },
            },
        ],
    )
    _write_job_dir(
        job_dir=code_job_dir,
        adapter_id="lobe.code.specialist.v1",
        bundle_rows=[
            {
                "bundle_id": "code_writer",
                "genotype": {
                    "guardrail_strength": "permissive",
                    "prompt_transform_style": "clarify_first",
                    "reasoning_directive": "bullet_proof",
                    "scoring_bias": "calibration",
                    "uncertainty_policy": "explicit_calibration",
                },
            }
        ],
    )
    return math_job_dir, code_job_dir


def test_r5_rerun_readiness_packet_holds_without_fresh_entrants(tmp_path: Path) -> None:
    scorecard_suite_path = tmp_path / "scorecard_suite.json"
    tie_suite_path = tmp_path / "tie_suite.json"
    _write_json(scorecard_suite_path, _scorecard_suite())
    _write_json(tie_suite_path, _tie_suite())
    math_job_dir, code_job_dir = _write_primary_entrants(tmp_path)

    packet = build_r5_rerun_readiness_packet(
        root=_REPO_ROOT,
        scorecard_suite=_scorecard_suite(),
        tie_suite=_tie_suite(),
        scorecard_suite_ref=str(scorecard_suite_path),
        tie_suite_ref=str(tie_suite_path),
        job_dirs=[math_job_dir, code_job_dir],
        fresh_job_dirs=[],
    )

    assert packet["status"] == "PASS"
    assert packet["questions"]["reproducible_across_reruns"] is True
    assert packet["questions"]["same_head_lab_consistent"] is True
    assert packet["questions"]["shadow_constraints_preserved"] is True
    assert packet["questions"]["remaining_tie_family_ambiguity"] is False
    assert packet["questions"]["survives_fresh_verified_entrants"] is False
    assert packet["readiness_posture"] == "HOLD_LAB_ONLY_PENDING_ADDITIONAL_CONFIRMATION"
    assert "FRESH_VERIFIED_ENTRANT_SURVIVAL_NOT_YET_CONFIRMED" in packet["blockers"]


def test_r5_rerun_readiness_packet_can_pass_with_fresh_entrants(tmp_path: Path) -> None:
    scorecard_suite_path = tmp_path / "scorecard_suite.json"
    tie_suite_path = tmp_path / "tie_suite.json"
    _write_json(scorecard_suite_path, _scorecard_suite())
    _write_json(tie_suite_path, _tie_suite())
    math_job_dir, code_job_dir = _write_primary_entrants(tmp_path)

    fresh_job_dir = tmp_path / "fresh_generalist"
    _write_job_dir(
        job_dir=fresh_job_dir,
        adapter_id="lobe.generalist.shadow.v1",
        bundle_rows=[
            {
                "bundle_id": "fresh_generalist",
                "genotype": {
                    "guardrail_strength": "balanced",
                    "prompt_transform_style": "compress",
                    "reasoning_directive": "steps_tagged",
                    "scoring_bias": "calibration",
                    "uncertainty_policy": "neutral",
                },
            }
        ],
    )

    packet = build_r5_rerun_readiness_packet(
        root=_REPO_ROOT,
        scorecard_suite=_scorecard_suite(),
        tie_suite=_tie_suite(),
        scorecard_suite_ref=str(scorecard_suite_path),
        tie_suite_ref=str(tie_suite_path),
        job_dirs=[math_job_dir, code_job_dir],
        fresh_job_dirs=[fresh_job_dir],
    )

    assert packet["status"] == "PASS"
    assert packet["questions"]["survives_fresh_verified_entrants"] is True
    assert packet["fresh_verified_entrant_assessment"]["status"] == "PASS_FRESH_ENTRANTS_SURVIVE"
    assert packet["readiness_posture"] == "READY_FOR_COUNTED_R5_RERUN_CONSIDERATION"
    assert packet["blockers"] == []


def test_r5_rerun_readiness_packet_cli_writes_packet(tmp_path: Path) -> None:
    scorecard_suite_path = tmp_path / "scorecard_suite.json"
    tie_suite_path = tmp_path / "tie_suite.json"
    _write_json(scorecard_suite_path, _scorecard_suite())
    _write_json(tie_suite_path, _tie_suite())
    math_job_dir, code_job_dir = _write_primary_entrants(tmp_path)

    out_path = tmp_path / "r5_rerun_readiness_packet.json"
    rc = main(
        [
            "--scorecard-suite",
            str(scorecard_suite_path),
            "--tie-suite",
            str(tie_suite_path),
            "--job-dir",
            str(math_job_dir),
            "--job-dir",
            str(code_job_dir),
            "--output",
            str(out_path),
        ]
    )
    assert rc == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["readiness_posture"] == "HOLD_LAB_ONLY_PENDING_ADDITIONAL_CONFIRMATION"
