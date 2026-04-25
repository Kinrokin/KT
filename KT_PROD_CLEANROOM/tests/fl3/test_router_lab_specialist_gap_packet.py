from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.router.run_router_lab_specialist_gap_packet import (  # noqa: E402
    build_router_lab_specialist_gap_packet,
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
                "case_id": "LAB_E01",
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
            {
                "case_id": "LAB_E02",
                "task_text": "Plan the repair, write the code change, then explain the failure path.",
                "required_terms": ["plan", "code", "explain"],
                "preferred_genotype": {
                    "prompt_transform_style": "expand_context",
                    "reasoning_directive": "decision_tree",
                    "scoring_bias": "precision",
                    "guardrail_strength": "balanced",
                },
                "weights": {
                    "prompt_transform_style": 1.0,
                    "reasoning_directive": 2.0,
                    "scoring_bias": 2.0,
                    "guardrail_strength": 1.0,
                },
            },
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


def test_router_lab_specialist_gap_packet_flags_generalist_cases_and_zero_win_entrants(tmp_path: Path) -> None:
    generalist_job_dir = tmp_path / "generalist"
    research_job_dir = tmp_path / "research"
    code_job_dir = tmp_path / "code"

    _write_job_dir(
        job_dir=generalist_job_dir,
        adapter_id="lobe.generalist.shadow.v1",
        bundle_rows=[
            {
                "bundle_id": "generalist_bundle",
                "genotype": {
                    "guardrail_strength": "balanced",
                    "prompt_transform_style": "clarify_first",
                    "reasoning_directive": "evidence_first",
                    "scoring_bias": "calibration",
                    "uncertainty_policy": "explicit_calibration",
                },
            }
        ],
    )
    _write_job_dir(
        job_dir=research_job_dir,
        adapter_id="lobe.research.specialist.v1",
        bundle_rows=[
            {
                "bundle_id": "research_bundle",
                "genotype": {
                    "guardrail_strength": "permissive",
                    "prompt_transform_style": "structured_outline",
                    "reasoning_directive": "evidence_first",
                    "scoring_bias": "precision",
                    "uncertainty_policy": "explicit_calibration",
                },
            }
        ],
    )
    _write_job_dir(
        job_dir=code_job_dir,
        adapter_id="lobe.code.specialist.v1",
        bundle_rows=[
            {
                "bundle_id": "code_bundle",
                "genotype": {
                    "guardrail_strength": "balanced",
                    "prompt_transform_style": "reframe",
                    "reasoning_directive": "decision_tree",
                    "scoring_bias": "precision",
                    "uncertainty_policy": "neutral",
                },
            }
        ],
    )

    packet = build_router_lab_specialist_gap_packet(
        root=_REPO_ROOT,
        scorecard_suite=_scorecard_suite(),
        tie_suite=_tie_suite(),
        scorecard_suite_ref="scorecard_suite.json",
        tie_suite_ref="tie_suite.json",
        job_dirs=[generalist_job_dir, research_job_dir, code_job_dir],
    )

    assert packet["status"] == "PASS"
    assert packet["specialist_gap_posture"] == "SPECIALIST_BROADENING_RECOMMENDED"
    assert packet["summary"]["generalist_owned_case_count"] == 1
    assert packet["summary"]["zero_win_entrant_count"] >= 1
    assert packet["zero_win_entrants"]
    assert packet["generalist_owned_cases"][0]["case_id"] == "LAB_E01"
    assert packet["targeted_specialist_candidates"][0]["target_reason"] == "GENERALIST_OWNS_CASE"


def test_router_lab_specialist_gap_packet_cli_writes_packet(tmp_path: Path) -> None:
    scorecard_suite_path = tmp_path / "scorecard_suite.json"
    tie_suite_path = tmp_path / "tie_suite.json"
    _write_json(scorecard_suite_path, _scorecard_suite())
    _write_json(tie_suite_path, _tie_suite())

    generalist_job_dir = tmp_path / "generalist"
    research_job_dir = tmp_path / "research"
    code_job_dir = tmp_path / "code"

    _write_job_dir(
        job_dir=generalist_job_dir,
        adapter_id="lobe.generalist.shadow.v1",
        bundle_rows=[
            {
                "bundle_id": "generalist_bundle",
                "genotype": {
                    "guardrail_strength": "balanced",
                    "prompt_transform_style": "clarify_first",
                    "reasoning_directive": "evidence_first",
                    "scoring_bias": "calibration",
                    "uncertainty_policy": "explicit_calibration",
                },
            }
        ],
    )
    _write_job_dir(
        job_dir=research_job_dir,
        adapter_id="lobe.research.specialist.v1",
        bundle_rows=[
            {
                "bundle_id": "research_bundle",
                "genotype": {
                    "guardrail_strength": "permissive",
                    "prompt_transform_style": "structured_outline",
                    "reasoning_directive": "evidence_first",
                    "scoring_bias": "precision",
                    "uncertainty_policy": "explicit_calibration",
                },
            }
        ],
    )
    _write_job_dir(
        job_dir=code_job_dir,
        adapter_id="lobe.code.specialist.v1",
        bundle_rows=[
            {
                "bundle_id": "code_bundle",
                "genotype": {
                    "guardrail_strength": "balanced",
                    "prompt_transform_style": "reframe",
                    "reasoning_directive": "decision_tree",
                    "scoring_bias": "precision",
                    "uncertainty_policy": "neutral",
                },
            }
        ],
    )

    out_path = tmp_path / "router_lab_specialist_gap_packet.json"
    rc = main(
        [
            "--scorecard-suite",
            str(scorecard_suite_path),
            "--tie-suite",
            str(tie_suite_path),
            "--job-dir",
            str(generalist_job_dir),
            "--job-dir",
            str(research_job_dir),
            "--job-dir",
            str(code_job_dir),
            "--output",
            str(out_path),
        ]
    )

    assert rc == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["summary"]["entrant_count"] == 3
    assert payload["specialist_gap_posture"] == "SPECIALIST_BROADENING_RECOMMENDED"
