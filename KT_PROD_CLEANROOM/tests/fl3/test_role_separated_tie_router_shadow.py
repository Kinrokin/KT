from __future__ import annotations

import json
from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.router.run_role_separated_tie_router_shadow import (  # noqa: E402
    build_role_separated_tie_router_shadow_report,
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


def test_role_separated_tie_router_shadow_enforces_distinct_specialists(tmp_path: Path) -> None:
    suite = {
        "cases": [
            {
                "case_id": "ROLESEP_R01",
                "pattern_family": "ROLESEP_R01",
                "single_case_baseline": {
                    "task_text": "Review the evidence and write a recommendation memo.",
                    "required_terms": ["evidence", "recommendation"],
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
                        "stage_id": "review",
                        "task_text": "Review the evidence and summarize the tradeoffs.",
                        "required_terms": ["evidence", "tradeoffs"],
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
                        "allowed_adapter_ids": ["lobe.math.specialist.v1"],
                    },
                    {
                        "stage_id": "memo",
                        "task_text": "Write the compressed recommendation memo and defend it.",
                        "required_terms": ["recommendation", "memo"],
                        "preferred_genotype": {
                            "prompt_transform_style": "compress",
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
                        "allowed_adapter_ids": ["lobe.code.specialist.v1"],
                        "require_distinct_from_previous_stage": True,
                    },
                ],
            }
        ]
    }

    math_job_dir = tmp_path / "math"
    code_job_dir = tmp_path / "code"
    _write_job_dir(
        job_dir=math_job_dir,
        adapter_id="lobe.math.specialist.v1",
        bundle_rows=[
            {
                "bundle_id": "M1",
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
                "bundle_id": "C1",
                "genotype": {
                    "guardrail_strength": "balanced",
                    "prompt_transform_style": "compress",
                    "reasoning_directive": "bullet_proof",
                    "scoring_bias": "calibration",
                    "uncertainty_policy": "explicit_calibration",
                },
            }
        ],
    )

    report = build_role_separated_tie_router_shadow_report(
        root=_REPO_ROOT,
        suite=suite,
        job_dirs=[math_job_dir, code_job_dir],
    )

    row = report["case_rows"][0]
    assert report["status"] == "PASS"
    assert report["summary"]["case_count"] == 1
    assert report["summary"]["route_advantage_case_count"] == 1
    assert report["summary"]["role_separated_case_count"] == 1
    assert report["summary"]["family_case_counts"] == {"ROLESEP_R01": 1}
    assert report["summary"]["family_route_advantage_counts"] == {"ROLESEP_R01": 1}
    assert report["summary"]["family_role_separated_counts"] == {"ROLESEP_R01": 1}
    assert row["route_advantage"] is True
    assert row["role_separation_enforced"] is True
    assert row["routed_adapter_ids"] == ["lobe.math.specialist.v1", "lobe.code.specialist.v1"]


def test_role_separated_tie_router_shadow_fails_closed_on_unsatisfied_constraints(tmp_path: Path) -> None:
    suite_path = tmp_path / "suite.json"
    _write_json(
        suite_path,
        {
            "cases": [
                {
                    "case_id": "ROLESEP_FAIL",
                    "pattern_family": "ROLESEP_FAIL",
                    "single_case_baseline": {
                        "task_text": "Review and summarize.",
                        "required_terms": ["review", "summary"],
                        "preferred_genotype": {
                            "reasoning_directive": "evidence_first",
                        },
                        "weights": {
                            "reasoning_directive": 2.0,
                        },
                    },
                    "stages": [
                        {
                            "stage_id": "review",
                            "task_text": "Review the evidence.",
                            "required_terms": ["review"],
                            "preferred_genotype": {
                                "reasoning_directive": "evidence_first",
                            },
                            "weights": {
                                "reasoning_directive": 2.0,
                            },
                            "allowed_adapter_ids": ["lobe.missing.specialist.v1"],
                        }
                    ],
                }
            ]
        },
    )

    job_dir = tmp_path / "entrant"
    _write_job_dir(
        job_dir=job_dir,
        adapter_id="lobe.generalist.shadow.v1",
        bundle_rows=[
            {
                "bundle_id": "G1",
                "genotype": {
                    "guardrail_strength": "permissive",
                    "prompt_transform_style": "reframe",
                    "reasoning_directive": "evidence_first",
                    "scoring_bias": "calibration",
                    "uncertainty_policy": "explicit_calibration",
                },
            }
        ],
    )

    out_path = tmp_path / "role_separated_tie_router_shadow_report.json"
    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        main(
            [
                "--suite",
                str(suite_path),
                "--job-dir",
                str(job_dir),
                "--output",
                str(out_path),
            ]
        )
