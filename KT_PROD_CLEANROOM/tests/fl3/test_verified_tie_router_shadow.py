from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.router.run_verified_tie_router_shadow import (  # noqa: E402
    build_verified_tie_router_shadow_report,
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


def test_verified_tie_router_shadow_finds_staged_advantage(tmp_path: Path) -> None:
    suite = {
        "cases": [
            {
                "case_id": "TIE_R01",
                "notes": "One entrant should win the evidence stage and the other the recommendation stage.",
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
                            "prompt_transform_style": "clarify_first",
                            "reasoning_directive": "evidence_first",
                            "uncertainty_policy": "explicit_calibration",
                        },
                        "weights": {
                            "prompt_transform_style": 1.0,
                            "reasoning_directive": 2.0,
                            "uncertainty_policy": 1.5,
                        },
                    },
                    {
                        "stage_id": "recommend",
                        "task_text": "Write a calibrated recommendation and explain the decision.",
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
    job_dir_a = tmp_path / "entrant_a"
    job_dir_b = tmp_path / "entrant_b"
    _write_job_dir(
        job_dir=job_dir_a,
        adapter_id="lobe.research.specialist.v1",
        bundle_rows=[
            {
                "bundle_id": "A1",
                "genotype": {
                    "guardrail_strength": "permissive",
                    "prompt_transform_style": "clarify_first",
                    "reasoning_directive": "evidence_first",
                    "scoring_bias": "precision",
                    "uncertainty_policy": "explicit_calibration",
                },
            }
        ],
    )
    _write_job_dir(
        job_dir=job_dir_b,
        adapter_id="lobe.writer.specialist.v1",
        bundle_rows=[
            {
                "bundle_id": "B1",
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

    report = build_verified_tie_router_shadow_report(
        root=_REPO_ROOT,
        suite=suite,
        job_dirs=[job_dir_a, job_dir_b],
    )
    row = report["case_rows"][0]
    assert report["status"] == "PASS"
    assert report["summary"]["router_advantage_visible"] is True
    assert report["summary"]["staged_recombination_case_count"] == 0
    assert report["summary"]["drop_or_rework_case_count"] == 0
    assert row["route_advantage"] is True
    assert row["recommended_action"] == "KEEP_AND_EXPAND"
    assert row["same_adapter_recombination_only"] is False
    assert row["routed_adapter_ids"] == ["lobe.research.specialist.v1", "lobe.writer.specialist.v1"]


def test_verified_tie_router_shadow_cli_writes_report(tmp_path: Path) -> None:
    suite_path = tmp_path / "suite.json"
    suite = {
        "cases": [
            {
                "case_id": "TIE_R02",
                "single_case_baseline": {
                    "task_text": "Use the tool and summarize the result.",
                    "required_terms": ["tool", "summarize"],
                    "preferred_genotype": {
                        "reasoning_directive": "minimal_chain",
                    },
                    "weights": {
                        "reasoning_directive": 2.0,
                    },
                },
                "stages": [
                    {
                        "stage_id": "tool",
                        "task_text": "Use the tool.",
                        "required_terms": ["tool"],
                        "preferred_genotype": {
                            "reasoning_directive": "minimal_chain",
                        },
                        "weights": {
                            "reasoning_directive": 2.0,
                        },
                    }
                ],
            }
        ]
    }
    _write_json(suite_path, suite)

    job_dir = tmp_path / "entrant"
    _write_job_dir(
        job_dir=job_dir,
        adapter_id="lobe.tool.specialist.v1",
        bundle_rows=[
            {
                "bundle_id": "T1",
                "genotype": {
                    "guardrail_strength": "permissive",
                    "prompt_transform_style": "compress",
                    "reasoning_directive": "minimal_chain",
                    "scoring_bias": "recall",
                    "uncertainty_policy": "neutral",
                },
            }
        ],
    )

    out_path = tmp_path / "verified_tie_router_shadow_report.json"
    rc = main(
        [
            "--suite",
            str(suite_path),
            "--job-dir",
            str(job_dir),
            "--output",
            str(out_path),
        ]
    )
    assert rc == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["summary"]["case_count"] == 1
