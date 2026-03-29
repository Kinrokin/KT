from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.router.run_verified_entrant_lab_scorecard import (  # noqa: E402
    build_verified_entrant_lab_scorecard,
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


def test_verified_entrant_lab_scorecard_prefers_differentiated_bundles(tmp_path: Path) -> None:
    suite = {
        "cases": [
            {
                "case_id": "LAB_E01",
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
            },
        ]
    }
    job_dir_a = tmp_path / "entrant_a"
    job_dir_b = tmp_path / "entrant_b"
    _write_job_dir(
        job_dir=job_dir_a,
        adapter_id="lobe.math.specialist.v1",
        bundle_rows=[
            {
                "bundle_id": "A1",
                "genotype": {
                    "guardrail_strength": "balanced",
                    "prompt_transform_style": "expand_context",
                    "reasoning_directive": "decision_tree",
                    "scoring_bias": "precision",
                    "uncertainty_policy": "neutral",
                },
            },
            {
                "bundle_id": "A2",
                "genotype": {
                    "guardrail_strength": "balanced",
                    "prompt_transform_style": "clarify_first",
                    "reasoning_directive": "bullet_proof",
                    "scoring_bias": "recall",
                    "uncertainty_policy": "conservative",
                },
            },
        ],
    )
    _write_job_dir(
        job_dir=job_dir_b,
        adapter_id="lobe.code.specialist.v1",
        bundle_rows=[
            {
                "bundle_id": "B1",
                "genotype": {
                    "guardrail_strength": "balanced",
                    "prompt_transform_style": "reframe",
                    "reasoning_directive": "decision_tree",
                    "scoring_bias": "precision",
                    "uncertainty_policy": "neutral",
                },
            },
            {
                "bundle_id": "B2",
                "genotype": {
                    "guardrail_strength": "permissive",
                    "prompt_transform_style": "clarify_first",
                    "reasoning_directive": "evidence_first",
                    "scoring_bias": "calibration",
                    "uncertainty_policy": "explicit_calibration",
                },
            },
        ],
    )

    report = build_verified_entrant_lab_scorecard(
        root=_REPO_ROOT,
        suite=suite,
        job_dirs=[job_dir_a, job_dir_b],
    )
    rows = {row["case_id"]: row for row in report["case_rows"]}

    assert report["status"] == "PASS"
    assert report["mode"] == "LAB_ONLY_NONCANONICAL"
    assert report["summary"]["differentiated_case_count"] == 2
    assert rows["LAB_E01"]["winner_adapter_ids"] == ["lobe.math.specialist.v1"]
    assert rows["LAB_E02"]["winner_adapter_ids"] == ["lobe.code.specialist.v1"]


def test_verified_entrant_lab_scorecard_cli_writes_report(tmp_path: Path) -> None:
    suite_path = tmp_path / "suite.json"
    suite = {
        "cases": [
            {
                "case_id": "LAB_E03",
                "task_text": "Use the tool and summarize the result.",
                "required_terms": ["tool", "summarize"],
                "preferred_genotype": {
                    "prompt_transform_style": "compress",
                    "reasoning_directive": "minimal_chain",
                    "guardrail_strength": "permissive",
                },
                "weights": {
                    "prompt_transform_style": 1.0,
                    "reasoning_directive": 2.0,
                    "guardrail_strength": 1.0,
                },
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

    out_path = tmp_path / "verified_entrant_lab_scorecard.json"
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
    assert payload["mode"] == "LAB_ONLY_NONCANONICAL"
    assert payload["summary"]["entrant_count"] == 1
    assert payload["summary"]["differentiated_case_count"] == 1
