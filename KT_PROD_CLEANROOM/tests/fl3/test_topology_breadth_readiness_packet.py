from __future__ import annotations

import json
from pathlib import Path

from tools.router.run_topology_breadth_readiness_packet import (  # noqa: E402
    build_topology_breadth_readiness_packet,
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


def _primary_report() -> dict:
    return {
        "schema_id": "kt.role_separated_tie_router_shadow_report.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "claim_boundary": "lab-only and noncanonical; not R5 evidence and cannot unlock R6",
        "summary": {
            "case_count": 2,
            "route_advantage_case_count": 2,
            "role_separated_case_count": 2,
        },
        "case_rows": [
            {
                "case_id": "PRIMARY_A",
                "pattern_family": "PRIMARY",
                "route_advantage": True,
                "multi_adapter_route": True,
                "role_separation_enforced": True,
                "routed_adapter_ids": ["lobe.math.specialist.v1", "lobe.code.specialist.v1"],
            },
            {
                "case_id": "PRIMARY_B",
                "pattern_family": "PRIMARY",
                "route_advantage": True,
                "multi_adapter_route": True,
                "role_separation_enforced": True,
                "routed_adapter_ids": ["lobe.math.specialist.v1", "lobe.code.specialist.v1"],
            },
        ],
    }


def _second_suite(*, terminal_adapter_id: str, terminal_style: str, terminal_reasoning: str) -> dict:
    return {
        "cases": [
            {
                "case_id": "SECOND_A",
                "pattern_family": "SECOND",
                "single_case_baseline": {
                    "task_text": "Research the evidence and write the recommendation.",
                    "required_terms": ["research", "recommendation"],
                    "preferred_genotype": {
                        "prompt_transform_style": "reframe",
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
                        "stage_id": "frame",
                        "task_text": "Research the evidence and capture the tradeoffs.",
                        "required_terms": ["research", "tradeoffs"],
                        "preferred_genotype": {
                            "prompt_transform_style": "reframe",
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
                        "allowed_adapter_ids": ["lobe.generalist.shadow.v1"],
                    },
                    {
                        "stage_id": "memo",
                        "task_text": "Write the compact recommendation memo.",
                        "required_terms": ["recommendation", "memo"],
                        "preferred_genotype": {
                            "prompt_transform_style": terminal_style,
                            "reasoning_directive": terminal_reasoning,
                            "scoring_bias": "calibration",
                            "uncertainty_policy": "explicit_calibration",
                        },
                        "weights": {
                            "prompt_transform_style": 1.0,
                            "reasoning_directive": 2.0,
                            "scoring_bias": 1.5,
                            "uncertainty_policy": 1.5,
                        },
                        "allowed_adapter_ids": [terminal_adapter_id],
                        "require_distinct_from_previous_stage": True,
                    },
                ],
            },
            {
                "case_id": "SECOND_B",
                "pattern_family": "SECOND",
                "single_case_baseline": {
                    "task_text": "Capture the tradeoffs and write the implementation note.",
                    "required_terms": ["tradeoffs", "implementation"],
                    "preferred_genotype": {
                        "prompt_transform_style": "reframe",
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
                        "stage_id": "frame",
                        "task_text": "Capture the tradeoffs for the decision.",
                        "required_terms": ["tradeoffs", "decision"],
                        "preferred_genotype": {
                            "prompt_transform_style": "reframe",
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
                        "allowed_adapter_ids": ["lobe.generalist.shadow.v1"],
                    },
                    {
                        "stage_id": "note",
                        "task_text": "Write the compact implementation note.",
                        "required_terms": ["implementation", "note"],
                        "preferred_genotype": {
                            "prompt_transform_style": terminal_style,
                            "reasoning_directive": terminal_reasoning,
                            "scoring_bias": "calibration",
                            "uncertainty_policy": "explicit_calibration",
                        },
                        "weights": {
                            "prompt_transform_style": 1.0,
                            "reasoning_directive": 2.0,
                            "scoring_bias": 1.5,
                            "uncertainty_policy": 1.5,
                        },
                        "allowed_adapter_ids": [terminal_adapter_id],
                        "require_distinct_from_previous_stage": True,
                    },
                ],
            },
            {
                "case_id": "SECOND_C",
                "pattern_family": "SECOND",
                "single_case_baseline": {
                    "task_text": "Summarize the evidence and write the escalation brief.",
                    "required_terms": ["evidence", "escalation"],
                    "preferred_genotype": {
                        "prompt_transform_style": "reframe",
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
                        "stage_id": "frame",
                        "task_text": "Summarize the evidence and capture the tradeoffs.",
                        "required_terms": ["evidence", "tradeoffs"],
                        "preferred_genotype": {
                            "prompt_transform_style": "reframe",
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
                        "allowed_adapter_ids": ["lobe.generalist.shadow.v1"],
                    },
                    {
                        "stage_id": "brief",
                        "task_text": "Write the compact escalation brief.",
                        "required_terms": ["escalation", "brief"],
                        "preferred_genotype": {
                            "prompt_transform_style": terminal_style,
                            "reasoning_directive": terminal_reasoning,
                            "scoring_bias": "calibration",
                            "uncertainty_policy": "explicit_calibration",
                        },
                        "weights": {
                            "prompt_transform_style": 1.0,
                            "reasoning_directive": 2.0,
                            "scoring_bias": 1.5,
                            "uncertainty_policy": 1.5,
                        },
                        "allowed_adapter_ids": [terminal_adapter_id],
                        "require_distinct_from_previous_stage": True,
                    },
                ],
            },
        ]
    }


def test_topology_breadth_readiness_packet_holds_on_single_terminal_bottleneck(tmp_path: Path) -> None:
    generalist_job = tmp_path / "generalist"
    code_job = tmp_path / "code"
    _write_job_dir(
        job_dir=generalist_job,
        adapter_id="lobe.generalist.shadow.v1",
        bundle_rows=[{
            "schema_id": "kt.policy_bundle.v1",
            "bundle_id": "G1",
            "genotype": {
                "guardrail_strength": "permissive",
                "prompt_transform_style": "reframe",
                "reasoning_directive": "evidence_first",
                "scoring_bias": "calibration",
                "uncertainty_policy": "explicit_calibration",
            },
        }],
    )
    _write_job_dir(
        job_dir=code_job,
        adapter_id="lobe.code.specialist.v1",
        bundle_rows=[{
            "schema_id": "kt.policy_bundle.v1",
            "bundle_id": "C1",
            "genotype": {
                "guardrail_strength": "balanced",
                "prompt_transform_style": "compress",
                "reasoning_directive": "bullet_proof",
                "scoring_bias": "calibration",
                "uncertainty_policy": "explicit_calibration",
            },
        }],
    )

    packet = build_topology_breadth_readiness_packet(
        root=tmp_path,
        primary_role_report=_primary_report(),
        primary_role_report_ref="primary.json",
        second_suite=_second_suite(
            terminal_adapter_id="lobe.code.specialist.v1",
            terminal_style="compress",
            terminal_reasoning="bullet_proof",
        ),
        second_suite_ref="second.json",
        job_dirs=[generalist_job, code_job],
        fresh_job_dirs=[generalist_job, code_job],
        dominant_route_pair="lobe.math.specialist.v1 -> lobe.code.specialist.v1",
    )

    assert packet["status"] == "PASS"
    assert packet["questions"]["second_distinct_topology_visible"] is True
    assert packet["questions"]["downstream_terminal_diversity_earned"] is False
    assert packet["topology_breadth_posture"] == "HOLD_LAB_ONLY_PENDING_DOWNSTREAM_DIVERSITY"
    assert "DOWNSTREAM_TERMINAL_DIVERSITY_NOT_EARNED" in packet["blockers"]


def test_topology_breadth_readiness_packet_can_clear_with_distinct_terminal(tmp_path: Path) -> None:
    generalist_job = tmp_path / "generalist"
    writer_job = tmp_path / "writer"
    _write_job_dir(
        job_dir=generalist_job,
        adapter_id="lobe.generalist.shadow.v1",
        bundle_rows=[{
            "schema_id": "kt.policy_bundle.v1",
            "bundle_id": "G1",
            "genotype": {
                "guardrail_strength": "permissive",
                "prompt_transform_style": "reframe",
                "reasoning_directive": "evidence_first",
                "scoring_bias": "calibration",
                "uncertainty_policy": "explicit_calibration",
            },
        }],
    )
    _write_job_dir(
        job_dir=writer_job,
        adapter_id="lobe.writer.specialist.v1",
        bundle_rows=[{
            "schema_id": "kt.policy_bundle.v1",
            "bundle_id": "W1",
            "genotype": {
                "guardrail_strength": "balanced",
                "prompt_transform_style": "compress",
                "reasoning_directive": "narrative_precision",
                "scoring_bias": "calibration",
                "uncertainty_policy": "explicit_calibration",
            },
        }],
    )

    packet = build_topology_breadth_readiness_packet(
        root=tmp_path,
        primary_role_report=_primary_report(),
        primary_role_report_ref="primary.json",
        second_suite=_second_suite(
            terminal_adapter_id="lobe.writer.specialist.v1",
            terminal_style="compress",
            terminal_reasoning="narrative_precision",
        ),
        second_suite_ref="second.json",
        job_dirs=[generalist_job, writer_job],
        fresh_job_dirs=[generalist_job, writer_job],
        dominant_route_pair="lobe.math.specialist.v1 -> lobe.code.specialist.v1",
    )

    assert packet["status"] == "PASS"
    assert packet["questions"]["second_distinct_topology_visible"] is True
    assert packet["questions"]["downstream_terminal_diversity_earned"] is True
    assert packet["questions"]["not_code_specialist_dependence_in_disguise"] is True
    assert packet["topology_breadth_posture"] == "READY_FOR_LATER_LAB_READINESS_REFRESH"


def test_topology_breadth_readiness_packet_cli_writes_packet(tmp_path: Path) -> None:
    primary_path = tmp_path / "primary.json"
    second_suite_path = tmp_path / "second.json"
    _write_json(primary_path, _primary_report())
    _write_json(
        second_suite_path,
        _second_suite(
            terminal_adapter_id="lobe.code.specialist.v1",
            terminal_style="compress",
            terminal_reasoning="bullet_proof",
        ),
    )

    generalist_job = tmp_path / "generalist"
    code_job = tmp_path / "code"
    _write_job_dir(
        job_dir=generalist_job,
        adapter_id="lobe.generalist.shadow.v1",
        bundle_rows=[{
            "schema_id": "kt.policy_bundle.v1",
            "bundle_id": "G1",
            "genotype": {
                "guardrail_strength": "permissive",
                "prompt_transform_style": "reframe",
                "reasoning_directive": "evidence_first",
                "scoring_bias": "calibration",
                "uncertainty_policy": "explicit_calibration",
            },
        }],
    )
    _write_job_dir(
        job_dir=code_job,
        adapter_id="lobe.code.specialist.v1",
        bundle_rows=[{
            "schema_id": "kt.policy_bundle.v1",
            "bundle_id": "C1",
            "genotype": {
                "guardrail_strength": "balanced",
                "prompt_transform_style": "compress",
                "reasoning_directive": "bullet_proof",
                "scoring_bias": "calibration",
                "uncertainty_policy": "explicit_calibration",
            },
        }],
    )

    out_path = tmp_path / "topology_breadth_packet.json"
    rc = main(
        [
            "--primary-role-report",
            str(primary_path),
            "--second-suite",
            str(second_suite_path),
            "--job-dir",
            str(generalist_job),
            "--job-dir",
            str(code_job),
            "--fresh-job-dir",
            str(generalist_job),
            "--fresh-job-dir",
            str(code_job),
            "--output",
            str(out_path),
        ]
    )

    assert rc == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["questions"]["downstream_terminal_diversity_earned"] is False
