from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.router.run_role_separated_router_survival_packet import (  # noqa: E402
    build_role_separated_router_survival_packet,
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


def _suite() -> dict:
    return {
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
            },
            {
                "case_id": "ROLESEP_R01B",
                "pattern_family": "ROLESEP_R01",
                "single_case_baseline": {
                    "task_text": "Build the incident matrix and write a calibrated rollout call.",
                    "required_terms": ["incident", "tradeoffs", "rollout"],
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
                        "stage_id": "matrix",
                        "task_text": "Build the incident matrix and surface the tradeoffs.",
                        "required_terms": ["incident", "tradeoffs"],
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
                        "stage_id": "rollout",
                        "task_text": "Write the compressed rollout call and defend it.",
                        "required_terms": ["rollout", "decision"],
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
            },
            {
                "case_id": "ROLESEP_R02",
                "pattern_family": "ROLESEP_R02",
                "single_case_baseline": {
                    "task_text": "Use the tool and deliver a concise escalation summary.",
                    "required_terms": ["tool", "summary", "escalation"],
                    "preferred_genotype": {
                        "guardrail_strength": "permissive",
                        "prompt_transform_style": "expand_context",
                        "reasoning_directive": "minimal_chain",
                        "scoring_bias": "calibration",
                        "uncertainty_policy": "explicit_calibration",
                    },
                    "weights": {
                        "guardrail_strength": 1.0,
                        "prompt_transform_style": 1.0,
                        "reasoning_directive": 2.0,
                        "scoring_bias": 1.5,
                        "uncertainty_policy": 1.5,
                    },
                },
                "stages": [
                    {
                        "stage_id": "capture",
                        "task_text": "Use the tool and preserve the context for handoff.",
                        "required_terms": ["tool", "context"],
                        "preferred_genotype": {
                            "guardrail_strength": "permissive",
                            "prompt_transform_style": "clarify_first",
                            "reasoning_directive": "minimal_chain",
                            "scoring_bias": "calibration",
                            "uncertainty_policy": "explicit_calibration",
                        },
                        "weights": {
                            "guardrail_strength": 1.0,
                            "prompt_transform_style": 1.0,
                            "reasoning_directive": 2.0,
                            "scoring_bias": 1.5,
                            "uncertainty_policy": 1.5,
                        },
                        "allowed_adapter_ids": ["lobe.math.specialist.v1"],
                    },
                    {
                        "stage_id": "handoff",
                        "task_text": "Write the compressed escalation summary for the next responder.",
                        "required_terms": ["summary", "escalation"],
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
            },
            {
                "case_id": "ROLESEP_R02B",
                "pattern_family": "ROLESEP_R02",
                "single_case_baseline": {
                    "task_text": "Preserve the tool evidence and deliver a concise escalation summary.",
                    "required_terms": ["tool", "evidence", "summary"],
                    "preferred_genotype": {
                        "guardrail_strength": "permissive",
                        "prompt_transform_style": "expand_context",
                        "reasoning_directive": "minimal_chain",
                        "scoring_bias": "calibration",
                        "uncertainty_policy": "explicit_calibration",
                    },
                    "weights": {
                        "guardrail_strength": 1.0,
                        "prompt_transform_style": 1.0,
                        "reasoning_directive": 2.0,
                        "scoring_bias": 1.5,
                        "uncertainty_policy": 1.5,
                    },
                },
                "stages": [
                    {
                        "stage_id": "capture",
                        "task_text": "Preserve the tool evidence and keep the context intact.",
                        "required_terms": ["tool", "evidence", "context"],
                        "preferred_genotype": {
                            "guardrail_strength": "permissive",
                            "prompt_transform_style": "clarify_first",
                            "reasoning_directive": "minimal_chain",
                            "scoring_bias": "calibration",
                            "uncertainty_policy": "explicit_calibration",
                        },
                        "weights": {
                            "guardrail_strength": 1.0,
                            "prompt_transform_style": 1.0,
                            "reasoning_directive": 2.0,
                            "scoring_bias": 1.5,
                            "uncertainty_policy": 1.5,
                        },
                        "allowed_adapter_ids": ["lobe.math.specialist.v1"],
                    },
                    {
                        "stage_id": "handoff",
                        "task_text": "Write the compressed escalation summary and next-step note.",
                        "required_terms": ["summary", "escalation"],
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
            },
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
                "bundle_id": "math_tool",
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
                    "guardrail_strength": "balanced",
                    "prompt_transform_style": "compress",
                    "reasoning_directive": "bullet_proof",
                    "scoring_bias": "calibration",
                    "uncertainty_policy": "explicit_calibration",
                },
            }
        ],
    )
    return math_job_dir, code_job_dir


def test_role_separated_router_survival_packet_passes_when_signal_is_strong(tmp_path: Path) -> None:
    suite_path = tmp_path / "suite.json"
    _write_json(suite_path, _suite())
    math_job_dir, code_job_dir = _write_primary_entrants(tmp_path)

    fresh_generalist_job_dir = tmp_path / "fresh_generalist"
    _write_job_dir(
        job_dir=fresh_generalist_job_dir,
        adapter_id="lobe.generalist.shadow.v1",
        bundle_rows=[
            {
                "bundle_id": "generalist_baseline",
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

    packet = build_role_separated_router_survival_packet(
        root=_REPO_ROOT,
        suite=_suite(),
        suite_ref=str(suite_path),
        job_dirs=[math_job_dir, code_job_dir, fresh_generalist_job_dir],
        fresh_job_dirs=[code_job_dir, fresh_generalist_job_dir],
    )

    assert packet["status"] == "PASS"
    assert packet["questions"]["reproducible_across_reruns"] is True
    assert packet["questions"]["same_head_lab_consistent"] is True
    assert packet["questions"]["shadow_constraints_preserved"] is True
    assert packet["questions"]["survives_fresh_verified_entrants"] is True
    assert packet["questions"]["tournament_like_constraints_passed"] is True
    assert packet["posture"] == "LAB_ROLE_SEPARATED_SURVIVAL_CONFIRMED"
    assert packet["blockers"] == []


def test_role_separated_router_survival_packet_holds_without_fresh_exposure(tmp_path: Path) -> None:
    suite_path = tmp_path / "suite.json"
    _write_json(suite_path, _suite())
    math_job_dir, code_job_dir = _write_primary_entrants(tmp_path)

    packet = build_role_separated_router_survival_packet(
        root=_REPO_ROOT,
        suite=_suite(),
        suite_ref=str(suite_path),
        job_dirs=[math_job_dir, code_job_dir],
        fresh_job_dirs=[],
    )

    assert packet["status"] == "PASS"
    assert packet["questions"]["survives_fresh_verified_entrants"] is False
    assert packet["posture"] == "HOLD_LAB_ONLY_PENDING_ROLE_SEPARATED_REWORK"
    assert "ROLE_SEPARATED_FRESH_VERIFIED_ENTRANT_SURVIVAL_NOT_EARNED" in packet["blockers"]


def test_role_separated_router_survival_packet_cli_writes_packet(tmp_path: Path) -> None:
    suite_path = tmp_path / "suite.json"
    _write_json(suite_path, _suite())
    math_job_dir, code_job_dir = _write_primary_entrants(tmp_path)
    fresh_generalist_job_dir = tmp_path / "fresh_generalist"
    _write_job_dir(
        job_dir=fresh_generalist_job_dir,
        adapter_id="lobe.generalist.shadow.v1",
        bundle_rows=[
            {
                "bundle_id": "generalist_baseline",
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

    out_path = tmp_path / "role_separated_router_survival_packet.json"
    rc = main(
        [
            "--suite",
            str(suite_path),
            "--job-dir",
            str(math_job_dir),
            "--job-dir",
            str(code_job_dir),
            "--job-dir",
            str(fresh_generalist_job_dir),
            "--fresh-job-dir",
            str(code_job_dir),
            "--fresh-job-dir",
            str(fresh_generalist_job_dir),
            "--output",
            str(out_path),
        ]
    )
    assert rc == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["posture"] == "LAB_ROLE_SEPARATED_SURVIVAL_CONFIRMED"
