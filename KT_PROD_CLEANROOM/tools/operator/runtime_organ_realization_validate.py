from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

_CLEANROOM_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _CLEANROOM_ROOT / "04_PROD_TEMPLE_V2" / "src"
for _path in (str(_CLEANROOM_ROOT), str(_SRC_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from cognition.cognitive_engine import CognitiveEngine
from cognition.cognitive_schemas import CognitivePlanSchema, CognitiveRequestSchema, MODE_DRY_RUN
from core.invariants_gate import CONSTITUTION_VERSION_HASH
from core.runtime_registry import load_runtime_registry
from core.spine import _runtime_registry_hash
from multiverse.multiverse_engine import MultiverseEngine
from multiverse.multiverse_schemas import MultiverseCandidateSchema, MultiverseEvaluationRequestSchema
from paradox.paradox_engine import ParadoxEngine
from paradox.paradox_schemas import ParadoxTriggerSchema
from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH
from schemas.schema_hash import sha256_text
from temporal.temporal_engine import TemporalEngine
from temporal.temporal_schemas import TemporalForkRequestSchema, TemporalReplayRequestSchema
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
COGNITION_PACK_REL = f"{REPORT_ROOT_REL}/kt_wave2c_cognitive_provenance_pack.json"
PARADOX_PACK_REL = f"{REPORT_ROOT_REL}/kt_wave2c_paradox_engine_pack.json"
TEMPORAL_PACK_REL = f"{REPORT_ROOT_REL}/kt_wave2c_temporal_engine_pack.json"
MULTIVERSE_PACK_REL = f"{REPORT_ROOT_REL}/kt_wave2c_multiverse_engine_pack.json"
RUNTIME_RECEIPT_REL = f"{REPORT_ROOT_REL}/runtime_organ_realization_receipt.json"
PRACTICAL_GRADE_REL = f"{REPORT_ROOT_REL}/organ_practical_grade_receipt.json"

FORBIDDEN_CLAIMS = [
    "Do not claim E2 or higher externality.",
    "Do not claim cross-host replay.",
    "Do not claim hostile or independent verification.",
    "Do not claim router superiority.",
    "Do not claim multi-lobe execution.",
    "Do not claim frontier, SOTA, or beyond-SOTA standing.",
]


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _context(*, input_text: str = "") -> Dict[str, Any]:
    return {
        "constitution_version_hash": CONSTITUTION_VERSION_HASH,
        "envelope": {"input": input_text},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
    }


def _registry_hash() -> str:
    return _runtime_registry_hash(load_runtime_registry())


def _make_cognition_request(
    *,
    registry_hash: str,
    request_id: str,
    artifact_ids: Sequence[str],
    max_steps: int,
    max_branching: int,
    max_depth: int,
) -> CognitiveRequestSchema:
    return CognitiveRequestSchema.from_dict(
        {
            "schema_id": CognitiveRequestSchema.SCHEMA_ID,
            "schema_version_hash": CognitiveRequestSchema.SCHEMA_VERSION_HASH,
            "request_id": request_id,
            "runtime_registry_hash": registry_hash,
            "mode": MODE_DRY_RUN,
            "input_hash": sha256_text(request_id),
            "max_steps": max_steps,
            "max_branching": max_branching,
            "max_depth": max_depth,
            "artifact_refs": [
                {
                    "artifact_id": artifact_id,
                    "artifact_hash": sha256_text(artifact_id),
                }
                for artifact_id in artifact_ids
            ],
        }
    )


def _build_custom_plan(*, registry_hash: str, plan_id: str, step_hashes: Sequence[str]) -> CognitivePlanSchema:
    payload = {
        "schema_id": CognitivePlanSchema.SCHEMA_ID,
        "schema_version_hash": CognitivePlanSchema.SCHEMA_VERSION_HASH,
        "plan_id": plan_id,
        "runtime_registry_hash": registry_hash,
        "request_hash": sha256_text(plan_id),
        "status": "OK",
        "mode": MODE_DRY_RUN,
        "steps": [
            {
                "step_index": index,
                "step_type": step_type,
                "step_hash": step_hash,
            }
            for index, (step_type, step_hash) in enumerate(
                zip(("CHECK_POLICY", "FINALIZE"), step_hashes, strict=True)
            )
        ],
        "plan_hash": "",
    }
    payload["plan_hash"] = CognitivePlanSchema.compute_plan_hash(payload)
    return CognitivePlanSchema.from_dict(payload)


def _build_candidate(*, candidate_id: str, metric_value: float) -> Dict[str, Any]:
    return {
        "schema_id": MultiverseCandidateSchema.SCHEMA_ID,
        "schema_version_hash": MultiverseCandidateSchema.SCHEMA_VERSION_HASH,
        "candidate_id": candidate_id,
        "token_count": 1,
        "metrics": {"m1": metric_value},
    }


def _build_multiverse_request(*, evaluation_id: str, registry_hash: str, metrics: Sequence[float]) -> MultiverseEvaluationRequestSchema:
    return MultiverseEvaluationRequestSchema.from_dict(
        {
            "schema_id": MultiverseEvaluationRequestSchema.SCHEMA_ID,
            "schema_version_hash": MultiverseEvaluationRequestSchema.SCHEMA_VERSION_HASH,
            "evaluation_id": evaluation_id,
            "runtime_registry_hash": registry_hash,
            "metric_names": ["m1"],
            "candidates": [
                _build_candidate(candidate_id=f"{evaluation_id}.c{index}", metric_value=value)
                for index, value in enumerate(metrics, start=1)
            ],
        }
    )


def _check_row(check_id: str, passed: bool, **details: Any) -> Dict[str, Any]:
    return {
        "check_id": check_id,
        "pass": bool(passed),
        **details,
    }


def _practical_grade_row(
    *,
    organ_id: str,
    practical_grade: str,
    practical_delta: str,
    evidence_ref: str,
    status: str,
) -> Dict[str, Any]:
    return {
        "organ_id": organ_id,
        "status": status,
        "practical_grade": practical_grade,
        "practical_delta": practical_delta,
        "evidence_ref": evidence_ref,
    }


def _build_cognition_pack(*, registry_hash: str) -> Dict[str, Any]:
    context = _context()
    policy_request = _make_cognition_request(
        registry_hash=registry_hash,
        request_id="w2.cognition.policy",
        artifact_ids=["policy.constraint"],
        max_steps=4,
        max_branching=1,
        max_depth=1,
    )
    evidence_request = _make_cognition_request(
        registry_hash=registry_hash,
        request_id="w2.cognition.evidence",
        artifact_ids=["memory.trace", "router.adapter"],
        max_steps=4,
        max_branching=2,
        max_depth=2,
    )
    policy_plan = CognitiveEngine.plan(context=context, request=policy_request).to_dict()
    evidence_plan = CognitiveEngine.plan(context=context, request=evidence_request).to_dict()

    policy_types = [str(step["step_type"]) for step in policy_plan["steps"]]
    evidence_types = [str(step["step_type"]) for step in evidence_plan["steps"]]
    semantic_variation = (
        policy_types != evidence_types
        and "INSPECT_EVIDENCE" in evidence_types
        and "EVALUATE" in evidence_types
        and "FINALIZE" in policy_types
    )

    plan_a = _build_custom_plan(
        registry_hash=registry_hash,
        plan_id="w2.cognition.hash_independence.a",
        step_hashes=(sha256_text("w2.cognition.00"), sha256_text("w2.cognition.01")),
    )
    plan_b = _build_custom_plan(
        registry_hash=registry_hash,
        plan_id="w2.cognition.hash_independence.b",
        step_hashes=(sha256_text("w2.cognition.ff"), sha256_text("w2.cognition.ee")),
    )
    result_a = CognitiveEngine.execute(context=context, plan=plan_a).to_dict()
    result_b = CognitiveEngine.execute(context=context, plan=plan_b).to_dict()
    score_vector_a = [int(step["score_0_100"]) for step in result_a["steps"]]
    score_vector_b = [int(step["score_0_100"]) for step in result_b["steps"]]
    legacy_prefix_scores_a = [int(step["step_hash"][:2], 16) % 101 for step in plan_a.to_dict()["steps"]]
    legacy_prefix_scores_b = [int(step["step_hash"][:2], 16) % 101 for step in plan_b.to_dict()["steps"]]
    hash_independent_scoring = (
        score_vector_a == score_vector_b
        and legacy_prefix_scores_a != legacy_prefix_scores_b
    )

    checks = [
        _check_row(
            "cognition_plan_varies_with_artifact_semantics",
            semantic_variation,
            policy_step_types=policy_types,
            evidence_step_types=evidence_types,
        ),
        _check_row(
            "cognition_execute_not_legacy_hash_prefix_scoring",
            hash_independent_scoring,
            score_vector=score_vector_a,
            legacy_prefix_scores_a=legacy_prefix_scores_a,
            legacy_prefix_scores_b=legacy_prefix_scores_b,
        ),
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.w2.cognition.pack.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "organ_id": "cognition",
        "bounded_summary": "Cognition now uses typed semantic step planning and structural scoring on the active path instead of hash-prefix-derived scoring.",
        "checks": checks,
        "stronger_claim_not_made": [
            "model-backed cognition superiority claimed",
            "cross-host cognition proof claimed",
            "frontier cognition claimed",
        ],
    }


def _build_temporal_pack(*, registry_hash: str) -> Dict[str, Any]:
    context = _context()
    fork_request = TemporalForkRequestSchema.from_dict(
        {
            "schema_id": TemporalForkRequestSchema.SCHEMA_ID,
            "schema_version_hash": TemporalForkRequestSchema.SCHEMA_VERSION_HASH,
            "trace_id": "w2.temporal.trace",
            "epoch_id": "w2.temporal.epoch",
            "runtime_registry_hash": registry_hash,
            "anchor_hash": sha256_text("w2.temporal.anchor"),
            "parent_fork_hash": None,
        }
    )
    fork = TemporalEngine.create_fork(context=context, request=fork_request).to_dict()
    positive_request = TemporalReplayRequestSchema.from_dict(
        {
            "schema_id": TemporalReplayRequestSchema.SCHEMA_ID,
            "schema_version_hash": TemporalReplayRequestSchema.SCHEMA_VERSION_HASH,
            "fork": fork,
            "replay_mode": "DRY_RUN",
            "runtime_registry_hash": registry_hash,
            "max_steps": 5,
        }
    )
    zero_request = TemporalReplayRequestSchema.from_dict(
        {
            "schema_id": TemporalReplayRequestSchema.SCHEMA_ID,
            "schema_version_hash": TemporalReplayRequestSchema.SCHEMA_VERSION_HASH,
            "fork": fork,
            "replay_mode": "DRY_RUN",
            "runtime_registry_hash": registry_hash,
            "max_steps": 0,
        }
    )
    positive_result = TemporalEngine.replay(context=context, request=positive_request).to_dict()
    zero_result = TemporalEngine.replay(context=context, request=zero_request).to_dict()

    checks = [
        _check_row(
            "temporal_positive_budget_yields_nonzero_steps",
            0 < int(positive_result["steps_executed"]) <= int(positive_request.data["max_steps"]),
            steps_executed=positive_result["steps_executed"],
            max_steps=positive_request.data["max_steps"],
        ),
        _check_row(
            "temporal_zero_budget_stays_zero",
            int(zero_result["steps_executed"]) == 0,
            steps_executed=zero_result["steps_executed"],
        ),
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.w2.temporal.pack.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "organ_id": "temporal",
        "bounded_summary": "Temporal now records bounded nonzero replay work when replay budget is positive and preserves zero-step behavior only for zero budget.",
        "checks": checks,
        "stronger_claim_not_made": [
            "full temporal execution history claimed",
            "cross-host temporal replay claimed",
            "broad time-travel semantics claimed",
        ],
    }


def _build_multiverse_pack(*, registry_hash: str) -> Dict[str, Any]:
    context = _context()
    close_request = _build_multiverse_request(
        evaluation_id="w2.multiverse.close",
        registry_hash=registry_hash,
        metrics=(0.51, 0.49),
    )
    wide_request = _build_multiverse_request(
        evaluation_id="w2.multiverse.wide",
        registry_hash=registry_hash,
        metrics=(0.95, 0.05),
    )
    close_result = MultiverseEngine.evaluate(context=context, request=close_request).to_dict()
    wide_result = MultiverseEngine.evaluate(context=context, request=wide_request).to_dict()

    checks = [
        _check_row(
            "multiverse_coherence_is_task_dependent",
            float(close_result["coherence_score"]) != float(wide_result["coherence_score"])
            and float(close_result["coherence_score"]) > float(wide_result["coherence_score"]),
            close_coherence=close_result["coherence_score"],
            wide_coherence=wide_result["coherence_score"],
        ),
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.w2.multiverse.pack.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "organ_id": "multiverse",
        "bounded_summary": "Multiverse now computes task-dependent coherence scores from candidate spread instead of returning a constant 1.0.",
        "checks": checks,
        "stronger_claim_not_made": [
            "broad multiverse search claimed",
            "live multi-branch superiority claimed",
            "frontier arbitration claimed",
        ],
    }


def _build_paradox_pack() -> Dict[str, Any]:
    policy_trigger = ParadoxTriggerSchema.from_dict(
        {
            "schema_id": ParadoxTriggerSchema.SCHEMA_ID,
            "schema_version_hash": ParadoxTriggerSchema.SCHEMA_VERSION_HASH,
            "trigger_type": "PARADOX_SIGNAL",
            "condition": "contradiction",
            "severity": 7,
            "confidence": 80,
            "subject_hash": "0" * 64,
            "signal_hash": "1" * 64,
        }
    )
    request_trigger = ParadoxTriggerSchema.from_dict(
        {
            "schema_id": ParadoxTriggerSchema.SCHEMA_ID,
            "schema_version_hash": ParadoxTriggerSchema.SCHEMA_VERSION_HASH,
            "trigger_type": "PARADOX_SIGNAL",
            "condition": "contradiction",
            "severity": 7,
            "confidence": 80,
            "subject_hash": "2" * 64,
            "signal_hash": "3" * 64,
        }
    )
    self_reference_trigger = ParadoxTriggerSchema.from_dict(
        {
            "schema_id": ParadoxTriggerSchema.SCHEMA_ID,
            "schema_version_hash": ParadoxTriggerSchema.SCHEMA_VERSION_HASH,
            "trigger_type": "PARADOX_SIGNAL",
            "condition": "self_reference",
            "severity": 7,
            "confidence": 80,
            "subject_hash": "4" * 64,
            "signal_hash": "5" * 64,
        }
    )
    loop_trigger = ParadoxTriggerSchema.from_dict(
        {
            "schema_id": ParadoxTriggerSchema.SCHEMA_ID,
            "schema_version_hash": ParadoxTriggerSchema.SCHEMA_VERSION_HASH,
            "trigger_type": "PARADOX_SIGNAL",
            "condition": "infinite_loop",
            "severity": 7,
            "confidence": 80,
            "subject_hash": "6" * 64,
            "signal_hash": "7" * 64,
        }
    )

    policy_result = ParadoxEngine.run(
        context=_context(input_text="policy evidence contradiction"),
        trigger=policy_trigger,
    ).to_dict()
    request_result = ParadoxEngine.run(
        context=_context(input_text="request output mismatch"),
        trigger=request_trigger,
    ).to_dict()
    self_reference_result = ParadoxEngine.run(
        context=_context(input_text="recursive subject"),
        trigger=self_reference_trigger,
    ).to_dict()
    loop_result = ParadoxEngine.run(
        context=_context(input_text="looping request"),
        trigger=loop_trigger,
    ).to_dict()

    observed_task_types = [
        policy_result["task"]["task_type"],
        request_result["task"]["task_type"],
        self_reference_result["task"]["task_type"],
        loop_result["task"]["task_type"],
    ]
    checks = [
        _check_row(
            "paradox_task_type_changes_with_context_and_condition",
            observed_task_types
            == [
                "POLICY_EVIDENCE_CONFLICT_V1",
                "REQUEST_OUTPUT_CONFLICT_V1",
                "SELF_REFERENCE_GUARD_V1",
                "LOOP_BUDGET_GUARD_V1",
            ],
            observed_task_types=observed_task_types,
        ),
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.w2.paradox.pack.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "organ_id": "paradox",
        "bounded_summary": "Paradox now classifies contradiction types from context and condition instead of always emitting one generic injection task.",
        "checks": checks,
        "stronger_claim_not_made": [
            "broad paradox metabolism claimed",
            "multi-round paradox reasoning claimed",
            "frontier contradiction engine claimed",
        ],
    }


def build_runtime_organ_realization_outputs(*, root: Path) -> Dict[str, Dict[str, Any]]:
    registry_hash = _registry_hash()
    cognition_pack = _build_cognition_pack(registry_hash=registry_hash)
    paradox_pack = _build_paradox_pack()
    temporal_pack = _build_temporal_pack(registry_hash=registry_hash)
    multiverse_pack = _build_multiverse_pack(registry_hash=registry_hash)

    packs = {
        "cognition_pack": cognition_pack,
        "paradox_pack": paradox_pack,
        "temporal_pack": temporal_pack,
        "multiverse_pack": multiverse_pack,
    }
    overall_status = "PASS" if all(str(pack["status"]).strip().upper() == "PASS" for pack in packs.values()) else "FAIL"
    current_head = _git_head(root)

    practical_rows = [
        _practical_grade_row(
            organ_id="cognition",
            practical_grade="O2_BOUNDED_SEMANTIC_PLANNER",
            practical_delta="Replaced hash-prefix scoring with typed semantic planning and structural scoring on the active path.",
            evidence_ref=COGNITION_PACK_REL,
            status=cognition_pack["status"],
        ),
        _practical_grade_row(
            organ_id="paradox",
            practical_grade="O1_CONTEXT_AWARE_CONFLICT_GATE",
            practical_delta="Replaced one generic task type with context- and condition-sensitive contradiction classification.",
            evidence_ref=PARADOX_PACK_REL,
            status=paradox_pack["status"],
        ),
        _practical_grade_row(
            organ_id="temporal",
            practical_grade="O1_NONZERO_REPLAY_ACCOUNTING",
            practical_delta="Positive replay budgets now produce bounded nonzero executed-step counts.",
            evidence_ref=TEMPORAL_PACK_REL,
            status=temporal_pack["status"],
        ),
        _practical_grade_row(
            organ_id="multiverse",
            practical_grade="O1_TASK_DEPENDENT_ARBITRATION",
            practical_delta="Coherence now varies with candidate spread instead of remaining constant.",
            evidence_ref=MULTIVERSE_PACK_REL,
            status=multiverse_pack["status"],
        ),
    ]
    practical_grade_receipt = {
        "schema_id": "kt.w2.organ_practical_grade_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "status": overall_status,
        "rows": practical_rows,
        "grade_law": "Practical grades are behavior-backed and do not inherit maturity from the rest of KT.",
    }
    runtime_receipt = {
        "schema_id": "kt.w2.runtime_organ_realization_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "status": overall_status,
        "claim_boundary": "W2 upgrades bounded current-head organ realism only. It does not widen externality, comparative, commercial, router, or prestige claims.",
        "organ_pack_refs": [
            COGNITION_PACK_REL,
            PARADOX_PACK_REL,
            TEMPORAL_PACK_REL,
            MULTIVERSE_PACK_REL,
        ],
        "practical_grade_receipt_ref": PRACTICAL_GRADE_REL,
        "attack_weakened": "placeholder-organ and architecture-theater attacks on cognition, temporal, multiverse, and paradox",
        "forbidden_claims_remaining": list(FORBIDDEN_CLAIMS),
        "next_lawful_move": "W2_MVCR_VALIDATE",
        "organ_statuses": {
            "cognition": cognition_pack["status"],
            "paradox": paradox_pack["status"],
            "temporal": temporal_pack["status"],
            "multiverse": multiverse_pack["status"],
        },
    }
    return {
        **packs,
        "practical_grade_receipt": practical_grade_receipt,
        "runtime_receipt": runtime_receipt,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate W2 runtime organ realization on the current-head canonical path.")
    parser.add_argument("--cognition-output", default=COGNITION_PACK_REL)
    parser.add_argument("--paradox-output", default=PARADOX_PACK_REL)
    parser.add_argument("--temporal-output", default=TEMPORAL_PACK_REL)
    parser.add_argument("--multiverse-output", default=MULTIVERSE_PACK_REL)
    parser.add_argument("--runtime-output", default=RUNTIME_RECEIPT_REL)
    parser.add_argument("--grade-output", default=PRACTICAL_GRADE_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    outputs = build_runtime_organ_realization_outputs(root=root)

    mapping = {
        "cognition_pack": Path(str(args.cognition_output)),
        "paradox_pack": Path(str(args.paradox_output)),
        "temporal_pack": Path(str(args.temporal_output)),
        "multiverse_pack": Path(str(args.multiverse_output)),
        "runtime_receipt": Path(str(args.runtime_output)),
        "practical_grade_receipt": Path(str(args.grade_output)),
    }
    for key, path in list(mapping.items()):
        resolved = path.expanduser()
        if not resolved.is_absolute():
            resolved = (root / resolved).resolve()
        mapping[key] = resolved
    for key, path in mapping.items():
        write_json_stable(path, outputs[key])

    summary = {
        "status": outputs["runtime_receipt"]["status"],
        "organ_statuses": outputs["runtime_receipt"]["organ_statuses"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if outputs["runtime_receipt"]["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
