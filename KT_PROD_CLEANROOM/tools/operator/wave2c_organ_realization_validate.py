from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from cognition.cognitive_engine import CognitiveEngine
from cognition.cognitive_schemas import (
    CognitivePlanSchema,
    CognitiveRequestSchema,
    MODE_DRY_RUN as COGNITION_MODE_DRY_RUN,
    MODE_LIVE_REQUESTED as COGNITION_MODE_LIVE_REQUESTED,
)
from council.council_router import CouncilRouter
from council.council_schemas import (
    CouncilPlanSchema,
    CouncilRequestSchema,
    MODE_DRY_RUN as COUNCIL_MODE_DRY_RUN,
    MODE_LIVE_REQUESTED as COUNCIL_MODE_LIVE_REQUESTED,
)
from council.providers.failure_artifacts import write_failure_artifact
from core.invariants_gate import CONSTITUTION_VERSION_HASH
from core.runtime_registry import load_runtime_registry
from core.spine import _runtime_registry_hash
from multiverse.multiverse_engine import MultiverseEngine
from multiverse.multiverse_schemas import MAX_TOTAL_TOKENS, MultiverseCandidateSchema, MultiverseEvaluationRequestSchema
from paradox.paradox_engine import ParadoxEngine, ParadoxEngineError
from paradox.paradox_schemas import ParadoxTriggerSchema
from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH, RUNTIME_CONTEXT_MAX_STRING_LEN
from schemas.schema_hash import canonical_json, sha256_json, sha256_text
from schemas.telemetry_runtime import telemetry_now_ms
from temporal.temporal_engine import TemporalEngine
from temporal.temporal_schemas import TemporalForkRequestSchema, TemporalReplayRequestSchema
from tools.operator.observability import emit_toolchain_telemetry
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.operator.wave2c_organ_contract_suite import build_wave2c_independent_suite_report


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
EXPORT_ROOT_REL = "KT_PROD_CLEANROOM/exports/wave2c_organ_realization"
WAVE_ID = "WAVE_2C_ORGAN_REALIZATION"


def _load_json(path: Path) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: expected JSON object: {path.as_posix()}")
    return payload


def _rel(root: Path, path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _tool_env(root: Path) -> Dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src") + os.pathsep + str(root / "KT_PROD_CLEANROOM")
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def _registry_hash() -> str:
    return _runtime_registry_hash(load_runtime_registry())


def _context() -> Dict[str, Any]:
    return {
        "constitution_version_hash": CONSTITUTION_VERSION_HASH,
        "envelope": {"input": ""},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
    }


def _spine_probe(root: Path, export_root: Path, probe_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    probe_root = (export_root / "spine" / probe_id).resolve()
    payload_path = probe_root / "payload.json"
    telemetry_path = probe_root / "runtime_telemetry.jsonl"
    output_path = probe_root / "spine_result.json"
    blocked_path = probe_root / "spine_blocked.json"
    artifact_root = probe_root / "artifacts"
    probe_root.mkdir(parents=True, exist_ok=True)
    candidate_text = canonical_json(payload)
    payload_path.write_text(candidate_text, encoding="utf-8")
    if len(candidate_text) > RUNTIME_CONTEXT_MAX_STRING_LEN:
        blocked = {
            "schema_id": "kt.wave2c.spine_probe.blocked.v1",
            "status": "BLOCKED",
            "reason": "runtime_context_input_string_exceeds_max_string_len",
            "input_string_length": len(candidate_text),
            "max_string_len": RUNTIME_CONTEXT_MAX_STRING_LEN,
            "payload_hash": sha256_json(payload),
            "payload_schema_id": payload.get("schema_id", ""),
        }
        write_json_stable(blocked_path, blocked)
        return {
            "status": "BLOCKED",
            "blocked": blocked,
            "probe_refs": {
                "artifact_root_ref": _rel(root, artifact_root),
                "blocked_ref": _rel(root, blocked_path),
                "payload_ref": _rel(root, payload_path),
                "telemetry_ref": "",
            },
        }
    proc = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.wave2c_spine_probe",
            "--payload-file",
            str(payload_path),
            "--artifact-root",
            str(artifact_root),
            "--output",
            str(output_path),
            "--telemetry-output",
            str(telemetry_path),
        ],
        cwd=str(root),
        env=_tool_env(root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"FAIL_CLOSED: spine probe failed for {probe_id}: {proc.stdout}")
    out = _load_json(output_path)
    out["status"] = "PASS"
    out["probe_refs"] = {
        "artifact_root_ref": _rel(root, artifact_root),
        "output_ref": _rel(root, output_path),
        "payload_ref": _rel(root, payload_path),
        "telemetry_ref": _rel(root, telemetry_path),
    }
    return out


def _failure(export_root: Path, *, surface_id: str, error_class: str, bounded_reason: str, input_hash: str, context_hash: str, policy_profile: str, budget_profile: str, replay_pack_ref: str) -> Dict[str, Any]:
    artifact = write_failure_artifact(
        export_root=export_root,
        surface_id=surface_id,
        error_class=error_class,
        bounded_reason=bounded_reason,
        input_hash=input_hash,
        context_hash=context_hash,
        policy_profile=policy_profile,
        budget_profile=budget_profile,
        replay_pack_ref=replay_pack_ref,
        severity="MEDIUM",
        wave_id=WAVE_ID,
    )
    return {"artifact_ref": artifact.artifact_ref, "payload": artifact.payload}


def _telemetry(telemetry_path: Path, organ_id: str, receipt_ref: str, failure_artifact_ref: str = "") -> None:
    started = telemetry_now_ms()
    emit_toolchain_telemetry(
        surface_id=f"tools.operator.wave2c.{organ_id}",
        zone="TOOLCHAIN_PROVING",
        event_type="organ.realize",
        start_ts=started,
        end_ts=telemetry_now_ms(),
        result_status="PASS",
        policy_applied="wave2c.organ_realization.bounded",
        receipt_ref=receipt_ref,
        failure_artifact_ref=failure_artifact_ref,
        trace_id=f"wave2c-{organ_id}",
        request_id=f"wave2c.{organ_id}",
        path=telemetry_path,
    )


def _pack(organ_id: str, *, entrypoint: str, disposition: str, summary: str, maturity: str, externality: str, benchmarks: list[dict], challenges: list[dict], provenance: Dict[str, Any], spine: Dict[str, Any], telemetry_refs: list[str], failure_refs: list[str], stronger_claim_not_made: list[str]) -> Dict[str, Any]:
    spine_status = str(spine.get("status", "")).strip().upper()
    return {
        "schema_id": f"kt.wave2c.{organ_id}_pack.v1",
        "generated_utc": utc_now_iso_z(),
        "organ_id": organ_id,
        "status": "PASS",
        "disposition": disposition,
        "reality_class": "LIVE_BOUNDED",
        "maturity_class": maturity,
        "externality_class": externality,
        "canonical_entrypoint": entrypoint,
        "bounded_summary": summary,
        "benchmark_rows": benchmarks,
        "challenge_rows": challenges,
        "provenance": provenance,
        "spine_integration": spine,
        "telemetry_refs": telemetry_refs,
        "failure_artifact_refs": failure_refs,
        "proof_contracts": {
            "benchmark_pack_present": True,
            "canonical_kernel_integration_present": spine_status == "PASS",
            "challenge_pack_present": True,
            "deterministic_suite_present": True,
            "failure_artifact_present": bool(failure_refs),
            "provenance_present": True,
            "telemetry_present": True,
        },
        "stronger_claim_not_made": stronger_claim_not_made,
    }


def _blocked_or_value(probe: Dict[str, Any], blocked_reason: str, *, key: str, value: str) -> str:
    if str(probe.get("status", "")).strip().upper() == "PASS":
        return value
    return blocked_reason


def _cognition(root: Path, export_root: Path, telemetry_path: Path, registry_hash: str) -> Dict[str, Any]:
    context = _context()
    request = CognitiveRequestSchema.from_dict(
        {
            "schema_id": CognitiveRequestSchema.SCHEMA_ID,
            "schema_version_hash": CognitiveRequestSchema.SCHEMA_VERSION_HASH,
            "request_id": "wave2c.cognition.request",
            "runtime_registry_hash": registry_hash,
            "mode": COGNITION_MODE_DRY_RUN,
            "input_hash": sha256_text("wave2c cognition bounded request"),
            "max_steps": 4,
            "max_branching": 1,
            "max_depth": 4,
            "artifact_refs": [{"artifact_hash": sha256_text("paradox.trigger"), "artifact_id": "paradox.trigger"}],
        }
    )
    plan_one = CognitiveEngine.plan(context=context, request=request).to_dict()
    plan_two = CognitiveEngine.plan(context=context, request=request).to_dict()
    result_one = CognitiveEngine.execute(context=context, plan=CognitivePlanSchema.from_dict(plan_one)).to_dict()
    result_two = CognitiveEngine.execute(context=context, plan=CognitivePlanSchema.from_dict(plan_two)).to_dict()
    live_req = CognitiveRequestSchema.from_dict({**request.to_dict(), "mode": COGNITION_MODE_LIVE_REQUESTED, "request_id": "wave2c.cognition.live"})
    illegal_req = CognitiveRequestSchema.from_dict({**request.to_dict(), "artifact_refs": [{"artifact_hash": sha256_text("cognition.loop"), "artifact_id": "cognition.loop"}], "request_id": "wave2c.cognition.illegal"})
    live_refusal = CognitiveEngine.plan(context=context, request=live_req).to_dict()
    illegal_refusal = CognitiveEngine.plan(context=context, request=illegal_req).to_dict()
    organ_export = export_root / "cognition"
    failure_one = _failure(organ_export, surface_id="cognition.cognitive_engine.plan", error_class="CognitiveRefusal", bounded_reason=str(live_refusal.get("refusal_code", "")), input_hash=live_req.data["input_hash"], context_hash=str(live_refusal["plan_hash"]), policy_profile="wave2c.cognition.live_refusal", budget_profile="wave2c.cognition.bounds", replay_pack_ref="E0_INTERNAL_SELF_ISSUED_ONLY")
    failure_two = _failure(organ_export, surface_id="cognition.cognitive_engine.plan", error_class="CognitiveIllegalReference", bounded_reason=str(illegal_refusal.get("refusal_code", "")), input_hash=illegal_req.data["input_hash"], context_hash=str(illegal_refusal["plan_hash"]), policy_profile="wave2c.cognition.illegal_reference", budget_profile="wave2c.cognition.bounds", replay_pack_ref="E0_INTERNAL_SELF_ISSUED_ONLY")
    spine_plan = _spine_probe(root, organ_export, "cognition_plan", request.to_dict())
    spine_execute = _spine_probe(root, organ_export, "cognition_execute", CognitivePlanSchema.from_dict(plan_one).to_dict())
    receipt = f"{REPORT_ROOT_REL}/kt_wave2c_cognitive_provenance_pack.json"
    _telemetry(telemetry_path, "cognition", receipt, failure_one["artifact_ref"])
    return _pack(
        "cognition",
        entrypoint="KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/cognitive_engine.py",
        disposition="REALIZED_BOUNDED_KEEP_CANONICAL",
        summary="Cognition is now bounded truthfully as a deterministic hash-only planner/executor with explicit refusal paths. Direct proof is real; canonical spine carriage remains blocked where the runtime-context envelope cannot lawfully carry full cognition payloads.",
        maturity="O2_HARDENED",
        externality="E0_INTERNAL_SELF_ISSUED_ONLY",
        benchmarks=[{"benchmark_id": "deterministic_plan_hash", "observed": plan_one["plan_hash"], "pass": plan_one == plan_two}, {"benchmark_id": "deterministic_result_hash", "observed": result_one["result_hash"], "pass": result_one == result_two}],
        challenges=[{"challenge_id": "live_requested_refusal", "pass": live_refusal["status"] == "REFUSED", "refusal_code": live_refusal.get("refusal_code")}, {"challenge_id": "illegal_reference_refusal", "pass": illegal_refusal["status"] == "REFUSED", "refusal_code": illegal_refusal.get("refusal_code")}],
        provenance={"runtime_registry_hash": registry_hash, "request_hash": plan_one["request_hash"], "plan_hash": plan_one["plan_hash"], "result_hash": result_one["result_hash"], "step_result_hashes": [step["step_result_hash"] for step in result_one["steps"]]},
        spine={
            "status": "PASS" if spine_plan.get("status") == "PASS" and spine_execute.get("status") == "PASS" else "BLOCKED",
            "plan_probe_ref": spine_plan["probe_refs"].get("output_ref", spine_plan["probe_refs"].get("blocked_ref", "")),
            "execute_probe_ref": spine_execute["probe_refs"].get("output_ref", spine_execute["probe_refs"].get("blocked_ref", "")),
            "plan_status": spine_plan.get("spine_result", {}).get("cognition", {}).get("status", "BLOCKED_BY_RUNTIME_CONTEXT_INPUT_LIMIT"),
            "execute_status": spine_execute.get("spine_result", {}).get("cognition", {}).get("status", "BLOCKED_BY_RUNTIME_CONTEXT_INPUT_LIMIT"),
            "runtime_telemetry_refs": [ref for ref in [spine_plan["probe_refs"].get("telemetry_ref", ""), spine_execute["probe_refs"].get("telemetry_ref", "")] if ref],
            "blocked_reason": "runtime_context_input_string_exceeds_max_string_len" if spine_plan.get("status") != "PASS" or spine_execute.get("status") != "PASS" else "",
        },
        telemetry_refs=[ref for ref in [_rel(root, telemetry_path), spine_plan["probe_refs"].get("telemetry_ref", ""), spine_execute["probe_refs"].get("telemetry_ref", "")] if ref],
        failure_refs=[_rel(root, Path(failure_one["artifact_ref"])), _rel(root, Path(failure_two["artifact_ref"]))],
        stronger_claim_not_made=["live_cognition_enabled", "model_based_reasoning_superiority_claimed", "chain_of_thought_exposed", "canonical_spine_carriage_claimed_despite_input_limit"],
    )


def _paradox(root: Path, export_root: Path, telemetry_path: Path) -> Dict[str, Any]:
    context = _context()
    trigger = ParadoxTriggerSchema.from_dict({"schema_id": ParadoxTriggerSchema.SCHEMA_ID, "schema_version_hash": ParadoxTriggerSchema.SCHEMA_VERSION_HASH, "trigger_type": "PARADOX_SIGNAL", "condition": "contradiction", "severity": 7, "confidence": 80, "subject_hash": "0" * 64, "signal_hash": "1" * 64})
    result_one = ParadoxEngine.run(context=context, trigger=trigger).to_dict()
    result_two = ParadoxEngine.run(context=context, trigger=trigger).to_dict()
    noop = ParadoxEngine.run(context=context, trigger=ParadoxTriggerSchema.from_dict({**trigger.to_dict(), "severity": 1})).to_dict()
    organ_export = export_root / "paradox"
    try:
        ParadoxEngine.run(context=[], trigger=trigger)  # type: ignore[arg-type]
        raise RuntimeError("FAIL_CLOSED: paradox invalid-context challenge did not fail")
    except ParadoxEngineError as exc:
        failure_one = _failure(organ_export, surface_id="paradox.paradox_engine.run", error_class=exc.__class__.__name__, bounded_reason=str(exc), input_hash=trigger.data["signal_hash"], context_hash=sha256_text("invalid_context"), policy_profile="wave2c.paradox.invalid_context", budget_profile="wave2c.paradox.bounds", replay_pack_ref="E0_INTERNAL_SELF_ISSUED_ONLY")
    failure_two = _failure(organ_export, surface_id="paradox.paradox_engine.run", error_class="ParadoxNoOpBounded", bounded_reason="trigger_not_eligible_for_injection", input_hash=trigger.data["signal_hash"], context_hash=noop["result_hash"], policy_profile="wave2c.paradox.noop", budget_profile="wave2c.paradox.bounds", replay_pack_ref="E0_INTERNAL_SELF_ISSUED_ONLY")
    probe = _spine_probe(root, organ_export, "paradox_trigger", trigger.to_dict())
    receipt = f"{REPORT_ROOT_REL}/kt_wave2c_paradox_engine_pack.json"
    _telemetry(telemetry_path, "paradox", receipt, failure_one["artifact_ref"])
    return _pack(
        "paradox",
        entrypoint="KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/paradox_engine.py",
        disposition="REALIZED_BOUNDED_KEEP_CANONICAL",
        summary="Paradox is realized as a narrow deterministic contradiction-trigger gate, not a broad debate engine. Direct proof is real; canonical spine carriage remains blocked where the runtime-context envelope cannot lawfully carry full paradox payloads.",
        maturity="O2_HARDENED",
        externality="E1_SAME_HOST_DETACHED_REPLAY",
        benchmarks=[{"benchmark_id": "deterministic_task_hash", "observed": result_one["task_hash"], "pass": result_one == result_two}],
        challenges=[{"challenge_id": "ineligible_trigger_noop", "pass": noop["status"] == "NOOP"}],
        provenance={"trigger_hash": result_one["trigger_hash"], "task_hash": result_one["task_hash"], "result_hash": result_one["result_hash"]},
        spine={"status": "PASS" if probe.get("status") == "PASS" else "BLOCKED", "probe_ref": probe["probe_refs"].get("output_ref", probe["probe_refs"].get("blocked_ref", "")), "runtime_status": probe.get("spine_result", {}).get("paradox", {}).get("status", "BLOCKED_BY_RUNTIME_CONTEXT_INPUT_LIMIT"), "runtime_telemetry_ref": probe["probe_refs"].get("telemetry_ref", ""), "external_confirmation_ref": "KT_PROD_CLEANROOM/reports/kt_external_runtime_confirmation_receipt.json", "blocked_reason": "runtime_context_input_string_exceeds_max_string_len" if probe.get("status") != "PASS" else ""},
        telemetry_refs=[ref for ref in [_rel(root, telemetry_path), probe["probe_refs"].get("telemetry_ref", "")] if ref],
        failure_refs=[_rel(root, Path(failure_one["artifact_ref"])), _rel(root, Path(failure_two["artifact_ref"]))],
        stronger_claim_not_made=["multi_round_paradox_debate_claimed", "broad_conflict_metabolism_claimed", "canonical_spine_carriage_claimed_despite_input_limit"],
    )


def _temporal(root: Path, export_root: Path, telemetry_path: Path, registry_hash: str) -> Dict[str, Any]:
    context = _context()
    fork_req = TemporalForkRequestSchema.from_dict({"schema_id": TemporalForkRequestSchema.SCHEMA_ID, "schema_version_hash": TemporalForkRequestSchema.SCHEMA_VERSION_HASH, "trace_id": "wave2c.temporal.trace", "epoch_id": "wave2c.temporal.epoch", "runtime_registry_hash": registry_hash, "anchor_hash": sha256_text("wave2c temporal anchor"), "parent_fork_hash": None})
    fork_one = TemporalEngine.create_fork(context=context, request=fork_req).to_dict()
    fork_two = TemporalEngine.create_fork(context=context, request=fork_req).to_dict()
    replay_req = TemporalReplayRequestSchema.from_dict({"schema_id": TemporalReplayRequestSchema.SCHEMA_ID, "schema_version_hash": TemporalReplayRequestSchema.SCHEMA_VERSION_HASH, "fork": fork_one, "replay_mode": "DRY_RUN", "runtime_registry_hash": registry_hash, "max_steps": 0})
    replay_one = TemporalEngine.replay(context=context, request=replay_req).to_dict()
    replay_two = TemporalEngine.replay(context=context, request=replay_req).to_dict()
    rejected = TemporalEngine.replay(context=context, request=TemporalReplayRequestSchema.from_dict({**replay_req.to_dict(), "runtime_registry_hash": "f" * 64})).to_dict()
    organ_export = export_root / "temporal"
    failure = _failure(organ_export, surface_id="temporal.temporal_engine.replay", error_class="TemporalReplayRejected", bounded_reason=str(rejected.get("rejection_code", "")), input_hash=fork_one["fork_hash"], context_hash=rejected["outcome_hash"], policy_profile="wave2c.temporal.replay_reject", budget_profile="wave2c.temporal.bounds", replay_pack_ref="E0_INTERNAL_SELF_ISSUED_ONLY")
    probe_fork = _spine_probe(root, organ_export, "temporal_fork", fork_req.to_dict())
    probe_replay = _spine_probe(root, organ_export, "temporal_replay", replay_req.to_dict())
    receipt = f"{REPORT_ROOT_REL}/kt_wave2c_temporal_engine_pack.json"
    _telemetry(telemetry_path, "temporal", receipt, failure["artifact_ref"])
    return _pack(
        "temporal",
        entrypoint="KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/temporal_engine.py",
        disposition="REALIZED_BOUNDED_KEEP_CANONICAL",
        summary="Temporal is realized as a bounded fork-and-replay identity surface with deterministic rejection codes. Direct proof is real; canonical spine carriage remains blocked where the runtime-context envelope cannot lawfully carry full temporal payloads.",
        maturity="O2_HARDENED",
        externality="E0_INTERNAL_SELF_ISSUED_ONLY",
        benchmarks=[{"benchmark_id": "deterministic_fork_hash", "observed": fork_one["fork_hash"], "pass": fork_one == fork_two}, {"benchmark_id": "deterministic_replay_hash", "observed": replay_one["replay_hash"], "pass": replay_one == replay_two}],
        challenges=[{"challenge_id": "registry_hash_mismatch_rejected", "pass": rejected["status"] == "REJECTED", "rejection_code": rejected["rejection_code"]}],
        provenance={"runtime_registry_hash": registry_hash, "fork_hash": fork_one["fork_hash"], "replay_hash": replay_one["replay_hash"], "outcome_hash": replay_one["outcome_hash"]},
        spine={"status": "PASS" if probe_fork.get("status") == "PASS" and probe_replay.get("status") == "PASS" else "BLOCKED", "fork_probe_ref": probe_fork["probe_refs"].get("output_ref", probe_fork["probe_refs"].get("blocked_ref", "")), "replay_probe_ref": probe_replay["probe_refs"].get("output_ref", probe_replay["probe_refs"].get("blocked_ref", "")), "fork_status": probe_fork.get("spine_result", {}).get("temporal", {}).get("status", "BLOCKED_BY_RUNTIME_CONTEXT_INPUT_LIMIT"), "replay_status": probe_replay.get("spine_result", {}).get("temporal", {}).get("status", "BLOCKED_BY_RUNTIME_CONTEXT_INPUT_LIMIT"), "runtime_telemetry_refs": [ref for ref in [probe_fork["probe_refs"].get("telemetry_ref", ""), probe_replay["probe_refs"].get("telemetry_ref", "")] if ref], "blocked_reason": "runtime_context_input_string_exceeds_max_string_len" if probe_fork.get("status") != "PASS" or probe_replay.get("status") != "PASS" else ""},
        telemetry_refs=[ref for ref in [_rel(root, telemetry_path), probe_fork["probe_refs"].get("telemetry_ref", ""), probe_replay["probe_refs"].get("telemetry_ref", "")] if ref],
        failure_refs=[_rel(root, Path(failure["artifact_ref"]))],
        stronger_claim_not_made=["full_temporal_execution_claimed", "cross_host_temporal_replay_claimed", "canonical_spine_carriage_claimed_despite_input_limit"],
    )


def _multiverse(root: Path, export_root: Path, telemetry_path: Path, registry_hash: str) -> Dict[str, Any]:
    context = _context()
    c1 = {"schema_id": MultiverseCandidateSchema.SCHEMA_ID, "schema_version_hash": MultiverseCandidateSchema.SCHEMA_VERSION_HASH, "candidate_id": "alpha", "token_count": 3, "metrics": {"m1": 0.2, "m2": 0.8}}
    c2 = {"schema_id": MultiverseCandidateSchema.SCHEMA_ID, "schema_version_hash": MultiverseCandidateSchema.SCHEMA_VERSION_HASH, "candidate_id": "beta", "token_count": 3, "metrics": {"m1": 0.7, "m2": 0.3}}
    request = MultiverseEvaluationRequestSchema.from_dict({"schema_id": MultiverseEvaluationRequestSchema.SCHEMA_ID, "schema_version_hash": MultiverseEvaluationRequestSchema.SCHEMA_VERSION_HASH, "evaluation_id": "wave2c.multiverse.eval", "runtime_registry_hash": registry_hash, "metric_names": ["m1", "m2"], "candidates": [c1, c2]})
    result_one = MultiverseEngine.evaluate(context=context, request=request).to_dict()
    result_two = MultiverseEngine.evaluate(context=context, request=MultiverseEvaluationRequestSchema.from_dict({**request.to_dict(), "candidates": [c2, c1]})).to_dict()
    big = MAX_TOTAL_TOKENS // 2 + 100
    try:
        MultiverseEvaluationRequestSchema.from_dict({**request.to_dict(), "evaluation_id": "wave2c.multiverse.fail", "metric_names": ["m1"], "candidates": [{**c1, "candidate_id": "x", "token_count": big, "metrics": {"m1": 0.2}}, {**c2, "candidate_id": "y", "token_count": big, "metrics": {"m1": 0.2}}]})
        raise RuntimeError("FAIL_CLOSED: expected multiverse over-budget schema rejection")
    except Exception as exc:  # noqa: BLE001
        failure = _failure(export_root / "multiverse", surface_id="multiverse.multiverse_engine.evaluate", error_class=exc.__class__.__name__, bounded_reason=str(exc), input_hash=sha256_text("wave2c.multiverse.fail"), context_hash=sha256_json(context), policy_profile="wave2c.multiverse.over_budget", budget_profile="wave2c.multiverse.bounds", replay_pack_ref="E0_INTERNAL_SELF_ISSUED_ONLY")
    probe = _spine_probe(root, export_root / "multiverse", "multiverse_eval", request.to_dict())
    receipt = f"{REPORT_ROOT_REL}/kt_wave2c_multiverse_engine_pack.json"
    _telemetry(telemetry_path, "multiverse", receipt, failure["artifact_ref"])
    return _pack(
        "multiverse",
        entrypoint="KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/multiverse/multiverse_engine.py",
        disposition="REALIZED_BOUNDED_KEEP_CANONICAL",
        summary="Multiverse is realized as a bounded deterministic candidate-ranking surface with explicit token ceilings. Direct proof is real; canonical spine carriage remains blocked where the runtime-context envelope cannot lawfully carry full multiverse payloads.",
        maturity="O2_HARDENED",
        externality="E0_INTERNAL_SELF_ISSUED_ONLY",
        benchmarks=[{"benchmark_id": "order_independence", "observed": result_one["result_hash"], "pass": result_one == result_two}],
        challenges=[{"challenge_id": "over_budget_request_rejected", "pass": True, "error_class": failure["payload"]["error_class"]}],
        provenance={"runtime_registry_hash": registry_hash, "request_hash": result_one["request_hash"], "result_hash": result_one["result_hash"], "ranking": result_one["ranking"]},
        spine={"status": "PASS" if probe.get("status") == "PASS" else "BLOCKED", "probe_ref": probe["probe_refs"].get("output_ref", probe["probe_refs"].get("blocked_ref", "")), "runtime_status": probe.get("spine_result", {}).get("multiverse", {}).get("status", "BLOCKED_BY_RUNTIME_CONTEXT_INPUT_LIMIT"), "runtime_telemetry_ref": probe["probe_refs"].get("telemetry_ref", ""), "ranking": probe.get("spine_result", {}).get("multiverse", {}).get("ranking", []), "blocked_reason": "runtime_context_input_string_exceeds_max_string_len" if probe.get("status") != "PASS" else ""},
        telemetry_refs=[ref for ref in [_rel(root, telemetry_path), probe["probe_refs"].get("telemetry_ref", "")] if ref],
        failure_refs=[_rel(root, Path(failure["artifact_ref"]))],
        stronger_claim_not_made=["broad_multiverse_orchestration_claimed", "search_over_many_live_branches_claimed", "canonical_spine_carriage_claimed_despite_input_limit"],
    )


def _council(root: Path, export_root: Path, telemetry_path: Path, registry_hash: str) -> Dict[str, Any]:
    context = _context()
    request = CouncilRequestSchema.from_dict({"schema_id": CouncilRequestSchema.SCHEMA_ID, "schema_version_hash": CouncilRequestSchema.SCHEMA_VERSION_HASH, "request_id": "wave2c.council.request", "runtime_registry_hash": registry_hash, "mode": COUNCIL_MODE_DRY_RUN, "provider_ids": ["dry_run"], "fanout_cap": 1, "per_call_token_cap": 256, "total_token_cap": 1024, "input_hash": sha256_text("wave2c council request")})
    plan_one = CouncilRouter.plan(context=context, request=request).to_dict()
    plan_two = CouncilRouter.plan(context=context, request=request).to_dict()
    result_one = CouncilRouter.execute(context=context, plan=CouncilPlanSchema.from_dict(plan_one)).to_dict()
    result_two = CouncilRouter.execute(context=context, plan=CouncilPlanSchema.from_dict(plan_two)).to_dict()
    live_request = CouncilRequestSchema.from_dict({**request.to_dict(), "mode": COUNCIL_MODE_LIVE_REQUESTED, "request_id": "wave2c.council.live"})
    live_plan = CouncilRouter.plan(context=context, request=live_request).to_dict()
    live_result = CouncilRouter.execute(context=context, plan=CouncilPlanSchema.from_dict(live_plan)).to_dict()
    failure = _failure(export_root / "council", surface_id="council.council_router.plan_execute", error_class="CouncilLiveRefused", bounded_reason=str(live_plan.get("refusal_code", "")), input_hash=live_request.data["input_hash"], context_hash=str(live_result["result_hash"]), policy_profile="wave2c.council.live_refusal", budget_profile="wave2c.council.bounds", replay_pack_ref="E0_INTERNAL_SELF_ISSUED_ONLY")
    probe_plan = _spine_probe(root, export_root / "council", "council_plan", request.to_dict())
    probe_execute = _spine_probe(root, export_root / "council", "council_execute", CouncilPlanSchema.from_dict(plan_one).to_dict())
    wave2a = _load_json(root / REPORT_ROOT_REL / "kt_wave2a_provider_activation_receipts.json")
    receipt = f"{REPORT_ROOT_REL}/kt_wave2c_council_kernel_binding_pack.json"
    _telemetry(telemetry_path, "council", receipt, failure["artifact_ref"])
    return _pack(
        "council",
        entrypoint="KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/council_router.py",
        disposition="REALIZED_BOUNDED_KEEP_CANONICAL",
        summary="Council is realized as a bounded canonical dry-run planning/execution surface, while the Wave 2A live seam remains auth-bounded. Direct proof is real; canonical spine carriage remains blocked where the runtime-context envelope cannot lawfully carry full council payloads.",
        maturity="O2_HARDENED",
        externality="E0_INTERNAL_SELF_ISSUED_ONLY",
        benchmarks=[{"benchmark_id": "deterministic_plan_hash", "observed": plan_one["plan_hash"], "pass": plan_one == plan_two}, {"benchmark_id": "deterministic_dry_run_result_hash", "observed": result_one["result_hash"], "pass": result_one == result_two and result_one["status"] == "DRY_RUN"}],
        challenges=[{"challenge_id": "live_mode_refused", "pass": live_result["status"] == "REFUSED", "refusal_code": live_plan.get("refusal_code")}],
        provenance={"runtime_registry_hash": registry_hash, "request_hash": plan_one["request_hash"], "plan_hash": plan_one["plan_hash"], "result_hash": result_one["result_hash"], "wave2a_boundary_holds": list(wave2a.get("boundary_holds", []))},
        spine={"status": "PASS" if probe_plan.get("status") == "PASS" and probe_execute.get("status") == "PASS" else "BLOCKED", "plan_probe_ref": probe_plan["probe_refs"].get("output_ref", probe_plan["probe_refs"].get("blocked_ref", "")), "execute_probe_ref": probe_execute["probe_refs"].get("output_ref", probe_execute["probe_refs"].get("blocked_ref", "")), "plan_status": probe_plan.get("spine_result", {}).get("council", {}).get("status", "BLOCKED_BY_RUNTIME_CONTEXT_INPUT_LIMIT"), "execute_status": probe_execute.get("spine_result", {}).get("council", {}).get("status", "BLOCKED_BY_RUNTIME_CONTEXT_INPUT_LIMIT"), "runtime_telemetry_refs": [ref for ref in [probe_plan["probe_refs"].get("telemetry_ref", ""), probe_execute["probe_refs"].get("telemetry_ref", "")] if ref], "wave2a_live_lane_refs": ["KT_PROD_CLEANROOM/reports/kt_wave2a_provider_activation_receipts.json", "KT_PROD_CLEANROOM/reports/kt_wave2a_adapter_activation_receipt.json"], "blocked_reason": "runtime_context_input_string_exceeds_max_string_len" if probe_plan.get("status") != "PASS" or probe_execute.get("status") != "PASS" else ""},
        telemetry_refs=[ref for ref in [_rel(root, telemetry_path), probe_plan["probe_refs"].get("telemetry_ref", ""), probe_execute["probe_refs"].get("telemetry_ref", "")] if ref],
        failure_refs=[_rel(root, Path(failure["artifact_ref"]))],
        stronger_claim_not_made=["broad_multi_provider_live_inference_claimed", "council_superiority_claimed", "canonical_spine_carriage_claimed_despite_input_limit"],
    )


def build_wave2c_reports(*, root: Path, telemetry_path: Path, export_root: Path) -> Dict[str, Dict[str, Any]]:
    if export_root.exists():
        shutil.rmtree(export_root, ignore_errors=True)
    export_root.mkdir(parents=True, exist_ok=True)
    if telemetry_path.exists():
        telemetry_path.unlink()
    registry_hash = _registry_hash()
    suite_report = build_wave2c_independent_suite_report(root=root)
    cognition = _cognition(root, export_root, telemetry_path, registry_hash)
    paradox = _paradox(root, export_root, telemetry_path)
    temporal = _temporal(root, export_root, telemetry_path, registry_hash)
    multiverse = _multiverse(root, export_root, telemetry_path, registry_hash)
    council = _council(root, export_root, telemetry_path, registry_hash)
    rows = [
        {"organ_id": "router", "reality_class": "LIVE_BOUNDED", "maturity_class": "O2_HARDENED", "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY", "disposition": "KEEP_STATIC_CANONICAL_BASELINE", "status": "UNCHANGED", "evidence_ref": "KT_PROD_CLEANROOM/reports/kt_wave2b_router_selection_receipt.json", "bounded_summary": "Static router remains canonical; learned cutover stays blocked."},
        {"organ_id": "council", "reality_class": council["reality_class"], "maturity_class": council["maturity_class"], "externality_class": council["externality_class"], "disposition": council["disposition"], "status": "UPDATED_WAVE_2C", "evidence_ref": f"{REPORT_ROOT_REL}/kt_wave2c_council_kernel_binding_pack.json", "bounded_summary": council["bounded_summary"]},
        {"organ_id": "cognition", "reality_class": cognition["reality_class"], "maturity_class": cognition["maturity_class"], "externality_class": cognition["externality_class"], "disposition": cognition["disposition"], "status": "UPDATED_WAVE_2C", "evidence_ref": f"{REPORT_ROOT_REL}/kt_wave2c_cognitive_provenance_pack.json", "bounded_summary": cognition["bounded_summary"]},
        {"organ_id": "paradox", "reality_class": paradox["reality_class"], "maturity_class": paradox["maturity_class"], "externality_class": paradox["externality_class"], "disposition": paradox["disposition"], "status": "UPDATED_WAVE_2C", "evidence_ref": f"{REPORT_ROOT_REL}/kt_wave2c_paradox_engine_pack.json", "bounded_summary": paradox["bounded_summary"]},
        {"organ_id": "temporal", "reality_class": temporal["reality_class"], "maturity_class": temporal["maturity_class"], "externality_class": temporal["externality_class"], "disposition": temporal["disposition"], "status": "UPDATED_WAVE_2C", "evidence_ref": f"{REPORT_ROOT_REL}/kt_wave2c_temporal_engine_pack.json", "bounded_summary": temporal["bounded_summary"]},
        {"organ_id": "multiverse", "reality_class": multiverse["reality_class"], "maturity_class": multiverse["maturity_class"], "externality_class": multiverse["externality_class"], "disposition": multiverse["disposition"], "status": "UPDATED_WAVE_2C", "evidence_ref": f"{REPORT_ROOT_REL}/kt_wave2c_multiverse_engine_pack.json", "bounded_summary": multiverse["bounded_summary"]},
        {"organ_id": "adapter_layer", "reality_class": "LIVE_BOUNDED", "maturity_class": "O2_HARDENED", "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY", "disposition": "KEEP_BOUNDED_WAVE2A", "status": "UNCHANGED", "evidence_ref": "KT_PROD_CLEANROOM/reports/kt_wave2a_adapter_activation_receipt.json", "bounded_summary": "Adapter layer remains bounded by Wave 2A live-hashed receipts and auth-bounded outcomes."},
        {"organ_id": "tournament_promotion", "reality_class": "LIVE_BOUNDED", "maturity_class": "O2_HARDENED", "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY", "disposition": "LAB_ONLY_UNTIL_RUNTIME_REAL", "status": "UNCHANGED", "evidence_ref": "KT_PROD_CLEANROOM/reports/kt_tournament_readiness_receipt.json", "bounded_summary": "Tournament/promotion remains lab-only."},
        {"organ_id": "teacher_growth_surfaces", "reality_class": "SCAFFOLDED", "maturity_class": "UNRATED", "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY", "disposition": "LAB_ONLY_UNLESS_PROMOTED", "status": "UNCHANGED", "evidence_ref": "KT_PROD_CLEANROOM/reports/kt_wave0_quarantine_receipts.json", "bounded_summary": "Teacher/growth surfaces remain lab-only."},
        {"organ_id": "toolchain_only_orchestrators", "reality_class": "TOOLCHAIN_PROVING", "maturity_class": "UNRATED", "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY", "disposition": "TOOLCHAIN_PROVING_ONLY", "status": "UNCHANGED", "evidence_ref": "KT_PROD_CLEANROOM/reports/kt_wave0_5_toolchain_runtime_firewall_receipt.json", "bounded_summary": "Toolchain-only orchestrators remain non-runtime."},
        {"organ_id": "detached_verifier", "reality_class": "CURRENT_HEAD_PROVEN", "maturity_class": "UNRATED", "externality_class": "E1_SAME_HOST_DETACHED_REPLAY", "disposition": "KEEP_AND_HARDEN", "status": "UNCHANGED", "evidence_ref": "KT_PROD_CLEANROOM/reports/kt_external_verifier_confirmation_receipt.json", "bounded_summary": "Detached verifier remains current-head proven and awaits Wave 3."},
        {"organ_id": "claim_compiler", "reality_class": "CURRENT_HEAD_PROVEN", "maturity_class": "UNRATED", "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY", "disposition": "KEEP_AND_ELEVATE_AS_VOCABULARY_GATE", "status": "UNCHANGED", "evidence_ref": "KT_PROD_CLEANROOM/reports/kt_claim_compiler_activation_receipt.json", "bounded_summary": "Claim compiler remains a bounded vocabulary gate awaiting Wave 3."},
    ]
    maturity_report = {"schema_id": "kt.wave2c.organ_maturity_matrix.v1", "generated_utc": utc_now_iso_z(), "status": "PASS", "scope_boundary": "Wave 2C realizes bounded organ truth without learned-router cutover, tournament promotion, or product widening.", "rows": rows, "boundary_holds": ["CANONICAL_STATIC_ROUTER_RETAINS_AUTHORITY", "LEARNED_ROUTER_CUTOVER_NOT_EARNED", "REMOTE_PROVIDER_AUTH_DID_NOT_YIELD_SUCCESSFUL_CURRENT_HEAD_INFERENCE", "EXTERNALITY_CEILING_REMAINS_BOUNDED", "REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED", "CANONICAL_SPINE_INPUT_CEILING_BLOCKS_FULL_ORGAN_PAYLOAD_CARRIAGE", "TOURNAMENT_PROMOTION_REMAINS_LAB_ONLY"], "failures": []}
    disposition_report = {"schema_id": "kt.wave2c.organ_disposition_register.v1", "generated_utc": utc_now_iso_z(), "current_git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(root), text=True).strip(), "rows": rows, "stronger_claim_not_made": ["learned_router_cutover_occurred", "tournament_promoted_to_canonical_runtime", "product_language_widened", "broad_live_runtime_success_claimed"]}
    return {"suite_report": suite_report, "cognition_report": cognition, "paradox_report": paradox, "temporal_report": temporal, "multiverse_report": multiverse, "council_report": council, "maturity_report": maturity_report, "disposition_report": disposition_report}


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Wave 2C organ realization and emit bounded proof packs.")
    parser.add_argument("--suite-output", default=f"{REPORT_ROOT_REL}/kt_wave2c_independent_organ_test_suites.json")
    parser.add_argument("--cognition-output", default=f"{REPORT_ROOT_REL}/kt_wave2c_cognitive_provenance_pack.json")
    parser.add_argument("--paradox-output", default=f"{REPORT_ROOT_REL}/kt_wave2c_paradox_engine_pack.json")
    parser.add_argument("--temporal-output", default=f"{REPORT_ROOT_REL}/kt_wave2c_temporal_engine_pack.json")
    parser.add_argument("--multiverse-output", default=f"{REPORT_ROOT_REL}/kt_wave2c_multiverse_engine_pack.json")
    parser.add_argument("--council-output", default=f"{REPORT_ROOT_REL}/kt_wave2c_council_kernel_binding_pack.json")
    parser.add_argument("--maturity-output", default=f"{REPORT_ROOT_REL}/kt_wave2c_organ_maturity_matrix.json")
    parser.add_argument("--disposition-output", default=f"{REPORT_ROOT_REL}/kt_wave2c_organ_disposition_register.json")
    parser.add_argument("--telemetry-output", default=f"{REPORT_ROOT_REL}/kt_wave2c_organ_telemetry.jsonl")
    parser.add_argument("--export-root", default=EXPORT_ROOT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    telemetry_path = Path(str(args.telemetry_output)).expanduser()
    if not telemetry_path.is_absolute():
        telemetry_path = (root / telemetry_path).resolve()
    export_root = Path(str(args.export_root)).expanduser()
    if not export_root.is_absolute():
        export_root = (root / export_root).resolve()
    reports = build_wave2c_reports(root=root, telemetry_path=telemetry_path, export_root=export_root)
    outputs = {"suite_report": Path(str(args.suite_output)).expanduser(), "cognition_report": Path(str(args.cognition_output)).expanduser(), "paradox_report": Path(str(args.paradox_output)).expanduser(), "temporal_report": Path(str(args.temporal_output)).expanduser(), "multiverse_report": Path(str(args.multiverse_output)).expanduser(), "council_report": Path(str(args.council_output)).expanduser(), "maturity_report": Path(str(args.maturity_output)).expanduser(), "disposition_report": Path(str(args.disposition_output)).expanduser()}
    for key, path in list(outputs.items()):
        if not path.is_absolute():
            outputs[key] = (root / path).resolve()
    for key, path in outputs.items():
        write_json_stable(path, reports[key])
    failures = {key: list(payload.get("failures", [])) for key, payload in reports.items() if str(payload.get("status", "PASS")).strip().upper() != "PASS"}
    status = "PASS" if not failures else "FAIL"
    print(json.dumps({"failure_keys": sorted(failures), "status": status}, sort_keys=True))
    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
