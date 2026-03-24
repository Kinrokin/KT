from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from cognition.cognitive_engine import CognitiveEngine
from cognition.cognitive_schemas import CognitivePlanSchema, CognitiveRequestSchema, MODE_DRY_RUN as COGNITION_MODE_DRY_RUN
from core.invariants_gate import CONSTITUTION_VERSION_HASH
from core.runtime_registry import load_runtime_registry
from core.spine import _runtime_registry_hash
from council.council_router import CouncilRouter
from council.council_schemas import CouncilPlanSchema, CouncilRequestSchema, MODE_DRY_RUN as COUNCIL_MODE_DRY_RUN
from council.providers.failure_artifacts import write_failure_artifact
from multiverse.multiverse_engine import MultiverseEngine
from multiverse.multiverse_schemas import (
    MultiverseCandidateSchema,
    MultiverseEvaluationRequestSchema,
)
from paradox.paradox_engine import ParadoxEngine
from paradox.paradox_schemas import ParadoxTriggerSchema
from schemas.runtime_context_schema import (
    RUNTIME_CONTEXT_MAX_INPUT_BYTES,
    RUNTIME_CONTEXT_MAX_STRING_LEN,
    RUNTIME_CONTEXT_SCHEMA_ID,
    RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
)
from schemas.schema_hash import canonical_json, sha256_json, sha256_text
from schemas.telemetry_runtime import DEFAULT_ENV_VAR as RUNTIME_TELEMETRY_ENV_VAR
from temporal.temporal_engine import TemporalEngine
from temporal.temporal_schemas import TemporalForkRequestSchema, TemporalReplayRequestSchema
from tools.operator.observability import emit_toolchain_telemetry, telemetry_now_ms
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
EXPORT_ROOT_REL = "KT_PROD_CLEANROOM/exports/c017_spine_carriage_remediation"
WAVE_ID = "C017_CANONICAL_SPINE_CARRIAGE_REMEDIATION_ONLY"
REMAINING_OPEN_TRUTHS = [
    "C005_ROUTER_AMBITION_EXCEEDS_IMPLEMENTATION",
    "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED",
    "C007_REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED",
    "C016_REMOTE_PROVIDER_AUTH_ONLY_FAIL_CLOSED_OUTCOMES_VISIBLE",
]


def _rel(root: Path, path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _registry_hash() -> str:
    return _runtime_registry_hash(load_runtime_registry())


def _context_with_input(*, input_text: str, artifact_root: Path) -> Dict[str, Any]:
    return {
        "artifact_root": str(artifact_root.resolve()),
        "constitution_version_hash": CONSTITUTION_VERSION_HASH,
        "envelope": {"input": input_text},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
    }


def _base_context() -> Dict[str, Any]:
    return {
        "constitution_version_hash": CONSTITUTION_VERSION_HASH,
        "envelope": {"input": ""},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
    }


def _tool_env(root: Path) -> Dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def _emit_toolchain_probe_telemetry(path: Path, *, probe_id: str, receipt_ref: str, result_status: str, failure_artifact_ref: str = "") -> None:
    started = telemetry_now_ms()
    emit_toolchain_telemetry(
        surface_id=f"tools.operator.c017.{probe_id}",
        zone="TOOLCHAIN_PROVING",
        event_type="spine.carriage_probe",
        start_ts=started,
        end_ts=telemetry_now_ms(),
        result_status=result_status,
        policy_applied="c017.spine_carriage_remediation",
        receipt_ref=receipt_ref,
        failure_artifact_ref=failure_artifact_ref,
        trace_id=f"c017-{probe_id}",
        request_id=f"c017.{probe_id}",
        path=path,
    )


def _expected_probe_specs(registry_hash: str) -> List[Dict[str, Any]]:
    context = _base_context()

    paradox_trigger = ParadoxTriggerSchema.from_dict(
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
    paradox_expected = ParadoxEngine.run(context=context, trigger=paradox_trigger).to_dict()

    temporal_fork = TemporalForkRequestSchema.from_dict(
        {
            "schema_id": TemporalForkRequestSchema.SCHEMA_ID,
            "schema_version_hash": TemporalForkRequestSchema.SCHEMA_VERSION_HASH,
            "trace_id": "c017.temporal.trace",
            "epoch_id": "c017.temporal.epoch",
            "runtime_registry_hash": registry_hash,
            "anchor_hash": sha256_text("c017 temporal anchor"),
            "parent_fork_hash": None,
        }
    )
    temporal_fork_expected = TemporalEngine.create_fork(context=context, request=temporal_fork).to_dict()
    temporal_replay = TemporalReplayRequestSchema.from_dict(
        {
            "schema_id": TemporalReplayRequestSchema.SCHEMA_ID,
            "schema_version_hash": TemporalReplayRequestSchema.SCHEMA_VERSION_HASH,
            "fork": temporal_fork_expected,
            "replay_mode": "DRY_RUN",
            "runtime_registry_hash": registry_hash,
            "max_steps": 0,
        }
    )
    temporal_replay_expected = TemporalEngine.replay(context=context, request=temporal_replay).to_dict()

    multiverse_request = MultiverseEvaluationRequestSchema.from_dict(
        {
            "schema_id": MultiverseEvaluationRequestSchema.SCHEMA_ID,
            "schema_version_hash": MultiverseEvaluationRequestSchema.SCHEMA_VERSION_HASH,
            "evaluation_id": "c017.multiverse.eval",
            "runtime_registry_hash": registry_hash,
            "metric_names": ["m1", "m2"],
            "candidates": [
                {
                    "schema_id": MultiverseCandidateSchema.SCHEMA_ID,
                    "schema_version_hash": MultiverseCandidateSchema.SCHEMA_VERSION_HASH,
                    "candidate_id": "alpha",
                    "token_count": 3,
                    "metrics": {"m1": 0.2, "m2": 0.8},
                },
                {
                    "schema_id": MultiverseCandidateSchema.SCHEMA_ID,
                    "schema_version_hash": MultiverseCandidateSchema.SCHEMA_VERSION_HASH,
                    "candidate_id": "beta",
                    "token_count": 3,
                    "metrics": {"m1": 0.7, "m2": 0.3},
                },
            ],
        }
    )
    multiverse_expected = MultiverseEngine.evaluate(context=context, request=multiverse_request).to_dict()

    cognition_request = CognitiveRequestSchema.from_dict(
        {
            "schema_id": CognitiveRequestSchema.SCHEMA_ID,
            "schema_version_hash": CognitiveRequestSchema.SCHEMA_VERSION_HASH,
            "request_id": "c017.cognition.request",
            "runtime_registry_hash": registry_hash,
            "mode": COGNITION_MODE_DRY_RUN,
            "input_hash": sha256_text("c017 cognition bounded request"),
            "max_steps": 4,
            "max_branching": 1,
            "max_depth": 4,
            "artifact_refs": [{"artifact_hash": sha256_text("paradox.trigger"), "artifact_id": "paradox.trigger"}],
        }
    )
    cognition_plan_expected = CognitiveEngine.plan(context=context, request=cognition_request).to_dict()
    cognition_execute_expected = CognitiveEngine.execute(
        context=context,
        plan=CognitivePlanSchema.from_dict(cognition_plan_expected),
    ).to_dict()

    council_request = CouncilRequestSchema.from_dict(
        {
            "schema_id": CouncilRequestSchema.SCHEMA_ID,
            "schema_version_hash": CouncilRequestSchema.SCHEMA_VERSION_HASH,
            "request_id": "c017.council.request",
            "runtime_registry_hash": registry_hash,
            "mode": COUNCIL_MODE_DRY_RUN,
            "provider_ids": ["dry_run"],
            "fanout_cap": 1,
            "per_call_token_cap": 256,
            "total_token_cap": 1024,
            "input_hash": sha256_text("c017 council request"),
        }
    )
    council_plan_expected = CouncilRouter.plan(context=context, request=council_request).to_dict()
    council_execute_expected = CouncilRouter.execute(
        context=context,
        plan=CouncilPlanSchema.from_dict(council_plan_expected),
    ).to_dict()

    return [
        {
            "probe_id": "paradox_trigger",
            "payload": paradox_trigger.to_dict(),
            "organ_key": "paradox",
            "expected": {
                "status": paradox_expected["status"],
                "eligible": paradox_expected["eligible"],
                "task_hash": paradox_expected["task_hash"],
                "trigger_hash": paradox_expected["trigger_hash"],
            },
        },
        {
            "probe_id": "temporal_fork",
            "payload": temporal_fork.to_dict(),
            "organ_key": "temporal",
            "expected": {
                "status": "OK",
                "mode": "FORK",
                "fork_hash": temporal_fork_expected["fork_hash"],
                "request_hash": temporal_fork_expected["request_hash"],
            },
        },
        {
            "probe_id": "temporal_replay",
            "payload": temporal_replay.to_dict(),
            "organ_key": "temporal",
            "expected": {
                "status": temporal_replay_expected["status"],
                "mode": "REPLAY",
                "replay_hash": temporal_replay_expected["replay_hash"],
                "outcome_hash": temporal_replay_expected["outcome_hash"],
                "steps_executed": temporal_replay_expected["steps_executed"],
            },
        },
        {
            "probe_id": "multiverse_evaluation",
            "payload": multiverse_request.to_dict(),
            "organ_key": "multiverse",
            "expected": {
                "status": "OK",
                "result_hash": multiverse_expected["result_hash"],
                "ranking": multiverse_expected["ranking"],
            },
        },
        {
            "probe_id": "cognition_request",
            "payload": cognition_request.to_dict(),
            "organ_key": "cognition",
            "expected": {
                "status": cognition_plan_expected["status"],
                "plan_hash": cognition_plan_expected["plan_hash"],
                "request_hash": cognition_plan_expected["request_hash"],
                "steps": len(cognition_plan_expected["steps"]),
            },
        },
        {
            "probe_id": "cognition_plan",
            "payload": CognitivePlanSchema.from_dict(cognition_plan_expected).to_dict(),
            "organ_key": "cognition",
            "expected": {
                "status": cognition_execute_expected["status"],
                "plan_hash": cognition_execute_expected["plan_hash"],
                "result_hash": cognition_execute_expected["result_hash"],
                "steps": len(cognition_execute_expected["steps"]),
            },
        },
        {
            "probe_id": "council_request",
            "payload": council_request.to_dict(),
            "organ_key": "council",
            "expected": {
                "status": council_plan_expected["status"],
                "plan_hash": council_plan_expected["plan_hash"],
                "request_hash": council_plan_expected["request_hash"],
            },
        },
        {
            "probe_id": "council_plan",
            "payload": CouncilPlanSchema.from_dict(council_plan_expected).to_dict(),
            "organ_key": "council",
            "expected": {
                "status": council_execute_expected["status"],
                "plan_hash": council_execute_expected["plan_hash"],
                "result_hash": council_execute_expected["result_hash"],
            },
        },
    ]


def _run_probe(root: Path, export_root: Path, telemetry_path: Path, spec: Dict[str, Any]) -> Dict[str, Any]:
    probe_root = (export_root / spec["probe_id"]).resolve()
    probe_root.mkdir(parents=True, exist_ok=True)
    artifact_root = (probe_root / "artifacts").resolve()
    artifact_root.mkdir(parents=True, exist_ok=True)
    payload_path = probe_root / "payload.json"
    output_path = probe_root / "spine_result.json"
    runtime_telemetry_path = probe_root / "runtime_telemetry.jsonl"

    payload = dict(spec["payload"])
    payload_text = canonical_json(payload)
    payload_path.write_text(payload_text, encoding="utf-8")

    env = _tool_env(root)
    env[RUNTIME_TELEMETRY_ENV_VAR] = str(runtime_telemetry_path)
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
            str(runtime_telemetry_path),
        ],
        cwd=str(root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"FAIL_CLOSED: c017 spine probe failed for {spec['probe_id']}: {proc.stdout}")

    result_payload = json.loads(output_path.read_text(encoding="utf-8"))
    result = dict(result_payload["spine_result"])

    write_json_stable(
        output_path,
        {
            "artifact_root": artifact_root.as_posix(),
            "payload_hash": sha256_json(payload),
            "probe_id": spec["probe_id"],
            "spine_result": result,
            "status": "PASS",
        },
    )
    runtime_slice = result.get(str(spec["organ_key"]), {})
    expected = dict(spec["expected"])
    comparison = {key: runtime_slice.get(key) == value for key, value in expected.items()}
    comparison_pass = all(comparison.values())
    governance_verdict_path = artifact_root / "governance_verdict.json"
    row = {
        "probe_id": spec["probe_id"],
        "payload_schema_id": payload.get("schema_id", ""),
        "input_string_length": len(payload_text),
        "input_utf8_bytes": len(payload_text.encode("utf-8")),
        "legacy_string_ceiling": RUNTIME_CONTEXT_MAX_STRING_LEN,
        "current_input_byte_ceiling": RUNTIME_CONTEXT_MAX_INPUT_BYTES,
        "status": "PASS" if comparison_pass else "FAIL",
        "comparison_pass": comparison_pass,
        "comparison": comparison,
        "expected_fields": expected,
        "observed_fields": {key: runtime_slice.get(key) for key in expected},
        "artifact_refs": {
            "artifact_root_ref": _rel(root, artifact_root),
            "governance_verdict_ref": _rel(root, governance_verdict_path) if governance_verdict_path.exists() else "",
            "payload_ref": _rel(root, payload_path),
            "runtime_telemetry_ref": _rel(root, runtime_telemetry_path) if runtime_telemetry_path.exists() else "",
            "spine_result_ref": _rel(root, output_path),
        },
    }
    _emit_toolchain_probe_telemetry(
        telemetry_path,
        probe_id=spec["probe_id"],
        receipt_ref=row["artifact_refs"]["spine_result_ref"],
        result_status=row["status"],
    )
    return row


def _run_oversize_probe(root: Path, export_root: Path, telemetry_path: Path) -> Dict[str, Any]:
    probe_root = (export_root / "oversize_guard").resolve()
    probe_root.mkdir(parents=True, exist_ok=True)
    artifact_root = (probe_root / "artifacts").resolve()
    payload_path = probe_root / "oversize_payload.json"
    output_path = probe_root / "oversize_probe_result.json"
    telemetry_output = probe_root / "oversize_runtime_telemetry.jsonl"
    oversize_payload = {"payload": "x" * (RUNTIME_CONTEXT_MAX_INPUT_BYTES + 128)}
    oversize_text = canonical_json(oversize_payload)
    payload_path.write_text(oversize_text, encoding="utf-8")

    env = _tool_env(root)
    env[RUNTIME_TELEMETRY_ENV_VAR] = str(telemetry_output)
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
            str(telemetry_output),
        ],
        cwd=str(root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    if proc.returncode == 0:
        status = "FAIL"
        error_class = "MissingFailClosed"
        error_message = "oversize runtime context unexpectedly passed"
    else:
        status = "PASS"
        error_class = "ContractViolationError"
        error_message = proc.stdout.strip()

    failure_artifact = write_failure_artifact(
        export_root=probe_root,
        surface_id="core.spine.run",
        error_class=error_class,
        bounded_reason=error_message,
        input_hash=sha256_text(oversize_text),
        context_hash=sha256_json(
            _context_with_input(
                input_text=oversize_text,
                artifact_root=artifact_root,
            )
        ),
        policy_profile="c017.spine_carriage.input_limit_guard",
        budget_profile="runtime_context.max_input_bytes",
        replay_pack_ref="E0_INTERNAL_SELF_ISSUED_ONLY",
        severity="MEDIUM",
        wave_id=WAVE_ID,
    )
    _emit_toolchain_probe_telemetry(
        telemetry_path,
        probe_id="oversize_guard",
        receipt_ref=_rel(root, failure_artifact.path),
        result_status=status,
        failure_artifact_ref=_rel(root, failure_artifact.path),
    )
    return {
        "probe_id": "oversize_guard",
        "input_utf8_bytes": len(oversize_text.encode("utf-8")),
        "max_input_bytes": RUNTIME_CONTEXT_MAX_INPUT_BYTES,
        "status": status,
        "error_class": error_class,
        "error_message": error_message,
        "expected_error_message": "envelope.input exceeds max_input_bytes (fail-closed)",
        "message_match": "envelope.input exceeds max_input_bytes (fail-closed)" in error_message,
        "failure_artifact_ref": _rel(root, failure_artifact.path),
        "input_ref": _rel(root, payload_path),
        "telemetry_ref": _rel(root, telemetry_output) if telemetry_output.exists() else "",
    }


def build_c017_receipt(*, root: Path, telemetry_path: Path, export_root: Path) -> Dict[str, Any]:
    export_root.mkdir(parents=True, exist_ok=True)
    if telemetry_path.exists():
        telemetry_path.unlink()

    registry = load_runtime_registry()
    registry_hash = _registry_hash()
    state_vault_ref = _rel(root, registry.resolve_state_vault_jsonl_path())

    started = telemetry_now_ms()
    probe_specs = _expected_probe_specs(registry_hash)
    probe_rows = [_run_probe(root, export_root, telemetry_path, spec) for spec in probe_specs]
    oversize_guard = _run_oversize_probe(root, export_root, telemetry_path)
    completed = telemetry_now_ms()

    all_probe_pass = all(str(row.get("status", "")).upper() == "PASS" for row in probe_rows)
    oversize_pass = str(oversize_guard.get("status", "")).upper() == "PASS" and bool(oversize_guard.get("message_match"))
    min_payload_len = min(row["input_string_length"] for row in probe_rows)
    max_payload_len = max(row["input_string_length"] for row in probe_rows)

    receipt = {
        "schema_id": "kt.c017.spine_carriage_remediation_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "work_order_id": "KT_UNIFIED_CONVERGENCE_MAX_POWER_CAMPAIGN_V2_1_1_FINAL",
        "wave_or_tranche_id": WAVE_ID,
        "status": "PASS" if all_probe_pass and oversize_pass else "FAIL",
        "scope_boundary": "C017 canonical spine carriage remediation only. No Wave 3 execution, no router promotion, no tournament/product/externality widening.",
        "exact_ceiling": {
            "contradiction_id": "C017_CANONICAL_SPINE_INPUT_CEILING_BLOCKS_FULL_ORGAN_PAYLOAD_CARRIAGE",
            "law_surface": "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/runtime_context_schema.py",
            "mechanism": "validate_runtime_context applied validate_bounded_json_value to the whole runtime context, so envelope.input was constrained by the generic 256-char string limit even though it already had its own max_input_bytes ceiling.",
            "spine_dependency": "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py parses candidate payloads only from context.envelope.input.",
            "legacy_general_string_limit": RUNTIME_CONTEXT_MAX_STRING_LEN,
            "input_byte_ceiling": RUNTIME_CONTEXT_MAX_INPUT_BYTES,
            "smallest_pre_fix_blocked_payload_len": min_payload_len,
            "largest_bounded_payload_len_proven": max_payload_len,
        },
        "minimal_fix": {
            "status": "IMPLEMENTED",
            "strategy": "Keep the generic runtime-context short-string ceiling intact everywhere except envelope.input, which remains explicitly bounded by max_input_bytes and max_context_bytes.",
            "files_changed": [
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/runtime_context_schema.py",
            ],
            "parallel_runtime_created": False,
            "spine_rewrite_performed": False,
            "zone_boundary_change": "NONE",
        },
        "carriage_matrix": probe_rows,
        "oversize_guard": oversize_guard,
        "runtime_truth_preservation": {
            "canonical_kernel_unchanged": "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py",
            "router_status": "STATIC_CANONICAL_BASELINE_UNCHANGED",
            "learned_router_cutover_allowed": False,
            "state_vault_ref": state_vault_ref,
            "toolchain_runtime_firewall_crossing_created": False,
            "telemetry_path_ref": _rel(root, telemetry_path),
        },
        "wave3_unlock_assessment": {
            "c017_closed": all_probe_pass and oversize_pass,
            "wave3_unlocked": all_probe_pass and oversize_pass,
            "reason": (
                "C017 no longer blocks Wave 3 entry because full bounded organ payloads now ride through the canonical spine with deterministic over-limit failure."
                if all_probe_pass and oversize_pass
                else "C017 remains open because canonical spine carriage or deterministic over-limit failure did not validate cleanly."
            ),
            "wave3_auto_opened": False,
        },
        "remaining_open_truths": list(REMAINING_OPEN_TRUTHS),
        "stronger_claim_not_made": [
            "minimum_viable_civilization_run_executed",
            "learned_router_cutover_occurred",
            "tournament_promoted_to_canonical_runtime",
            "product_language_widened",
            "externality_class_widened",
            "broad_current_head_external_runtime_capability_confirmed",
        ],
        "timing_ms": {
            "start_ts": started,
            "end_ts": completed,
            "latency_ms": max(0, completed - started),
        },
    }
    emit_toolchain_telemetry(
        surface_id="tools.operator.c017_spine_carriage_validate",
        zone="TOOLCHAIN_PROVING",
        event_type="c017.spine_carriage_validate",
        start_ts=started,
        end_ts=completed,
        result_status=receipt["status"],
        policy_applied="c017.spine_carriage_remediation",
        receipt_ref=f"{REPORT_ROOT_REL}/kt_c017_spine_carriage_remediation_receipt.json",
        failure_artifact_ref=oversize_guard["failure_artifact_ref"],
        trace_id="c017-spine-carriage",
        request_id="c017.spine_carriage_validate",
        path=telemetry_path,
    )
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate C017 canonical spine carriage remediation without opening Wave 3.")
    parser.add_argument(
        "--receipt-output",
        default=f"{REPORT_ROOT_REL}/kt_c017_spine_carriage_remediation_receipt.json",
    )
    parser.add_argument(
        "--telemetry-output",
        default=f"{REPORT_ROOT_REL}/kt_c017_spine_carriage_telemetry.jsonl",
    )
    parser.add_argument(
        "--export-root",
        default=EXPORT_ROOT_REL,
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    receipt_path = Path(str(args.receipt_output)).expanduser()
    if not receipt_path.is_absolute():
        receipt_path = (root / receipt_path).resolve()
    telemetry_path = Path(str(args.telemetry_output)).expanduser()
    if not telemetry_path.is_absolute():
        telemetry_path = (root / telemetry_path).resolve()
    export_root = Path(str(args.export_root)).expanduser()
    if not export_root.is_absolute():
        export_root = (root / export_root).resolve()

    receipt = build_c017_receipt(root=root, telemetry_path=telemetry_path, export_root=export_root)
    write_json_stable(receipt_path, receipt)
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "wave3_unlocked": receipt["wave3_unlock_assessment"]["wave3_unlocked"],
            },
            sort_keys=True,
        )
    )
    return 0 if receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
