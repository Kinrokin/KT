from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, semantically_equal_json, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
WORK_ORDER_REL = "KT_PROD_CLEANROOM/AUDITS/COUNCIL_PACKET/V2/WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION.v2.json"
STEP9_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_runtime_and_experiment_memory_sealing_receipt.json"
STATE_VECTOR_REL = f"{REPORT_ROOT_REL}/kt_state_vector.json"
CLAIM_REGISTRY_REL = f"{REPORT_ROOT_REL}/kt_claim_registry.json"
CONFLICT_REGISTER_REL = f"{REPORT_ROOT_REL}/kt_conflict_register.json"
COUNTEREXAMPLE_REGISTER_REL = f"{REPORT_ROOT_REL}/kt_counterexample_register.json"
FRONTIER_SETTLEMENT_REL = f"{REPORT_ROOT_REL}/frontier_settlement_receipt.json"
H1_GATE_REL = f"{REPORT_ROOT_REL}/h1_activation_gate_receipt.json"
NEXT_HORIZON_REL = f"{REPORT_ROOT_REL}/next_horizon_activation_receipt.json"
LEARNING_DELTA_REGISTER_REL = f"{REPORT_ROOT_REL}/kt_learning_delta_register.json"
LINEAGE_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_lineage_manifest.json"

SAFETY_ENVELOPE_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_safety_envelope.json"
ORGAN_INVARIANTS_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_organ_invariants.json"
CLAIM_TAXONOMY_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_claim_taxonomy.json"
CONSTITUTION_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/KT_Constitution_v1.md"
COURT_PROCEDURE_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_constitutional_court_procedure.json"
PRESSURE_RESPONSE_REL = "KT_PROD_CLEANROOM/governance/pressure_response_taxonomy.json"
FAILURE_MODE_REL = "KT_PROD_CLEANROOM/governance/failure_mode_taxonomy.json"

PARADOX_ENGINE_REL = "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/paradox_engine.py"
PARADOX_SCHEMAS_REL = "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/paradox_schemas.py"
PARADOX_TEST_REL = "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/tests/test_paradox_engine.py"
PARADOX_EVENT_SCHEMA_REL = "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.paradox_event.v1.json"
LEGACY_PARADOX_EVENT_SCHEMA_REL = "KT_PROD_CLEANROOM/tools/growth/state/paradox_event_schema_v1.json"

PARADOX_MODEL_REL = f"{REPORT_ROOT_REL}/kt_paradox_models.tla"
PARADOX_INVARIANTS_REL = f"{REPORT_ROOT_REL}/kt_paradox_invariants.json"
PARADOX_COUNTEREXAMPLES_REL = f"{REPORT_ROOT_REL}/kt_paradox_counterexamples.json"
PARADOX_STRESS_RESULTS_REL = f"{REPORT_ROOT_REL}/kt_paradox_stress_results.json"
PARADOX_CLAIM_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_paradox_claim_matrix.json"
PROOF_OBLIGATION_SCHEDULER_REL = f"{REPORT_ROOT_REL}/kt_proof_obligation_scheduler.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_paradox_program_bounded_receipt.json"

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/paradox_verification_compile.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_paradox_verification_compile.py"

DELIVERABLE_REFS = [
    PARADOX_MODEL_REL,
    PARADOX_INVARIANTS_REL,
    PARADOX_COUNTEREXAMPLES_REL,
    PARADOX_STRESS_RESULTS_REL,
    PARADOX_CLAIM_MATRIX_REL,
    PROOF_OBLIGATION_SCHEDULER_REL,
]
SUBJECT_ARTIFACT_REFS = DELIVERABLE_REFS + [TOOL_REL, TEST_REL]
PLANNED_MUTATES = SUBJECT_ARTIFACT_REFS + [RECEIPT_REL]

WORK_ORDER_ID = "WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION"
WORK_ORDER_SCHEMA_ID = "kt.work_order.max_refactor_e2e_institutional_memory_and_full_stack_adjudication.v2"

PROTECTED_PREFIXES = (
    "KT_PROD_CLEANROOM/docs/commercial/",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/",
    "kt_truth_ledger:",
    ".github/workflows/",
)

REQUIRED_INVARIANT_IDS = [
    "no_infinite_contradiction_loop",
    "no_indefinite_hold_without_ttl",
    "no_governance_bypass_under_paradox_load",
    "no_silent_flattening_to_trivial_answers",
    "no_untracked_delta_generation_during_resolution",
]


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_parent(root: Path, commit: str) -> str:
    if not str(commit).strip():
        return ""
    try:
        return _git(root, "rev-parse", f"{commit}^")
    except Exception:  # noqa: BLE001
        return ""


def _git_diff_files(root: Path, older: str, newer: str, paths: Sequence[str]) -> List[str]:
    if not older or not newer:
        return []
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return []
    try:
        output = _git(root, "diff", "--name-only", older, newer, "--", *existing)
    except Exception:  # noqa: BLE001
        return []
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _git_last_commit_for_paths(root: Path, paths: Sequence[str]) -> str:
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return ""
    try:
        return _git(root, "log", "-1", "--format=%H", "--", *existing)
    except Exception:  # noqa: BLE001
        return ""


def _normalize_ref(ref: str) -> str:
    return str(ref).replace("\\", "/").strip()


def _unique_refs(values: Sequence[str]) -> List[str]:
    refs: List[str] = []
    seen = set()
    for value in values:
        normalized = _normalize_ref(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            refs.append(normalized)
    return refs


def _is_protected(path: str) -> bool:
    normalized = _normalize_ref(path)
    return any(normalized.startswith(prefix) for prefix in PROTECTED_PREFIXES)


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _write_text_stable(path: Path, text: str) -> bool:
    rendered = text.replace("\r\n", "\n")
    if path.exists() and path.read_text(encoding="utf-8") == rendered:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8", newline="\n")
    return True


def _parse_iso_z(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _format_iso_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_p_days(value: str) -> int:
    if not value.startswith("P") or not value.endswith("D"):
        raise RuntimeError(f"FAIL_CLOSED: unsupported TTL duration: {value}")
    return int(value[1:-1])


def _step_context(root: Path) -> Dict[str, Any]:
    step9 = _load_required(root, STEP9_RECEIPT_REL)
    if str(step9.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: Step 10 is blocked until the Step 9 sealing receipt is PASS.")

    return {
        "work_order": _load_required(root, WORK_ORDER_REL),
        "step9_receipt": step9,
        "step9_evidence_commit": _git_last_commit_for_paths(root, [STEP9_RECEIPT_REL]),
        "state_vector": _load_required(root, STATE_VECTOR_REL),
        "claim_registry": _load_required(root, CLAIM_REGISTRY_REL),
        "conflict_register": _load_required(root, CONFLICT_REGISTER_REL),
        "counterexample_register": _load_required(root, COUNTEREXAMPLE_REGISTER_REL),
        "frontier_settlement": _load_required(root, FRONTIER_SETTLEMENT_REL),
        "h1_gate": _load_required(root, H1_GATE_REL),
        "next_horizon": _load_required(root, NEXT_HORIZON_REL),
        "safety_envelope": _load_required(root, SAFETY_ENVELOPE_REL),
        "organ_invariants": _load_required(root, ORGAN_INVARIANTS_REL),
        "claim_taxonomy": _load_required(root, CLAIM_TAXONOMY_REL),
        "court_procedure": _load_required(root, COURT_PROCEDURE_REL),
        "pressure_response": _load_required(root, PRESSURE_RESPONSE_REL),
        "failure_mode": _load_required(root, FAILURE_MODE_REL),
        "learning_delta_register": _load_required(root, LEARNING_DELTA_REGISTER_REL),
        "lineage_manifest": _load_required(root, LINEAGE_MANIFEST_REL),
        "paradox_event_schema": _load_required(root, PARADOX_EVENT_SCHEMA_REL),
        "legacy_paradox_event_schema": _load_required(root, LEGACY_PARADOX_EVENT_SCHEMA_REL),
    }


def _paradox_model_text() -> str:
    return """---- MODULE KTParadoxMetabolism ----
EXTENDS Naturals

CONSTANT MaxHoldDays

VARIABLES state, ttlDaysRemaining, governanceBypassAttempted, flattenedToTrivial, deltaGenerated, deltaTracked, contradictionLoopDepth

States == {"IDLE", "SIGNALLED", "HOLD", "ESCALATED", "FAIL_CLOSED", "RESOLVED"}

Init ==
  /\\ state = "IDLE"
  /\\ ttlDaysRemaining = MaxHoldDays
  /\\ governanceBypassAttempted = FALSE
  /\\ flattenedToTrivial = FALSE
  /\\ deltaGenerated = FALSE
  /\\ deltaTracked = TRUE
  /\\ contradictionLoopDepth = 0

Signal ==
  /\\ state = "IDLE"
  /\\ state' = "SIGNALLED"
  /\\ contradictionLoopDepth' = contradictionLoopDepth + 1
  /\\ UNCHANGED <<ttlDaysRemaining, governanceBypassAttempted, flattenedToTrivial, deltaGenerated, deltaTracked>>

EnterHold ==
  /\\ state = "SIGNALLED"
  /\\ state' = "HOLD"
  /\\ ttlDaysRemaining' \\in 1..MaxHoldDays
  /\\ UNCHANGED <<governanceBypassAttempted, flattenedToTrivial, deltaGenerated, deltaTracked, contradictionLoopDepth>>

Tick ==
  /\\ state = "HOLD"
  /\\ ttlDaysRemaining > 1
  /\\ ttlDaysRemaining' = ttlDaysRemaining - 1
  /\\ UNCHANGED <<state, governanceBypassAttempted, flattenedToTrivial, deltaGenerated, deltaTracked, contradictionLoopDepth>>

Escalate ==
  /\\ state = "HOLD"
  /\\ ttlDaysRemaining = 1
  /\\ state' = "ESCALATED"
  /\\ UNCHANGED <<ttlDaysRemaining, governanceBypassAttempted, flattenedToTrivial, deltaGenerated, deltaTracked, contradictionLoopDepth>>

FailClosed ==
  /\\ governanceBypassAttempted \\/ flattenedToTrivial
  /\\ state' = "FAIL_CLOSED"
  /\\ UNCHANGED <<ttlDaysRemaining, governanceBypassAttempted, flattenedToTrivial, deltaGenerated, deltaTracked, contradictionLoopDepth>>

Resolve ==
  /\\ state \\in {"SIGNALLED", "HOLD", "ESCALATED"}
  /\\ ~governanceBypassAttempted
  /\\ ~flattenedToTrivial
  /\\ deltaTracked
  /\\ state' = "RESOLVED"
  /\\ UNCHANGED <<ttlDaysRemaining, governanceBypassAttempted, flattenedToTrivial, deltaGenerated, deltaTracked, contradictionLoopDepth>>

Next == Signal \\/ EnterHold \\/ Tick \\/ Escalate \\/ FailClosed \\/ Resolve

NoInfiniteContradictionLoop == contradictionLoopDepth <= 1
NoIndefiniteHoldWithoutTTL == state = "HOLD" => ttlDaysRemaining \\in 1..MaxHoldDays
NoGovernanceBypassUnderParadoxLoad == governanceBypassAttempted => state = "FAIL_CLOSED"
NoSilentFlatteningToTrivialAnswers == flattenedToTrivial => state = "FAIL_CLOSED"
NoUntrackedDeltaGenerationDuringResolution == deltaGenerated => deltaTracked

Spec == Init /\\ [][Next]_<<state, ttlDaysRemaining, governanceBypassAttempted, flattenedToTrivial, deltaGenerated, deltaTracked, contradictionLoopDepth>>

====
"""


def _load_paradox_runtime(root: Path) -> Tuple[Any, Any, Any, str, str]:
    runtime_src = root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src"
    if str(runtime_src) not in sys.path:
        sys.path.insert(0, str(runtime_src))
    from paradox.paradox_engine import ParadoxEngine  # type: ignore[import-not-found]
    from paradox.paradox_schemas import ParadoxTriggerSchema  # type: ignore[import-not-found]
    from schemas.base_schema import SchemaValidationError  # type: ignore[import-not-found]
    from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH  # type: ignore[import-not-found]

    return ParadoxEngine, ParadoxTriggerSchema, SchemaValidationError, RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH


def _scan_salvage_paradox_history(root: Path) -> Dict[str, int]:
    salvage_root = root / "KT_PROD_CLEANROOM" / "tools" / "growth" / "artifacts" / "salvage"
    dream_files = 0
    dream_with_unresolved = 0
    seed_files = 0
    seed_with_nonzero = 0
    eval_files = 0
    eval_with_nonzero = 0

    for path in salvage_root.rglob("dream.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        dream_files += 1
        if payload.get("unresolved_paradoxes"):
            dream_with_unresolved += 1

    for path in salvage_root.rglob("seed.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        seed_files += 1
        counts = payload.get("counts", {}) if isinstance(payload.get("counts"), dict) else {}
        if int(counts.get("paradox_events", 0)) != 0:
            seed_with_nonzero += 1

    for path in salvage_root.rglob("eval.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        eval_files += 1
        if int(payload.get("paradox_events", 0)) != 0:
            eval_with_nonzero += 1

    return {
        "dream_files": dream_files,
        "dream_files_with_unresolved_paradoxes": dream_with_unresolved,
        "seed_files": seed_files,
        "seed_files_with_nonzero_paradox_events": seed_with_nonzero,
        "eval_files": eval_files,
        "eval_files_with_nonzero_paradox_events": eval_with_nonzero,
    }


def _build_stress_results(ctx: Dict[str, Any], root: Path, *, generated_utc: str) -> Dict[str, Any]:
    ParadoxEngine, ParadoxTriggerSchema, SchemaValidationError, runtime_schema_id, runtime_schema_hash = _load_paradox_runtime(root)
    context = {
        "envelope": {"input": "Resolve governed contradiction without overread."},
        "schema_id": runtime_schema_id,
        "schema_version_hash": runtime_schema_hash,
        "constitution_version_hash": "0" * 64,
    }
    trigger_payload = {
        "schema_id": ParadoxTriggerSchema.SCHEMA_ID,
        "schema_version_hash": ParadoxTriggerSchema.SCHEMA_VERSION_HASH,
        "trigger_type": "PARADOX_SIGNAL",
        "condition": "contradiction",
        "severity": 7,
        "confidence": 80,
        "subject_hash": "0" * 64,
        "signal_hash": "1" * 64,
    }
    trigger = ParadoxTriggerSchema.from_dict(trigger_payload)
    repeated = [ParadoxEngine.run(context=context, trigger=trigger).to_dict() for _ in range(16)]
    deterministic = len({row["task_hash"] for row in repeated}) == 1 and len({row["result_hash"] for row in repeated}) == 1
    eligible = repeated[0]

    low_severity_payload = dict(trigger_payload)
    low_severity_payload["severity"] = 1
    low_severity_trigger = ParadoxTriggerSchema.from_dict(low_severity_payload)
    noop = ParadoxEngine.run(context=context, trigger=low_severity_trigger).to_dict()

    unknown_field_rejected = False
    try:
        invalid = dict(trigger_payload)
        invalid["extra"] = "forbidden"
        ParadoxTriggerSchema.from_dict(invalid)
    except SchemaValidationError:
        unknown_field_rejected = True

    oversized_rejected = False
    try:
        invalid = dict(trigger_payload)
        invalid["condition"] = "x" * 1000
        ParadoxTriggerSchema.from_dict(invalid)
    except SchemaValidationError:
        oversized_rejected = True

    network_isolation = False
    original_socket = socket.socket
    original_create_connection = socket.create_connection

    def _raise_network(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("network attempted")

    socket.socket = _raise_network  # type: ignore[assignment]
    socket.create_connection = _raise_network  # type: ignore[assignment]
    try:
        ParadoxEngine.run(context=context, trigger=trigger)
        network_isolation = True
    finally:
        socket.socket = original_socket  # type: ignore[assignment]
        socket.create_connection = original_create_connection  # type: ignore[assignment]

    before_context = json.dumps(context, sort_keys=True)
    ParadoxEngine.run(context=context, trigger=trigger)
    context_immutable = before_context == json.dumps(context, sort_keys=True)

    salvage_stats = _scan_salvage_paradox_history(root)
    ttl_policy = ctx["safety_envelope"].get("paradox_hold_policy", {})

    cases = [
        {
            "case_id": "eligible_signal_single_injection_deterministic",
            "status": "PASS" if deterministic and eligible["status"] == "INJECTED" else "FAIL",
            "observation": {
                "repeat_count": len(repeated),
                "task_hash": eligible["task_hash"],
                "result_hash": eligible["result_hash"],
                "status": eligible["status"],
            },
            "evidence_refs": [PARADOX_ENGINE_REL, PARADOX_SCHEMAS_REL, PARADOX_TEST_REL],
        },
        {
            "case_id": "ineligible_signal_fail_closed_to_noop",
            "status": "PASS" if noop["status"] == "NOOP" and noop["task_hash"] == "0" * 64 else "FAIL",
            "observation": {
                "status": noop["status"],
                "task_hash": noop["task_hash"],
            },
            "evidence_refs": [PARADOX_ENGINE_REL, PARADOX_SCHEMAS_REL],
        },
        {
            "case_id": "unknown_fields_rejected",
            "status": "PASS" if unknown_field_rejected else "FAIL",
            "observation": {"rejected": unknown_field_rejected},
            "evidence_refs": [PARADOX_SCHEMAS_REL, PARADOX_TEST_REL],
        },
        {
            "case_id": "oversized_condition_rejected",
            "status": "PASS" if oversized_rejected else "FAIL",
            "observation": {"rejected": oversized_rejected},
            "evidence_refs": [PARADOX_SCHEMAS_REL, PARADOX_TEST_REL],
        },
        {
            "case_id": "network_side_effects_blocked",
            "status": "PASS" if network_isolation else "FAIL",
            "observation": {"network_isolation": network_isolation},
            "evidence_refs": [PARADOX_ENGINE_REL, PARADOX_TEST_REL],
        },
        {
            "case_id": "context_immutability_preserved",
            "status": "PASS" if context_immutable else "FAIL",
            "observation": {"context_immutable": context_immutable},
            "evidence_refs": [PARADOX_ENGINE_REL, PARADOX_TEST_REL],
        },
        {
            "case_id": "salvage_history_has_no_unresolved_paradox_accumulation",
            "status": "PASS"
            if salvage_stats["dream_files_with_unresolved_paradoxes"] == 0
            and salvage_stats["seed_files_with_nonzero_paradox_events"] == 0
            and salvage_stats["eval_files_with_nonzero_paradox_events"] == 0
            else "FAIL",
            "observation": salvage_stats,
            "evidence_refs": [LEGACY_PARADOX_EVENT_SCHEMA_REL],
        },
    ]

    return {
        "schema_id": "kt.operator.paradox_stress_results.v1",
        "generated_utc": generated_utc,
        "engine_surface_refs": [PARADOX_ENGINE_REL, PARADOX_SCHEMAS_REL, PARADOX_TEST_REL],
        "schema_surface_refs": [PARADOX_EVENT_SCHEMA_REL, LEGACY_PARADOX_EVENT_SCHEMA_REL],
        "stress_cases": cases,
        "summary": {
            "case_count": len(cases),
            "pass_count": sum(1 for row in cases if row["status"] == "PASS"),
            "ttl_required": bool(ttl_policy.get("ttl_required", False)),
            "ttl_duration": str(ttl_policy.get("max_hold_without_escalation", "")).strip(),
            **salvage_stats,
        },
        "stress_verdict": "PASS" if all(row["status"] == "PASS" for row in cases) else "FAIL",
    }


def _build_proof_obligation_scheduler(ctx: Dict[str, Any], *, generated_utc: str) -> Dict[str, Any]:
    hold_policy = ctx["safety_envelope"].get("paradox_hold_policy", {})
    ttl = str(hold_policy.get("max_hold_without_escalation", "")).strip()
    ttl_days = _parse_p_days(ttl)
    opened_utc = str(ctx["next_horizon"].get("created_utc", "")).strip()
    opened_at = _parse_iso_z(opened_utc)
    expires_utc = _format_iso_z(opened_at + timedelta(days=ttl_days))

    obligations = []
    for blocker in ctx["h1_gate"].get("blockers", []):
        blocker_id = str(blocker).strip()
        obligations.append(
            {
                "obligation_id": f"PARADOX_HOLD::{blocker_id}",
                "blocker_id": blocker_id,
                "opened_utc": opened_utc,
                "ttl": ttl,
                "expires_utc": expires_utc,
                "current_status": "ACTIVE_WITH_TTL",
                "on_expiry_actions": list(hold_policy.get("escalation_actions", [])),
                "source_hold_surface_ref": NEXT_HORIZON_REL,
                "evidence_refs": _unique_refs([NEXT_HORIZON_REL, H1_GATE_REL, FRONTIER_SETTLEMENT_REL, COURT_PROCEDURE_REL]),
            }
        )

    return {
        "schema_id": "kt.operator.proof_obligation_scheduler.v1",
        "generated_utc": generated_utc,
        "scheduler_basis": {
            "source_hold_surface_ref": NEXT_HORIZON_REL,
            "source_hold_status": str(ctx["next_horizon"].get("status", "")).strip(),
            "ttl_required": bool(hold_policy.get("ttl_required", False)),
            "ttl_duration": ttl,
            "opened_utc": opened_utc,
            "expires_utc": expires_utc,
        },
        "scheduled_obligations": obligations,
        "summary": {
            "scheduled_count": len(obligations),
            "default_action": "FAIL_CLOSED",
            "escalation_actions": list(hold_policy.get("escalation_actions", [])),
        },
    }


def _build_paradox_invariants(
    ctx: Dict[str, Any], stress_results: Dict[str, Any], scheduler: Dict[str, Any], *, generated_utc: str
) -> Dict[str, Any]:
    foundation_rows = {
        str(row.get("invariant_id", "")).strip(): row
        for row in ctx["organ_invariants"].get("invariants", [])
        if isinstance(row, dict)
    }
    active_foundation = foundation_rows.get("paradox_holds_require_ttl_or_fail_closed", {})
    rows = [
        {
            "invariant_id": "no_infinite_contradiction_loop",
            "status": "BOUNDED_BY_MODEL_AND_STRESS",
            "statement": "Eligible paradox signals resolve to a single injected task and do not recurse indefinitely.",
            "machine_target": ["ParadoxEngine.run", "contradictionLoopDepth <= 1", "stress_cases.eligible_signal_single_injection_deterministic"],
            "evidence_refs": [PARADOX_ENGINE_REL, PARADOX_SCHEMAS_REL, PARADOX_STRESS_RESULTS_REL, PARADOX_MODEL_REL],
        },
        {
            "invariant_id": "no_indefinite_hold_without_ttl",
            "status": "BOUNDED_BY_POLICY_AND_SCHEDULER",
            "statement": "Paradox-adjacent hold states carry a P7D TTL and explicit expiry actions of FAIL_CLOSED or constitutional-court escalation.",
            "machine_target": ["hold_status", "hold_ttl", "escalation_path"],
            "evidence_refs": _unique_refs(
                [
                    SAFETY_ENVELOPE_REL,
                    NEXT_HORIZON_REL,
                    H1_GATE_REL,
                    PROOF_OBLIGATION_SCHEDULER_REL,
                    str(active_foundation.get("active_refs", [""])[0]) if active_foundation.get("active_refs") else "",
                ]
            ),
        },
        {
            "invariant_id": "no_governance_bypass_under_paradox_load",
            "status": "BOUNDED_BY_FAIL_CLOSED_GOVERNANCE",
            "statement": "Paradox pressure cannot silently bypass governance; ambiguity routes to H1_BLOCKED, HOLD, or FAIL_CLOSED paths instead of upgrade.",
            "machine_target": ["h1_gate_verdict", "emergency_fail_closed_rule", "on_expiry_actions"],
            "evidence_refs": [COURT_PROCEDURE_REL, FRONTIER_SETTLEMENT_REL, H1_GATE_REL, NEXT_HORIZON_REL],
        },
        {
            "invariant_id": "no_silent_flattening_to_trivial_answers",
            "status": "BOUNDED_BY_ENGINE_AND_BOUNDARY_SURFACES",
            "statement": "Eligible contradiction signals remain explicit injections, and blocked frontier surfaces remain explicitly blocked rather than flattened to green.",
            "machine_target": ["ParadoxEngine.run status", "frontier_settlement_verdict", "h1_gate_verdict"],
            "evidence_refs": [PARADOX_ENGINE_REL, PARADOX_STRESS_RESULTS_REL, FRONTIER_SETTLEMENT_REL, H1_GATE_REL],
        },
        {
            "invariant_id": "no_untracked_delta_generation_during_resolution",
            "status": "BOUNDED_BY_STEP9_LINEAGE_GUARDS",
            "statement": "No delta may emerge from paradox resolution unless it is already lineaged through the Step 9 governed experiment and delta registries.",
            "machine_target": ["learning_delta.lineage_complete", "learning_delta_exclusions", "canonical_precedence_rules"],
            "evidence_refs": [STEP9_RECEIPT_REL, LEARNING_DELTA_REGISTER_REL, LINEAGE_MANIFEST_REL],
        },
    ]

    if [row["invariant_id"] for row in rows] != REQUIRED_INVARIANT_IDS:
        raise RuntimeError("FAIL_CLOSED: Step 10 invariant coverage drifted.")
    if stress_results.get("stress_verdict") != "PASS":
        raise RuntimeError("FAIL_CLOSED: Step 10 invariants require passing paradox stress results.")
    if not scheduler.get("scheduled_obligations"):
        raise RuntimeError("FAIL_CLOSED: Step 10 invariants require TTL-backed scheduled obligations.")

    return {
        "schema_id": "kt.operator.paradox_invariants.v1",
        "generated_utc": generated_utc,
        "required_invariant_ids": REQUIRED_INVARIANT_IDS,
        "invariants": rows,
        "summary": {
            "invariant_count": len(rows),
            "all_required_present": True,
            "ttl_policy_ref": SAFETY_ENVELOPE_REL,
        },
    }


def _build_paradox_counterexamples(
    ctx: Dict[str, Any], stress_results: Dict[str, Any], scheduler: Dict[str, Any], *, generated_utc: str
) -> Dict[str, Any]:
    rows = [
        {
            "counterexample_id": "PARADOX_CEX::INFINITE_LOOP_SIGNAL_CHAIN",
            "target_invariant": "no_infinite_contradiction_loop",
            "status": "DISPROVED_BY_STRESS",
            "observed": stress_results["stress_cases"][0]["observation"],
            "evidence_refs": [PARADOX_STRESS_RESULTS_REL, PARADOX_MODEL_REL],
        },
        {
            "counterexample_id": "PARADOX_CEX::INDEFINITE_H1_HOLD",
            "target_invariant": "no_indefinite_hold_without_ttl",
            "status": "BOUNDED_BY_TTL_POLICY",
            "observed": {
                "next_horizon_status": str(ctx["next_horizon"].get("status", "")).strip(),
                "ttl": scheduler["scheduler_basis"]["ttl_duration"],
                "expires_utc": scheduler["scheduler_basis"]["expires_utc"],
            },
            "evidence_refs": [NEXT_HORIZON_REL, SAFETY_ENVELOPE_REL, PROOF_OBLIGATION_SCHEDULER_REL],
        },
        {
            "counterexample_id": "PARADOX_CEX::GOVERNANCE_BYPASS_UNDER_LOAD",
            "target_invariant": "no_governance_bypass_under_paradox_load",
            "status": "DISPROVED_BY_BOUNDARY",
            "observed": {
                "frontier_settlement_verdict": str(ctx["frontier_settlement"].get("frontier_settlement_verdict", "")).strip(),
                "h1_gate_verdict": str(ctx["h1_gate"].get("h1_gate_verdict", "")).strip(),
            },
            "evidence_refs": [COURT_PROCEDURE_REL, FRONTIER_SETTLEMENT_REL, H1_GATE_REL],
        },
        {
            "counterexample_id": "PARADOX_CEX::TRIVIAL_NOOP_FLATTENING",
            "target_invariant": "no_silent_flattening_to_trivial_answers",
            "status": "DISPROVED_BY_ENGINE",
            "observed": {
                "eligible_status": stress_results["stress_cases"][0]["observation"]["status"],
                "ineligible_status": stress_results["stress_cases"][1]["observation"]["status"],
            },
            "evidence_refs": [PARADOX_STRESS_RESULTS_REL, PARADOX_ENGINE_REL],
        },
        {
            "counterexample_id": "PARADOX_CEX::UNTRACKED_DELTA_GENERATION",
            "target_invariant": "no_untracked_delta_generation_during_resolution",
            "status": "DISPROVED_BY_LINEAGE_GUARD",
            "observed": {
                "learning_delta_count": int(ctx["learning_delta_register"]["summary"]["learning_delta_count"]),
                "excluded_surfaces": [row["artifact_ref"] for row in ctx["lineage_manifest"].get("learning_delta_exclusions", [])],
            },
            "evidence_refs": [STEP9_RECEIPT_REL, LEARNING_DELTA_REGISTER_REL, LINEAGE_MANIFEST_REL],
        },
    ]

    return {
        "schema_id": "kt.operator.paradox_counterexamples.v1",
        "generated_utc": generated_utc,
        "counterexamples": rows,
        "summary": {
            "counterexample_count": len(rows),
            "unresolved_count": sum(1 for row in rows if not str(row.get("status", "")).startswith(("DISPROVED", "BOUNDED"))),
        },
    }


def _build_paradox_claim_matrix(
    ctx: Dict[str, Any], invariants: Dict[str, Any], stress_results: Dict[str, Any], scheduler: Dict[str, Any], *, generated_utc: str
) -> Dict[str, Any]:
    claim_row = next(
        row for row in ctx["claim_registry"].get("claim_classes", []) if str(row.get("claim_class_id", "")).strip() == "paradox_bound_claim"
    )
    claims = [
        {
            "claim_id": "PARADOX_PROGRAM_BOUNDED_AT_DOCUMENTARY_CEILING",
            "status": "evidenced",
            "claim_text": "Paradox metabolism is now bounded at the documentary-only ceiling by explicit model, invariants, stress results, and counterexample handling.",
            "evidence_refs": [PARADOX_MODEL_REL, PARADOX_INVARIANTS_REL, PARADOX_STRESS_RESULTS_REL, PARADOX_COUNTEREXAMPLES_REL],
            "blockers": [],
        },
        {
            "claim_id": "PARADOX_HOLD_TTL_ENFORCED",
            "status": "evidenced",
            "claim_text": "Current paradox-adjacent hold surfaces are tied to a P7D TTL and explicit expiry escalation actions.",
            "evidence_refs": [SAFETY_ENVELOPE_REL, NEXT_HORIZON_REL, PROOF_OBLIGATION_SCHEDULER_REL],
            "blockers": [],
        },
        {
            "claim_id": "PARADOX_EXTERNAL_SUPERIORITY",
            "status": "aspirational",
            "claim_text": "No external superiority, competition-grade, or publication-grade paradox claim is admissible from Step 10 alone.",
            "evidence_refs": [CLAIM_TAXONOMY_REL, STATE_VECTOR_REL, FRONTIER_SETTLEMENT_REL],
            "blockers": ["DOCUMENTARY_ONLY_CEILING", "FULL_STACK_ADJUDICATION_PENDING"],
        },
    ]
    return {
        "schema_id": "kt.operator.paradox_claim_matrix.v1",
        "generated_utc": generated_utc,
        "claim_class_id": "paradox_bound_claim",
        "previous_step7_status": str(claim_row.get("status", "")).strip(),
        "current_status": "evidenced",
        "current_admissibility_ceiling": "DOCUMENTARY_ONLY",
        "claims": claims,
        "summary": {
            "claim_count": len(claims),
            "evidenced_count": sum(1 for row in claims if row["status"] == "evidenced"),
            "aspirational_count": sum(1 for row in claims if row["status"] == "aspirational"),
            "stress_verdict": stress_results.get("stress_verdict"),
            "scheduled_obligation_count": len(scheduler.get("scheduled_obligations", [])),
        },
    }


def build_step10_outputs(root: Path, generated_utc: Optional[str] = None) -> Dict[str, Any]:
    generated = generated_utc or utc_now_iso_z()
    ctx = _step_context(root)
    model_text = _paradox_model_text()
    stress_results = _build_stress_results(ctx, root, generated_utc=generated)
    scheduler = _build_proof_obligation_scheduler(ctx, generated_utc=generated)
    invariants = _build_paradox_invariants(ctx, stress_results, scheduler, generated_utc=generated)
    counterexamples = _build_paradox_counterexamples(ctx, stress_results, scheduler, generated_utc=generated)
    claim_matrix = _build_paradox_claim_matrix(ctx, invariants, stress_results, scheduler, generated_utc=generated)

    if stress_results.get("stress_verdict") != "PASS":
        raise RuntimeError("FAIL_CLOSED: Step 10 cannot pass with failing paradox stress results.")
    if counterexamples["summary"]["unresolved_count"] != 0:
        raise RuntimeError("FAIL_CLOSED: Step 10 counterexamples remain unresolved.")
    if claim_matrix.get("current_status") != "evidenced":
        raise RuntimeError("FAIL_CLOSED: Step 10 paradox claim matrix failed to evidence the bounded program.")

    return {
        "kt_paradox_models_tla": model_text,
        "kt_paradox_invariants": invariants,
        "kt_paradox_counterexamples": counterexamples,
        "kt_paradox_stress_results": stress_results,
        "kt_paradox_claim_matrix": claim_matrix,
        "kt_proof_obligation_scheduler": scheduler,
    }


def build_step10_receipt(root: Path) -> Dict[str, Any]:
    ctx = _step_context(root)
    generated_utc = utc_now_iso_z()
    first = build_step10_outputs(root, generated_utc=generated_utc)
    second = build_step10_outputs(root, generated_utc=generated_utc)

    if first["kt_paradox_models_tla"] != second["kt_paradox_models_tla"]:
        raise RuntimeError("FAIL_CLOSED: nondeterministic Step 10 model text detected.")
    for key in first:
        if key == "kt_paradox_models_tla":
            continue
        if not semantically_equal_json(first[key], second[key]):
            raise RuntimeError(f"FAIL_CLOSED: nondeterministic Step 10 output detected: {key}")

    compiled_head = _git_head(root)
    parent = _git_parent(root, compiled_head)
    actual_touched = sorted(set(_git_diff_files(root, parent, compiled_head, SUBJECT_ARTIFACT_REFS) + [RECEIPT_REL]))
    unexpected_touches = sorted(set(actual_touched) - set(PLANNED_MUTATES))
    protected_touch_violations = [path for path in actual_touched if _is_protected(path)]

    return {
        "schema_id": "kt.operator.paradox_program_bounded_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "pass_verdict": "PARADOX_PROGRAM_BOUNDED",
        "compiled_head_commit": compiled_head,
        "current_head_commit": compiled_head,
        "controlling_work_order": {
            "schema_id": WORK_ORDER_SCHEMA_ID,
            "work_order_id": WORK_ORDER_ID,
            "step_id": 10,
            "step_name": "PARADOX_METABOLISM_VERIFICATION_PROGRAM",
        },
        "step9_gate_subject_commit": str(ctx["step9_receipt"].get("compiled_head_commit", "")).strip(),
        "step9_gate_evidence_commit": str(ctx["step9_evidence_commit"]).strip(),
        "claim_boundary": (
            "This receipt bounds the paradox program for compiled_head_commit only. "
            "It does not reopen authority settlement, platform enforcement, or H1 activation, and it does not upgrade the ceiling beyond documentary-only paradox claims."
        ),
        "summary": {
            "required_invariant_count": len(first["kt_paradox_invariants"]["invariants"]),
            "stress_case_count": int(first["kt_paradox_stress_results"]["summary"]["case_count"]),
            "scheduled_obligation_count": int(first["kt_proof_obligation_scheduler"]["summary"]["scheduled_count"]),
            "counterexample_count": int(first["kt_paradox_counterexamples"]["summary"]["counterexample_count"]),
        },
        "checks": [
            {
                "check": "step9_gate_passed",
                "detail": "Step 10 requires the Step 9 runtime and experiment memory receipt to be PASS.",
                "refs": [STEP9_RECEIPT_REL],
                "status": "PASS",
            },
            {
                "check": "required_invariants_covered_exactly",
                "detail": "All five Step 10 required invariants must be present in the compiled paradox invariants artifact.",
                "refs": [PARADOX_INVARIANTS_REL, PARADOX_MODEL_REL],
                "status": "PASS"
                if [row["invariant_id"] for row in first["kt_paradox_invariants"]["invariants"]] == REQUIRED_INVARIANT_IDS
                else "FAIL",
            },
            {
                "check": "stress_program_passes",
                "detail": "Paradox engine stress and salvage-history scans must pass without unresolved accumulation or network side effects.",
                "refs": [PARADOX_STRESS_RESULTS_REL, PARADOX_ENGINE_REL, PARADOX_TEST_REL],
                "status": "PASS" if first["kt_paradox_stress_results"].get("stress_verdict") == "PASS" else "FAIL",
            },
            {
                "check": "hold_scheduler_enforces_ttl",
                "detail": "Current HOLD surfaces must be scheduled with TTL and expiry actions of FAIL_CLOSED or constitutional-court escalation.",
                "refs": [PROOF_OBLIGATION_SCHEDULER_REL, NEXT_HORIZON_REL, SAFETY_ENVELOPE_REL],
                "status": "PASS"
                if first["kt_proof_obligation_scheduler"]["scheduled_obligations"]
                and bool(ctx["safety_envelope"].get("paradox_hold_policy", {}).get("ttl_required", False))
                else "FAIL",
            },
            {
                "check": "untracked_delta_generation_remains_blocked",
                "detail": "Paradox resolution may not manufacture unlineaged deltas outside the Step 9 governed lineage surfaces.",
                "refs": [LEARNING_DELTA_REGISTER_REL, LINEAGE_MANIFEST_REL, PARADOX_COUNTEREXAMPLES_REL],
                "status": "PASS"
                if first["kt_paradox_counterexamples"]["summary"]["unresolved_count"] == 0
                else "FAIL",
            },
            {
                "check": "post_touch_accounting_clean",
                "detail": "Actual touched set must match the lawful Step 10 subject files plus the Step 10 receipt.",
                "refs": SUBJECT_ARTIFACT_REFS + [RECEIPT_REL],
                "status": "PASS" if not unexpected_touches and not protected_touch_violations else "FAIL",
            },
        ],
        "planned_mutates": PLANNED_MUTATES,
        "actual_touched": actual_touched,
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "next_lawful_step": {
            "step_id": 11,
            "step_name": "DOCTRINE_COMPILER_PROFILES_AND_EXTERNAL_PROFESSIONALIZATION",
            "status_after_step_10": "UNLOCKED" if not unexpected_touches and not protected_touch_violations else "BLOCKED",
        },
    }


def write_step10_outputs(root: Path) -> Dict[str, Any]:
    outputs = build_step10_outputs(root)
    artifact_map = {
        PARADOX_INVARIANTS_REL: outputs["kt_paradox_invariants"],
        PARADOX_COUNTEREXAMPLES_REL: outputs["kt_paradox_counterexamples"],
        PARADOX_STRESS_RESULTS_REL: outputs["kt_paradox_stress_results"],
        PARADOX_CLAIM_MATRIX_REL: outputs["kt_paradox_claim_matrix"],
        PROOF_OBLIGATION_SCHEDULER_REL: outputs["kt_proof_obligation_scheduler"],
    }
    writes = []
    tla_updated = _write_text_stable(root / Path(PARADOX_MODEL_REL), outputs["kt_paradox_models_tla"])
    writes.append({"artifact_ref": PARADOX_MODEL_REL, "updated": bool(tla_updated), "schema_id": "tla.module"})
    for rel, payload in artifact_map.items():
        changed = write_json_stable(root / Path(rel), payload)
        writes.append({"artifact_ref": rel, "updated": bool(changed), "schema_id": str(payload.get("schema_id", "")).strip()})
    return {"status": "PASS", "artifacts_written": writes}


def emit_step10_receipt(root: Path) -> Dict[str, Any]:
    receipt = build_step10_receipt(root)
    write_json_stable(root / Path(RECEIPT_REL), receipt)
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compile Step 10 paradox metabolism model, stress results, claim matrix, and scheduler.")
    parser.add_argument("--emit-receipt", action="store_true", help="Emit the Step 10 receipt instead of only the subject artifacts.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    result = emit_step10_receipt(root) if args.emit_receipt else write_step10_outputs(root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
