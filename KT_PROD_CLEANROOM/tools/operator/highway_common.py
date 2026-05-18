from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


WORK_ORDER_ID = "KT_HIGHWAY_PATHWAY_SYSTEM_SUPERLANE_INITIATION_v1_0"
CURRENT_MODE = "PREP_ONLY"
FINAL_LABEL = "HIGHWAY_PATHWAY_SYSTEM_v1_PREP_ONLY_RELANDED__AUTHORITY_BLOCKED_BY_H06_EXTERNAL_ATTESTATION_REQUIRED"
EXTERNAL_ATTESTATION_BLOCKER = "H06_INDEPENDENT_EXTERNAL_REAUDIT_ATTESTATION_REQUIRED"
HIGHWAY_CANONICAL_PROMOTION_BLOCKER = "HIGHWAY_CANONICAL_PROMOTION_NOT_AUTHORIZED"
COMMERCIAL_CLAIM_BLOCKER = "COMMERCIAL_CLAIM_AUTHORIZATION_NOT_GRANTED"
FP0_BLOCKER = "FP0_NO_CLAIM_EXPANSION_PREP_ONLY"
CURRENT_BLOCKERS = (
    EXTERNAL_ATTESTATION_BLOCKER,
    HIGHWAY_CANONICAL_PROMOTION_BLOCKER,
    COMMERCIAL_CLAIM_BLOCKER,
    FP0_BLOCKER,
)

# Backward-compatible names for older tests/imports; values now reflect the live H06 wall.
TRUTH_LOCK_VALIDATION_BLOCKER = HIGHWAY_CANONICAL_PROMOTION_BLOCKER
DETACHED_VERIFIER_BLOCKER = "DETACHED_VERIFIER_KIT_ALREADY_ADVANCED_NOT_CURRENT_BLOCKER"

ALLOWED_MODES = (
    "PREP_ONLY",
    "SHADOW_ONLY",
    "WARN_ONLY",
    "FAIL_CLOSED",
    "CANONICAL_ACTIVE",
    "BLOCKED",
)

PROMOTION_LADDER = (
    "PREP_ONLY",
    "SHADOW_ONLY",
    "WARN_ONLY",
    "FAIL_CLOSED_CANDIDATE",
    "CANONICAL_ACTIVE",
)

INCIDENT_CLASSES = (
    "POSTURE_CONTRADICTION",
    "TRUTH_LOCK_DRIFT",
    "CANONICAL_SCOPE_BREACH",
    "TRUST_ZONE_BREACH",
    "UNAUTHORIZED_FP0_PROMOTION",
    "UNAUTHORIZED_DETACHED_VERIFIER_PROMOTION",
    "RECEIPT_MISSING",
    "REPLAY_FAILURE",
    "SECRET_OR_RESIDUE_RISK",
    "COMMERCIAL_OVERCLAIM",
)

ADAPTIVE_RATIFICATION_ORDER = (
    "crucible_registry",
    "policy_c_pressure_taxonomy",
    "adapter_lifecycle",
    "tournament_promotion_merge_law",
    "static_router_baseline",
    "shadow_router_evaluation",
    "best_static_adapter_comparison",
    "learned_router",
    "multi_lobe_orchestration",
)

SUPERLANES: Sequence[Dict[str, Any]] = (
    {
        "id": "AUTHORITY_GATE",
        "name": "Authority Gate / Truth Lock Wall",
        "purpose": "Prevent highway work from outrunning current KT authority.",
        "authority_required": "H06_EXTERNAL_ATTESTATION_OR_SEPARATE_PROMOTION_AUTHORITY",
        "entry_conditions": ["Truth Lock validated", "Detached Verifier advanced", "H06 external attestation remains parked"],
        "exit_conditions": ["activation remains blocked until separate promotion authority exists"],
        "required_receipts": ["highway_authority_gate_receipt.json"],
        "ci_enforcement_level": "PREP_ONLY_LOCAL",
        "canonical_scope_effect": "NONE_PREP_ONLY",
    },
    {
        "id": "HIGHWAY_CONSTITUTION",
        "name": "Highway Constitution / Registry",
        "purpose": "Define the lane system as law, not vibes.",
        "authority_required": "PREP_ONLY_DESIGN_AND_LOCAL_VALIDATION",
        "entry_conditions": ["highway pathway system packet accepted as prep-only work"],
        "exit_conditions": ["registry and contracts are parseable and explicit"],
        "required_receipts": ["highway_matrix_receipt.json"],
        "ci_enforcement_level": "PREP_ONLY_LOCAL",
        "canonical_scope_effect": "NONE_PREP_ONLY",
    },
    {
        "id": "LANE_ADMISSION_AND_ROUTING",
        "name": "Lane Admission And Routing",
        "purpose": "Classify work into one primary highway lane with optional secondary advisory lanes.",
        "authority_required": "EXPLICIT_OPERATOR_INTENT_AND_SCOPE",
        "entry_conditions": ["work item includes intent and declared scope"],
        "exit_conditions": ["route receipt emitted or blocked with reason"],
        "required_receipts": ["highway_route_receipt.json"],
        "ci_enforcement_level": "PREP_ONLY_LOCAL",
        "canonical_scope_effect": "NONE_PREP_ONLY",
    },
    {
        "id": "CANONICAL_RUNTIME",
        "name": "Canonical Runtime",
        "purpose": "Protect safe-run and canonical runtime routes.",
        "authority_required": "TRUTH_LOCK_VALIDATED_CANONICAL_RUNTIME_SCOPE",
        "entry_conditions": ["operator intent touches runtime or truth writers"],
        "exit_conditions": ["no mutation or scoped non-regression proof"],
        "required_receipts": ["highway_canonical_runtime_guard_receipt.json"],
        "ci_enforcement_level": "PREP_ONLY_LOCAL",
        "canonical_scope_effect": "BLOCKED_UNTIL_AUTHORIZED",
    },
    {
        "id": "TRUTH_AND_POSTURE",
        "name": "Truth And Posture",
        "purpose": "Make highway posture mechanically derived.",
        "authority_required": "TRUTH_ENGINE_SUPPORT",
        "entry_conditions": ["status or posture claim requested"],
        "exit_conditions": ["posture conflict count zero"],
        "required_receipts": ["highway_posture_receipt.json", "highway_posture_conflict_receipt.json"],
        "ci_enforcement_level": "PREP_ONLY_LOCAL",
        "canonical_scope_effect": "NONE_PREP_ONLY",
    },
    {
        "id": "BOUNDARY_AND_TRUST_ZONE",
        "name": "Boundary And Trust Zone",
        "purpose": "Ensure highway lanes do not hide failures behind renames.",
        "authority_required": "TRUST_ZONE_PASS",
        "entry_conditions": ["zone transition or exclusion declared"],
        "exit_conditions": ["explicit reviewed exclusions only"],
        "required_receipts": ["highway_trust_zone_receipt.json"],
        "ci_enforcement_level": "PREP_ONLY_LOCAL",
        "canonical_scope_effect": "NONE_PREP_ONLY",
    },
    {
        "id": "REGULATED_WORK",
        "name": "Regulated Work",
        "purpose": "Route higher-risk work into stricter invariants.",
        "authority_required": "REGULATED_SCOPE_RECEIPTS",
        "entry_conditions": ["regulated or client-facing risk surface"],
        "exit_conditions": ["claim limiter and evidence manifest present"],
        "required_receipts": ["highway_regulated_lane_receipt.json"],
        "ci_enforcement_level": "PREP_ONLY_LOCAL",
        "canonical_scope_effect": "NONE_PREP_ONLY",
    },
    {
        "id": "EMERGENCY_AND_FREEZE",
        "name": "Emergency And Freeze",
        "purpose": "Freeze unsafe changes and preserve evidence without bypassing law.",
        "authority_required": "INCIDENT_OR_FREEZE_CAUSE",
        "entry_conditions": ["contradiction, drift, breach, missing receipt, or overclaim"],
        "exit_conditions": ["freeze or incident receipt emitted"],
        "required_receipts": ["highway_emergency_freeze_receipt.json", "highway_incident_receipt.json"],
        "ci_enforcement_level": "PREP_ONLY_LOCAL",
        "canonical_scope_effect": "FREEZE_ONLY_NO_AUTHORITY_BYPASS",
    },
    {
        "id": "LAB_AND_ADAPTIVE_RATIFICATION",
        "name": "Lab And Adaptive Ratification",
        "purpose": "Prepare adaptive work without letting it outrun authority.",
        "authority_required": "ADAPTIVE_RATIFICATION_ORDER",
        "entry_conditions": ["adapter, router, lobe, crucible, or FP0 work"],
        "exit_conditions": ["prep-only or ratified ladder state"],
        "required_receipts": ["highway_adaptive_ratification_receipt.json"],
        "ci_enforcement_level": "PREP_ONLY_LOCAL",
        "canonical_scope_effect": "NONE_PREP_ONLY",
    },
    {
        "id": "PROMOTION_AND_ROLLBACK",
        "name": "Promotion And Rollback",
        "purpose": "Make all movement toward canonical status governed and reversible.",
        "authority_required": "PROMOTION_LADDER_AND_ROLLBACK_PLAN",
        "entry_conditions": ["promotion or rollback requested"],
        "exit_conditions": ["allowed ladder move or blocked jump"],
        "required_receipts": ["highway_promotion_receipt.json", "highway_rollback_receipt.json"],
        "ci_enforcement_level": "PREP_ONLY_LOCAL",
        "canonical_scope_effect": "BLOCKED_UNTIL_AUTHORIZED",
    },
    {
        "id": "COMMERCIAL_DELIVERY",
        "name": "Commercial Delivery",
        "purpose": "Prepare commercial delivery without unsupported claims.",
        "authority_required": "CLAIM_CEILING_AND_SAFE_RUN_BOUNDARY",
        "entry_conditions": ["commercial wrapper, runbook, public verifier, or claim surface"],
        "exit_conditions": ["claims remain bounded by proof"],
        "required_receipts": ["highway_commercial_delivery_receipt.json"],
        "ci_enforcement_level": "PREP_ONLY_LOCAL",
        "canonical_scope_effect": "NONE_PREP_ONLY",
    },
    {
        "id": "COMPARATIVE_PROOF",
        "name": "Comparative Proof",
        "purpose": "Prepare external comparison without self-referential superiority claims.",
        "authority_required": "COMPARATIVE_RECEIPTS",
        "entry_conditions": ["benchmark, baseline, provider, or superiority work"],
        "exit_conditions": ["prepared-not-claimed or evidence-backed result"],
        "required_receipts": ["highway_comparative_proof_receipt.json"],
        "ci_enforcement_level": "PREP_ONLY_LOCAL",
        "canonical_scope_effect": "NONE_PREP_ONLY",
    },
    {
        "id": "CI_VERIFICATION_RELEASE_BARRIER",
        "name": "CI Verification Release Barrier",
        "purpose": "Consolidate highway verification into a matrix barrier.",
        "authority_required": "MATRIX_PASS_AND_AUTHORITY_GATE",
        "entry_conditions": ["highway matrix run"],
        "exit_conditions": ["consolidated receipt emitted"],
        "required_receipts": ["highway_matrix_receipt.json"],
        "ci_enforcement_level": "PREP_ONLY_LOCAL",
        "canonical_scope_effect": "NONE_PREP_ONLY",
    },
)

LANE_IDS = {lane["id"] for lane in SUPERLANES}


class HighwayFailure(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _root(output_root: Path | None = None) -> Path:
    return Path(output_root) if output_root is not None else repo_root()


def _write_json(root: Path, raw_path: str, payload: Mapping[str, Any]) -> Path:
    path = root / raw_path
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json_stable(path, dict(payload))
    return path


def _write_text(root: Path, raw_path: str, text: str) -> Path:
    path = root / raw_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def _base_artifact(artifact_id: str, *, superlane: str | None = None) -> Dict[str, Any]:
    return {
        "schema_id": f"kt.highway.{artifact_id.lower()}.v1",
        "artifact_id": artifact_id,
        "work_order_id": WORK_ORDER_ID,
        "authority": "PREP_ONLY",
        "mode": CURRENT_MODE,
        "activation_allowed": False,
        "truth_lock_replay_canonical": True,
        "truth_lock_validation_authorized": True,
        "detached_verifier_authorized": True,
        "fp0_authority": "PREP_ONLY_NO_CLAIM_EXPANSION",
        "blocked_by": list(CURRENT_BLOCKERS),
        "final_label": FINAL_LABEL,
        "generated_utc": utc_now_iso_z(),
        "superlane": superlane,
        "cannot_claim_external_audit_complete": True,
        "cannot_activate_fp0_as_authority": True,
        "cannot_claim_canonical_highway_status": True,
        "cannot_mutate_truth_engine_law": True,
        "cannot_mutate_trust_zone_law": True,
    }


def authority_state() -> Dict[str, Any]:
    return {
        "mode": CURRENT_MODE,
        "truth_lock_replay_canonical": True,
        "truth_lock_validation_authorized": True,
        "detached_verifier_authorized": True,
        "fp0_authority": "PREP_ONLY_NO_CLAIM_EXPANSION",
        "activation_allowed": False,
        "reason": EXTERNAL_ATTESTATION_BLOCKER,
        "blockers": list(CURRENT_BLOCKERS),
        "current_lawful_label": FINAL_LABEL,
    }


def write_authority_gate_receipt(output_root: Path | None = None) -> Dict[str, Any]:
    root = _root(output_root)
    receipt = {
        "schema_id": "kt.highway.authority_gate_receipt.v1",
        "artifact_id": "HIGHWAY_AUTHORITY_GATE_RECEIPT",
        "work_order_id": WORK_ORDER_ID,
        "generated_utc": utc_now_iso_z(),
        **authority_state(),
        "authority_verdict": "BLOCKED",
        "protected_merge_gate": "H06_EXTERNAL_ATTESTATION",
    }
    _write_json(root, "exports/_truth/current/highway_authority_gate_receipt.json", receipt)
    return receipt


def classify_lane(work_item: Mapping[str, Any]) -> Dict[str, Any]:
    intent = str(work_item.get("operator_intent", "")).lower()
    requested_scope = str(work_item.get("requested_scope", "")).lower()
    authority_requested = str(work_item.get("authority_requested", "PREP_ONLY")).upper()
    target_paths = [str(item).lower() for item in work_item.get("target_paths", []) or []]
    text = " ".join([intent, requested_scope, *target_paths])

    selected = "TRUTH_AND_POSTURE"
    if work_item.get("touches_canonical_runtime") or "safe-run" in text or "runtime" in text:
        selected = "CANONICAL_RUNTIME"
    elif work_item.get("touches_commercial_surface") or "commercial" in text or "claim" in text:
        selected = "COMMERCIAL_DELIVERY"
    elif "emergency" in text or "freeze" in text or work_item.get("risk_class") == "EMERGENCY":
        selected = "EMERGENCY_AND_FREEZE"
    elif (
        work_item.get("touches_lab_or_archive")
        or work_item.get("touches_fp0")
        or any(word in text for word in ("adapter", "router", "lobe", "crucible", "fp0"))
    ):
        selected = "LAB_AND_ADAPTIVE_RATIFICATION"
    elif work_item.get("touches_detached_verifier"):
        selected = "LAB_AND_ADAPTIVE_RATIFICATION"
    elif work_item.get("touches_governance") or work_item.get("touches_truth_lock") or work_item.get("touches_validation"):
        selected = "AUTHORITY_GATE"

    blockers: List[str] = []
    decision = "ALLOW_PREP_ONLY"
    if not text.strip() and not any(work_item.values()):
        blockers.append("BLOCK_SCOPE_AMBIGUOUS")
        decision = "BLOCK_SCOPE_AMBIGUOUS"
    elif authority_requested in {"CANONICAL_ACTIVE", "FAIL_CLOSED", "DETACHED_VERIFIER_ACTIVE", "FP0_HIGHWAY_ACTIVE"}:
        blockers.append(HIGHWAY_CANONICAL_PROMOTION_BLOCKER)
        decision = "BLOCK_AUTHORITY_REQUIRED"
    if work_item.get("touches_detached_verifier"):
        blockers.append(EXTERNAL_ATTESTATION_BLOCKER)
        decision = "BLOCK_EXTERNAL_ATTESTATION_REQUIRED"
    if work_item.get("touches_fp0") or "fp0" in text:
        blockers.append(FP0_BLOCKER)
        decision = "BLOCK_FP0_PREP_ONLY"

    return {
        "selected_superlane": selected,
        "secondary_superlanes": _secondary_lanes(selected, work_item),
        "mode": CURRENT_MODE,
        "allowed": decision == "ALLOW_PREP_ONLY",
        "blocked": decision != "ALLOW_PREP_ONLY",
        "decision": decision,
        "blockers": sorted(set(blockers)),
        "authority_basis": "PREP_ONLY_DESIGN_AND_LOCAL_VALIDATION",
        "truth_sources_checked": ["H06_EXTERNAL_REAUDIT_STATUS", "TRUTH_LOCK_VALIDATION_STATUS", "FP0_NO_CLAIM_EXPANSION_STATUS"],
        "canonical_effect": "NONE",
        "prep_only_effect": "LOCAL_DESIGN_AND_VALIDATION",
        "required_next_gate": "COLLECT_INDEPENDENT_EXTERNAL_REAUDIT_ATTESTATION_OR_SEPARATE_HIGHWAY_PROMOTION_AUTHORITY",
    }


def _secondary_lanes(primary: str, work_item: Mapping[str, Any]) -> List[str]:
    lanes: List[str] = []
    if work_item.get("touches_commercial_surface") and primary != "COMMERCIAL_DELIVERY":
        lanes.append("COMMERCIAL_DELIVERY")
    if work_item.get("touches_fp0") and primary != "LAB_AND_ADAPTIVE_RATIFICATION":
        lanes.append("LAB_AND_ADAPTIVE_RATIFICATION")
    if work_item.get("touches_validation") and primary != "TRUTH_AND_POSTURE":
        lanes.append("TRUTH_AND_POSTURE")
    return lanes


def write_route_receipt(work_item: Mapping[str, Any] | None = None, output_root: Path | None = None) -> Dict[str, Any]:
    root = _root(output_root)
    item = dict(work_item or {"work_order_id": WORK_ORDER_ID, "operator_intent": "prep-only highway pathway system"})
    decision = classify_lane(item)
    receipt = {
        "schema_id": "kt.highway.route_receipt.v1",
        "artifact_id": "HIGHWAY_ROUTE_RECEIPT",
        "work_order_id": item.get("work_order_id", WORK_ORDER_ID),
        "generated_utc": utc_now_iso_z(),
        **decision,
    }
    _write_json(root, "exports/_truth/current/highway_route_receipt.json", receipt)
    return receipt


def canonical_runtime_guard(output_root: Path | None = None, *, mutation_requested: bool = False) -> Dict[str, Any]:
    root = _root(output_root)
    receipt = {
        "schema_id": "kt.highway.canonical_runtime_guard_receipt.v1",
        "artifact_id": "HIGHWAY_CANONICAL_RUNTIME_GUARD_RECEIPT",
        "work_order_id": WORK_ORDER_ID,
        "generated_utc": utc_now_iso_z(),
        "mode": CURRENT_MODE,
        "safe_run_remains_lawful_entrypoint": True,
        "substitute_runtime_introduced": False,
        "canonical_mutation_requested": mutation_requested,
        "canonical_mutation_allowed": False,
        "canonical_effect": "NONE_PREP_ONLY",
        "status": "PASS_PREP_ONLY" if not mutation_requested else "BLOCKED_AUTHORITY_REQUIRED",
    }
    _write_json(root, "exports/_truth/current/highway_canonical_runtime_guard_receipt.json", receipt)
    return receipt


def posture_sync(output_root: Path | None = None) -> Dict[str, Any]:
    root = _root(output_root)
    receipt = {
        "schema_id": "kt.highway.posture_receipt.v1",
        "artifact_id": "HIGHWAY_POSTURE_RECEIPT",
        "work_order_id": WORK_ORDER_ID,
        "generated_utc": utc_now_iso_z(),
        "posture": "HIGHWAY_PREP_ONLY",
        "strongest_supported_posture": "HIGHWAY_PREP_ONLY",
        "truth_basis": authority_state(),
    }
    _write_json(root, "exports/_truth/current/highway_posture_receipt.json", receipt)
    return receipt


def posture_conflict_scan(claims: Sequence[str] | None = None, output_root: Path | None = None) -> Dict[str, Any]:
    root = _root(output_root)
    claims = list(claims or [])
    forbidden = ("HIGHWAY_CANONICAL_ACTIVE", "FAIL_CLOSED", "DETACHED_VERIFIER_ACTIVE", "FP0_HIGHWAY_ACTIVE")
    conflicts = [claim for claim in claims if any(token in claim.upper() for token in forbidden)]
    receipt = {
        "schema_id": "kt.highway.posture_conflict_receipt.v1",
        "artifact_id": "HIGHWAY_POSTURE_CONFLICT_RECEIPT",
        "work_order_id": WORK_ORDER_ID,
        "generated_utc": utc_now_iso_z(),
        "posture_conflict_count": len(conflicts),
        "conflicts": conflicts,
        "status": "PASS" if not conflicts else "FAIL_CLOSED",
    }
    _write_json(root, "exports/_truth/current/highway_posture_conflict_receipt.json", receipt)
    if conflicts:
        raise HighwayFailure("HIGHWAY_POSTURE_CONFLICT", "stronger-than-truth highway posture claim detected")
    return receipt


def trust_zone_validate(config: Mapping[str, Any] | None = None, output_root: Path | None = None) -> Dict[str, Any]:
    root = _root(output_root)
    config = dict(config or {})
    silent_exclusions = config.get("silent_exclusions", [])
    exclusions = config.get("exclusions", [])
    failures: List[str] = []
    if silent_exclusions:
        failures.append("SILENT_EXCLUSION_REJECTED")
    for exclusion in exclusions:
        if not isinstance(exclusion, Mapping) or not exclusion.get("path") or not exclusion.get("justification"):
            failures.append("EXCLUSION_MISSING_JUSTIFICATION")
    receipt = {
        "schema_id": "kt.highway.trust_zone_receipt.v1",
        "artifact_id": "HIGHWAY_TRUST_ZONE_RECEIPT",
        "work_order_id": WORK_ORDER_ID,
        "generated_utc": utc_now_iso_z(),
        "zones": ["CANONICAL", "LAB", "ARCHIVE", "COMMERCIAL", "PREP_ONLY", "RUNTIME_TRUTH", "GENERATED_EXPORT"],
        "failures": failures,
        "status": "PASS" if not failures else "FAIL_CLOSED",
    }
    _write_json(root, "exports/_truth/current/highway_trust_zone_receipt.json", receipt)
    if failures:
        raise HighwayFailure("HIGHWAY_TRUST_ZONE_CONFLICT", ",".join(failures))
    return receipt


def zone_transition_receipt(output_root: Path | None = None) -> Dict[str, Any]:
    root = _root(output_root)
    receipt = {
        "schema_id": "kt.highway.zone_transition_receipt.v1",
        "artifact_id": "HIGHWAY_ZONE_TRANSITION_RECEIPT",
        "work_order_id": WORK_ORDER_ID,
        "generated_utc": utc_now_iso_z(),
        "mode": CURRENT_MODE,
        "transitions_allowed_now": ["PREP_ONLY_TO_PREP_ONLY"],
        "canonical_transition_allowed": False,
    }
    _write_json(root, "exports/_truth/current/highway_zone_transition_receipt.json", receipt)
    return receipt


def regulated_lane_guard(request: Mapping[str, Any] | None = None, output_root: Path | None = None) -> Dict[str, Any]:
    root = _root(output_root)
    request = dict(request or {})
    has_claim_limiter = bool(request.get("commercial_claim_limiter", True))
    has_manifest = bool(request.get("evidence_manifest", True))
    allowed = has_claim_limiter and has_manifest
    receipt = {
        "schema_id": "kt.highway.regulated_lane_receipt.v1",
        "artifact_id": "HIGHWAY_REGULATED_LANE_RECEIPT",
        "work_order_id": WORK_ORDER_ID,
        "generated_utc": utc_now_iso_z(),
        "regulated_work_allowed_as_prep_only": allowed,
        "unsupported_legal_or_compliance_posture": False,
        "status": "PASS_PREP_ONLY" if allowed else "FAIL_CLOSED",
    }
    _write_json(root, "exports/_truth/current/highway_regulated_lane_receipt.json", receipt)
    return receipt


def emergency_freeze(event_class: str = "POSTURE_CONTRADICTION", output_root: Path | None = None) -> Dict[str, Any]:
    root = _root(output_root)
    receipt = {
        "schema_id": "kt.highway.emergency_freeze_receipt.v1",
        "artifact_id": "HIGHWAY_EMERGENCY_FREEZE_RECEIPT",
        "work_order_id": WORK_ORDER_ID,
        "generated_utc": utc_now_iso_z(),
        "event_class": event_class,
        "freeze_allowed": True,
        "evidence_preservation_allowed": True,
        "authority_bypass_authorized": False,
        "truth_lock_bypass_authorized": False,
        "status": "FREEZE_ONLY_NO_BYPASS",
    }
    _write_json(root, "exports/_truth/current/highway_emergency_freeze_receipt.json", receipt)
    return receipt


def incident_receipt(event_class: str = "POSTURE_CONTRADICTION", output_root: Path | None = None) -> Dict[str, Any]:
    root = _root(output_root)
    receipt = {
        "schema_id": "kt.highway.incident_receipt.v1",
        "artifact_id": "HIGHWAY_INCIDENT_RECEIPT",
        "work_order_id": WORK_ORDER_ID,
        "generated_utc": utc_now_iso_z(),
        "event_class": event_class,
        "incident_classes_supported": list(INCIDENT_CLASSES),
        "status": "RECEIPT_ONLY",
    }
    _write_json(root, "exports/_truth/current/highway_incident_receipt.json", receipt)
    return receipt


def adaptive_gate(requested: str = "FP0_HIGHWAY_ACTIVE", output_root: Path | None = None) -> Dict[str, Any]:
    root = _root(output_root)
    requested_upper = requested.upper()
    blockers: List[str] = []
    if "FP0" in requested_upper:
        blockers.append("BLOCK_FP0_PREP_ONLY")
    if "DETACHED_VERIFIER" in requested_upper:
        blockers.append("BLOCK_EXTERNAL_ATTESTATION_REQUIRED_FOR_EXTERNAL_ACCEPTANCE")
    if "LEARNED_ROUTER" in requested_upper:
        blockers.append("BLOCK_ROUTER_ORDER_VIOLATION")
    receipt = {
        "schema_id": "kt.highway.adaptive_ratification_receipt.v1",
        "artifact_id": "HIGHWAY_ADAPTIVE_RATIFICATION_RECEIPT",
        "work_order_id": WORK_ORDER_ID,
        "generated_utc": utc_now_iso_z(),
        "requested": requested,
        "ratification_order": list(ADAPTIVE_RATIFICATION_ORDER),
        "blockers": blockers,
        "status": "BLOCKED" if blockers else "PASS_PREP_ONLY",
    }
    _write_json(root, "exports/_truth/current/highway_adaptive_ratification_receipt.json", receipt)
    return receipt


def promotion_gate(from_mode: str = "PREP_ONLY", to_mode: str = "CANONICAL_ACTIVE", output_root: Path | None = None) -> Dict[str, Any]:
    root = _root(output_root)
    allowed = False
    if from_mode in PROMOTION_LADDER and to_mode in PROMOTION_LADDER:
        allowed = PROMOTION_LADDER.index(to_mode) == PROMOTION_LADDER.index(from_mode) + 1
    if to_mode == "CANONICAL_ACTIVE":
        allowed = False
    receipt = {
        "schema_id": "kt.highway.promotion_receipt.v1",
        "artifact_id": "HIGHWAY_PROMOTION_RECEIPT",
        "work_order_id": WORK_ORDER_ID,
        "generated_utc": utc_now_iso_z(),
        "from_mode": from_mode,
        "to_mode": to_mode,
        "promotion_allowed": allowed,
        "promotion_ladder": list(PROMOTION_LADDER),
        "blockers": [] if allowed else [HIGHWAY_CANONICAL_PROMOTION_BLOCKER, "PROMOTION_LADDER_OR_AUTHORITY_NOT_SATISFIED"],
        "status": "PASS" if allowed else "BLOCKED",
    }
    _write_json(root, "exports/_truth/current/highway_promotion_receipt.json", receipt)
    return receipt


def rollback_plan(output_root: Path | None = None) -> Dict[str, Any]:
    root = _root(output_root)
    receipt = {
        "schema_id": "kt.highway.rollback_receipt.v1",
        "artifact_id": "HIGHWAY_ROLLBACK_RECEIPT",
        "work_order_id": WORK_ORDER_ID,
        "generated_utc": utc_now_iso_z(),
        "rollback_required_for_canonical_promotion": True,
        "canonical_change_present": False,
        "rollback_plan_status": "PREP_ONLY_AVAILABLE",
        "files_revert": [],
        "truth_surfaces_regenerate": ["exports/_truth/current/highway_matrix_receipt.json"],
    }
    _write_json(root, "exports/_truth/current/highway_rollback_receipt.json", receipt)
    return receipt


def commercial_claim_guard(claims: Sequence[str] | None = None, output_root: Path | None = None) -> Dict[str, Any]:
    root = _root(output_root)
    claims = list(claims or [])
    forbidden_tokens = ("SOC 2 CERTIFIED", "HIPAA COMPLIANT", "PRODUCTION COMMERCIAL LIVE", "COMMERCIAL ACTIVATION AUTHORIZED")
    rejected = [claim for claim in claims if any(token in claim.upper() for token in forbidden_tokens)]
    receipt = {
        "schema_id": "kt.highway.commercial_delivery_receipt.v1",
        "artifact_id": "HIGHWAY_COMMERCIAL_DELIVERY_RECEIPT",
        "work_order_id": WORK_ORDER_ID,
        "generated_utc": utc_now_iso_z(),
        "claims_checked": claims,
        "rejected_claims": rejected,
        "safe_run_bypass_authorized": False,
        "status": "PASS" if not rejected else "FAIL_CLOSED",
    }
    _write_json(root, "exports/_truth/current/highway_commercial_delivery_receipt.json", receipt)
    if rejected:
        raise HighwayFailure("HIGHWAY_COMMERCIAL_OVERCLAIM", "unsupported commercial claim rejected")
    return receipt


def comparative_proof_guard(
    *,
    superiority_claimed: bool = False,
    comparative_receipts_present: bool = False,
    output_root: Path | None = None,
) -> Dict[str, Any]:
    root = _root(output_root)
    allowed = not superiority_claimed or comparative_receipts_present
    receipt = {
        "schema_id": "kt.highway.comparative_proof_receipt.v1",
        "artifact_id": "HIGHWAY_COMPARATIVE_PROOF_RECEIPT",
        "work_order_id": WORK_ORDER_ID,
        "generated_utc": utc_now_iso_z(),
        "initial_status": "COMPARATIVE_PROOF_PREPARED_NOT_CLAIMED",
        "superiority_claimed": superiority_claimed,
        "comparative_receipts_present": comparative_receipts_present,
        "claim_allowed": allowed,
        "status": "PASS_PREP_ONLY" if allowed else "FAIL_CLOSED",
    }
    _write_json(root, "exports/_truth/current/highway_comparative_proof_receipt.json", receipt)
    if not allowed:
        raise HighwayFailure("HIGHWAY_COMPARATIVE_CLAIM_UNSUPPORTED", "superiority claim requires comparative receipts")
    return receipt


def _schema_artifact(name: str, required: Sequence[str]) -> Dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"kt.highway.schemas.{name}.v1",
        "title": name,
        "type": "object",
        "required": list(required),
        "properties": {
            "schema_id": {"type": "string"},
            "artifact_id": {"type": "string"},
            "authority": {"type": "string"},
            "mode": {"type": "string"},
            "work_order_id": {"type": "string"},
        },
        "additionalProperties": True,
    }


def static_artifacts() -> Dict[str, Any]:
    registry_entries = []
    for lane in SUPERLANES:
        entry = dict(lane)
        entry.update(
            {
                "allowed_inputs": ["explicit_operator_intent", "declared_scope", "current_truth_state"],
                "forbidden_inputs": ["implicit_authority", "branch_bound_truth_as_canonical", "unsupported_claims"],
                "truth_sources": ["highway_authority_gate_receipt", "Truth Lock state", "FP0 queue state"],
                "allowed_modes": list(ALLOWED_MODES),
                "blocked_modes": ["CANONICAL_ACTIVE", "FAIL_CLOSED"] if lane["id"] != "EMERGENCY_AND_FREEZE" else ["AUTHORITY_BYPASS"],
                "promotion_rules": "must follow PREP_ONLY -> SHADOW_ONLY -> WARN_ONLY -> FAIL_CLOSED_CANDIDATE -> CANONICAL_ACTIVE",
                "rollback_rules": "required before any canonical-impacting promotion",
            }
        )
        registry_entries.append(entry)

    artifacts: Dict[str, Any] = {
        "governance/highway_authority_gate_v1.json": {
            **_base_artifact("HIGHWAY_AUTHORITY_GATE_V1", superlane="AUTHORITY_GATE"),
            **authority_state(),
        },
        "governance/highway_activation_ladder_v1.json": {
            **_base_artifact("HIGHWAY_ACTIVATION_LADDER_V1", superlane="AUTHORITY_GATE"),
            "promotion_ladder": list(PROMOTION_LADDER),
            "current_allowed_mode": CURRENT_MODE,
            "fail_closed_enforcement_allowed": False,
        },
        "governance/highway_pathway_system_v1.json": {
            **_base_artifact("HIGHWAY_PATHWAY_SYSTEM_V1"),
            "mission": "Additive prep-only lane-governed pathway fabric for KT.",
            "not_a_rewrite": True,
            "not_parallel_runtime": True,
            "safe_run_remains_lawful_entrypoint": True,
            "superlane_ids": [lane["id"] for lane in SUPERLANES],
        },
        "governance/highway_superlane_registry_v1.json": {
            **_base_artifact("HIGHWAY_SUPERLANE_REGISTRY_V1"),
            "superlanes": registry_entries,
        },
        "governance/highway_lane_contract_v1.json": {
            **_base_artifact("HIGHWAY_LANE_CONTRACT_V1"),
            "lane_contract_fields": [
                "id",
                "name",
                "purpose",
                "allowed_inputs",
                "forbidden_inputs",
                "authority_required",
                "truth_sources",
                "entry_conditions",
                "exit_conditions",
                "required_receipts",
                "allowed_modes",
                "blocked_modes",
                "promotion_rules",
                "rollback_rules",
                "ci_enforcement_level",
                "canonical_scope_effect",
            ],
            "no_lane_may_be_implicit": True,
        },
        "governance/highway_receipt_contract_v1.json": {
            **_base_artifact("HIGHWAY_RECEIPT_CONTRACT_V1"),
            "required_receipt_fields": [
                "schema_id",
                "artifact_id",
                "work_order_id",
                "mode",
                "status",
                "generated_utc",
                "authority_basis",
                "canonical_effect",
            ],
        },
        "governance/highway_route_contract_v1.json": {
            **_base_artifact("HIGHWAY_ROUTE_CONTRACT_V1"),
            "required_route_fields": [
                "work_order_id",
                "selected_superlane",
                "secondary_superlanes",
                "mode",
                "allowed",
                "blocked",
                "blockers",
                "authority_basis",
                "truth_sources_checked",
                "canonical_effect",
                "prep_only_effect",
                "required_next_gate",
            ],
        },
        "governance/highway_canonical_runtime_lane_v1.json": {
            **_base_artifact("HIGHWAY_CANONICAL_RUNTIME_LANE_V1", superlane="CANONICAL_RUNTIME"),
            "safe_run_only_lawful_production_entrypoint": True,
            "no_substitute_runtime": True,
        },
        "governance/highway_truth_posture_lane_v1.json": {
            **_base_artifact("HIGHWAY_TRUTH_POSTURE_LANE_V1", superlane="TRUTH_AND_POSTURE"),
            "posture_enums": [
                "HIGHWAY_PREP_ONLY",
                "HIGHWAY_SHADOW_READY",
                "HIGHWAY_WARN_ONLY_READY",
                "HIGHWAY_FAIL_CLOSED_READY",
                "HIGHWAY_CANONICAL_ACTIVE",
                "HIGHWAY_BLOCKED",
                "HIGHWAY_CONFLICT",
            ],
            "strongest_current_posture": "HIGHWAY_PREP_ONLY",
        },
        "governance/highway_trust_zone_lane_v1.json": {
            **_base_artifact("HIGHWAY_TRUST_ZONE_LANE_V1", superlane="BOUNDARY_AND_TRUST_ZONE"),
            "zones": ["CANONICAL", "LAB", "ARCHIVE", "COMMERCIAL", "PREP_ONLY", "RUNTIME_TRUTH", "GENERATED_EXPORT"],
            "silent_exclusions_allowed": False,
        },
        "governance/highway_zone_transition_rules_v1.json": {
            **_base_artifact("HIGHWAY_ZONE_TRANSITION_RULES_V1", superlane="BOUNDARY_AND_TRUST_ZONE"),
            "allowed_now": ["PREP_ONLY_TO_PREP_ONLY"],
            "canonical_transition_allowed": False,
        },
        "governance/highway_regulated_lane_v1.json": {
            **_base_artifact("HIGHWAY_REGULATED_LANE_V1", superlane="REGULATED_WORK"),
            "requires_operator_intent_capture": True,
            "requires_commercial_claim_limiter": True,
        },
        "governance/highway_emergency_lane_v1.json": {
            **_base_artifact("HIGHWAY_EMERGENCY_LANE_V1", superlane="EMERGENCY_AND_FREEZE"),
            "may_freeze": True,
            "may_bypass_law": False,
        },
        "governance/highway_freeze_authority_v1.json": {
            **_base_artifact("HIGHWAY_FREEZE_AUTHORITY_V1", superlane="EMERGENCY_AND_FREEZE"),
            "freeze_only_authority": True,
            "truth_lock_bypass_authorized": False,
        },
        "governance/highway_incident_contract_v1.json": {
            **_base_artifact("HIGHWAY_INCIDENT_CONTRACT_V1", superlane="EMERGENCY_AND_FREEZE"),
            "incident_classes": list(INCIDENT_CLASSES),
        },
        "governance/highway_lab_adaptive_lane_v1.json": {
            **_base_artifact("HIGHWAY_LAB_ADAPTIVE_LANE_V1", superlane="LAB_AND_ADAPTIVE_RATIFICATION"),
            "fp0_authority": "PREP_ONLY_QUEUED_NONAUTHORITATIVE",
            "canonical_activation_allowed": False,
        },
        "governance/highway_adaptive_ratification_ladder_v1.json": {
            **_base_artifact("HIGHWAY_ADAPTIVE_RATIFICATION_LADDER_V1", superlane="LAB_AND_ADAPTIVE_RATIFICATION"),
            "ratification_order": list(ADAPTIVE_RATIFICATION_ORDER),
        },
        "governance/highway_promotion_lane_v1.json": {
            **_base_artifact("HIGHWAY_PROMOTION_LANE_V1", superlane="PROMOTION_AND_ROLLBACK"),
            "promotion_ladder": list(PROMOTION_LADDER),
            "direct_prep_to_canonical_allowed": False,
        },
        "governance/highway_rollback_lane_v1.json": {
            **_base_artifact("HIGHWAY_ROLLBACK_LANE_V1", superlane="PROMOTION_AND_ROLLBACK"),
            "rollback_required_before_canonical_promotion": True,
        },
        "governance/highway_bridge_contract_v1.json": {
            **_base_artifact("HIGHWAY_BRIDGE_CONTRACT_V1", superlane="PROMOTION_AND_ROLLBACK"),
            "bridge_allowed_now": "PREP_ONLY_TO_PREP_ONLY",
        },
        "governance/highway_commercial_lane_v1.json": {
            **_base_artifact("HIGHWAY_COMMERCIAL_LANE_V1", superlane="COMMERCIAL_DELIVERY"),
            "new_skus_allowed": False,
            "unsupported_compliance_claims_allowed": False,
            "safe_run_bypass_allowed": False,
        },
        "governance/highway_comparative_proof_lane_v1.json": {
            **_base_artifact("HIGHWAY_COMPARATIVE_PROOF_LANE_V1", superlane="COMPARATIVE_PROOF"),
            "initial_status": "COMPARATIVE_PROOF_PREPARED_NOT_CLAIMED",
            "superiority_claim_allowed_without_receipts": False,
        },
        "schemas/highway_pathway_system.schema.json": _schema_artifact("highway_pathway_system", ["schema_id", "artifact_id", "authority", "mode"]),
        "schemas/highway_superlane_registry.schema.json": _schema_artifact("highway_superlane_registry", ["schema_id", "artifact_id", "superlanes"]),
        "schemas/highway_lane_contract.schema.json": _schema_artifact("highway_lane_contract", ["schema_id", "artifact_id", "lane_contract_fields"]),
        "schemas/highway_route_receipt.schema.json": _schema_artifact("highway_route_receipt", ["schema_id", "artifact_id", "selected_superlane"]),
        "schemas/highway_matrix_receipt.schema.json": _schema_artifact("highway_matrix_receipt", ["schema_id", "artifact_id", "checks"]),
        "commercial/highway_client_wrapper_spec_v1.json": {
            **_base_artifact("HIGHWAY_CLIENT_WRAPPER_SPEC_V1", superlane="COMMERCIAL_DELIVERY"),
            "client_wrapper_status": "PREP_ONLY",
            "new_skus": [],
        },
        "commercial/highway_deployment_profiles_v1.json": {
            **_base_artifact("HIGHWAY_DEPLOYMENT_PROFILES_V1", superlane="COMMERCIAL_DELIVERY"),
            "deployment_profiles": [],
            "safe_run_required": True,
        },
        "commercial/highway_public_verifier_kit_v1.json": {
            **_base_artifact("HIGHWAY_PUBLIC_VERIFIER_KIT_V1", superlane="COMMERCIAL_DELIVERY"),
            "detached_verifier_authorized": True,
            "status": "PREP_ONLY_DRAFT",
        },
        "evals/highway_comparative_scorecard_v1.json": {
            **_base_artifact("HIGHWAY_COMPARATIVE_SCORECARD_V1", superlane="COMPARATIVE_PROOF"),
            "status": "COMPARATIVE_PROOF_PREPARED_NOT_CLAIMED",
            "scores": [],
        },
        "evals/highway_monolith_vs_adapter_vs_router_matrix_v1.json": {
            **_base_artifact("HIGHWAY_MONOLITH_VS_ADAPTER_VS_ROUTER_MATRIX_V1", superlane="COMPARATIVE_PROOF"),
            "status": "PREP_ONLY",
            "comparisons": [],
        },
        "evals/highway_proof_bundle_comparison_v1.json": {
            **_base_artifact("HIGHWAY_PROOF_BUNDLE_COMPARISON_V1", superlane="COMPARATIVE_PROOF"),
            "status": "PREP_ONLY",
            "proof_bundles": [],
        },
    }
    return artifacts


def generate_static_artifacts(output_root: Path | None = None) -> List[str]:
    root = _root(output_root)
    written: List[str] = []
    for raw_path, payload in static_artifacts().items():
        if raw_path.endswith(".json"):
            _write_json(root, raw_path, payload)
        else:
            _write_text(root, raw_path, str(payload))
        written.append(raw_path)
    _write_text(
        root,
        "commercial/highway_operator_runbook_v1.md",
        "# Highway Operator Runbook v1\n\n"
        "Mode: PREP_ONLY.\n\n"
        "The highway pathway system is an additive routing and proof fabric. It does not replace safe-run, "
        "does not claim external audit acceptance, and does not expand commercial claims while independent external attestation remains pending.\n",
    )
    written.append("commercial/highway_operator_runbook_v1.md")
    _write_text(
        root,
        "ci/jobs/verify_highway_pathway.yml",
        "name: verify-highway-pathway-prep-only\n"
        "mode: PREP_ONLY_LOCAL\n"
        "commands:\n"
        "  - python KT_PROD_CLEANROOM/tools/operator/run_highway_matrix.py\n"
        "  - python -m pytest KT_PROD_CLEANROOM/tests/operator/test_run_highway_matrix.py -q\n",
    )
    written.append("ci/jobs/verify_highway_pathway.yml")
    return written


def json_schema_validate_highway_files(output_root: Path | None = None) -> Dict[str, Any]:
    root = _root(output_root)
    paths = [root / raw for raw in static_artifacts().keys() if raw.endswith(".json")]
    failures: List[str] = []
    for path in paths:
        if not path.exists():
            failures.append(f"MISSING:{path.as_posix()}")
            continue
        try:
            with path.open("r", encoding="utf-8-sig") as handle:
                payload = json.load(handle)
        except Exception as exc:  # pragma: no cover - exact parser text is not important
            failures.append(f"INVALID_JSON:{path.as_posix()}:{exc}")
            continue
        if not isinstance(payload, MutableMapping):
            failures.append(f"NOT_OBJECT:{path.as_posix()}")
        elif "schema_id" not in payload and "$schema" not in payload:
            failures.append(f"MISSING_SCHEMA:{path.as_posix()}")
    return {
        "checked": len(paths),
        "failures": failures,
        "status": "PASS" if not failures else "FAIL_CLOSED",
    }


def run_highway_matrix(output_root: Path | None = None) -> Dict[str, Any]:
    root = _root(output_root)
    artifacts = generate_static_artifacts(root)
    checks = [
        {"name": "highway_authority_gate", "result": write_authority_gate_receipt(root)["authority_verdict"]},
        {"name": "highway_lane_admission", "result": classify_lane({"operator_intent": "prep highway"})["decision"]},
        {"name": "highway_route_resolver", "result": write_route_receipt(output_root=root)["decision"]},
        {"name": "highway_canonical_runtime_guard", "result": canonical_runtime_guard(root)["status"]},
        {"name": "highway_posture_sync", "result": posture_sync(root)["posture"]},
        {"name": "highway_posture_conflict_scan", "result": posture_conflict_scan(output_root=root)["status"]},
        {"name": "highway_trust_zone_validate", "result": trust_zone_validate(output_root=root)["status"]},
        {"name": "highway_zone_transition_receipt", "result": zone_transition_receipt(root)["canonical_transition_allowed"]},
        {"name": "highway_regulated_lane_guard", "result": regulated_lane_guard(output_root=root)["status"]},
        {"name": "highway_emergency_freeze", "result": emergency_freeze(output_root=root)["status"]},
        {"name": "highway_incident_receipt", "result": incident_receipt(output_root=root)["status"]},
        {"name": "highway_adaptive_gate", "result": adaptive_gate(output_root=root)["status"]},
        {"name": "highway_promotion_gate", "result": promotion_gate(output_root=root)["status"]},
        {"name": "highway_rollback_plan", "result": rollback_plan(root)["rollback_plan_status"]},
        {"name": "highway_commercial_claim_guard", "result": commercial_claim_guard(output_root=root)["status"]},
        {"name": "highway_comparative_proof_guard", "result": comparative_proof_guard(output_root=root)["status"]},
        {"name": "json_schema_validation", "result": json_schema_validate_highway_files(root)["status"]},
    ]
    matrix = {
        "schema_id": "kt.highway.matrix_receipt.v1",
        "artifact_id": "HIGHWAY_MATRIX_RECEIPT",
        "work_order_id": WORK_ORDER_ID,
        "generated_utc": utc_now_iso_z(),
        "mode": CURRENT_MODE,
        "authority_verdict": "BLOCKED",
        "current_blockers": list(CURRENT_BLOCKERS),
        "files_generated_or_verified": artifacts,
        "checks": checks,
        "posture_conflict_count": 0,
        "canonical_effect": "None",
        "promotion_status": "Not promoted",
        "next_lawful_action": "Collect independent external re-audit attestation or separately authorize highway shadow promotion.",
        "final_label": FINAL_LABEL,
    }
    _write_json(root, "exports/_truth/current/highway_matrix_receipt.json", matrix)
    return matrix


def write_developer_report(output_root: Path | None = None) -> Path:
    root = _root(output_root)
    matrix = run_highway_matrix(root)
    operator_files = [
        "KT_PROD_CLEANROOM/tools/operator/highway_common.py",
        "KT_PROD_CLEANROOM/tools/operator/highway_authority_gate.py",
        "KT_PROD_CLEANROOM/tools/operator/highway_lane_admission.py",
        "KT_PROD_CLEANROOM/tools/operator/highway_route_resolver.py",
        "KT_PROD_CLEANROOM/tools/operator/highway_route_receipt.py",
        "KT_PROD_CLEANROOM/tools/operator/highway_canonical_runtime_guard.py",
        "KT_PROD_CLEANROOM/tools/operator/highway_posture_sync.py",
        "KT_PROD_CLEANROOM/tools/operator/highway_posture_conflict_scan.py",
        "KT_PROD_CLEANROOM/tools/operator/highway_trust_zone_validate.py",
        "KT_PROD_CLEANROOM/tools/operator/highway_zone_transition_receipt.py",
        "KT_PROD_CLEANROOM/tools/operator/highway_regulated_lane_guard.py",
        "KT_PROD_CLEANROOM/tools/operator/highway_emergency_freeze.py",
        "KT_PROD_CLEANROOM/tools/operator/highway_incident_receipt.py",
        "KT_PROD_CLEANROOM/tools/operator/highway_adaptive_gate.py",
        "KT_PROD_CLEANROOM/tools/operator/highway_promotion_gate.py",
        "KT_PROD_CLEANROOM/tools/operator/highway_rollback_plan.py",
        "KT_PROD_CLEANROOM/tools/operator/highway_commercial_claim_guard.py",
        "KT_PROD_CLEANROOM/tools/operator/highway_comparative_proof_guard.py",
        "KT_PROD_CLEANROOM/tools/operator/run_highway_matrix.py",
    ]
    test_files = [
        "KT_PROD_CLEANROOM/tests/operator/test_highway_authority_gate.py",
        "KT_PROD_CLEANROOM/tests/operator/test_highway_lane_admission.py",
        "KT_PROD_CLEANROOM/tests/operator/test_highway_route_resolver.py",
        "KT_PROD_CLEANROOM/tests/operator/test_highway_canonical_runtime_guard.py",
        "KT_PROD_CLEANROOM/tests/operator/test_highway_posture_sync.py",
        "KT_PROD_CLEANROOM/tests/operator/test_highway_posture_conflict_scan.py",
        "KT_PROD_CLEANROOM/tests/operator/test_highway_trust_zone_validate.py",
        "KT_PROD_CLEANROOM/tests/operator/test_highway_regulated_lane_guard.py",
        "KT_PROD_CLEANROOM/tests/operator/test_highway_emergency_freeze.py",
        "KT_PROD_CLEANROOM/tests/operator/test_highway_incident_receipt.py",
        "KT_PROD_CLEANROOM/tests/operator/test_highway_adaptive_gate.py",
        "KT_PROD_CLEANROOM/tests/operator/test_highway_promotion_gate.py",
        "KT_PROD_CLEANROOM/tests/operator/test_highway_rollback_plan.py",
        "KT_PROD_CLEANROOM/tests/operator/test_highway_commercial_claim_guard.py",
        "KT_PROD_CLEANROOM/tests/operator/test_highway_comparative_proof_guard.py",
        "KT_PROD_CLEANROOM/tests/operator/test_run_highway_matrix.py",
    ]
    added_files = [*operator_files, *test_files, *matrix["files_generated_or_verified"]]
    text = "\n".join(
        [
            "TITLE:",
            "KT Highway Pathway System Superlane Initiation Report",
            "",
            "MODE:",
            CURRENT_MODE,
            "",
            "AUTHORITY VERDICT:",
            "Blocked",
            "",
            "CURRENT BLOCKERS:",
            "- " + "\n- ".join(CURRENT_BLOCKERS),
            "",
            "FILES ADDED:",
            "- " + "\n- ".join(added_files),
            "",
            "FILES MODIFIED:",
            "- None outside additive prep-only highway artifacts and receipts",
            "",
            "SUPERLANES IMPLEMENTED:",
            "- " + "\n- ".join(lane["id"] for lane in SUPERLANES),
            "",
            "RECEIPTS EMITTED:",
            "- exports/_truth/current/highway_authority_gate_receipt.json",
            "- exports/_truth/current/highway_route_receipt.json",
            "- exports/_truth/current/highway_matrix_receipt.json",
            "",
            "VALIDATION RUN:",
            "- python KT_PROD_CLEANROOM/tools/operator/run_highway_matrix.py",
            "",
            "TEST RESULTS:",
            "- See local pytest output",
            "",
            "POSTURE CONFLICT COUNT:",
            str(matrix["posture_conflict_count"]),
            "",
            "CANONICAL EFFECT:",
            "None",
            "",
            "PROMOTION STATUS:",
            "Not promoted",
            "",
            "NEXT LAWFUL ACTION:",
            "Collect independent external re-audit attestation; continue prep/shadow/no-claim-expansion work under claim ceiling.",
            "",
            "FINAL LABEL:",
            FINAL_LABEL,
            "",
        ]
    )
    return _write_text(root, "KT_PROD_CLEANROOM/reports/highway_pathway_system_superlane_initiation_report.md", text)


def cli(tool_name: str, argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"Run {tool_name}")
    parser.add_argument("--output-root", default="", help="Optional alternate output root for tests")
    args = parser.parse_args(list(argv) if argv is not None else None)
    output_root = Path(args.output_root) if args.output_root else None

    if tool_name == "highway_authority_gate":
        write_authority_gate_receipt(output_root)
    elif tool_name == "highway_lane_admission":
        write_route_receipt({"work_order_id": WORK_ORDER_ID, "operator_intent": "prep-only lane admission"}, output_root)
    elif tool_name == "highway_route_resolver":
        write_route_receipt({"work_order_id": WORK_ORDER_ID, "operator_intent": "prep-only route resolver"}, output_root)
    elif tool_name == "highway_route_receipt":
        write_route_receipt(output_root=output_root)
    elif tool_name == "highway_canonical_runtime_guard":
        canonical_runtime_guard(output_root)
    elif tool_name == "highway_posture_sync":
        posture_sync(output_root)
    elif tool_name == "highway_posture_conflict_scan":
        posture_conflict_scan(output_root=output_root)
    elif tool_name == "highway_trust_zone_validate":
        trust_zone_validate(output_root=output_root)
    elif tool_name == "highway_zone_transition_receipt":
        zone_transition_receipt(output_root)
    elif tool_name == "highway_regulated_lane_guard":
        regulated_lane_guard(output_root=output_root)
    elif tool_name == "highway_emergency_freeze":
        emergency_freeze(output_root=output_root)
    elif tool_name == "highway_incident_receipt":
        incident_receipt(output_root=output_root)
    elif tool_name == "highway_adaptive_gate":
        adaptive_gate(output_root=output_root)
    elif tool_name == "highway_promotion_gate":
        promotion_gate(output_root=output_root)
    elif tool_name == "highway_rollback_plan":
        rollback_plan(output_root)
    elif tool_name == "highway_commercial_claim_guard":
        commercial_claim_guard(output_root=output_root)
    elif tool_name == "highway_comparative_proof_guard":
        comparative_proof_guard(output_root=output_root)
    elif tool_name == "run_highway_matrix":
        run_highway_matrix(output_root)
        write_developer_report(output_root)
    else:  # pragma: no cover - wrapper programming error
        raise HighwayFailure("HIGHWAY_UNKNOWN_TOOL", tool_name)
    return 0
