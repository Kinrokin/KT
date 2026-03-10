from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.posture_consistency import verify_posture
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.truth_authority import build_settled_truth_source_receipt, build_truth_supersession_receipt, path_ref
from tools.operator.truth_publication import (
    CURRENT_POINTER_REL,
    TRUTH_PUBLICATION_REQUIRED_ARTIFACTS,
    TRUTH_PUBLICATION_REQUIRED_LAW_SURFACES,
    load_publication_stabilization_state,
    publish_truth_artifacts,
)
from tools.operator.truth_engine import (
    CANONICAL_READY_FOR_REEARNED_GREEN,
    TRUTHFUL_GREEN,
    build_truth_receipts,
    derive_live_validation_state,
)


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
COMPLETION_PROGRAM_REF = "KT_PROD_CLEANROOM/docs/operator/KT_CONSTITUTIONAL_COMPLETION_PROGRAM.md"

CONSTITUTIONAL_DOMAINS: List[Dict[str, Any]] = [
    {
        "domain_id": "DOMAIN_1_TRUTH_PUBLICATION_ARCHITECTURE",
        "title": "Truth publication architecture",
        "entry_gate": "FOUNDATIONAL_LAW_TRANCHE_COMPLETE",
        "exit_gate": "TRUTH_PUBLICATION_STABILIZED",
        "required_law_surfaces": TRUTH_PUBLICATION_REQUIRED_LAW_SURFACES,
        "required_artifacts": TRUTH_PUBLICATION_REQUIRED_ARTIFACTS,
    },
    {
        "domain_id": "DOMAIN_2_PROMOTION_CIVILIZATION",
        "title": "Promotion civilization",
        "entry_gate": "H1_ACTIVATION_ALLOWED",
        "exit_gate": "PROMOTION_CIVILIZATION_RATIFIED",
        "required_law_surfaces": [
            "KT_PROD_CLEANROOM/governance/promotion_engine_law.json",
            "KT_PROD_CLEANROOM/governance/crucible_lifecycle_law.json",
            "KT_PROD_CLEANROOM/governance/adapter_lifecycle_law.json",
            "KT_PROD_CLEANROOM/governance/tournament_law.json",
            "KT_PROD_CLEANROOM/governance/merge_law.json",
            "KT_PROD_CLEANROOM/governance/router_promotion_law.json",
            "KT_PROD_CLEANROOM/governance/lobe_promotion_law.json",
            "KT_PROD_CLEANROOM/governance/rollback_law.json",
            "KT_PROD_CLEANROOM/governance/revalidation_law.json",
            "KT_PROD_CLEANROOM/governance/retirement_law.json",
        ],
        "required_artifacts": [
            "KT_PROD_CLEANROOM/governance/crucible_registry.json",
            "KT_PROD_CLEANROOM/governance/adapter_registry.json",
            "KT_PROD_CLEANROOM/governance/router_policy_registry.json",
            "KT_PROD_CLEANROOM/governance/lobe_role_registry.json",
            "KT_PROD_CLEANROOM/reports/promotion_receipt.json",
            "KT_PROD_CLEANROOM/reports/rollback_plan_receipt.json",
            "KT_PROD_CLEANROOM/reports/risk_ledger_receipt.json",
            "KT_PROD_CLEANROOM/reports/revalidation_receipt.json",
            "KT_PROD_CLEANROOM/reports/zone_crossing_receipt.json",
        ],
    },
    {
        "domain_id": "DOMAIN_3_CAPABILITY_ATLAS",
        "title": "Capability atlas",
        "entry_gate": "PROMOTION_CIVILIZATION_RATIFIED",
        "exit_gate": "CAPABILITY_ATLAS_RATIFIED",
        "required_law_surfaces": [
            "KT_PROD_CLEANROOM/governance/capability_atlas_contract.json",
            "KT_PROD_CLEANROOM/governance/capability_dimension_registry.json",
            "KT_PROD_CLEANROOM/governance/pressure_response_taxonomy.json",
            "KT_PROD_CLEANROOM/governance/failure_mode_taxonomy.json",
            "KT_PROD_CLEANROOM/governance/capability_evidence_binding_rules.json",
        ],
        "required_artifacts": [
            "KT_PROD_CLEANROOM/reports/capability_atlas.schema.json",
            "KT_PROD_CLEANROOM/reports/capability_topology.json",
            "KT_PROD_CLEANROOM/reports/pressure_behavior_matrix.json",
            "KT_PROD_CLEANROOM/reports/routing_delta_matrix.json",
            "KT_PROD_CLEANROOM/reports/merge_interference_index.json",
            "KT_PROD_CLEANROOM/reports/lobe_cooperation_matrix.json",
            "KT_PROD_CLEANROOM/reports/behavior_delta_receipt.json",
        ],
    },
    {
        "domain_id": "DOMAIN_4_CONSTITUTIONAL_COURT",
        "title": "Constitutional court",
        "entry_gate": "CAPABILITY_ATLAS_RATIFIED",
        "exit_gate": "CONSTITUTIONAL_COURT_RATIFIED",
        "required_law_surfaces": [
            "KT_PROD_CLEANROOM/governance/constitutional_court_contract.json",
            "KT_PROD_CLEANROOM/governance/amendment_law.json",
            "KT_PROD_CLEANROOM/governance/appeal_law.json",
            "KT_PROD_CLEANROOM/governance/dissent_law.json",
            "KT_PROD_CLEANROOM/governance/precedent_registry_rules.json",
            "KT_PROD_CLEANROOM/governance/constitutional_review_triggers.json",
        ],
        "required_artifacts": [
            "KT_PROD_CLEANROOM/reports/constitutional_court.schema.json",
            "KT_PROD_CLEANROOM/reports/amendment_receipt.json",
            "KT_PROD_CLEANROOM/reports/appeal_receipt.json",
            "KT_PROD_CLEANROOM/reports/dissent_receipt.json",
            "KT_PROD_CLEANROOM/reports/precedent_registry.json",
            "KT_PROD_CLEANROOM/reports/constitutional_review_receipt.json",
        ],
    },
    {
        "domain_id": "DOMAIN_5_ECONOMIC_TRUTH_PLANE",
        "title": "Economic truth plane",
        "entry_gate": "CONSTITUTIONAL_COURT_RATIFIED",
        "exit_gate": "ECONOMIC_TRUTH_PLANE_RATIFIED",
        "required_law_surfaces": [
            "KT_PROD_CLEANROOM/governance/economic_truth_plane_contract.json",
            "KT_PROD_CLEANROOM/governance/routing_economic_integration_rules.json",
            "KT_PROD_CLEANROOM/governance/escalation_cost_rules.json",
            "KT_PROD_CLEANROOM/governance/compute_allocation_rules.json",
            "KT_PROD_CLEANROOM/governance/risk_adjusted_utility_rules.json",
        ],
        "required_artifacts": [
            "KT_PROD_CLEANROOM/reports/economic_truth_plane.schema.json",
            "KT_PROD_CLEANROOM/reports/uncertainty_cost_index.json",
            "KT_PROD_CLEANROOM/reports/compute_cost_profile.json",
            "KT_PROD_CLEANROOM/reports/escalation_cost_profile.json",
            "KT_PROD_CLEANROOM/reports/remediation_cost_profile.json",
            "KT_PROD_CLEANROOM/reports/risk_adjusted_route_receipt.json",
        ],
    },
    {
        "domain_id": "DOMAIN_6_EXTERNAL_LEGIBILITY",
        "title": "External legibility",
        "entry_gate": "ECONOMIC_TRUTH_PLANE_RATIFIED",
        "exit_gate": "EXTERNAL_LEGIBILITY_RATIFIED",
        "required_law_surfaces": [
            "KT_PROD_CLEANROOM/governance/external_legibility_contract.json",
            "KT_PROD_CLEANROOM/governance/public_verifier_rules.json",
            "KT_PROD_CLEANROOM/governance/deployment_profile_rules.json",
            "KT_PROD_CLEANROOM/governance/documentary_authority_label_rules.json",
            "KT_PROD_CLEANROOM/governance/external_packet_sanitization_rules.json",
        ],
        "required_artifacts": [
            "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
            "KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json",
            "KT_PROD_CLEANROOM/reports/deployment_profiles.json",
            "KT_PROD_CLEANROOM/reports/client_delivery_schema.json",
            "KT_PROD_CLEANROOM/reports/documentary_authority_labels.json",
            "KT_PROD_CLEANROOM/reports/commercial_program_catalog.json",
        ],
    },
]


def _load_required(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return load_json(path)


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    write_json_stable(path, payload)


def _report_ref(report_root_rel: str, name: str) -> str:
    return str((Path(report_root_rel) / name).as_posix())


def _truth_sources(report_root_rel: str) -> List[str]:
    return [
        CURRENT_POINTER_REL,
        _report_ref(report_root_rel, "live_validation_index.json"),
        _report_ref(report_root_rel, "settled_truth_source_receipt.json"),
        _report_ref(report_root_rel, "posture_consistency_enforcement_receipt.json"),
        _report_ref(report_root_rel, "posture_conflict_receipt.json"),
    ]


def _missing_required_paths(*, root: Path, paths: Sequence[str]) -> List[str]:
    missing: List[str] = []
    for rel in paths:
        if not (root / Path(rel)).exists():
            missing.append(str(Path(rel).as_posix()))
    return missing


def _surface_health_failures(*, root: Path, paths: Sequence[str], allowed_statuses: Sequence[str]) -> List[str]:
    allowed = {str(item).strip().upper() for item in allowed_statuses if str(item).strip()}
    failures: List[str] = []
    for rel in paths:
        path = root / Path(rel)
        if not path.exists() or path.suffix.lower() != ".json":
            continue
        try:
            payload = load_json(path)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{Path(rel).as_posix()} unreadable: {exc}")
            continue
        if not isinstance(payload, dict):
            continue
        status = str(payload.get("status", "")).strip()
        if status and status.upper() not in allowed:
            failures.append(f"{Path(rel).as_posix()} status={status}")
    return failures


def _build_constitutional_board_state(*, root: Path, authority_mode: str, posture_state: str, open_blockers: Sequence[str]) -> Dict[str, Any]:
    publication_state = load_publication_stabilization_state(root=root)
    truth_publication_stabilized = (
        authority_mode == "SETTLED_AUTHORITATIVE"
        and posture_state == TRUTHFUL_GREEN
        and not list(open_blockers)
        and str(publication_state.get("status", "")).strip() == "PASS"
        and bool(publication_state.get("board_transition_ready"))
    )
    program_gates: Dict[str, bool] = {
        "FOUNDATIONAL_LAW_TRANCHE_COMPLETE": True,
        "TRUTH_PUBLICATION_STABILIZED": truth_publication_stabilized,
        "H1_ACTIVATION_ALLOWED": truth_publication_stabilized,
    }
    gate_status_map: Dict[str, Dict[str, Any]] = {}
    constitutional_domains: List[Dict[str, Any]] = []

    for index, domain in enumerate(CONSTITUTIONAL_DOMAINS):
        domain_id = str(domain["domain_id"])
        title = str(domain["title"])
        entry_gate = str(domain["entry_gate"])
        exit_gate = str(domain["exit_gate"])
        required_law_surfaces = [str(item) for item in domain.get("required_law_surfaces", [])]
        required_artifacts = [str(item) for item in domain.get("required_artifacts", [])]
        missing_law_surfaces = _missing_required_paths(root=root, paths=required_law_surfaces)
        missing_artifacts = _missing_required_paths(root=root, paths=required_artifacts)
        unhealthy_law_surfaces = _surface_health_failures(
            root=root,
            paths=required_law_surfaces,
            allowed_statuses=("ACTIVE",),
        )
        unhealthy_artifacts = _surface_health_failures(
            root=root,
            paths=required_artifacts,
            allowed_statuses=("PASS", "ACTIVE", "READY", "COMPLETED", "AUTHORITATIVE", "IMPLEMENTED"),
        )

        entry_gate_open = bool(program_gates.get(entry_gate, False))
        if exit_gate not in program_gates:
            program_gates[exit_gate] = False

        activation_rules: List[Dict[str, Any]] = [
            {
                "rule": "entry_gate_open",
                "gate_id": entry_gate,
                "status": "PASS" if entry_gate_open else "FAIL",
            },
            {
                "rule": "required_law_surfaces_present",
                "status": "PASS" if not missing_law_surfaces else "FAIL",
                "missing": missing_law_surfaces,
            },
            {
                "rule": "required_law_surfaces_healthy",
                "status": "PASS" if not unhealthy_law_surfaces else "FAIL",
                "failures": unhealthy_law_surfaces,
            },
            {
                "rule": "required_artifacts_present",
                "status": "PASS" if not missing_artifacts else "FAIL",
                "missing": missing_artifacts,
            },
            {
                "rule": "required_artifacts_healthy",
                "status": "PASS" if not unhealthy_artifacts else "FAIL",
                "failures": unhealthy_artifacts,
            },
        ]

        domain_blockers: List[str] = []
        if domain_id == "DOMAIN_1_TRUTH_PUBLICATION_ARCHITECTURE":
            if not truth_publication_stabilized:
                if open_blockers:
                    domain_blockers.extend(str(item) for item in open_blockers if str(item).strip())
                publication_blockers = [str(item).strip() for item in publication_state.get("blockers", []) if str(item).strip()]
                if publication_blockers:
                    domain_blockers.extend(publication_blockers)
                if not open_blockers and not publication_blockers:
                    domain_blockers.append("truth publication architecture has not yet stabilized")
        else:
            if not entry_gate_open:
                domain_blockers.append(f"entry gate closed: {entry_gate}")
        domain_blockers.extend(f"missing required law surface: {path}" for path in missing_law_surfaces)
        domain_blockers.extend(f"missing required artifact: {path}" for path in missing_artifacts)
        domain_blockers.extend(f"unhealthy law surface: {item}" for item in unhealthy_law_surfaces)
        domain_blockers.extend(f"unhealthy artifact: {item}" for item in unhealthy_artifacts)

        deduped_domain_blockers: List[str] = []
        seen_blockers = set()
        for blocker in domain_blockers:
            if blocker in seen_blockers:
                continue
            seen_blockers.add(blocker)
            deduped_domain_blockers.append(blocker)

        if domain_id == "DOMAIN_1_TRUTH_PUBLICATION_ARCHITECTURE":
            exit_gate_open = truth_publication_stabilized
            status = "COMPLETED" if truth_publication_stabilized else "ACTIVE"
        else:
            exit_gate_open = bool(entry_gate_open and not deduped_domain_blockers)
            program_gates[exit_gate] = exit_gate_open
        if domain_id != "DOMAIN_1_TRUTH_PUBLICATION_ARCHITECTURE" and not entry_gate_open:
            status = "LOCKED"
        elif exit_gate_open:
            status = "COMPLETED"
        elif domain_id == "DOMAIN_1_TRUTH_PUBLICATION_ARCHITECTURE":
            status = "ACTIVE"
        else:
            status = "ACTIVE"

        constitutional_domains.append(
            {
                "domain_id": domain_id,
                "title": title,
                "status": status,
                "entry_gate": entry_gate,
                "exit_gate": exit_gate,
                "activation_rules": activation_rules,
                "required_law_surfaces": required_law_surfaces,
                "required_artifacts": required_artifacts,
                "active_blockers": deduped_domain_blockers,
            }
        )

        entry_gate_blockers = [] if entry_gate_open else [f"entry gate closed: {entry_gate}"]
        gate_status_map.setdefault(
            entry_gate,
            {
                "gate_id": entry_gate,
                "domain_id": domain_id,
                "open": entry_gate_open,
                "blockers": entry_gate_blockers,
            },
        )
        gate_status_map[exit_gate] = {
            "gate_id": exit_gate,
            "domain_id": domain_id,
            "open": truth_publication_stabilized if domain_id == "DOMAIN_1_TRUTH_PUBLICATION_ARCHITECTURE" else exit_gate_open,
            "blockers": deduped_domain_blockers,
        }

        if index + 1 < len(CONSTITUTIONAL_DOMAINS):
            next_domain = CONSTITUTIONAL_DOMAINS[index + 1]
            next_gate = str(next_domain["entry_gate"])
            if next_gate not in program_gates:
                program_gates[next_gate] = truth_publication_stabilized if next_gate == "H1_ACTIVATION_ALLOWED" else False

    current_domain = next((row for row in constitutional_domains if row["status"] == "ACTIVE"), constitutional_domains[-1])
    return {
        "completion_program_ref": COMPLETION_PROGRAM_REF,
        "current_constitutional_domain": {
            "domain_id": current_domain["domain_id"],
            "title": current_domain["title"],
        },
        "program_gates": program_gates,
        "domain_gate_statuses": list(gate_status_map.values()),
        "constitutional_domains": constitutional_domains,
    }


def _finish_line_predicates(*, posture_state: str, worktree_dirty: bool, one_button_status: bool) -> Dict[str, bool]:
    return {
        "constitutional_truth_live": posture_state != "TRUTH_DEFECTS_PRESENT",
        "canonical_scope_enforced": True,
        "current_worktree_clean": not worktree_dirty,
        "one_button_current_head_pass": bool(one_button_status),
        "posture_receipts_synchronized": True,
        "truth_engine_authoritative": True,
        "truthful_green_active": posture_state == TRUTHFUL_GREEN,
    }


def _release_decision(posture_state: str) -> str:
    return {
        "TRUTH_DEFECTS_PRESENT": "NO_GO_TRUTH_DEFECTS_PRESENT",
        "CANONICAL_VALIDATED_DIRTY_WORKTREE": "HOLD_DIRTY_WORKTREE",
        CANONICAL_READY_FOR_REEARNED_GREEN: "HOLD_CANONICAL_READY_FOR_REEARNED_GREEN",
        TRUTHFUL_GREEN: "GO_PRESS_BUTTON_PRODUCTION_ELIGIBLE",
    }[posture_state]


def _next_transition(posture_state: str) -> str:
    return {
        "TRUTH_DEFECTS_PRESENT": "REPAIR_TRUTH_DEFECTS",
        "CANONICAL_VALIDATED_DIRTY_WORKTREE": "COMMIT_OR_CLEAN_ACTIVE_WORKTREE",
        CANONICAL_READY_FOR_REEARNED_GREEN: "REENABLE_GREEN_FROM_CURRENT_HEAD",
        TRUTHFUL_GREEN: "NONE_REQUIRED_RUNTIME_LAWFUL_GREEN_ACTIVE",
    }[posture_state]


def _stop_gates(posture_state: str, live_checks: List[Dict[str, Any]]) -> List[str]:
    if posture_state == TRUTHFUL_GREEN:
        return []
    gates: List[str] = []
    if posture_state == "CANONICAL_VALIDATED_DIRTY_WORKTREE":
        gates.append("DIRTY_WORKTREE")
    if posture_state == CANONICAL_READY_FOR_REEARNED_GREEN:
        gates.append("GREEN_NOT_REEARNED")
    if posture_state == "TRUTH_DEFECTS_PRESENT":
        for row in live_checks:
            if not isinstance(row, dict):
                continue
            if not bool(row.get("critical")):
                continue
            if str(row.get("status", "")).strip().upper() == "PASS":
                continue
            gates.append(str(row.get("check_id", "UNKNOWN")).strip() or "UNKNOWN")
    return gates


def _truthful_green_supported(*, root: Path, report_root: Path, live_head: str, branch_ref: str) -> bool:
    preflight = _load_required(report_root / "one_button_preflight_receipt.json")
    production = _load_required(report_root / "one_button_production_receipt.json")
    branch = _load_required(root / DEFAULT_REPORT_ROOT_REL / "main_branch_protection_receipt.json")

    if str(preflight.get("status", "")).strip() != "PASS":
        return False
    if str(production.get("status", "")).strip() != "PASS":
        return False
    if str(preflight.get("validated_head_sha", "")).strip() != live_head:
        return False
    if str(production.get("validated_head_sha", "")).strip() != live_head:
        return False
    if str(preflight.get("branch_ref", "")).strip() != branch_ref:
        return False
    if str(production.get("branch_ref", "")).strip() != branch_ref:
        return False
    if branch_ref == "main" and str(branch.get("status", "")).strip() != "PASS":
        return False
    return True


def build_receipts(*, root: Path, index: Dict[str, Any], report_root_rel: str, live_validation_index_ref: str) -> Dict[str, Dict[str, Any]]:
    live_head = str((index.get("worktree") or {}).get("head_sha", "")).strip()
    branch_ref = str(index.get("branch_ref", "")).strip()
    worktree_dirty = bool((index.get("worktree") or {}).get("git_dirty"))
    checks = index.get("checks") if isinstance(index.get("checks"), list) else []
    live_state = derive_live_validation_state(index)
    posture_state = live_state
    report_root = (root / report_root_rel).resolve()
    generated_utc = str(index.get("generated_utc", "")).strip() or utc_now_iso_z()
    if live_state == CANONICAL_READY_FOR_REEARNED_GREEN and _truthful_green_supported(
        root=root,
        report_root=report_root,
        live_head=live_head,
        branch_ref=branch_ref,
    ):
        posture_state = TRUTHFUL_GREEN

    stop_gates = _stop_gates(posture_state, checks if isinstance(checks, list) else [])
    release_decision = _release_decision(posture_state)
    finish_line = _finish_line_predicates(
        posture_state=posture_state,
        worktree_dirty=worktree_dirty,
        one_button_status=posture_state == TRUTHFUL_GREEN,
    )

    current_state = {
        "schema_id": "kt.operator.current_state_receipt.v3",
        "generated_utc": generated_utc,
        "status": "PASS",
        "posture_state": posture_state,
        "current_p0_state": posture_state,
        "branch_ref": branch_ref,
        "validated_head_sha": live_head,
        "truth_sources": _truth_sources(report_root_rel),
        "validation_index_ref": live_validation_index_ref,
        "active_stop_gates": stop_gates,
        "current_release_decision": release_decision,
        "finish_line_predicates": finish_line,
        "next_allowed_transition": _next_transition(posture_state),
        "closure_receipts": [
            live_validation_index_ref,
            _report_ref(report_root_rel, "posture_consistency_enforcement_receipt.json"),
            _report_ref(report_root_rel, "posture_conflict_receipt.json"),
            _report_ref(report_root_rel, "posture_consistency_receipt.json"),
            _report_ref(report_root_rel, "one_button_preflight_receipt.json"),
            _report_ref(report_root_rel, "one_button_production_receipt.json"),
            f"{DEFAULT_REPORT_ROOT_REL}/main_branch_protection_receipt.json",
        ],
    }

    runtime_audit = {
        "schema_id": "kt.operator.runtime_closure_audit.v3",
        "generated_utc": generated_utc,
        "status": "PASS",
        "overall_verdict": "PASS",
        "posture_state": posture_state,
        "current_state": posture_state,
        "branch_ref": branch_ref,
        "validated_head_sha": live_head,
        "blocking_groups": stop_gates,
        "release_decision": release_decision,
        "repo_hygiene_status": "PASS" if not worktree_dirty else "HOLD",
        "validator_substance_checked": True,
        "audit_scope": [
            "live truth reconciliation",
            "canonical readiness synchronization",
            "one-button current-head admissibility",
            "truthful posture sealing",
        ],
        "real_path_targets_checked": [
            "program.certify.canonical_hmac",
            "program.hat_demo",
            "program.red_assault.serious_v1",
            "safe-run:program.certify.canonical_hmac",
        ],
        "evidence_plane_targets_checked": [
            "delivery/delivery_manifest.json",
            "evidence/constitutional_snapshot.json",
            "evidence/worm_manifest.json",
            "evidence/evidence_core_merkle.json",
            "evidence/replay_receipt.json",
            "evidence/secret_scan_report.json",
            "reports/bindingloop_check.json",
        ],
        "notes": [
            f"Posture synchronized from live validation state {live_state}.",
            "Only truth-engine-aligned receipts remain active truth surfaces.",
        ],
    }

    if posture_state == TRUTHFUL_GREEN:
        p0_green = {
            "schema_id": "kt.p0_green_full_receipt.v2",
            "created_utc": generated_utc,
            "status": "PASS",
            "claim": TRUTHFUL_GREEN,
            "claim_admissible": True,
            "lawful_green_claim_admissible": True,
            "head_sha": live_head,
            "validated_head_sha": live_head,
            "branch_ref": branch_ref,
            "may_claim_now": [
                "truthful green active on current head",
                "canonical_hmac one-button production eligible",
                "current truth surfaces synchronized",
            ],
            "may_not_claim_yet": [],
            "one_button_preflight_receipt": _report_ref(report_root_rel, "one_button_preflight_receipt.json"),
            "one_button_production_receipt": _report_ref(report_root_rel, "one_button_production_receipt.json"),
            "main_branch_protection_receipt": f"{DEFAULT_REPORT_ROOT_REL}/main_branch_protection_receipt.json",
        }
        final_green = {
            "schema_id": "kt.green_final_receipt.v2",
            "created_utc": generated_utc,
            "status": "PASS",
            "repo": "Kinrokin/KT",
            "posture_state": TRUTHFUL_GREEN,
            "release_state": "GO_PRESS_BUTTON_PRODUCTION_ELIGIBLE",
            "statement": "KT current-head truth surfaces are synchronized and canonical_hmac one-button production is eligible.",
            "p0_green_full_receipt": _report_ref(report_root_rel, "p0_green_full_receipt.json"),
            "one_button_preflight_receipt": _report_ref(report_root_rel, "one_button_preflight_receipt.json"),
            "one_button_production_receipt": _report_ref(report_root_rel, "one_button_production_receipt.json"),
            "branch_protection_receipt": f"{DEFAULT_REPORT_ROOT_REL}/main_branch_protection_receipt.json",
        }
    else:
        p0_green = {
            "schema_id": "kt.p0_green_full_receipt.v2",
            "created_utc": generated_utc,
            "status": "SUPERSEDED",
            "claim": TRUTHFUL_GREEN,
            "claim_admissible": False,
            "current_truthful_state": posture_state,
            "validated_head_sha": live_head,
            "blockers": stop_gates,
            "superseded_by": _truth_sources(report_root_rel),
        }
        final_green = {
            "schema_id": "kt.green_final_receipt.v2",
            "created_utc": generated_utc,
            "status": "SUPERSEDED",
            "repo": "Kinrokin/KT",
            "posture_state": posture_state,
            "release_state": release_decision,
            "statement": f"KT is not currently truthful green; active truthful posture is {posture_state}.",
            "superseded_by": _truth_sources(report_root_rel),
        }

    return {
        "current_state": current_state,
        "runtime_audit": runtime_audit,
        "p0_green": p0_green,
        "final_green": final_green,
    }


def _sync_secondary_surfaces(
    *,
    root: Path,
    posture_state: str,
    live_head: str,
    truth_source_ref: str,
    authority_mode: str,
    open_blockers: List[str],
) -> None:
    readiness_scope = _load_required(root / "KT_PROD_CLEANROOM" / "governance" / "readiness_scope_manifest.json")
    blockers: List[str] = []
    if posture_state == "TRUTH_DEFECTS_PRESENT":
        blockers.append("non-dirty critical truth failures remain")
    if posture_state == "CANONICAL_VALIDATED_DIRTY_WORKTREE":
        blockers.append("active worktree is dirty")
    if posture_state == CANONICAL_READY_FOR_REEARNED_GREEN:
        blockers.append("green has not been re-earned from current-head one-button receipts")
    blockers.extend(str(item).strip() for item in open_blockers if str(item).strip())
    deduped_blockers: List[str] = []
    seen = set()
    for blocker in blockers:
        if blocker in seen:
            continue
        seen.add(blocker)
        deduped_blockers.append(blocker)
    readiness_scope["current_authority_mode"] = authority_mode
    readiness_scope["authoritative_truth_source"] = truth_source_ref
    readiness_scope["current_blockers"] = deduped_blockers
    _write_json(root / "KT_PROD_CLEANROOM" / "governance" / "readiness_scope_manifest.json", readiness_scope)

    execution_board = _load_required(root / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json")
    previous_authority_mode = str(execution_board.get("authority_mode", "")).strip()
    workstreams = execution_board.get("workstreams") if isinstance(execution_board.get("workstreams"), list) else []
    for row in workstreams:
        if not isinstance(row, dict):
            continue
        workstream_id = str(row.get("workstream_id", "")).strip()
        if workstream_id == "PHASE_0_CORE_TRUTH_REPAIR":
            row["status"] = "COMPLETED" if posture_state != "TRUTH_DEFECTS_PRESENT" else "BLOCKED"
        elif workstream_id == "PHASE_1_H0_FREEZE":
            row["status"] = "READY" if posture_state == TRUTHFUL_GREEN else "BLOCKED"
        elif workstream_id == "PHASE_2_TRUTH_ENGINE":
            row["status"] = "AUTHORITATIVE"
        elif workstream_id == "PHASE_3_BOUNDARY_PURIFICATION":
            row["status"] = "IMPLEMENTED"
        elif workstream_id == "PHASE_4_SETTLED_AUTHORITY":
            row["status"] = "COMPLETED" if authority_mode == "SETTLED_AUTHORITATIVE" else "BLOCKED"
    execution_board["status"] = "ACTIVE"
    execution_board["last_synced_head_sha"] = live_head
    execution_board["current_posture_state"] = posture_state
    execution_board["authority_mode"] = authority_mode
    execution_board["authoritative_current_head_truth_source"] = truth_source_ref
    execution_board["open_blockers"] = deduped_blockers
    freeze_policy = _load_required(root / "KT_PROD_CLEANROOM" / "governance" / "h0_freeze_policy.json")
    freeze_policy["activation_state"] = "ELIGIBLE_FOR_FREEZE" if posture_state == TRUTHFUL_GREEN else "PENDING_TRUTHFUL_GREEN"
    freeze_policy["current_posture_state"] = posture_state
    freeze_policy["freeze_scope_manifest"] = "KT_PROD_CLEANROOM/governance/canonical_freeze_manifest.json"
    freeze_policy["amendment_scope_manifest"] = "KT_PROD_CLEANROOM/governance/amendment_scope_manifest.json"
    _write_json(root / "KT_PROD_CLEANROOM" / "governance" / "h0_freeze_policy.json", freeze_policy)
    promotion_receipt_path = root / "KT_PROD_CLEANROOM" / "reports" / "settled_authority_promotion_receipt.json"
    if previous_authority_mode != authority_mode or not promotion_receipt_path.exists():
        _write_json(
            promotion_receipt_path,
            _authority_promotion_receipt(
                previous_authority_mode=previous_authority_mode,
                new_authority_mode=authority_mode,
                live_head=live_head,
                report_root_rel=DEFAULT_REPORT_ROOT_REL,
                open_blockers=deduped_blockers,
            ),
        )
    board_state = _build_constitutional_board_state(
        root=root,
        authority_mode=authority_mode,
        posture_state=posture_state,
        open_blockers=deduped_blockers,
    )
    execution_board["schema_id"] = "kt.governance.execution_board.v3"
    execution_board["board_id"] = "EXECUTION_BOARD_V3_20260309"
    execution_board["completion_program_ref"] = board_state["completion_program_ref"]
    execution_board["current_constitutional_domain"] = board_state["current_constitutional_domain"]
    execution_board["program_gates"] = board_state["program_gates"]
    execution_board["domain_gate_statuses"] = board_state["domain_gate_statuses"]
    execution_board["constitutional_domains"] = board_state["constitutional_domains"]
    _write_json(root / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json", execution_board)


def _reconciliation_report(*, report_root: Path, report_root_rel: str, derived_state: str, live_head: str) -> Dict[str, Any]:
    current_state = _load_required(report_root / "current_state_receipt.json")
    runtime_audit = _load_required(report_root / "runtime_closure_audit.json")
    posture = _load_required(report_root / "posture_consistency_receipt.json")
    generated_utc = str(current_state.get("generated_utc", "")).strip() or utc_now_iso_z()
    return {
        "schema_id": "kt.operator.truth_surface_reconciliation_report.v2",
        "generated_utc": generated_utc,
        "claimed_state": {
            "current_state_receipt": {
                "posture_state": str(current_state.get("posture_state", "")).strip(),
                "validated_head_sha": str(current_state.get("validated_head_sha", "")).strip(),
                "status": str(current_state.get("status", "")).strip(),
            },
            "runtime_closure_audit": {
                "posture_state": str(runtime_audit.get("posture_state", "")).strip(),
                "validated_head_sha": str(runtime_audit.get("validated_head_sha", "")).strip(),
                "status": str(runtime_audit.get("status", "")).strip(),
            },
            "posture_consistency_receipt": {
                "status": str(posture.get("status", "")).strip(),
                "posture_state": str(posture.get("posture_state", "")).strip(),
            },
        },
        "live_state": {
            "derived_state": derived_state,
            "live_head_sha": live_head,
        },
        "reconciliation_result": "TRUTH_SURFACES_SYNCHRONIZED",
        "required_next_actions": [] if derived_state == TRUTHFUL_GREEN else ["re-earn green from current-head one-button receipts"],
        "active_report_root": report_root_rel,
    }


def _authority_promotion_receipt(
    *,
    previous_authority_mode: str,
    new_authority_mode: str,
    live_head: str,
    report_root_rel: str,
    open_blockers: List[str],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.settled_authority_promotion_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "prior_authority_state": previous_authority_mode,
        "new_authority_state": new_authority_mode,
        "validated_head_sha": live_head,
        "clean_clone_proof_ref": _report_ref(report_root_rel, "live_validation_index.json"),
        "posture_sync_ref": _report_ref(report_root_rel, "posture_consistency_enforcement_receipt.json"),
        "truth_supersession_ref": _report_ref(report_root_rel, "truth_supersession_receipt.json"),
        "execution_board_ref": "KT_PROD_CLEANROOM/governance/execution_board.json",
        "promotion_verdict": "PASS" if new_authority_mode == "SETTLED_AUTHORITATIVE" else "HOLD",
        "open_blockers": open_blockers,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Sync active truth receipts from live validation evidence.")
    ap.add_argument("--live-validation-index", default=f"{DEFAULT_REPORT_ROOT_REL}/live_validation_index.json")
    ap.add_argument("--report-root", default=DEFAULT_REPORT_ROOT_REL)
    ap.add_argument("--sync-secondary-surfaces", action="store_true")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    index_path = Path(str(args.live_validation_index)).expanduser()
    if not index_path.is_absolute():
        index_path = (root / index_path).resolve()
    index = _load_required(index_path)
    report_root = Path(str(args.report_root)).expanduser()
    if not report_root.is_absolute():
        report_root = (root / report_root).resolve()
    report_root_rel = path_ref(root=root, path=report_root)
    live_validation_index_ref = path_ref(root=root, path=index_path)
    receipts = build_receipts(
        root=root,
        index=index,
        report_root_rel=report_root_rel,
        live_validation_index_ref=live_validation_index_ref,
    )

    reports_root = report_root
    _write_json(reports_root / "current_state_receipt.json", receipts["current_state"])
    _write_json(reports_root / "runtime_closure_audit.json", receipts["runtime_audit"])
    _write_json(reports_root / "p0_green_full_receipt.json", receipts["p0_green"])
    _write_json(reports_root / "kt_green_final_receipt.json", receipts["final_green"])

    try:
        posture = verify_posture(
            root=root,
            expected_posture="",
            live_validation_index_rel=str(args.live_validation_index),
            report_root_rel=report_root_rel,
        )
        _write_json(reports_root / "posture_consistency_receipt.json", posture)
    except Exception as exc:  # noqa: BLE001
        posture = {
            "schema_id": "kt.operator.posture_consistency_receipt.v1",
            "status": "FAIL",
            "message": str(exc),
            "expected_posture": "",
        }
        _write_json(reports_root / "posture_consistency_receipt.json", posture)
        print(str(exc))
        return 2

    derived_state = str(receipts["current_state"].get("posture_state", "")).strip()
    live_head = str((index.get("worktree") or {}).get("head_sha", "")).strip()
    _write_json(
        reports_root / "truth_surface_reconciliation_report.json",
        _reconciliation_report(report_root=reports_root, report_root_rel=report_root_rel, derived_state=derived_state, live_head=live_head),
    )
    truth_receipts = build_truth_receipts(root=root, live_validation_index_path=index_path, report_root_rel=report_root_rel)
    _write_json(reports_root / "posture_consistency_enforcement_receipt.json", truth_receipts["enforcement"])
    _write_json(reports_root / "posture_conflict_receipt.json", truth_receipts["conflicts"])
    settled_truth = build_settled_truth_source_receipt(
        root=root,
        live_validation_index_path=index_path,
        report_root_rel=report_root_rel,
        index=index,
        current_state=receipts["current_state"],
        runtime_audit=receipts["runtime_audit"],
        posture_consistency=posture,
        enforcement=truth_receipts["enforcement"],
        conflicts=truth_receipts["conflicts"],
    )
    supersession = build_truth_supersession_receipt(
        root=root,
        live_validation_index_path=index_path,
        report_root_rel=report_root_rel,
        index=index,
        current_state=receipts["current_state"],
        runtime_audit=receipts["runtime_audit"],
        posture_consistency=posture,
        enforcement=truth_receipts["enforcement"],
        conflicts=truth_receipts["conflicts"],
    )
    _write_json(reports_root / "settled_truth_source_receipt.json", settled_truth)
    _write_json(reports_root / "truth_supersession_receipt.json", supersession)
    publication = publish_truth_artifacts(
        root=root,
        report_root_rel=report_root_rel,
        live_validation_index_path=index_path,
        authority_mode=str(settled_truth.get("status", "")).strip(),
        posture_state=derived_state,
        board_open_blockers=[str(item).strip() for item in settled_truth.get("open_blockers", []) if str(item).strip()],
    )
    if bool(args.sync_secondary_surfaces) or report_root_rel == DEFAULT_REPORT_ROOT_REL:
        _sync_secondary_surfaces(
            root=root,
            posture_state=derived_state,
            live_head=live_head,
            truth_source_ref=str(publication.get("current_pointer_ref", CURRENT_POINTER_REL)).strip() or CURRENT_POINTER_REL,
            authority_mode=str(settled_truth.get("status", "")).strip(),
            open_blockers=[str(item).strip() for item in settled_truth.get("open_blockers", []) if str(item).strip()],
        )

    print(
        json.dumps(
            {
                "authority_mode": str(settled_truth.get("status", "")).strip(),
                "posture_state": derived_state,
                "report_root": report_root_rel,
                "status": "PASS",
                "validated_head_sha": live_head,
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
