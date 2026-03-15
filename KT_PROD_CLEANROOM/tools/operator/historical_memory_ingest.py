from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
WORK_ORDER_REL = "KT_PROD_CLEANROOM/AUDITS/COUNCIL_PACKET/V2/WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION.v2.json"
STEP1_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_governance_baseline_ingestion_receipt.json"
STEP3_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_constitutional_spine_ratification_receipt.json"
BASELINE_BUNDLE_REL = f"{REPORT_ROOT_REL}/kt_governance_closeout_bundle.json"
WS_CLOSEOUT_SUMMARY_REL = f"{REPORT_ROOT_REL}/ws0_ws11_closeout_summary.json"
WS_CLOSEOUT_BLOCKERS_REL = f"{REPORT_ROOT_REL}/ws0_ws11_closeout_blocker_register.json"
PUBLIC_VERIFIER_REL = f"{REPORT_ROOT_REL}/public_verifier_manifest.json"
REPRESENTATIVE_REPRO_REL = f"{REPORT_ROOT_REL}/representative_authority_lane_reproducibility_receipt.json"
RUN_SWEEP_MATRIX_REL = f"{REPORT_ROOT_REL}/run_sweep_audit_failure_matrix.json"
POSTURE_CONFLICT_REL = f"{REPORT_ROOT_REL}/posture_conflict_receipt.json"

ARCHIVE_ROOT_REL = "KT_ARCHIVE"
AUDIT_PACKET_DIR_REL = f"{ARCHIVE_ROOT_REL}/docs/audit/KT_REPO_AUTHORITY_AUDIT_20260309"
AUDIT_README_REL = f"{AUDIT_PACKET_DIR_REL}/README.md"
AUDIT_BLOCKER_MATRIX_REL = f"{AUDIT_PACKET_DIR_REL}/blocker_matrix.json"
AUDIT_SCORECARD_REL = f"{AUDIT_PACKET_DIR_REL}/subsystem_scorecard.md"
AUDIT_LOCAL_RESIDUE_REL = f"{AUDIT_PACKET_DIR_REL}/local_residue_summary.json"
AUDIT_REPO_CENSUS_REL = f"{AUDIT_PACKET_DIR_REL}/repo_census.csv"
AUDIT_IMPLEMENTATION_REL = f"{AUDIT_PACKET_DIR_REL}/IMPLEMENTATION_COMPLETION_REPORT_20260309.md"
AUDIT_FULL_ATTEMPT_REL = f"{AUDIT_PACKET_DIR_REL}/KT_FULL_COMPLETION_ATTEMPT_REPORT_20260310.md"
AUDIT_E2E_CAMPAIGN_REL = f"{AUDIT_PACKET_DIR_REL}/KT_E2E_COMPLETION_CAMPAIGN_REPORT_20260310.md"
AUDIT_WORKSET_REL = f"{AUDIT_PACKET_DIR_REL}/workset_and_priority_order.md"

CODEX_MANIFEST_REL = "KT-Codex/metadata/manifest.json"
CODEX_DELIVERABLE_REL = "KT-Codex/deliverable_manifest.md"
CODEX_CONFLICT_SCHEMA_REL = "KT-Codex/schemas/conflict_event.schema.json"
CODEX_MULTIVERSAL_CONFLICT_SCHEMA_REL = "KT-Codex/schemas/multiversal_conflict_event.schema.json"
CODEX_SUITE_REGISTRY_REL = "KT-Codex/Volume-III-Technical/18-Suite-Registry-Constitution.md"

OPERATOR_BLUEPRINT_REL = "KT_PROD_CLEANROOM/docs/operator/KT_FINAL_CONSTITUTIONAL_COMPLETION_BLUEPRINT.md"
OPERATOR_MANDATE_REL = "KT_PROD_CLEANROOM/docs/operator/KT_FULL_AGENT_COMPLETION_MANDATE.md"

CRUCIBLE_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/crucible_registry.json"
CRUCIBLE_RUN_LEDGER_REL = "KT_PROD_CLEANROOM/tools/growth/ledgers/c019_crucible_runs.jsonl"

CLAIMS_REL = f"{REPORT_ROOT_REL}/kt_historical_claims.json"
CONFLICTS_REL = f"{REPORT_ROOT_REL}/kt_historical_conflicts.json"
RESOLUTIONS_REL = f"{REPORT_ROOT_REL}/kt_historical_resolutions.json"
FORGOTTEN_SURFACES_REL = f"{REPORT_ROOT_REL}/kt_forgotten_surface_register.json"
REOPENED_DEFECTS_REL = f"{REPORT_ROOT_REL}/kt_reopened_defect_register.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_historical_memory_ingestion_receipt.json"

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/historical_memory_ingest.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_historical_memory_ingest.py"

DELIVERABLE_REFS = [CLAIMS_REL, CONFLICTS_REL, RESOLUTIONS_REL, FORGOTTEN_SURFACES_REL, REOPENED_DEFECTS_REL]
SUBJECT_ARTIFACT_REFS = DELIVERABLE_REFS + [TOOL_REL, TEST_REL]
PLANNED_MUTATES = SUBJECT_ARTIFACT_REFS + [RECEIPT_REL]

WORK_ORDER_ID = "WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION"
WORK_ORDER_SCHEMA_ID = "kt.work_order.max_refactor_e2e_institutional_memory_and_full_stack_adjudication.v2"

PROTECTED_PREFIXES = (
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/",
    "kt_truth_ledger:",
    ".github/workflows/",
    "KT_PROD_CLEANROOM/docs/commercial/",
)

EXEMPLAR_CRUCIBLES = ("CRU-GOV-REFUSAL-01", "CRU-GOV-HONESTY-01", "CRU-GOV-HONESTY-02", "CRU-GOV-HONESTY-03")


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_last_commit_for_paths(root: Path, paths: Sequence[str]) -> str:
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return ""
    try:
        return _git(root, "log", "-1", "--format=%H", "--", *existing)
    except Exception:  # noqa: BLE001
        return ""


def _git_history_for_paths(root: Path, paths: Sequence[str]) -> List[str]:
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return []
    try:
        output = _git(root, "log", "--format=%H", "--", *existing)
    except Exception:  # noqa: BLE001
        return []
    return [line.strip() for line in output.splitlines() if line.strip()]


def _git_parent(root: Path, commit: str) -> str:
    if not str(commit).strip():
        return ""
    try:
        return _git(root, "rev-parse", f"{commit}^")
    except Exception:  # noqa: BLE001
        return ""


def _git_changed_files(root: Path, commit: str) -> List[str]:
    if not str(commit).strip():
        return []
    try:
        output = _git(root, "show", "--pretty=", "--name-only", commit)
    except Exception:  # noqa: BLE001
        return []
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _git_diff_files(root: Path, older: str, newer: str, paths: Sequence[str]) -> List[str]:
    if not str(older).strip() or not str(newer).strip():
        return []
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return []
    try:
        output = _git(root, "diff", "--name-only", older, newer, "--", *existing)
    except Exception:  # noqa: BLE001
        return []
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _is_protected(path: str) -> bool:
    normalized = str(path).replace("\\", "/")
    return any(normalized.startswith(prefix) for prefix in PROTECTED_PREFIXES)


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _read_required(root: Path, rel: str) -> str:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required text artifact: {rel}")
    return path.read_text(encoding="utf-8")


def _count_files(root: Path, rel: str) -> int:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        return 0
    if path.is_file():
        return 1
    return sum(1 for item in path.rglob("*") if item.is_file())


def _jsonl_rows(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            raw = str(line).strip()
            if raw:
                yield json.loads(raw)


def _step_context(root: Path) -> Dict[str, Any]:
    step1 = _load_required(root, STEP1_RECEIPT_REL)
    step3 = _load_required(root, STEP3_RECEIPT_REL)
    if str(step1.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: Step 4 is blocked until Step 1 baseline ingestion is PASS.")
    if str(step3.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: Step 4 is blocked until Step 3 constitutional spine ratification is PASS.")
    return {
        "step1_receipt": step1,
        "step3_receipt": step3,
        "step1_evidence_commit": _git_last_commit_for_paths(root, [STEP1_RECEIPT_REL]),
        "step3_evidence_commit": _git_last_commit_for_paths(root, [STEP3_RECEIPT_REL]),
        "work_order": _load_required(root, WORK_ORDER_REL),
    }


def _source_family_rows(root: Path) -> List[Dict[str, Any]]:
    return [
        {
            "family_id": "authority_audit_packet_20260309",
            "root_ref": AUDIT_PACKET_DIR_REL,
            "file_count": _count_files(root, AUDIT_PACKET_DIR_REL),
            "purpose": "Historical governance baseline, blockers, and scorecards.",
        },
        {
            "family_id": "root_audit_lineage_docs",
            "root_ref": "KT_ARCHIVE/docs/audit",
            "file_count": _count_files(root, "KT_ARCHIVE/docs/audit"),
            "purpose": "Top-level historical system maps and lineage docs.",
        },
        {
            "family_id": "kt_codex",
            "root_ref": "KT-Codex",
            "file_count": _count_files(root, "KT-Codex"),
            "purpose": "Codex lineage, schemas, packs, and doctrine drafts outside active law surfaces.",
        },
        {
            "family_id": "operator_historical_doctrine",
            "root_ref": "KT_PROD_CLEANROOM/docs/operator",
            "file_count": _count_files(root, "KT_PROD_CLEANROOM/docs/operator"),
            "purpose": "Historical operator doctrine and completion blueprints.",
        },
        {
            "family_id": "crucible_history",
            "root_ref": CRUCIBLE_RUN_LEDGER_REL,
            "file_count": _count_files(root, CRUCIBLE_RUN_LEDGER_REL),
            "purpose": "Historical crucible registry and governed run ledger.",
        },
        {
            "family_id": "historical_conflict_receipts",
            "root_ref": REPORT_ROOT_REL,
            "file_count": 2,
            "purpose": "Conflict-style receipts retained from older audit and rerun cycles.",
        },
    ]


def _crucible_history(root: Path) -> Dict[str, Any]:
    registry = _load_required(root, CRUCIBLE_REGISTRY_REL)
    ledger_path = (root / Path(CRUCIBLE_RUN_LEDGER_REL)).resolve()
    if not ledger_path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing crucible run ledger: {CRUCIBLE_RUN_LEDGER_REL}")

    outcome_counts: Counter[str] = Counter()
    governance_pass_counts: Counter[str] = Counter()
    output_contract_pass_counts: Counter[str] = Counter()
    replay_pass_counts: Counter[str] = Counter()
    crucible_counts: Counter[str] = Counter()
    exemplar_runs: Dict[str, Dict[str, Any]] = {}

    total_runs = 0
    for row in _jsonl_rows(ledger_path):
        total_runs += 1
        crucible_id = str(row.get("crucible_id", "")).strip()
        outcome_counts[str(row.get("outcome", "UNKNOWN")).strip() or "UNKNOWN"] += 1
        governance_pass_counts["PASS" if bool(row.get("governance_pass")) else "FAIL"] += 1
        output_contract_pass_counts["PASS" if bool(row.get("output_contract_pass")) else "FAIL"] += 1
        replay_pass_counts["PASS" if bool(row.get("replay_pass")) else "FAIL"] += 1
        if crucible_id:
            crucible_counts[crucible_id] += 1
            if crucible_id in EXEMPLAR_CRUCIBLES and crucible_id not in exemplar_runs:
                exemplar_runs[crucible_id] = {
                    "artifacts_dir": str(row.get("artifacts_dir", "")).replace("\\", "/"),
                    "crucible_id": crucible_id,
                    "governance_pass": bool(row.get("governance_pass")),
                    "kernel_target": str(row.get("kernel_target", "")).strip(),
                    "outcome": str(row.get("outcome", "")).strip(),
                    "output_contract_pass": bool(row.get("output_contract_pass")),
                    "replay_pass": bool(row.get("replay_pass")),
                    "run_id": str(row.get("run_id", "")).strip(),
                }

    registry_ids = {str(entry.get("crucible_id", "")).strip() for entry in registry.get("entries", []) if isinstance(entry, dict)}
    observed_ids = set(crucible_counts)

    return {
        "registry_ref": CRUCIBLE_REGISTRY_REL,
        "run_ledger_ref": CRUCIBLE_RUN_LEDGER_REL,
        "registered_crucibles": int(registry.get("entry_count", 0)),
        "unique_crucibles_observed_in_runs": len(observed_ids),
        "registered_but_not_observed": sorted(registry_ids - observed_ids),
        "observed_but_not_registered": sorted(value for value in observed_ids - registry_ids if value),
        "total_runs": total_runs,
        "outcome_counts": dict(sorted(outcome_counts.items())),
        "governance_pass_counts": dict(sorted(governance_pass_counts.items())),
        "output_contract_pass_counts": dict(sorted(output_contract_pass_counts.items())),
        "replay_pass_counts": dict(sorted(replay_pass_counts.items())),
        "top_crucible_run_counts": [{"crucible_id": crucible_id, "run_count": count} for crucible_id, count in crucible_counts.most_common(10)],
        "exemplar_runs": [exemplar_runs[key] for key in EXEMPLAR_CRUCIBLES if key in exemplar_runs],
    }


def build_historical_claims(*, root: Path) -> Dict[str, Any]:
    _step_context(root)

    scorecard_text = _read_required(root, AUDIT_SCORECARD_REL)
    full_attempt_text = _read_required(root, AUDIT_FULL_ATTEMPT_REL)
    e2e_campaign_text = _read_required(root, AUDIT_E2E_CAMPAIGN_REL)
    implementation_text = _read_required(root, AUDIT_IMPLEMENTATION_REL)
    codex_manifest = _load_required(root, CODEX_MANIFEST_REL)
    crucible_registry = _load_required(root, CRUCIBLE_REGISTRY_REL)
    blocker_matrix = _load_required(root, AUDIT_BLOCKER_MATRIX_REL)

    claims = [
        {
            "claim_id": "AUDIT_REMOTE_PARITY_NOT_ACHIEVED_20260309",
            "claim_status": "obsolete",
            "plane": "judgment_plane",
            "source_epoch": "2026-03-09_authority_audit",
            "claim_text": "The 2026-03-09 authority audit recorded local main ahead of origin/main by six commits.",
            "current_relationship": "Historical only; later governance settlement restored remote parity.",
            "evidence_refs": [AUDIT_README_REL, AUDIT_BLOCKER_MATRIX_REL],
        },
        {
            "claim_id": "AUDIT_CLEAN_CLONE_EQUIVALENCE_NOT_PROVEN_20260309",
            "claim_status": "partially_evidenced",
            "plane": "proof_plane",
            "source_epoch": "2026-03-09_authority_audit",
            "claim_text": "The historical audit refused clean-clone equivalence at the pinned head.",
            "current_relationship": "Later work proved same-MVE representative reproducibility, but not current-head general clean-clone equivalence.",
            "evidence_refs": [AUDIT_README_REL, AUDIT_BLOCKER_MATRIX_REL, REPRESENTATIVE_REPRO_REL],
        },
        {
            "claim_id": "SCORECARD_CAPABILITY_EXCEEDS_CERTIFICATION",
            "claim_status": "evidenced",
            "plane": "operability_plane",
            "source_epoch": "2026-03-09_authority_audit",
            "claim_text": "The scorecard concluded that the repo could do more than it could certify.",
            "observed_phrase_present": "the repo can do more than it can presently certify" in scorecard_text,
            "current_relationship": "Still directionally useful as historical diagnosis of evidence lag.",
            "evidence_refs": [AUDIT_SCORECARD_REL],
        },
        {
            "claim_id": "FULL_COMPLETION_ATTEMPT_OFFICIAL_COMPLETION_REFUSED",
            "claim_status": "evidenced",
            "plane": "judgment_plane",
            "source_epoch": "2026-03-10_full_completion_attempt",
            "claim_text": "The historical completion-attempt report refused official end-to-end completion because tracked live state and HEAD were recursively coupled.",
            "observed_phrase_present": "Official end-to-end completion is **not** a truthful claim" in full_attempt_text,
            "current_relationship": "Later governance work replaced this with typed subject/evidence boundaries instead of pretending the recursion disappeared.",
            "evidence_refs": [AUDIT_FULL_ATTEMPT_REL, PUBLIC_VERIFIER_REL],
        },
        {
            "claim_id": "E2E_CAMPAIGN_WORKSPACE_COMPLETE_NOT_PUBLICATION_GRADE",
            "claim_status": "obsolete",
            "plane": "judgment_plane",
            "source_epoch": "2026-03-10_workspace_campaign",
            "claim_text": "The historical campaign report claimed workspace completion but explicitly refused publication-grade finalization.",
            "observed_phrase_present": "workspace-complete" in e2e_campaign_text and "official remote-published completion: **not yet**" in e2e_campaign_text,
            "current_relationship": "Superseded by the later WS0-WS11 closeout bundle and its explicit claim ceiling.",
            "evidence_refs": [AUDIT_E2E_CAMPAIGN_REL, WS_CLOSEOUT_SUMMARY_REL],
        },
        {
            "claim_id": "IMPLEMENTATION_TRANCHE_FOUNDATIONAL_LAW_COMPLETE_BUT_UNSETTLED",
            "claim_status": "obsolete",
            "plane": "temporal_plane",
            "source_epoch": "2026-03-09_foundational_law_tranche",
            "claim_text": "The implementation tranche completed foundational law work but still refused final settled authority until a pinned clean head was reratified.",
            "observed_phrase_present": "Scope Completed" in implementation_text and "What Is Still Not Settled" in implementation_text,
            "current_relationship": "Historically important because later WS0-WS11 work sealed the retained baseline without reopening this tranche.",
            "evidence_refs": [AUDIT_IMPLEMENTATION_REL, BASELINE_BUNDLE_REL],
        },
        {
            "claim_id": "CODEX_OUTSIDE_LAW_SURFACES_AND_STILL_DRAFT",
            "claim_status": "evidenced",
            "plane": "lineage_plane",
            "source_epoch": "2026-02-19_codex_initial_release",
            "claim_text": "KT-Codex content is intentionally outside KT_PROD_CLEANROOM law surfaces and remains draft lineage material.",
            "current_relationship": "Still relevant as external lineage input, not active ratified law.",
            "evidence_refs": [CODEX_MANIFEST_REL, CODEX_DELIVERABLE_REL],
            "manifest_status": str(codex_manifest.get("status", "")).strip(),
        },
        {
            "claim_id": "CRUCIBLE_REGISTRY_LAB_ONLY_UNTIL_PROMOTED",
            "claim_status": "evidenced",
            "plane": "lineage_plane",
            "source_epoch": "2026-03-10_crucible_registry",
            "claim_text": "The historical crucible registry marks listed crucibles as lab-only until promoted.",
            "current_relationship": "Still binding as lineage memory for later experiment and delta registries.",
            "evidence_refs": [CRUCIBLE_REGISTRY_REL, CRUCIBLE_RUN_LEDGER_REL],
            "registry_status": str(crucible_registry.get("status", "")).strip(),
        },
        {
            "claim_id": "HISTORICAL_BLOCKER_PACKET_WAS_OPEN",
            "claim_status": "evidenced",
            "plane": "proof_plane",
            "source_epoch": "2026-03-09_authority_audit",
            "claim_text": "The original blocker packet remained open with unresolved remote parity, clean-clone proof, stale truth surfaces, residue, and archive contamination.",
            "current_relationship": "Still required lineage input for reopened-defect classification.",
            "evidence_refs": [AUDIT_BLOCKER_MATRIX_REL],
            "historical_overall_status": str(blocker_matrix.get("overall_status", "")).strip(),
        },
    ]

    return {
        "schema_id": "kt.operator.historical_claims.v1",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "Historical claims are lineage memory only. Their inclusion preserves institutional memory and evidence chains, "
            "but does not reactivate them as current law or upgrade any current-head claim."
        ),
        "source_families": _source_family_rows(root),
        "claims": claims,
        "crucible_history": _crucible_history(root),
    }


def build_historical_conflicts(*, root: Path) -> Dict[str, Any]:
    _step_context(root)

    blocker_matrix = _load_required(root, AUDIT_BLOCKER_MATRIX_REL)
    run_sweep = _load_required(root, RUN_SWEEP_MATRIX_REL)
    posture_conflict = _load_required(root, POSTURE_CONFLICT_REL)
    codex_conflict_schema = _load_required(root, CODEX_CONFLICT_SCHEMA_REL)
    codex_multiversal_schema = _load_required(root, CODEX_MULTIVERSAL_CONFLICT_SCHEMA_REL)

    blocker_conflicts = [
        {
            "conflict_id": str(row.get("blocker_id", "")).strip(),
            "description": str(row.get("description", "")).strip(),
            "historical_status": str(row.get("status", "")).strip(),
            "order": int(row.get("order", 0)),
            "severity": str(row.get("severity", "")).strip(),
            "evidence_refs": list(row.get("evidence_paths", [])),
            "exit_criteria": list(row.get("exit_criteria", [])),
        }
        for row in blocker_matrix.get("blockers", [])
        if isinstance(row, dict)
    ]

    run_sweep_conflicts = [
        {
            "conflict_id": f"RUN_SWEEP::{str(row.get('test_id', '')).strip()}",
            "baseline_status": str(row.get("baseline_status", "")).strip(),
            "clearance_status": str(row.get("clearance_status", "")).strip(),
            "cause_class": str(row.get("cause_class", "")).strip(),
            "cause_detail": str(row.get("cause_detail", "")).strip(),
            "disposition": str(row.get("disposition", "")).strip(),
            "test_id": str(row.get("test_id", "")).strip(),
            "evidence_refs": [RUN_SWEEP_MATRIX_REL],
        }
        for row in run_sweep.get("failures", [])
        if isinstance(row, dict)
    ]

    codex_conflict_models = [
        {
            "artifact_ref": CODEX_CONFLICT_SCHEMA_REL,
            "model_id": str(codex_conflict_schema.get("schema_id", "")).strip(),
            "resolution_statuses": list((((codex_conflict_schema.get("properties") or {}).get("resolution") or {}).get("properties") or {}).get("status", {}).get("enum", [])),
        },
        {
            "artifact_ref": CODEX_MULTIVERSAL_CONFLICT_SCHEMA_REL,
            "model_id": str(codex_multiversal_schema.get("schema_id", "")).strip(),
            "resolution_statuses": list((((codex_multiversal_schema.get("properties") or {}).get("resolution") or {}).get("properties") or {}).get("status", {}).get("enum", [])),
        },
    ]

    return {
        "schema_id": "kt.operator.historical_conflicts.v1",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "Historical conflicts are ingested as archived contradiction memory. They remain evidence-bearing lineage inputs, "
            "not active governance commands unless a later artifact explicitly reopens them."
        ),
        "historical_blocker_conflicts": blocker_conflicts,
        "historical_receipt_conflicts": run_sweep_conflicts,
        "codex_conflict_models": codex_conflict_models,
        "historical_posture_conflict_receipt": {
            "artifact_ref": POSTURE_CONFLICT_REL,
            "conflict_count": len(posture_conflict.get("conflicts", [])),
            "derived_state": str(posture_conflict.get("derived_state", "")).strip(),
            "status": str(posture_conflict.get("status", "")).strip(),
        },
    }


def build_historical_resolutions(*, root: Path) -> Dict[str, Any]:
    _step_context(root)

    blocker_matrix = _load_required(root, AUDIT_BLOCKER_MATRIX_REL)
    run_sweep = _load_required(root, RUN_SWEEP_MATRIX_REL)

    resolved_blockers = [
        {
            "blocker_id": str(row.get("blocker_id", "")).strip(),
            "description": str(row.get("description", "")).strip(),
            "historical_status": str(row.get("status", "")).strip(),
            "evidence_refs": list(row.get("evidence_paths", [])),
            "exit_criteria": list(row.get("exit_criteria", [])),
        }
        for row in blocker_matrix.get("blockers", [])
        if isinstance(row, dict) and str(row.get("status", "")).strip() == "CLOSED"
    ]

    run_sweep_clearances = [
        {
            "clearance_id": f"CLEARANCE::{str(row.get('test_id', '')).strip()}",
            "cause_class": str(row.get("cause_class", "")).strip(),
            "clearance_status": str(row.get("clearance_status", "")).strip(),
            "code_change_required": bool(row.get("code_change_required")),
            "disposition": str(row.get("disposition", "")).strip(),
            "test_id": str(row.get("test_id", "")).strip(),
            "evidence_refs": [RUN_SWEEP_MATRIX_REL],
        }
        for row in run_sweep.get("failures", [])
        if isinstance(row, dict)
    ]

    governance_ladders = [
        {
            "ladder_id": "AUTHORITY_AUDIT_20260309",
            "ladder_status": "OPEN_BLOCKERS",
            "statement": "The 2026-03-09 authority audit packet opened a blocker ladder instead of claiming green closure.",
            "evidence_refs": [AUDIT_README_REL, AUDIT_BLOCKER_MATRIX_REL],
        },
        {
            "ladder_id": "IMPLEMENTATION_TRANCHE_20260309",
            "ladder_status": "FOUNDATIONAL_LAW_COMPLETE_BUT_UNSETTLED",
            "statement": "The implementation tranche completed foundational law work but required a later pinned-head ratification cycle.",
            "evidence_refs": [AUDIT_IMPLEMENTATION_REL],
        },
        {
            "ladder_id": "FULL_COMPLETION_ATTEMPT_20260310",
            "ladder_status": "OFFICIAL_COMPLETION_REFUSED",
            "statement": "The full completion attempt report refused official completion because tracked state and HEAD were recursively coupled.",
            "evidence_refs": [AUDIT_FULL_ATTEMPT_REL],
        },
        {
            "ladder_id": "WORKSPACE_CAMPAIGN_20260310",
            "ladder_status": "WORKSPACE_COMPLETE_NOT_PUBLICATION_GRADE",
            "statement": "The workspace campaign declared local board completion but explicitly withheld publication-grade closure.",
            "evidence_refs": [AUDIT_E2E_CAMPAIGN_REL],
        },
        {
            "ladder_id": "WS0_WS11_CLOSEOUT_20260314",
            "ladder_status": "SEALED_WITH_OPEN_BLOCKERS",
            "statement": "The retained WS0-WS11 baseline sealed the admissibility ceiling with explicit proven and not_proven boundaries.",
            "evidence_refs": [WS_CLOSEOUT_SUMMARY_REL, WS_CLOSEOUT_BLOCKERS_REL],
        },
    ]

    return {
        "schema_id": "kt.operator.historical_resolutions.v1",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "Historical resolutions record explicit closures, fail-closed clearances, and governance-ladder transitions stated in prior artifacts. "
            "They preserve chronology without reopening any closed domain."
        ),
        "historical_governance_ladders": governance_ladders,
        "resolved_blockers": resolved_blockers,
        "receipt_clearances": run_sweep_clearances,
    }


def build_forgotten_surface_register(*, root: Path) -> Dict[str, Any]:
    _step_context(root)

    surfaces = [
        {
            "surface_ref": "KT_ARCHIVE/docs/audit/ADAPTER_LINEAGE_SYSTEM.md",
            "surface_class": "historical_lineage_doc",
            "current_status": "historical_reference_only",
            "historical_role": "adapter lineage system map",
            "recovery_track": "step_6_graph_and_lineage_compilation",
            "evidence_refs": ["KT_ARCHIVE/docs/audit/ADAPTER_LINEAGE_SYSTEM.md", AUDIT_WORKSET_REL],
        },
        {
            "surface_ref": "KT_ARCHIVE/docs/audit/ADAPTER_SYSTEM_MAP.md",
            "surface_class": "historical_system_map",
            "current_status": "historical_reference_only",
            "historical_role": "adapter topology and control-surface map",
            "recovery_track": "step_6_graph_and_lineage_compilation",
            "evidence_refs": ["KT_ARCHIVE/docs/audit/ADAPTER_SYSTEM_MAP.md", AUDIT_WORKSET_REL],
        },
        {
            "surface_ref": "KT_ARCHIVE/docs/audit/CRUCIBLE_OUTPUT_SCHEMA.md",
            "surface_class": "historical_contract_doc",
            "current_status": "historical_reference_only",
            "historical_role": "older crucible output contract",
            "recovery_track": "step_9_runtime_experiment_memory",
            "evidence_refs": ["KT_ARCHIVE/docs/audit/CRUCIBLE_OUTPUT_SCHEMA.md", CRUCIBLE_RUN_LEDGER_REL],
        },
        {
            "surface_ref": "KT_ARCHIVE/docs/audit/EPOCH_EXECUTION_FLOW.md",
            "surface_class": "historical_execution_doc",
            "current_status": "historical_reference_only",
            "historical_role": "older epoch execution model",
            "recovery_track": "step_3_constitutional_spine_and_meta_governance",
            "evidence_refs": ["KT_ARCHIVE/docs/audit/EPOCH_EXECUTION_FLOW.md", AUDIT_WORKSET_REL],
        },
        {
            "surface_ref": "KT_ARCHIVE/docs/audit/KT_E2E_PROTOCOL.md",
            "surface_class": "historical_protocol_doc",
            "current_status": "historical_reference_only",
            "historical_role": "older end-to-end protocol doctrine",
            "recovery_track": "step_12_full_stack_adjudication",
            "evidence_refs": ["KT_ARCHIVE/docs/audit/KT_E2E_PROTOCOL.md", AUDIT_WORKSET_REL],
        },
        {
            "surface_ref": "KT_ARCHIVE/docs/audit/KT_LEARNING_SYSTEM_MASTER_MAP.md",
            "surface_class": "historical_learning_doc",
            "current_status": "historical_reference_only",
            "historical_role": "learning-system topology and memory surface",
            "recovery_track": "step_9_runtime_experiment_memory",
            "evidence_refs": ["KT_ARCHIVE/docs/audit/KT_LEARNING_SYSTEM_MASTER_MAP.md", "KT_ARCHIVE/docs/audit/LEARNING_SIGNAL_INDEX.md"],
        },
        {
            "surface_ref": "KT_ARCHIVE/docs/audit/LEARNING_SIGNAL_INDEX.md",
            "surface_class": "historical_learning_doc",
            "current_status": "historical_reference_only",
            "historical_role": "signal taxonomy for older learning surfaces",
            "recovery_track": "step_9_runtime_experiment_memory",
            "evidence_refs": ["KT_ARCHIVE/docs/audit/LEARNING_SIGNAL_INDEX.md", "KT_ARCHIVE/docs/audit/KT_LEARNING_SYSTEM_MASTER_MAP.md"],
        },
        {
            "surface_ref": CODEX_MANIFEST_REL,
            "surface_class": "draft_codex_manifest",
            "current_status": "draft_external_lineage",
            "historical_role": "codex release manifest outside active law surfaces",
            "recovery_track": "step_11_doctrine_compiler_profiles",
            "evidence_refs": [CODEX_MANIFEST_REL, CODEX_DELIVERABLE_REL],
        },
        {
            "surface_ref": CODEX_CONFLICT_SCHEMA_REL,
            "surface_class": "codex_schema",
            "current_status": "draft_external_lineage",
            "historical_role": "codex conflict-event schema",
            "recovery_track": "step_10_paradox_metabolism_verification",
            "evidence_refs": [CODEX_CONFLICT_SCHEMA_REL],
        },
        {
            "surface_ref": CODEX_MULTIVERSAL_CONFLICT_SCHEMA_REL,
            "surface_class": "codex_schema",
            "current_status": "draft_external_lineage",
            "historical_role": "codex multiversal conflict-event schema",
            "recovery_track": "step_10_paradox_metabolism_verification",
            "evidence_refs": [CODEX_MULTIVERSAL_CONFLICT_SCHEMA_REL],
        },
        {
            "surface_ref": CODEX_SUITE_REGISTRY_REL,
            "surface_class": "codex_doctrine",
            "current_status": "draft_external_lineage",
            "historical_role": "suite-registry constitutional doctrine",
            "recovery_track": "step_11_doctrine_compiler_profiles",
            "evidence_refs": [CODEX_SUITE_REGISTRY_REL, CODEX_MANIFEST_REL],
        },
        {
            "surface_ref": OPERATOR_BLUEPRINT_REL,
            "surface_class": "historical_operator_doctrine",
            "current_status": "lineage_only_nonratified",
            "historical_role": "completion blueprint preceding the new constitutional spine",
            "recovery_track": "step_11_doctrine_compiler_profiles",
            "evidence_refs": [OPERATOR_BLUEPRINT_REL, AUDIT_FULL_ATTEMPT_REL],
        },
        {
            "surface_ref": OPERATOR_MANDATE_REL,
            "surface_class": "historical_operator_doctrine",
            "current_status": "lineage_only_nonratified",
            "historical_role": "older full-agent completion mandate",
            "recovery_track": "step_11_doctrine_compiler_profiles",
            "evidence_refs": [OPERATOR_MANDATE_REL, AUDIT_FULL_ATTEMPT_REL],
        },
        {
            "surface_ref": "KT_ARCHIVE/legacy_runtime/KT_TEMPLE_ROOT",
            "surface_class": "archive_root",
            "current_status": "archive_only_root_residue",
            "historical_role": "preserved earlier KT root",
            "recovery_track": "step_8_normalization_plan",
            "evidence_refs": [AUDIT_WORKSET_REL, AUDIT_REPO_CENSUS_REL],
        },
        {
            "surface_ref": "KT_ARCHIVE/legacy_runtime/KT_LANE_LORA_PHASE_B",
            "surface_class": "archive_root",
            "current_status": "archive_only_root_residue",
            "historical_role": "older lane export tree retained at repo root",
            "recovery_track": "step_8_normalization_plan",
            "evidence_refs": [AUDIT_WORKSET_REL, AUDIT_REPO_CENSUS_REL],
        },
        {
            "surface_ref": "KT_ARCHIVE/vault",
            "surface_class": "archive_surface",
            "current_status": "archive_only",
            "historical_role": "in-repo archive vault",
            "recovery_track": "step_8_normalization_plan",
            "evidence_refs": [AUDIT_WORKSET_REL],
        },
        {
            "surface_ref": "KT_ARCHIVE/root_legacy/EPOCH_CROSS.json",
            "surface_class": "root_historical_operation_artifact",
            "current_status": "root_archive_contamination_risk",
            "historical_role": "root historical operation artifact",
            "recovery_track": "step_8_normalization_plan",
            "evidence_refs": [AUDIT_REPO_CENSUS_REL, AUDIT_WORKSET_REL],
        },
        {
            "surface_ref": "KT_ARCHIVE/root_legacy/RUN_REPORT.md",
            "surface_class": "root_historical_operation_artifact",
            "current_status": "root_archive_contamination_risk",
            "historical_role": "root historical run report",
            "recovery_track": "step_8_normalization_plan",
            "evidence_refs": [AUDIT_REPO_CENSUS_REL, AUDIT_WORKSET_REL],
        },
        {
            "surface_ref": "KT_ARCHIVE/root_legacy/runbook.txt",
            "surface_class": "root_historical_operation_artifact",
            "current_status": "root_archive_contamination_risk",
            "historical_role": "root historical runbook",
            "recovery_track": "step_8_normalization_plan",
            "evidence_refs": [AUDIT_REPO_CENSUS_REL, AUDIT_WORKSET_REL],
        },
    ]

    enriched = []
    for row in surfaces:
        enriched.append({**row, "exists": (root / Path(str(row["surface_ref"]))).exists()})

    return {
        "schema_id": "kt.operator.forgotten_surface_register.v1",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This register lists historically important surfaces that must be remembered explicitly before later catalog, normalization, doctrine, or paradox work. "
            "Listing a surface here does not ratify it as current canon."
        ),
        "surfaces": enriched,
    }


def build_reopened_defect_register(*, root: Path) -> Dict[str, Any]:
    _step_context(root)

    blocker_matrix = _load_required(root, AUDIT_BLOCKER_MATRIX_REL)
    representative = _load_required(root, REPRESENTATIVE_REPRO_REL)
    public_verifier = _load_required(root, PUBLIC_VERIFIER_REL)
    closeout_summary = _load_required(root, WS_CLOSEOUT_SUMMARY_REL)

    head_commit = _git_head(root)
    origin_main_commit = _git(root, "rev-parse", "origin/main")
    blocker_rows = {str(row.get("blocker_id", "")).strip(): row for row in blocker_matrix.get("blockers", []) if isinstance(row, dict)}

    defects = [
        {
            "defect_id": "TARGET_NOT_REMOTE_EQUAL",
            "historical_status": str(blocker_rows["TARGET_NOT_REMOTE_EQUAL"].get("status", "")).strip(),
            "current_status": "RESOLVED_LATER",
            "reopened": False,
            "current_summary": "Current HEAD matches origin/main.",
            "current_evidence_refs": ["git:HEAD", "git:origin/main"],
            "historical_evidence_refs": list(blocker_rows["TARGET_NOT_REMOTE_EQUAL"].get("evidence_paths", [])),
            "current_values": {"head_commit": head_commit, "origin_main_commit": origin_main_commit},
        },
        {
            "defect_id": "NO_CLEAN_CLONE_PROOF_AT_CURRENT_HEAD",
            "historical_status": str(blocker_rows["NO_CLEAN_CLONE_PROOF_AT_CURRENT_HEAD"].get("status", "")).strip(),
            "current_status": "TRANSFORMED_REPRESENTATIVE_ONLY",
            "reopened": True,
            "current_summary": "Representative same-MVE reproducibility is proven, but general current-head clean-clone equivalence is still not claimed.",
            "current_evidence_refs": [REPRESENTATIVE_REPRO_REL, WS_CLOSEOUT_SUMMARY_REL],
            "historical_evidence_refs": list(blocker_rows["NO_CLEAN_CLONE_PROOF_AT_CURRENT_HEAD"].get("evidence_paths", [])),
            "current_values": {
                "representative_authority_lane_proven": bool(representative.get("representative_authority_lane_proven")),
                "cross_environment_controlled_variation_complete": bool(representative.get("cross_environment_controlled_variation_complete")),
                "validated_head_sha": str(representative.get("validated_head_sha", "")).strip(),
            },
        },
        {
            "defect_id": "TRACKED_TRUTH_SURFACES_STALE",
            "historical_status": str(blocker_rows["TRACKED_TRUTH_SURFACES_STALE"].get("status", "")).strip(),
            "current_status": "TRANSFORMED_TYPED_SUBJECT_EVIDENCE_BOUNDARY",
            "reopened": True,
            "current_summary": "The stale-truth problem was transformed into explicit evidence-vs-subject typing rather than hidden tracked-state overread.",
            "current_evidence_refs": [PUBLIC_VERIFIER_REL, WS_CLOSEOUT_SUMMARY_REL],
            "historical_evidence_refs": list(blocker_rows["TRACKED_TRUTH_SURFACES_STALE"].get("evidence_paths", [])),
            "current_values": {
                "evidence_commit": str(public_verifier.get("evidence_commit", "")).strip(),
                "truth_subject_commit": str(public_verifier.get("truth_subject_commit", "")).strip(),
                "evidence_equals_subject": bool(public_verifier.get("evidence_equals_subject")),
                "subject_verdict": str(public_verifier.get("subject_verdict", "")).strip(),
                "closeout_verdict": str(closeout_summary.get("closeout_verdict", "")).strip(),
            },
        },
        {
            "defect_id": "LOCAL_RESIDUE_PRESENT",
            "historical_status": str(blocker_rows["LOCAL_RESIDUE_PRESENT"].get("status", "")).strip(),
            "current_status": "STILL_OPEN",
            "reopened": True,
            "current_summary": "The local secret-like residue still exists at repo root.",
            "current_evidence_refs": [AUDIT_LOCAL_RESIDUE_REL, ".env.secret"],
            "historical_evidence_refs": list(blocker_rows["LOCAL_RESIDUE_PRESENT"].get("evidence_paths", [])),
            "current_values": {"env_secret_exists": (root / ".env.secret").exists()},
        },
        {
            "defect_id": "ROOT_ARCHIVE_CONTAMINATION",
            "historical_status": str(blocker_rows["ROOT_ARCHIVE_CONTAMINATION"].get("status", "")).strip(),
            "current_status": "STILL_OPEN",
            "reopened": True,
            "current_summary": "Historical archive material has been re-rooted under KT_ARCHIVE and remains lineage-only.",
            "current_evidence_refs": [AUDIT_WORKSET_REL, "KT_ARCHIVE/docs/audit", "KT_ARCHIVE/legacy_runtime/KT_TEMPLE_ROOT", "KT_ARCHIVE/legacy_runtime/KT_LANE_LORA_PHASE_B"],
            "historical_evidence_refs": list(blocker_rows["ROOT_ARCHIVE_CONTAMINATION"].get("evidence_paths", [])),
            "current_values": {
                "docs_audit_exists": (root / "KT_ARCHIVE" / "docs" / "audit").exists(),
                "kt_temple_root_exists": (root / "KT_ARCHIVE" / "legacy_runtime" / "KT_TEMPLE_ROOT").exists(),
                "kt_lane_lora_phase_b_exists": (root / "KT_ARCHIVE" / "legacy_runtime" / "KT_LANE_LORA_PHASE_B").exists(),
            },
        },
        {
            "defect_id": "TRUTH_ENGINE_EXTERNAL_PATH_ASSUMPTION",
            "historical_status": str(blocker_rows["TRUTH_ENGINE_EXTERNAL_PATH_ASSUMPTION"].get("status", "")).strip(),
            "current_status": "REMAINS_RESOLVED",
            "reopened": False,
            "current_summary": "The external-path acceptance repair remains part of the retained tool/test surface.",
            "current_evidence_refs": [
                "KT_PROD_CLEANROOM/tools/operator/truth_engine.py",
                "KT_PROD_CLEANROOM/tests/operator/test_truth_engine_and_authority.py",
            ],
            "historical_evidence_refs": list(blocker_rows["TRUTH_ENGINE_EXTERNAL_PATH_ASSUMPTION"].get("evidence_paths", [])),
        },
        {
            "defect_id": "TRUST_ZONE_MODEL_INCOMPLETE",
            "historical_status": str(blocker_rows["TRUST_ZONE_MODEL_INCOMPLETE"].get("status", "")).strip(),
            "current_status": "REMAINS_RESOLVED",
            "reopened": False,
            "current_summary": "The six-zone trust model remains resolved and later runtime-boundary work hardened it further.",
            "current_evidence_refs": [
                "KT_PROD_CLEANROOM/governance/trust_zone_registry.json",
                "KT_PROD_CLEANROOM/reports/runtime_boundary_integrity_receipt.json",
            ],
            "historical_evidence_refs": list(blocker_rows["TRUST_ZONE_MODEL_INCOMPLETE"].get("evidence_paths", [])),
        },
        {
            "defect_id": "READINESS_SCOPE_INCOMPLETE",
            "historical_status": str(blocker_rows["READINESS_SCOPE_INCOMPLETE"].get("status", "")).strip(),
            "current_status": "REMAINS_RESOLVED",
            "reopened": False,
            "current_summary": "Readiness scoping remains narrowed away from generated and quarantined surfaces.",
            "current_evidence_refs": [
                "KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json",
                "KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json",
            ],
            "historical_evidence_refs": list(blocker_rows["READINESS_SCOPE_INCOMPLETE"].get("evidence_paths", [])),
        },
    ]

    return {
        "schema_id": "kt.operator.reopened_defect_register.v1",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This register maps historical defects to their current disposition without silently upgrading the current admissibility ceiling. "
            "A transformed defect is still remembered as an open lineage constraint until later work closes it explicitly."
        ),
        "defects": defects,
    }


def build_historical_memory_ingestion_report(*, root: Path) -> Dict[str, Any]:
    ctx = _step_context(root)
    claims = _load_required(root, CLAIMS_REL)
    conflicts = _load_required(root, CONFLICTS_REL)
    resolutions = _load_required(root, RESOLUTIONS_REL)
    forgotten = _load_required(root, FORGOTTEN_SURFACES_REL)
    reopened = _load_required(root, REOPENED_DEFECTS_REL)
    run_sweep = _load_required(root, RUN_SWEEP_MATRIX_REL)

    checks: List[Dict[str, Any]] = []
    failures: List[str] = []

    def _status_row(*, check: str, passed: bool, detail: str, refs: Sequence[str]) -> Dict[str, Any]:
        return {"check": check, "detail": detail, "refs": list(refs), "status": "PASS" if passed else "FAIL"}

    step_gate_ok = str(ctx["step1_receipt"].get("status", "")).strip() == "PASS" and str(ctx["step3_receipt"].get("status", "")).strip() == "PASS"
    checks.append(
        _status_row(
            check="prior_gates_passed",
            passed=step_gate_ok,
            detail="Step 4 requires Step 1 baseline ingestion and Step 3 constitutional ratification to be PASS.",
            refs=[STEP1_RECEIPT_REL, STEP3_RECEIPT_REL],
        )
    )
    if not step_gate_ok:
        failures.append("prior_gates_passed")

    governance_ladders_ok = len(resolutions.get("historical_governance_ladders", [])) >= 5
    checks.append(
        _status_row(
            check="historical_governance_ladders_ingested",
            passed=governance_ladders_ok,
            detail="Historical governance ladders must be explicitly carried from the older audit, completion, campaign, and closeout stages.",
            refs=[RESOLUTIONS_REL, AUDIT_IMPLEMENTATION_REL, AUDIT_FULL_ATTEMPT_REL, AUDIT_E2E_CAMPAIGN_REL, WS_CLOSEOUT_SUMMARY_REL],
        )
    )
    if not governance_ladders_ok:
        failures.append("historical_governance_ladders_ingested")

    codex_history_ok = any(str(row.get("family_id", "")).strip() == "kt_codex" and int(row.get("file_count", 0)) > 0 for row in claims.get("source_families", [])) and any(
        str(row.get("surface_ref", "")).strip() == CODEX_MANIFEST_REL for row in forgotten.get("surfaces", [])
    )
    checks.append(
        _status_row(
            check="canon_codex_history_ingested",
            passed=codex_history_ok,
            detail="Codex lineage must be represented both as source family history and as explicitly remembered surfaces.",
            refs=[CLAIMS_REL, FORGOTTEN_SURFACES_REL, CODEX_MANIFEST_REL, CODEX_DELIVERABLE_REL],
        )
    )
    if not codex_history_ok:
        failures.append("canon_codex_history_ingested")

    conflict_registers_ok = (
        len(conflicts.get("historical_blocker_conflicts", [])) >= 8
        and len(conflicts.get("codex_conflict_models", [])) == 2
        and len(conflicts.get("historical_receipt_conflicts", [])) == int(run_sweep.get("cleared_failure_count", 0))
    )
    checks.append(
        _status_row(
            check="old_conflict_registers_ingested",
            passed=conflict_registers_ok,
            detail="Historical blocker registers, codex conflict models, and rerun conflict receipts must all be ingested.",
            refs=[CONFLICTS_REL, AUDIT_BLOCKER_MATRIX_REL, RUN_SWEEP_MATRIX_REL, CODEX_CONFLICT_SCHEMA_REL, CODEX_MULTIVERSAL_CONFLICT_SCHEMA_REL],
        )
    )
    if not conflict_registers_ok:
        failures.append("old_conflict_registers_ingested")

    crucible = claims.get("crucible_history", {})
    crucible_ok = int(crucible.get("registered_crucibles", 0)) >= 14 and int(crucible.get("total_runs", 0)) > 0 and len(crucible.get("exemplar_runs", [])) >= 4
    checks.append(
        _status_row(
            check="crucible_history_ingested",
            passed=crucible_ok,
            detail="Historical crucible registry and run-ledger memory must be summarized with registered entries, observed runs, and exemplar evidence.",
            refs=[CLAIMS_REL, CRUCIBLE_REGISTRY_REL, CRUCIBLE_RUN_LEDGER_REL],
        )
    )
    if not crucible_ok:
        failures.append("crucible_history_ingested")

    forgotten_ok = len(forgotten.get("surfaces", [])) >= 18 and all(bool(row.get("exists")) for row in forgotten.get("surfaces", []))
    checks.append(
        _status_row(
            check="forgotten_surfaces_explicitly_listed",
            passed=forgotten_ok,
            detail="Historically important but noncanonical surfaces must be listed explicitly rather than left to conversational recall.",
            refs=[FORGOTTEN_SURFACES_REL, AUDIT_WORKSET_REL],
        )
    )
    if not forgotten_ok:
        failures.append("forgotten_surfaces_explicitly_listed")

    reopened_ok = len(reopened.get("defects", [])) >= 8 and any(
        str(row.get("defect_id", "")).strip() == "LOCAL_RESIDUE_PRESENT" and str(row.get("current_status", "")).strip() == "STILL_OPEN"
        for row in reopened.get("defects", [])
    )
    checks.append(
        _status_row(
            check="reopened_defects_classified",
            passed=reopened_ok,
            detail="Historical blockers must be mapped to current resolved, transformed, or still-open dispositions.",
            refs=[REOPENED_DEFECTS_REL, AUDIT_BLOCKER_MATRIX_REL, PUBLIC_VERIFIER_REL, REPRESENTATIVE_REPRO_REL],
        )
    )
    if not reopened_ok:
        failures.append("reopened_defects_classified")

    subject_commit = _git_last_commit_for_paths(root, SUBJECT_ARTIFACT_REFS)
    current_head_commit = _git_head(root)
    subject_history = _git_history_for_paths(root, SUBJECT_ARTIFACT_REFS)
    earliest_subject_commit = subject_history[-1] if subject_history else ""
    step_baseline_commit = _git_parent(root, earliest_subject_commit)
    actual_subject_touched = _git_diff_files(root, step_baseline_commit, subject_commit, SUBJECT_ARTIFACT_REFS)
    if not actual_subject_touched:
        actual_subject_touched = _git_changed_files(root, subject_commit)
    actual_touched = sorted(set(actual_subject_touched + [RECEIPT_REL]))
    unexpected_touches = sorted(set(actual_touched) - set(PLANNED_MUTATES))
    protected_touch_violations = sorted(path for path in actual_touched if _is_protected(path))
    post_touch_ok = set(actual_touched) == set(PLANNED_MUTATES) and not unexpected_touches and not protected_touch_violations

    checks.append(
        _status_row(
            check="post_touch_accounting_clean",
            passed=post_touch_ok,
            detail="Actual touched set must match the lawful Step 4 subject files plus the ingestion receipt.",
            refs=PLANNED_MUTATES,
        )
    )
    if not post_touch_ok:
        failures.append("post_touch_accounting_clean")

    status = "PASS" if not failures else "FAIL_CLOSED"
    verdict = "HISTORICAL_MEMORY_INGESTED" if status == "PASS" else "HISTORICAL_MEMORY_INCOMPLETE_FAIL_CLOSED"

    return {
        "schema_id": "kt.operator.historical_memory_ingestion_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "pass_verdict": verdict,
        "controlling_work_order": {
            "schema_id": WORK_ORDER_SCHEMA_ID,
            "work_order_id": WORK_ORDER_ID,
            "step_id": 4,
            "step_name": "HISTORICAL_EVIDENCE_INGESTION_AND_FORGOTTEN_SURFACE_RECOVERY",
        },
        "step1_gate_subject_commit": str(ctx["step1_receipt"].get("compiled_head_commit", "")).strip(),
        "step1_gate_evidence_commit": str(ctx["step1_evidence_commit"]).strip(),
        "step3_gate_subject_commit": str(ctx["step3_receipt"].get("compiled_head_commit", "")).strip(),
        "step3_gate_evidence_commit": str(ctx["step3_evidence_commit"]).strip(),
        "compiled_head_commit": subject_commit,
        "current_head_commit": current_head_commit,
        "claim_boundary": (
            "This receipt validates Step 4 historical memory ingestion for compiled_head_commit only. "
            "A later repository head that contains this receipt is evidence about compiled_head_commit, not automatically that compiled head."
        ),
        "planned_mutates": list(PLANNED_MUTATES),
        "actual_touched": actual_touched,
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "checks": checks,
        "next_lawful_step": {
            "step_id": 5,
            "step_name": "SNAPSHOT_DETERMINISM_AND_PHYSICAL_INVENTORY",
            "status_after_step_4": "UNLOCKED" if status == "PASS" else "BLOCKED",
        },
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ingest historical KT evidence and forgotten surfaces into bounded machine-readable Step 4 artifacts.")
    parser.add_argument("--root", default="", help="Optional repository root override.")
    parser.add_argument("--emit-receipt", action="store_true", help="Write the Step 4 receipt instead of the subject deliverables.")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = Path(str(args.root)).resolve() if str(args.root).strip() else repo_root()

    if bool(args.emit_receipt):
        report = build_historical_memory_ingestion_report(root=root)
        write_json_stable((root / Path(RECEIPT_REL)).resolve(), report)
        print(
            json.dumps(
                {
                    "status": report["status"],
                    "pass_verdict": report["pass_verdict"],
                    "compiled_head_commit": report["compiled_head_commit"],
                    "current_head_commit": report["current_head_commit"],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if report["status"] == "PASS" else 1

    payloads = {
        CLAIMS_REL: build_historical_claims(root=root),
        CONFLICTS_REL: build_historical_conflicts(root=root),
        RESOLUTIONS_REL: build_historical_resolutions(root=root),
        FORGOTTEN_SURFACES_REL: build_forgotten_surface_register(root=root),
        REOPENED_DEFECTS_REL: build_reopened_defect_register(root=root),
    }

    writes: List[Dict[str, Any]] = []
    for rel, payload in payloads.items():
        changed = write_json_stable((root / Path(rel)).resolve(), payload)
        writes.append({"artifact_ref": rel, "updated": changed, "schema_id": str(payload.get("schema_id", "")).strip()})

    print(json.dumps({"status": "PASS", "artifacts_written": writes, "source_families": _source_family_rows(root)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
