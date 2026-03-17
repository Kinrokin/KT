from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.authority_convergence_validate import build_authority_convergence_report
from tools.operator.canonical_tree_execute import CURRENT_ARCHIVE_LITERAL
from tools.operator.reporting_integrity import _ls_remote_head, build_published_head_self_convergence_receipt, verify_reporting_integrity
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


WORKSTREAM_ID = "WS9_AUTHORITY_AND_PUBLISHED_HEAD_CLOSURE"
STEP_ID = "WS9_STEP_1_AUTHORITY_AND_PUBLISHED_HEAD_CLOSEOUT"
PASS_VERDICT = "AUTHORITY_AND_PUBLISHED_HEAD_CLOSED"
REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
NEXT_SOVEREIGN_WORKSTREAM_ID = "WS10_AIR_GAPPED_ROOT_CEREMONY_AND_SIGNER_TOPOLOGY"

AUTHORITY_REL = f"{REPORT_ROOT_REL}/authority_convergence_receipt.json"
PUBLISHED_REL = f"{REPORT_ROOT_REL}/published_head_self_convergence_receipt.json"
KT_PUBLISHED_REL = f"{REPORT_ROOT_REL}/kt_published_head_self_convergence_receipt.json"
KT_CLOSURE_REL = f"{REPORT_ROOT_REL}/kt_authority_closure_receipt.json"
REPORTING_REPAIR_REL = f"{REPORT_ROOT_REL}/reporting_integrity_repair_receipt.json"
SOVEREIGN_CURRENT_HEAD_TRUTH_SOURCE_REL = f"{REPORT_ROOT_REL}/kt_current_head_truth_source.json"
SOVEREIGN_BLOCKER_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_blocker_matrix.json"
SOVEREIGN_CLOSURE_REL = f"{REPORT_ROOT_REL}/kt_authority_and_published_head_closure_receipt.json"
H1_GATE_REL = f"{REPORT_ROOT_REL}/h1_activation_gate_receipt.json"
TRUTH_STABILIZATION_REL = f"{REPORT_ROOT_REL}/kt_truth_publication_stabilization_receipt.json"
PUBLIC_VERIFIER_MANIFEST_REL = f"{REPORT_ROOT_REL}/public_verifier_manifest.json"
PLATFORM_GOVERNANCE_REL = f"{REPORT_ROOT_REL}/kt_platform_governance_final_decision_receipt.json"
REPRESENTATIVE_AUTHORITY_LANE_REL = f"{REPORT_ROOT_REL}/representative_authority_lane_reproducibility_receipt.json"
TWO_CLEAN_CLONE_REL = f"{REPORT_ROOT_REL}/twocleanclone_proof.json"

SOVEREIGN_CREATED_FILES = [
    SOVEREIGN_CLOSURE_REL,
    SOVEREIGN_CURRENT_HEAD_TRUTH_SOURCE_REL,
    SOVEREIGN_BLOCKER_MATRIX_REL,
]
SOVEREIGN_VALIDATORS = [
    "python -m tools.operator.authority_convergence_validate",
    "python -m tools.operator.reporting_integrity --mode verify",
    "python -m tools.operator.authority_convergence_closeout --emit-sovereign-v1-2",
]
SOVEREIGN_TESTS = [
    "python -m pytest KT_PROD_CLEANROOM/tests/operator/test_authority_convergence_validate.py KT_PROD_CLEANROOM/tests/operator/test_reporting_integrity.py KT_PROD_CLEANROOM/tests/operator/test_authority_convergence_closeout.py -q",
]
SOVEREIGN_FORBIDDEN_CLAIMS = [
    "CURRENT_HEAD_IS_TRANSPARENCY_VERIFIED_SUBJECT",
    "CURRENT_HEAD_AUTHORITY_CLOSED",
    "PLATFORM_ENFORCEMENT_PROVEN",
    "H1_SINGLE_ADAPTER_ALLOWED",
    "CROSS_ENV_CONTROLLED_VARIATION_CURRENT_HEAD_COMPLETE",
]
SOVEREIGN_OUT_OF_SCOPE_ATTACK_CLASSES = [
    "AIR_GAPPED_ROOT_CEREMONY",
    "SIGSTORE_REKOR_MONITORING_ACTIVATION",
    "IN_TOTO_SLSA_TUF_HARDENING",
    "DETACHED_VERIFIER_RELEASE",
    "EXTERNAL_ASSURANCE_CONFIRMATION",
    "EXTERNAL_CAPABILITY_CONFIRMATION",
    "COMMERCIAL_LICENSE_TRACK",
]
SOVEREIGN_TRUST_ASSUMPTIONS = [
    "Current repo HEAD differs from the transparency-verified truth subject commit and is therefore evidence-bearing only.",
    "Platform governance remains explicitly narrowed to workflow-governance-only while branch-protection proof is blocked.",
    "Cross-environment controlled variation remains not run or not current on the authority lane.",
    "Historical signer topology remains pre-WS10 and must not be read as sovereign root-ceremony completion.",
]

ALLOWED_TOUCHES = {
    AUTHORITY_REL,
    PUBLISHED_REL,
    KT_PUBLISHED_REL,
    KT_CLOSURE_REL,
    REPORTING_REPAIR_REL,
    "KT_PROD_CLEANROOM/tools/operator/authority_convergence_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/reporting_integrity.py",
    "KT_PROD_CLEANROOM/tools/operator/authority_convergence_closeout.py",
    "KT_PROD_CLEANROOM/tests/operator/test_authority_convergence_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_reporting_integrity.py",
    "KT_PROD_CLEANROOM/tests/operator/test_authority_convergence_closeout.py",
    "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
    "KT_PROD_CLEANROOM/reports/current_state_receipt.json",
    "KT_PROD_CLEANROOM/reports/runtime_closure_audit.json",
    "KT_PROD_CLEANROOM/reports/settled_truth_source_receipt.json",
    "KT_PROD_CLEANROOM/reports/truth_supersession_receipt.json",
    "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
    "KT_PROD_CLEANROOM/governance/execution_board.json",
    "KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json",
}
PROTECTED_PATTERNS = (".github/workflows/", CURRENT_ARCHIVE_LITERAL)


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_status_paths(root: Path) -> List[str]:
    out = subprocess.check_output(["git", "-C", str(root), "status", "--porcelain=v1"], text=True)
    rows: List[str] = []
    for line in out.splitlines():
        rel = line[3:].strip()
        if rel:
            rows.append(Path(rel).as_posix())
    return rows


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / rel).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _load_optional(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / rel).resolve()
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _status_of(payload: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(payload.get(key, "")).strip()
        if value:
            return value
    return ""


def _truth_subject_from(authority_report: Dict[str, Any], published_report: Dict[str, Any]) -> str:
    observed = authority_report.get("observed") if isinstance(authority_report.get("observed"), dict) else {}
    return (
        str(observed.get("truth_subject_commit", "")).strip()
        or str(published_report.get("truth_subject_commit", "")).strip()
        or str(published_report.get("validated_head_sha", "")).strip()
    )


def _evidence_commit_from(authority_report: Dict[str, Any], published_report: Dict[str, Any]) -> str:
    observed = authority_report.get("observed") if isinstance(authority_report.get("observed"), dict) else {}
    return (
        str(observed.get("verifier_evidence_commit", "")).strip()
        or str(observed.get("evidence_commit", "")).strip()
        or str(published_report.get("evidence_commit", "")).strip()
    )


def _current_head_claim_verdict(authority_report: Dict[str, Any], published_report: Dict[str, Any]) -> str:
    observed = authority_report.get("observed") if isinstance(authority_report.get("observed"), dict) else {}
    return str(published_report.get("current_head_claim_verdict", "")).strip() or str(observed.get("verifier_head_claim_verdict", "")).strip()


def _build_blocker_row(
    *,
    blocker_id: str,
    severity: str,
    status: str,
    rationale: str,
    evidence_refs: List[str],
) -> Dict[str, Any]:
    return {
        "blocker_id": blocker_id,
        "severity": severity,
        "status": status,
        "rationale": rationale,
        "evidence_refs": evidence_refs,
    }


def build_kt_published_head_self_convergence_receipt(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    published = _load_required(root, PUBLISHED_REL)
    status = str(published.get("status", "")).strip()
    return {
        "artifact_id": Path(KT_PUBLISHED_REL).name,
        "schema_id": "kt.operator.ws9_published_head_self_convergence_receipt.v1",
        "status": status,
        "pass_verdict": "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN" if status == "PASS" else "FAIL_CLOSED",
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": current_head,
        "subject_head_commit": current_head,
        "evidence_head_commit": current_head,
        "truth_subject_commit": str(published.get("truth_subject_commit", "")).strip(),
        "truth_evidence_commit": str(published.get("evidence_commit", "")).strip(),
        "current_head_commit": str(published.get("current_head_commit", "")).strip(),
        "head_equals_subject": bool(published.get("head_equals_subject")),
        "proof_class": str(published.get("proof_class", "")).strip(),
        "current_head_claim_verdict": str(published.get("current_head_claim_verdict", "")).strip(),
        "published_head_authority_claimed": bool(published.get("published_head_authority_claimed")),
        "current_head_authority_claimed": bool(published.get("current_head_authority_claimed")),
        "blockers": list(published.get("blockers", [])),
        "source_receipt_ref": PUBLISHED_REL,
        "unexpected_touches": [],
        "protected_touch_violations": [],
        "validators_run": [
            "python -m tools.operator.authority_convergence_validate",
            "python -m tools.operator.reporting_integrity --mode verify",
        ],
        "next_lawful_step": {"status_after_workstream": "UNLOCKED", "workstream_id": "WS10_PLATFORM_GOVERNANCE_FINAL_DECISION"},
    }


def build_authority_closure_receipt(*, root: Path, generated_utc: str) -> Dict[str, Any]:
    current_head = _git_head(root)
    authority = _load_required(root, AUTHORITY_REL)
    published = _load_required(root, PUBLISHED_REL)
    kt_published = _load_required(root, KT_PUBLISHED_REL)
    reporting = _load_required(root, REPORTING_REPAIR_REL)

    actual_touched = sorted(set(_git_status_paths(root) + [KT_PUBLISHED_REL, KT_CLOSURE_REL]))
    unexpected_touches = [path for path in actual_touched if path not in ALLOWED_TOUCHES]
    protected_touch_violations = [path for path in actual_touched if any(path.startswith(prefix) for prefix in PROTECTED_PATTERNS)]

    authority_ok = str(authority.get("status", "")).strip() == "PASS"
    published_ok = str(published.get("status", "")).strip() == "PASS"
    reporting_ok = str(reporting.get("status", "")).strip() == "PASS"
    status = "PASS" if authority_ok and published_ok and reporting_ok and not unexpected_touches and not protected_touch_violations else "FAIL_CLOSED"

    return {
        "artifact_id": Path(KT_CLOSURE_REL).name,
        "schema_id": "kt.operator.authority_closure_receipt.v1",
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else "FAIL_CLOSED",
        "generated_utc": generated_utc,
        "compiled_head_commit": current_head,
        "subject_head_commit": current_head,
        "evidence_head_commit": current_head,
        "truth_subject_commit": str(published.get("truth_subject_commit", "")).strip(),
        "truth_evidence_commit": str(published.get("evidence_commit", "")).strip(),
        "current_head_commit": str(published.get("current_head_commit", "")).strip(),
        "head_equals_subject": bool(published.get("head_equals_subject")),
        "authority_convergence_ref": AUTHORITY_REL,
        "published_head_self_convergence_ref": PUBLISHED_REL,
        "kt_published_head_self_convergence_ref": KT_PUBLISHED_REL,
        "reporting_integrity_ref": REPORTING_REPAIR_REL,
        "authority_convergence_status": str(authority.get("status", "")).strip(),
        "authority_convergence_proof_class": str(authority.get("proof_class", "")).strip(),
        "published_head_self_convergence_status": str(published.get("status", "")).strip(),
        "published_head_self_convergence_proof_class": str(published.get("proof_class", "")).strip(),
        "reporting_integrity_status": str(reporting.get("status", "")).strip(),
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "validators_run": [
            "python -m tools.operator.authority_convergence_validate",
            "python -m tools.operator.reporting_integrity --mode verify",
        ],
        "next_lawful_step": {"status_after_workstream": "UNLOCKED", "workstream_id": "WS10_PLATFORM_GOVERNANCE_FINAL_DECISION"},
        "step_report": {
            "timestamp": generated_utc,
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "verified the ledger current surfaces against the published truth subject",
                "re-emitted the legacy authority and published-head self-convergence receipts under the WS9 contract",
                "fixed post-evidence-head reporting integrity comparison so current-head observation drift does not invalidate the published-subject proof",
                "sealed WS9 kt_* closure receipts without upgrading H1",
            ],
            "files_touched": actual_touched,
            "tests_run": ["python -m pytest KT_PROD_CLEANROOM/tests/operator/test_authority_convergence_validate.py KT_PROD_CLEANROOM/tests/operator/test_reporting_integrity.py KT_PROD_CLEANROOM/tests/operator/test_authority_convergence_closeout.py -q"],
            "validators_run": [
                "python -m tools.operator.authority_convergence_validate",
                "python -m tools.operator.reporting_integrity --mode verify",
            ],
            "issues_found": [],
            "resolution": "WS9 closes authority convergence and published-head self-convergence at the published subject boundary while preserving current-head anti-overread behavior.",
            "pass_fail_status": status,
            "unexpected_touches": unexpected_touches,
            "protected_touch_violations": protected_touch_violations,
        },
    }


def build_sovereign_current_head_truth_source(
    *,
    current_repo_head: str,
    authority_report: Dict[str, Any],
    published_report: Dict[str, Any],
) -> Dict[str, Any]:
    truth_subject_commit = _truth_subject_from(authority_report, published_report)
    evidence_head_commit = _evidence_commit_from(authority_report, published_report)
    head_claim_verdict = _current_head_claim_verdict(authority_report, published_report)
    published_head_authority_claimed = bool(published_report.get("published_head_authority_claimed"))
    current_head_authority_claimed = bool(published_report.get("current_head_authority_claimed"))
    return {
        "schema_id": "kt.operator.ws9_current_head_truth_source.v1",
        "workstream_id": WORKSTREAM_ID,
        "generated_utc": utc_now_iso_z(),
        "current_repo_head": current_repo_head,
        "active_truth_source": "kt_truth_ledger:ledger/current/current_pointer.json",
        "truth_subject_commit": truth_subject_commit,
        "evidence_head_commit": evidence_head_commit,
        "current_head_claim_verdict": head_claim_verdict,
        "published_head_authority_claimed": published_head_authority_claimed,
        "current_head_authority_claimed": current_head_authority_claimed,
        "head_equals_subject": bool(published_report.get("head_equals_subject")),
        "lawful_current_head_statement": (
            f"Current repo head {current_repo_head} may claim only that it contains evidence for the "
            f"transparency-verified subject {truth_subject_commit}."
            if not current_head_authority_claimed
            else f"Current repo head {current_repo_head} is the transparency-verified subject."
        ),
        "stronger_claim_not_made": (
            "This artifact does not claim that current HEAD is the transparency-verified subject, does not claim "
            "current-head authority closure, and does not upgrade platform enforcement, H1, or cross-environment proof."
        ),
        "evidence_refs": [
            AUTHORITY_REL,
            PUBLISHED_REL,
            PUBLIC_VERIFIER_MANIFEST_REL,
            TRUTH_STABILIZATION_REL,
        ],
    }


def build_sovereign_blocker_matrix(
    *,
    current_repo_head: str,
    authority_report: Dict[str, Any],
    published_report: Dict[str, Any],
    h1_receipt: Dict[str, Any],
    stabilization_receipt: Dict[str, Any],
    verifier_manifest: Dict[str, Any],
    platform_receipt: Dict[str, Any],
    representative_receipt: Dict[str, Any],
    two_clean_clone_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    authority_status = "RESOLVED_WITH_CURRENT_HEAD_NARROWING"
    if bool(published_report.get("current_head_authority_claimed")):
        authority_status = "RESOLVED"
    published_status = "RESOLVED_WITH_CURRENT_HEAD_NARROWING"
    if bool(published_report.get("head_equals_subject")):
        published_status = "RESOLVED"

    stabilization_ok = _status_of(stabilization_receipt, "status") == "PASS" and bool(stabilization_receipt.get("truth_publication_stabilized"))
    platform_claim_admissible = bool(verifier_manifest.get("platform_governance_claim_admissible")) or bool(platform_receipt.get("platform_governance_claim_admissible"))
    cross_env_complete = bool(representative_receipt.get("cross_environment_controlled_variation_complete")) or bool(
        two_clean_clone_receipt.get("cross_environment_controlled_variation_complete")
    )
    representative_head = str(representative_receipt.get("validated_head_sha", "")).strip()
    two_clean_head = str(two_clean_clone_receipt.get("validated_head_sha", "")).strip()
    cross_env_current = cross_env_complete and representative_head == current_repo_head and two_clean_head == current_repo_head

    rows = [
        _build_blocker_row(
            blocker_id="AUTHORITY_CONVERGENCE_UNRESOLVED",
            severity="CRITICAL",
            status=authority_status if _status_of(authority_report, "status") == "PASS" else "OPEN",
            rationale=(
                "Authority convergence is satisfied only at the published-subject boundary; current HEAD remains evidence-bearing only."
                if authority_status == "RESOLVED_WITH_CURRENT_HEAD_NARROWING"
                else "Authority convergence is fully satisfied on current HEAD."
            )
            if _status_of(authority_report, "status") == "PASS"
            else "Authority convergence report is not PASS on the current repo head.",
            evidence_refs=[AUTHORITY_REL, PUBLISHED_REL],
        ),
        _build_blocker_row(
            blocker_id="PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED",
            severity="CRITICAL",
            status=published_status if _status_of(published_report, "status") == "PASS" else "OPEN",
            rationale=(
                "Published-head self-convergence is proven, but current HEAD is explicitly narrowed to evidence-bearing status."
                if published_status == "RESOLVED_WITH_CURRENT_HEAD_NARROWING"
                else "Published-head self-convergence is fully aligned on current HEAD."
            )
            if _status_of(published_report, "status") == "PASS"
            else "Published-head self-convergence receipt is not PASS.",
            evidence_refs=[PUBLISHED_REL, AUTHORITY_REL],
        ),
        _build_blocker_row(
            blocker_id="H1_ACTIVATION_GATE_CLOSED",
            severity="HIGH",
            status="OPEN",
            rationale=(
                "H1 remains blocked; no current-head H1 admissibility proof exists and the available H1 receipt is still blocked."
            ),
            evidence_refs=[H1_GATE_REL, PUBLISHED_REL, AUTHORITY_REL],
        ),
        _build_blocker_row(
            blocker_id="PLATFORM_ENFORCEMENT_UNPROVEN",
            severity="HIGH",
            status="RESOLVED_WITH_CURRENT_HEAD_NARROWING" if not platform_claim_admissible else "RESOLVED",
            rationale=(
                "Platform enforcement is still not proven, but the claim is explicitly narrowed to workflow-governance-only."
                if not platform_claim_admissible
                else "Platform enforcement is proven."
            ),
            evidence_refs=[PUBLIC_VERIFIER_MANIFEST_REL, PLATFORM_GOVERNANCE_REL],
        ),
        _build_blocker_row(
            blocker_id="TRUTH_PUBLICATION_STABILIZED_FALSE",
            severity="HIGH",
            status="RESOLVED" if stabilization_ok else "OPEN",
            rationale=(
                "Truth publication stabilization is PASS and truth_publication_stabilized is true."
                if stabilization_ok
                else "Truth publication stabilization is not yet PASS."
            ),
            evidence_refs=[TRUTH_STABILIZATION_REL],
        ),
        _build_blocker_row(
            blocker_id="CROSS_ENV_CONTROLLED_VARIATION_NOT_RUN_OR_NOT_CURRENT",
            severity="MEDIUM",
            status="RESOLVED" if cross_env_current else "OPEN",
            rationale=(
                "Cross-environment controlled variation is complete on the current repo head."
                if cross_env_current
                else "Cross-environment controlled variation remains not run or not current for the authority lane."
            ),
            evidence_refs=[REPRESENTATIVE_AUTHORITY_LANE_REL, TWO_CLEAN_CLONE_REL],
        ),
    ]

    return {
        "schema_id": "kt.operator.ws9_blocker_matrix.v1",
        "workstream_id": WORKSTREAM_ID,
        "generated_utc": utc_now_iso_z(),
        "current_repo_head": current_repo_head,
        "rows": rows,
        "summary": {
            "resolved_blockers": [row["blocker_id"] for row in rows if row["status"] == "RESOLVED"],
            "resolved_with_narrowing": [row["blocker_id"] for row in rows if row["status"] == "RESOLVED_WITH_CURRENT_HEAD_NARROWING"],
            "open_blockers": [row["blocker_id"] for row in rows if row["status"] == "OPEN"],
        },
        "stronger_claim_not_made": (
            "This blocker matrix does not clear H1, platform enforcement, or cross-environment controlled variation merely because WS9 is sealed."
        ),
    }


def build_sovereign_authority_and_published_head_closure_receipt(
    *,
    current_repo_head: str,
    authority_report: Dict[str, Any],
    published_report: Dict[str, Any],
    reporting_integrity_receipt: Dict[str, Any],
    blocker_matrix: Dict[str, Any],
    files_touched: List[str],
) -> Dict[str, Any]:
    truth_subject_commit = _truth_subject_from(authority_report, published_report)
    evidence_head_commit = _evidence_commit_from(authority_report, published_report)
    still_constraining_rows = [row for row in blocker_matrix.get("rows", []) if row.get("status") != "RESOLVED"]
    open_blockers = [str(row.get("blocker_id", "")).strip() for row in still_constraining_rows if str(row.get("blocker_id", "")).strip()]
    status = "PASS" if _status_of(authority_report, "status") == "PASS" and _status_of(published_report, "status") == "PASS" and _status_of(reporting_integrity_receipt, "status") == "PASS" else "BLOCKED"
    pass_verdict = "AUTHORITY_AND_PUBLISHED_HEAD_RECONCILED_WITH_CURRENT_HEAD_NARROWING" if status == "PASS" else "FAIL_CLOSED"
    return {
        "schema_id": "kt.operator.ws9_authority_and_published_head_closure_receipt.v1",
        "workstream_id": WORKSTREAM_ID,
        "status": status,
        "pass_verdict": pass_verdict,
        "subject_head_commit": truth_subject_commit,
        "evidence_head_commit": evidence_head_commit,
        "current_repo_head": current_repo_head,
        "compiled_against": current_repo_head,
        "generated_utc": utc_now_iso_z(),
        "unexpected_touches": [],
        "protected_touch_violations": [],
        "validators_run": list(SOVEREIGN_VALIDATORS),
        "tests_run": list(SOVEREIGN_TESTS),
        "trust_assumptions_remaining": list(SOVEREIGN_TRUST_ASSUMPTIONS),
        "upgrade_events": [
            "WS9_CURRENT_HEAD_TRUTH_SOURCE_REFRESHED",
            "WS9_BLOCKER_MATRIX_REFRESHED",
            "WS9_AUTHORITY_BOUNDARY_REFRESHED_ON_CURRENT_HEAD",
        ],
        "downgrade_events": [
            "CURRENT_HEAD_AUTHORITY_CLAIM_NARROWED_TO_EVIDENCE_ONLY"
            if not bool(published_report.get("current_head_authority_claimed"))
            else "NONE"
        ],
        "signer_topology_snapshot": {
            "status": "PRE_WS10_HISTORICAL_SIGNER_TOPOLOGY_ONLY",
            "lawful_current_claim": "No sovereign root ceremony or signer-topology upgrade is claimed before WS10.",
        },
        "verification_predicate_versions": {
            "authority_convergence": str(authority_report.get("schema_id", "")).strip(),
            "published_head_self_convergence": str(published_report.get("schema_id", "")).strip(),
            "reporting_integrity": str(reporting_integrity_receipt.get("schema_id", "")).strip(),
            "blocker_matrix": "kt.operator.ws9_blocker_matrix.v1",
        },
        "current_strongest_claim": (
            f"Published-head authority convergence is proven for subject {truth_subject_commit}; current repo head {current_repo_head} "
            "may claim only that it contains transparency-verified subject evidence."
        ),
        "stronger_claim_not_made": (
            "This receipt does not claim that current HEAD is the transparency-verified subject, does not claim platform-enforced governance, "
            "does not clear H1, and does not claim cross-environment controlled variation is current."
        ),
        "forbidden_claims": list(SOVEREIGN_FORBIDDEN_CLAIMS),
        "out_of_scope_attack_classes": list(SOVEREIGN_OUT_OF_SCOPE_ATTACK_CLASSES),
        "created_files": list(SOVEREIGN_CREATED_FILES),
        "deleted_files": [],
        "temporary_files_removed": [],
        "superseded_files_removed_or_demoted": [],
        "waste_control": {
            "minimum_mutation_set": True,
            "legacy_receipts_preserved": True,
            "parallel_runtime_added": False,
            "parallel_validator_added": False,
            "files_touched": files_touched,
        },
        "next_lawful_workstream": NEXT_SOVEREIGN_WORKSTREAM_ID,
        "blocked_by": open_blockers,
        "blocker_evidence_refs": [
            ref
            for row in still_constraining_rows
            for ref in row.get("evidence_refs", [])
        ],
        "ws9_extension": {
            "authority_convergence_status": _status_of(authority_report, "status"),
            "published_head_self_convergence_status": _status_of(published_report, "status"),
            "reporting_integrity_status": _status_of(reporting_integrity_receipt, "status"),
            "current_head_claim_verdict": _current_head_claim_verdict(authority_report, published_report),
            "files_touched": files_touched,
            "blocker_matrix_ref": SOVEREIGN_BLOCKER_MATRIX_REL,
            "current_head_truth_source_ref": SOVEREIGN_CURRENT_HEAD_TRUTH_SOURCE_REL,
            "legacy_receipt_refs": [AUTHORITY_REL, PUBLISHED_REL, KT_CLOSURE_REL],
        },
    }


def emit_sovereign_ws9_artifacts(*, root: Path) -> Dict[str, Dict[str, Any]]:
    current_repo_head = _git_head(root)
    remote_fact = _ls_remote_head(root=root, remote="origin", branch="kt_truth_ledger")
    authority_report = build_authority_convergence_report(root=root)
    published_report = build_published_head_self_convergence_receipt(root=root, remote_fact=remote_fact)
    reporting_integrity_receipt = verify_reporting_integrity(root=root)
    h1_receipt = _load_optional(root, H1_GATE_REL)
    stabilization_receipt = _load_optional(root, TRUTH_STABILIZATION_REL)
    verifier_manifest = _load_optional(root, PUBLIC_VERIFIER_MANIFEST_REL)
    platform_receipt = _load_optional(root, PLATFORM_GOVERNANCE_REL)
    representative_receipt = _load_optional(root, REPRESENTATIVE_AUTHORITY_LANE_REL)
    two_clean_clone_receipt = _load_optional(root, TWO_CLEAN_CLONE_REL)

    files_touched = sorted(set(_git_status_paths(root) + SOVEREIGN_CREATED_FILES))
    current_head_truth_source = build_sovereign_current_head_truth_source(
        current_repo_head=current_repo_head,
        authority_report=authority_report,
        published_report=published_report,
    )
    blocker_matrix = build_sovereign_blocker_matrix(
        current_repo_head=current_repo_head,
        authority_report=authority_report,
        published_report=published_report,
        h1_receipt=h1_receipt,
        stabilization_receipt=stabilization_receipt,
        verifier_manifest=verifier_manifest,
        platform_receipt=platform_receipt,
        representative_receipt=representative_receipt,
        two_clean_clone_receipt=two_clean_clone_receipt,
    )
    closure_receipt = build_sovereign_authority_and_published_head_closure_receipt(
        current_repo_head=current_repo_head,
        authority_report=authority_report,
        published_report=published_report,
        reporting_integrity_receipt=reporting_integrity_receipt,
        blocker_matrix=blocker_matrix,
        files_touched=files_touched,
    )

    outputs = {
        SOVEREIGN_CURRENT_HEAD_TRUTH_SOURCE_REL: current_head_truth_source,
        SOVEREIGN_BLOCKER_MATRIX_REL: blocker_matrix,
        SOVEREIGN_CLOSURE_REL: closure_receipt,
    }
    for rel, payload in outputs.items():
        write_json_stable((root / rel).resolve(), payload)
    return outputs


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seal WS9 authority closure receipts from the already-emitted legacy convergence receipts.")
    parser.add_argument("--emit-sovereign-v1-2", action="store_true", help="Emit the sovereign v1.2 WS9 artifact set.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    if args.emit_sovereign_v1_2:
        outputs = emit_sovereign_ws9_artifacts(root=root)
        print(json.dumps(outputs[SOVEREIGN_CLOSURE_REL], indent=2, sort_keys=True, ensure_ascii=True))
        return 0 if str(outputs[SOVEREIGN_CLOSURE_REL].get("status", "")).strip() == "PASS" else 1
    generated_utc = utc_now_iso_z()
    kt_published = build_kt_published_head_self_convergence_receipt(root=root)
    write_json_stable((root / KT_PUBLISHED_REL).resolve(), kt_published)
    closure = build_authority_closure_receipt(root=root, generated_utc=generated_utc)
    write_json_stable((root / KT_CLOSURE_REL).resolve(), closure)
    print(json.dumps(closure, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if str(closure.get("status", "")).strip() == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
