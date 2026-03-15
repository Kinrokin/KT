from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
FOUNDATION_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_foundation_pack_ratification_receipt.json"
WORK_ORDER_REL = "KT_PROD_CLEANROOM/AUDITS/COUNCIL_PACKET/V2/WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION.v2.json"
PRECEDENCE_NOTE_REL = "KT_PROD_CLEANROOM/AUDITS/COUNCIL_PACKET/V2/WORK_ORDER_KT_MAX_REFACTOR_E2E_EXECUTION_PRECEDENCE.v1.json"

CLOSEOUT_INDEX_REL = f"{REPORT_ROOT_REL}/ws0_ws11_closeout_receipt_index.json"
CLOSEOUT_BLOCKERS_REL = f"{REPORT_ROOT_REL}/ws0_ws11_closeout_blocker_register.json"
CLOSEOUT_LADDER_REL = f"{REPORT_ROOT_REL}/ws0_ws11_closeout_proof_class_ladder.json"
CLOSEOUT_SUMMARY_REL = f"{REPORT_ROOT_REL}/ws0_ws11_closeout_summary.json"

BUNDLE_REL = f"{REPORT_ROOT_REL}/kt_governance_closeout_bundle.json"
BLOCKER_LADDER_REL = f"{REPORT_ROOT_REL}/kt_open_blocker_ladder.json"
CLAIM_CEILING_REL = f"{REPORT_ROOT_REL}/kt_claim_ceiling_summary.json"
EVIDENCE_MAP_REL = f"{REPORT_ROOT_REL}/kt_governance_evidence_subject_map.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_governance_baseline_ingestion_receipt.json"

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/governance_baseline_ingest.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_governance_baseline_ingest.py"

CLOSEOUT_REFS = [
    CLOSEOUT_INDEX_REL,
    CLOSEOUT_BLOCKERS_REL,
    CLOSEOUT_LADDER_REL,
    CLOSEOUT_SUMMARY_REL,
]

DELIVERABLE_REFS = [
    BUNDLE_REL,
    BLOCKER_LADDER_REL,
    CLAIM_CEILING_REL,
    EVIDENCE_MAP_REL,
]

SUBJECT_ARTIFACT_REFS = DELIVERABLE_REFS + [TOOL_REL, TEST_REL]
PLANNED_MUTATES = SUBJECT_ARTIFACT_REFS + [RECEIPT_REL]

WORK_ORDER_ID = "WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION"
WORK_ORDER_SCHEMA_ID = "kt.work_order.max_refactor_e2e_institutional_memory_and_full_stack_adjudication.v2"

SEVERITY_RANK = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
BLOCKER_TO_PROOF_CLASSES = {
    "PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED": ["PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN", "H1_SINGLE_ADAPTER_ALLOWED"],
    "AUTHORITY_CONVERGENCE_UNRESOLVED": ["PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN", "H1_SINGLE_ADAPTER_ALLOWED"],
    "TRUTH_PUBLICATION_STABILIZED_FALSE": ["H1_SINGLE_ADAPTER_ALLOWED"],
    "PLATFORM_ENFORCEMENT_UNPROVEN": ["PLATFORM_ENFORCEMENT_PROVEN"],
    "CROSS_ENV_CONTROLLED_VARIATION_NOT_RUN": ["CROSS_ENV_CONTROLLED_VARIATION_COMPLETE"],
    "H1_ACTIVATION_GATE_CLOSED": ["H1_SINGLE_ADAPTER_ALLOWED"],
}

UNPROVEN_CLASS_IDS = {
    "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN",
    "H1_SINGLE_ADAPTER_ALLOWED",
    "PLATFORM_ENFORCEMENT_PROVEN",
    "CROSS_ENV_CONTROLLED_VARIATION_COMPLETE",
}

PROTECTED_PREFIXES = (
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/",
    "kt_truth_ledger:",
    ".github/workflows/",
    "KT_PROD_CLEANROOM/docs/commercial/",
)


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    try:
        return _git(root, "rev-parse", "HEAD")
    except Exception:  # noqa: BLE001
        return ""


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
    return [str(line).strip() for line in output.splitlines() if str(line).strip()]


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
        output = _git(root, "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", commit)
    except Exception:  # noqa: BLE001
        return []
    files = []
    for line in output.splitlines():
        value = str(line).strip().replace("\\", "/")
        if value:
            files.append(value)
    return files


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
    files = []
    for line in output.splitlines():
        value = str(line).strip().replace("\\", "/")
        if value:
            files.append(value)
    return files


def _is_protected(path: str) -> bool:
    normalized = str(path).replace("\\", "/")
    return any(normalized.startswith(prefix) for prefix in PROTECTED_PREFIXES)


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _artifact_meta(root: Path, rel: str) -> Dict[str, Any]:
    payload = _load_required(root, rel)
    return {
        "artifact_ref": rel,
        "generated_utc": str(payload.get("generated_utc", "")).strip(),
        "schema_id": str(payload.get("schema_id", "")).strip(),
        "status": str(payload.get("status", payload.get("closeout_verdict", ""))).strip(),
    }


def _baseline_context(root: Path) -> Dict[str, Any]:
    foundation = _load_required(root, FOUNDATION_RECEIPT_REL)
    if str(foundation.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: Step 1 baseline ingestion is blocked until the foundation pack ratification receipt is PASS.")

    summary = _load_required(root, CLOSEOUT_SUMMARY_REL)
    blockers = _load_required(root, CLOSEOUT_BLOCKERS_REL)
    ladder = _load_required(root, CLOSEOUT_LADDER_REL)
    index = _load_required(root, CLOSEOUT_INDEX_REL)
    work_order = _load_required(root, WORK_ORDER_REL)
    precedence = _load_required(root, PRECEDENCE_NOTE_REL)

    compiled_heads = {
        str(summary.get("compiled_head_commit", "")).strip(),
        str(blockers.get("compiled_head_commit", "")).strip(),
        str(ladder.get("compiled_head_commit", "")).strip(),
        str(index.get("compiled_head_commit", "")).strip(),
    }
    compiled_heads.discard("")
    if len(compiled_heads) != 1:
        raise RuntimeError("FAIL_CLOSED: baseline closeout artifacts do not agree on a single compiled_head_commit.")

    baseline_subject_commit = next(iter(compiled_heads))
    baseline_evidence_commit = _git_last_commit_for_paths(root, CLOSEOUT_REFS)
    if not baseline_evidence_commit:
        raise RuntimeError("FAIL_CLOSED: governance baseline evidence commit is not discoverable.")

    return {
        "baseline_evidence_commit": baseline_evidence_commit,
        "baseline_subject_commit": baseline_subject_commit,
        "blockers": blockers,
        "foundation_receipt": foundation,
        "foundation_receipt_evidence_commit": _git_last_commit_for_paths(root, [FOUNDATION_RECEIPT_REL]),
        "index": index,
        "ladder": ladder,
        "precedence": precedence,
        "summary": summary,
        "work_order": work_order,
    }


def _load_domain_receipt(root: Path, rel: str) -> Dict[str, Any]:
    return _load_required(root, rel)


def build_governance_evidence_subject_map(*, root: Path) -> Dict[str, Any]:
    ctx = _baseline_context(root)
    public_verifier = _load_domain_receipt(root, f"{REPORT_ROOT_REL}/public_verifier_manifest.json")
    platform = _load_domain_receipt(root, f"{REPORT_ROOT_REL}/platform_governance_narrowing_receipt.json")
    runtime_boundary = _load_domain_receipt(root, f"{REPORT_ROOT_REL}/runtime_boundary_integrity_receipt.json")
    representative = _load_domain_receipt(root, f"{REPORT_ROOT_REL}/representative_authority_lane_reproducibility_receipt.json")
    frontier = _load_domain_receipt(root, f"{REPORT_ROOT_REL}/frontier_settlement_receipt.json")
    h1_gate = _load_domain_receipt(root, f"{REPORT_ROOT_REL}/h1_activation_gate_receipt.json")

    entries = [
        {
            "domain_id": "governance_closeout_baseline",
            "evidence_commit": ctx["baseline_evidence_commit"],
            "subject_commit": ctx["baseline_subject_commit"],
            "verdict": str(ctx["summary"].get("closeout_verdict", "")).strip(),
            "claim_boundary": str(ctx["summary"].get("claim_boundary", "")).strip(),
            "evidence_refs": list(CLOSEOUT_REFS),
        },
        {
            "domain_id": "transparency_verified_truth_subject",
            "evidence_commit": _git_last_commit_for_paths(
                root,
                [f"{REPORT_ROOT_REL}/cryptographic_publication_receipt.json", f"{REPORT_ROOT_REL}/cryptographic_publication/authority_subject.json"],
            ),
            "subject_commit": str(public_verifier.get("truth_subject_commit", "")).strip(),
            "verdict": str(public_verifier.get("subject_verdict", "")).strip(),
            "claim_boundary": str(public_verifier.get("claim_boundary", "")).strip(),
            "evidence_refs": [
                f"{REPORT_ROOT_REL}/cryptographic_publication_receipt.json",
                f"{REPORT_ROOT_REL}/cryptographic_publication/authority_subject.json",
                f"{REPORT_ROOT_REL}/public_verifier_manifest.json",
            ],
        },
        {
            "domain_id": "workflow_governance_only",
            "evidence_commit": _git_last_commit_for_paths(
                root,
                [f"{REPORT_ROOT_REL}/platform_governance_narrowing_receipt.json", f"{REPORT_ROOT_REL}/public_verifier_manifest.json"],
            ),
            "subject_commit": str(platform.get("platform_governance_subject_commit", "")).strip(),
            "verdict": str(platform.get("platform_governance_verdict", "")).strip(),
            "claim_boundary": str(platform.get("platform_governance_claim_boundary", "")).strip(),
            "evidence_refs": [
                f"{REPORT_ROOT_REL}/platform_governance_narrowing_receipt.json",
                f"{REPORT_ROOT_REL}/public_verifier_manifest.json",
            ],
        },
        {
            "domain_id": "canonical_runtime_boundary",
            "evidence_commit": _git_last_commit_for_paths(
                root,
                [
                    f"{REPORT_ROOT_REL}/runtime_boundary_integrity_receipt.json",
                    f"{REPORT_ROOT_REL}/commercial_claim_compiler_receipt.json",
                    f"{REPORT_ROOT_REL}/commercial_program_catalog.json",
                ],
            ),
            "subject_commit": str(runtime_boundary.get("runtime_boundary_subject_commit", "")).strip(),
            "verdict": str(runtime_boundary.get("runtime_boundary_verdict", "")).strip(),
            "claim_boundary": "Canonical runtime proof applies to runtime_boundary_subject_commit only; later evidence heads contain proof for that subject unless SHAs match.",
            "evidence_refs": [
                f"{REPORT_ROOT_REL}/runtime_boundary_integrity_receipt.json",
                f"{REPORT_ROOT_REL}/commercial_claim_compiler_receipt.json",
                f"{REPORT_ROOT_REL}/commercial_program_catalog.json",
            ],
        },
        {
            "domain_id": "representative_authority_lane_reproducibility",
            "evidence_commit": _git_last_commit_for_paths(
                root,
                [
                    f"{REPORT_ROOT_REL}/representative_authority_lane_reproducibility_receipt.json",
                    f"{REPORT_ROOT_REL}/proofrunbundle_index.json",
                    f"{REPORT_ROOT_REL}/twocleanclone_proof.json",
                ],
            ),
            "subject_commit": str(representative.get("validated_head_sha", "")).strip(),
            "verdict": "REPRESENTATIVE_SAME_MVE_ONLY" if bool(representative.get("representative_authority_lane_proven")) else "NOT_PROVEN",
            "claim_boundary": "Representative authority-lane reproducibility is proven only on the same MVE, not across controlled environment variation.",
            "evidence_refs": [
                f"{REPORT_ROOT_REL}/representative_authority_lane_reproducibility_receipt.json",
                f"{REPORT_ROOT_REL}/proofrunbundle_index.json",
                f"{REPORT_ROOT_REL}/twocleanclone_proof.json",
            ],
        },
        {
            "domain_id": "frontier_settlement_h1_gate",
            "evidence_commit": _git_last_commit_for_paths(
                root,
                [
                    f"{REPORT_ROOT_REL}/frontier_settlement_receipt.json",
                    f"{REPORT_ROOT_REL}/h1_activation_gate_receipt.json",
                    f"{REPORT_ROOT_REL}/next_horizon_activation_receipt.json",
                ],
            ),
            "subject_commit": str(frontier.get("compiled_head_commit", "")).strip(),
            "verdict": str(frontier.get("frontier_settlement_verdict", "")).strip(),
            "claim_boundary": str(h1_gate.get("claim_boundary", "")).strip()
            or "Frontier settlement is proven only as an evaluation; H1 remains blocked unless the explicit activation gate changes.",
            "evidence_refs": [
                f"{REPORT_ROOT_REL}/frontier_settlement_receipt.json",
                f"{REPORT_ROOT_REL}/h1_activation_gate_receipt.json",
                f"{REPORT_ROOT_REL}/next_horizon_activation_receipt.json",
            ],
        },
        {
            "domain_id": "foundation_pack_gate",
            "evidence_commit": str(ctx["foundation_receipt_evidence_commit"]).strip(),
            "subject_commit": str(ctx["foundation_receipt"].get("compiled_head_commit", "")).strip(),
            "verdict": str(ctx["foundation_receipt"].get("pass_verdict", "")).strip(),
            "claim_boundary": str(ctx["foundation_receipt"].get("claim_boundary", "")).strip(),
            "evidence_refs": [FOUNDATION_RECEIPT_REL],
        },
    ]

    return {
        "schema_id": "kt.operator.governance_evidence_subject_map.v1",
        "generated_utc": utc_now_iso_z(),
        "baseline_subject_commit": ctx["baseline_subject_commit"],
        "baseline_evidence_commit": ctx["baseline_evidence_commit"],
        "claim_boundary": (
            "This map freezes governance-domain evidence_commit versus subject_commit pairs for the sealed baseline. "
            "Later repository heads may contain this map as evidence, but they do not become the mapped subject commits unless the SHAs match."
        ),
        "entries": entries,
    }


def build_claim_ceiling_summary(*, root: Path) -> Dict[str, Any]:
    ctx = _baseline_context(root)
    evidence_map = build_governance_evidence_subject_map(root=root)
    ladder_levels = [row for row in ctx["ladder"].get("levels", []) if isinstance(row, dict)]
    attained_levels = [row for row in ladder_levels if bool(row.get("attained"))]
    unattained_levels = [row for row in ladder_levels if not bool(row.get("attained"))]
    highest_attained = max(attained_levels, key=lambda row: int(row.get("rank", 0)))

    evidence_map_by_domain = {row["domain_id"]: row for row in evidence_map["entries"]}

    return {
        "schema_id": "kt.operator.claim_ceiling_summary.v1",
        "generated_utc": utc_now_iso_z(),
        "baseline_subject_commit": ctx["baseline_subject_commit"],
        "baseline_evidence_commit": ctx["baseline_evidence_commit"],
        "closeout_verdict": str(ctx["summary"].get("closeout_verdict", "")).strip(),
        "highest_attained_proof_class": {
            "proof_class_id": str(highest_attained.get("proof_class_id", "")).strip(),
            "rank": int(highest_attained.get("rank", 0)),
            "subject_commit": str(highest_attained.get("subject_commit", "")).strip(),
            "boundary": str(highest_attained.get("boundary", "")).strip(),
        },
        "current_ceiling_by_domain": {
            "truth_subject": {
                "ceiling_id": "PUBLISHED_HEAD_TRANSPARENCY_VERIFIED_SUBJECT",
                "subject_commit": evidence_map_by_domain["transparency_verified_truth_subject"]["subject_commit"],
                "evidence_commit": evidence_map_by_domain["transparency_verified_truth_subject"]["evidence_commit"],
                "boundary": evidence_map_by_domain["transparency_verified_truth_subject"]["claim_boundary"],
            },
            "governance": {
                "ceiling_id": "WORKFLOW_GOVERNANCE_ONLY",
                "subject_commit": evidence_map_by_domain["workflow_governance_only"]["subject_commit"],
                "evidence_commit": evidence_map_by_domain["workflow_governance_only"]["evidence_commit"],
                "boundary": evidence_map_by_domain["workflow_governance_only"]["claim_boundary"],
            },
            "runtime_boundary": {
                "ceiling_id": "CANONICAL_RUNTIME_BOUNDARY_SETTLED",
                "subject_commit": evidence_map_by_domain["canonical_runtime_boundary"]["subject_commit"],
                "evidence_commit": evidence_map_by_domain["canonical_runtime_boundary"]["evidence_commit"],
                "boundary": evidence_map_by_domain["canonical_runtime_boundary"]["claim_boundary"],
            },
            "reproducibility": {
                "ceiling_id": "REPRESENTATIVE_AUTHORITY_LANE_SAME_MVE_ONLY",
                "subject_commit": evidence_map_by_domain["representative_authority_lane_reproducibility"]["subject_commit"],
                "evidence_commit": evidence_map_by_domain["representative_authority_lane_reproducibility"]["evidence_commit"],
                "boundary": evidence_map_by_domain["representative_authority_lane_reproducibility"]["claim_boundary"],
            },
            "activation": {
                "ceiling_id": "H1_BLOCKED",
                "subject_commit": evidence_map_by_domain["frontier_settlement_h1_gate"]["subject_commit"],
                "evidence_commit": evidence_map_by_domain["frontier_settlement_h1_gate"]["evidence_commit"],
                "boundary": "Frontier settlement is proven as evaluation only; H1 remains blocked.",
            },
        },
        "unattained_proof_classes": [
            {
                "proof_class_id": str(row.get("proof_class_id", "")).strip(),
                "rank": int(row.get("rank", 0)),
                "subject_commit": str(row.get("subject_commit", "")).strip(),
                "boundary": str(row.get("boundary", "")).strip(),
            }
            for row in unattained_levels
        ],
        "no_new_governance_victory_claims": True,
    }


def build_open_blocker_ladder(*, root: Path) -> Dict[str, Any]:
    ctx = _baseline_context(root)
    remaining = [row for row in ctx["blockers"].get("remaining_blockers", []) if isinstance(row, dict)]
    remaining_sorted = sorted(remaining, key=lambda row: (SEVERITY_RANK.get(str(row.get("severity", "")).strip(), 99), str(row.get("blocker_id", "")).strip()))
    return {
        "schema_id": "kt.operator.open_blocker_ladder.v1",
        "generated_utc": utc_now_iso_z(),
        "baseline_subject_commit": ctx["baseline_subject_commit"],
        "baseline_evidence_commit": ctx["baseline_evidence_commit"],
        "claim_boundary": (
            "This ladder freezes only the open governance blockers inherited from the sealed WS0-WS11 baseline. "
            "It does not reopen them or imply that they were cleared by Step 1 ingestion."
        ),
        "open_blocker_count": len(remaining_sorted),
        "blocker_ladder": [
            {
                "rank": index + 1,
                "blocker_id": str(row.get("blocker_id", "")).strip(),
                "severity": str(row.get("severity", "")).strip(),
                "status": str(row.get("status", "")).strip(),
                "blocks": list(row.get("blocks", [])),
                "blocked_proof_classes": list(BLOCKER_TO_PROOF_CLASSES.get(str(row.get("blocker_id", "")).strip(), [])),
                "evidence_refs": list(row.get("evidence_refs", [])),
            }
            for index, row in enumerate(remaining_sorted)
        ],
        "resolved_blocker_ids": [str(row.get("blocker_id", "")).strip() for row in ctx["blockers"].get("resolved_blockers", []) if isinstance(row, dict)],
    }


def build_governance_closeout_bundle(*, root: Path) -> Dict[str, Any]:
    ctx = _baseline_context(root)
    open_ladder = build_open_blocker_ladder(root=root)

    return {
        "schema_id": "kt.operator.governance_closeout_bundle.v1",
        "generated_utc": utc_now_iso_z(),
        "baseline_subject_commit": ctx["baseline_subject_commit"],
        "baseline_evidence_commit": ctx["baseline_evidence_commit"],
        "baseline_is_immutable_input": True,
        "closeout_verdict": str(ctx["summary"].get("closeout_verdict", "")).strip(),
        "foundation_pack_gate": {
            "subject_commit": str(ctx["foundation_receipt"].get("compiled_head_commit", "")).strip(),
            "evidence_commit": str(ctx["foundation_receipt_evidence_commit"]).strip(),
            "status": str(ctx["foundation_receipt"].get("pass_verdict", "")).strip(),
        },
        "claim_boundary": (
            "This bundle freezes the sealed governance/admissibility program as immutable baseline input to the full-stack refactor program. "
            "It may be cited as baseline evidence, but it does not reopen or upgrade any governance victory claim."
        ),
        "source_refs": list(CLOSEOUT_REFS),
        "open_blocker_count": int(open_ladder.get("open_blocker_count", 0)),
        "proven": list(ctx["summary"].get("proven", [])),
        "not_proven": list(ctx["summary"].get("not_proven", [])),
        "claim_ceiling_ref": CLAIM_CEILING_REL,
        "open_blocker_ladder_ref": BLOCKER_LADDER_REL,
        "evidence_subject_map_ref": EVIDENCE_MAP_REL,
        "no_new_governance_victory_claims": True,
    }


def _status_row(*, check: str, passed: bool, detail: str, refs: Sequence[str]) -> Dict[str, Any]:
    return {
        "check": check,
        "detail": detail,
        "refs": list(refs),
        "status": "PASS" if passed else "FAIL",
    }


def build_governance_baseline_ingestion_report(*, root: Path) -> Dict[str, Any]:
    ctx = _baseline_context(root)
    bundle = _load_required(root, BUNDLE_REL)
    blocker_ladder = _load_required(root, BLOCKER_LADDER_REL)
    claim_ceiling = _load_required(root, CLAIM_CEILING_REL)
    evidence_map = _load_required(root, EVIDENCE_MAP_REL)

    checks: List[Dict[str, Any]] = []
    failures: List[str] = []

    foundation_passed = str(ctx["foundation_receipt"].get("status", "")).strip() == "PASS"
    checks.append(
        _status_row(
            check="foundation_pack_gate_passed",
            passed=foundation_passed,
            detail="Step 2 foundation pack ratification must be PASS before Step 1 ingestion is admissible.",
            refs=[FOUNDATION_RECEIPT_REL],
        )
    )
    if not foundation_passed:
        failures.append("foundation_pack_gate_passed")

    closeout_subject_consistent = (
        bundle.get("baseline_subject_commit") == ctx["baseline_subject_commit"]
        and blocker_ladder.get("baseline_subject_commit") == ctx["baseline_subject_commit"]
        and claim_ceiling.get("baseline_subject_commit") == ctx["baseline_subject_commit"]
        and evidence_map.get("baseline_subject_commit") == ctx["baseline_subject_commit"]
    )
    checks.append(
        _status_row(
            check="baseline_subject_commit_explicit_and_consistent",
            passed=closeout_subject_consistent and bool(ctx["baseline_subject_commit"]),
            detail="All Step 1 artifacts must pin the same governance baseline subject commit.",
            refs=DELIVERABLE_REFS,
        )
    )
    if not (closeout_subject_consistent and bool(ctx["baseline_subject_commit"])):
        failures.append("baseline_subject_commit_explicit_and_consistent")

    baseline_evidence_explicit = (
        bundle.get("baseline_evidence_commit") == ctx["baseline_evidence_commit"]
        and blocker_ladder.get("baseline_evidence_commit") == ctx["baseline_evidence_commit"]
        and claim_ceiling.get("baseline_evidence_commit") == ctx["baseline_evidence_commit"]
        and evidence_map.get("baseline_evidence_commit") == ctx["baseline_evidence_commit"]
        and bool(ctx["baseline_evidence_commit"])
    )
    checks.append(
        _status_row(
            check="baseline_evidence_commit_explicit",
            passed=baseline_evidence_explicit,
            detail="All Step 1 artifacts must pin the same governance baseline evidence commit.",
            refs=DELIVERABLE_REFS,
        )
    )
    if not baseline_evidence_explicit:
        failures.append("baseline_evidence_commit_explicit")

    summary_match = bundle.get("proven") == ctx["summary"].get("proven") and bundle.get("not_proven") == ctx["summary"].get("not_proven")
    checks.append(
        _status_row(
            check="proven_vs_not_proven_explicit",
            passed=summary_match and bool(bundle.get("proven")) and bool(bundle.get("not_proven")),
            detail="The baseline bundle must carry explicit proven and not_proven sections without mutation.",
            refs=[BUNDLE_REL, CLOSEOUT_SUMMARY_REL],
        )
    )
    if not (summary_match and bool(bundle.get("proven")) and bool(bundle.get("not_proven"))):
        failures.append("proven_vs_not_proven_explicit")

    blocker_ids = [str(row.get("blocker_id", "")).strip() for row in blocker_ladder.get("blocker_ladder", []) if isinstance(row, dict)]
    source_blocker_ids = [str(row.get("blocker_id", "")).strip() for row in ctx["blockers"].get("remaining_blockers", []) if isinstance(row, dict)]
    blockers_explicit = (
        set(blocker_ids) == set(source_blocker_ids)
        and len(blocker_ids) == len(source_blocker_ids)
        and int(blocker_ladder.get("open_blocker_count", 0)) == len(source_blocker_ids)
        and len(source_blocker_ids) > 0
    )
    checks.append(
        _status_row(
            check="open_blockers_explicit",
            passed=blockers_explicit,
            detail="The blocker ladder must preserve the open blocker set exactly from the sealed closeout baseline.",
            refs=[BLOCKER_LADDER_REL, CLOSEOUT_BLOCKERS_REL],
        )
    )
    if not blockers_explicit:
        failures.append("open_blockers_explicit")

    no_new_victories = (
        str(bundle.get("closeout_verdict", "")).strip() == "SEALED_WITH_OPEN_BLOCKERS"
        and bool(bundle.get("no_new_governance_victory_claims"))
        and bool(claim_ceiling.get("no_new_governance_victory_claims"))
        and str(((claim_ceiling.get("current_ceiling_by_domain") or {}).get("governance") or {}).get("ceiling_id", "")).strip()
        == "WORKFLOW_GOVERNANCE_ONLY"
        and str(((claim_ceiling.get("current_ceiling_by_domain") or {}).get("activation") or {}).get("ceiling_id", "")).strip() == "H1_BLOCKED"
        and UNPROVEN_CLASS_IDS.issubset(
            {str(row.get("proof_class_id", "")).strip() for row in claim_ceiling.get("unattained_proof_classes", []) if isinstance(row, dict)}
        )
    )
    checks.append(
        _status_row(
            check="no_new_governance_victory_claims_introduced",
            passed=no_new_victories,
            detail="Step 1 may freeze the baseline but must not upgrade governance, authority, runtime, or activation claims.",
            refs=[BUNDLE_REL, CLAIM_CEILING_REL, CLOSEOUT_SUMMARY_REL, CLOSEOUT_LADDER_REL],
        )
    )
    if not no_new_victories:
        failures.append("no_new_governance_victory_claims_introduced")

    evidence_map_explicit = len(evidence_map.get("entries", [])) >= 6 and all(
        bool(str(row.get("evidence_commit", "")).strip()) and bool(str(row.get("subject_commit", "")).strip())
        for row in evidence_map.get("entries", [])
        if isinstance(row, dict)
    )
    checks.append(
        _status_row(
            check="governance_evidence_subject_map_explicit",
            passed=evidence_map_explicit,
            detail="The evidence-subject map must expose explicit evidence_commit and subject_commit pairs for the baseline governance domains.",
            refs=[EVIDENCE_MAP_REL],
        )
    )
    if not evidence_map_explicit:
        failures.append("governance_evidence_subject_map_explicit")

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
            detail="Actual touched set must match the lawful Step 1 subject files plus the ingestion receipt.",
            refs=PLANNED_MUTATES,
        )
    )
    if not post_touch_ok:
        failures.append("post_touch_accounting_clean")

    status = "PASS" if not failures else "FAIL_CLOSED"
    verdict = "BASELINE_FROZEN" if status == "PASS" else "BASELINE_AMBIGUOUS_FAIL_CLOSED"

    return {
        "schema_id": "kt.operator.governance_baseline_ingestion_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "pass_verdict": verdict,
        "controlling_work_order": {
            "schema_id": WORK_ORDER_SCHEMA_ID,
            "work_order_id": WORK_ORDER_ID,
            "step_id": 1,
            "step_name": "KT_GOVERNANCE_CLOSEOUT_BASELINE_INGESTION",
        },
        "foundation_gate_ref": FOUNDATION_RECEIPT_REL,
        "foundation_gate_subject_commit": str(ctx["foundation_receipt"].get("compiled_head_commit", "")).strip(),
        "foundation_gate_evidence_commit": str(ctx["foundation_receipt_evidence_commit"]).strip(),
        "current_head_commit": current_head_commit,
        "compiled_head_commit": subject_commit,
        "baseline_subject_commit": ctx["baseline_subject_commit"],
        "baseline_evidence_commit": ctx["baseline_evidence_commit"],
        "claim_boundary": (
            "This receipt validates the Step 1 governance baseline ingestion for compiled_head_commit only. "
            "The frozen governance baseline remains the earlier baseline_subject_commit/baseline_evidence_commit pair; this receipt is later evidence about that pair."
        ),
        "planned_mutates": list(PLANNED_MUTATES),
        "actual_touched": actual_touched,
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "checks": checks,
        "next_lawful_step": {
            "step_id": 3,
            "step_name": "CONSTITUTIONAL_SPINE_AND_META_GOVERNANCE",
            "status_after_step_1": "UNLOCKED" if status == "PASS" else "BLOCKED",
        },
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Freeze the sealed governance closeout baseline into Step 1 ingestion artifacts.")
    parser.add_argument("--root", default="", help="Optional repository root override.")
    parser.add_argument("--emit-receipt", action="store_true", help="Write the Step 1 ingestion receipt instead of the subject deliverables.")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = Path(str(args.root)).resolve() if str(args.root).strip() else repo_root()

    if bool(args.emit_receipt):
        report = build_governance_baseline_ingestion_report(root=root)
        write_json_stable((root / Path(RECEIPT_REL)).resolve(), report)
        print(
            json.dumps(
                {
                    "status": report["status"],
                    "pass_verdict": report["pass_verdict"],
                    "compiled_head_commit": report["compiled_head_commit"],
                    "baseline_subject_commit": report["baseline_subject_commit"],
                    "baseline_evidence_commit": report["baseline_evidence_commit"],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if report["status"] == "PASS" else 1

    payloads = {
        BUNDLE_REL: build_governance_closeout_bundle(root=root),
        BLOCKER_LADDER_REL: build_open_blocker_ladder(root=root),
        CLAIM_CEILING_REL: build_claim_ceiling_summary(root=root),
        EVIDENCE_MAP_REL: build_governance_evidence_subject_map(root=root),
    }

    writes: List[Dict[str, Any]] = []
    for rel, payload in payloads.items():
        changed = write_json_stable((root / Path(rel)).resolve(), payload)
        writes.append({"artifact_ref": rel, "updated": changed, "schema_id": str(payload.get("schema_id", "")).strip()})

    print(
        json.dumps(
            {
                "status": "PASS",
                "baseline_subject_commit": payloads[BUNDLE_REL]["baseline_subject_commit"],
                "baseline_evidence_commit": payloads[BUNDLE_REL]["baseline_evidence_commit"],
                "artifacts_written": writes,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
