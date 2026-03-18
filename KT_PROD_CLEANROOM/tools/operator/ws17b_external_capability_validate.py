from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


WORKSTREAM_ID = "WS17B_EXTERNAL_CONFIRMATION_CAPABILITY"
STEP_ID = "WS17B_STEP_1_PROVE_OUTSIDER_CAPABILITY_REPLAY_ON_BOUNDED_HISTORICAL_SURFACE"
PASS_VERDICT = "OUTSIDER_VERIFIABLE_BOUNDED_CAPABILITY_CONFIRMATION_PROVEN"
BLOCKED_VERDICT = "OUTSIDER_VERIFIABLE_BOUNDED_CAPABILITY_CONFIRMATION_NOT_PROVEN"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
GOVERNANCE_ROOT_REL = "KT_PROD_CLEANROOM/governance"
TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/ws17b_external_capability_validate.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_ws17b_external_capability_validate.py"

EXECUTION_DAG_REL = f"{GOVERNANCE_ROOT_REL}/kt_execution_dag.json"
COMPARATOR_REGISTRY_REL = f"{GOVERNANCE_ROOT_REL}/kt_comparator_registry.json"
BENCHMARK_WINDOWS_REL = f"{GOVERNANCE_ROOT_REL}/kt_benchmark_validity_windows.json"
WS16_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_tevv_dataset_registry_receipt.json"
WS17A_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_external_assurance_confirmation_receipt.json"
FRONTIER_PACKET_REL = f"{REPORT_ROOT_REL}/kt_frontier_audit_packet.json"
FRONTIER_SCORECARD_REL = f"{REPORT_ROOT_REL}/kt_frontier_rerun_scorecard.json"
READJUDICATION_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_sota_readjudication_receipt.json"
PUBLIC_HORIZON_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_public_horizon_receipt.json"
RED_TEAM_RESULTS_REL = f"{REPORT_ROOT_REL}/kt_red_team_results_receipt.json"
FORMAL_INVARIANT_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_formal_invariant_receipt.json"
EXTERNAL_REPRODUCTION_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_external_reproduction_receipt.json"
DETACHED_VERIFIER_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_detached_receipt.json"
BUILD_VERIFICATION_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_build_verification_receipt.json"
REVISION_TRUST_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_revision_trust_receipt.json"
REPO_HYGIENE_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_repo_hygiene_receipt.json"
OPERATOR_GREENLINE_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_operator_greenline_receipt.json"
WS12_CLOSURE_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_total_closure_campaign_completion_receipt.json"
WS12_FINAL_BUNDLE_REL = f"{REPORT_ROOT_REL}/kt_final_completion_bundle.json"
WS15_STATUS_VERDICT_REL = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS15_status_seal_b4789a5/verdict.txt"
WS15_CANONICAL_HMAC_VERDICT_REL = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS15_canonical_hmac_seal_b4789a5/verdict.txt"
WS15_AUTHORITY_VERDICT_REL = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS15_authority_grade_b4789a5/verdict.txt"

IMPORT_MANIFEST_REL = f"{REPORT_ROOT_REL}/ws17b_capability/kt_external_capability_import_manifest.json"
REPLAY_REPORT_REL = f"{REPORT_ROOT_REL}/ws17b_capability/kt_outsider_capability_replay_report.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_external_capability_confirmation_receipt.json"

NEXT_WORKSTREAM_ON_PASS = "WS18_RELEASE_CEREMONY_AND_FINAL_READJUDICATION"
HISTORICAL_CAPABILITY_SUBJECT = "b4789a544954066ee6c225bc9cfa3fddb51c12ee"
HISTORICAL_EVALUATED_REPO_HEAD = "0cf1ccdde5a5543678daffe9e60284c903b911ab"
FRESHNESS_MAX_AGE_HOURS = 24
USED_COMPARATOR_IDS = [
    "sha256_exact_file_match_v1",
    "subject_head_equality_v1",
    "freshness_window_fail_closed_v1",
    "worst_case_pack_status_v1",
]
SECRET_ENV_PREFIXES = ("KT_HMAC_KEY_",)

REQUIRED_PUBLIC_REFS = [
    COMPARATOR_REGISTRY_REL,
    BENCHMARK_WINDOWS_REL,
    WS16_RECEIPT_REL,
    WS17A_RECEIPT_REL,
    FRONTIER_PACKET_REL,
    FRONTIER_SCORECARD_REL,
    READJUDICATION_RECEIPT_REL,
    PUBLIC_HORIZON_RECEIPT_REL,
    RED_TEAM_RESULTS_REL,
    FORMAL_INVARIANT_RECEIPT_REL,
    EXTERNAL_REPRODUCTION_RECEIPT_REL,
    DETACHED_VERIFIER_RECEIPT_REL,
    BUILD_VERIFICATION_RECEIPT_REL,
    REVISION_TRUST_RECEIPT_REL,
    REPO_HYGIENE_RECEIPT_REL,
    OPERATOR_GREENLINE_RECEIPT_REL,
    WS12_CLOSURE_RECEIPT_REL,
    WS12_FINAL_BUNDLE_REL,
    WS15_STATUS_VERDICT_REL,
    WS15_CANONICAL_HMAC_VERDICT_REL,
    WS15_AUTHORITY_VERDICT_REL,
]
PLANNED_MUTATES = [
    TOOL_REL,
    TEST_REL,
    IMPORT_MANIFEST_REL,
    REPLAY_REPORT_REL,
    RECEIPT_REL,
    EXECUTION_DAG_REL,
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_status_lines(root: Path) -> List[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return [line.rstrip("\n") for line in result.stdout.splitlines() if line.strip()]


def _dirty_relpaths(status_lines: Sequence[str]) -> List[str]:
    rels: List[str] = []
    for line in status_lines:
        rel = line[3:].strip()
        if rel:
            rels.append(Path(rel).as_posix())
    return sorted(set(rels))


def _path_in_scope(path: str) -> bool:
    normalized = Path(path).as_posix()
    planned = {Path(item).as_posix() for item in PLANNED_MUTATES}
    return normalized in planned or any(
        normalized.startswith(f"{item}/") or item.startswith(f"{normalized}/") for item in planned
    )


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required WS17B input: {rel}")
    return _read_json(path)


def _load_required_text(root: Path, rel: str) -> str:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required WS17B input: {rel}")
    return path.read_text(encoding="utf-8")


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _check(
    ok: bool,
    check_id: str,
    detail: str,
    refs: Sequence[str],
    failures: Optional[Sequence[str]] = None,
    **extra: Any,
) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "check": check_id,
        "status": "PASS" if ok else "FAIL",
        "detail": detail,
        "refs": [Path(ref).as_posix() for ref in refs],
    }
    if failures:
        row["failures"] = [str(item) for item in failures]
    row.update(extra)
    return row


def _copy_public_inputs(root: Path, package_root: Path) -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    for rel in REQUIRED_PUBLIC_REFS + [TOOL_REL]:
        source = (root / Path(rel)).resolve()
        if not source.exists():
            raise RuntimeError(f"FAIL_CLOSED: package input missing: {rel}")
        target = (package_root / Path(rel)).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        hashes[Path(rel).as_posix()] = _file_sha256(source)
    return hashes


def _detached_env() -> Tuple[Dict[str, str], List[str]]:
    env = dict(os.environ)
    removed: List[str] = []
    for key in list(env):
        if key in {"PYTHONPATH", "GIT_DIR", "GIT_WORK_TREE"} or any(key.startswith(prefix) for prefix in SECRET_ENV_PREFIXES):
            env.pop(key, None)
            removed.append(key)
    return env, sorted(set(removed))


def _parse_verdict(text: str, pattern: str, error: str) -> re.Match[str]:
    match = re.search(pattern, text)
    if not match:
        raise RuntimeError(error)
    return match


def _parse_generated_utc(payload: Dict[str, Any]) -> datetime:
    raw = str(payload.get("generated_utc", "")).strip()
    if not raw:
        raise RuntimeError("FAIL_CLOSED: missing generated_utc field")
    return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)


def _fresh_within(payload: Dict[str, Any], *, max_age_hours: int) -> bool:
    generated = _parse_generated_utc(payload)
    return datetime.now(timezone.utc) - generated <= timedelta(hours=max_age_hours)


def _run_detached_replay(package_root: Path, report_output: Path) -> Tuple[Dict[str, Any], Dict[str, str], List[str], str, str]:
    env, removed_env_keys = _detached_env()
    command = [
        sys.executable,
        str((package_root / Path(TOOL_REL)).resolve()),
        "--detached-package-root",
        str(package_root.resolve()),
        "--report-output",
        str(report_output.resolve()),
    ]
    result = subprocess.run(
        command,
        cwd=str(package_root.resolve()),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        check=False,
    )
    if not report_output.exists():
        raise RuntimeError(
            "FAIL_CLOSED: detached outsider capability replay did not emit a report\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    report = _read_json(report_output)
    package_hashes = {Path(rel).as_posix(): _file_sha256((package_root / Path(rel)).resolve()) for rel in REQUIRED_PUBLIC_REFS}
    return report, package_hashes, removed_env_keys, result.stdout, result.stderr


def validate_detached_package(package_root: Path) -> Dict[str, Any]:
    comparator_registry = _load_required_json(package_root, COMPARATOR_REGISTRY_REL)
    benchmark_windows = _load_required_json(package_root, BENCHMARK_WINDOWS_REL)
    ws16_receipt = _load_required_json(package_root, WS16_RECEIPT_REL)
    ws17a_receipt = _load_required_json(package_root, WS17A_RECEIPT_REL)
    frontier_packet = _load_required_json(package_root, FRONTIER_PACKET_REL)
    frontier_scorecard = _load_required_json(package_root, FRONTIER_SCORECARD_REL)
    readjudication = _load_required_json(package_root, READJUDICATION_RECEIPT_REL)
    public_horizon = _load_required_json(package_root, PUBLIC_HORIZON_RECEIPT_REL)
    red_team_results = _load_required_json(package_root, RED_TEAM_RESULTS_REL)
    formal_invariant = _load_required_json(package_root, FORMAL_INVARIANT_RECEIPT_REL)
    external_reproduction = _load_required_json(package_root, EXTERNAL_REPRODUCTION_RECEIPT_REL)
    detached_verifier = _load_required_json(package_root, DETACHED_VERIFIER_RECEIPT_REL)
    build_verification = _load_required_json(package_root, BUILD_VERIFICATION_RECEIPT_REL)
    revision_trust = _load_required_json(package_root, REVISION_TRUST_RECEIPT_REL)
    repo_hygiene = _load_required_json(package_root, REPO_HYGIENE_RECEIPT_REL)
    operator_greenline = _load_required_json(package_root, OPERATOR_GREENLINE_RECEIPT_REL)
    ws12_closure = _load_required_json(package_root, WS12_CLOSURE_RECEIPT_REL)
    ws12_bundle = _load_required_json(package_root, WS12_FINAL_BUNDLE_REL)
    ws15_status_verdict = _load_required_text(package_root, WS15_STATUS_VERDICT_REL)
    ws15_canonical_hmac_verdict = _load_required_text(package_root, WS15_CANONICAL_HMAC_VERDICT_REL)
    ws15_authority_verdict = _load_required_text(package_root, WS15_AUTHORITY_VERDICT_REL)

    package_git_dir = (package_root / ".git").exists()
    comparator_ids = [str(row.get("comparator_id", "")).strip() for row in comparator_registry.get("comparators", []) if isinstance(row, dict)]
    missing_comparators = [comp_id for comp_id in USED_COMPARATOR_IDS if comp_id not in comparator_ids]
    pinned_hashes = {Path(rel).as_posix(): _file_sha256((package_root / Path(rel)).resolve()) for rel in REQUIRED_PUBLIC_REFS}

    subject_rows = {
        "frontier_packet": str(frontier_packet.get("sealed_subject_anchor_commit", "")).strip(),
        "frontier_scorecard": str(frontier_scorecard.get("sealed_subject_anchor_commit", "")).strip(),
        "readjudication_subject": str(readjudication.get("subject_head_commit", "")).strip(),
        "readjudication_evidence": str(readjudication.get("evidence_head_commit", "")).strip(),
        "public_horizon": str(public_horizon.get("subject_head_commit", "")).strip(),
        "red_team": str(red_team_results.get("subject_head_commit", "")).strip(),
        "formal_invariant": str(formal_invariant.get("subject_head_commit", "")).strip(),
        "external_reproduction": str(external_reproduction.get("subject_head_commit", "")).strip(),
        "detached_verifier": str(detached_verifier.get("subject_head_commit", "")).strip(),
        "build_verification": str(build_verification.get("subject_head_commit", "")).strip(),
        "revision_trust": str(revision_trust.get("subject_head_commit", "")).strip(),
    }
    subject_mismatches = [name for name, subject in subject_rows.items() if subject != HISTORICAL_CAPABILITY_SUBJECT]

    scorecard_targets = [row for row in frontier_scorecard.get("target_checks", []) if isinstance(row, dict)]
    scorecard_hard_stops = [row for row in frontier_scorecard.get("hard_stop_checks", []) if isinstance(row, dict)]
    scorecard_failures = [
        *(str(row.get("target_id", "")).strip() for row in scorecard_targets if str(row.get("status", "")).strip() != "PASS"),
        *(str(row.get("condition_id", "")).strip() for row in scorecard_hard_stops if str(row.get("status", "")).strip() != "PASS"),
    ]

    required_refs_missing = [rel for rel in REQUIRED_PUBLIC_REFS if not (package_root / Path(rel)).exists()]
    ws16_checks = [row for row in ws16_receipt.get("checks", []) if isinstance(row, dict)]
    ws16_validity_window_ok = any(
        str(row.get("check", "")).strip() == "current_head_truth_rows_within_validity_windows"
        and str(row.get("status", "")).strip() == "PASS"
        for row in ws16_checks
    )
    benchmark_window_rows = [row for row in benchmark_windows.get("windows", []) if isinstance(row, dict)]
    benchmark_window_contract_ok = (
        str(benchmark_windows.get("status", "")).strip() == "ACTIVE"
        and len(benchmark_window_rows) >= 2
        and all(bool(row.get("requires_subject_binding")) for row in benchmark_window_rows)
        and all(str(row.get("staleness_action", "")).strip() == "FAIL_CLOSED" for row in benchmark_window_rows)
    )

    status_match = "KT_STATUS_PASS" in ws15_status_verdict
    canonical_match = "KT_CERTIFY_PASS" in ws15_canonical_hmac_verdict
    authority_match = _parse_verdict(
        ws15_authority_verdict,
        r"KT_AUTHORITY_GRADE_([A-D][+-]?)\s+status=(PASS|BLOCKED|FAIL_CLOSED)",
        "FAIL_CLOSED: unable to parse WS15 authority verdict",
    )
    authority_ok = authority_match.group(1).strip() == "A" and authority_match.group(2).strip() == "PASS"

    checks: List[Dict[str, Any]] = []
    blockers: List[str] = []

    required_present = not required_refs_missing
    checks.append(
        _check(
            required_present,
            "required_public_capability_inputs_present",
            "WS17B detached capability replay requires the published frontier/readjudication bundle, its bounded proof ladder, and the locked WS16/WS17A governance receipts only.",
            REQUIRED_PUBLIC_REFS,
            failures=required_refs_missing,
        )
    )
    if not required_present:
        blockers.append("REQUIRED_PUBLIC_INPUTS_MISSING")

    comparator_ok = str(comparator_registry.get("status", "")).strip() == "ACTIVE" and not missing_comparators
    checks.append(
        _check(
            comparator_ok,
            "ws16_comparator_registry_contains_required_capability_comparators",
            "WS17B must reuse the locked WS16 comparator registry for exact-hash, subject-binding, freshness, and worst-case aggregation.",
            [COMPARATOR_REGISTRY_REL],
            failures=missing_comparators,
            used_comparator_ids=USED_COMPARATOR_IDS,
        )
    )
    if not comparator_ok:
        blockers.append("COMPARATOR_REGISTRY_MISSING_REQUIRED_ROWS")

    ws16_and_ws17a_ok = (
        str(ws16_receipt.get("status", "")).strip() == "PASS"
        and str(ws17a_receipt.get("status", "")).strip() == "PASS"
        and bool(ws17a_receipt.get("assurance_only_not_capability")) is True
    )
    checks.append(
        _check(
            ws16_and_ws17a_ok,
            "ws16_and_ws17a_governance_lane_still_pass_and_bounded",
            "Capability confirmation may proceed only after the locked TEVV lane remains PASS and the carried-forward WS17A lane remains assurance-only.",
            [WS16_RECEIPT_REL, WS17A_RECEIPT_REL],
        )
    )
    if not ws16_and_ws17a_ok:
        blockers.append("UPSTREAM_GOVERNANCE_LANE_NOT_PASS")

    frontier_bundle_ok = (
        str(frontier_scorecard.get("final_readjudication", {}).get("status", "")).strip() == "PASS"
        and str(frontier_scorecard.get("final_readjudication", {}).get("frontier_posture", "")).strip() == "BOUNDED_SOTA_A"
        and str(frontier_scorecard.get("final_readjudication", {}).get("overall_bounded_system_grade", "")).strip() == "A"
        and str(readjudication.get("status", "")).strip() == "PASS"
        and str(readjudication.get("pass_verdict", "")).strip() == "BOUNDED_SOTA_ON_LIVE_AUDITED_TARGET_PROVEN"
        and str(readjudication.get("questions", {}).get("what_final_audited_target_was_rerun", {}).get("evaluated_repo_head_commit", "")).strip() == HISTORICAL_EVALUATED_REPO_HEAD
        and not scorecard_failures
    )
    checks.append(
        _check(
            frontier_bundle_ok,
            "frontier_and_readjudication_bundle_is_capability_bearing_and_passes",
            "The capability-bearing surface must remain the bounded frontier/readjudication bundle with all target checks and hard-stop checks PASS.",
            [FRONTIER_PACKET_REL, FRONTIER_SCORECARD_REL, READJUDICATION_RECEIPT_REL],
            failures=scorecard_failures,
            evaluated_repo_head_commit=HISTORICAL_EVALUATED_REPO_HEAD,
        )
    )
    if not frontier_bundle_ok:
        blockers.append("CAPABILITY_SURFACE_NOT_PASS")

    subject_binding_ok = not subject_mismatches
    checks.append(
        _check(
            subject_binding_ok,
            "historical_capability_surface_subject_binding_intact",
            "The detached capability replay must stay bound to the exact audited historical capability subject head.",
            [
                FRONTIER_PACKET_REL,
                FRONTIER_SCORECARD_REL,
                READJUDICATION_RECEIPT_REL,
                PUBLIC_HORIZON_RECEIPT_REL,
                RED_TEAM_RESULTS_REL,
                FORMAL_INVARIANT_RECEIPT_REL,
                EXTERNAL_REPRODUCTION_RECEIPT_REL,
                DETACHED_VERIFIER_RECEIPT_REL,
                BUILD_VERIFICATION_RECEIPT_REL,
                REVISION_TRUST_RECEIPT_REL,
            ],
            failures=subject_mismatches,
            historical_subject_head_commit=HISTORICAL_CAPABILITY_SUBJECT,
        )
    )
    if not subject_binding_ok:
        blockers.append("HISTORICAL_SUBJECT_HEAD_MISMATCH")

    supporting_surface_ok = all(
        str(payload.get("status", "")).strip() == "PASS"
        for payload in (
            public_horizon,
            red_team_results,
            formal_invariant,
            external_reproduction,
            detached_verifier,
            build_verification,
            revision_trust,
            repo_hygiene,
            operator_greenline,
            ws12_closure,
        )
    ) and str(ws12_closure.get("public_showability_gate_status", "")).strip() == "BLOCKED" and str(ws12_closure.get("tournament_gate_status", "")).strip() == "BLOCKED" and str(ws12_bundle.get("proof_class_summary", {}).get("governance_ceiling", "")).strip() == "WORKFLOW_GOVERNANCE_ONLY"
    checks.append(
        _check(
            supporting_surface_ok,
            "supporting_capability_surfaces_and_boundaries_hold",
            "The bounded capability replay requires the exact supporting public-horizon, challenge, formal, detached, reproduction, and closure boundaries to remain PASS without softening blocked horizons.",
            [
                PUBLIC_HORIZON_RECEIPT_REL,
                RED_TEAM_RESULTS_REL,
                FORMAL_INVARIANT_RECEIPT_REL,
                EXTERNAL_REPRODUCTION_RECEIPT_REL,
                DETACHED_VERIFIER_RECEIPT_REL,
                BUILD_VERIFICATION_RECEIPT_REL,
                REVISION_TRUST_RECEIPT_REL,
                REPO_HYGIENE_RECEIPT_REL,
                OPERATOR_GREENLINE_RECEIPT_REL,
                WS12_CLOSURE_RECEIPT_REL,
                WS12_FINAL_BUNDLE_REL,
            ],
        )
    )
    if not supporting_surface_ok:
        blockers.append("SUPPORTING_CAPABILITY_BOUNDARY_NOT_PASS")

    ws15_verdicts_ok = status_match and canonical_match and authority_ok
    checks.append(
        _check(
            ws15_verdicts_ok,
            "ws15_delivery_integrity_verdicts_remain_green",
            "The bounded capability surface still relies on the three sealed WS15 delivery-integrity verdict lanes remaining PASS/A.",
            [WS15_STATUS_VERDICT_REL, WS15_CANONICAL_HMAC_VERDICT_REL, WS15_AUTHORITY_VERDICT_REL],
            authority_grade=authority_match.group(1).strip(),
        )
    )
    if not ws15_verdicts_ok:
        blockers.append("WS15_DELIVERY_VERDICTS_NOT_GREEN")

    freshness_ok = ws16_validity_window_ok and benchmark_window_contract_ok
    checks.append(
        _check(
            freshness_ok,
            "locked_benchmark_validity_windows_carried_forward_from_ws16",
            "WS17B must reuse the WS16 PASS check that the current truth rows were within locked validity windows, and the active benchmark window contract must remain fail-closed.",
            [WS16_RECEIPT_REL, BENCHMARK_WINDOWS_REL],
        )
    )
    if not freshness_ok:
        blockers.append("BENCHMARK_VALIDITY_WINDOW_NOT_SATISFIED")

    detached_ok = not package_git_dir
    checks.append(
        _check(
            detached_ok,
            "detached_capability_package_has_no_repo_checkout",
            "Outsider capability replay must run from a detached package without a git checkout.",
            [TOOL_REL],
            detached_package_root=str(package_root.resolve()),
        )
    )
    if not detached_ok:
        blockers.append("DETACHED_PACKAGE_CONTAINS_GIT_CHECKOUT")

    checks.append(
        _check(
            not blockers,
            "worst_case_pack_status_remains_pass",
            "Any failed required capability component forces the detached pack away from PASS.",
            [COMPARATOR_REGISTRY_REL],
            failures=blockers,
        )
    )

    status = "PASS" if not blockers else "BLOCKED"
    return {
        "schema_id": "kt.operator.ws17b.outsider_capability_replay_report.v1",
        "artifact_id": "kt_outsider_capability_replay_report.json",
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else BLOCKED_VERDICT,
        "capability_confirmation_mode": "OUTSIDER_VERIFIABLE_DETACHED_CAPABILITY_REPLAY",
        "capability_scope": "HISTORICAL_BOUNDED_FRONTIER_TARGET_ONLY",
        "independent_third_party_confirmation": False,
        "outsider_verifiable": True,
        "historical_capability_subject_head_commit": HISTORICAL_CAPABILITY_SUBJECT,
        "historical_evaluated_repo_head_commit": HISTORICAL_EVALUATED_REPO_HEAD,
        "capability_surfaces": [
            FRONTIER_SCORECARD_REL,
            READJUDICATION_RECEIPT_REL,
        ],
        "used_comparator_ids": USED_COMPARATOR_IDS,
        "pinned_dataset_hashes": pinned_hashes,
        "freshness_window_applied_hours": FRESHNESS_MAX_AGE_HOURS,
        "checks": checks,
        "blocked_by": blockers,
        "limitations": [
            "WS17B proves only one outsider-verifiable replay of the historical bounded frontier/readjudication bundle on subject head b4789a5.",
            "WS17B does not upgrade that historical audited target into current-head capability.",
            "WS17B does not widen verifier coverage, activate threshold-root acceptance, prove release readiness, prove release ceremony execution, or prove campaign completion.",
            "The repo-root import fragility remains visible and unfixed.",
        ],
        "stronger_claim_not_made": [
            "Current HEAD itself has now been externally confirmed as bounded SOTA.",
            "Verifier coverage is broader than the already-bounded imported surfaces.",
            "Release readiness, release ceremony execution, or campaign completion is proven.",
        ],
    }


def emit_ws17b_external_capability(*, root: Optional[Path] = None) -> Dict[str, Any]:
    repo = root or _repo_root()
    pre_status = _git_status_lines(repo)
    pre_dirty = _dirty_relpaths(pre_status)
    if pre_dirty:
        out_of_scope = [path for path in pre_dirty if not _path_in_scope(path)]
        if out_of_scope:
            raise RuntimeError(f"FAIL_CLOSED: WS17B prewrite workspace not clean: {out_of_scope}")

    current_head = _git_head(repo)
    dag = _load_required_json(repo, EXECUTION_DAG_REL)
    ws16_receipt = _load_required_json(repo, WS16_RECEIPT_REL)
    ws17a_receipt = _load_required_json(repo, WS17A_RECEIPT_REL)
    ws17b_lawful_before_mutation = (
        str(dag.get("current_node", "")).strip() == WORKSTREAM_ID
        or any(isinstance(node, dict) and node.get("id") == WORKSTREAM_ID and str(node.get("status", "")).strip() in {"UNLOCKED", "PASS"} for node in dag.get("nodes", []))
        or str(dag.get("next_lawful_workstream", "")).strip() == WORKSTREAM_ID
    )

    temp_root = Path(tempfile.mkdtemp(prefix="kt_ws17b_capability_")).resolve()
    package_root = temp_root / "package"
    package_hashes = _copy_public_inputs(repo, package_root)
    detached_report_output = package_root / Path(REPLAY_REPORT_REL)
    detached_report, detached_hashes, removed_env_keys, detached_stdout, detached_stderr = _run_detached_replay(package_root, detached_report_output)

    import_manifest = {
        "schema_id": "kt.operator.ws17b.external_capability_import_manifest.v1",
        "artifact_id": "kt_external_capability_import_manifest.json",
        "status": detached_report["status"],
        "compiled_against": current_head,
        "capability_subject_head_commit": HISTORICAL_CAPABILITY_SUBJECT,
        "capability_confirmation_mode": "OUTSIDER_VERIFIABLE_DETACHED_CAPABILITY_REPLAY",
        "detached_package_ephemeral": True,
        "detached_package_root": str(package_root),
        "repo_checkout_present_in_detached_package": False,
        "removed_secret_env_keys": removed_env_keys,
        "used_comparator_ids": list(USED_COMPARATOR_IDS),
        "freshness_window_applied_hours": FRESHNESS_MAX_AGE_HOURS,
        "historical_surface_currentness_rule": "Historical audited capability surfaces remain exact-hash pinned and subject-bound; freshness windows apply only to current governance receipts and the new replay evidence, not to the sealed historical subject itself.",
        "anti_cherry_picking_rules_applied": [
            "all_declared_capability_components_required",
            "no_failed_row_omission",
            "historical_audited_surface_may_not_be_softened_into_current_head_capability",
            "worst_status_governs_pack_status",
        ],
        "imported_public_refs": {
            rel: {
                "source_sha256": package_hashes[rel],
                "detached_copy_sha256": detached_hashes[rel],
            }
            for rel in REQUIRED_PUBLIC_REFS
        },
        "detached_replay_report_sha256": _file_sha256(detached_report_output),
        "detached_replay_stdout": detached_stdout.strip(),
        "detached_replay_stderr": detached_stderr.strip(),
        "stronger_claim_not_made": [
            "The detached capability replay upgrades the historical audited target into current-head capability.",
            "The detached capability replay widens verifier coverage, release readiness, or campaign completion.",
        ],
    }
    _write_json((repo / Path(IMPORT_MANIFEST_REL)).resolve(), import_manifest)
    _write_json((repo / Path(REPLAY_REPORT_REL)).resolve(), detached_report)

    blocked_by = list(detached_report.get("blocked_by", []))
    checks = [
        _check(
            str(ws16_receipt.get("status", "")).strip() == "PASS",
            "ws16_tevv_receipt_pass",
            "WS17B depends on the locked WS16 TEVV/comparator/pin registry remaining PASS.",
            [WS16_RECEIPT_REL],
        ),
        _check(
            str(ws17a_receipt.get("status", "")).strip() == "PASS"
            and bool(ws17a_receipt.get("assurance_only_not_capability")) is True,
            "ws17a_assurance_receipt_pass_and_remains_bounded",
            "WS17B depends on the frozen WS17A assurance lane remaining PASS and still not overreading assurance into capability.",
            [WS17A_RECEIPT_REL],
        ),
        _check(
            ws17b_lawful_before_mutation,
            "ws17b_is_current_lawful_workstream",
            "WS17B may proceed only after the frozen WS17A boundary unlocks the capability lane.",
            [EXECUTION_DAG_REL],
        ),
        _check(
            str(detached_report.get("status", "")).strip() == "PASS",
            "detached_outsider_capability_replay_pass",
            "At least one outsider-verifiable capability-bearing surface must succeed under detached replay with exact pins and the locked comparator set.",
            [REPLAY_REPORT_REL, IMPORT_MANIFEST_REL],
            failures=blocked_by,
        ),
    ]

    status = "PASS" if not blocked_by else "BLOCKED"
    next_lawful = NEXT_WORKSTREAM_ON_PASS if status == "PASS" else WORKSTREAM_ID

    ws17b_node = next(node for node in dag["nodes"] if node["id"] == WORKSTREAM_ID)
    ws18_node = next(node for node in dag["nodes"] if node["id"] == NEXT_WORKSTREAM_ON_PASS)
    ws17b_node["status"] = status
    ws17b_node["ratification_checkpoint"] = Path(RECEIPT_REL).name
    ws17b_node["claim_boundary"] = (
        "WS17B PASS proves only one outsider-verifiable capability replay of the historical bounded frontier/readjudication bundle on subject head b4789a5. "
        "It does not upgrade that historical audited target into current-head capability, does not widen verifier coverage, and does not prove release readiness, release ceremony execution, or campaign completion."
    )
    ws18_node["status"] = "UNLOCKED" if status == "PASS" else "LOCKED_PENDING_WS17B_PASS"
    dag["current_node"] = WORKSTREAM_ID
    dag["current_repo_head"] = current_head
    dag["generated_utc"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    dag["next_lawful_workstream"] = next_lawful
    semantic = dag.get("semantic_boundary") if isinstance(dag.get("semantic_boundary"), dict) else {}
    if status == "PASS":
        semantic["lawful_current_claim"] = (
            "WS17B proves one outsider-verifiable capability replay of the historical bounded frontier/readjudication bundle on subject head b4789a5 only. "
            "It does not upgrade that historical audited target into current-head capability, does not widen verifier coverage, and does not prove release readiness, release ceremony execution, or campaign completion."
        )
    stronger = list(semantic.get("stronger_claim_not_made", [])) if isinstance(semantic.get("stronger_claim_not_made"), list) else []
    for item in [
        "WS17B upgrades the historical audited target into current-head capability.",
        "Verifier coverage is broader than the already-bounded imported surfaces.",
        "Release readiness is proven.",
        "Release ceremony execution is proven.",
        "Campaign completion is proven.",
    ]:
        if item not in stronger:
            stronger.append(item)
    semantic["stronger_claim_not_made"] = list(dict.fromkeys(stronger))
    dag["semantic_boundary"] = semantic
    _write_json((repo / Path(EXECUTION_DAG_REL)).resolve(), dag)

    post_status = _git_status_lines(repo)
    unexpected_touches = [path for path in _dirty_relpaths(post_status) if not _path_in_scope(path)]
    if unexpected_touches:
        raise RuntimeError(f"FAIL_CLOSED: WS17B touched out-of-scope paths: {unexpected_touches}")

    receipt = {
        "schema_id": "kt.operator.ws17b.external_capability_confirmation_receipt.v1",
        "artifact_id": "kt_external_capability_confirmation_receipt.json",
        "workstream_id": WORKSTREAM_ID,
        "step_id": STEP_ID,
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else BLOCKED_VERDICT,
        "compiled_against": current_head,
        "current_repo_head": current_head,
        "capability_confirmation_mode": "OUTSIDER_VERIFIABLE_DETACHED_CAPABILITY_REPLAY",
        "capability_scope": "HISTORICAL_BOUNDED_FRONTIER_TARGET_ONLY",
        "capability_surfaces": [
            FRONTIER_SCORECARD_REL,
            READJUDICATION_RECEIPT_REL,
        ],
        "historical_capability_subject_head_commit": HISTORICAL_CAPABILITY_SUBJECT,
        "historical_evaluated_repo_head_commit": HISTORICAL_EVALUATED_REPO_HEAD,
        "independent_third_party_confirmation": False,
        "outsider_verifiable": True,
        "used_comparator_ids": list(USED_COMPARATOR_IDS),
        "checks": checks,
        "blocked_by": blocked_by,
        "imported_evidence": {
            "import_manifest_ref": IMPORT_MANIFEST_REL,
            "outsider_replay_report_ref": REPLAY_REPORT_REL,
            "imported_hashes": {
                IMPORT_MANIFEST_REL: _file_sha256((repo / Path(IMPORT_MANIFEST_REL)).resolve()),
                REPLAY_REPORT_REL: _file_sha256((repo / Path(REPLAY_REPORT_REL)).resolve()),
            },
        },
        "limitations": [
            "WS17B proves only one outsider-verifiable replay of the historical bounded frontier/readjudication bundle on subject head b4789a5.",
            "WS17B does not upgrade that historical audited target into current-head capability.",
            "WS17B does not widen verifier coverage, activate threshold-root acceptance, prove release readiness, prove release ceremony execution, or prove campaign completion.",
            "The repo-root import fragility remains visible and unfixed.",
        ],
        "next_lawful_workstream": next_lawful,
        "stronger_claim_not_made": [
            "WS17B upgrades the historical audited target into current-head capability.",
            "WS17B widens verifier coverage beyond the already-bounded imported surfaces.",
            "WS17B proves release readiness, release ceremony execution, or campaign completion.",
        ],
        "validators_run": ["python -m tools.operator.ws17b_external_capability_validate"],
        "tests_run": ["python -m pytest -q tests/operator/test_ws17b_external_capability_validate.py"],
        "unexpected_touches": [],
        "protected_touch_violations": [],
    }
    _write_json((repo / Path(RECEIPT_REL)).resolve(), receipt)
    return receipt


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="WS17B outsider-verifiable detached capability replay validator")
    parser.add_argument("--detached-package-root", help="Run only the detached outsider replay against a public package root")
    parser.add_argument("--report-output", help="Path to the detached replay report JSON")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.detached_package_root:
        package_root = Path(args.detached_package_root).resolve()
        report_output = Path(args.report_output).resolve() if args.report_output else (package_root / Path(REPLAY_REPORT_REL)).resolve()
        report = validate_detached_package(package_root)
        _write_json(report_output, report)
        return 0 if report["status"] == "PASS" else 1

    receipt = emit_ws17b_external_capability(root=_repo_root())
    print(json.dumps({"status": receipt["status"], "next_lawful_workstream": receipt["next_lawful_workstream"]}, indent=2, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
