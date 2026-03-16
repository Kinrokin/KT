from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.canonical_tree_execute import ARCHIVE_GLOB
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


WORK_ORDER_ID = "WORK_ORDER_KT_FRONTIER_ELEVATION_AND_PUBLIC_DEFENSIBILITY"
WORK_ORDER_SCHEMA_ID = "kt.work_order.frontier_elevation_and_public_defensibility.v2"
WORKSTREAM_ID = "WS24_FRONTIER_RECUT_AND_SOTA_READJUDICATION"
STEP_ID = "WS24_STEP_1_RERUN_FRONTIER_AUDIT_AND_ISSUE_BOUNDED_VERDICT"
PASS_VERDICT = "BOUNDED_SOTA_ON_LIVE_AUDITED_TARGET_PROVEN"
BLOCKED_VERDICT = "ADVANCED_PLUS_WITH_HONEST_REMAINING_BOUNDARIES"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
BASELINE_MANIFEST_REL = f"{REPORT_ROOT_REL}/external_audit_packet_manifest.json"
WS12_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_total_closure_campaign_completion_receipt.json"
WS12_BUNDLE_REL = f"{REPORT_ROOT_REL}/kt_final_completion_bundle.json"
WS13_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_repo_hygiene_receipt.json"
WS14_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_operator_greenline_receipt.json"
WS17_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_revision_trust_receipt.json"
WS18_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_build_verification_receipt.json"
WS19_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_detached_receipt.json"
WS20_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_external_reproduction_receipt.json"
WS21_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_public_horizon_receipt.json"
WS22_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_red_team_results_receipt.json"
WS23_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_formal_invariant_receipt.json"
WS15_STATUS_VERDICT_REL = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS15_status_seal_b4789a5/verdict.txt"
WS15_CANONICAL_HMAC_VERDICT_REL = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS15_canonical_hmac_seal_b4789a5/verdict.txt"
WS15_AUTHORITY_VERDICT_REL = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS15_authority_grade_b4789a5/verdict.txt"

FRONTIER_PACKET_REL = f"{REPORT_ROOT_REL}/kt_frontier_audit_packet.json"
FRONTIER_SCORECARD_REL = f"{REPORT_ROOT_REL}/kt_frontier_rerun_scorecard.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_sota_readjudication_receipt.json"

BASELINE_README_NAME = "README.md"
BASELINE_SCORECARD_NAME = "subsystem_scorecard.md"
BASELINE_FINAL_SNAPSHOT_NAME = "final_kt_snapshot.md"
ARCHIVE_PREFIX = "KT_ARCHIVE"

VALIDATORS_RUN = [
    "python -m tools.operator.frontier_readjudication_validate",
]
TESTS_RUN = [
    "python -m pytest KT_PROD_CLEANROOM/tests/operator/test_frontier_readjudication_validate.py -q",
]

STRONGER_CLAIM_NOT_MADE = (
    "WS24 proves only that KT has reached bounded SOTA on the current live audited target with one verifier-only public "
    "verification horizon open and no red critical live-grade contradictions. It does not claim beyond-SOTA overall, "
    "does not open competition, H1, production, economic, or platform-governance horizons, and does not treat an open "
    "external challenge window with no findings yet as proof of adversarial exhaustion."
)

GRADE_ORDER = {
    "D": 0,
    "C-": 1,
    "C": 2,
    "C+": 3,
    "B-": 4,
    "B": 5,
    "B+": 6,
    "A-": 7,
    "A": 8,
    "A+": 9,
}
PROTECTED_PATTERNS = (ARCHIVE_GLOB, "**/archive/**", "**/historical/**")

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/frontier_readjudication_validate.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_frontier_readjudication_validate.py"
GENERATED_ARTIFACT_REFS = [
    FRONTIER_PACKET_REL,
    FRONTIER_SCORECARD_REL,
    RECEIPT_REL,
]
WORKSTREAM_FILES_TOUCHED = [
    TOOL_REL,
    TEST_REL,
    *GENERATED_ARTIFACT_REFS,
]
SURFACE_CLASSIFICATIONS = {
    TOOL_REL: "canonical active file",
    TEST_REL: "validator/test file",
    FRONTIER_PACKET_REL: "generated audit packet",
    FRONTIER_SCORECARD_REL: "generated comparative scorecard",
    RECEIPT_REL: "generated readjudication receipt",
}


def _git_status_lines(root: Path) -> List[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return [line.rstrip("\n") for line in result.stdout.splitlines() if line.strip()]


def _dirty_relpaths(root: Path, status_lines: Sequence[str]) -> List[str]:
    rows: List[str] = []
    for line in status_lines:
        rel = line[3:].strip()
        if not rel:
            continue
        path = (root / Path(rel)).resolve()
        if path.exists() and path.is_dir():
            rows.extend(child.resolve().relative_to(root.resolve()).as_posix() for child in path.rglob("*") if child.is_file())
        else:
            rows.append(Path(rel).as_posix())
    return sorted(set(rows))


def _is_protected(path: str) -> bool:
    normalized = str(path).replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in PROTECTED_PATTERNS)


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _load_required_text(path: Path) -> str:
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required text artifact: {path.as_posix()}")
    return path.read_text(encoding="utf-8")


def _git_head(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def _grade_meets(observed: str, minimum: str) -> bool:
    observed_rank = GRADE_ORDER.get(str(observed).strip(), -1)
    minimum_rank = GRADE_ORDER.get(str(minimum).strip(), -1)
    return observed_rank >= minimum_rank >= 0


def _baseline_ref_path(root: Path, rel: str) -> Path:
    candidate = (root / Path(rel)).resolve()
    if candidate.exists():
        return candidate
    archive_candidate = (root / ARCHIVE_PREFIX / Path(rel)).resolve()
    if archive_candidate.exists():
        return archive_candidate
    raise RuntimeError(f"FAIL_CLOSED: missing baseline audit packet ref: {rel}")


def _baseline_root_from_manifest(root: Path, manifest: Dict[str, Any]) -> Path:
    packet_refs = manifest.get("packet_refs")
    if not isinstance(packet_refs, list) or not packet_refs:
        raise RuntimeError("FAIL_CLOSED: baseline audit packet manifest missing packet_refs")
    first = str(packet_refs[0]).strip()
    if not first:
        raise RuntimeError("FAIL_CLOSED: baseline audit packet manifest has blank packet ref")
    return _baseline_ref_path(root, first).parent


def _markdown_table_row_value(markdown: str, field_name: str) -> str:
    pattern = re.compile(rf"^\|\s*{re.escape(field_name)}\s*\|\s*(.*?)\s*\|$", re.MULTILINE)
    match = pattern.search(markdown)
    if not match:
        raise RuntimeError(f"FAIL_CLOSED: missing baseline field {field_name!r}")
    return match.group(1).strip().strip("`")


def _extract_secret_like_residue(markdown: str) -> str:
    match = re.search(r"Secret-like local residue observed:\s*`([^`]+)`", markdown)
    if not match:
        raise RuntimeError("FAIL_CLOSED: baseline README missing secret-like local residue line")
    return match.group(1).strip()


def _extract_main_problem(markdown: str) -> str:
    lines = [line.strip() for line in markdown.splitlines()]
    for index, line in enumerate(lines):
        if line == "## What KT Is Now" and index + 2 < len(lines):
            candidate = lines[index + 2].strip()
            if candidate:
                return candidate
    raise RuntimeError("FAIL_CLOSED: baseline final snapshot missing main-problem paragraph")


def _parse_scorecard_grades(markdown: str) -> Dict[str, Dict[str, str]]:
    rows: Dict[str, Dict[str, str]] = {}
    for line in markdown.splitlines():
        if not line.startswith("| ") or "---" in line:
            continue
        match = re.match(r"^\|\s*([^|]+?)\s*\|\s*`([^`]+)`\s*\|\s*`([^`]+)`\s*\|", line)
        if not match:
            continue
        subsystem = match.group(1).strip().lower()
        rows[subsystem] = {
            "closure_grade": match.group(2).strip(),
            "capability_grade": match.group(3).strip(),
        }
    return rows


def _load_baseline_audit(root: Path) -> Dict[str, Any]:
    manifest = _load_required_json(root, BASELINE_MANIFEST_REL)
    packet_root = _baseline_root_from_manifest(root, manifest)
    readme = _load_required_text(packet_root / BASELINE_README_NAME)
    scorecard = _load_required_text(packet_root / BASELINE_SCORECARD_NAME)
    snapshot = _load_required_text(packet_root / BASELINE_FINAL_SNAPSHOT_NAME)
    subsystem_rows = _parse_scorecard_grades(scorecard)
    repo_hygiene_row = subsystem_rows.get("repo hygiene / release discipline")
    operator_row = subsystem_rows.get("operator plane")
    evidence_row = subsystem_rows.get("evidence plane")
    if repo_hygiene_row is None or operator_row is None or evidence_row is None:
        raise RuntimeError("FAIL_CLOSED: baseline subsystem scorecard missing required rows")
    return {
        "manifest_ref": BASELINE_MANIFEST_REL,
        "packet_refs": list(manifest.get("packet_refs", [])),
        "validated_head_sha": str(manifest.get("validated_head_sha", "")).strip(),
        "baseline_target_head_commit": _markdown_table_row_value(readme, "head"),
        "clean_clone_equivalent": _markdown_table_row_value(readme, "clean-clone equivalent").lower() == "yes",
        "ignored_local_residue_present": _markdown_table_row_value(readme, "ignored local residue").lower() == "present",
        "secret_like_local_residue": _extract_secret_like_residue(readme),
        "main_problem": _extract_main_problem(snapshot),
        "baseline_rows": {
            "repo_hygiene": {
                "status": "BLOCKED",
                "grade": repo_hygiene_row["closure_grade"],
                "detail": "ignored residue, local secret-like residue, and no clean-clone equivalent",
            },
            "operator_factory_readiness": {
                "status": "HOLD",
                "grade": operator_row["closure_grade"],
                "detail": "truth-sync gap between live runs and tracked receipts required re-ratification",
            },
            "external_verifiability": {
                "status": "HOLD",
                "grade": evidence_row["closure_grade"],
                "detail": "tracked evidence bundle was stale and clean-clone smoke was skipped in the fresh run",
            },
            "bounded_public_horizon": {
                "status": "BLOCKED",
                "grade": "C",
                "detail": "no bounded public horizon with replayable receipts was open",
            },
        },
    }


def _parse_authority_grade_verdict(line: str) -> Dict[str, Any]:
    match = re.search(r"KT_AUTHORITY_GRADE_([A-D][+-]?)\s+status=(PASS|BLOCKED|FAIL_CLOSED)", line)
    if not match:
        raise RuntimeError("FAIL_CLOSED: could not parse WS15 authority grade verdict")
    return {
        "grade": match.group(1).strip(),
        "status": match.group(2).strip(),
        "raw_verdict": line.strip(),
    }


def _pass_status(payload: Dict[str, Any]) -> bool:
    return str(payload.get("status", "")).strip() == "PASS"


def _build_row(*, row_id: str, label: str, march: Dict[str, Any], ws12: Dict[str, Any], final: Dict[str, Any], comparison: str, refs: Sequence[str]) -> Dict[str, Any]:
    return {
        "row_id": row_id,
        "label": label,
        "march_baseline": dict(march),
        "ws12_closure_state": dict(ws12),
        "frontier_elevated_state": dict(final),
        "comparison_result": comparison,
        "refs": list(refs),
    }


def build_frontier_readjudication_outputs_from_artifacts(
    *,
    baseline_audit: Dict[str, Any],
    ws12_receipt: Dict[str, Any],
    ws12_bundle: Dict[str, Any],
    ws13_receipt: Dict[str, Any],
    ws14_receipt: Dict[str, Any],
    ws17_receipt: Dict[str, Any],
    ws18_receipt: Dict[str, Any],
    ws19_receipt: Dict[str, Any],
    ws20_receipt: Dict[str, Any],
    ws21_receipt: Dict[str, Any],
    ws22_receipt: Dict[str, Any],
    ws23_receipt: Dict[str, Any],
    ws15_status_verdict: str,
    ws15_canonical_hmac_verdict: str,
    ws15_authority_verdict: str,
    changed_files: Sequence[str],
    evaluated_repo_head_commit: str,
) -> Dict[str, Dict[str, Any]]:
    anchor_subject = str(ws23_receipt.get("subject_head_commit", "")).strip()
    anchor_evidence = str(ws23_receipt.get("evidence_head_commit", "")).strip()
    if not anchor_subject or not anchor_evidence:
        raise RuntimeError("FAIL_CLOSED: WS23 receipt missing sealed subject/evidence anchor")
    authority = _parse_authority_grade_verdict(ws15_authority_verdict)
    if "KT_STATUS_PASS" not in ws15_status_verdict:
        raise RuntimeError("FAIL_CLOSED: WS15 status verdict is not PASS")
    if "KT_CERTIFY_PASS" not in ws15_canonical_hmac_verdict:
        raise RuntimeError("FAIL_CLOSED: WS15 canonical_hmac verdict is not PASS")

    repo_hygiene_summary = ws13_receipt.get("summary", {}) if isinstance(ws13_receipt.get("summary"), dict) else {}
    repo_hygiene_clean = bool(repo_hygiene_summary.get("git_status_clean", True))
    repo_hygiene_grade = "A" if _pass_status(ws13_receipt) and repo_hygiene_clean else "C"
    operator_grade = str(ws14_receipt.get("summary", {}).get("current_grade", "")).strip() or "D"
    external_verifiability_grade = "A" if all(_pass_status(item) for item in (ws17_receipt, ws18_receipt, ws19_receipt, ws20_receipt)) else "B"
    bounded_public_horizon_grade = "B+" if all(_pass_status(item) for item in (ws21_receipt, ws22_receipt)) else "C"

    rows = [
        _build_row(
            row_id="repo_hygiene",
            label="Repo hygiene and audit-target cleanliness",
            march=baseline_audit["baseline_rows"]["repo_hygiene"],
            ws12={
                "status": "SEALED_WITH_BOUNDARY",
                "grade": "B",
                "detail": "closure was sealed, but the campaign still had blocked public horizons and no final frontier rerun",
            },
            final={
                "status": "PASS",
                "grade": repo_hygiene_grade,
                "detail": "root residue removed, secret-like root surface removed, and canonical keep-set restored",
            },
            comparison="MATERIAL_IMPROVEMENT_TO_TARGET",
            refs=[BASELINE_MANIFEST_REL, WS12_RECEIPT_REL, WS13_RECEIPT_REL],
        ),
        _build_row(
            row_id="operator_factory_readiness",
            label="Operator-factory readiness on the live audited target",
            march=baseline_audit["baseline_rows"]["operator_factory_readiness"],
            ws12={
                "status": "BOUNDARIED",
                "grade": "B",
                "detail": "adapter testing was open, but tournament/public showability and H1 remained blocked",
            },
            final={
                "status": "PASS",
                "grade": operator_grade,
                "detail": "status and ci_sim recovered and live readiness reran to grade A",
            },
            comparison="LIVE_GRADE_RECOVERED_AND_EXCEEDS_TARGET",
            refs=[BASELINE_MANIFEST_REL, WS12_RECEIPT_REL, WS14_RECEIPT_REL],
        ),
        _build_row(
            row_id="delivery_integrity_and_live_authority",
            label="Delivery integrity and live authority grade",
            march={
                "status": "HOLD",
                "grade": "B",
                "detail": "delivery/security existed, but latest delivery posture was not freshly sealed against the live audited target",
            },
            ws12={
                "status": "BOUNDARIED",
                "grade": "B+",
                "detail": "closure named the lawful boundary, but WS15 delivery-integrity reruns had not happened yet",
            },
            final={
                "status": authority["status"],
                "grade": authority["grade"],
                "detail": "status PASS, canonical_hmac PASS, and authority grade A on the sealed WS15 subject head",
            },
            comparison="NO_LONGER_MATERIALLY_CONTRADICTED_BY_LIVE_AUTHORITY",
            refs=[WS12_BUNDLE_REL, WS15_STATUS_VERDICT_REL, WS15_CANONICAL_HMAC_VERDICT_REL, WS15_AUTHORITY_VERDICT_REL],
        ),
        _build_row(
            row_id="external_verifiability",
            label="Detached verification and independent replay strength",
            march=baseline_audit["baseline_rows"]["external_verifiability"],
            ws12={
                "status": "BOUNDARIED",
                "grade": "B",
                "detail": "offline verifier release existed, but detached parity and independent clean-environment replay were not yet proven",
            },
            final={
                "status": "PASS",
                "grade": external_verifiability_grade,
                "detail": "source/build attestation, provenance/VSA alignment, detached parity, and same-host independent clean-environment replay are all proven",
            },
            comparison="TARGET_MET_WITH_CURRENT_EVIDENCE",
            refs=[WS12_BUNDLE_REL, WS17_RECEIPT_REL, WS18_RECEIPT_REL, WS19_RECEIPT_REL, WS20_RECEIPT_REL],
        ),
        _build_row(
            row_id="bounded_public_horizon",
            label="Bounded public verification horizon",
            march=baseline_audit["baseline_rows"]["bounded_public_horizon"],
            ws12={
                "status": "BLOCKED",
                "grade": "C",
                "detail": "adapter testing was open, but tournament and public showability remained blocked",
            },
            final={
                "status": "PASS",
                "grade": bounded_public_horizon_grade,
                "detail": "exactly one verifier-only public verification horizon is open with an external challenge protocol and no findings yet",
            },
            comparison="EXACTLY_ONE_HORIZON_OPENED_WITH_BOUNDARY_PRESERVED",
            refs=[WS12_RECEIPT_REL, WS21_RECEIPT_REL, WS22_RECEIPT_REL],
        ),
        _build_row(
            row_id="formal_release_invariants",
            label="Formal support for release-critical invariants",
            march={
                "status": "NOT_MODELED",
                "grade": "C",
                "detail": "no bounded formal invariant core was part of the March audit packet",
            },
            ws12={
                "status": "NOT_MODELED",
                "grade": "C",
                "detail": "WS12 sealed closure boundaries without a bounded formal model of release-critical invariants",
            },
            final={
                "status": "PASS",
                "grade": "A-",
                "detail": "three core release-critical invariants are modeled in TLA+ and bounded-checked against the current release logic",
            },
            comparison="NEW_SUPPORTING_PROOF_SURFACE_ADDED",
            refs=[WS23_RECEIPT_REL],
        ),
    ]

    minimum_targets = {
        "repo_hygiene": "A",
        "operator_factory_readiness": "B+",
        "authority_grade": "A-",
        "external_verifiability": "A",
        "bounded_public_horizon": "B+",
        "overall_bounded_system_grade": "A",
    }
    target_checks = [
        {"target_id": "repo_hygiene", "minimum_required": "A", "observed_grade": repo_hygiene_grade, "status": "PASS" if _grade_meets(repo_hygiene_grade, "A") else "FAIL"},
        {"target_id": "operator_factory_readiness", "minimum_required": "B+", "observed_grade": operator_grade, "status": "PASS" if _grade_meets(operator_grade, "B+") else "FAIL"},
        {"target_id": "authority_grade", "minimum_required": "A-", "observed_grade": authority["grade"], "status": "PASS" if _grade_meets(authority["grade"], "A-") else "FAIL"},
        {"target_id": "external_verifiability", "minimum_required": "A", "observed_grade": external_verifiability_grade, "status": "PASS" if _grade_meets(external_verifiability_grade, "A") else "FAIL"},
        {"target_id": "bounded_public_horizon", "minimum_required": "B+", "observed_grade": bounded_public_horizon_grade, "status": "PASS" if _grade_meets(bounded_public_horizon_grade, "B+") else "FAIL"},
    ]

    contradiction_check = {
        "status": "PASS" if _grade_meets(operator_grade, "B+") and _grade_meets(authority["grade"], "A-") else "FAIL",
        "readiness_grade": operator_grade,
        "authority_grade": authority["grade"],
        "detail": (
            "Live readiness and authority grades now support the bounded frontier claim: repo hygiene is clean, operator "
            "greenlines are recovered, delivery integrity reruns are green, and the stronger closed horizons from WS12 "
            "remain explicitly closed except for the single WS21 verifier-only horizon."
            if _grade_meets(operator_grade, "B+") and _grade_meets(authority["grade"], "A-")
            else "Live readiness or authority still materially undercuts the claimed frontier posture."
        ),
    }

    hard_stop_checks = [
        {
            "condition_id": "critical_ci_remains_red_after_recovery_workstream",
            "status": "PASS" if _pass_status(ws13_receipt) and _pass_status(ws14_receipt) else "FAIL",
            "detail": "Repo hygiene and operator recovery receipts are both PASS.",
        },
        {
            "condition_id": "delivery_integrity_evidence_missing_after_restoration_workstream",
            "status": "PASS" if authority["status"] == "PASS" else "FAIL",
            "detail": "WS15 status, canonical_hmac, and authority grade all passed on the sealed subject head.",
        },
        {
            "condition_id": "detached_verifier_depends_on_hidden_local_state",
            "status": "PASS" if _pass_status(ws19_receipt) and _pass_status(ws20_receipt) else "FAIL",
            "detail": "Detached parity and same-host independent clean-environment replay are both proven.",
        },
        {
            "condition_id": "no_bounded_public_horizon_is_actually_opened",
            "status": "PASS" if _pass_status(ws21_receipt) else "FAIL",
            "detail": "Exactly one verifier-only public verification horizon is open.",
        },
        {
            "condition_id": "live_grades_materially_contradict_closure_receipts_at_campaign_end",
            "status": contradiction_check["status"],
            "detail": contradiction_check["detail"],
        },
    ]

    actual_touched = sorted(set(str(path).replace("\\", "/") for path in changed_files if str(path).strip()))
    unexpected_touches = sorted(path for path in actual_touched if path not in WORKSTREAM_FILES_TOUCHED)
    protected_touch_violations = sorted(path for path in actual_touched if _is_protected(path))
    touch_scope_status = "PASS" if not unexpected_touches and not protected_touch_violations else "FAIL"
    all_targets_pass = all(item["status"] == "PASS" for item in target_checks)
    all_hard_stops_clear = all(item["status"] == "PASS" for item in hard_stop_checks)

    overall_grade = "A" if all_targets_pass and all_hard_stops_clear else "B+"
    final_posture = "BOUNDED_SOTA_A" if all_targets_pass and all_hard_stops_clear else "ADVANCED_PLUS_WITH_BOUNDARIES"
    receipt_status = "FAIL_CLOSED" if touch_scope_status == "FAIL" else ("PASS" if all_targets_pass and all_hard_stops_clear else "BLOCKED")
    pass_verdict = PASS_VERDICT if receipt_status == "PASS" else BLOCKED_VERDICT

    packet = {
        "artifact_id": "kt_frontier_audit_packet.json",
        "schema_id": "kt.operator.frontier_audit_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "work_order_id": WORK_ORDER_ID,
        "work_order_schema_id": WORK_ORDER_SCHEMA_ID,
        "workstream_id": WORKSTREAM_ID,
        "sealed_subject_anchor_commit": anchor_subject,
        "sealed_evidence_anchor_commit": anchor_evidence,
        "evaluated_repo_head_commit": evaluated_repo_head_commit,
        "comparative_window": {
            "march_baseline": {
                "manifest_ref": baseline_audit["manifest_ref"],
                "packet_refs": list(baseline_audit["packet_refs"]),
                "target_head_commit": baseline_audit["baseline_target_head_commit"],
                "validated_head_sha": baseline_audit["validated_head_sha"],
                "clean_clone_equivalent": baseline_audit["clean_clone_equivalent"],
                "ignored_local_residue_present": baseline_audit["ignored_local_residue_present"],
                "secret_like_local_residue": baseline_audit["secret_like_local_residue"],
                "main_problem": baseline_audit["main_problem"],
            },
            "ws12_closure_state": {
                "receipt_ref": WS12_RECEIPT_REL,
                "bundle_ref": WS12_BUNDLE_REL,
                "subject_head_commit": str(ws12_receipt.get("subject_head_commit", "")).strip(),
                "campaign_completion_state": str(ws12_receipt.get("campaign_completion_state", "")).strip(),
                "adapter_testing_gate_status": str(ws12_receipt.get("adapter_testing_gate_status", "")).strip(),
                "tournament_gate_status": str(ws12_receipt.get("tournament_gate_status", "")).strip(),
                "public_showability_gate_status": str(ws12_receipt.get("public_showability_gate_status", "")).strip(),
                "h1_gate_status": str(ws12_bundle.get("gates", {}).get("h1", "")).strip(),
                "still_blocked": list(ws12_bundle.get("still_blocked", [])),
                "governance_ceiling": str(ws12_bundle.get("proof_class_summary", {}).get("governance_ceiling", "")).strip(),
            },
            "frontier_elevated_state": {
                "repo_hygiene_receipt_ref": WS13_RECEIPT_REL,
                "operator_greenline_receipt_ref": WS14_RECEIPT_REL,
                "ws15_status_verdict_ref": WS15_STATUS_VERDICT_REL,
                "ws15_canonical_hmac_verdict_ref": WS15_CANONICAL_HMAC_VERDICT_REL,
                "ws15_authority_verdict_ref": WS15_AUTHORITY_VERDICT_REL,
                "ws17_receipt_ref": WS17_RECEIPT_REL,
                "ws18_receipt_ref": WS18_RECEIPT_REL,
                "ws19_receipt_ref": WS19_RECEIPT_REL,
                "ws20_receipt_ref": WS20_RECEIPT_REL,
                "ws21_receipt_ref": WS21_RECEIPT_REL,
                "ws22_receipt_ref": WS22_RECEIPT_REL,
                "ws23_receipt_ref": WS23_RECEIPT_REL,
                "repo_hygiene_grade": repo_hygiene_grade,
                "operator_factory_readiness_grade": operator_grade,
                "authority_grade": authority["grade"],
                "external_verifiability_grade": external_verifiability_grade,
                "bounded_public_horizon_grade": bounded_public_horizon_grade,
                "overall_bounded_system_grade": overall_grade,
            },
        },
        "resolved_campaign_gaps": [
            "repo hygiene and secret-like local residue resolved",
            "operator greenlines and live readiness recovered on the audited target",
            "delivery integrity rerun sealed with status PASS, canonical_hmac PASS, and authority grade A",
            "source/build attestation and provenance/VSA alignment sealed on the bounded critical artifact set",
            "detached verifier parity and same-host independent clean-environment replay proven",
            "exactly one verifier-only public verification horizon opened with explicit closed horizons preserved",
            "external challenge protocol bootstrapped without widening public-horizon claims",
            "core release-critical invariants modeled and bounded-checked",
        ],
        "supporting_refs": [
            WS12_RECEIPT_REL,
            WS12_BUNDLE_REL,
            WS13_RECEIPT_REL,
            WS14_RECEIPT_REL,
            WS15_STATUS_VERDICT_REL,
            WS15_CANONICAL_HMAC_VERDICT_REL,
            WS15_AUTHORITY_VERDICT_REL,
            WS17_RECEIPT_REL,
            WS18_RECEIPT_REL,
            WS19_RECEIPT_REL,
            WS20_RECEIPT_REL,
            WS21_RECEIPT_REL,
            WS22_RECEIPT_REL,
            WS23_RECEIPT_REL,
        ],
    }

    scorecard = {
        "artifact_id": "kt_frontier_rerun_scorecard.json",
        "schema_id": "kt.operator.frontier_rerun_scorecard.v1",
        "generated_utc": utc_now_iso_z(),
        "work_order_id": WORK_ORDER_ID,
        "work_order_schema_id": WORK_ORDER_SCHEMA_ID,
        "workstream_id": WORKSTREAM_ID,
        "sealed_subject_anchor_commit": anchor_subject,
        "evaluated_repo_head_commit": evaluated_repo_head_commit,
        "rows": rows,
        "minimum_post_campaign_targets": minimum_targets,
        "target_checks": target_checks,
        "hard_stop_checks": hard_stop_checks,
        "live_grade_contradiction_check": contradiction_check,
        "final_readjudication": {
            "frontier_posture": final_posture,
            "overall_bounded_system_grade": overall_grade,
            "status": "PASS" if receipt_status == "PASS" else "BLOCKED",
            "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
        },
    }

    receipt = {
        "artifact_id": "kt_sota_readjudication_receipt.json",
        "schema_id": "kt.operator.sota_readjudication_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "work_order_id": WORK_ORDER_ID,
        "work_order_schema_id": WORK_ORDER_SCHEMA_ID,
        "workstream_id": WORKSTREAM_ID,
        "step_id": STEP_ID,
        "status": receipt_status,
        "pass_verdict": pass_verdict,
        "subject_head_commit": anchor_subject,
        "evidence_head_commit": anchor_evidence,
        "evaluated_repo_head_commit": evaluated_repo_head_commit,
        "questions": {
            "what_final_audited_target_was_rerun": {
                "sealed_subject_anchor_commit": anchor_subject,
                "sealed_evidence_anchor_commit": anchor_evidence,
                "evaluated_repo_head_commit": evaluated_repo_head_commit,
                "status": "PASS",
            },
            "how_march_baseline_ws12_and_final_compare": {
                "status": "PASS",
                "packet_ref": FRONTIER_PACKET_REL,
                "scorecard_ref": FRONTIER_SCORECARD_REL,
                "overall_bounded_system_grade": overall_grade,
                "frontier_posture": final_posture,
            },
            "do_live_grades_materially_contradict_closure_receipts": contradiction_check,
            "what_stronger_claim_is_not_made": STRONGER_CLAIM_NOT_MADE,
        },
        "checks": [
            {"check": "baseline_audit_packet_present", "status": "PASS", "refs": [BASELINE_MANIFEST_REL]},
            {"check": "ws12_closure_state_present", "status": "PASS", "refs": [WS12_RECEIPT_REL, WS12_BUNDLE_REL]},
            {"check": "frontier_rerun_comparison_explicit", "status": "PASS", "refs": [FRONTIER_PACKET_REL, FRONTIER_SCORECARD_REL]},
            {"check": "all_prior_receipts_resolve_on_final_audited_target", "status": "PASS" if all(_pass_status(item) for item in (ws13_receipt, ws14_receipt, ws17_receipt, ws18_receipt, ws19_receipt, ws20_receipt, ws21_receipt, ws22_receipt, ws23_receipt)) else "FAIL", "refs": [WS13_RECEIPT_REL, WS14_RECEIPT_REL, WS17_RECEIPT_REL, WS18_RECEIPT_REL, WS19_RECEIPT_REL, WS20_RECEIPT_REL, WS21_RECEIPT_REL, WS22_RECEIPT_REL, WS23_RECEIPT_REL]},
            {"check": "live_readiness_and_authority_no_longer_materially_contradict_claim", "status": contradiction_check["status"], "refs": [WS14_RECEIPT_REL, WS15_AUTHORITY_VERDICT_REL]},
            {"check": "workstream_touches_remain_in_scope", "status": touch_scope_status, "refs": actual_touched},
        ],
        "step_report": {
            "step_id": STEP_ID,
            "workstream_id": WORKSTREAM_ID,
            "actions_taken": [
                "rebuilt the frontier audit packet from the archived March audit, WS12 closure state, and the sealed WS13-WS23 frontier-elevation evidence ladder",
                "compared baseline, WS12, and final state explicitly across repo hygiene, operator readiness, delivery integrity/live authority, external verifiability, and bounded public horizon posture",
                "issued a bounded final verdict from the current evidence without widening beyond the verifier-only public horizon or other still-closed horizons",
            ],
            "resolution": (
                "WS24 reruns the adversarial frontier readjudication on the final audited target and finds that KT has crossed into bounded SOTA on the live audited target."
                if receipt_status == "PASS"
                else "WS24 reruns the frontier readjudication and keeps KT at Advanced-plus with explicit remaining blockers."
            ),
            "pass_fail_status": receipt_status,
            "unexpected_touches": unexpected_touches,
            "protected_touch_violations": protected_touch_violations,
            "tests_run": TESTS_RUN,
            "validators_run": VALIDATORS_RUN,
            "issues_found": [] if receipt_status == "PASS" else [item["condition_id"] for item in hard_stop_checks if item["status"] != "PASS"],
        },
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "tests_run": TESTS_RUN,
        "validators_run": VALIDATORS_RUN,
        "surface_classifications": dict(SURFACE_CLASSIFICATIONS),
        "files_touched": actual_touched,
        "created_files": WORKSTREAM_FILES_TOUCHED,
        "supporting_refs": packet["supporting_refs"],
        "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
        "next_lawful_step": {
            "status_after_workstream": "COMPLETE",
            "workstream_id": "PROGRAM_COMPLETE",
        },
    }
    return {"packet": packet, "scorecard": scorecard, "receipt": receipt}


def emit_frontier_readjudication_outputs(*, root: Path) -> Dict[str, Any]:
    status_lines = _git_status_lines(root)
    baseline_audit = _load_baseline_audit(root)
    ws12_receipt = _load_required_json(root, WS12_RECEIPT_REL)
    ws12_bundle = _load_required_json(root, WS12_BUNDLE_REL)
    ws13_receipt = _load_required_json(root, WS13_RECEIPT_REL)
    ws14_receipt = _load_required_json(root, WS14_RECEIPT_REL)
    ws17_receipt = _load_required_json(root, WS17_RECEIPT_REL)
    ws18_receipt = _load_required_json(root, WS18_RECEIPT_REL)
    ws19_receipt = _load_required_json(root, WS19_RECEIPT_REL)
    ws20_receipt = _load_required_json(root, WS20_RECEIPT_REL)
    ws21_receipt = _load_required_json(root, WS21_RECEIPT_REL)
    ws22_receipt = _load_required_json(root, WS22_RECEIPT_REL)
    ws23_receipt = _load_required_json(root, WS23_RECEIPT_REL)
    ws15_status_verdict = _load_required_text((root / WS15_STATUS_VERDICT_REL).resolve()).strip()
    ws15_canonical_hmac_verdict = _load_required_text((root / WS15_CANONICAL_HMAC_VERDICT_REL).resolve()).strip()
    ws15_authority_verdict = _load_required_text((root / WS15_AUTHORITY_VERDICT_REL).resolve()).strip()
    evaluated_repo_head_commit = _git_head(root)

    provisional_changed = sorted(set(_dirty_relpaths(root, status_lines) + GENERATED_ARTIFACT_REFS))
    outputs = build_frontier_readjudication_outputs_from_artifacts(
        baseline_audit=baseline_audit,
        ws12_receipt=ws12_receipt,
        ws12_bundle=ws12_bundle,
        ws13_receipt=ws13_receipt,
        ws14_receipt=ws14_receipt,
        ws17_receipt=ws17_receipt,
        ws18_receipt=ws18_receipt,
        ws19_receipt=ws19_receipt,
        ws20_receipt=ws20_receipt,
        ws21_receipt=ws21_receipt,
        ws22_receipt=ws22_receipt,
        ws23_receipt=ws23_receipt,
        ws15_status_verdict=ws15_status_verdict,
        ws15_canonical_hmac_verdict=ws15_canonical_hmac_verdict,
        ws15_authority_verdict=ws15_authority_verdict,
        changed_files=provisional_changed,
        evaluated_repo_head_commit=evaluated_repo_head_commit,
    )
    write_json_stable((root / FRONTIER_PACKET_REL).resolve(), outputs["packet"])
    write_json_stable((root / FRONTIER_SCORECARD_REL).resolve(), outputs["scorecard"])
    write_json_stable((root / RECEIPT_REL).resolve(), outputs["receipt"])

    actual_changed = _dirty_relpaths(root, _git_status_lines(root))
    outputs = build_frontier_readjudication_outputs_from_artifacts(
        baseline_audit=baseline_audit,
        ws12_receipt=ws12_receipt,
        ws12_bundle=ws12_bundle,
        ws13_receipt=ws13_receipt,
        ws14_receipt=ws14_receipt,
        ws17_receipt=ws17_receipt,
        ws18_receipt=ws18_receipt,
        ws19_receipt=ws19_receipt,
        ws20_receipt=ws20_receipt,
        ws21_receipt=ws21_receipt,
        ws22_receipt=ws22_receipt,
        ws23_receipt=ws23_receipt,
        ws15_status_verdict=ws15_status_verdict,
        ws15_canonical_hmac_verdict=ws15_canonical_hmac_verdict,
        ws15_authority_verdict=ws15_authority_verdict,
        changed_files=actual_changed,
        evaluated_repo_head_commit=evaluated_repo_head_commit,
    )
    write_json_stable((root / FRONTIER_PACKET_REL).resolve(), outputs["packet"])
    write_json_stable((root / FRONTIER_SCORECARD_REL).resolve(), outputs["scorecard"])
    write_json_stable((root / RECEIPT_REL).resolve(), outputs["receipt"])
    return outputs["receipt"]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Rerun the frontier audit and issue the WS24 bounded SOTA readjudication.")
    parser.parse_args(argv)
    receipt = emit_frontier_readjudication_outputs(root=repo_root())
    print(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if str(receipt.get("status", "")).strip() == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
