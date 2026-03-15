from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.canonical_tree_execute import ARCHIVE_GLOB
from tools.operator.constitutional_completion_emit import TRUTH_POINTER_REF
from tools.operator.documentary_truth_validate import build_documentary_truth_report
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.operator.truth_authority import CURRENT_POINTER_REL


WORKSTREAM_ID = "WS6_LEDGER_LED_AUTHORITY_FINALIZATION"
STEP_ID = "WS6_STEP_1_FINALIZE_LEDGER_AUTHORITY_TOPOLOGY"
PASS_VERDICT = "LEDGER_AUTHORITY_FINALIZED"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
DOCUMENTARY_VALIDATION_REL = f"{REPORT_ROOT_REL}/documentary_truth_validation_receipt.json"
DEMOTION_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_documentary_demotion_final_receipt.json"
CUTOVER_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_authority_topology_cutover_receipt.json"

LEDGER_POINTER_REF = "kt_truth_ledger:ledger/current/current_pointer.json"
LEDGER_CURRENT_STATE_REF = "kt_truth_ledger:ledger/current/current_state_receipt.json"
LEDGER_RUNTIME_AUDIT_REF = "kt_truth_ledger:ledger/current/runtime_closure_audit.json"

CURRENT_STATE_REL = f"{REPORT_ROOT_REL}/current_state_receipt.json"
RUNTIME_AUDIT_REL = f"{REPORT_ROOT_REL}/runtime_closure_audit.json"

SUBJECT_SURFACES = [
    "KT_PROD_CLEANROOM/governance/execution_board.json",
    "KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json",
    "KT_PROD_CLEANROOM/governance/settled_truth_source_contract.json",
    "KT_PROD_CLEANROOM/governance/current_pointer_transition_rules.json",
    "KT_PROD_CLEANROOM/governance/settled_authority_migration_contract.json",
    "KT_PROD_CLEANROOM/governance/truth_snapshot_retention_rules.json",
    "KT_PROD_CLEANROOM/governance/tracked_vs_generated_truth_boundary.json",
    "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json",
    "KT_PROD_CLEANROOM/governance/public_verifier_rules.json",
    "KT_PROD_CLEANROOM/governance/external_legibility_contract.json",
    "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
    "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
    "KT_PROD_CLEANROOM/reports/current_state_receipt.json",
    "KT_PROD_CLEANROOM/reports/runtime_closure_audit.json",
    "KT_PROD_CLEANROOM/reports/truth_pointer_index.json",
    "KT_PROD_CLEANROOM/reports/truth_clean_state_receipt.json",
    "KT_PROD_CLEANROOM/reports/truth_publication_receipt.json",
    "KT_PROD_CLEANROOM/reports/truth_publication_supersession_receipt.json",
    "KT_PROD_CLEANROOM/reports/truth_publication_stabilization_receipt.json",
    "KT_PROD_CLEANROOM/tools/operator/constitutional_completion_emit.py",
    "KT_PROD_CLEANROOM/tools/operator/authority_topology_cutover_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_authority_topology_cutover.py",
]

ALLOWED_TOUCH_PATTERNS = [
    *SUBJECT_SURFACES,
    DOCUMENTARY_VALIDATION_REL,
    DEMOTION_RECEIPT_REL,
    CUTOVER_RECEIPT_REL,
]

PROTECTED_TOUCH_PATTERNS = [
    ".github/workflows/**",
    ARCHIVE_GLOB,
]

MIRROR_TARGETS: List[Tuple[str, str]] = [
    (CURRENT_POINTER_REL, LEDGER_POINTER_REF),
    (CURRENT_STATE_REL, LEDGER_CURRENT_STATE_REF),
    (RUNTIME_AUDIT_REL, LEDGER_RUNTIME_AUDIT_REF),
]


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    try:
        return _git(root, "rev-parse", "HEAD")
    except Exception:  # noqa: BLE001
        return ""


def _git_status_lines(root: Path) -> List[str]:
    try:
        output = subprocess.check_output(["git", "-C", str(root), "status", "--short"], text=True)
    except Exception:  # noqa: BLE001
        return []
    return [line.rstrip() for line in output.splitlines() if line.strip()]


def _git_changed_files(root: Path, commit: str) -> List[str]:
    if not commit:
        return []
    try:
        output = _git(root, "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", commit)
    except Exception:  # noqa: BLE001
        return []
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _status_paths(root: Path) -> List[str]:
    touched: List[str] = []
    for line in _git_status_lines(root):
        payload = line[3:] if len(line) > 3 else ""
        if " -> " in payload:
            before, after = payload.split(" -> ", 1)
            touched.extend([before.replace("\\", "/"), after.replace("\\", "/")])
        elif payload:
            touched.append(payload.replace("\\", "/"))
    return sorted({path for path in touched if path}, key=str.lower)


def _matches_any(path: str, patterns: Sequence[str]) -> bool:
    normalized = str(path).replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in patterns)


def _documentary_only(payload: Dict[str, Any]) -> bool:
    return bool(payload.get("documentary_only")) and payload.get("live_authority") is False


def _build_demotion_receipt(*, root: Path, current_head: str) -> Dict[str, Any]:
    mirrors: List[Dict[str, Any]] = []
    for rel, superseded_by in MIRROR_TARGETS:
        payload = _load_json(root / rel)
        mirrors.append(
            {
                "path": rel,
                "status": str(payload.get("status", "")).strip(),
                "documentary_only": bool(payload.get("documentary_only")),
                "live_authority": payload.get("live_authority"),
                "mirror_class": str(payload.get("mirror_class", "")).strip(),
                "superseded_by": payload.get("superseded_by"),
                "expected_superseded_by": superseded_by,
            }
        )
    status = "PASS" if all(bool(row["documentary_only"]) and row["live_authority"] is False for row in mirrors) else "FAIL_CLOSED"
    return {
        "artifact_id": "kt_documentary_demotion_final_receipt.json",
        "schema_id": "kt.operator.documentary_demotion_final_receipt.v1",
        "workstream_id": WORKSTREAM_ID,
        "status": status,
        "pass_verdict": "DOCUMENTARY_DEMOTION_FINALIZED" if status == "PASS" else "DOCUMENTARY_DEMOTION_NOT_FINALIZED",
        "compiled_head_commit": current_head,
        "subject_head_commit": current_head,
        "evidence_head_commit": current_head,
        "unexpected_touches": [],
        "protected_touch_violations": [],
        "validators_run": [
            "python -m tools.operator.authority_topology_cutover_validate",
        ],
        "next_lawful_step": {
            "status_after_workstream": "UNLOCKED" if status == "PASS" else "BLOCKED",
            "workstream_id": "WS7_TRUST_ROOT_AND_PUBLICATION_ATTESTATION",
        },
        "generated_utc": utc_now_iso_z(),
        "active_truth_source_ref": LEDGER_POINTER_REF,
        "mirror_targets": mirrors,
    }


def build_authority_topology_cutover_outputs(*, root: Path) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    policy = _load_json(root / "KT_PROD_CLEANROOM/governance/documentary_truth_policy.json")
    board = _load_json(root / "KT_PROD_CLEANROOM/governance/execution_board.json")
    readiness = _load_json(root / "KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json")
    settled_contract = _load_json(root / "KT_PROD_CLEANROOM/governance/settled_truth_source_contract.json")
    transition_rules = _load_json(root / "KT_PROD_CLEANROOM/governance/current_pointer_transition_rules.json")
    migration_contract = _load_json(root / "KT_PROD_CLEANROOM/governance/settled_authority_migration_contract.json")
    retention_rules = _load_json(root / "KT_PROD_CLEANROOM/governance/truth_snapshot_retention_rules.json")
    truth_boundary = _load_json(root / "KT_PROD_CLEANROOM/governance/tracked_vs_generated_truth_boundary.json")
    scope_manifest = _load_json(root / "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json")
    verifier_rules = _load_json(root / "KT_PROD_CLEANROOM/governance/public_verifier_rules.json")
    external_legibility = _load_json(root / "KT_PROD_CLEANROOM/governance/external_legibility_contract.json")
    verifier_manifest = _load_json(root / "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json")

    documentary_report = build_documentary_truth_report(root=root)
    current_head = _git_head(root)

    checks: List[Dict[str, Any]] = []
    failures: List[str] = []

    def _check(check_id: str, ok: bool, **payload: Any) -> None:
        row = {"check": check_id, "status": "PASS" if ok else "FAIL"}
        row.update(payload)
        checks.append(row)
        if not ok:
            failures.append(check_id)

    _check(
        "policy_active_truth_source_is_ledger_pointer",
        str(policy.get("active_current_head_truth_source", "")).strip() == LEDGER_POINTER_REF,
        actual=str(policy.get("active_current_head_truth_source", "")).strip(),
        expected=LEDGER_POINTER_REF,
    )
    _check(
        "execution_board_points_to_ledger_pointer",
        str(board.get("authoritative_current_head_truth_source", "")).strip() == LEDGER_POINTER_REF,
        actual=str(board.get("authoritative_current_head_truth_source", "")).strip(),
        expected=LEDGER_POINTER_REF,
    )
    _check(
        "readiness_scope_points_to_ledger_pointer",
        str(readiness.get("authoritative_truth_source", "")).strip() == LEDGER_POINTER_REF,
        actual=str(readiness.get("authoritative_truth_source", "")).strip(),
        expected=LEDGER_POINTER_REF,
    )
    _check(
        "settled_truth_source_contract_points_to_ledger_pointer",
        str(settled_contract.get("current_head_truth_root", "")).strip() == LEDGER_POINTER_REF,
        actual=str(settled_contract.get("current_head_truth_root", "")).strip(),
        expected=LEDGER_POINTER_REF,
    )
    _check(
        "current_pointer_transition_rules_point_to_ledger_pointer",
        str(transition_rules.get("current_pointer_ref", "")).strip() == LEDGER_POINTER_REF,
        actual=str(transition_rules.get("current_pointer_ref", "")).strip(),
        expected=LEDGER_POINTER_REF,
    )
    _check(
        "truth_snapshot_retention_rules_point_to_ledger_pointer",
        str(retention_rules.get("current_pointer_ref", "")).strip() == LEDGER_POINTER_REF,
        actual=str(retention_rules.get("current_pointer_ref", "")).strip(),
        expected=LEDGER_POINTER_REF,
    )
    required_outputs = migration_contract.get("required_outputs") if isinstance(migration_contract.get("required_outputs"), list) else []
    _check(
        "settled_authority_migration_outputs_ledger_pointer",
        LEDGER_POINTER_REF in required_outputs and CURRENT_POINTER_REL not in required_outputs,
        required_outputs=required_outputs,
    )
    generated_authoritative = truth_boundary.get("generated_authoritative_surfaces") if isinstance(truth_boundary.get("generated_authoritative_surfaces"), list) else []
    tracked_documentary = truth_boundary.get("tracked_documentary_surfaces") if isinstance(truth_boundary.get("tracked_documentary_surfaces"), list) else []
    _check(
        "truth_boundary_promotes_only_ledger_generated_authority",
        LEDGER_POINTER_REF in generated_authoritative and CURRENT_POINTER_REL not in generated_authoritative,
        generated_authoritative_surfaces=generated_authoritative,
    )
    _check(
        "truth_boundary_demotes_repo_mirror_surfaces",
        all(path in tracked_documentary for path in (CURRENT_POINTER_REL, CURRENT_STATE_REL, RUNTIME_AUDIT_REL)),
        tracked_documentary_surfaces=tracked_documentary,
    )
    generated_truth = scope_manifest.get("generated_truth_surfaces") if isinstance(scope_manifest.get("generated_truth_surfaces"), list) else []
    _check(
        "canonical_scope_includes_ledger_truth_refs",
        all(path in generated_truth for path in (LEDGER_POINTER_REF, LEDGER_CURRENT_STATE_REF, LEDGER_RUNTIME_AUDIT_REF)),
        generated_truth_surfaces=generated_truth,
    )
    _check(
        "public_verifier_manifest_points_to_ledger_pointer",
        str(verifier_manifest.get("truth_pointer_ref", "")).strip() == LEDGER_POINTER_REF,
        actual=str(verifier_manifest.get("truth_pointer_ref", "")).strip(),
        expected=LEDGER_POINTER_REF,
    )
    verifier_authority_refs = verifier_rules.get("authority_refs") if isinstance(verifier_rules.get("authority_refs"), list) else []
    _check(
        "public_verifier_rules_reference_ledger_pointer",
        LEDGER_POINTER_REF in verifier_authority_refs and CURRENT_POINTER_REL not in verifier_authority_refs,
        authority_refs=verifier_authority_refs,
    )
    external_authority_refs = external_legibility.get("authority_refs") if isinstance(external_legibility.get("authority_refs"), list) else []
    _check(
        "external_legibility_contract_references_ledger_pointer",
        LEDGER_POINTER_REF in external_authority_refs and CURRENT_POINTER_REL not in external_authority_refs,
        authority_refs=external_authority_refs,
    )
    _check(
        "constitutional_completion_emit_default_truth_pointer_is_ledger",
        TRUTH_POINTER_REF == LEDGER_POINTER_REF,
        actual=TRUTH_POINTER_REF,
        expected=LEDGER_POINTER_REF,
    )
    _check(
        "documentary_truth_validation_passes",
        str(documentary_report.get("status", "")).strip() == "PASS",
        failures=documentary_report.get("failures", []),
    )

    demotion_receipt = _build_demotion_receipt(root=root, current_head=current_head)

    touched_from_head = _git_changed_files(root, current_head)
    dirty_paths = _status_paths(root)
    touched = sorted(set(touched_from_head + dirty_paths + [DOCUMENTARY_VALIDATION_REL, DEMOTION_RECEIPT_REL, CUTOVER_RECEIPT_REL]), key=str.lower)
    unexpected = [path for path in touched if not _matches_any(path, ALLOWED_TOUCH_PATTERNS)]
    protected = [path for path in touched if _matches_any(path, PROTECTED_TOUCH_PATTERNS)]
    if unexpected:
        failures.append("unexpected_touches_present")
    if protected:
        failures.append("protected_touch_violations_present")

    status = "PASS" if not failures else "FAIL_CLOSED"
    cutover_receipt = {
        "artifact_id": "kt_authority_topology_cutover_receipt.json",
        "schema_id": "kt.operator.authority_topology_cutover_receipt.v1",
        "workstream_id": WORKSTREAM_ID,
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else "LEDGER_AUTHORITY_NOT_FINALIZED",
        "compiled_head_commit": current_head,
        "subject_head_commit": current_head,
        "evidence_head_commit": current_head,
        "unexpected_touches": unexpected,
        "protected_touch_violations": protected,
        "validators_run": [
            "python -m tools.operator.authority_topology_cutover_validate",
        ],
        "next_lawful_step": {
            "status_after_workstream": "UNLOCKED" if status == "PASS" else "BLOCKED",
            "workstream_id": "WS7_TRUST_ROOT_AND_PUBLICATION_ATTESTATION",
        },
        "generated_utc": utc_now_iso_z(),
        "active_truth_source_ref": LEDGER_POINTER_REF,
        "documentary_validation_ref": DOCUMENTARY_VALIDATION_REL,
        "documentary_validation_status": str(documentary_report.get("status", "")).strip(),
        "checks": checks,
        "issues_found": failures,
        "step_report": {
            "timestamp": utc_now_iso_z(),
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "cut over live authority contracts to the ledger current pointer",
                "pointed execution board and readiness scope at the ledger current pointer",
                "marked main-bound current truth mirrors documentary-only",
                "repointed public verifier and external legibility surfaces to the ledger current pointer",
                "validated the final documentary demotion boundary",
            ],
            "files_touched": touched,
            "tests_run": [
                "python -m pytest KT_PROD_CLEANROOM/tests/operator/test_authority_topology_cutover.py -q",
            ],
            "validators_run": [
                "python -m tools.operator.authority_topology_cutover_validate",
            ],
            "issues_found": failures,
            "resolution": (
                "WS6 finalizes the ledger-led live authority topology and freezes the repo mirrors as documentary-only."
                if status == "PASS"
                else "Ledger authority cutover remains blocked; inspect failed checks and touch accounting."
            ),
            "pass_fail_status": status,
            "unexpected_touches": unexpected,
            "protected_touch_violations": protected,
        },
    }
    demotion_receipt["unexpected_touches"] = list(unexpected)
    demotion_receipt["protected_touch_violations"] = list(protected)
    demotion_receipt["next_lawful_step"] = cutover_receipt["next_lawful_step"]
    return documentary_report, demotion_receipt, cutover_receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate the WS6 ledger-led authority topology cutover.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    _parse_args(argv)
    root = repo_root()
    documentary_report, demotion_receipt, cutover_receipt = build_authority_topology_cutover_outputs(root=root)
    write_json_stable(root / DOCUMENTARY_VALIDATION_REL, documentary_report)
    write_json_stable(root / DEMOTION_RECEIPT_REL, demotion_receipt)
    write_json_stable(root / CUTOVER_RECEIPT_REL, cutover_receipt)
    print(
        json.dumps(
            {
                "status": cutover_receipt["status"],
                "workstream_id": WORKSTREAM_ID,
                "pass_verdict": cutover_receipt["pass_verdict"],
                "changed": sorted([DOCUMENTARY_VALIDATION_REL, DEMOTION_RECEIPT_REL, CUTOVER_RECEIPT_REL]),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if cutover_receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
