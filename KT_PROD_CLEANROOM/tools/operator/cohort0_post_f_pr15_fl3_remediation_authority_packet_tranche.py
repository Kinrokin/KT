from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_pr15_fl3_remediation_authority_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_pr15_fl3_remediation_authority_receipt.json"
OUTPUT_BLOCKERS = "cohort0_post_f_pr15_fl3_remediation_blocker_ledger.json"
OUTPUT_REPORT = "COHORT0_POST_F_PR15_FL3_REMEDIATION_AUTHORITY_REPORT.md"

REQUIRED_BRANCH = "authoritative/post-f-pr15-fl3-remediation"
PARENT_AUTHORITATIVE_BRANCH = "authoritative/post-f-truth-engine"
EXECUTION_STATUS = "PASS__POST_F_PR15_FL3_REMEDIATION_AUTHORITY_BOUND"
OUTCOME = "POST_F_PR15_FL3_REMEDIATION_LANE_OPEN__NARROW_BLOCKER_PROGRAM_ONLY"
NEXT_MOVE = "AUTHOR_POST_F_PR15_FL3_LAW_BUNDLE_AND_AMENDMENT_MISMATCH_PACKET"


def _current_branch_name(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip() or "UNKNOWN_BRANCH"


def _git_status_porcelain(root: Path) -> str:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout


def _git_rev_parse(root: Path, ref: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", ref],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip()


def _git_merge_base(root: Path, left: str, right: str) -> str:
    result = subprocess.run(
        ["git", "merge-base", left, right],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip()


def _path_exists(root: Path, rel_path: str) -> bool:
    return (root / rel_path).exists()


def _probe_fl3_meta_evaluator(root: Path) -> Dict[str, Any]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [
            str((root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src").resolve()),
            str((root / "KT_PROD_CLEANROOM").resolve()),
        ]
    )
    result = subprocess.run(
        ["python", "-m", "tools.verification.fl3_meta_evaluator"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
    )
    return {
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "combined_tail": "\n".join(
            [part for part in [result.stdout.strip(), result.stderr.strip()] if part]
        )[-1200:],
    }


def _tranche_plan() -> List[Dict[str, Any]]:
    return [
        {
            "tranche_id": "T01",
            "lane_step": "law_bundle_and_amendment_mismatch",
            "summary": "Fix current LAW_BUNDLE hash / amendment expectation drift first.",
            "success_condition": "fl3_meta_evaluator no longer fail-closes on missing kt.law_amendment.v2 or law-bundle hash mismatch.",
        },
        {
            "tranche_id": "T02",
            "lane_step": "missing_active_tree_assets",
            "summary": "Bind missing active-tree assets and emit explicit asset-gap receipt instead of silent file recreation.",
            "success_condition": "required active-tree audit/runtime path assets are present or lawfully superseded.",
        },
        {
            "tranche_id": "T03",
            "lane_step": "archive_assumption_decontamination",
            "summary": "Remove active test/workflow dependence on quarantined archive-era surfaces.",
            "success_condition": "archive-era assumptions are converted into active-tree law or explicit clean skips.",
        },
        {
            "tranche_id": "T04",
            "lane_step": "phase_path_normalization",
            "summary": "Normalize superseded phase entrypoint/path expectations with explicit receipts.",
            "success_condition": "phase path references resolve lawfully through current active-tree paths or supersession maps.",
        },
        {
            "tranche_id": "T05",
            "lane_step": "full_fl3_red_to_green",
            "summary": "Rerun the full FL3 suite only after T01-T04 are frozen.",
            "success_condition": "PR15 required FL3 checks are green enough to merge without changing truth-engine or package law.",
        },
    ]


def build_outputs(
    *,
    branch_name: str,
    branch_head: str,
    parent_head: str,
    truth_engine_recompute_receipt: Dict[str, Any],
    truth_engine_replay_packet: Dict[str, Any],
    truth_engine_handoff_note: Dict[str, Any],
    meta_probe: Dict[str, Any],
    asset_exists: Dict[str, bool],
) -> Dict[str, Dict[str, Any] | str]:
    tranche_plan = _tranche_plan()
    blockers: List[Dict[str, Any]] = [
        {
            "blocker_id": "PR15_FL3_LAW_BUNDLE_AND_AMENDMENT_MISMATCH",
            "tranche_id": "T01",
            "severity": "blocking_high",
            "summary": "fl3_meta_evaluator still fail-closes on current law-bundle/amendment expectations.",
            "evidence": meta_probe["combined_tail"] or f"returncode={meta_probe['returncode']}",
            "in_scope_files": [
                ".github/workflows/ci_fl3_pr_fast.yml",
                ".github/workflows/ci_epic15_governance.yml",
                ".github/workflows/ci_epic16_governance.yml",
                "KT_PROD_CLEANROOM/tools/verification/fl3_meta_evaluator.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_fl3_meta_evaluator.py",
            ],
        },
        {
            "blocker_id": "PR15_FL3_MISSING_ACTIVE_TREE_ASSETS",
            "tranche_id": "T02",
            "severity": "blocking_high",
            "summary": "The FL3 suite still carries active-tree asset expectation drift: some required assets exist, but parts of the suite resolve them through the wrong path layer and treat them as missing.",
            "evidence": {
                "fl3_canonical_runtime_paths_exists": asset_exists["fl3_canonical_runtime_paths"],
                "failure_taxonomy_exists": asset_exists["failure_taxonomy"],
                "suite_path_resolution_mismatch_observed": True,
            },
            "in_scope_files": [
                "KT_PROD_CLEANROOM/AUDITS/FL3_CANONICAL_RUNTIME_PATHS.json",
                "KT_PROD_CLEANROOM/AUDITS/FAILURE_TAXONOMY_FL3.json",
                "KT_PROD_CLEANROOM/tools/audit_intelligence/run_audit_intelligence.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_audit_intelligence.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_fl3_canonical_runtime_paths.py",
            ],
        },
        {
            "blocker_id": "PR15_FL3_ARCHIVE_ASSUMPTION_DECONTAMINATION",
            "tranche_id": "T03",
            "severity": "blocking_medium",
            "summary": "Some FL3 workflows/tests still assume quarantined archive-era receipt surfaces are active truth.",
            "evidence": {
                "archive_receipts_dir_exists": asset_exists["archive_receipts_dir"],
                "ci_fl3_pr_fast_receipt_validation_now_skips_missing_archive": True,
            },
            "in_scope_files": [
                ".github/workflows/ci_fl3_pr_fast.yml",
                "KT_PROD_CLEANROOM/tests/fl3/test_fl3_receipts_no_secrets.py",
                "KT_PROD_CLEANROOM/tools/verification/validate_receipts.py",
            ],
        },
        {
            "blocker_id": "PR15_FL3_PHASE_PATH_NORMALIZATION",
            "tranche_id": "T04",
            "severity": "blocking_medium",
            "summary": "Phase entrypoint/path expectations drifted relative to the active tree and need explicit normalization receipts.",
            "evidence": {
                "phase1c_executor_exists": asset_exists["phase1c_executor"],
            },
            "in_scope_files": [
                "KT_PROD_CLEANROOM/tools/verification/phase1c_execute.py",
                "KT_PROD_CLEANROOM/tools/verification/phase2_execute.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_phase1c_execute_smoke.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_phase2_execute_dry_run_smoke.py",
            ],
        },
        {
            "blocker_id": "PR15_FL3_FULL_RED_TO_GREEN_PENDING",
            "tranche_id": "T05",
            "severity": "blocking_high",
            "summary": "The full FL3 suite remains red until T01-T04 are frozen and rerun.",
            "evidence": "Local full FL3 rerun remains red after harness fixes; merge is not ready until the ordered remediation stack completes.",
            "in_scope_files": [
                ".github/workflows/ci_fl3_pr_fast.yml",
                ".github/workflows/ci_epic15_governance.yml",
                ".github/workflows/ci_epic16_governance.yml",
                ".github/workflows/ci_fl4_preflight.yml",
                ".github/workflows/ci_truth_barrier.yml",
                "KT_PROD_CLEANROOM/tests/fl3/**",
            ],
        },
    ]

    blocker_ledger = {
        "schema_id": "kt.operator.cohort0_post_f_pr15_fl3_remediation_blocker_ledger.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": OUTCOME,
        "blocking_blocker_count": len(blockers),
        "tranche_plan": tranche_plan,
        "blockers": blockers,
    }

    packet = {
        "schema_id": "kt.operator.cohort0_post_f_pr15_fl3_remediation_authority_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": OUTCOME,
        "claim_boundary": (
            "This authority packet opens only the narrow PR15 FL3 remediation lane. "
            "It does not widen package truth, does not change truth-engine derivation law, "
            "and does not authorize the main truth-engine replay early."
        ),
        "authority_header": {
            "authoritative_branch": branch_name,
            "authoritative_branch_head": branch_head,
            "parent_truth_engine_branch": PARENT_AUTHORITATIVE_BRANCH,
            "parent_truth_engine_branch_head": parent_head,
            "package_promotion_still_deferred": True,
            "truth_engine_law_unchanged": True,
            "replay_on_main_still_deferred_until_pr15_merge": True,
        },
        "current_read": {
            "truth_engine_recompute_scope": str(truth_engine_recompute_receipt.get("recompute_scope", "")).strip(),
            "truth_engine_blocking_contradiction_count": int(
                truth_engine_recompute_receipt.get("blocking_contradiction_count", 0)
            ),
            "truth_engine_advisory_condition_count": int(
                truth_engine_recompute_receipt.get("advisory_condition_count", 0)
            ),
            "remote_replay_expected_change": dict(
                truth_engine_replay_packet.get("expected_advisory_disappearance", {})
            ),
            "post_pr_canonical_success_condition": str(
                truth_engine_handoff_note.get("first_canonical_truth_engine_freeze_on_main", {}).get(
                    "success_condition", ""
                )
            ).strip(),
        },
        "exact_scope": {
            "workflow_scope": [
                ".github/workflows/ci_no_conflict_markers.yml",
                ".github/workflows/ci_fl3_pr_fast.yml",
                ".github/workflows/ci_epic15_governance.yml",
                ".github/workflows/ci_epic16_governance.yml",
                ".github/workflows/ci_fl4_preflight.yml",
                ".github/workflows/ci_truth_barrier.yml",
            ],
            "tooling_scope": [
                "KT_PROD_CLEANROOM/tools/verification/fl3_meta_evaluator.py",
                "KT_PROD_CLEANROOM/tools/verification/fl3_validators.py",
                "KT_PROD_CLEANROOM/tools/verification/validate_receipts.py",
                "KT_PROD_CLEANROOM/tools/verification/phase1c_execute.py",
                "KT_PROD_CLEANROOM/tools/verification/phase2_execute.py",
                "KT_PROD_CLEANROOM/tools/audit_intelligence/run_audit_intelligence.py",
            ],
            "test_scope": [
                "KT_PROD_CLEANROOM/tests/fl3/test_fl3_meta_evaluator.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_fl3_law_bundle_integrity.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_fl3_canonical_runtime_paths.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_fl3_receipts_no_secrets.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_operator_cli.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_phase1c_execute_smoke.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_phase2_execute_dry_run_smoke.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_audit_intelligence.py",
            ],
        },
        "do_not_widen_boundaries": [
            "Do not widen package truth.",
            "Do not change truth-engine derivation law.",
            "Do not rerun the main truth-engine replay early.",
            "Do not let prep lanes become authoritative.",
            "Do not widen Track 03 or package promotion to chase green checks.",
        ],
        "success_condition": {
            "required_checks_green_enough_to_merge": True,
            "package_promotion_deferral_unchanged": True,
            "truth_engine_law_unchanged": True,
            "main_truth_engine_replay_still_waits_for_pr15_merge": True,
        },
        "tranche_order": tranche_plan,
        "blocker_ledger_ref": common.resolve_path(
            repo_root(), f"KT_PROD_CLEANROOM/reports/{OUTPUT_BLOCKERS}"
        ).as_posix(),
        "source_refs": common.output_ref_dict(
            truth_engine_recompute_receipt=common.resolve_path(
                repo_root(), "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_recompute_receipt.json"
            ),
            truth_engine_replay_packet=common.resolve_path(
                repo_root(), "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_post_merge_replay_packet.json"
            ),
            truth_engine_handoff_note=common.resolve_path(
                repo_root(), "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_post_pr_canonical_handoff_note.json"
            ),
        ),
        "next_lawful_move": NEXT_MOVE,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_pr15_fl3_remediation_authority_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": OUTCOME,
        "blocker_count": len(blockers),
        "tranche_count": len(tranche_plan),
        "next_lawful_move": NEXT_MOVE,
    }

    report = common.report_lines(
        "Cohort0 Post-F PR15 FL3 Remediation Authority Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Lane outcome: `{OUTCOME}`",
            f"- Authoritative remediation branch: `{branch_name}`",
            f"- Parent truth-engine head: `{parent_head}`",
            f"- Blocker count: `{len(blockers)}`",
            f"- Tranche count: `{len(tranche_plan)}`",
            "- Package promotion remains deferred.",
            "- Truth-engine replay on main remains deferred until PR `#15` actually merges.",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "blockers": blocker_ledger, "report": report}


def run(
    *,
    reports_root: Path,
    truth_engine_recompute_receipt_path: Path,
    truth_engine_replay_packet_path: Path,
    truth_engine_handoff_note_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: remediation authority packet must run on {REQUIRED_BRANCH}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: remediation authority packet requires a clean worktree")

    truth_engine_recompute_receipt = common.load_json_required(
        root, truth_engine_recompute_receipt_path, label="truth-engine recompute receipt"
    )
    truth_engine_replay_packet = common.load_json_required(
        root, truth_engine_replay_packet_path, label="truth-engine post-merge replay packet"
    )
    truth_engine_handoff_note = common.load_json_required(
        root, truth_engine_handoff_note_path, label="truth-engine post-PR canonical handoff note"
    )
    common.ensure_pass(truth_engine_recompute_receipt, label="truth-engine recompute receipt")
    common.ensure_pass(truth_engine_replay_packet, label="truth-engine post-merge replay packet")
    common.ensure_pass(truth_engine_handoff_note, label="truth-engine post-PR canonical handoff note")

    if str(truth_engine_recompute_receipt.get("next_lawful_move", "")).strip() != "RERUN_POST_F_TRUTH_ENGINE_RECOMPUTE_ON_MAIN_AFTER_PR15_MERGE":
        raise RuntimeError("FAIL_CLOSED: truth-engine lane no longer authorizes the deferred main replay contract")

    parent_head = _git_rev_parse(root, PARENT_AUTHORITATIVE_BRANCH)
    branch_head = _git_rev_parse(root, "HEAD")
    if _git_merge_base(root, PARENT_AUTHORITATIVE_BRANCH, "HEAD") != parent_head:
        raise RuntimeError("FAIL_CLOSED: remediation branch must descend cleanly from the truth-engine branch head")

    meta_probe = _probe_fl3_meta_evaluator(root)
    asset_exists = {
        "fl3_canonical_runtime_paths": _path_exists(root, "KT_PROD_CLEANROOM/AUDITS/FL3_CANONICAL_RUNTIME_PATHS.json"),
        "failure_taxonomy": _path_exists(root, "KT_PROD_CLEANROOM/AUDITS/FAILURE_TAXONOMY_FL3.json"),
        "archive_receipts_dir": _path_exists(root, "KT_ARCHIVE/vault/receipts"),
        "phase1c_executor": _path_exists(root, "KT_PROD_CLEANROOM/tools/verification/phase1c_execute.py"),
    }

    outputs = build_outputs(
        branch_name=branch_name,
        branch_head=branch_head,
        parent_head=parent_head,
        truth_engine_recompute_receipt=truth_engine_recompute_receipt,
        truth_engine_replay_packet=truth_engine_replay_packet,
        truth_engine_handoff_note=truth_engine_handoff_note,
        meta_probe=meta_probe,
        asset_exists=asset_exists,
    )

    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    common.write_text(
        (reports_root / OUTPUT_BLOCKERS).resolve(),
        __import__("json").dumps(outputs["blockers"], indent=2, sort_keys=True) + "\n",
    )
    return {
        "lane_outcome": OUTCOME,
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": NEXT_MOVE,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Open the narrow PR15 FL3 remediation authority lane.")
    parser.add_argument(
        "--truth-engine-recompute-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_recompute_receipt.json",
    )
    parser.add_argument(
        "--truth-engine-replay-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_post_merge_replay_packet.json",
    )
    parser.add_argument(
        "--truth-engine-handoff-note",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_post_pr_canonical_handoff_note.json",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        truth_engine_recompute_receipt_path=common.resolve_path(root, args.truth_engine_recompute_receipt),
        truth_engine_replay_packet_path=common.resolve_path(root, args.truth_engine_replay_packet),
        truth_engine_handoff_note_path=common.resolve_path(root, args.truth_engine_handoff_note),
    )
    print(result["lane_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
