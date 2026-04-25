from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_pr15_fl3_archive_assumption_decontamination_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_pr15_fl3_archive_assumption_decontamination_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_PR15_FL3_ARCHIVE_ASSUMPTION_DECONTAMINATION_REPORT.md"

REQUIRED_BRANCH = "authoritative/post-f-pr15-fl3-remediation"
EXECUTION_STATUS = "PASS__POST_F_PR15_FL3_ARCHIVE_ASSUMPTION_DECONTAMINATION_BOUND"
OUTCOME_DEFINED = (
    "POST_F_PR15_FL3_ARCHIVE_ASSUMPTION_DECONTAMINATION_DEFINED__TEST_LAYER_STILL_TREATS_ARCHIVE_RECEIPTS_AS_ACTIVE"
)
OUTCOME_CLEARED = "POST_F_PR15_FL3_ARCHIVE_ASSUMPTION_DECONTAMINATION_RESOLVED__TRANCHE3_CLEARED"
NEXT_MOVE_DEFINED = "EXECUTE_POST_F_PR15_FL3_ARCHIVE_ASSUMPTION_DECONTAMINATION_REMEDIATION"
NEXT_MOVE_CLEARED = "AUTHOR_POST_F_PR15_FL3_PHASE_PATH_NORMALIZATION_PACKET"

AUTHORITY_PACKET_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_remediation_authority_packet.json"
AUTHORITY_RECEIPT_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_remediation_authority_receipt.json"
BLOCKER_LEDGER_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_remediation_blocker_ledger.json"
T02_RECEIPT_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_active_tree_asset_expectation_drift_receipt.json"

ARCHIVE_RECEIPTS_REL = "KT_ARCHIVE/vault/receipts"
CI_WORKFLOW_REL = ".github/workflows/ci_fl3_pr_fast.yml"
SECRETS_TEST_REL = "KT_PROD_CLEANROOM/tests/fl3/test_fl3_receipts_no_secrets.py"
VALIDATE_RECEIPTS_TEST_REL = "KT_PROD_CLEANROOM/tools/verification/tests/test_validate_receipts.py"


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
        ["git", "status", "--porcelain", "--untracked-files=no"],
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


def _path_exists(root: Path, rel_path: str) -> bool:
    return common.resolve_path(root, rel_path).exists()


def _workflow_skips_missing_archive_receipts(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    return "if [ -d KT_ARCHIVE/vault/receipts ]; then" in text and "SKIP: KT_ARCHIVE/vault/receipts is not present on the active canonical tree" in text


def _secrets_test_still_requires_archive_receipts(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    return 'assert receipts_dir.exists()' in text


def _secrets_test_skips_missing_archive_receipts(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    return "pytest.skip" in text and "active canonical tree" in text


def _validate_receipts_repo_test_still_requires_archive_dir(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    return 'receipts_dir = Path("KT_ARCHIVE/vault/receipts")' in text and "pytest.skip" not in text


def _validate_receipts_repo_test_skips_missing_archive_dir(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    return 'receipts_dir = Path("KT_ARCHIVE/vault/receipts")' in text and "pytest.skip" in text


def _resolution_classes() -> List[Dict[str, str]]:
    return [
        {
            "class_id": "DEMOTE_ARCHIVE_RECEIPTS_FROM_ACTIVE_TREE_REQUIREMENT",
            "summary": "Tests may not require KT_ARCHIVE/vault/receipts to exist on the active canonical tree when workflow law already treats that surface as optional lineage-only input.",
        },
        {
            "class_id": "ALIGN_TEST_BEHAVIOR_WITH_WORKFLOW_SKIP_LAW",
            "summary": "If archive receipts are absent from the active tree, tests must skip or use isolated fixtures rather than fail-close on the missing archive directory.",
        },
        {
            "class_id": "KEEP_ARCHIVE_PROMOTION_FORBIDDEN",
            "summary": "Resolve the assumption at the test layer; do not re-promote archive receipts into the active canonical tree just to make the suite green.",
        },
    ]


def build_outputs(
    *,
    branch_name: str,
    branch_head: str,
    authority_packet: Dict[str, Any],
    archive_receipts_exists: bool,
    workflow_skips_missing_archive_receipts: bool,
    secrets_test_requires_archive_receipts: bool,
    secrets_test_skips_missing_archive_receipts: bool,
    validate_receipts_repo_test_requires_archive_dir: bool,
    validate_receipts_repo_test_skips_missing_archive_dir: bool,
) -> Dict[str, Dict[str, Any] | str]:
    defined = (
        not archive_receipts_exists
        and workflow_skips_missing_archive_receipts
        and (secrets_test_requires_archive_receipts or validate_receipts_repo_test_requires_archive_dir)
    )
    cleared = (
        not archive_receipts_exists
        and workflow_skips_missing_archive_receipts
        and secrets_test_skips_missing_archive_receipts
        and validate_receipts_repo_test_skips_missing_archive_dir
    )
    if defined == cleared:
        raise RuntimeError("FAIL_CLOSED: tranche T03 state is neither the frozen archive-assumption condition nor the cleared condition")

    lane_outcome = OUTCOME_CLEARED if cleared else OUTCOME_DEFINED
    next_move = NEXT_MOVE_CLEARED if cleared else NEXT_MOVE_DEFINED
    tranche_state = "cleared" if cleared else "defined"
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_pr15_fl3_archive_assumption_decontamination_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": lane_outcome,
        "claim_boundary": (
            "This packet binds tranche T03 only. It does not widen package truth, does not change truth-engine law, "
            "and does not authorize archive promotion or main replay."
        ),
        "authority_header": {
            "authoritative_branch": branch_name,
            "authoritative_branch_head": branch_head,
            "package_promotion_still_deferred": bool(
                authority_packet.get("authority_header", {}).get("package_promotion_still_deferred", False)
            ),
            "truth_engine_law_unchanged": bool(
                authority_packet.get("authority_header", {}).get("truth_engine_law_unchanged", False)
            ),
            "replay_on_main_still_deferred_until_pr15_merge": bool(
                authority_packet.get("authority_header", {}).get("replay_on_main_still_deferred_until_pr15_merge", False)
            ),
        },
        "tranche_header": {
            "tranche_id": "T03",
            "tranche_name": "archive_assumption_decontamination",
            "ordered_blocker_position": 3,
            "tranche_state": tranche_state,
            "archive_assumption_class": (
                "TEST_LAYER_STILL_REQUIRES_ARCHIVE_RECEIPTS_ON_ACTIVE_TREE"
                if not cleared
                else "ARCHIVE_RECEIPTS_DEMOTED_TO_LINEAGE_ONLY_IN_TEST_LAYER"
            ),
        },
        "archive_truth": {
            "archive_receipts_rel": ARCHIVE_RECEIPTS_REL,
            "archive_receipts_exists_on_active_tree": archive_receipts_exists,
            "workflow_skip_law_present": workflow_skips_missing_archive_receipts,
        },
        "decontamination_evidence": {
            "secrets_test_requires_archive_receipts": secrets_test_requires_archive_receipts,
            "secrets_test_skips_missing_archive_receipts": secrets_test_skips_missing_archive_receipts,
            "validate_receipts_repo_test_requires_archive_dir": validate_receipts_repo_test_requires_archive_dir,
            "validate_receipts_repo_test_skips_missing_archive_dir": validate_receipts_repo_test_skips_missing_archive_dir,
        },
        "precedence_rule": {
            "winning_source": "active_canonical_tree_boundary_plus_ci_skip_law",
            "winning_rule": (
                "If KT_ARCHIVE/vault/receipts is absent from the active canonical tree and CI explicitly treats that absence as a lawful skip, "
                "test expectations may not re-promote archive receipts into active-tree requirements."
            ),
            "resolution_decision_rule": (
                "Prefer decontaminating the test layer to match active-tree boundary law over restoring archive receipts into the canonical tree."
            ),
        },
        "allowed_resolution_classes": _resolution_classes(),
        "live_resolution_read": {
            "archive_receipts_are_active_tree_requirement": False,
            "test_layer_archive_assumption_present": not cleared,
            "recommended_resolution_class": (
                "ALIGN_TEST_BEHAVIOR_WITH_WORKFLOW_SKIP_LAW"
                if not cleared
                else "ADVANCE_TO_T04_PHASE_PATH_NORMALIZATION"
            ),
            "recommended_resolution_summary": (
                "Workflow law already demotes missing archive receipts to a lawful skip; the remaining defect is the test layer still treating that archive surface as mandatory."
                if not cleared
                else "Archive receipt assumptions are decontaminated from the test layer and tranche T03 is cleared."
            ),
        },
        "exact_scope": {
            "workflow_scope": [CI_WORKFLOW_REL],
            "test_scope": [
                SECRETS_TEST_REL,
                VALIDATE_RECEIPTS_TEST_REL,
            ],
            "tool_scope": [
                "KT_PROD_CLEANROOM/tools/verification/validate_receipts.py",
            ],
        },
        "do_not_widen_boundaries": authority_packet.get("do_not_widen_boundaries", []),
        "success_condition": {
            "archive_receipts_remain_outside_active_tree": True,
            "tests_no_longer_require_archive_receipts_dir_when_absent": True,
            "blocker_ledger_advances_to_tranche_4": True,
            "package_truth_unchanged": True,
            "truth_engine_law_unchanged": True,
            "archive_promotion_forbidden": True,
        },
        "source_refs": common.output_ref_dict(
            remediation_authority_packet=common.resolve_path(repo_root(), AUTHORITY_PACKET_PATH),
            remediation_authority_receipt=common.resolve_path(repo_root(), AUTHORITY_RECEIPT_PATH),
            remediation_blocker_ledger=common.resolve_path(repo_root(), BLOCKER_LEDGER_PATH),
            tranche2_receipt=common.resolve_path(repo_root(), T02_RECEIPT_PATH),
            ci_fl3_pr_fast=common.resolve_path(repo_root(), CI_WORKFLOW_REL),
            fl3_receipts_no_secrets_test=common.resolve_path(repo_root(), SECRETS_TEST_REL),
            validate_receipts_repo_test=common.resolve_path(repo_root(), VALIDATE_RECEIPTS_TEST_REL),
        ),
        "next_lawful_move": next_move,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_pr15_fl3_archive_assumption_decontamination_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": lane_outcome,
        "tranche_id": "T03",
        "tranche_state": tranche_state,
        "archive_receipts_exists_on_active_tree": archive_receipts_exists,
        "workflow_skip_law_present": workflow_skips_missing_archive_receipts,
        "secrets_test_still_requires_archive_receipts": secrets_test_requires_archive_receipts,
        "validate_receipts_repo_test_still_requires_archive_dir": validate_receipts_repo_test_requires_archive_dir,
        "next_lawful_move": next_move,
    }
    report = common.report_lines(
        "Cohort0 Post-F PR15 FL3 Archive Assumption Decontamination Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Lane outcome: `{lane_outcome}`",
            "- Tranche: `T03 archive_assumption_decontamination`",
            f"- Tranche state: `{tranche_state}`",
            f"- Archive receipts exist on active tree: `{archive_receipts_exists}`",
            f"- Workflow skip law present: `{workflow_skips_missing_archive_receipts}`",
            f"- Secrets test still requires archive receipts: `{secrets_test_requires_archive_receipts}`",
            f"- Validate-receipts repo test still requires archive dir: `{validate_receipts_repo_test_requires_archive_dir}`",
            f"- Recommended resolution class: `{packet['live_resolution_read']['recommended_resolution_class']}`",
            f"- Next lawful move: `{next_move}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    authority_packet_path: Path,
    authority_receipt_path: Path,
    blocker_ledger_path: Path,
    tranche2_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: tranche T03 must run on {REQUIRED_BRANCH}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: tranche T03 requires a clean tracked worktree")

    authority_packet = common.load_json_required(root, authority_packet_path, label="PR15 FL3 remediation authority packet")
    authority_receipt = common.load_json_required(root, authority_receipt_path, label="PR15 FL3 remediation authority receipt")
    blocker_ledger = common.load_json_required(root, blocker_ledger_path, label="PR15 FL3 remediation blocker ledger")
    tranche2_receipt = common.load_json_required(root, tranche2_receipt_path, label="tranche T02 receipt")
    common.ensure_pass(authority_packet, label="PR15 FL3 remediation authority packet")
    common.ensure_pass(authority_receipt, label="PR15 FL3 remediation authority receipt")
    common.ensure_pass(blocker_ledger, label="PR15 FL3 remediation blocker ledger")
    common.ensure_pass(tranche2_receipt, label="tranche T02 receipt")

    if str(tranche2_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_POST_F_PR15_FL3_ARCHIVE_ASSUMPTION_DECONTAMINATION_PACKET":
        raise RuntimeError("FAIL_CLOSED: tranche T02 receipt no longer authorizes tranche T03 packet")

    blockers = blocker_ledger.get("blockers")
    if not isinstance(blockers, list) or len(blockers) < 3 or blockers[2].get("tranche_id") != "T03":
        raise RuntimeError("FAIL_CLOSED: blocker ledger no longer binds tranche T03 as the third remediation blocker")

    archive_receipts_exists = _path_exists(root, ARCHIVE_RECEIPTS_REL)
    workflow_skips_missing_archive_receipts = _workflow_skips_missing_archive_receipts(common.resolve_path(root, CI_WORKFLOW_REL))
    secrets_test_requires_archive_receipts = _secrets_test_still_requires_archive_receipts(common.resolve_path(root, SECRETS_TEST_REL))
    secrets_test_skips_missing_archive_receipts = _secrets_test_skips_missing_archive_receipts(common.resolve_path(root, SECRETS_TEST_REL))
    validate_receipts_repo_test_requires_archive_dir = _validate_receipts_repo_test_still_requires_archive_dir(
        common.resolve_path(root, VALIDATE_RECEIPTS_TEST_REL)
    )
    validate_receipts_repo_test_skips_missing_archive_dir = _validate_receipts_repo_test_skips_missing_archive_dir(
        common.resolve_path(root, VALIDATE_RECEIPTS_TEST_REL)
    )

    outputs = build_outputs(
        branch_name=branch_name,
        branch_head=_git_rev_parse(root, "HEAD"),
        authority_packet=authority_packet,
        archive_receipts_exists=archive_receipts_exists,
        workflow_skips_missing_archive_receipts=workflow_skips_missing_archive_receipts,
        secrets_test_requires_archive_receipts=secrets_test_requires_archive_receipts,
        secrets_test_skips_missing_archive_receipts=secrets_test_skips_missing_archive_receipts,
        validate_receipts_repo_test_requires_archive_dir=validate_receipts_repo_test_requires_archive_dir,
        validate_receipts_repo_test_skips_missing_archive_dir=validate_receipts_repo_test_skips_missing_archive_dir,
    )
    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    return {
        "lane_outcome": str(outputs["packet"]["lane_outcome"]),
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": str(outputs["receipt"]["next_lawful_move"]),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Bind tranche T03 for PR15 FL3 archive-assumption decontamination.")
    parser.add_argument("--authority-packet", default=AUTHORITY_PACKET_PATH)
    parser.add_argument("--authority-receipt", default=AUTHORITY_RECEIPT_PATH)
    parser.add_argument("--blocker-ledger", default=BLOCKER_LEDGER_PATH)
    parser.add_argument("--tranche2-receipt", default=T02_RECEIPT_PATH)
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        authority_packet_path=common.resolve_path(root, args.authority_packet),
        authority_receipt_path=common.resolve_path(root, args.authority_receipt),
        blocker_ledger_path=common.resolve_path(root, args.blocker_ledger),
        tranche2_receipt_path=common.resolve_path(root, args.tranche2_receipt),
    )
    print(result["lane_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
