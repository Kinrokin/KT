from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z
from tools.audit_intelligence.run_audit_intelligence import repo_root_from as _audit_intel_repo_root_from
from tools.verification.fl3_canonical import repo_root_from as _shared_repo_root_from


OUTPUT_PACKET = "cohort0_post_f_pr15_fl3_active_tree_asset_expectation_drift_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_pr15_fl3_active_tree_asset_expectation_drift_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_PR15_FL3_ACTIVE_TREE_ASSET_EXPECTATION_DRIFT_REPORT.md"

REQUIRED_BRANCH = "authoritative/post-f-pr15-fl3-remediation"
EXECUTION_STATUS = "PASS__POST_F_PR15_FL3_ACTIVE_TREE_ASSET_EXPECTATION_DRIFT_BOUND"
OUTCOME_DRIFT = (
    "POST_F_PR15_FL3_ACTIVE_TREE_ASSET_EXPECTATION_DRIFT_DEFINED__WEAK_ROOT_SELECTION_COLLIDES_WITH_NESTED_CLEANROOM"
)
OUTCOME_CLEARED = "POST_F_PR15_FL3_ACTIVE_TREE_ASSET_EXPECTATION_DRIFT_RESOLVED__TRANCHE2_CLEARED"
NEXT_MOVE_DRIFT = "EXECUTE_POST_F_PR15_FL3_ACTIVE_TREE_ASSET_EXPECTATION_DRIFT_REMEDIATION"
NEXT_MOVE_CLEARED = "AUTHOR_POST_F_PR15_FL3_ARCHIVE_ASSUMPTION_DECONTAMINATION_PACKET"

AUTHORITY_PACKET_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_remediation_authority_packet.json"
AUTHORITY_RECEIPT_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_remediation_authority_receipt.json"
BLOCKER_LEDGER_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_remediation_blocker_ledger.json"
T01_RECEIPT_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_receipt.json"

CANONICAL_RUNTIME_PATHS_REL = "KT_PROD_CLEANROOM/AUDITS/FL3_CANONICAL_RUNTIME_PATHS.json"
FAILURE_TAXONOMY_REL = "KT_PROD_CLEANROOM/AUDITS/FAILURE_TAXONOMY_FL3.json"
TEST_FILE_REL = "KT_PROD_CLEANROOM/tests/fl3/test_fl3_canonical_runtime_paths.py"
AUDIT_INTEL_TOOL_REL = "KT_PROD_CLEANROOM/tools/audit_intelligence/run_audit_intelligence.py"


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


def _weak_repo_root_from(path: Path) -> Path:
    p = path.resolve()
    for parent in [p] + list(p.parents):
        if (parent / "KT_PROD_CLEANROOM").is_dir():
            return parent
    raise RuntimeError("FAIL_CLOSED: weak repo-root probe could not find KT_PROD_CLEANROOM child")


def _canonical_repo_root_from(path: Path) -> Path:
    return _shared_repo_root_from(path)


def _audit_intelligence_repo_root_from(path: Path) -> Path:
    return _audit_intel_repo_root_from(path)


def _test_source_uses_bootstrap_root(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    return "_REPO_ROOT = bootstrap_syspath()" in text and "def _repo_root()" not in text


def _path_exists(root: Path, rel_path: str) -> bool:
    return common.resolve_path(root, rel_path).exists()


def _resolution_classes() -> List[Dict[str, str]]:
    return [
        {
            "class_id": "NORMALIZE_REPO_ROOT_SELECTION_PRECEDENCE",
            "summary": "Replace weak 'first parent with KT_PROD_CLEANROOM child' root detection with the cleanroom-source sentinel used by active-tree bootstrap helpers.",
        },
        {
            "class_id": "BIND_CANONICAL_ASSET_LOOKUP_TO_TRUE_REPO_ROOT",
            "summary": "Require FL3 asset readers to resolve canonical audit artifacts from the true repository root, not from the first nested cleanroom-like subtree.",
        },
        {
            "class_id": "QUARANTINE_NESTED_SUBTREE_FROM_ROOT_SELECTION",
            "summary": "Treat KT_PROD_CLEANROOM/KT_PROD_CLEANROOM as an implementation subtree that may exist on disk but may not satisfy repo-root selection on its own.",
        },
    ]


def build_outputs(
    *,
    branch_name: str,
    branch_head: str,
    authority_packet: Dict[str, Any],
    canonical_runtime_paths_exists: bool,
    failure_taxonomy_exists: bool,
    nested_cleanroom_subtree_exists: bool,
    weak_test_root: Path,
    weak_test_runtime_paths_target: Path,
    audit_intel_local_root: Path,
    audit_intel_failure_taxonomy_target: Path,
    shared_helper_root: Path,
    shared_helper_failure_taxonomy_target: Path,
    test_source_uses_bootstrap_root: bool,
) -> Dict[str, Dict[str, Any] | str]:
    drift_present = (
        canonical_runtime_paths_exists
        and failure_taxonomy_exists
        and nested_cleanroom_subtree_exists
        and not weak_test_runtime_paths_target.exists()
        and not audit_intel_failure_taxonomy_target.exists()
        and not shared_helper_failure_taxonomy_target.exists()
        and not test_source_uses_bootstrap_root
    )
    cleared = (
        canonical_runtime_paths_exists
        and failure_taxonomy_exists
        and test_source_uses_bootstrap_root
        and audit_intel_failure_taxonomy_target.exists()
        and shared_helper_failure_taxonomy_target.exists()
        and shared_helper_root == repo_root()
    )
    if drift_present == cleared:
        raise RuntimeError(
            "FAIL_CLOSED: tranche T02 state is neither the frozen drift condition nor the cleared post-remediation condition"
        )

    lane_outcome = OUTCOME_CLEARED if cleared else OUTCOME_DRIFT
    next_move = NEXT_MOVE_CLEARED if cleared else NEXT_MOVE_DRIFT
    tranche_state = "cleared" if cleared else "defined"
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_pr15_fl3_active_tree_asset_expectation_drift_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": lane_outcome,
        "claim_boundary": (
            "This packet binds tranche T02 only. It does not widen package truth, does not change truth-engine law, "
            "and does not authorize replay on main or archive promotion."
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
            "tranche_id": "T02",
            "tranche_name": "active_tree_asset_expectation_drift",
            "ordered_blocker_position": 2,
            "tranche_state": tranche_state,
            "drift_class": (
                "WEAK_ROOT_SELECTION_COLLIDES_WITH_NESTED_CLEANROOM_SUBTREE"
                if not cleared
                else "ACTIVE_TREE_ASSET_EXPECTATION_NORMALIZED"
            ),
        },
        "asset_truth": {
            "canonical_runtime_paths_rel": CANONICAL_RUNTIME_PATHS_REL,
            "canonical_runtime_paths_exists": canonical_runtime_paths_exists,
            "failure_taxonomy_rel": FAILURE_TAXONOMY_REL,
            "failure_taxonomy_exists": failure_taxonomy_exists,
            "nested_cleanroom_subtree_rel": "KT_PROD_CLEANROOM/KT_PROD_CLEANROOM",
            "nested_cleanroom_subtree_exists": nested_cleanroom_subtree_exists,
        },
        "drift_evidence": {
            "test_file": common.resolve_path(repo_root(), TEST_FILE_REL).as_posix(),
            "weak_test_root_probe": weak_test_root.as_posix(),
            "weak_test_runtime_paths_target": weak_test_runtime_paths_target.as_posix(),
            "weak_test_runtime_paths_target_exists": weak_test_runtime_paths_target.exists(),
            "test_source_uses_bootstrap_root": test_source_uses_bootstrap_root,
            "audit_intelligence_local_root_probe": audit_intel_local_root.as_posix(),
            "audit_intelligence_failure_taxonomy_target": audit_intel_failure_taxonomy_target.as_posix(),
            "audit_intelligence_failure_taxonomy_target_exists": audit_intel_failure_taxonomy_target.exists(),
            "shared_helper_root_probe": shared_helper_root.as_posix(),
            "shared_helper_failure_taxonomy_target": shared_helper_failure_taxonomy_target.as_posix(),
            "shared_helper_failure_taxonomy_target_exists": shared_helper_failure_taxonomy_target.exists(),
        },
        "precedence_rule": {
            "winning_source": "cleanroom_source_tree_sentinel",
            "winning_rule": (
                "Repo-root selection must prefer the cleanroom source-tree sentinel "
                "(KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/fl3_suite_registry_schema.py) "
                "over the weaker 'first parent containing KT_PROD_CLEANROOM' heuristic."
            ),
            "active_tree_decision_rule": (
                "If canonical assets exist at repo_root/KT_PROD_CLEANROOM/AUDITS but fail-close under "
                "repo_root/KT_PROD_CLEANROOM/KT_PROD_CLEANROOM/AUDITS, the defect class is root-selection drift, not missing assets."
            ),
            "resolution_decision_rule": (
                "Prefer normalizing root-selection precedence and canonical asset lookup over recreating or moving active-tree assets."
            ),
        },
        "allowed_resolution_classes": _resolution_classes(),
        "live_resolution_read": {
            "genuine_missing_asset": False,
            "root_selection_precedence_drift": not cleared,
            "nested_subtree_requires_quarantine_from_root_selection": nested_cleanroom_subtree_exists,
            "recommended_resolution_class": (
                "NORMALIZE_REPO_ROOT_SELECTION_PRECEDENCE"
                if not cleared
                else "ADVANCE_TO_T03_ARCHIVE_ASSUMPTION_DECONTAMINATION"
            ),
            "recommended_resolution_summary": (
                "Canonical FL3 assets exist on the active tree, but weak root selection misclassifies a nested cleanroom subtree as repo root."
                if not cleared
                else "Canonical FL3 asset lookup is now normalized to the true repo root and tranche T02 is cleared."
            ),
        },
        "exact_scope": {
            "shared_helper_scope": [
                "KT_PROD_CLEANROOM/tools/verification/fl3_canonical.py",
                "KT_PROD_CLEANROOM/tools/verification/fl3_validators.py",
                "KT_PROD_CLEANROOM/tools/audit_intelligence/run_audit_intelligence.py",
            ],
            "test_scope": [
                "KT_PROD_CLEANROOM/tests/fl3/_bootstrap.py",
                TEST_FILE_REL,
                "KT_PROD_CLEANROOM/tests/fl3/test_audit_intelligence.py",
            ],
            "asset_scope": [
                CANONICAL_RUNTIME_PATHS_REL,
                FAILURE_TAXONOMY_REL,
            ],
        },
        "do_not_widen_boundaries": authority_packet.get("do_not_widen_boundaries", []),
        "success_condition": {
            "active_tree_assets_remain_where_they_are": True,
            "repo_root_selection_normalized": True,
            "shared_helper_reads_canonical_assets_from_true_repo_root": True,
            "blocker_ledger_advances_to_tranche_3": True,
            "package_truth_unchanged": True,
            "truth_engine_law_unchanged": True,
            "main_replay_still_deferred": True,
        },
        "source_refs": common.output_ref_dict(
            remediation_authority_packet=common.resolve_path(repo_root(), AUTHORITY_PACKET_PATH),
            remediation_authority_receipt=common.resolve_path(repo_root(), AUTHORITY_RECEIPT_PATH),
            remediation_blocker_ledger=common.resolve_path(repo_root(), BLOCKER_LEDGER_PATH),
            tranche1_receipt=common.resolve_path(repo_root(), T01_RECEIPT_PATH),
            canonical_runtime_paths=common.resolve_path(repo_root(), CANONICAL_RUNTIME_PATHS_REL),
            failure_taxonomy=common.resolve_path(repo_root(), FAILURE_TAXONOMY_REL),
            fl3_canonical_helper=common.resolve_path(repo_root(), "KT_PROD_CLEANROOM/tools/verification/fl3_canonical.py"),
            audit_intelligence_runner=common.resolve_path(repo_root(), AUDIT_INTEL_TOOL_REL),
        ),
        "next_lawful_move": next_move,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_pr15_fl3_active_tree_asset_expectation_drift_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": lane_outcome,
        "tranche_id": "T02",
        "tranche_state": tranche_state,
        "canonical_runtime_paths_exists": canonical_runtime_paths_exists,
        "failure_taxonomy_exists": failure_taxonomy_exists,
        "weak_root_selection_misroutes_test_asset_lookup": not weak_test_runtime_paths_target.exists(),
        "audit_intelligence_local_root_misroutes_failure_taxonomy": not audit_intel_failure_taxonomy_target.exists(),
        "shared_helper_root_matches_repo_root": shared_helper_root == repo_root(),
        "next_lawful_move": next_move,
    }
    report = common.report_lines(
        "Cohort0 Post-F PR15 FL3 Active-Tree Asset Expectation Drift Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Lane outcome: `{lane_outcome}`",
            "- Tranche: `T02 active_tree_asset_expectation_drift`",
            f"- Tranche state: `{tranche_state}`",
            f"- Canonical runtime paths asset exists: `{canonical_runtime_paths_exists}`",
            f"- Failure taxonomy asset exists: `{failure_taxonomy_exists}`",
            f"- Nested cleanroom subtree exists: `{nested_cleanroom_subtree_exists}`",
            f"- Weak test asset target exists: `{weak_test_runtime_paths_target.exists()}`",
            f"- Audit-intelligence taxonomy target exists: `{audit_intel_failure_taxonomy_target.exists()}`",
            f"- Shared helper root matches repo root: `{shared_helper_root == repo_root()}`",
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
    tranche1_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: tranche T02 must run on {REQUIRED_BRANCH}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: tranche T02 requires a clean tracked worktree")

    authority_packet = common.load_json_required(root, authority_packet_path, label="PR15 FL3 remediation authority packet")
    authority_receipt = common.load_json_required(root, authority_receipt_path, label="PR15 FL3 remediation authority receipt")
    blocker_ledger = common.load_json_required(root, blocker_ledger_path, label="PR15 FL3 remediation blocker ledger")
    tranche1_receipt = common.load_json_required(root, tranche1_receipt_path, label="tranche T01 receipt")
    common.ensure_pass(authority_packet, label="PR15 FL3 remediation authority packet")
    common.ensure_pass(authority_receipt, label="PR15 FL3 remediation authority receipt")
    common.ensure_pass(blocker_ledger, label="PR15 FL3 remediation blocker ledger")
    common.ensure_pass(tranche1_receipt, label="tranche T01 receipt")

    if str(tranche1_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_POST_F_PR15_FL3_ACTIVE_TREE_ASSET_EXPECTATION_DRIFT_PACKET":
        raise RuntimeError("FAIL_CLOSED: tranche T01 receipt no longer authorizes tranche T02 packet")

    blockers = blocker_ledger.get("blockers")
    if not isinstance(blockers, list) or len(blockers) < 2 or blockers[1].get("tranche_id") != "T02":
        raise RuntimeError("FAIL_CLOSED: blocker ledger no longer binds tranche T02 as the second remediation blocker")

    canonical_runtime_paths_exists = _path_exists(root, CANONICAL_RUNTIME_PATHS_REL)
    failure_taxonomy_exists = _path_exists(root, FAILURE_TAXONOMY_REL)
    nested_cleanroom_subtree_exists = _path_exists(root, "KT_PROD_CLEANROOM/KT_PROD_CLEANROOM")
    test_file = common.resolve_path(root, TEST_FILE_REL)
    audit_intel_tool = common.resolve_path(root, AUDIT_INTEL_TOOL_REL)

    weak_test_root = _weak_repo_root_from(test_file)
    weak_test_runtime_paths_target = (
        weak_test_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FL3_CANONICAL_RUNTIME_PATHS.json"
    ).resolve()
    audit_intel_local_root = _audit_intelligence_repo_root_from(audit_intel_tool)
    audit_intel_failure_taxonomy_target = (
        audit_intel_local_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FAILURE_TAXONOMY_FL3.json"
    ).resolve()
    shared_helper_root = _canonical_repo_root_from(audit_intel_tool)
    shared_helper_failure_taxonomy_target = (
        shared_helper_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FAILURE_TAXONOMY_FL3.json"
    ).resolve()
    test_source_uses_bootstrap_root = _test_source_uses_bootstrap_root(test_file)

    outputs = build_outputs(
        branch_name=branch_name,
        branch_head=_git_rev_parse(root, "HEAD"),
        authority_packet=authority_packet,
        canonical_runtime_paths_exists=canonical_runtime_paths_exists,
        failure_taxonomy_exists=failure_taxonomy_exists,
        nested_cleanroom_subtree_exists=nested_cleanroom_subtree_exists,
        weak_test_root=weak_test_root,
        weak_test_runtime_paths_target=weak_test_runtime_paths_target,
        audit_intel_local_root=audit_intel_local_root,
        audit_intel_failure_taxonomy_target=audit_intel_failure_taxonomy_target,
        shared_helper_root=shared_helper_root,
        shared_helper_failure_taxonomy_target=shared_helper_failure_taxonomy_target,
        test_source_uses_bootstrap_root=test_source_uses_bootstrap_root,
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
    parser = common.main_parser("Bind tranche T02 for PR15 FL3 active-tree asset expectation drift.")
    parser.add_argument("--authority-packet", default=AUTHORITY_PACKET_PATH)
    parser.add_argument("--authority-receipt", default=AUTHORITY_RECEIPT_PATH)
    parser.add_argument("--blocker-ledger", default=BLOCKER_LEDGER_PATH)
    parser.add_argument("--tranche1-receipt", default=T01_RECEIPT_PATH)
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        authority_packet_path=common.resolve_path(root, args.authority_packet),
        authority_receipt_path=common.resolve_path(root, args.authority_receipt),
        blocker_ledger_path=common.resolve_path(root, args.blocker_ledger),
        tranche1_receipt_path=common.resolve_path(root, args.tranche1_receipt),
    )
    print(result["lane_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
