from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z
from tools.operator.trust_zone_validate import validate_trust_zones


OUTPUT_PACKET = "cohort0_post_merge_canonical_truth_boundary_readiness_audit_packet.json"
OUTPUT_RECEIPT = "cohort0_post_merge_canonical_truth_boundary_readiness_audit_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_MERGE_CANONICAL_TRUTH_BOUNDARY_READINESS_AUDIT_REPORT.md"

REQUIRED_BRANCH = "authoritative/trust-zone-boundary-purification"
EXECUTION_STATUS = "PASS__POST_MERGE_CANONICAL_TRUTH_BOUNDARY_READINESS_AUDIT_BOUND"
OUTCOME = "POST_MERGE_CANONICAL_TRUTH_AND_BOUNDARY_READINESS_CONFIRMED"
NEXT_MOVE = "PROMOTE_TRUST_ZONE_BOUNDARY_PURIFICATION_AS_NEXT_AUTHORITATIVE_LANE"
EXPECTED_TRUST_ZONE_PREP_OUTCOME = "POST_F_TRUST_ZONE_BOUNDARY_PURIFICATION_PREP_DEFINED__NON_AUTHORITATIVE"


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


def _git_is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.returncode == 0


def _expect_pass(payload: Dict[str, Any], *, label: str) -> Dict[str, Any]:
    common.ensure_pass(payload, label=label)
    return {
        "label": label,
        "schema_id": str(payload.get("schema_id", "")).strip(),
        "status": str(payload.get("status", "")).strip(),
        "execution_status": str(payload.get("execution_status", "")).strip(),
        "outcome": str(payload.get("outcome", "")).strip(),
        "next_lawful_move": str(payload.get("next_lawful_move", "")).strip(),
    }


def _require_list_contains(payload: Dict[str, Any], key: str, expected: str, *, label: str) -> None:
    values = payload.get(key, [])
    if not isinstance(values, list) or expected not in [str(item).strip() for item in values]:
        raise RuntimeError(f"FAIL_CLOSED: {label} must include {expected} in {key}")


def _local_quarantine_manifests(root: Path) -> List[str]:
    quarantine_root = root / "_tmp" / "local_untracked_quarantine"
    if not quarantine_root.is_dir():
        return []
    return sorted(path.relative_to(root).as_posix() for path in quarantine_root.glob("*/manifest.json") if path.is_file())


def build_outputs(
    *,
    branch_ref: str,
    head_ref: str,
    origin_main_ref: str,
    origin_main_is_ancestor: bool,
    track01_receipt: Dict[str, Any],
    track02_receipt: Dict[str, Any],
    track03_receipt: Dict[str, Any],
    track03_post_merge_receipt: Dict[str, Any],
    pr15_receipt: Dict[str, Any],
    pr15_blocker_ledger: Dict[str, Any],
    recompute_receipt: Dict[str, Any],
    contradiction_ledger: Dict[str, Any],
    posture_index: Dict[str, Any],
    handoff_receipt: Dict[str, Any],
    trust_zone_prep_receipt: Dict[str, Any],
    trust_zone_validation: Dict[str, Any],
    local_quarantine_manifest_refs: Sequence[str],
) -> Dict[str, Dict[str, Any] | str]:
    truth_surfaces = [
        _expect_pass(track01_receipt, label="Track 01 final summary receipt"),
        _expect_pass(track02_receipt, label="Track 02 final summary receipt"),
        _expect_pass(track03_receipt, label="Track 03 final summary receipt"),
        _expect_pass(track03_post_merge_receipt, label="Track 03 post-merge closeout receipt"),
        _expect_pass(pr15_receipt, label="PR15 FL3 full red-to-green receipt"),
        _expect_pass(handoff_receipt, label="truth-engine post-PR canonical handoff receipt"),
    ]

    packet = {
        "schema_id": "kt.operator.cohort0_post_merge_canonical_truth_boundary_readiness_audit_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "outcome": OUTCOME,
        "branch_ref": branch_ref,
        "audited_head_ref": head_ref,
        "audited_origin_main_ref": origin_main_ref,
        "claim_boundary": (
            "Post-merge canonical truth and boundary-readiness audit only. "
            "This packet does not perform package promotion and does not rewrite truth-engine law."
        ),
        "main_convergence": {
            "origin_main_is_ancestor_of_lane_head": origin_main_is_ancestor,
            "canonical_replay_branch_ref": str(recompute_receipt.get("branch_ref", "")).strip(),
            "canonical_replay_scope": str(recompute_receipt.get("recompute_scope", "")).strip(),
        },
        "aligned_truth_surfaces": truth_surfaces,
        "pr15_remediation_alignment": {
            "blocking_blocker_count": int(pr15_blocker_ledger.get("blocking_blocker_count", 0)),
            "full_fl3_suite_green": bool(dict(pr15_blocker_ledger.get("t05_validation", {})).get("full_fl3_suite_green", False)),
            "full_fl3_summary": str(dict(pr15_blocker_ledger.get("t05_validation", {})).get("full_fl3_summary", "")).strip(),
        },
        "truth_engine_alignment": {
            "recompute_status": str(recompute_receipt.get("status", "")).strip(),
            "recompute_scope": str(recompute_receipt.get("recompute_scope", "")).strip(),
            "recompute_branch_ref": str(recompute_receipt.get("branch_ref", "")).strip(),
            "blocking_contradiction_count": int(recompute_receipt.get("blocking_contradiction_count", 0)),
            "advisory_condition_count": int(recompute_receipt.get("advisory_condition_count", 0)),
            "ledger_blocking_contradiction_count": int(contradiction_ledger.get("blocking_contradiction_count", 0)),
            "ledger_advisory_contradiction_count": int(contradiction_ledger.get("advisory_contradiction_count", 0)),
            "handoff_execution_status": str(handoff_receipt.get("execution_status", "")).strip(),
        },
        "package_boundary": {
            "package_truth_posture": list(posture_index.get("package_truth_posture", [])),
            "package_promotion_remains_deferred": "PACKAGE_PROMOTION_DEFERRED" in list(posture_index.get("package_truth_posture", [])),
            "no_package_promotion_performed_by_this_audit": True,
        },
        "local_untracked_residue": {
            "local_quarantine_manifest_refs": list(local_quarantine_manifest_refs),
            "manifest_count": len(local_quarantine_manifest_refs),
            "authority_status": "LOCAL_ONLY_NON_AUTHORITATIVE_QUARANTINE",
        },
        "boundary_readiness": {
            "trust_zone_validation_status": str(trust_zone_validation.get("status", "")).strip(),
            "trust_zone_validation_check_count": len(list(trust_zone_validation.get("checks", []))),
            "trust_zone_validation_failure_count": len(list(trust_zone_validation.get("failures", []))),
            "prep_receipt_outcome": str(trust_zone_prep_receipt.get("outcome", "")).strip(),
            "prep_lane_was_non_authoritative_until_this_audit": True,
            "ready_to_promote_authoritative_lane": True,
        },
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_merge_canonical_truth_boundary_readiness_audit_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "outcome": OUTCOME,
        "aligned_truth_surface_count": len(truth_surfaces),
        "blocking_contradiction_count": int(recompute_receipt.get("blocking_contradiction_count", 0)),
        "advisory_contradiction_count": int(contradiction_ledger.get("advisory_contradiction_count", 0)),
        "package_promotion_remains_deferred": packet["package_boundary"]["package_promotion_remains_deferred"],
        "trust_zone_validation_status": packet["boundary_readiness"]["trust_zone_validation_status"],
        "next_lawful_move": NEXT_MOVE,
    }
    report = common.report_lines(
        "Cohort0 Post-Merge Canonical Truth Boundary-Readiness Audit Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Outcome: `{OUTCOME}`",
            f"- Branch ref: `{branch_ref}`",
            f"- Audited origin/main: `{origin_main_ref}`",
            "- Track 01/02/03 and PR15 remediation truth surfaces: `aligned`",
            f"- Truth-engine recompute scope: `{packet['truth_engine_alignment']['recompute_scope']}`",
            f"- Blocking contradictions: `{receipt['blocking_contradiction_count']}`",
            f"- Advisory contradictions: `{receipt['advisory_contradiction_count']}`",
            f"- Package promotion deferred: `{receipt['package_promotion_remains_deferred']}`",
            f"- Trust-zone validation status: `{receipt['trust_zone_validation_status']}`",
            f"- Local quarantine manifest count: `{len(local_quarantine_manifest_refs)}`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    track01_receipt_path: Path,
    track02_receipt_path: Path,
    track03_receipt_path: Path,
    track03_post_merge_receipt_path: Path,
    pr15_receipt_path: Path,
    pr15_blocker_ledger_path: Path,
    recompute_receipt_path: Path,
    contradiction_ledger_path: Path,
    posture_index_path: Path,
    handoff_receipt_path: Path,
    trust_zone_prep_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: post-merge boundary-readiness audit must run on {REQUIRED_BRANCH}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: post-merge boundary-readiness audit requires a clean worktree")
    head_ref = _git_rev_parse(root, "HEAD")
    origin_main_ref = _git_rev_parse(root, "origin/main")
    origin_main_is_ancestor = _git_is_ancestor(root, "origin/main", "HEAD")
    if not origin_main_is_ancestor:
        raise RuntimeError("FAIL_CLOSED: origin/main must be an ancestor of the trust-zone lane head")

    track01_receipt = common.load_json_required(root, track01_receipt_path, label="Track 01 final summary receipt")
    track02_receipt = common.load_json_required(root, track02_receipt_path, label="Track 02 final summary receipt")
    track03_receipt = common.load_json_required(root, track03_receipt_path, label="Track 03 final summary receipt")
    track03_post_merge_receipt = common.load_json_required(root, track03_post_merge_receipt_path, label="Track 03 post-merge closeout receipt")
    pr15_receipt = common.load_json_required(root, pr15_receipt_path, label="PR15 FL3 full red-to-green receipt")
    pr15_blocker_ledger = common.load_json_required(root, pr15_blocker_ledger_path, label="PR15 FL3 full red-to-green blocker ledger")
    recompute_receipt = common.load_json_required(root, recompute_receipt_path, label="truth-engine recompute receipt")
    contradiction_ledger = common.load_json_required(root, contradiction_ledger_path, label="truth-engine contradiction ledger")
    posture_index = common.load_json_required(root, posture_index_path, label="truth-engine posture index")
    handoff_receipt = common.load_json_required(root, handoff_receipt_path, label="truth-engine post-PR canonical handoff receipt")
    trust_zone_prep_receipt = common.load_json_required(root, trust_zone_prep_receipt_path, label="trust-zone prep receipt")
    trust_zone_validation = validate_trust_zones(root=root)

    common.ensure_pass(pr15_blocker_ledger, label="PR15 FL3 full red-to-green blocker ledger")
    if int(pr15_blocker_ledger.get("blocking_blocker_count", 0)) != 0:
        raise RuntimeError("FAIL_CLOSED: PR15 blocker ledger must have zero blocking blockers")
    if not bool(dict(pr15_blocker_ledger.get("t05_validation", {})).get("full_fl3_suite_green", False)):
        raise RuntimeError("FAIL_CLOSED: PR15 blocker ledger must preserve full FL3 suite green status")
    common.ensure_pass(recompute_receipt, label="truth-engine recompute receipt")
    if str(recompute_receipt.get("branch_ref", "")).strip() != "main":
        raise RuntimeError("FAIL_CLOSED: truth-engine recompute receipt must be main-bound")
    if str(recompute_receipt.get("recompute_scope", "")).strip() != "CANONICAL_MAIN_REPLAY_CONVERGED":
        raise RuntimeError("FAIL_CLOSED: truth-engine recompute receipt must be canonical main replay converged")
    recompute_blocking_count = int(recompute_receipt.get("blocking_contradiction_count", 0))
    recompute_advisory_count = int(recompute_receipt.get("advisory_condition_count", 0))
    if recompute_blocking_count != 0 or recompute_advisory_count != 0:
        raise RuntimeError("FAIL_CLOSED: truth-engine recompute receipt must report zero blocking contradictions and zero advisory conditions")
    common.ensure_pass(contradiction_ledger, label="truth-engine contradiction ledger")
    ledger_blocking_count = int(contradiction_ledger.get("blocking_contradiction_count", 0))
    ledger_advisory_count = int(contradiction_ledger.get("advisory_contradiction_count", 0))
    if recompute_blocking_count != ledger_blocking_count or recompute_advisory_count != ledger_advisory_count:
        raise RuntimeError("FAIL_CLOSED: truth-engine recompute receipt contradiction summary must match contradiction ledger counts")
    if ledger_blocking_count != 0 or ledger_advisory_count != 0:
        raise RuntimeError("FAIL_CLOSED: truth-engine contradiction ledger must have zero blocking and zero advisory contradictions")
    common.ensure_pass(handoff_receipt, label="truth-engine post-PR canonical handoff receipt")
    if str(handoff_receipt.get("next_lawful_move", "")).strip() != NEXT_MOVE:
        raise RuntimeError("FAIL_CLOSED: canonical handoff must point to trust-zone boundary purification")
    _require_list_contains(posture_index, "package_truth_posture", "PACKAGE_PROMOTION_DEFERRED", label="truth-engine posture index")
    _require_list_contains(posture_index, "merge_truth_posture", "TRACK03_REPO_AUTHORITY_CANONICAL_ON_MAIN", label="truth-engine posture index")
    _require_list_contains(posture_index, "theorem_truth_posture", "THEOREM_POSTURE_CANONICAL_ON_MAIN", label="truth-engine posture index")
    _require_list_contains(posture_index, "product_truth_posture", "PRODUCT_POSTURE_STILL_BOUNDED", label="truth-engine posture index")
    common.ensure_pass(trust_zone_prep_receipt, label="trust-zone prep receipt")
    if str(trust_zone_prep_receipt.get("outcome", "")).strip() != EXPECTED_TRUST_ZONE_PREP_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: trust-zone prep receipt must preserve the expected non-authoritative prep outcome")
    if str(trust_zone_validation.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: trust-zone validation must pass before promotion")

    outputs = build_outputs(
        branch_ref=branch_name,
        head_ref=head_ref,
        origin_main_ref=origin_main_ref,
        origin_main_is_ancestor=origin_main_is_ancestor,
        track01_receipt=track01_receipt,
        track02_receipt=track02_receipt,
        track03_receipt=track03_receipt,
        track03_post_merge_receipt=track03_post_merge_receipt,
        pr15_receipt=pr15_receipt,
        pr15_blocker_ledger=pr15_blocker_ledger,
        recompute_receipt=recompute_receipt,
        contradiction_ledger=contradiction_ledger,
        posture_index=posture_index,
        handoff_receipt=handoff_receipt,
        trust_zone_prep_receipt=trust_zone_prep_receipt,
        trust_zone_validation=trust_zone_validation,
        local_quarantine_manifest_refs=_local_quarantine_manifests(root),
    )
    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    return {"outcome": OUTCOME, "next_lawful_move": NEXT_MOVE}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Audit post-merge canonical truth and boundary-readiness before trust-zone promotion.")
    parser.add_argument("--track01-receipt", default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_01_final_summary_receipt.json")
    parser.add_argument("--track02-receipt", default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_final_summary_receipt.json")
    parser.add_argument("--track03-receipt", default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_final_summary_receipt.json")
    parser.add_argument("--track03-post-merge-receipt", default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_closeout_receipt.json")
    parser.add_argument("--pr15-receipt", default="KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_full_red_to_green_receipt.json")
    parser.add_argument("--pr15-blocker-ledger", default="KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_full_red_to_green_blocker_ledger.json")
    parser.add_argument("--recompute-receipt", default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_recompute_receipt.json")
    parser.add_argument("--contradiction-ledger", default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_ledger.json")
    parser.add_argument("--posture-index", default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_posture_index.json")
    parser.add_argument("--handoff-receipt", default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_post_pr_canonical_handoff_receipt.json")
    parser.add_argument("--trust-zone-prep-receipt", default="KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_trust_zone_boundary_purification_receipt.json")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        track01_receipt_path=common.resolve_path(root, args.track01_receipt),
        track02_receipt_path=common.resolve_path(root, args.track02_receipt),
        track03_receipt_path=common.resolve_path(root, args.track03_receipt),
        track03_post_merge_receipt_path=common.resolve_path(root, args.track03_post_merge_receipt),
        pr15_receipt_path=common.resolve_path(root, args.pr15_receipt),
        pr15_blocker_ledger_path=common.resolve_path(root, args.pr15_blocker_ledger),
        recompute_receipt_path=common.resolve_path(root, args.recompute_receipt),
        contradiction_ledger_path=common.resolve_path(root, args.contradiction_ledger),
        posture_index_path=common.resolve_path(root, args.posture_index),
        handoff_receipt_path=common.resolve_path(root, args.handoff_receipt),
        trust_zone_prep_receipt_path=common.resolve_path(root, args.trust_zone_prep_receipt),
    )
    print(result["outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
