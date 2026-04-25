from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_truth_engine_contradiction_validator_authority_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_truth_engine_contradiction_validator_authority_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRUTH_ENGINE_CONTRADICTION_VALIDATOR_AUTHORITY_REPORT.md"

REQUIRED_BRANCH = "authoritative/post-f-truth-engine"
EXECUTION_STATUS = "PASS__POST_F_TRUTH_ENGINE_AUTHORITATIVE_LANE_BOUND"
LANE_OUTCOME = "POST_F_TRUTH_ENGINE_CONTRADICTION_VALIDATOR_LANE_OPEN__AUTHORITATIVE_ONLY"
NEXT_MOVE = "AUTHOR_POST_F_TRUTH_ENGINE_CONTRADICTION_VALIDATOR_CONTRACT_PACKET"


def _current_branch_name(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    branch = result.stdout.strip()
    return branch or "UNKNOWN_BRANCH"


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


def build_outputs(
    *,
    branch_name: str,
    branch_head: str,
    main_head: str,
    scaffold_packet: Dict[str, Any],
    post_merge_snapshot: Dict[str, Any],
    post_merge_receipt: Dict[str, Any],
) -> Dict[str, Dict[str, Any] | str]:
    first_lane = str(post_merge_receipt.get("first_post_merge_authoritative_lane", "")).strip()
    retained_prep = list(post_merge_snapshot.get("retained_non_authoritative_prep_lanes", []))
    package_split = dict(post_merge_snapshot.get("package_promotion_split", {}))

    packet = {
        "schema_id": "kt.operator.cohort0_post_f_truth_engine_contradiction_validator_authority_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": LANE_OUTCOME,
        "claim_boundary": (
            "This packet opens only the truth-engine/contradiction-validator lane as the first post-merge authoritative lane. "
            "It does not promote package-internal artifacts, and it does not promote the other prep lanes."
        ),
        "authority_header": {
            "canonical_authority_branch": "main",
            "authoritative_lane_branch": branch_name,
            "authoritative_lane_branch_head": branch_head,
            "canonical_parent_main_head": main_head,
            "track03_repo_authority_now_canonical": bool(post_merge_receipt.get("track03_repo_authority_now_canonical", False)),
            "package_promotion_still_deferred": bool(post_merge_receipt.get("package_promotion_still_deferred", False)),
        },
        "lane_transition": {
            "promoted_lane_id": first_lane,
            "promoted_from_prep_packet_ref": common.resolve_path(
                repo_root(), "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_truth_engine_scope_packet.json"
            ).as_posix(),
            "promotion_basis_ref": common.resolve_path(
                repo_root(), "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_closeout_receipt.json"
            ).as_posix(),
            "promoted_after_canonical_merge": True,
            "retained_non_authoritative_prep_lanes": retained_prep,
        },
        "authoritative_scope": {
            "posture_enum": list(scaffold_packet.get("posture_enum", [])),
            "truth_engine_contract": dict(scaffold_packet.get("truth_engine_contract", {})),
            "contradiction_rules": list(scaffold_packet.get("contradiction_rules", [])),
            "source_precedence_table": list(scaffold_packet.get("source_precedence_table", [])),
            "stale_surface_exclusion_logic": dict(scaffold_packet.get("stale_surface_exclusion_logic", {})),
        },
        "preserved_boundaries": {
            "package_promotion_boundary": str(package_split.get("package_promotion_boundary", "")).strip(),
            "package_auto_promotion_candidate_count": int(package_split.get("auto_promotion_candidate_count", 0)),
            "review_approved_auto_skip_count": int(package_split.get("review_approved_auto_skip_count", 0)),
            "review_approved_out_of_scope_count": int(package_split.get("review_approved_out_of_scope_count", 0)),
            "other_prep_lanes_remain_non_authoritative": True,
        },
        "source_refs": common.output_ref_dict(
            post_merge_snapshot=common.resolve_path(
                repo_root(), "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_branch_snapshot.json"
            ),
            post_merge_receipt=common.resolve_path(
                repo_root(), "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_closeout_receipt.json"
            ),
            prep_truth_engine_scope=common.resolve_path(
                repo_root(), "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_truth_engine_scope_packet.json"
            ),
        ),
        "next_lawful_move": NEXT_MOVE,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_truth_engine_contradiction_validator_authority_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": LANE_OUTCOME,
        "authoritative_lane_branch": branch_name,
        "authoritative_lane_branch_head": branch_head,
        "canonical_parent_main_head": main_head,
        "package_promotion_still_deferred": bool(post_merge_receipt.get("package_promotion_still_deferred", False)),
        "next_lawful_move": NEXT_MOVE,
    }

    report = common.report_lines(
        "Cohort0 Post-F Truth Engine Contradiction Validator Authority Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Lane outcome: `{LANE_OUTCOME}`",
            f"- Authoritative lane branch: `{branch_name}`",
            f"- Canonical parent main head: `{main_head}`",
            f"- Promoted lane id: `{first_lane}`",
            "- Package promotion remains deferred.",
            f"- Retained non-authoritative prep lanes: `{len(retained_prep)}`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    post_merge_snapshot_path: Path,
    post_merge_receipt_path: Path,
    prep_truth_engine_scope_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: truth-engine authority packet must run on {REQUIRED_BRANCH}, got {branch_name}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: truth-engine authority packet requires a clean worktree")

    post_merge_snapshot = common.load_json_required(root, post_merge_snapshot_path, label="Track 03 post-merge branch snapshot")
    post_merge_receipt = common.load_json_required(root, post_merge_receipt_path, label="Track 03 post-merge closeout receipt")
    scaffold_packet = common.load_json_required(root, prep_truth_engine_scope_path, label="prep truth-engine scope packet")
    common.ensure_pass(post_merge_receipt, label="Track 03 post-merge closeout receipt")
    common.ensure_pass(scaffold_packet, label="prep truth-engine scope packet")

    if str(post_merge_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_POST_F_TRUTH_ENGINE_CONTRADICTION_VALIDATOR_AUTHORITY_PACKET":
        raise RuntimeError("FAIL_CLOSED: post-merge closeout did not authorize the truth-engine authority packet as next move")
    if not bool(post_merge_receipt.get("package_promotion_still_deferred", False)):
        raise RuntimeError("FAIL_CLOSED: package promotion deferral must still hold when opening the truth-engine lane")
    if str(post_merge_receipt.get("first_post_merge_authoritative_lane", "")).strip() != "truth_engine_contradiction_validator_scaffold":
        raise RuntimeError("FAIL_CLOSED: truth-engine is not the ranked first post-merge authoritative lane")
    if str(scaffold_packet.get("lane_status", "")).strip() != "AUTHORIZED__NON_AUTHORITATIVE_PREP_ONLY":
        raise RuntimeError("FAIL_CLOSED: prep truth-engine scope packet must still be prep-only before promotion")

    main_head = _git_rev_parse(root, "main")
    branch_head = _git_rev_parse(root, "HEAD")
    if _git_merge_base(root, "main", "HEAD") != main_head:
        raise RuntimeError("FAIL_CLOSED: truth-engine authoritative branch must be based on current main without divergence")

    outputs = build_outputs(
        branch_name=branch_name,
        branch_head=branch_head,
        main_head=main_head,
        scaffold_packet=scaffold_packet,
        post_merge_snapshot=post_merge_snapshot,
        post_merge_receipt=post_merge_receipt,
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
        "lane_outcome": LANE_OUTCOME,
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": NEXT_MOVE,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Promote the truth-engine scaffold into the first post-merge authoritative lane.")
    parser.add_argument(
        "--post-merge-snapshot",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_branch_snapshot.json",
    )
    parser.add_argument(
        "--post-merge-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_closeout_receipt.json",
    )
    parser.add_argument(
        "--prep-truth-engine-scope",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_truth_engine_scope_packet.json",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        post_merge_snapshot_path=common.resolve_path(root, args.post_merge_snapshot),
        post_merge_receipt_path=common.resolve_path(root, args.post_merge_receipt),
        prep_truth_engine_scope_path=common.resolve_path(root, args.prep_truth_engine_scope),
    )
    print(result["lane_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
