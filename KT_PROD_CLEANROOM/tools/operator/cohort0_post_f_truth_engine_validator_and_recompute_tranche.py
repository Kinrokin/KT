from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


OUTPUT_AUTHORITY_GRAPH = "cohort0_post_f_truth_engine_authority_graph.json"
OUTPUT_POSTURE_INDEX = "cohort0_post_f_truth_engine_posture_index.json"
OUTPUT_CONTRADICTION_LEDGER = "cohort0_post_f_truth_engine_contradiction_ledger.json"
OUTPUT_STALE_QUARANTINE = "cohort0_post_f_truth_engine_stale_source_quarantine_list.json"
OUTPUT_RECOMPUTE_RECEIPT = "cohort0_post_f_truth_engine_recompute_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRUTH_ENGINE_FIRST_RECOMPUTE_REPORT.md"
CANONICAL_REPLAY_OUTPUT_REPORT = "COHORT0_POST_F_TRUTH_ENGINE_CANONICAL_MAIN_REPLAY_REPORT.md"

REQUIRED_BRANCH = "authoritative/post-f-truth-engine"
CANONICAL_REPLAY_BRANCH = "main"
EXECUTION_STATUS = "PASS__POST_F_TRUTH_ENGINE_VALIDATOR_AND_FIRST_RECOMPUTE_BOUND"
OUTCOME = "POST_F_TRUTH_ENGINE_FIRST_RECOMPUTE_COMPLETE__BRANCH_AUTHORITATIVE_REMOTE_MAIN_PENDING"
NEXT_MOVE = "RERUN_POST_F_TRUTH_ENGINE_RECOMPUTE_ON_MAIN_AFTER_PR15_MERGE"
CANONICAL_REPLAY_EXECUTION_STATUS = "PASS__POST_F_TRUTH_ENGINE_CANONICAL_MAIN_RECOMPUTE_BOUND"
CANONICAL_REPLAY_OUTCOME = "POST_F_TRUTH_ENGINE_RECOMPUTE_COMPLETE__CANONICAL_MAIN_CONVERGED"
CANONICAL_REPLAY_NEXT_MOVE = "PROMOTE_TRUST_ZONE_BOUNDARY_PURIFICATION_AS_NEXT_AUTHORITATIVE_LANE"


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


def _remote_main_divergence(root: Path) -> Dict[str, Any]:
    try:
        result = subprocess.run(
            ["git", "rev-list", "--left-right", "--count", "origin/main...main"],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
    except subprocess.CalledProcessError:
        return {"remote_ref_present": False, "remote_ahead_of_local_main": 0, "local_main_ahead_of_remote": 0}
    parts = [part.strip() for part in result.stdout.strip().split() if part.strip()]
    if len(parts) != 2:
        return {"remote_ref_present": False, "remote_ahead_of_local_main": 0, "local_main_ahead_of_remote": 0}
    return {
        "remote_ref_present": True,
        "remote_ahead_of_local_main": int(parts[0]),
        "local_main_ahead_of_remote": int(parts[1]),
    }


def _validate_against_schema(payload: Dict[str, Any], schema: Dict[str, Any], *, label: str) -> None:
    missing = [field for field in schema.get("required_fields", []) if field not in payload]
    if missing:
        raise RuntimeError(f"FAIL_CLOSED: {label} missing required fields: {', '.join(missing)}")


def _derive_posture_index(*, branch_law: Dict[str, Any], product_truth: Dict[str, Any], post_merge_receipt: Dict[str, Any], remote_divergence: Dict[str, Any]) -> Dict[str, Any]:
    theorem_truth = []
    canonical_branch_status = dict(branch_law.get("canonical_live_branch_status", {}))
    if bool(canonical_branch_status.get("gate_d_cleared_on_successor_line", False)):
        theorem_truth.append("GATE_D_CLEARED__SUCCESSOR_LINE")
    if bool(canonical_branch_status.get("gate_e_open", False)):
        theorem_truth.append("GATE_E_OPEN__SUCCESSOR_LINE")
    if bool(post_merge_receipt.get("track03_repo_authority_now_canonical", False)):
        theorem_truth.append("THEOREM_POSTURE_CANONICAL_ON_MAIN")

    product_truth_posture = []
    canonical_product = dict(product_truth.get("canonical_live_product_status", {}))
    if bool(canonical_product.get("gate_f_narrow_wedge_confirmed", False)):
        product_truth_posture.append("GATE_F_ONE_NARROW_WEDGE_CONFIRMED__LOCAL_VERIFIER_MODE_ONLY")
    if bool(post_merge_receipt.get("track03_repo_authority_now_canonical", False)):
        product_truth_posture.append("PRODUCT_POSTURE_CANONICAL_ON_MAIN")
    if not bool(canonical_product.get("gate_f_open", False)):
        product_truth_posture.append("PRODUCT_POSTURE_STILL_BOUNDED")

    merge_truth = ["TRACK03_REPO_AUTHORITY_CANONICAL_ON_MAIN"]
    if int(remote_divergence.get("local_main_ahead_of_remote", 0)) > 0:
        merge_truth.append("TRACK03_PROTECTED_PR_PENDING")

    package_truth = ["PACKAGE_PROMOTION_DEFERRED"]

    return {
        "schema_id": "kt.operator.cohort0_post_f_truth_engine_posture_index.v1",
        "generated_utc": utc_now_iso_z(),
        "theorem_truth_posture": theorem_truth,
        "product_truth_posture": product_truth_posture,
        "merge_truth_posture": merge_truth,
        "package_truth_posture": package_truth,
        "winning_source_refs": {
            "theorem_truth": branch_law.get("authoritative_live_surfaces", {}).get("successor_master_orchestrator_receipt_ref", ""),
            "product_truth": product_truth.get("authoritative_live_product_surfaces", {}).get("gate_f_review_receipt", ""),
            "merge_truth": common.resolve_path(repo_root(), "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_closeout_receipt.json").as_posix(),
            "package_truth": common.resolve_path(repo_root(), "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_branch_snapshot.json").as_posix(),
        },
    }


def _build_authority_graph(*, contract_packet: Dict[str, Any], branch_law: Dict[str, Any], product_truth: Dict[str, Any], branch_ref: str) -> Dict[str, Any]:
    winning = [
        {
            "source_class_id": "canonical_post_merge_repo_authority",
            "rank": 1,
            "ref": common.resolve_path(repo_root(), "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_closeout_receipt.json").as_posix(),
            "drives_live_truth": True,
        },
        {
            "source_class_id": "canonical_theorem_and_product_truth",
            "rank": 2,
            "ref": branch_law.get("authoritative_live_surfaces", {}).get("successor_master_orchestrator_receipt_ref", ""),
            "drives_live_truth": True,
        },
        {
            "source_class_id": "canonical_theorem_and_product_truth",
            "rank": 2,
            "ref": product_truth.get("authoritative_live_product_surfaces", {}).get("gate_f_review_receipt", ""),
            "drives_live_truth": True,
        },
        {
            "source_class_id": "authoritative_successor_lane_packets",
            "rank": 3,
            "ref": common.resolve_path(repo_root(), "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_authority_receipt.json").as_posix(),
            "drives_live_truth": True,
        },
    ]
    rejected = [
        {
            "source_class_id": "deferred_package_and_non_authoritative_prep",
            "ref": common.resolve_path(
                repo_root(), "KT_PROD_CLEANROOM/runs/post_f_track_03/run-20260424-152430-bb49da8/staging/scripts/stage_and_promote.sh"
            ).as_posix(),
            "rejection_reason": "Deferred package artifact cannot drive repo truth until a later package-promotion court.",
            "contradiction_class_id": "package_vs_repo",
        }
    ]
    for ref in contract_packet.get("exclusion_law", {}).get("retained_non_authoritative_prep_lanes", []):
        rejected.append(
            {
                "source_class_id": "deferred_package_and_non_authoritative_prep",
                "ref": ref,
                "rejection_reason": "Prep lane remains non-authoritative after truth-engine promotion.",
                "contradiction_class_id": "prep_lane_overreach",
            }
        )

    edges = [
        {
            "from_ref": winning[0]["ref"],
            "to_ref": winning[1]["ref"],
            "edge_type": "outranks",
            "justification": "Canonical post-merge repo authority gates theorem posture consumers.",
        },
        {
            "from_ref": winning[0]["ref"],
            "to_ref": winning[2]["ref"],
            "edge_type": "outranks",
            "justification": "Canonical post-merge repo authority gates product posture consumers.",
        },
        {
            "from_ref": winning[0]["ref"],
            "to_ref": winning[3]["ref"],
            "edge_type": "permits_extension_only",
            "justification": "Authoritative successor lane extends derivation law without weakening canonical truth.",
        },
    ]
    return {
        "schema_id": "kt.operator.cohort0_post_f_truth_engine_authority_graph.v1",
        "generated_utc": utc_now_iso_z(),
        "branch_ref": branch_ref,
        "winning_authority_sources": winning,
        "rejected_conflicting_sources": rejected,
        "precedence_edges": edges,
    }


def _build_stale_quarantine(contract_packet: Dict[str, Any]) -> Dict[str, Any]:
    root = repo_root()
    candidates = [
        {
            "ref": common.resolve_path(
                root, "KT_PROD_CLEANROOM/runs/post_f_track_03/run-20260424-152430-bb49da8/staging/scripts/stage_and_promote.sh"
            ).as_posix(),
            "reason": "Deferred package artifact remains outside repo truth until package-promotion court.",
            "source_class_id": "deferred_package_and_non_authoritative_prep",
            "replacement_ref": common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_closeout_receipt.json").as_posix(),
        }
    ]
    for lane_id in contract_packet.get("exclusion_law", {}).get("retained_non_authoritative_prep_lanes", []):
        candidates.append(
            {
                "ref": lane_id,
                "reason": "Prep lane retained as non-authoritative after truth-engine promotion.",
                "source_class_id": "deferred_package_and_non_authoritative_prep",
                "replacement_ref": common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_authority_receipt.json").as_posix(),
            }
        )
    candidates = sorted(candidates, key=lambda row: row["ref"])
    return {
        "schema_id": "kt.operator.cohort0_post_f_truth_engine_stale_source_quarantine_list.v1",
        "generated_utc": utc_now_iso_z(),
        "quarantine_candidate_count": len(candidates),
        "quarantine_candidates": candidates,
    }


def _build_contradiction_ledger(*, remote_divergence: Dict[str, Any]) -> Dict[str, Any]:
    contradictions: List[Dict[str, Any]] = []
    if int(remote_divergence.get("remote_ahead_of_local_main", 0)) > 0:
        contradictions.append(
            {
                "contradiction_id": "branch_local_vs_canonical::origin_main_ahead",
                "class_id": "branch_local_vs_canonical",
                "severity": "blocking_high",
                "triggered_by_refs": ["origin/main", "main"],
                "governing_precedence_class_id": "canonical_post_merge_repo_authority",
                "halt_behavior": "HALT_RECOMPUTE",
                "resolution_path": "Refresh local main from origin/main and rerun authority promotion from the refreshed canonical base.",
            }
        )
    blocking = [row for row in contradictions if row["severity"].startswith("blocking")]
    advisory = []
    if int(remote_divergence.get("local_main_ahead_of_remote", 0)) > 0:
        advisory.append(
            {
                "contradiction_id": "merge_truth::remote_main_pending_pr15",
                "class_id": "branch_local_vs_canonical",
                "severity": "advisory_low",
                "triggered_by_refs": ["main", "origin/main"],
                "governing_precedence_class_id": "canonical_post_merge_repo_authority",
                "halt_behavior": "WARN_ONLY",
                "resolution_path": "Rerun identical recompute on main after PR #15 lands.",
            }
        )
    contradictions.extend(advisory)
    return {
        "schema_id": "kt.operator.cohort0_post_f_truth_engine_contradiction_ledger.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not blocking else "FAIL",
        "blocking_contradiction_count": len(blocking),
        "advisory_contradiction_count": len(advisory),
        "contradictions": contradictions,
    }


def _build_recompute_receipt(
    *,
    authority_graph: Dict[str, Any],
    posture_index: Dict[str, Any],
    contradiction_ledger: Dict[str, Any],
    stale_quarantine: Dict[str, Any],
    remote_divergence: Dict[str, Any],
    branch_ref: str,
    next_lawful_move: str,
) -> Dict[str, Any]:
    root = repo_root()
    advisory_conditions = []
    if int(remote_divergence.get("local_main_ahead_of_remote", 0)) > 0:
        advisory_conditions.append("remote_main_pending_pr15_merge")
    canonical_mode = branch_ref == CANONICAL_REPLAY_BRANCH
    recompute_scope = "CANONICAL_MAIN_REPLAY_CONVERGED" if canonical_mode else "AUTHORITATIVE_BRANCH_AND_CANONICAL_MAIN_IN_SYNC"
    if advisory_conditions:
        recompute_scope = "AUTHORITATIVE_BRANCH_ONLY__REMOTE_MAIN_PENDING"
    return {
        "schema_id": "kt.operator.cohort0_post_f_truth_engine_recompute_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if int(contradiction_ledger.get("blocking_contradiction_count", 0)) == 0 else "FAIL",
        "branch_ref": branch_ref,
        "derived_from_contract_id": "kt.operator.cohort0_post_f_truth_engine_contradiction_validator_contract_packet.v1",
        "authority_graph_ref": common.resolve_path(root, f"KT_PROD_CLEANROOM/reports/{OUTPUT_AUTHORITY_GRAPH}").as_posix(),
        "posture_index_ref": common.resolve_path(root, f"KT_PROD_CLEANROOM/reports/{OUTPUT_POSTURE_INDEX}").as_posix(),
        "contradiction_ledger_ref": common.resolve_path(root, f"KT_PROD_CLEANROOM/reports/{OUTPUT_CONTRADICTION_LEDGER}").as_posix(),
        "stale_source_quarantine_list_ref": common.resolve_path(root, f"KT_PROD_CLEANROOM/reports/{OUTPUT_STALE_QUARANTINE}").as_posix(),
        "blocking_contradiction_count": int(contradiction_ledger.get("blocking_contradiction_count", 0)),
        "advisory_condition_count": len(advisory_conditions),
        "recompute_scope": recompute_scope,
        "next_lawful_move": next_lawful_move,
    }


def build_outputs(
    *,
    schema_packet: Dict[str, Any],
    contract_packet: Dict[str, Any],
    branch_law: Dict[str, Any],
    product_truth: Dict[str, Any],
    post_merge_receipt: Dict[str, Any],
    remote_divergence: Dict[str, Any],
    branch_ref: str,
    execution_status: str,
    outcome: str,
    next_lawful_move: str,
) -> Dict[str, Dict[str, Any] | str]:
    authority_graph = _build_authority_graph(contract_packet=contract_packet, branch_law=branch_law, product_truth=product_truth, branch_ref=branch_ref)
    posture_index = _derive_posture_index(
        branch_law=branch_law,
        product_truth=product_truth,
        post_merge_receipt=post_merge_receipt,
        remote_divergence=remote_divergence,
    )
    contradiction_ledger = _build_contradiction_ledger(remote_divergence=remote_divergence)
    stale_quarantine = _build_stale_quarantine(contract_packet=contract_packet)
    recompute_receipt = _build_recompute_receipt(
        authority_graph=authority_graph,
        posture_index=posture_index,
        contradiction_ledger=contradiction_ledger,
        stale_quarantine=stale_quarantine,
        remote_divergence=remote_divergence,
        branch_ref=branch_ref,
        next_lawful_move=next_lawful_move,
    )

    schema_defs = dict(schema_packet.get("emission_surface_schemas", {}))
    _validate_against_schema(authority_graph, schema_defs["authority_graph"], label="authority graph")
    _validate_against_schema(posture_index, schema_defs["posture_index"], label="posture index")
    _validate_against_schema(contradiction_ledger, schema_defs["contradiction_ledger"], label="contradiction ledger")
    _validate_against_schema(stale_quarantine, schema_defs["stale_source_quarantine_list"], label="stale source quarantine list")
    _validate_against_schema(recompute_receipt, schema_defs["recompute_receipt"], label="recompute receipt")

    report_title = (
        "Cohort0 Post-F Truth Engine Canonical Main Replay Report"
        if branch_ref == CANONICAL_REPLAY_BRANCH
        else "Cohort0 Post-F Truth Engine First Recompute Report"
    )
    report = common.report_lines(
        report_title,
        [
            f"- Execution status: `{execution_status}`",
            f"- Outcome: `{outcome}`",
            f"- Branch ref: `{branch_ref}`",
            f"- Blocking contradictions: `{contradiction_ledger['blocking_contradiction_count']}`",
            f"- Advisory contradictions: `{contradiction_ledger['advisory_contradiction_count']}`",
            f"- Remote main pending: `{int(remote_divergence.get('local_main_ahead_of_remote', 0)) > 0}`",
            f"- Next lawful move: `{next_lawful_move}`",
        ],
    )
    return {
        "authority_graph": authority_graph,
        "posture_index": posture_index,
        "contradiction_ledger": contradiction_ledger,
        "stale_quarantine": stale_quarantine,
        "recompute_receipt": recompute_receipt,
        "report": report,
    }


def run(
    *,
    reports_root: Path,
    authority_packet_path: Path,
    contract_packet_path: Path,
    schema_packet_path: Path,
    schema_receipt_path: Path,
    branch_law_path: Path,
    product_truth_path: Path,
    post_merge_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    allowed_branches = {REQUIRED_BRANCH, CANONICAL_REPLAY_BRANCH}
    if branch_name not in allowed_branches:
        raise RuntimeError(
            f"FAIL_CLOSED: truth-engine recompute tranche must run on {REQUIRED_BRANCH} or {CANONICAL_REPLAY_BRANCH}, got {branch_name}"
        )
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: truth-engine recompute tranche requires a clean worktree")

    authority_packet = common.load_json_required(root, authority_packet_path, label="truth-engine authority packet")
    contract_packet = common.load_json_required(root, contract_packet_path, label="truth-engine contract packet")
    schema_packet = common.load_json_required(root, schema_packet_path, label="validator schema and taxonomy packet")
    schema_receipt = common.load_json_required(root, schema_receipt_path, label="validator schema and taxonomy receipt")
    branch_law = common.load_json_required(root, branch_law_path, label="successor branch law packet")
    product_truth = common.load_json_required(root, product_truth_path, label="post-close live product truth packet")
    post_merge_receipt = common.load_json_required(root, post_merge_receipt_path, label="Track 03 post-merge closeout receipt")

    common.ensure_pass(authority_packet, label="truth-engine authority packet")
    common.ensure_pass(contract_packet, label="truth-engine contract packet")
    common.ensure_pass(schema_packet, label="validator schema and taxonomy packet")
    common.ensure_pass(schema_receipt, label="validator schema and taxonomy receipt")
    common.ensure_pass(branch_law, label="successor branch law packet")
    common.ensure_pass(product_truth, label="post-close live product truth packet")
    common.ensure_pass(post_merge_receipt, label="Track 03 post-merge closeout receipt")

    if str(schema_receipt.get("next_lawful_move", "")).strip() != "IMPLEMENT_POST_F_TRUTH_ENGINE_VALIDATOR_AND_RECOMPUTE_TRANCHE":
        raise RuntimeError("FAIL_CLOSED: schema/taxonomy packet does not authorize the recompute tranche")

    main_head = _git_rev_parse(root, "main")
    if _git_merge_base(root, "main", "HEAD") != main_head:
        raise RuntimeError("FAIL_CLOSED: authoritative truth-engine branch must remain based on current main without divergence")

    remote_divergence = _remote_main_divergence(root)
    if int(remote_divergence.get("remote_ahead_of_local_main", 0)) > 0:
        raise RuntimeError("FAIL_CLOSED: origin/main is ahead of local main; refresh canonical base before recompute")
    if branch_name == CANONICAL_REPLAY_BRANCH and int(remote_divergence.get("local_main_ahead_of_remote", 0)) > 0:
        raise RuntimeError("FAIL_CLOSED: canonical main replay requires local main and origin/main to be converged")
    if branch_name == CANONICAL_REPLAY_BRANCH and not bool(remote_divergence.get("remote_ref_present", False)):
        raise RuntimeError("FAIL_CLOSED: canonical main replay requires origin/main to be present and converged")

    execution_status = EXECUTION_STATUS
    outcome = OUTCOME
    next_lawful_move = NEXT_MOVE
    if branch_name == CANONICAL_REPLAY_BRANCH:
        execution_status = CANONICAL_REPLAY_EXECUTION_STATUS
        outcome = CANONICAL_REPLAY_OUTCOME
        next_lawful_move = CANONICAL_REPLAY_NEXT_MOVE

    outputs = build_outputs(
        schema_packet=schema_packet,
        contract_packet=contract_packet,
        branch_law=branch_law,
        product_truth=product_truth,
        post_merge_receipt=post_merge_receipt,
        remote_divergence=remote_divergence,
        branch_ref=branch_name,
        execution_status=execution_status,
        outcome=outcome,
        next_lawful_move=next_lawful_move,
    )

    write_json_stable((reports_root / OUTPUT_AUTHORITY_GRAPH).resolve(), outputs["authority_graph"])
    write_json_stable((reports_root / OUTPUT_POSTURE_INDEX).resolve(), outputs["posture_index"])
    write_json_stable((reports_root / OUTPUT_CONTRADICTION_LEDGER).resolve(), outputs["contradiction_ledger"])
    write_json_stable((reports_root / OUTPUT_STALE_QUARANTINE).resolve(), outputs["stale_quarantine"])
    write_json_stable((reports_root / OUTPUT_RECOMPUTE_RECEIPT).resolve(), outputs["recompute_receipt"])
    report_name = CANONICAL_REPLAY_OUTPUT_REPORT if branch_name == CANONICAL_REPLAY_BRANCH else OUTPUT_REPORT
    common.write_text((reports_root / report_name).resolve(), str(outputs["report"]))
    return {"outcome": outcome, "receipt_path": (reports_root / OUTPUT_RECOMPUTE_RECEIPT).resolve().as_posix(), "next_lawful_move": next_lawful_move}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Run the first authoritative truth-engine validator and recompute tranche.")
    parser.add_argument(
        "--authority-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_authority_packet.json",
    )
    parser.add_argument(
        "--contract-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_contradiction_validator_contract_packet.json",
    )
    parser.add_argument(
        "--schema-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_packet.json",
    )
    parser.add_argument(
        "--schema-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_receipt.json",
    )
    parser.add_argument(
        "--product-truth-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_gate_f_post_close_live_product_truth_packet.json",
    )
    parser.add_argument(
        "--post-merge-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_post_merge_closeout_receipt.json",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        authority_packet_path=common.resolve_path(root, args.authority_packet),
        contract_packet_path=common.resolve_path(root, args.contract_packet),
        schema_packet_path=common.resolve_path(root, args.schema_packet),
        schema_receipt_path=common.resolve_path(root, args.schema_receipt),
        branch_law_path=common.resolve_path(root, args.branch_law_packet),
        product_truth_path=common.resolve_path(root, args.product_truth_packet),
        post_merge_receipt_path=common.resolve_path(root, args.post_merge_receipt),
    )
    print(result["outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
