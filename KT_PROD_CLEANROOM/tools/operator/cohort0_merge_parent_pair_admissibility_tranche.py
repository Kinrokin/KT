from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.merge.merge_evaluator import _compute_champion_set, _compute_dominance_pairs, _load_entrant_evidence
from tools.operator.cohort0_promotion_merge_followthrough_tranche import _rank_entrants
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_FOLLOWTHROUGH_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_tournament_followthrough_packet.json"
DEFAULT_PROMOTION_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_promotion_candidate_receipt.json"
DEFAULT_CHILD_CANDIDATE_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_merge_child_candidate_receipt.json"
DEFAULT_CHILD_EVAL_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_merge_child_evaluation_receipt.json"
DEFAULT_PARENT_PAIR_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_merge_parent_pair_admissibility_receipt.json"


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _resolve_path(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    else:
        path = path.resolve()
    return path


def _resolve_authoritative(root: Path, tracked_path: Path, ref_field: str, label: str) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(tracked_path, label=f"tracked {label}")
    authoritative_ref = str(tracked.get(ref_field, "")).strip()
    authoritative_path = _resolve_path(root, authoritative_ref) if authoritative_ref else tracked_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")


def _load_execution_context(
    *,
    root: Path,
    followthrough_packet: Dict[str, Any],
) -> Tuple[Path, Dict[str, Any], Path, Dict[str, Any], Path]:
    execution_ref = str(followthrough_packet.get("carrier_surface_summary", {}).get("source_tournament_execution_receipt_ref", "")).strip()
    if not execution_ref:
        execution_ref = str(followthrough_packet.get("source_tournament_execution_receipt_ref", "")).strip()
    if not execution_ref:
        raise RuntimeError("FAIL_CLOSED: followthrough packet missing source tournament execution receipt ref")
    execution_receipt_path = _resolve_path(root, execution_ref)
    execution_receipt = _load_json_required(execution_receipt_path, label="source tournament execution receipt")

    tournament_result_ref = str(execution_receipt.get("tournament_result_ref", "")).strip()
    if not tournament_result_ref:
        raise RuntimeError("FAIL_CLOSED: execution receipt missing tournament result ref")
    tournament_result_path = _resolve_path(root, tournament_result_ref)
    tournament_result = _load_json_required(tournament_result_path, label="source tournament result")

    prep_packet_ref = str(execution_receipt.get("source_prep_packet_ref", "")).strip()
    if not prep_packet_ref:
        raise RuntimeError("FAIL_CLOSED: execution receipt missing source prep packet ref")
    prep_packet_path = _resolve_path(root, prep_packet_ref)
    prep_packet = _load_json_required(prep_packet_path, label="source tournament prep packet")

    entrants_root_ref = str(prep_packet.get("refs", {}).get("tournament_entrants_root_ref", "")).strip()
    if not entrants_root_ref:
        raise RuntimeError("FAIL_CLOSED: prep packet missing tournament entrants root ref")
    entrants_root = _resolve_path(root, entrants_root_ref)
    if not entrants_root.is_dir():
        raise RuntimeError(f"FAIL_CLOSED: missing tournament entrants root: {entrants_root.as_posix()}")

    return execution_receipt_path, execution_receipt, tournament_result_path, tournament_result, entrants_root


def _pair_relation(
    *,
    left_hash: str,
    right_hash: str,
    dominance_pairs: List[Dict[str, str]],
    left_hard_pass: bool,
    right_hard_pass: bool,
    pair_champions: List[str],
) -> str:
    if not left_hard_pass or not right_hard_pass:
        return "HARD_PASS_PRECONDITION_FAILED"
    left_dominates = any(
        str(row.get("dominant_adapter_root_hash", "")).strip() == left_hash
        and str(row.get("dominated_adapter_root_hash", "")).strip() == right_hash
        for row in dominance_pairs
    )
    right_dominates = any(
        str(row.get("dominant_adapter_root_hash", "")).strip() == right_hash
        and str(row.get("dominated_adapter_root_hash", "")).strip() == left_hash
        for row in dominance_pairs
    )
    if left_dominates:
        return "LEFT_PARENT_DOMINATES_RIGHT_PARENT"
    if right_dominates:
        return "RIGHT_PARENT_DOMINATES_LEFT_PARENT"
    if set(pair_champions) == {left_hash, right_hash}:
        return "CO_CHAMPION_PARENT_PAIR"
    return "NO_ADMISSIBLE_PARENT_PAIR_RELATION"


def _search_parent_pairs(
    *,
    ranked_entrants: List[Dict[str, Any]],
    tournament_result: Dict[str, Any],
    entrants_root: Path,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    entrant_by_hash = {
        str(row.get("adapter_root_hash", "")).strip(): dict(row)
        for row in tournament_result.get("entrants", [])
        if isinstance(row, dict) and str(row.get("adapter_root_hash", "")).strip()
    }
    non_champions = [dict(row) for row in ranked_entrants if not bool(row.get("is_champion"))]
    epsilon = float(tournament_result.get("epsilon", 0.0)) if isinstance(tournament_result.get("epsilon"), (int, float)) else 0.0

    axes_by_hash: Dict[str, Dict[str, float]] = {}
    hard_pass_by_hash: Dict[str, bool] = {}
    for row in non_champions:
        adapter_root_hash = str(row.get("adapter_root_hash", "")).strip()
        entrant = entrant_by_hash.get(adapter_root_hash)
        if not entrant:
            raise RuntimeError(f"FAIL_CLOSED: tournament result missing entrant row for {adapter_root_hash}")
        axes, hard_pass = _load_entrant_evidence(entrants_root=entrants_root, entrant=entrant)
        axes_by_hash[adapter_root_hash] = axes
        hard_pass_by_hash[adapter_root_hash] = hard_pass

    pair_rows: List[Dict[str, Any]] = []
    admissible_rows: List[Dict[str, Any]] = []
    for left, right in itertools.combinations(non_champions, 2):
        left_hash = str(left.get("adapter_root_hash", "")).strip()
        right_hash = str(right.get("adapter_root_hash", "")).strip()
        pair_hashes = sorted([left_hash, right_hash])
        pair_dominance = _compute_dominance_pairs(
            hashes=pair_hashes,
            axes_by_hash=axes_by_hash,
            hard_pass_by_hash=hard_pass_by_hash,
            epsilon=epsilon,
        )
        pair_champions = _compute_champion_set(hashes=pair_hashes, dominance_pairs=pair_dominance)
        left_hard_pass = bool(hard_pass_by_hash.get(left_hash, False))
        right_hard_pass = bool(hard_pass_by_hash.get(right_hash, False))
        admissible = bool(left_hard_pass and right_hard_pass and set(pair_champions) == set(pair_hashes))

        reason_codes: List[str] = []
        if not left_hard_pass or not right_hard_pass:
            reason_codes.append("MERGE_PARENT_HARD_PASS_PRECONDITION_FAILED")
        if set(pair_champions) != set(pair_hashes):
            reason_codes.append("MERGE_PRECONDITION_FAILED")

        row = {
            "left_parent": {
                "adapter_id": str(left.get("adapter_id", "")).strip(),
                "adapter_root_hash": left_hash,
                "adapter_version": str(left.get("adapter_version", "")).strip(),
                "rank": int(left.get("rank", 0)),
                "hard_pass": left_hard_pass,
            },
            "right_parent": {
                "adapter_id": str(right.get("adapter_id", "")).strip(),
                "adapter_root_hash": right_hash,
                "adapter_version": str(right.get("adapter_version", "")).strip(),
                "rank": int(right.get("rank", 0)),
                "hard_pass": right_hard_pass,
            },
            "admissible": admissible,
            "relation": _pair_relation(
                left_hash=left_hash,
                right_hash=right_hash,
                dominance_pairs=pair_dominance,
                left_hard_pass=left_hard_pass,
                right_hard_pass=right_hard_pass,
                pair_champions=pair_champions,
            ),
            "reason_codes": sorted(set(reason_codes)),
        }
        pair_rows.append(row)
        if admissible:
            admissible_rows.append(row)

    return pair_rows, admissible_rows


def _build_parent_pair_receipt(
    *,
    subject_head: str,
    followthrough_path: Path,
    promotion_path: Path,
    child_candidate_path: Path,
    child_eval_path: Path,
    tournament_result_path: Path,
    promotion_receipt: Dict[str, Any],
    pair_rows: List[Dict[str, Any]],
    admissible_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    if admissible_rows:
        posture = "ADMISSIBLE_PARENT_PAIR_EXISTS__RESELECTION_AVAILABLE_ON_CURRENT_TOURNAMENT_GRAPH"
        next_lawful_move = "RESELECT_ADMISSIBLE_PARENT_SEEDS_AND_REEVALUATE_MERGE_CHILD"
    else:
        posture = "NO_ADMISSIBLE_PARENT_PAIR_EXISTS_ON_CURRENT_TOURNAMENT_GRAPH"
        next_lawful_move = "PREPARE_NEW_TOURNAMENT_GRAPH_OR_NEW_CHILD_CANDIDATE_BEFORE_MERGE_REENTRY"
    return {
        "schema_id": "kt.operator.cohort0_merge_parent_pair_admissibility_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "admissibility_posture": posture,
        "claim_boundary": "This receipt binds only the current-graph parent-pair admissibility search for bounded merge reentry. It does not declare merge success, router authority, or externality widening.",
        "source_followthrough_packet_ref": followthrough_path.as_posix(),
        "source_promotion_candidate_receipt_ref": promotion_path.as_posix(),
        "source_merge_child_candidate_receipt_ref": child_candidate_path.as_posix(),
        "source_merge_child_evaluation_receipt_ref": child_eval_path.as_posix(),
        "source_tournament_result_ref": tournament_result_path.as_posix(),
        "child_candidate": dict(promotion_receipt.get("candidate", {})),
        "non_champion_parent_pair_candidate_count": len(pair_rows),
        "admissible_parent_pair_count": len(admissible_rows),
        "admissible_parent_pairs": admissible_rows,
        "pair_evaluations": pair_rows,
        "next_lawful_move": next_lawful_move,
    }


def _build_updated_child_eval_receipt(
    *,
    existing_child_eval: Dict[str, Any],
    parent_pair_receipt_path: Path,
    admissible_parent_pair_count: int,
) -> Dict[str, Any]:
    updated = dict(existing_child_eval)
    updated["generated_utc"] = utc_now_iso_z()
    updated["merge_parent_pair_admissibility_receipt_ref"] = parent_pair_receipt_path.as_posix()
    updated["admissible_parent_pair_count"] = int(admissible_parent_pair_count)
    if admissible_parent_pair_count > 0:
        updated["evaluation_posture"] = "MERGE_CHILD_EVALUATED__ADMISSIBLE_PARENT_PAIR_RESELECTION_AVAILABLE"
        updated["next_lawful_move"] = "RESELECT_ADMISSIBLE_PARENT_SEEDS_AND_REEVALUATE_MERGE_CHILD"
    else:
        updated["evaluation_posture"] = "MERGE_CHILD_EVALUATED__NO_ADMISSIBLE_PARENT_PAIR_EXISTS_ON_CURRENT_TOURNAMENT_GRAPH"
        updated["next_lawful_move"] = "PREPARE_NEW_TOURNAMENT_GRAPH_OR_NEW_CHILD_CANDIDATE_BEFORE_MERGE_REENTRY"
    updated["claim_boundary"] = (
        "This receipt captures bounded merge-child evaluation plus current-graph parent-pair admissibility. "
        "It does not by itself declare a promotion verdict, router authority, or externality widening."
    )
    return updated


def _build_updated_followthrough_packet(
    *,
    existing_followthrough: Dict[str, Any],
    parent_pair_receipt_path: Path,
    updated_child_eval_path: Path,
    pair_rows: List[Dict[str, Any]],
    admissible_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    packet = dict(existing_followthrough)
    packet["generated_utc"] = utc_now_iso_z()
    merge_followthrough = dict(packet.get("merge_followthrough", {}))
    promotion_followthrough = dict(packet.get("promotion_followthrough", {}))

    attempted_parent_seeds = list(merge_followthrough.get("recommended_parent_seeds", []))
    merge_followthrough["admissible_parent_pair_search_receipt_ref"] = parent_pair_receipt_path.as_posix()
    merge_followthrough["attempted_parent_seed_count"] = len(attempted_parent_seeds)
    merge_followthrough["attempted_parent_seeds"] = attempted_parent_seeds
    merge_followthrough["parent_pair_candidates_examined_count"] = len(pair_rows)
    merge_followthrough["admissible_parent_pair_count"] = len(admissible_rows)
    merge_followthrough["recommended_parent_seed_selection_rule"] = "admissible_non_champion_parent_pairs_by_dominance_rank"
    merge_followthrough["execution_ready"] = False

    if admissible_rows:
        next_pair = admissible_rows[0]
        merge_followthrough["recommended_parent_seed_count"] = 2
        merge_followthrough["recommended_parent_seeds"] = [
            dict(next_pair["left_parent"]),
            dict(next_pair["right_parent"]),
        ]
        merge_followthrough["blockers"] = ["MERGE_CHILD_REEVALUATION_NOT_PREPARED"]
        merge_followthrough["next_lawful_move"] = "RESELECT_ADMISSIBLE_PARENT_SEEDS_AND_REEVALUATE_MERGE_CHILD"
        packet["followthrough_posture"] = "MERGE_CHILD_EVALUATED__ADMISSIBLE_PARENT_PAIR_RESELECTION_AVAILABLE"
        promotion_followthrough["blocked_by"] = "MERGE_CHILD_REEVALUATION_NOT_PREPARED__PROMOTION_NOT_BINDABLE"
        packet["next_question"] = "Which admissible parent pair should be tested next against the bounded child candidate?"
    else:
        merge_followthrough["recommended_parent_seed_count"] = 0
        merge_followthrough["recommended_parent_seeds"] = []
        merge_followthrough["blockers"] = ["NO_ADMISSIBLE_PARENT_PAIR_EXISTS_ON_CURRENT_TOURNAMENT_GRAPH"]
        merge_followthrough["next_lawful_move"] = "PREPARE_NEW_TOURNAMENT_GRAPH_OR_NEW_CHILD_CANDIDATE_BEFORE_MERGE_REENTRY"
        packet["followthrough_posture"] = "MERGE_CHILD_EVALUATED__NO_ADMISSIBLE_PARENT_PAIR_EXISTS_ON_CURRENT_TOURNAMENT_GRAPH"
        promotion_followthrough["blocked_by"] = "NO_ADMISSIBLE_PARENT_PAIR_EXISTS_ON_CURRENT_TOURNAMENT_GRAPH__PROMOTION_NOT_BINDABLE"
        packet["next_question"] = "What new tournament graph or child candidate could reopen merge admissibility once no admissible parent pair exists?"

    promotion_followthrough["execution_ready"] = False
    packet["promotion_followthrough"] = promotion_followthrough
    packet["merge_followthrough"] = merge_followthrough
    packet["merge_child_evaluation_receipt_ref"] = updated_child_eval_path.as_posix()
    packet["merge_parent_pair_admissibility_receipt_ref"] = parent_pair_receipt_path.as_posix()
    return packet


def run_merge_parent_pair_admissibility_tranche(
    *,
    followthrough_report_path: Path,
    promotion_report_path: Path,
    child_candidate_report_path: Path,
    child_eval_report_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    authoritative_followthrough_path, followthrough_packet = _resolve_authoritative(
        root,
        followthrough_report_path.resolve(),
        "authoritative_followthrough_packet_ref",
        "cohort0 tournament followthrough packet",
    )
    authoritative_promotion_path, promotion_receipt = _resolve_authoritative(
        root,
        promotion_report_path.resolve(),
        "authoritative_promotion_candidate_receipt_ref",
        "cohort0 promotion candidate receipt",
    )
    authoritative_child_candidate_path, child_candidate_receipt = _resolve_authoritative(
        root,
        child_candidate_report_path.resolve(),
        "authoritative_merge_child_candidate_receipt_ref",
        "cohort0 merge child candidate receipt",
    )
    authoritative_child_eval_path, child_eval_receipt = _resolve_authoritative(
        root,
        child_eval_report_path.resolve(),
        "authoritative_merge_child_evaluation_receipt_ref",
        "cohort0 merge child evaluation receipt",
    )

    _, _, tournament_result_path, tournament_result, entrants_root = _load_execution_context(
        root=root,
        followthrough_packet=followthrough_packet,
    )
    ranked_entrants = _rank_entrants(tournament_result)
    pair_rows, admissible_rows = _search_parent_pairs(
        ranked_entrants=ranked_entrants,
        tournament_result=tournament_result,
        entrants_root=entrants_root,
    )

    target_root = authoritative_root.resolve() if authoritative_root is not None else (authoritative_child_eval_path.parent / "parent_pair_admissibility").resolve()
    target_root.mkdir(parents=True, exist_ok=True)

    parent_pair_receipt = _build_parent_pair_receipt(
        subject_head=str(promotion_receipt.get("subject_head", "")).strip(),
        followthrough_path=authoritative_followthrough_path,
        promotion_path=authoritative_promotion_path,
        child_candidate_path=authoritative_child_candidate_path,
        child_eval_path=authoritative_child_eval_path,
        tournament_result_path=tournament_result_path,
        promotion_receipt=promotion_receipt,
        pair_rows=pair_rows,
        admissible_rows=admissible_rows,
    )
    authoritative_parent_pair_path = (target_root / "cohort0_merge_parent_pair_admissibility_receipt.json").resolve()
    write_json_stable(authoritative_parent_pair_path, parent_pair_receipt)

    updated_child_eval = _build_updated_child_eval_receipt(
        existing_child_eval=child_eval_receipt,
        parent_pair_receipt_path=authoritative_parent_pair_path,
        admissible_parent_pair_count=len(admissible_rows),
    )
    authoritative_updated_child_eval_path = (target_root / "cohort0_merge_child_evaluation_receipt.json").resolve()
    write_json_stable(authoritative_updated_child_eval_path, updated_child_eval)

    updated_followthrough = _build_updated_followthrough_packet(
        existing_followthrough=followthrough_packet,
        parent_pair_receipt_path=authoritative_parent_pair_path,
        updated_child_eval_path=authoritative_updated_child_eval_path,
        pair_rows=pair_rows,
        admissible_rows=admissible_rows,
    )
    authoritative_updated_followthrough_path = (target_root / "cohort0_real_engine_tournament_followthrough_packet.json").resolve()
    write_json_stable(authoritative_updated_followthrough_path, updated_followthrough)

    reports_root.mkdir(parents=True, exist_ok=True)

    tracked_parent_pair = dict(parent_pair_receipt)
    tracked_parent_pair["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_MERGE_PARENT_PAIR_ADMISSIBILITY_RECEIPT"
    tracked_parent_pair["authoritative_merge_parent_pair_admissibility_receipt_ref"] = authoritative_parent_pair_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_PARENT_PAIR_REPORT_REL).name).resolve(), tracked_parent_pair)

    tracked_child_eval = dict(updated_child_eval)
    tracked_child_eval["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_MERGE_CHILD_EVALUATION_RECEIPT"
    tracked_child_eval["authoritative_merge_child_evaluation_receipt_ref"] = authoritative_updated_child_eval_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_CHILD_EVAL_REPORT_REL).name).resolve(), tracked_child_eval)

    tracked_followthrough = dict(updated_followthrough)
    tracked_followthrough["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_TOURNAMENT_FOLLOWTHROUGH_ARTIFACT"
    tracked_followthrough["authoritative_followthrough_packet_ref"] = authoritative_updated_followthrough_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_FOLLOWTHROUGH_REPORT_REL).name).resolve(), tracked_followthrough)

    return {
        "merge_parent_pair_admissibility_receipt": parent_pair_receipt,
        "merge_child_evaluation_receipt": updated_child_eval,
        "followthrough_packet": updated_followthrough,
        "merge_child_candidate_receipt": child_candidate_receipt,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Bind current-graph merge parent-pair admissibility after bounded child evaluation.")
    ap.add_argument(
        "--followthrough-report",
        default=DEFAULT_FOLLOWTHROUGH_REPORT_REL,
        help=f"Tracked tournament followthrough report path. Default: {DEFAULT_FOLLOWTHROUGH_REPORT_REL}",
    )
    ap.add_argument(
        "--promotion-report",
        default=DEFAULT_PROMOTION_REPORT_REL,
        help=f"Tracked promotion candidate report path. Default: {DEFAULT_PROMOTION_REPORT_REL}",
    )
    ap.add_argument(
        "--child-candidate-report",
        default=DEFAULT_CHILD_CANDIDATE_REPORT_REL,
        help=f"Tracked merge child candidate report path. Default: {DEFAULT_CHILD_CANDIDATE_REPORT_REL}",
    )
    ap.add_argument(
        "--child-eval-report",
        default=DEFAULT_CHILD_EVAL_REPORT_REL,
        help=f"Tracked merge child evaluation report path. Default: {DEFAULT_CHILD_EVAL_REPORT_REL}",
    )
    ap.add_argument(
        "--authoritative-root",
        default="",
        help="Optional authoritative output root. Default: <authoritative_child_eval_parent>/parent_pair_admissibility",
    )
    ap.add_argument(
        "--reports-root",
        default="KT_PROD_CLEANROOM/reports",
        help="Tracked carrier report root. Default: KT_PROD_CLEANROOM/reports",
    )
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_merge_parent_pair_admissibility_tranche(
        followthrough_report_path=_resolve_path(root, str(args.followthrough_report)),
        promotion_report_path=_resolve_path(root, str(args.promotion_report)),
        child_candidate_report_path=_resolve_path(root, str(args.child_candidate_report)),
        child_eval_report_path=_resolve_path(root, str(args.child_eval_report)),
        authoritative_root=_resolve_path(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve_path(root, str(args.reports_root)),
        workspace_root=root,
    )
    receipt = payload["merge_parent_pair_admissibility_receipt"]
    followthrough = payload["followthrough_packet"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "admissibility_posture": receipt["admissibility_posture"],
                "admissible_parent_pair_count": receipt["admissible_parent_pair_count"],
                "next_lawful_move": followthrough["merge_followthrough"]["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
