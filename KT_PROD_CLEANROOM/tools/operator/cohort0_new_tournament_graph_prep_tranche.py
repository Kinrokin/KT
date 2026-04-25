from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_FOLLOWTHROUGH_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_tournament_followthrough_packet.json"
DEFAULT_PARENT_PAIR_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_merge_parent_pair_admissibility_receipt.json"
DEFAULT_NEW_GRAPH_PREP_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_new_tournament_graph_prep_packet.json"


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


def _relation_is_ordering(relation: str) -> bool:
    cleaned = str(relation).strip()
    return cleaned in {"LEFT_PARENT_DOMINATES_RIGHT_PARENT", "RIGHT_PARENT_DOMINATES_LEFT_PARENT"}


def _validate_inputs(
    *,
    followthrough_packet: Dict[str, Any],
    parent_pair_receipt: Dict[str, Any],
) -> None:
    if str(followthrough_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: followthrough packet must be PASS")
    if (
        str(followthrough_packet.get("followthrough_posture", "")).strip()
        != "MERGE_CHILD_EVALUATED__NO_ADMISSIBLE_PARENT_PAIR_EXISTS_ON_CURRENT_TOURNAMENT_GRAPH"
    ):
        raise RuntimeError("FAIL_CLOSED: followthrough packet is not at the current-graph merge blocker posture")

    merge_followthrough = followthrough_packet.get("merge_followthrough") if isinstance(followthrough_packet.get("merge_followthrough"), dict) else {}
    if int(merge_followthrough.get("admissible_parent_pair_count", -1)) != 0:
        raise RuntimeError("FAIL_CLOSED: followthrough packet must bind zero admissible parent pairs")

    if str(parent_pair_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: parent pair admissibility receipt must be PASS")
    if (
        str(parent_pair_receipt.get("admissibility_posture", "")).strip()
        != "NO_ADMISSIBLE_PARENT_PAIR_EXISTS_ON_CURRENT_TOURNAMENT_GRAPH"
    ):
        raise RuntimeError("FAIL_CLOSED: parent pair admissibility receipt does not bind the graph-level blocker")
    if int(parent_pair_receipt.get("admissible_parent_pair_count", -1)) != 0:
        raise RuntimeError("FAIL_CLOSED: parent pair admissibility receipt must bind zero admissible parent pairs")


def _load_tournament_result(root: Path, parent_pair_receipt: Dict[str, Any]) -> Tuple[Path, Dict[str, Any]]:
    tournament_result_ref = str(parent_pair_receipt.get("source_tournament_result_ref", "")).strip()
    if not tournament_result_ref:
        raise RuntimeError("FAIL_CLOSED: parent pair admissibility receipt missing tournament result ref")
    tournament_result_path = _resolve_path(root, tournament_result_ref)
    tournament_result = _load_json_required(tournament_result_path, label="tournament result")
    if str(tournament_result.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: source tournament result must be PASS")
    return tournament_result_path, tournament_result


def _build_new_graph_prep_packet(
    *,
    subject_head: str,
    followthrough_path: Path,
    parent_pair_path: Path,
    tournament_result_path: Path,
    parent_pair_receipt: Dict[str, Any],
    tournament_result: Dict[str, Any],
) -> Dict[str, Any]:
    entrants = tournament_result.get("entrants") if isinstance(tournament_result.get("entrants"), list) else []
    champion_set = [str(x).strip() for x in tournament_result.get("champion_set", []) if str(x).strip()]
    champion_count = len(champion_set)
    entrant_count = len([row for row in entrants if isinstance(row, dict)])
    non_champion_count = max(0, entrant_count - champion_count)
    dominance_pair_count = len(tournament_result.get("dominance_pairs", [])) if isinstance(tournament_result.get("dominance_pairs"), list) else 0
    total_pair_count = math.comb(entrant_count, 2) if entrant_count >= 2 else 0
    total_order_across_all_entrants = dominance_pair_count == total_pair_count and champion_count == 1

    pair_rows = parent_pair_receipt.get("pair_evaluations") if isinstance(parent_pair_receipt.get("pair_evaluations"), list) else []
    non_champion_pair_candidate_count = int(parent_pair_receipt.get("non_champion_parent_pair_candidate_count", 0))
    non_champion_total_order = (
        len(pair_rows) == non_champion_pair_candidate_count
        and non_champion_pair_candidate_count == (math.comb(non_champion_count, 2) if non_champion_count >= 2 else 0)
        and all(_relation_is_ordering(str(row.get("relation", ""))) for row in pair_rows if isinstance(row, dict))
    )

    graph_change_target_sentence = (
        "Earn a new schema-bound tournament result on a new authoritative graph where the current total-order relation "
        "is broken strongly enough that at least one non-champion parent pair becomes merge-admissible, so "
        "`admissible_parent_pair_count` rises above `0` before merge reentry is considered again."
    )

    return {
        "schema_id": "kt.operator.cohort0_new_tournament_graph_prep_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "prep_posture": "NEW_TOURNAMENT_GRAPH_REQUIRED__PREP_TARGET_BOUND",
        "branch_selection_posture": "NEW_TOURNAMENT_GRAPH_BRANCH_SELECTED__CHILD_CANDIDATE_BRANCH_DEFERRED",
        "claim_boundary": (
            "This packet prepares only the bounded new-tournament-graph path after graph-level merge blockage. "
            "It does not declare merge success, router authority, externality widening, or commercialization."
        ),
        "current_graph_summary": {
            "entrant_count": entrant_count,
            "champion_count": champion_count,
            "non_champion_count": non_champion_count,
            "dominance_pair_count": dominance_pair_count,
            "total_pair_count": total_pair_count,
            "total_order_across_all_entrants": total_order_across_all_entrants,
            "non_champion_parent_pair_candidate_count": non_champion_pair_candidate_count,
            "admissible_parent_pair_count": 0,
            "non_champion_total_order": non_champion_total_order,
        },
        "new_tournament_graph_target_sentence": graph_change_target_sentence,
        "required_structural_changes": [
            "Emit a new schema-bound tournament result on a new authoritative graph root instead of replaying the current graph.",
            "Break the current total-order relation strongly enough that at least one non-champion pair is no longer ordered under merge-parent preconditions.",
            "Raise `admissible_parent_pair_count` from `0` to at least `1` before any merge reentry search is reopened.",
            "Preserve tournament law: schema-bound entrant evidence, PASS admission, and PASS fragility on the new graph cycle.",
            "If the same 13 entrants are reused, reduce the complete-order ceiling below the current `dominance_pair_count = 78`; if the entrant set changes, the new graph must still create at least one admissible parent pair.",
        ],
        "non_forward_motion_classes": [
            "Pair-shopping on the current graph after zero admissible parent pairs have already been bound.",
            "Replaying the current tournament result or current pair relations and hoping merge law changes by narration.",
            "Router or externality narration without first earning a new graph substrate.",
            "Treating the current graph-level blocker as if it were only a bad parent-seed guess.",
        ],
        "source_packet_refs": {
            "followthrough_packet_ref": followthrough_path.as_posix(),
            "parent_pair_admissibility_receipt_ref": parent_pair_path.as_posix(),
            "tournament_result_ref": tournament_result_path.as_posix(),
        },
        "next_lawful_move": "PREPARE_SCHEMA_BOUND_NEW_TOURNAMENT_GRAPH_EVIDENCE_AND_RERUN_TOURNAMENT",
    }


def _build_updated_followthrough_packet(
    *,
    existing_followthrough: Dict[str, Any],
    prep_packet_path: Path,
) -> Dict[str, Any]:
    packet = dict(existing_followthrough)
    packet["generated_utc"] = utc_now_iso_z()
    merge_followthrough = dict(packet.get("merge_followthrough", {}))
    merge_followthrough["graph_reentry_branch_selected"] = "NEW_TOURNAMENT_GRAPH"
    merge_followthrough["child_candidate_branch_deferred"] = True
    merge_followthrough["new_tournament_graph_prep_packet_ref"] = prep_packet_path.as_posix()
    merge_followthrough["current_graph_reentry_allowed"] = False
    merge_followthrough["next_lawful_move"] = "PREPARE_SCHEMA_BOUND_NEW_TOURNAMENT_GRAPH_EVIDENCE_AND_RERUN_TOURNAMENT"
    packet["merge_followthrough"] = merge_followthrough
    packet["new_tournament_graph_prep_packet_ref"] = prep_packet_path.as_posix()
    packet["next_question"] = "What new tournament graph evidence will break the current total order and create at least one admissible parent pair?"
    return packet


def run_new_tournament_graph_prep_tranche(
    *,
    followthrough_report_path: Path,
    parent_pair_report_path: Path,
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
    authoritative_parent_pair_path, parent_pair_receipt = _resolve_authoritative(
        root,
        parent_pair_report_path.resolve(),
        "authoritative_merge_parent_pair_admissibility_receipt_ref",
        "cohort0 merge parent pair admissibility receipt",
    )
    _validate_inputs(followthrough_packet=followthrough_packet, parent_pair_receipt=parent_pair_receipt)
    tournament_result_path, tournament_result = _load_tournament_result(root, parent_pair_receipt)

    target_root = authoritative_root.resolve() if authoritative_root is not None else (authoritative_parent_pair_path.parent / "new_tournament_graph_prep").resolve()
    target_root.mkdir(parents=True, exist_ok=True)

    prep_packet = _build_new_graph_prep_packet(
        subject_head=str(followthrough_packet.get("subject_head", "")).strip(),
        followthrough_path=authoritative_followthrough_path,
        parent_pair_path=authoritative_parent_pair_path,
        tournament_result_path=tournament_result_path,
        parent_pair_receipt=parent_pair_receipt,
        tournament_result=tournament_result,
    )
    authoritative_prep_packet_path = (target_root / "cohort0_new_tournament_graph_prep_packet.json").resolve()
    write_json_stable(authoritative_prep_packet_path, prep_packet)

    updated_followthrough = _build_updated_followthrough_packet(
        existing_followthrough=followthrough_packet,
        prep_packet_path=authoritative_prep_packet_path,
    )
    authoritative_updated_followthrough_path = (target_root / "cohort0_real_engine_tournament_followthrough_packet.json").resolve()
    write_json_stable(authoritative_updated_followthrough_path, updated_followthrough)

    reports_root.mkdir(parents=True, exist_ok=True)
    tracked_prep_packet = dict(prep_packet)
    tracked_prep_packet["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_NEW_TOURNAMENT_GRAPH_PREP_PACKET"
    tracked_prep_packet["authoritative_new_tournament_graph_prep_packet_ref"] = authoritative_prep_packet_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_NEW_GRAPH_PREP_REPORT_REL).name).resolve(), tracked_prep_packet)

    tracked_followthrough = dict(updated_followthrough)
    tracked_followthrough["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_TOURNAMENT_FOLLOWTHROUGH_ARTIFACT"
    tracked_followthrough["authoritative_followthrough_packet_ref"] = authoritative_updated_followthrough_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_FOLLOWTHROUGH_REPORT_REL).name).resolve(), tracked_followthrough)

    return {
        "new_tournament_graph_prep_packet": prep_packet,
        "followthrough_packet": updated_followthrough,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Prepare the bounded new-tournament-graph branch after graph-level merge blockage.")
    ap.add_argument(
        "--followthrough-report",
        default=DEFAULT_FOLLOWTHROUGH_REPORT_REL,
        help=f"Tracked tournament followthrough report path. Default: {DEFAULT_FOLLOWTHROUGH_REPORT_REL}",
    )
    ap.add_argument(
        "--parent-pair-report",
        default=DEFAULT_PARENT_PAIR_REPORT_REL,
        help=f"Tracked merge parent pair admissibility report path. Default: {DEFAULT_PARENT_PAIR_REPORT_REL}",
    )
    ap.add_argument(
        "--authoritative-root",
        default="",
        help="Optional authoritative output root. Default: <authoritative_parent_pair_parent>/new_tournament_graph_prep",
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
    payload = run_new_tournament_graph_prep_tranche(
        followthrough_report_path=_resolve_path(root, str(args.followthrough_report)),
        parent_pair_report_path=_resolve_path(root, str(args.parent_pair_report)),
        authoritative_root=_resolve_path(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve_path(root, str(args.reports_root)),
        workspace_root=root,
    )
    prep_packet = payload["new_tournament_graph_prep_packet"]
    print(
        json.dumps(
            {
                "status": prep_packet["status"],
                "prep_posture": prep_packet["prep_posture"],
                "next_lawful_move": prep_packet["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
