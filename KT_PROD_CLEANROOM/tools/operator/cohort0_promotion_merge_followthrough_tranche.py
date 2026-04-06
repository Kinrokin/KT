from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_EXECUTION_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_tournament_execution_receipt.json"
DEFAULT_IMPORT_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_adapter_import_receipt.json"
DEFAULT_GRADE_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_adapter_grade_receipt.json"
DEFAULT_FOLLOWTHROUGH_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_tournament_followthrough_packet.json"
DEFAULT_PROMOTION_CANDIDATE_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_promotion_candidate_receipt.json"


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


def _rank_entrants(tournament_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    entrants = tournament_result.get("entrants") if isinstance(tournament_result.get("entrants"), list) else []
    dominance_pairs = tournament_result.get("dominance_pairs") if isinstance(tournament_result.get("dominance_pairs"), list) else []
    rows: Dict[str, Dict[str, Any]] = {}
    champion_hashes = {str(x).strip() for x in tournament_result.get("champion_set", []) if str(x).strip()}

    for entrant in entrants:
        if not isinstance(entrant, dict):
            continue
        adapter_root_hash = str(entrant.get("adapter_root_hash", "")).strip()
        if not adapter_root_hash:
            continue
        rows[adapter_root_hash] = {
            "adapter_root_hash": adapter_root_hash,
            "adapter_id": str(entrant.get("adapter_id", "")).strip(),
            "adapter_version": str(entrant.get("adapter_version", "")).strip(),
            "dominated_count": 0,
            "dominator_count": 0,
            "is_champion": adapter_root_hash in champion_hashes,
        }

    for pair in dominance_pairs:
        if not isinstance(pair, dict):
            continue
        dominant = str(pair.get("dominant_adapter_root_hash", "")).strip()
        dominated = str(pair.get("dominated_adapter_root_hash", "")).strip()
        if dominant in rows:
            rows[dominant]["dominated_count"] += 1
        if dominated in rows:
            rows[dominated]["dominator_count"] += 1

    ranked = sorted(
        rows.values(),
        key=lambda row: (
            int(row.get("dominator_count", 0)),
            -int(row.get("dominated_count", 0)),
            str(row.get("adapter_id", "")),
            str(row.get("adapter_root_hash", "")),
        ),
    )
    for idx, row in enumerate(ranked, start=1):
        row["rank"] = idx
    return ranked


def _build_promotion_candidate_receipt(
    *,
    subject_head: str,
    tournament_execution_receipt_path: Path,
    tournament_result_path: Path,
    ranked_entrants: List[Dict[str, Any]],
    champion_count: int,
    dominance_pair_count: int,
) -> Dict[str, Any]:
    champions = [row for row in ranked_entrants if bool(row.get("is_champion"))]
    if champion_count != 1 or len(champions) != 1:
        raise RuntimeError("FAIL_CLOSED: promotion candidate receipt requires exactly one tournament champion")
    champion = dict(champions[0])
    return {
        "schema_id": "kt.operator.cohort0_promotion_candidate_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "candidate_posture": "UNIQUE_TOURNAMENT_CHAMPION_IDENTIFIED__MERGE_CHILD_PREP_REQUIRED",
        "claim_boundary": "This receipt identifies only the bounded tournament champion as the current promotion candidate. It does not declare merge success, router authority, or externality widening.",
        "source_tournament_execution_receipt_ref": tournament_execution_receipt_path.as_posix(),
        "source_tournament_result_ref": tournament_result_path.as_posix(),
        "candidate": champion,
        "tournament_summary": {
            "entrant_count": len(ranked_entrants),
            "champion_count": champion_count,
            "dominance_pair_count": dominance_pair_count,
        },
        "next_lawful_move": "PREPARE_SCHEMA_BOUND_MERGE_CHILD_CANDIDATE_AND_CHILD_EVAL",
    }


def _build_followthrough_packet(
    *,
    import_receipt_path: Path,
    import_receipt: Dict[str, Any],
    grade_receipt_path: Path,
    grade_receipt: Dict[str, Any],
    tournament_execution_receipt_path: Path,
    tournament_execution_receipt: Dict[str, Any],
    tournament_result_path: Path,
    tournament_result: Dict[str, Any],
    promotion_candidate_receipt_path: Path,
    promotion_candidate_receipt: Dict[str, Any],
    ranked_entrants: List[Dict[str, Any]],
) -> Dict[str, Any]:
    champion = dict(promotion_candidate_receipt.get("candidate", {}))
    non_champions = [row for row in ranked_entrants if not bool(row.get("is_champion"))]
    recommended_parent_seeds = [
        {
            "adapter_root_hash": str(row.get("adapter_root_hash", "")).strip(),
            "adapter_id": str(row.get("adapter_id", "")).strip(),
            "adapter_version": str(row.get("adapter_version", "")).strip(),
            "rank": int(row.get("rank", 0)),
        }
        for row in non_champions[:2]
    ]
    merge_blockers = [
        "MERGE_CHILD_CANDIDATE_ARTIFACT_NOT_PREPARED",
        "MERGE_CHILD_EVAL_REPORT_NOT_PREPARED",
        "MERGE_MANIFEST_NOT_PREPARED",
        "MERGE_EVAL_RECEIPT_NOT_PREPARED",
        "MERGE_ROLLBACK_PLAN_NOT_PREPARED",
    ]
    return {
        "schema_id": "kt.operator.cohort0_real_engine_tournament_followthrough_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "followthrough_posture": "TOURNAMENT_EXECUTED__PROMOTION_CANDIDATE_IDENTIFIED__MERGE_CHILD_PREP_REQUIRED",
        "subject_head": str(import_receipt.get("subject_head", "")).strip(),
        "adapter_evidence_grade": str(grade_receipt.get("grade", "")).strip(),
        "claim_boundary": "This packet advances only bounded promotion and merge follow-through after tournament execution. It does not declare merge success, router authority, externality widening, comparative claims, or commercial activation.",
        "carrier_surface_summary": {
            "source_import_receipt_ref": import_receipt_path.as_posix(),
            "source_grade_receipt_ref": grade_receipt_path.as_posix(),
            "source_tournament_execution_receipt_ref": tournament_execution_receipt_path.as_posix(),
            "source_tournament_result_ref": tournament_result_path.as_posix(),
        },
        "tournament_followthrough": {
            "execution_ready": True,
            "execution_status": str(tournament_execution_receipt.get("status", "")).strip(),
            "champion_count": int(tournament_execution_receipt.get("champion_count", 0)),
            "champion_set": list(tournament_execution_receipt.get("champion_set", [])),
            "dominance_pair_count": int(tournament_execution_receipt.get("dominance_pair_count", 0)),
            "result_ref": tournament_result_path.as_posix(),
            "next_lawful_move": "PREPARE_PROMOTION_CANDIDATE_AND_MERGE_CHILD",
        },
        "promotion_followthrough": {
            "candidate_identified": True,
            "candidate_receipt_ref": promotion_candidate_receipt_path.as_posix(),
            "candidate_adapter_id": str(champion.get("adapter_id", "")).strip(),
            "candidate_adapter_root_hash": str(champion.get("adapter_root_hash", "")).strip(),
            "candidate_rank": int(champion.get("rank", 0)),
            "execution_ready": False,
            "blocked_by": "PROMOTION_DECISION_REMAINS_BOUNDED_PENDING_MERGE_CHILD_PREP",
        },
        "merge_followthrough": {
            "execution_ready": False,
            "recommended_parent_seed_count": len(recommended_parent_seeds),
            "recommended_parent_seed_selection_rule": "strongest_two_non_champion_entrants_by_dominance_rank",
            "recommended_parent_seeds": recommended_parent_seeds,
            "blockers": merge_blockers,
            "next_lawful_move": "PREPARE_SCHEMA_BOUND_MERGE_CHILD_CANDIDATE_AND_CHILD_EVAL_AGAINST_RECOMMENDED_PARENT_SEEDS",
        },
        "next_question": "Can a real schema-bound merge child candidate beat the recommended parent seed pair under merge law?",
    }


def run_promotion_merge_followthrough_tranche(
    *,
    execution_report_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    authoritative_execution_receipt_path, execution_receipt = _resolve_authoritative(
        root,
        execution_report_path.resolve(),
        "authoritative_tournament_execution_receipt_ref",
        "cohort0 tournament execution receipt",
    )
    import_report_path = _resolve_path(root, DEFAULT_IMPORT_REPORT_REL)
    grade_report_path = _resolve_path(root, DEFAULT_GRADE_REPORT_REL)
    authoritative_import_receipt_path, import_receipt = _resolve_authoritative(
        root, import_report_path, "authoritative_import_receipt_ref", "cohort0 import receipt"
    )
    authoritative_grade_receipt_path, grade_receipt = _resolve_authoritative(
        root, grade_report_path, "authoritative_grade_receipt_ref", "cohort0 grade receipt"
    )
    if str(execution_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: promotion/merge followthrough requires PASS tournament execution receipt")

    tournament_result_path = _resolve_path(root, str(execution_receipt.get("tournament_result_ref", "")).strip())
    tournament_result = _load_json_required(tournament_result_path, label="tournament result")
    if str(tournament_result.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: promotion/merge followthrough requires PASS tournament result")

    ranked_entrants = _rank_entrants(tournament_result)
    champion_count = len([row for row in ranked_entrants if bool(row.get("is_champion"))])
    dominance_pair_count = len(list(tournament_result.get("dominance_pairs", [])))

    target_root = authoritative_root.resolve() if authoritative_root is not None else authoritative_execution_receipt_path.parent.resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    authoritative_promotion_candidate_path = (target_root / "cohort0_promotion_candidate_receipt.json").resolve()
    authoritative_followthrough_path = (target_root / "cohort0_real_engine_tournament_followthrough_packet.json").resolve()

    promotion_candidate_receipt = _build_promotion_candidate_receipt(
        subject_head=str(import_receipt.get("subject_head", "")).strip(),
        tournament_execution_receipt_path=authoritative_execution_receipt_path,
        tournament_result_path=tournament_result_path,
        ranked_entrants=ranked_entrants,
        champion_count=champion_count,
        dominance_pair_count=dominance_pair_count,
    )
    write_json_stable(authoritative_promotion_candidate_path, promotion_candidate_receipt)

    followthrough_packet = _build_followthrough_packet(
        import_receipt_path=authoritative_import_receipt_path,
        import_receipt=import_receipt,
        grade_receipt_path=authoritative_grade_receipt_path,
        grade_receipt=grade_receipt,
        tournament_execution_receipt_path=authoritative_execution_receipt_path,
        tournament_execution_receipt=execution_receipt,
        tournament_result_path=tournament_result_path,
        tournament_result=tournament_result,
        promotion_candidate_receipt_path=authoritative_promotion_candidate_path,
        promotion_candidate_receipt=promotion_candidate_receipt,
        ranked_entrants=ranked_entrants,
    )
    write_json_stable(authoritative_followthrough_path, followthrough_packet)

    reports_root.mkdir(parents=True, exist_ok=True)
    carrier_promotion_candidate = dict(promotion_candidate_receipt)
    carrier_promotion_candidate["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_PROMOTION_CANDIDATE_RECEIPT"
    carrier_promotion_candidate["authoritative_promotion_candidate_receipt_ref"] = authoritative_promotion_candidate_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_PROMOTION_CANDIDATE_REPORT_REL).name).resolve(), carrier_promotion_candidate)

    carrier_followthrough = dict(followthrough_packet)
    carrier_followthrough["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_TOURNAMENT_FOLLOWTHROUGH_ARTIFACT"
    carrier_followthrough["authoritative_followthrough_packet_ref"] = authoritative_followthrough_path.as_posix()
    carrier_followthrough["source_import_receipt_ref"] = authoritative_import_receipt_path.as_posix()
    carrier_followthrough["source_grade_receipt_ref"] = authoritative_grade_receipt_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_FOLLOWTHROUGH_REPORT_REL).name).resolve(), carrier_followthrough)

    return {
        "promotion_candidate_receipt": promotion_candidate_receipt,
        "followthrough_packet": followthrough_packet,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Prepare Cohort-0 promotion/merge follow-through after tournament execution.")
    ap.add_argument(
        "--execution-report",
        default=DEFAULT_EXECUTION_REPORT_REL,
        help=f"Tracked tournament execution report path. Default: {DEFAULT_EXECUTION_REPORT_REL}",
    )
    ap.add_argument(
        "--authoritative-root",
        default="",
        help="Optional authoritative output root. Default: authoritative tournament execution receipt parent.",
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
    execution_report_path = _resolve_path(root, str(args.execution_report))
    authoritative_root = _resolve_path(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None
    reports_root = _resolve_path(root, str(args.reports_root))
    payload = run_promotion_merge_followthrough_tranche(
        execution_report_path=execution_report_path,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=root,
    )
    promotion = payload["promotion_candidate_receipt"]
    follow = payload["followthrough_packet"]
    print(
        json.dumps(
            {
                "status": promotion["status"],
                "candidate_adapter_id": promotion["candidate"]["adapter_id"],
                "followthrough_posture": follow["followthrough_posture"],
                "next_lawful_move": follow["merge_followthrough"]["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
