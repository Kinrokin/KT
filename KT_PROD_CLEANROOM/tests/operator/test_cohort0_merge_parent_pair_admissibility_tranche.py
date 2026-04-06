from __future__ import annotations

import json
from pathlib import Path

from schemas.fl3_schema_common import sha256_hex_of_obj
from tools.operator import (
    cohort0_merge_child_eval_tranche,
    cohort0_merge_parent_pair_admissibility_tranche,
    cohort0_promotion_merge_followthrough_tranche,
)
from tools.training.fl3_factory.manifests import sha256_file as sha256_file_canonical

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_merge_child_eval_tranche import _run_authoritative_promotion_chain


ROOT = Path(__file__).resolve().parents[3]


def _write_json(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _rewrite_fixture_to_total_order(execution_root: Path, reports_root: Path) -> None:
    tracked_execution = reports_root / "cohort0_tournament_execution_receipt.json"
    tracked_execution_payload = json.loads(tracked_execution.read_text(encoding="utf-8"))
    authoritative_execution = Path(str(tracked_execution_payload["authoritative_tournament_execution_receipt_ref"]))
    execution_payload = json.loads(authoritative_execution.read_text(encoding="utf-8"))

    tournament_result_path = Path(str(execution_payload["tournament_result_ref"]))
    tournament_result = json.loads(tournament_result_path.read_text(encoding="utf-8"))
    ranked = cohort0_promotion_merge_followthrough_tranche._rank_entrants(tournament_result)

    ordered_hashes = [str(row["adapter_root_hash"]) for row in ranked]
    dominance_pairs = []
    for idx, dominant in enumerate(ordered_hashes):
        for dominated in ordered_hashes[idx + 1 :]:
            dominance_pairs.append(
                {
                    "dominant_adapter_root_hash": dominant,
                    "dominated_adapter_root_hash": str(dominated),
                }
            )
    tournament_result["champion_set"] = [ordered_hashes[0]]
    tournament_result["dominance_pairs"] = dominance_pairs
    _write_json(tournament_result_path, tournament_result)

    execution_payload["champion_count"] = 1
    execution_payload["champion_set"] = [ordered_hashes[0]]
    execution_payload["dominance_pair_count"] = len(dominance_pairs)
    _write_json(authoritative_execution, execution_payload)

    prep_packet_path = Path(str(execution_payload["source_prep_packet_ref"]))
    prep_packet = json.loads(prep_packet_path.read_text(encoding="utf-8"))
    entrants_root = Path(str(prep_packet["refs"]["tournament_entrants_root_ref"]))

    for idx, row in enumerate(ranked):
        adapter_root_hash = str(row["adapter_root_hash"])
        adapter_id = str(row["adapter_id"])
        adapter_version = str(row["adapter_version"])
        entrant_root = entrants_root / adapter_root_hash
        eval_path = entrant_root / "eval_report.json"
        job_dir_manifest_path = entrant_root / "job_dir_manifest.json"

        eval_report = json.loads(eval_path.read_text(encoding="utf-8"))
        eval_report["adapter_id"] = adapter_id
        eval_report["adapter_version"] = adapter_version
        eval_report["final_verdict"] = "PASS"
        eval_report["utility_floor_score"] = round(1.0 - (idx * 0.02), 3)
        eval_report["utility_floor_pass"] = True
        results = eval_report.setdefault("results", {})
        results["trace_present"] = True
        results["metric_probe_agreement"] = True
        eval_report["eval_id"] = sha256_hex_of_obj(
            eval_report,
            drop_keys={"created_at", "eval_id"},
        )
        _write_json(eval_path, eval_report)

        job_dir_manifest = json.loads(job_dir_manifest_path.read_text(encoding="utf-8"))
        files = job_dir_manifest.get("files") if isinstance(job_dir_manifest.get("files"), list) else []
        for item in files:
            if isinstance(item, dict) and str(item.get("path", "")).strip() == "eval_report.json":
                item["sha256"] = sha256_file_canonical(eval_path)
        job_dir_manifest["job_dir_manifest_id"] = sha256_hex_of_obj(
            job_dir_manifest,
            drop_keys={"created_at", "job_dir_manifest_id"},
        )
        _write_json(job_dir_manifest_path, job_dir_manifest)

    _ = cohort0_promotion_merge_followthrough_tranche.run_promotion_merge_followthrough_tranche(
        execution_report_path=tracked_execution,
        authoritative_root=execution_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )


def test_cohort0_merge_parent_pair_admissibility_tranche_binds_zero_pair_blocker(tmp_path: Path) -> None:
    execution_root, reports_root = _run_authoritative_promotion_chain(tmp_path)

    _ = cohort0_merge_child_eval_tranche.run_merge_child_eval_tranche(
        promotion_report_path=reports_root / "cohort0_promotion_candidate_receipt.json",
        followthrough_report_path=reports_root / "cohort0_real_engine_tournament_followthrough_packet.json",
        authoritative_root=execution_root / "merge_child_eval",
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    _rewrite_fixture_to_total_order(execution_root, reports_root)

    payload = cohort0_merge_parent_pair_admissibility_tranche.run_merge_parent_pair_admissibility_tranche(
        followthrough_report_path=reports_root / "cohort0_real_engine_tournament_followthrough_packet.json",
        promotion_report_path=reports_root / "cohort0_promotion_candidate_receipt.json",
        child_candidate_report_path=reports_root / "cohort0_merge_child_candidate_receipt.json",
        child_eval_report_path=reports_root / "cohort0_merge_child_evaluation_receipt.json",
        authoritative_root=execution_root / "merge_parent_pair_admissibility",
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    receipt = payload["merge_parent_pair_admissibility_receipt"]
    child_eval = payload["merge_child_evaluation_receipt"]
    followthrough = payload["followthrough_packet"]

    assert receipt["status"] == "PASS"
    assert receipt["admissibility_posture"] == "NO_ADMISSIBLE_PARENT_PAIR_EXISTS_ON_CURRENT_TOURNAMENT_GRAPH"
    assert receipt["admissible_parent_pair_count"] == 0
    assert receipt["non_champion_parent_pair_candidate_count"] == 66

    assert child_eval["evaluation_posture"] == "MERGE_CHILD_EVALUATED__NO_ADMISSIBLE_PARENT_PAIR_EXISTS_ON_CURRENT_TOURNAMENT_GRAPH"
    assert child_eval["next_lawful_move"] == "PREPARE_NEW_TOURNAMENT_GRAPH_OR_NEW_CHILD_CANDIDATE_BEFORE_MERGE_REENTRY"

    assert followthrough["followthrough_posture"] == "MERGE_CHILD_EVALUATED__NO_ADMISSIBLE_PARENT_PAIR_EXISTS_ON_CURRENT_TOURNAMENT_GRAPH"
    assert followthrough["merge_followthrough"]["admissible_parent_pair_count"] == 0
    assert followthrough["merge_followthrough"]["recommended_parent_seed_count"] == 0
    assert followthrough["merge_followthrough"]["attempted_parent_seed_count"] == 2
    assert "NO_ADMISSIBLE_PARENT_PAIR_EXISTS_ON_CURRENT_TOURNAMENT_GRAPH" in followthrough["merge_followthrough"]["blockers"]

    tracked_parent_pair = json.loads(
        (reports_root / "cohort0_merge_parent_pair_admissibility_receipt.json").read_text(encoding="utf-8")
    )
    tracked_child_eval = json.loads(
        (reports_root / "cohort0_merge_child_evaluation_receipt.json").read_text(encoding="utf-8")
    )
    tracked_followthrough = json.loads(
        (reports_root / "cohort0_real_engine_tournament_followthrough_packet.json").read_text(encoding="utf-8")
    )
    assert tracked_parent_pair["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_MERGE_PARENT_PAIR_ADMISSIBILITY_RECEIPT"
    assert tracked_child_eval["evaluation_posture"] == child_eval["evaluation_posture"]
    assert tracked_followthrough["followthrough_posture"] == followthrough["followthrough_posture"]
