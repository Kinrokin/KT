from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_recomposed_r5_router_proof_tranche as tranche

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def test_recomposed_r5_router_proof_tranche_detects_material_advance_without_overclaim(tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    authoritative_root = tmp_path / "authoritative"
    subject_head = "5f1fb07200fe8fcbce57ef1ed92d1189ab571c91"

    bridge = tmp_path / "cohort0_recomposed_router_shadow_bridge_receipt.json"
    shadow = tmp_path / "cohort0_recomposed_router_shadow_eval_matrix.json"
    health = tmp_path / "cohort0_recomposed_route_distribution_health.json"
    scorecard = tmp_path / "cohort0_recomposed_router_superiority_scorecard.json"
    pre_health = tmp_path / "route_distribution_health.json"
    pre_scorecard = tmp_path / "router_superiority_scorecard.json"

    _write_json(bridge, {"status": "PASS", "subject_head": subject_head, "r5_admissible": True})
    _write_json(shadow, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        health,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "route_distribution_delta_count": 34,
            "exact_path_universality_broken": True,
            "shadow_match_rate": 0.1282,
            "route_collapse_detected": False,
            "unique_route_targets": ["lobe.alpha.v1", "lobe.p2.v1", "lobe.beta.v1"],
        },
    )
    _write_json(
        scorecard,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "router_superiority_earned": False,
            "r5_admissible": True,
            "best_static_baseline": {"adapter_id": "lobe.alpha.v1"},
        },
    )
    _write_json(pre_health, {"status": "PASS", "subject_head": subject_head, "route_distribution_delta_count": 0, "shadow_match_rate": 1.0})
    _write_json(pre_scorecard, {"status": "PASS", "subject_head": subject_head})

    payload = tranche.run_recomposed_r5_router_proof_tranche(
        bridge_receipt_path=bridge,
        shadow_matrix_path=shadow,
        health_report_path=health,
        scorecard_path=scorecard,
        pre_kaggle_health_path=pre_health,
        pre_kaggle_scorecard_path=pre_scorecard,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    ordered = payload["router_ordered_proof_receipt"]
    receipt = payload["router_vs_best_adapter_proof_receipt"]

    assert ordered["status"] == "PASS"
    assert ordered["material_advance_detected"] is True
    assert ordered["verdict_posture"] == tranche.VERDICT_MATERIAL_ADVANCE
    assert receipt["status"] == "PASS"
    assert receipt["verdict_posture"] == tranche.VERDICT_MATERIAL_ADVANCE
    assert receipt["router_proof_summary"]["router_superiority_earned"] is False
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE_RESIDUAL

    tracked = json.loads((reports_root / "cohort0_recomposed_router_vs_best_adapter_proof_receipt.json").read_text(encoding="utf-8"))
    assert tracked["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTER_VS_BEST_ADAPTER_PROOF_RECEIPT"
