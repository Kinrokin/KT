from __future__ import annotations

import json
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_unified_convergence_anchor_matches_current_head_truth_surfaces() -> None:
    root = _repo_root()
    anchor = _load_json(
        root
        / "KT_PROD_CLEANROOM"
        / "governance"
        / "kt_unified_convergence_max_power_campaign_v2_1_1_anchor.json"
    )
    blocker_matrix = _load_json(
        root / "KT_PROD_CLEANROOM" / "reports" / "kt_wave5_blocker_matrix.json"
    )
    readjudication = _load_json(
        root
        / "KT_PROD_CLEANROOM"
        / "reports"
        / "kt_wave5_final_readjudication_receipt.json"
    )
    tier_ruling = _load_json(
        root / "KT_PROD_CLEANROOM" / "reports" / "kt_wave5_final_tier_ruling.json"
    )
    truth_map = _load_json(
        root
        / "KT_PROD_CLEANROOM"
        / "reports"
        / "kt_unified_convergence_current_truth_map.json"
    )
    router_receipt = _load_json(
        root
        / "KT_PROD_CLEANROOM"
        / "reports"
        / "post_wave5_c005_router_ratification_receipt.json"
    )

    assert anchor["schema_id"] == "kt.unified_convergence.work_order_anchor.v2"
    assert anchor["work_order_id"] == "KT_UNIFIED_CONVERGENCE_MAX_POWER_CAMPAIGN_V2_1_1_FINAL"
    assert anchor["work_order_id"] == readjudication["work_order_id"] == truth_map["work_order_id"]
    assert anchor["mode"] == "ONE_CURRENT_HEAD_REALITY_ONE_CANONICAL_BLOCKER_MAP_ONE_CLAIM_CEILING_ONE_DAG_SERIALIZED_PROMOTION"

    closed = set(anchor["current_head_posture"]["current_head_canonical_closed"])
    assert {
        "C007_CANONICAL_RUNTIME_IMPORT_INSTALL_LANE",
        "C016A_CANONICAL_SAME_HOST_LIVE_HASHED_AUTHENTICATED_SUCCESS_LANE",
        "C016B_CANONICAL_SAME_HOST_LIVE_HASHED_RESILIENCE_REPEATABILITY_LANE",
        "CAMPAIGN_C005_ROUTER_CLOSED_BY_HONEST_STATIC_ROUTER_RATIFICATION_HOLD",
    }.issubset(closed)

    assert anchor["current_head_posture"]["current_head_open_canonical_blockers"] == [
        "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"
    ]
    assert blocker_matrix["open_blocker_count"] == 1
    assert blocker_matrix["open_blockers"][0]["blocker_id"] == "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"
    assert readjudication["remaining_open_contradictions"] == [
        "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"
    ]
    assert tier_ruling["remaining_open_contradictions"] == [
        "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"
    ]

    assert anchor["current_authorized_scope"]["authoritative_track"] == "C006 only"
    assert "ROUTER_SUPERIORITY_AND_MULTI_LOBE_PROMOTION" in anchor["current_head_posture"][
        "active_governed_advancement_objectives"
    ]
    assert router_receipt["current_head_blocker_status"] == "CLOSED"
    assert router_receipt["continuing_governed_objective"]["abandonment_status"] == "NOT_ABANDONED"
    assert "not abandon" in anchor["execution_state"]["router_boundary"].lower()
    assert "not abandonment" in truth_map["truth_partitions"]["current_head_runtime_truth"][
        "advancement_boundary"
    ].lower()

    bindings = anchor["surface_bindings"]
    assert bindings["blocker_matrix"] == "KT_PROD_CLEANROOM/reports/kt_wave5_blocker_matrix.json"
    assert bindings["final_readjudication_receipt"] == "KT_PROD_CLEANROOM/reports/kt_wave5_final_readjudication_receipt.json"
    assert bindings["router_ratification_receipt"] == "KT_PROD_CLEANROOM/reports/post_wave5_c005_router_ratification_receipt.json"
