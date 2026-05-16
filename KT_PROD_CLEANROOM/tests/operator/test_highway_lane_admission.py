from __future__ import annotations

from tools.operator import highway_common as highway


def test_lane_admission_maps_canonical_runtime_work_to_canonical_runtime():
    decision = highway.classify_lane({"operator_intent": "change safe-run", "touches_canonical_runtime": True})
    assert decision["selected_superlane"] == "CANONICAL_RUNTIME"


def test_lane_admission_maps_commercial_claims_to_commercial_delivery():
    decision = highway.classify_lane({"operator_intent": "prepare commercial claim surface", "touches_commercial_surface": True})
    assert decision["selected_superlane"] == "COMMERCIAL_DELIVERY"


def test_lane_admission_maps_freeze_events_to_emergency_lane():
    decision = highway.classify_lane({"operator_intent": "freeze a posture contradiction", "risk_class": "EMERGENCY"})
    assert decision["selected_superlane"] == "EMERGENCY_AND_FREEZE"


def test_lane_admission_maps_adapter_router_lobe_to_adaptive_lane():
    decision = highway.classify_lane({"operator_intent": "router and lobe prep", "touches_lab_or_archive": True})
    assert decision["selected_superlane"] == "LAB_AND_ADAPTIVE_RATIFICATION"


def test_lane_admission_blocks_ambiguous_scope():
    decision = highway.classify_lane({})
    assert decision["decision"] == "BLOCK_SCOPE_AMBIGUOUS"
    assert decision["blocked"] is True
