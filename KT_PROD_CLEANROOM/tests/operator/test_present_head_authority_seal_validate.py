from __future__ import annotations

from tools.operator.omega_gate import build_authority_resolution_index, build_current_head_truth_lock, build_historical_claim_firewall
from tools.operator.present_head_authority_seal_validate import (
    build_authority_resolution_receipt,
    build_historical_claim_firewall_receipt,
    build_present_head_authority_seal_receipt,
)
from tools.operator.titanium_common import repo_root


def test_present_head_authority_seal_surfaces_compile() -> None:
    root = repo_root()
    authority_resolution = build_authority_resolution_index(root=root)
    historical_firewall = build_historical_claim_firewall(root=root)
    truth_lock = build_current_head_truth_lock(root=root)

    authority_resolution_receipt = build_authority_resolution_receipt(root=root, authority_resolution_index=authority_resolution)
    historical_firewall_receipt = build_historical_claim_firewall_receipt(root=root, historical_claim_firewall=historical_firewall)
    seal_receipt = build_present_head_authority_seal_receipt(
        root=root,
        current_head_truth_lock=truth_lock,
        authority_resolution_receipt=authority_resolution_receipt,
        historical_claim_firewall_receipt=historical_firewall_receipt,
    )

    assert authority_resolution["status"] == "PASS"
    assert historical_firewall["status"] == "ACTIVE"
    assert authority_resolution_receipt["status"] == "PASS"
    assert historical_firewall_receipt["status"] == "PASS"
    assert seal_receipt["status"] == "PASS"
    assert authority_resolution_receipt["documentary_compatibility_pointer_documentary_only"] is True
    assert truth_lock["authority_resolution_index_ref"].endswith("authority_resolution_index.json")
    assert truth_lock["historical_claim_firewall_ref"].endswith("historical_claim_firewall.json")
