from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_e1_bounded_campaign_cli_compiles_bounded_pack(tmp_path: Path, monkeypatch, capsys) -> None:
    root = _repo_root()
    sys.path.insert(0, str(root / "KT_PROD_CLEANROOM"))
    sys.path.insert(0, str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src"))
    from tools.operator import e1_bounded_campaign_validate as e1

    monkeypatch.setattr(e1, "_enforce_write_scope_pre", lambda _root: [])
    monkeypatch.setattr(
        e1,
        "_enforce_write_scope_post",
        lambda _root, *, prewrite_dirty, allowed_repo_writes: {
            "prewrite_dirty_paths": list(prewrite_dirty),
            "postwrite_dirty_paths": list(prewrite_dirty),
            "allowed_repo_writes": list(allowed_repo_writes),
            "unexpected_postwrite_paths": [],
            "undeclared_created_paths": [],
        },
    )

    commercial_truth_path = tmp_path / "commercial_truth.json"
    verifier_kit_path = tmp_path / "public_verifier_kit.json"
    second_host_kit_path = tmp_path / "second_host_kit.json"
    external_audit_path = tmp_path / "external_audit_packet.json"
    receipt_path = tmp_path / "receipt.json"
    tracked_t7_receipt = root / "KT_PROD_CLEANROOM" / "reports" / "comparator_side_reader_contract_adoption_receipt.json"
    tracked_t7_before = tracked_t7_receipt.read_text(encoding="utf-8") if tracked_t7_receipt.exists() else None

    result = e1.main(
        [
            "--commercial-truth-output",
            str(commercial_truth_path),
            "--public-verifier-kit-output",
            str(verifier_kit_path),
            "--second-host-kit-output",
            str(second_host_kit_path),
            "--external-audit-output",
            str(external_audit_path),
            "--receipt-output",
            str(receipt_path),
        ]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["status"] == "PASS"
    assert payload["externality_class_max"] == "E1_SAME_HOST_DETACHED_REPLAY"
    assert payload["comparative_widening"] == "FORBIDDEN"
    assert payload["commercial_widening"] == "FORBIDDEN"
    assert payload["second_host_kit_status"] in {"READY_PENDING_HARDWARE", "READY_STAGED_PENDING_HARDWARE"}
    assert payload["comparator_contract_status"] == "PASS"
    assert payload["side_reader_receipt_refresh_scope_status"] == "PASS"
    assert payload["side_reader_receipt_refresh_enabled"] is False
    if tracked_t7_before is None:
        assert tracked_t7_receipt.exists() is False
    else:
        assert tracked_t7_receipt.read_text(encoding="utf-8") == tracked_t7_before

    commercial_truth = json.loads(commercial_truth_path.read_text(encoding="utf-8"))
    verifier_kit = json.loads(verifier_kit_path.read_text(encoding="utf-8"))
    second_host_kit = json.loads(second_host_kit_path.read_text(encoding="utf-8"))
    external_audit = json.loads(external_audit_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

    assert commercial_truth["status"] == "PASS"
    assert commercial_truth["externality_class_max"] == "E1_SAME_HOST_DETACHED_REPLAY"
    assert commercial_truth["comparative_widening"] == "FORBIDDEN"
    assert commercial_truth["commercial_widening"] == "FORBIDDEN"
    assert "governed_execution" in commercial_truth["offer_surface"]
    assert "KT_PROD_CLEANROOM/docs/commercial/E1_DEMO_SCRIPT.md" in commercial_truth["buyer_safe_material_refs"]
    assert "KT_PROD_CLEANROOM/docs/operator/RUN_KT_IN_30_MINUTES.md" in commercial_truth["buyer_safe_material_refs"]
    assert "KT_PROD_CLEANROOM/product/one_page_product_truth_surface.md" in commercial_truth["buyer_safe_material_refs"]
    assert "KT_PROD_CLEANROOM/product/operator_runbook_v2.md" in commercial_truth["buyer_safe_material_refs"]
    assert len(commercial_truth["demo_flow"]) == 7
    assert commercial_truth["presales_flow"] == [
        "Diagnostic",
        "Demo",
        "Verifier handoff",
        "Proposal",
        "Bounded pilot",
    ]
    assert "buyer_simple_product_plane" in commercial_truth["offer_surface"]

    assert verifier_kit["status"] == "PASS"
    assert verifier_kit["kit_status"] == "BOUNDED_E1_READY"
    assert verifier_kit["operator_quickstart_ref"] == "KT_PROD_CLEANROOM/docs/operator/RUN_KT_IN_30_MINUTES.md"
    assert verifier_kit["client_wrapper_spec_ref"] == "KT_PROD_CLEANROOM/product/client_wrapper_spec.json"
    assert verifier_kit["support_boundary_ref"] == "KT_PROD_CLEANROOM/product/support_boundary.json"
    assert verifier_kit["expected_operator_time_budget_minutes"] == 15
    assert verifier_kit["pass_fail_surface"] == "CLEAR_PASS_FAIL_BOUNDARY"

    assert second_host_kit["status"] == "PASS"
    assert second_host_kit["kit_status"] in {"READY_PENDING_HARDWARE", "READY_STAGED_PENDING_HARDWARE"}
    assert any("build_c006_second_host_bundle" in cmd for cmd in [second_host_kit["bundle_builder_command"]])
    assert second_host_kit["deferral_status_receipt_ref"] == "KT_PROD_CLEANROOM/reports/c006_deferral_status_receipt.json"
    assert second_host_kit["second_host_kit_hardening_receipt_ref"] == "KT_PROD_CLEANROOM/reports/second_host_kit_hardening_receipt.json"

    assert external_audit["status"] == "PASS"
    assert external_audit["validated_head_sha"]
    assert "KT_PROD_CLEANROOM/docs/commercial/E1_DEMO_SCRIPT.md" in external_audit["packet_refs"]
    assert "KT_PROD_CLEANROOM/docs/operator/RUN_KT_IN_30_MINUTES.md" in external_audit["packet_refs"]
    assert "KT_PROD_CLEANROOM/reports/c006_deferral_status_receipt.json" in external_audit["packet_refs"]
    assert "KT_PROD_CLEANROOM/reports/second_host_kit_hardening_receipt.json" in external_audit["packet_refs"]
    assert "KT_PROD_CLEANROOM/reports/product_install_15m_receipt.json" in external_audit["packet_refs"]
    assert "KT_PROD_CLEANROOM/reports/operator_handoff_receipt.json" in external_audit["packet_refs"]
    assert "KT_PROD_CLEANROOM/reports/standards_mapping_receipt.json" in external_audit["packet_refs"]
    assert "KT_PROD_CLEANROOM/product/client_wrapper_spec.json" in external_audit["packet_refs"]
    assert "KT_PROD_CLEANROOM/product/one_page_product_truth_surface.md" in external_audit["packet_refs"]
    assert receipt["status"] == "PASS"
