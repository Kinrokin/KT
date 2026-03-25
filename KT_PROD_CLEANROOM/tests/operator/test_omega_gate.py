from __future__ import annotations

from tools.operator import omega_gate
from tools.operator.omega_gate import (
    build_authority_supersession_map,
    build_current_head_truth_lock,
    build_omega_gate_receipt,
    build_report_authority_index,
)
from tools.operator.titanium_common import repo_root


def test_current_head_truth_lock_builds_against_live_repo() -> None:
    lock = build_current_head_truth_lock(root=repo_root())
    assert lock["status"] == "PASS"
    assert lock["active_blocker_matrix_ref"].endswith("kt_wave5_blocker_matrix.json")
    assert "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED" in lock["active_open_blocker_ids"]
    assert lock["active_deferred_blocker_ids"] == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"]
    assert lock["deferred_blocker_alignment_status"] == "PASS"
    assert lock["claim_ceiling_enforcements"]["externality_class_max"] == "E1_SAME_HOST_DETACHED_REPLAY"
    assert lock["claim_ceiling_enforcements"]["comparative_widening"] == "FORBIDDEN"
    assert lock["claim_ceiling_enforcements"]["commercial_widening"] == "FORBIDDEN"
    assert lock["authority_resolution_status"] == "PASS"
    assert lock["historical_claim_firewall_status"] == "ACTIVE"
    assert lock["authority_resolution_index_ref"].endswith("authority_resolution_index.json")
    assert lock["historical_claim_firewall_ref"].endswith("historical_claim_firewall.json")
    assert lock["press_ready"] is False


def test_report_authority_index_has_one_active_blocker_family() -> None:
    index = build_report_authority_index(root=repo_root())
    blocker_rows = [row for row in index["rows"] if row["function_id"] == "blocker_matrix"]
    assert len(blocker_rows) == 1
    assert blocker_rows[0]["authority_status"] == "ACTIVE_CURRENT_HEAD_WORKTREE_FAMILY"
    deferred_rows = [row for row in index["rows"] if row["function_id"] == "deferred_blocker_register"]
    assert len(deferred_rows) == 1
    assert deferred_rows[0]["authority_status"] == "ACTIVE_CURRENT_HEAD_SUPPORT_REGISTER"


def test_omega_gate_receipt_and_supersession_map_compile() -> None:
    gate = build_omega_gate_receipt(root=repo_root())
    supersession = build_authority_supersession_map(root=repo_root())
    assert gate["status"] == "PASS"
    assert gate["active_blocker_family"] == "WAVE5_CURRENT_HEAD_WORKTREE_FAMILY"
    assert gate["authority_resolution_index_ref"].endswith("authority_resolution_index.json")
    assert gate["historical_claim_firewall_ref"].endswith("historical_claim_firewall.json")
    assert supersession["status"] == "PASS"
    assert any(row["function_id"] == "blocker_matrix" for row in supersession["rows"])
    assert any(row["function_id"] == "historical_claim_firewall" for row in supersession["rows"])


def test_selected_family_accepts_publication_carrier_of_validated_subject(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(omega_gate, "_git_head", lambda root: "carrier456")
    monkeypatch.setattr(
        omega_gate,
        "_current_truth_head_context",
        lambda root: {
            "validated_subject_head_sha": "subject123",
            "publication_carrier_head_sha": "carrier456",
            "head_relation": "PUBLICATION_CARRIER_OF_VALIDATED_SUBJECT",
        },
    )

    def fake_load_optional(root, rel):
        if rel == omega_gate.WAVE5_READJUDICATION_REL:
            return {"status": "PASS", "compiled_head_commit": "subject123"}
        if rel == omega_gate.WAVE5_BLOCKER_REL:
            return {"status": "PASS"}
        return {}

    monkeypatch.setattr(omega_gate, "_load_optional", fake_load_optional)
    family = omega_gate._selected_family(tmp_path)

    assert family["family_id"] == "WAVE5_CURRENT_HEAD_WORKTREE_FAMILY"
    assert family["validated_subject_head_sha"] == "subject123"
    assert family["publication_carrier_head_sha"] == "carrier456"
