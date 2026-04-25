from __future__ import annotations

from pathlib import Path

from tools.operator.b02_runtime_unify_t5_validate import (
    build_b02_runtime_unify_t5_outputs,
    build_b02_runtime_unify_t5_receipt,
)
from tools.operator.titanium_common import repo_root


def test_build_b02_runtime_unify_t5_outputs_passes_on_live_repo(tmp_path: Path) -> None:
    root = repo_root()
    outputs = build_b02_runtime_unify_t5_outputs(
        root=root,
        export_root=tmp_path / "exports",
        c017_telemetry_path=tmp_path / "c017_telemetry.jsonl",
        w1_telemetry_path=tmp_path / "w1_telemetry.jsonl",
    )

    assert outputs["promotion_civilization_ratification_receipt"]["status"] == "PASS"
    assert outputs["b02_runtime_unify_t5_receipt"]["status"] == "PASS"
    assert outputs["b02_runtime_unify_t5_receipt"]["entry_gate_status"] is True
    assert outputs["b02_runtime_unify_t5_receipt"]["exit_gate_status"] is True
    assert outputs["b02_runtime_unify_t5_receipt"]["resolution_path"] in {
        "PATH_A_CLEAR_WITHIN_B02",
        "PATH_B_RECLASSIFY_OUT_OF_B02",
    }
    assert outputs["b02_runtime_unify_t5_receipt"]["forbidden_claims_remaining"]


def test_build_b02_runtime_unify_t5_receipt_opens_exit_only_when_board_gate_is_open() -> None:
    t4_receipt = {"status": "PASS", "entry_gate_status": True}
    ratification_receipt = {"status": "PASS"}
    execution_board = {"program_gates": {"PROMOTION_CIVILIZATION_RATIFIED": True}}

    receipt = build_b02_runtime_unify_t5_receipt(
        head="abc123",
        execution_board=execution_board,
        t4_receipt=t4_receipt,
        ratification_receipt=ratification_receipt,
    )

    assert receipt["status"] == "PASS"
    assert receipt["execution_board_gate_status"] is True
    assert receipt["exit_gate_status"] is True
    assert receipt["next_lawful_move"] == "REASSESS_GATE_C_AUTHORIZATION_FROM_EXECUTION_BOARD"


def test_build_b02_runtime_unify_t5_receipt_reclassifies_subject_mismatch_out_of_b02() -> None:
    t4_receipt = {"status": "PASS", "entry_gate_status": True}
    ratification_receipt = {"status": "PASS"}
    execution_board = {
        "program_gates": {"PROMOTION_CIVILIZATION_RATIFIED": False},
        "constitutional_domains": [
            {
                "domain_id": "DOMAIN_2_PROMOTION_CIVILIZATION",
                "active_blockers": [
                    "KT_PROD_CLEANROOM/reports/promotion_civilization_ratification_receipt.json validated_head_sha=abc123 != oldsubject",
                    "KT_PROD_CLEANROOM/reports/promotion_receipt.json validated_head_sha=abc123 != oldsubject",
                    "KT_PROD_CLEANROOM/reports/rollback_plan_receipt.json validated_head_sha=abc123 != oldsubject",
                    "KT_PROD_CLEANROOM/reports/risk_ledger_receipt.json validated_head_sha=abc123 != oldsubject",
                    "KT_PROD_CLEANROOM/reports/revalidation_receipt.json validated_head_sha=abc123 != oldsubject",
                    "KT_PROD_CLEANROOM/reports/zone_crossing_receipt.json validated_head_sha=abc123 != oldsubject",
                ],
            }
        ],
    }

    receipt = build_b02_runtime_unify_t5_receipt(
        head="abc123",
        execution_board=execution_board,
        t4_receipt=t4_receipt,
        ratification_receipt=ratification_receipt,
    )

    assert receipt["status"] == "PASS"
    assert receipt["execution_board_gate_status"] is False
    assert receipt["gate_c_authorized"] is False
    assert receipt["resolution_path"] == "PATH_B_RECLASSIFY_OUT_OF_B02"
    assert receipt["exit_gate_status"] is True
    assert receipt["next_lawful_move"] == "HOLD_GATE_C_CLOSED_CARRY_PROMOTION_CIVILIZATION_RATIFICATION_FORWARD"
