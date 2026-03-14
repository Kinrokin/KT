from __future__ import annotations

from tools.operator.titanium_common import repo_root
from tools.operator.ws0_ws11_closeout import (
    build_closeout_blocker_register,
    build_closeout_proof_class_ladder,
    build_closeout_receipt_index,
    build_closeout_summary,
)


def test_ws0_ws11_closeout_bundle_is_structurally_complete() -> None:
    root = repo_root()

    receipt_index = build_closeout_receipt_index(root=root)
    blocker_register = build_closeout_blocker_register(root=root)
    proof_ladder = build_closeout_proof_class_ladder(root=root)
    summary = build_closeout_summary(root=root)

    assert receipt_index["schema_id"] == "kt.operator.ws0_ws11_closeout_receipt_index.v1"
    assert len(receipt_index["workstream_index"]) == 12
    assert {row["workstream_id"] for row in receipt_index["workstream_index"]} == {
        "WS0",
        "WS1",
        "WS2",
        "WS3",
        "WS4",
        "WS5",
        "WS6",
        "WS7",
        "WS8",
        "WS9",
        "WS10",
        "WS11",
    }
    assert any(row["artifact_ref"].endswith("frontier_settlement_receipt.json") for row in receipt_index["artifact_index"])
    assert any(row["artifact_ref"].endswith("public_verifier_manifest.json") for row in receipt_index["artifact_index"])

    assert blocker_register["schema_id"] == "kt.operator.ws0_ws11_closeout_blocker_register.v1"
    assert blocker_register["remaining_blockers"]
    assert blocker_register["resolved_blockers"]
    assert {row["blocker_id"] for row in blocker_register["remaining_blockers"]} >= {
        "PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED",
        "AUTHORITY_CONVERGENCE_UNRESOLVED",
        "H1_ACTIVATION_GATE_CLOSED",
    }

    assert proof_ladder["schema_id"] == "kt.operator.ws0_ws11_closeout_proof_class_ladder.v1"
    assert len(proof_ladder["levels"]) == 12
    assert [row["rank"] for row in proof_ladder["levels"]] == list(range(1, 13))
    assert any(row["proof_class_id"] == "FRONTIER_SETTLEMENT_WITH_H1_BLOCK" for row in proof_ladder["levels"])
    assert any(row["proof_class_id"] == "H1_SINGLE_ADAPTER_ALLOWED" for row in proof_ladder["levels"])

    assert summary["schema_id"] == "kt.operator.ws0_ws11_closeout_summary.v1"
    assert summary["closeout_verdict"] == "SEALED_WITH_OPEN_BLOCKERS"
    assert summary["proven"]
    assert summary["not_proven"]
    assert any("transparency-verified truth subject" in row["statement"] for row in summary["proven"])
    assert any("H1 is not allowed" in row["statement"] for row in summary["not_proven"])
