from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_truth_engine_validator_schema_and_contradiction_taxonomy_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_validator_schema_and_taxonomy_packet_binds_emission_and_recompute_contract(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _write_json(
        reports / "cohort0_post_f_truth_engine_contradiction_validator_authority_packet.json",
        {
            "schema_id": "authority-packet",
            "status": "PASS",
            "authority_header": {"package_promotion_still_deferred": True},
        },
    )
    _write_json(
        reports / "cohort0_post_f_truth_engine_contradiction_validator_contract_packet.json",
        {
            "schema_id": "contract-packet",
            "status": "PASS",
        },
    )
    _write_json(
        reports / "cohort0_post_f_truth_engine_contradiction_validator_contract_receipt.json",
        {
            "schema_id": "contract-receipt",
            "status": "PASS",
            "next_lawful_move": "AUTHOR_POST_F_TRUTH_ENGINE_VALIDATOR_SCHEMA_AND_CONTRADICTION_TAXONOMY_PACKET",
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "main-head" if ref == "main" else "branch-head")
    monkeypatch.setattr(tranche, "_git_merge_base", lambda root, left, right: "main-head")

    result = tranche.run(
        reports_root=reports,
        authority_packet_path=reports / "cohort0_post_f_truth_engine_contradiction_validator_authority_packet.json",
        contract_packet_path=reports / "cohort0_post_f_truth_engine_contradiction_validator_contract_packet.json",
        contract_receipt_path=reports / "cohort0_post_f_truth_engine_contradiction_validator_contract_receipt.json",
    )

    assert result["outcome"] == tranche.OUTCOME
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
    assert len(packet["emission_surface_schemas"]) == 5
    assert len(packet["contradiction_taxonomy"]) == 7
    assert "validator_behavior" in packet
    assert "first_recompute_court" in packet
