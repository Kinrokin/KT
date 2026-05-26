from __future__ import annotations

from pathlib import Path

from g32_test_utils import ROOT, load_json


def test_repo_state_diff_contract_expected_surfaces_exist_and_forbidden_paths_scoped() -> None:
    contract = load_json("reports/repo_state_diff_contract.json")

    assert contract["schema_id"] == "kt.repo_state_diff_contract.v1"
    assert contract["claim_ceiling_unchanged"] is True
    assert contract["artifact_registry_updated"] is True
    assert contract["next_lawful_move"] == "RUN_KTG3FULL_V12_SPECIALIST_ROUTING_PACKET"
    for rel in contract["expected_files"]:
        assert (ROOT / rel).exists(), rel
    assert "commercial/" in contract["forbidden_paths"]
    assert not Path("commercial/customer_safe_language_pack.md") in [Path(p) for p in contract["expected_files"]]
