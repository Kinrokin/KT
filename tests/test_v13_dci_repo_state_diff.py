from __future__ import annotations

from g32_test_utils import ROOT, load_json


def test_v13_dci_and_repo_state_diff_bind_expected_outputs() -> None:
    dci = load_json("reports/v13_dci_trace_receipt.json")
    contract = load_json("reports/v13_repo_state_diff_contract.json")
    registry_delta = load_json("registry/artifact_authority_registry_v13_admission_delta_receipt.json")

    assert dci["direct_corpus_interaction_pass"] is True
    assert contract["next_lawful_move"] == "RUN_KTG3FULL_V13_CANONICAL_SPECIALIST_ROUTED_BENCH_PACKET"
    assert contract["claim_ceiling_unchanged"] is True
    for rel in contract["expected_files"]:
        assert (ROOT / rel).exists(), rel
    assert registry_delta["claim_ceiling_unchanged"] is True
    assert registry_delta["production_commercial_external_superiority_authority_added"] is False
