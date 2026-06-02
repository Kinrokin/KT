from tests.v17_7_3_utils import assert_no_authority, read_json


def test_v17_7_3_noise_bounds_block_invalid_perturbations() -> None:
    receipt = read_json("reports/v17_7_3_noise_bounds_receipt.json")
    perturbations = read_json("reports/v17_7_3_perturbation_suite_manifest.json")
    assert receipt["invalid_perturbation_block"] is True
    assert "gold_answer_change" in perturbations["invalid_perturbations_blocked"]
    assert_no_authority(receipt)
    assert_no_authority(perturbations)
