from scripts import build_v17_7_4_heldout_or_shuffle_control_packet as builder


def test_adversarial_receipts_do_not_claim_hidden_latent_access():
    receipts = builder.adversarial_receipts("SHUFFLE_CONTROL_PACKET", heldout_bound=False)
    elv = receipts["v17_7_4_extraction_latent_variance_receipt.json"]

    assert elv["status"] == "DESIGN_ONLY_LATENT_TELEMETRY_NOT_AVAILABLE"
    assert elv["true_latent_variance_measured"] is False
    assert elv["proxy_only"] is True
    assert elv["promotion_authority"] is False


def test_epc_negative_control_halt_rate_is_runtime_required_and_fail_closed():
    receipts = builder.adversarial_receipts("SHUFFLE_CONTROL_PACKET", heldout_bound=False)
    halt_rate = receipts["v17_7_4_epc_negative_control_halt_rate_receipt.json"]

    assert halt_rate["status"] == "PASS_PLAN_RUNTIME_REQUIRED"
    assert halt_rate["epc_true_positive_halt_rate_formula"] == "blocked_negative_controls / total_negative_controls"
    assert halt_rate["runtime_blocks_if_any_negative_control_passes"] is True


def test_micro_furnace_readiness_index_does_not_authorize_training_or_v18():
    receipts = builder.adversarial_receipts("SHUFFLE_CONTROL_PACKET", heldout_bound=False)
    mfri = receipts["v17_7_4_micro_furnace_readiness_index_receipt.json"]

    assert mfri["status"] == "PASS_DESIGN_ONLY_NO_TRAINING_AUTHORITY"
    assert mfri["training_authorized"] is False
    assert mfri["v18_authorized"] is False
    assert mfri["runtime_authorized"] == "SHUFFLE_CONTROL_PACKET_ONLY"


def test_shuffle_gap_receipt_is_not_heldout_generalization_gap():
    receipts = builder.adversarial_receipts("SHUFFLE_CONTROL_PACKET", heldout_bound=False)
    gap = receipts["v17_7_4_heldout_generalization_gap_receipt.json"]

    assert gap["status"] == "SHUFFLE_STABILITY_GAP_ONLY_NOT_HELDOUT"
    assert gap["heldout_bound"] is False
    assert gap["heldout_generalization_claim"] is False


def test_spurious_correlation_receipt_names_dataset_shape_risk_without_authority():
    receipts = builder.adversarial_receipts("SHUFFLE_CONTROL_PACKET", heldout_bound=False)
    correlation = receipts["v17_7_4_spurious_structural_correlation_receipt.json"]

    assert correlation["status"] == "PASS_PLAN_RUNTIME_REQUIRED"
    assert correlation["route_superiority_claim"] is False
    assert "dataset-order/shuffle-position artifacts" in correlation["risks_checked"]
    assert correlation["claim_boundary"] == "No shuffle-control result may be described as held-out generalization."
