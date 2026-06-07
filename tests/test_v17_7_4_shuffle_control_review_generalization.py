import json

import pytest
from scripts import build_v17_7_4_shuffle_control_review_generalization as builder


def require_assessment():
    path, sha, assessment = builder.load_assessment()
    if path is None:
        pytest.skip("measured shuffle-control assessment ZIP is not available in this environment")
    return path, sha, assessment


def test_loads_measured_shuffle_assessment_and_binds_runtime():
    path, sha, assessment = require_assessment()
    assert sha == "8eafb3faa6616af12ccb1817af8569af6cff418ec632671fccbc6a194877f962"

    runtime = builder.runtime_binding(sha, None, assessment)
    scorecard = builder.scorecard_binding(assessment)

    assert runtime["status"] == "PASS"
    assert runtime["row_count"] == 50
    assert runtime["runner_exit_code"] == 0
    assert runtime["tokenized_input_hash_match_count"] == 50
    assert runtime["difference_owner"] == "NONE"
    assert runtime["not_heldout_generalization"] is True
    assert scorecard["correct_count"] == 41
    assert scorecard["full_prompt_plus_output_tokens_per_correct"] == 145.121951
    assert scorecard["visible_answer_tokens_per_correct"] == 1.219512


def test_telemetry_review_computes_negative_control_rate_but_keeps_elv_proxy_only():
    _, sha, assessment = require_assessment()
    telemetry = builder.telemetry_reviews(assessment)

    halt = telemetry["v17_7_4_shuffle_epc_negative_control_halt_rate_runtime_update.json"]
    elv = telemetry["v17_7_4_shuffle_elv_proxy_runtime_update.json"]
    mfri = telemetry["v17_7_4_shuffle_mfri_runtime_update.json"]

    assert halt["status"] == "MEASURED_FROM_RUNTIME_NEGATIVE_CONTROL_RECEIPT"
    assert halt["negative_control_count"] == 5
    assert halt["false_pass_count"] == 0
    assert halt["halt_rate"] == 1.0
    assert elv["status"] == "PROXY_ONLY"
    assert elv["true_latent_variance_measured"] is False
    assert mfri["training_authorized"] is False


def test_stability_court_supports_shuffle_only_not_generalization():
    _, sha, assessment = require_assessment()
    court = builder.stability_court(assessment)

    stability = court["v17_7_4_reprolock_shuffle_stability_court.json"]
    hardcoded = court["v17_7_4_reprolock_not_hardcoded_evidence_receipt.json"]

    assert stability["status"] == "SHUFFLE_STABILITY_SUPPORTED"
    assert stability["not_heldout_generalization"] is True
    assert stability["overclaim_blocked"] is True
    assert hardcoded["status"] == "SUPPORTED_NOT_PROVEN"


def test_diagnostic_sources_do_not_bind_as_generalization_sources():
    sources = builder.generalization_source_receipts()
    binding = sources["v17_7_4_generalization_row_source_binding_receipt.json"]
    search = sources["v17_7_4_generalization_row_source_search_receipt.json"]

    if binding["status"] == "BOUND":
        assert binding["row_count"] == 50
        assert binding["bound_source"] == "admission/v17_7_4_reprolock_heldout_row_manifest.json"
    else:
        assert binding["status"] == "NOT_BOUND_WITH_SEARCH_RECEIPT"
        assert binding["row_count"] == 0
    candidates = {candidate["path"]: candidate for candidate in search["candidates"]}
    truegen = candidates["admission/v17_7_4_truegen_row_manifest.json"]
    boundary = candidates["admission/v17_7_3_targeted_boundary_row_manifest.json"]
    assert "expected_answer_hash_not_bound_for_all_rows" in truegen["defects"]
    assert "diagnostic_not_generalization_source" in truegen["defects"]
    assert "training_search_not_generalization_source" in boundary["defects"]


def test_builder_emits_no_packet_without_lawful_source():
    require_assessment()
    assert builder.main() == 0
    summary = json.loads((builder.ROOT / "reports" / "v17_7_4_shuffle_control_review_generalization_builder_summary.json").read_text())

    assert summary["status"] == "PASS"
    if summary["generalization_row_source_binding_status"] == "BOUND":
        assert summary["selected_next_lane"] == "RUN_REPROLOCK_GENERALIZATION_PROBE_50"
        assert summary["next_lawful_move"] == "RUN_REPROLOCK_GENERALIZATION_PROBE_50"
    else:
        assert summary["generalization_row_source_binding_status"] == "NOT_BOUND_WITH_SEARCH_RECEIPT"
        assert summary["selected_next_lane"] == "ACQUIRE_HELDOUT_ROW_SOURCE"
        assert summary["packet_path_if_any"] is None
        assert summary["next_lawful_move"] == "ACQUIRE_OR_AUTHOR_HELDOUT_ROW_SOURCE"
    assert summary["claim_ceiling_status"] == "PRESERVED"
