from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tools.operator import run_lobe_adapter_router_gpu_conversion_staging as staging
from tools.operator import run_bounded_forward_streams


def _copy_inputs(tmp_path: Path) -> None:
    root = staging.repo_root()
    required = {
        *staging.LIVE_INPUTS.values(),
        *staging.STALE_OR_PREP_ONLY_INPUTS.values(),
    }
    for raw in sorted(required):
        source = root / raw
        if not source.is_file():
            continue
        target = tmp_path / raw
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def test_gpu_conversion_staging_emits_ready_target_without_training(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    summary = staging.run(output_root=tmp_path)
    receipt = summary["staging_receipt"]

    assert receipt["selected_outcome"] == staging.TARGET_OUTCOME
    assert receipt["staging_passed"] is True
    assert receipt["training_execution_pending"] is True
    assert receipt["full_gpu_training_executed"] is False
    assert receipt["trained_weights_exist_claimed"] is False
    assert receipt["external_audit_accepted"] is False
    assert receipt["commercial_claim_authorized"] is False
    assert receipt["seven_b_amplification_proven"] is False
    assert receipt["category_leadership_claim_authorized"] is False
    assert receipt["beyond_sota_claim_authorized"] is False
    assert receipt["truth_engine_law_changed"] is False
    assert receipt["trust_zone_law_changed"] is False


def test_gpu_conversion_staging_outputs_required_deliverables(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    staging.run(output_root=tmp_path)

    for raw in staging.OUTPUTS.values():
        assert (tmp_path / raw).is_file(), raw


def test_gpu_conversion_cutline_binds_live_inputs_and_retires_stale_blockers(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    staging.run(output_root=tmp_path)
    cutline = _load(tmp_path / staging.OUTPUTS["cutline"])
    classification = _load(tmp_path / staging.OUTPUTS["classification"])

    assert cutline["missing_live_input_count"] == 0
    assert cutline["current_head_binding_semantics"].startswith("pre-staging live-input git head")
    assert cutline["artifact_commit_expected_after_write"] == "PENDING_COMMIT_OR_PR_HEAD"
    assert cutline["validation_must_recompute_live_input_hashes"] is True
    assert cutline["stale_inputs_control_gpu_campaign"] is False
    assert classification["stale_b04_r6_canary_blockers_control_gpu_campaign"] is False
    assert classification["branch_bound_artifacts_control_gpu_campaign"] is False
    assert "KT_PROD_CLEANROOM/reports/kt_lobe_abi_contract_prep_only.json" in classification["classes"][
        "STALE_OR_PREP_ONLY_NOT_CONTROLLING"
    ]


def test_lobes_and_adapters_require_recipe_eval_rollback_and_receipts(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    staging.run(output_root=tmp_path)
    lobes = _load(tmp_path / staging.OUTPUTS["lobe_target_matrix"])["lobes"]
    adapters = _load(tmp_path / staging.OUTPUTS["adapter_target_matrix"])["adapters"]

    assert lobes
    for lobe in lobes:
        assert lobe["requires_dataset_provenance"] is True
        assert lobe["requires_recipe"] is True
        assert lobe["requires_eval_gate"] is True
        assert lobe["requires_rollback"] is True
        assert lobe["requires_receipt"] is True
        assert lobe["production_authority_after_training"] is False

    assert adapters
    for adapter in adapters:
        assert adapter["requires_lineage_manifest"] is True
        assert adapter["requires_eval_receipt"] is True
        assert adapter["requires_tournament_entry_receipt"] is True
        assert adapter["requires_rollback_plan"] is True
        assert adapter["promotion_authorized_by_this_packet"] is False


def test_lora_and_qlora_are_explicitly_staged_without_claim_expansion(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    staging.run(output_root=tmp_path)
    matrix = _load(tmp_path / staging.OUTPUTS["recipe_matrix"])
    recipes = {recipe["recipe_id"]: recipe for recipe in matrix["recipes"]}

    assert matrix["qlora_either_staged_with_tests_or_excluded"] is True
    assert recipes["LORA_SMOKE_V1"]["first_campaign_status"] == "INCLUDED"
    assert recipes["QLORA_MEMORY_GATED_V1"]["first_campaign_status"] == "STAGED_WITH_SMOKE_TEST_NOT_REQUIRED_FOR_FIRST_PASS"
    assert recipes["QLORA_MEMORY_GATED_V1"]["requires_bitsandbytes_smoke_test"] is True
    assert recipes["QLORA_MEMORY_GATED_V1"]["fallback_recipe"] == "LORA_SMOKE_V1"
    assert matrix["seven_b_amplification_proven"] is False


def test_dataset_provenance_and_import_contract_are_required_before_execution(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    staging.run(output_root=tmp_path)
    dataset_manifest = _load(tmp_path / staging.OUTPUTS["dataset_manifest"])
    import_contract = _load(tmp_path / staging.OUTPUTS["import_contract"])
    kaggle_packet = _load(tmp_path / staging.OUTPUTS["kaggle_packet"])
    training_authorization = _load(tmp_path / staging.OUTPUTS["training_authorization"])

    assert dataset_manifest["dataset_without_provenance_allowed"] is False
    assert dataset_manifest["training_without_dataset_manifest_allowed"] is False
    assert all(dataset["blocks_training_if_missing"] for dataset in dataset_manifest["datasets"])
    assert training_authorization["full_training_authorized_by_this_packet"] is False
    assert training_authorization["kaggle_smoke_execution_ready_next"] is True
    assert training_authorization["kaggle_smoke_is_not_full_training"] is True
    assert import_contract["import_allowed_only_after_hashing"] is True
    assert import_contract["import_does_not_authorize_claims"] is True
    assert import_contract["training_execution_next_not_done"] is True
    required_outputs = set(kaggle_packet["required_outputs"])
    hash_bindings = {
        item["required_output"]: item["hash_field"]
        for item in import_contract["required_output_hash_bindings"]
    }
    assert set(hash_bindings) == required_outputs
    assert set(hash_bindings.values()).issubset(set(import_contract["required_import_fields"]))
    assert "training_run_receipt_hash" in import_contract["required_import_fields"]
    assert "candidate_provenance_hash" in import_contract["required_import_fields"]
    assert "router_trace_csv_hash" in import_contract["required_import_fields"]
    assert kaggle_packet["deterministic_seed"] == 1337
    assert kaggle_packet["cache_policy"]["reuse_cached_hf_downloads"] is True
    assert kaggle_packet["cache_policy"]["network_flaky_mode_supported"] is True
    assert kaggle_packet["time_limit_policy"]["safe_resume_required"] is True
    assert "artifact_import_hash_smoke" in kaggle_packet["execution_phases"]
    assert "/kaggle/working" in kaggle_packet["windows_to_linux_path_note"]
    assert "candidate_provenance.json" in kaggle_packet["required_outputs"]
    assert "negative_result_ledger.json" in kaggle_packet["required_outputs"]


def test_router_candidate_plan_binds_static_baseline_without_superiority_claim(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    staging.run(output_root=tmp_path)
    router_plan = _load(tmp_path / staging.OUTPUTS["router_plan"])
    static_baseline = _load(tmp_path / staging.OUTPUTS["static_baseline"])
    benchmark_gate = _load(tmp_path / staging.OUTPUTS["benchmark_gate"])

    assert router_plan["learned_router_activation_allowed"] is False
    assert router_plan["learned_router_superiority_claim_allowed"] is False
    assert router_plan["next_router_gate"] == "AUTHOR_B04_R6_LEARNED_ROUTER_CANDIDATE_SOURCE_FROM_GPU_ARTIFACTS"
    assert static_baseline["baseline_required"] == "best_static_adapter"
    assert static_baseline["router_candidate_must_beat_static_before_claim"] is True
    assert static_baseline["known_prior_r6_result"]["candidate_win_count"] == 0
    assert benchmark_gate["public_superiority_claim_allowed"] is False
    assert benchmark_gate["external_benchmarking_pending"] is True


def test_gpu_conversion_runbook_claim_scan_passes(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    staging.run(output_root=tmp_path)
    raw = staging.OUTPUTS["runbook"]
    text = (tmp_path / raw).read_text(encoding="utf-8-sig")

    assert run_bounded_forward_streams.scan_claim_text(text, source=raw) == []


def test_gpu_conversion_rejects_claim_boundary_drift(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    claim_path = tmp_path / staging.LIVE_INPUTS["claim_boundary"]
    claim_boundary = _load(claim_path)
    claim_boundary["commercial_claim_authorized"] = True
    claim_path.write_text(json.dumps(claim_boundary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="Claim boundary drift"):
        staging.run(output_root=tmp_path)


def test_gpu_conversion_rejects_duplicate_keys_in_authority_inputs(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    claim_path = tmp_path / staging.LIVE_INPUTS["claim_boundary"]
    claim_path.write_text(
        '{"schema_id":"x","commercial_claim_authorized":false,"commercial_claim_authorized":true}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate JSON key"):
        staging.run(output_root=tmp_path)


def test_gpu_conversion_blocks_missing_live_inputs(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    (tmp_path / staging.LIVE_INPUTS["training_eval_fabric"]).unlink()

    with pytest.raises(RuntimeError, match="GPU conversion staging blocked"):
        staging.run(output_root=tmp_path)
