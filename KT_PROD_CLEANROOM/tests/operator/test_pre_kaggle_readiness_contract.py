from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools.operator import pre_kaggle_readiness_contract as contract


ROOT = Path(__file__).resolve().parents[2]


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")


def _plan(tmp_path: Path) -> tuple[dict, Path]:
    source_root = tmp_path / "source"
    source_root.mkdir(exist_ok=True)
    packet_root = tmp_path / "packet-input"
    packet_root.mkdir(exist_ok=True)
    packet = packet_root / "exact_fixture.zip"
    packet.write_bytes(b"fixture packet bytes")

    stage_root = tmp_path / "canonical-stage"
    nested = stage_root / "nested"
    nested.mkdir(parents=True, exist_ok=True)
    prompt_manifest = nested / "prompt_manifest.json"
    prompt_manifest.write_bytes(b'{"fixture":"prompt manifest"}\n')
    adapter_marker = stage_root / "adapters" / "required_adapter.marker"
    adapter_marker.parent.mkdir(parents=True, exist_ok=True)
    adapter_marker.write_bytes(b"required adapter inventory marker\n")

    adapter_root = tmp_path / "adapter-input"
    adapter_dir = adapter_root / "learning_delta_lobe"
    adapter_dir.mkdir(parents=True, exist_ok=True)
    config = {
        "adapter_id": "learning_delta_lobe",
        "base_model_name_or_path": "Qwen/Qwen2.5-7B-Instruct",
        "base_model_revision": "a" * 40,
        "peft_type": "LORA",
        "target_modules": ["q_proj", "v_proj"],
    }
    config_path = adapter_dir / "adapter_config.json"
    _write_json(config_path, config)
    model_path = adapter_dir / "adapter_model.safetensors"
    model_path.write_bytes(b"fixture adapter weights")

    source_head = "b" * 40
    packet_sha = _digest(packet.read_bytes())
    plan = {
        "identity_planes": {
            "source": {"repo_head": source_head, "source_tree_sha256": "c" * 64},
            "artifact": {"adapter_manifest_sha256": "d" * 64, "adapter_identity": "learning-delta-v1"},
            "environment": {"environment_lock_sha256": "e" * 64, "toolchain_id": "declared-qwen-qlora"},
            "measurement": {
                "measurement_manifest_sha256": "f" * 64,
                "benchmark_selection_status": "UNSELECTED_FOR_EXPERIMENT",
            },
        },
        "packet_root": str(packet_root),
        "packet_selection": {
            "packet_name": packet.name,
            "packet_sha256": packet_sha,
            "source_head": source_head,
            "identity_mode": "CURRENT_EXPERIMENT",
            "requested_head": source_head,
            "subject_head": source_head,
            "current_git_head": source_head,
            "requested_head_remote_reachable": True,
            "packet_hash_scope": "EXTERNAL_MANIFEST",
            "manifest": {
                "packet_name": packet.name,
                "packet_sha256": packet_sha,
                "source_head": source_head,
                "self_referential_packet_hash": False,
            },
        },
        "adapter_root": str(adapter_root),
        "adapter": {
            "adapter_directory": adapter_dir.name,
            "adapter_config_filename": config_path.name,
            "adapter_model_filename": model_path.name,
            "adapter_config_sha256": _digest(config_path.read_bytes()),
            "adapter_model_sha256": _digest(model_path.read_bytes()),
            "adapter_id": config["adapter_id"],
            "base_model_name_or_path": config["base_model_name_or_path"],
            "base_model_revision": config["base_model_revision"],
            "peft_type": config["peft_type"],
            "target_modules": config["target_modules"],
        },
        "input_inventory": {
            "stage_root": str(stage_root),
            "expected_stage_root_name": stage_root.name,
            "required_inputs": [
                {
                    "logical_name": "prompt_manifest",
                    "relative_path": "nested/prompt_manifest.json",
                    "sha256": _digest(prompt_manifest.read_bytes()),
                },
                {
                    "logical_name": "adapter_marker",
                    "relative_path": "adapters/required_adapter.marker",
                    "sha256": _digest(adapter_marker.read_bytes()),
                },
            ],
        },
        "hf_transport": {
            "selected_source": "HF_VAULT",
            "secret_source": "KAGGLE_SECRETS",
            "token_printed": False,
            "token_available_to_runner": True,
            "live_route_available": True,
            "mounted_fallback_allowed": True,
            "transport_mode": "XET",
            "xet_failure_observed": False,
            "transport_fallback_policy": "CONDITIONAL_EXPLICIT",
            "dependency_conflict": False,
            "download_state": "COMPLETE",
            "cache_root": str(tmp_path / "external-hf-cache"),
        },
        "environment": {
            "python_version": "3.10.12",
            "pip_check_status": "PASS",
            "packages": {
                "torch": "2.2.0+cu121",
                "transformers": "4.39.3",
                "peft": "0.10.0",
                "bitsandbytes": "0.43.1",
            },
            "required_packages": {
                "torch": "2.2.0+cu121",
                "transformers": "4.39.3",
                "peft": "0.10.0",
                "bitsandbytes": "0.43.1",
            },
            "quantization_mode": "QLORA",
            "load_in_4bit": True,
            "cuda_available": True,
            "cuda_version": "12.1",
            "bitsandbytes_cuda_backend": "AVAILABLE",
        },
        "resource_controls": {
            "loader_api": "AutoModelForCausalLM.from_pretrained",
            "quantization_config_used": True,
            "legacy_load_in_4bit_kwarg_forwarded": False,
            "four_bit_linear_modules_present": True,
            "glibcxx_compatible": True,
            "process_isolation": "PROCESS_PER_ARM",
            "model_released_between_arms": True,
            "adapter_unloaded_between_arms": True,
            "memory_telemetry_enabled": True,
            "sequence_length": 96,
            "batch_size": 1,
            "max_sequence_length": 96,
            "max_batch_size": 1,
            "oom_policy": "PARTIAL_ASSESSMENT_ONLY",
        },
        "runtime_contract": {
            "expected_contract_filename": "runtime_contract.json",
            "contract_filename": "runtime_contract.json",
            "values": {
                "run_root": "/external/run",
                "output_root": "/external/output",
                "artifact_root": "/external/artifacts",
                "base_model_dir": "/external/base-model",
                "route_head_dir": "/external/route-head",
            },
            "legacy_aliases": {"full_run_root": "/external/run"},
            "artifact_status": "CREATED",
            "presentation_status": "FAILED_AFTER_ARTIFACT",
        },
        "output": {
            "output_root": str(tmp_path / "external-output"),
            "subtrees": list(contract.REQUIRED_OUTPUT_SUBTREES),
            "minimum_free_bytes": 1024,
            "assessment_includes": ["assessment_return/measurement_journal.jsonl", "assessment_return/summary.json"],
        },
        "runner": {"runner_file": "runtime/future_kaggle_runner.py", "runner_file_sha256": "1" * 64},
        "supervision": {
            "rows": [
                {
                    "sample_id": "train-1",
                    "prompt": "What is two plus two?",
                    "target": "4",
                    "family": "formal_math",
                    "source": "fixture",
                    "action": "solve",
                    "audited_object_sha256": "2" * 64,
                    "training_object_sha256": "2" * 64,
                }
            ]
        },
        "measurement": {
            "manifest_kind": "BENCHMARK",
            "measurement_authority": "PLAN_ONLY",
            "requested_row_count": 1,
            "prompt_template_sha256": "3" * 64,
            "scorer_sha256": "4" * 64,
            "normalizer_sha256": "5" * 64,
            "finalizer_sha256": "6" * 64,
            "generation_config_sha256": "7" * 64,
            "seed_policy_sha256": "8" * 64,
            "rows": [
                {
                    "sample_id": "measurement-1",
                    "question_text": "What is two plus two?",
                    "source_row_sha256": "9" * 64,
                    "expected_answer_sha256": "a" * 64,
                    "expected_answer_visible_to_model": False,
                }
            ],
        },
        "scorecard": {
            "rows": [
                {
                    "sample_id": "measurement-1",
                    "decision_sample_id": "measurement-1",
                    "prediction_sample_id": "measurement-1",
                    "decision_correct": True,
                    "prediction_correct": True,
                }
            ],
            "row_count": 1,
            "correct_count": 1,
            "accuracy": 1.0,
            "frozen_source_reuse": False,
        },
        "claim_ceiling": {
            "evidence_mode": "SIMULATION_ONLY",
            "result_status": "STATIC_PREFLIGHT_PASS",
            "claims": {
                "fresh_generation": False,
                "performance_superiority": False,
                "promotion": False,
                "external_authority": False,
                "commercial_authority": False,
            },
            "hf_upload_observed": False,
            "mandatory_gates": [{"gate_id": "static-preflight", "required": True, "status": "PASS"}],
        },
        "finalization_payload": {"status": "static", "rows": ["measurement-1"]},
        "execution": {flag: False for flag in contract.EXECUTION_FLAGS},
    }
    return plan, source_root


def _expect(code: str, call, *args, **kwargs) -> None:
    with pytest.raises(contract.PreflightViolation, match=code):
        call(*args, **kwargs)


def test_governance_contract_is_static_and_execution_ceiling_is_explicit() -> None:
    policy = json.loads((ROOT / "governance" / "pre_kaggle_runtime_contract.json").read_text(encoding="utf-8"))
    assert policy["schema_id"] == contract.SCHEMA_ID
    assert policy["status"] == "ACTIVE_STATIC_CONTROL_PLANE_ONLY"
    assert policy["execution_ceiling"]["model_inference_invoked"] is False
    assert policy["execution_ceiling"]["training_invoked"] is False
    assert policy["execution_ceiling"]["kaggle_execution_authorized"] is False
    assert policy["execution_ceiling"]["final_benchmark_selection_authorized"] is False


def test_positive_preflight_is_static_and_nonexecuting(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    result = contract.evaluate_static_preflight(plan, source_root=source_root, available_bytes=1024)

    assert result["status"] == contract.PASS_STATUS
    assert result["packet"]["packet_name"] == "exact_fixture.zip"
    assert result["adapter"]["adapter_directory"] == "learning_delta_lobe"
    assert result["simulation_only"] is True
    assert result["model_inference_invoked"] is False
    assert result["training_invoked"] is False
    assert result["kaggle_execution_authorized"] is False
    assert result["final_benchmark_selected"] is False


def test_source_head_mismatch_fails_before_any_other_effect(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    plan["packet_selection"]["source_head"] = "0" * 40
    plan["packet_selection"]["manifest"]["source_head"] = "0" * 40

    _expect("SOURCE_HEAD_MISMATCH", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_exact_packet_discovery_rejects_multiple_candidates(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    Path(plan["packet_root"], "stale_fixture.zip").write_bytes(b"stale")

    _expect("PACKET_DISCOVERY_MULTIPLE_CANDIDATES", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


@pytest.mark.parametrize("mutation, expected", [("bytes", "PACKET_SHA256_MISMATCH"), ("manifest", "PACKET_MANIFEST_MISMATCH")])
def test_packet_digest_and_manifest_are_independently_bound(tmp_path: Path, mutation: str, expected: str) -> None:
    plan, source_root = _plan(tmp_path)
    if mutation == "bytes":
        Path(plan["packet_root"], plan["packet_selection"]["packet_name"]).write_bytes(b"tampered")
    else:
        plan["packet_selection"]["manifest"]["packet_sha256"] = "0" * 64

    _expect(expected, contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


@pytest.mark.parametrize("mutation, expected", [("remove_config", "ADAPTER_CONFIG_MISSING"), ("remove_model", "ADAPTER_MODEL_MISSING")])
def test_adapter_requires_both_config_and_model(tmp_path: Path, mutation: str, expected: str) -> None:
    plan, source_root = _plan(tmp_path)
    adapter = Path(plan["adapter_root"], plan["adapter"]["adapter_directory"])
    target = adapter / plan["adapter"]["adapter_config_filename" if mutation == "remove_config" else "adapter_model_filename"]
    target.unlink()

    _expect(expected, contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


@pytest.mark.parametrize(
    "mutation, expected",
    [
        ("renamed_directory", "ADAPTER_DIRECTORY_MISSING"),
        ("corrupt_model", "ADAPTER_MODEL_SHA256_MISMATCH"),
        ("wrong_base", "ADAPTER_BASE_MODEL_MISMATCH"),
    ],
)
def test_adapter_identity_rejects_renames_wrong_bytes_and_config_drift(tmp_path: Path, mutation: str, expected: str) -> None:
    plan, source_root = _plan(tmp_path)
    adapter = Path(plan["adapter_root"], plan["adapter"]["adapter_directory"])
    if mutation == "renamed_directory":
        adapter.rename(adapter.with_name("learning_delta_lobe_renamed"))
    elif mutation == "corrupt_model":
        (adapter / plan["adapter"]["adapter_model_filename"]).write_bytes(b"wrong model bytes")
    else:
        config_path = adapter / plan["adapter"]["adapter_config_filename"]
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        payload["base_model_name_or_path"] = "Qwen/wrong-base"
        _write_json(config_path, payload)
        plan["adapter"]["adapter_config_sha256"] = _digest(config_path.read_bytes())

    _expect(expected, contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


@pytest.mark.parametrize(
    "field, value, expected",
    [
        ("load_in_4bit", False, "QLORA_4BIT_REQUIRED"),
        ("bitsandbytes_cuda_backend", "UNAVAILABLE", "QLORA_BITSANDBYTES_CUDA_REQUIRED"),
        ("cuda_available", False, "QLORA_CUDA_REQUIRED"),
    ],
)
def test_qlora_requires_four_bit_and_an_available_cuda_backend(
    tmp_path: Path, field: str, value: object, expected: str
) -> None:
    plan, source_root = _plan(tmp_path)
    plan["environment"][field] = value

    _expect(expected, contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_output_root_inside_source_and_heavy_assessment_content_are_rejected(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    plan["output"]["output_root"] = str(source_root / "generated")
    _expect("OUTPUT_ROOT_IN_SOURCE_TREE", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)

    plan, source_root = _plan(tmp_path)
    plan["output"]["assessment_includes"].append("ephemeral_heavy/adapter_model.safetensors")
    _expect("ASSESSMENT_INCLUDES_HEAVY_OUTPUT", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_output_reserve_is_a_declared_gate_not_a_free_assumption(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    _expect("OUTPUT_DISK_RESERVE_UNMET", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1023)


def test_partial_simulated_failure_preserves_incremental_rows_as_assessment_only(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    receipt = contract.preserve_partial_measurements(
        source_root,
        plan["output"],
        1024,
        [{"sample_id": "one", "correct": True}, {"sample_id": "two", "correct": False}],
        "simulated arm interruption",
    )
    journal = Path(receipt["journal"])
    rows = [json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()]

    assert receipt["status"] == contract.PARTIAL_STATUS
    assert receipt["output_mode"] == contract.ASSESSMENT_ONLY
    assert receipt["completed_measured_rows"] == 2
    assert receipt["performance_claim_authorized"] is False
    assert receipt["model_inference_invoked"] is False
    assert [row["event"] for row in rows] == ["MEASURED_ROW", "MEASURED_ROW", "SIMULATED_ARM_FAILURE"]
    assert (journal.parent / "partial_assessment_receipt.json").is_file()


def test_runner_identity_must_be_meaningful_without_executing_it(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    plan["runner"]["runner_file"] = "__file__"
    _expect("RUNNER_FILE_INVALID", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_execution_request_and_final_benchmark_selection_are_out_of_scope(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    plan["execution"]["model_inference_requested"] = True
    _expect("OUT_OF_SCOPE_EXECUTION_REQUEST", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)

    plan, source_root = _plan(tmp_path)
    plan["identity_planes"]["measurement"]["benchmark_selection_status"] = "SELECTED"
    _expect("FINAL_BENCHMARK_SELECTION_OUT_OF_SCOPE", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_identity_planes_reject_cross_plane_substitution(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    plan["identity_planes"]["source"]["adapter_manifest_sha256"] = "0" * 64
    _expect("IDENTITY_CROSS_PLANE_SUBSTITUTION", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


@pytest.mark.parametrize(
    "field, value, expected",
    [
        ("requested_head", "0" * 40, "CURRENT_HEAD_BINDING_MISMATCH"),
        ("requested_head_remote_reachable", False, "REQUESTED_HEAD_NOT_REMOTE_REACHABLE"),
        ("packet_hash_scope", "SELF_REFERENTIAL", "SELF_REFERENTIAL_PACKET_HASH_FORBIDDEN"),
    ],
)
def test_current_packet_identity_rejects_stale_unreachable_and_self_referential_designs(
    tmp_path: Path, field: str, value: object, expected: str
) -> None:
    plan, source_root = _plan(tmp_path)
    plan["packet_selection"][field] = value

    _expect(expected, contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


@pytest.mark.parametrize(
    "mutation, expected",
    [
        ("missing", "INPUT_REQUIRED_ARTIFACT_MISSING"),
        ("extra", "INPUT_INVENTORY_UNEXPECTED_FILE"),
        ("duplicate_name", "INPUT_LOGICAL_NAME_DUPLICATE"),
        ("wrong_root", "INPUT_STAGE_ROOT_MISMATCH"),
    ],
)
def test_nested_input_inventory_requires_one_exact_stage_and_no_ambiguous_extra(
    tmp_path: Path, mutation: str, expected: str
) -> None:
    plan, source_root = _plan(tmp_path)
    inventory = plan["input_inventory"]
    stage_root = Path(inventory["stage_root"])
    if mutation == "missing":
        (stage_root / "adapters" / "required_adapter.marker").unlink()
    elif mutation == "extra":
        (stage_root / "nested" / "stale_candidate.zip").write_bytes(b"stale")
    elif mutation == "duplicate_name":
        inventory["required_inputs"][1]["logical_name"] = "prompt_manifest"
    else:
        inventory["expected_stage_root_name"] = "wrong-stage-root"

    _expect(expected, contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


@pytest.mark.parametrize(
    "mutation, expected",
    [
        ("raw_secret", "SECRET_MATERIAL_FORBIDDEN"),
        ("printed", "SECRET_EXPOSURE_FORBIDDEN"),
        ("route", "HF_LIVE_ROUTE_UNAVAILABLE"),
        ("http", "HF_HTTP_FALLBACK_UNJUSTIFIED"),
        ("cache", "HF_CACHE_ROOT_INVALID"),
    ],
)
def test_hf_transport_keeps_secrets_redacted_and_fallbacks_explicit(
    tmp_path: Path, mutation: str, expected: str
) -> None:
    plan, source_root = _plan(tmp_path)
    transport = plan["hf_transport"]
    if mutation == "raw_secret":
        transport["raw_token"] = "do-not-store-secrets"
    elif mutation == "printed":
        transport["token_printed"] = True
    elif mutation == "route":
        transport["live_route_available"] = False
    elif mutation == "http":
        transport["transport_mode"] = "HTTP_FALLBACK"
    else:
        transport["cache_root"] = str(source_root / "cache")

    _expect(expected, contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


@pytest.mark.parametrize(
    "field, value, expected",
    [
        ("four_bit_linear_modules_present", False, "QLORA_FOUR_BIT_MODULES_REQUIRED"),
        ("legacy_load_in_4bit_kwarg_forwarded", True, "QLORA_LEGACY_LOAD_KWARG_FORBIDDEN"),
        ("process_isolation", "IN_PROCESS", "PROCESS_ISOLATION_REQUIRED"),
        ("memory_telemetry_enabled", False, "MEMORY_TELEMETRY_REQUIRED"),
        ("sequence_length", 97, "SEQUENCE_LENGTH_OUTSIDE_ENVELOPE"),
    ],
)
def test_resource_controls_reject_fake_qlora_and_unbounded_arm_lifecycle(
    tmp_path: Path, field: str, value: object, expected: str
) -> None:
    plan, source_root = _plan(tmp_path)
    plan["resource_controls"][field] = value

    _expect(expected, contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


@pytest.mark.parametrize(
    "mutation, expected",
    [
        ("filename", "RUNTIME_CONTRACT_FILENAME_MISMATCH"),
        ("missing_key", "RUNTIME_REQUIRED_KEY_MISSING"),
        ("alias", "RUNTIME_LEGACY_ALIAS_MISMATCH"),
        ("false_success", "RUNTIME_PRESENTATION_FALSE_SUCCESS"),
    ],
)
def test_runtime_contract_distinguishes_wrong_shape_from_presentation_tail_failure(
    tmp_path: Path, mutation: str, expected: str
) -> None:
    plan, source_root = _plan(tmp_path)
    runtime = plan["runtime_contract"]
    if mutation == "filename":
        runtime["contract_filename"] = "legacy_contract.json"
    elif mutation == "missing_key":
        runtime["values"].pop("route_head_dir")
    elif mutation == "alias":
        runtime["legacy_aliases"]["full_run_root"] = "/different"
    else:
        runtime["artifact_status"] = "MISSING"
        runtime["presentation_status"] = "PASS"

    _expect(expected, contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


@pytest.mark.parametrize(
    "mutation, expected",
    [
        ("target_leak", "SUPERVISION_TARGET_LEAKS_TO_PROMPT"),
        ("provenance", "SUPERVISION_OBJECT_PROVENANCE_MISMATCH"),
        ("question", "MEASUREMENT_QUESTION_TEXT_MISSING"),
        ("answer", "MEASUREMENT_EXPECTED_ANSWER_VISIBLE_TO_MODEL"),
    ],
)
def test_supervision_and_measurement_require_distinct_audited_inputs(
    tmp_path: Path, mutation: str, expected: str
) -> None:
    plan, source_root = _plan(tmp_path)
    if mutation == "target_leak":
        plan["supervision"]["rows"][0]["prompt"] = "The answer is 4"
    elif mutation == "provenance":
        plan["supervision"]["rows"][0]["training_object_sha256"] = "0" * 64
    elif mutation == "question":
        plan["measurement"]["rows"][0].pop("question_text")
    else:
        plan["measurement"]["rows"][0]["expected_answer"] = "4"

    _expect(expected, contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_scorecard_and_claims_cannot_promote_simulation_or_replay(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    plan["scorecard"]["accuracy"] = 0.0
    _expect("SCORECARD_AGGREGATE_MISMATCH", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)

    plan, source_root = _plan(tmp_path)
    plan["claim_ceiling"]["evidence_mode"] = "FROZEN_OUTPUT_REPLAY"
    plan["claim_ceiling"]["claims"]["fresh_generation"] = True
    _expect("REPLAY_CANNOT_CLAIM_FRESH_GENERATION", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)

    plan, source_root = _plan(tmp_path)
    plan["claim_ceiling"]["mandatory_gates"][0]["status"] = "SKIP"
    _expect("MANDATORY_GATE_NOT_PASS", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_finalization_rejects_non_json_safe_payload_before_a_tail_failure(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    plan["finalization_payload"] = {"unsafe_path": Path("not-json-safe")}
    _expect("FINALIZATION_PAYLOAD_NOT_JSON_SAFE", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_output_subtrees_reject_non_string_entries(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    plan["output"]["subtrees"] = [{}]
    _expect("OUTPUT_SUBTREE_LAYOUT_INVALID", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_input_inventory_rejects_symlink_entries(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    stage_root = Path(plan["input_inventory"]["stage_root"])
    link = stage_root / "nested" / "linked.marker"
    link.symlink_to(stage_root / "nested" / "prompt_manifest.json")
    _expect("INPUT_INVENTORY_SYMLINK_FORBIDDEN", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_scorecard_rejects_boolean_aggregates(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    plan["scorecard"]["row_count"] = True
    _expect("SCORECARD_AGGREGATE_MISMATCH", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_hf_transport_rejects_unknown_fields(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    plan["hf_transport"]["access_token"] = "must-not-appear"
    _expect("HF_TRANSPORT_FIELD_UNKNOWN", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_input_inventory_rejects_symlinked_directory_escape(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    stage_root = Path(plan["input_inventory"]["stage_root"])
    outside = tmp_path / "outside"
    outside.mkdir()
    payload = outside / "payload.bin"
    payload.write_bytes(b"outside")
    link_dir = stage_root / "linked"
    link_dir.symlink_to(outside, target_is_directory=True)
    plan["input_inventory"]["required_inputs"].append(
        {"logical_name": "escaped", "relative_path": "linked/payload.bin", "sha256": _digest(payload.read_bytes())}
    )
    _expect("INPUT_PATH_ESCAPES_STAGE_ROOT", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_output_assessment_return_rejects_symlink_root(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    output_root = Path(plan["output"]["output_root"])
    output_root.mkdir()
    outside = tmp_path / "outside-assessment"
    outside.mkdir()
    (output_root / "assessment_return").symlink_to(outside, target_is_directory=True)
    _expect(
        "ASSESSMENT_RETURN_ROOT_INVALID",
        contract.preserve_partial_measurements,
        source_root,
        plan["output"],
        1024,
        [],
        "fixture failure",
    )


def test_finalization_rejects_nonfinite_numbers(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    plan["finalization_payload"] = {"nan": float("nan")}
    _expect("FINALIZATION_PAYLOAD_NOT_JSON_SAFE", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_dependency_report_root_rejects_symlink_before_resolution(tmp_path: Path) -> None:
    from tools.operator import dependency_inventory_emit as emit

    root = tmp_path / "repo"
    root.mkdir()
    target = tmp_path / "external"
    target.mkdir()
    link = root / "reports"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="DEPENDENCY_REPORT_ROOT_SYMLINK_FORBIDDEN"):
        emit.resolve_external_report_root(root=root, report_root=root / "reports")


def test_packet_selection_rejects_symlink_entries(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    packet_root = Path(plan["packet_root"])
    packet_root.joinpath("linked.zip").symlink_to(packet_root / "exact_fixture.zip")
    _expect("PACKET_SYMLINK_ENTRY_FORBIDDEN", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_execution_ceiling_rejects_unknown_operation_flags(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    plan["execution"]["network_access_requested"] = True
    _expect("OUT_OF_SCOPE_EXECUTION_REQUEST", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)
    plan, source_root = _plan(tmp_path)
    plan["execution"]["unlisted_operation"] = False
    _expect("EXECUTION_FLAG_UNKNOWN", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_fresh_generation_cannot_claim_promotion_or_superiority(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    plan["claim_ceiling"]["evidence_mode"] = "FRESH_GENERATION_INTERNAL"
    plan["claim_ceiling"]["claims"]["promotion"] = True
    _expect("CLAIM_EXCEEDS_EVIDENCE_TIER", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_output_assessment_rejects_symlink_destination_file(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    output_root = Path(plan["output"]["output_root"])
    assessment = output_root / "assessment_return"
    assessment.mkdir(parents=True)
    outside = tmp_path / "outside-journal.jsonl"
    outside.write_text("external\n", encoding="utf-8")
    (assessment / "measurement_journal.jsonl").symlink_to(outside)
    _expect("ASSESSMENT_OUTPUT_DESTINATION_INVALID", contract.preserve_partial_measurements, source_root, plan["output"], 1024, [], "fixture failure")


def test_partial_measurement_rejects_nonfinite_row(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    _expect("PARTIAL_MEASUREMENT_ROW_NOT_JSON_SAFE", contract.preserve_partial_measurements, source_root, plan["output"], 1024, [{"value": float("inf")}], "fixture failure")


def test_packet_selection_rejects_unexpected_regular_entry(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    Path(plan["packet_root"], "stale.txt").write_text("stale", encoding="utf-8")
    _expect("PACKET_DISCOVERY_UNEXPECTED_ENTRY", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_output_allocation_requires_assessment_contents(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    plan["output"]["assessment_includes"] = []
    _expect("ASSESSMENT_CONTENTS_INVALID", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)



def test_adapter_rejects_config_model_filename_collision(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    plan["adapter"]["adapter_model_filename"] = plan["adapter"]["adapter_config_filename"]
    _expect("ADAPTER_CONFIG_MODEL_NAME_COLLISION", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)


def test_scorecard_rejects_measurement_sample_id_mismatch(tmp_path: Path) -> None:
    plan, source_root = _plan(tmp_path)
    plan["scorecard"]["rows"][0]["sample_id"] = "different-sample"
    plan["scorecard"]["rows"][0]["decision_sample_id"] = "different-sample"
    plan["scorecard"]["rows"][0]["prediction_sample_id"] = "different-sample"
    _expect("SCORECARD_MEASUREMENT_ID_MISMATCH", contract.evaluate_static_preflight, plan, source_root=source_root, available_bytes=1024)
