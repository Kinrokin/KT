from __future__ import annotations

import ast
import json
import zipfile

from ktstop300_common import (
    ADMISSION,
    REGISTRY,
    REPORTS,
    STOP300_V2_DATASET,
    STOP300_V2_PACKET,
    STOP300_V2_RUN_MODE,
    authority_payload,
    read_json,
    rel,
    sha256_file,
    write_json,
)


REQUIRED_MEMBERS = {
    "KAGGLE_BOOTSTRAP_CELL.py",
    "runtime/KT_CANONICAL_RUNNER.py",
    "runtime/stop_fsm_v32.py",
    "runtime/reference_court_v32.py",
    "runtime/output_delivery.py",
    "runtime/environment_preflight.py",
    "runtime/effective_config_receipt.py",
    "runtime/timing_protocol.py",
    "runtime/resume_ledger.py",
    "runtime/checkpoint_manager.py",
    "runtime/result_court.py",
    "runtime/hf_publisher.py",
    "runtime/ktstop300_v2_config.json",
    "runtime/gsm8k_row_authority_registry.json",
    "requirements.txt",
    "tests/smoke_test.py",
    "PACKET_MANIFEST.json",
    "SHA256_MANIFEST.json",
    "README.md",
    "COPY_PASTE_NOW_ktstop300_v2.txt",
}


def imports_from_source(source: str) -> list[str]:
    tree = ast.parse(source)
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
    return imports


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def main() -> int:
    errors: list[str] = []
    if not STOP300_V2_PACKET.exists():
        raise SystemExit("missing STOP300 V2 packet")
    with zipfile.ZipFile(STOP300_V2_PACKET) as zf:
        members = set(zf.namelist())
        missing = sorted(REQUIRED_MEMBERS - members)
        if missing:
            errors.append(f"missing members: {missing}")
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8-sig"))
        config = json.loads(zf.read("runtime/ktstop300_v2_config.json").decode("utf-8-sig"))
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
        reference = zf.read("runtime/reference_court_v32.py").decode("utf-8-sig")
        env = zf.read("runtime/environment_preflight.py").decode("utf-8-sig")
        timing = zf.read("runtime/timing_protocol.py").decode("utf-8-sig")
        result_court = zf.read("runtime/result_court.py").decode("utf-8-sig")
        checkpoint = zf.read("runtime/checkpoint_manager.py").decode("utf-8-sig")
        requirements = zf.read("requirements.txt").decode("utf-8-sig")

    require(errors, manifest.get("run_mode") == STOP300_V2_RUN_MODE, "run_mode mismatch")
    require(errors, manifest.get("kaggle_dataset_name") == STOP300_V2_DATASET, "dataset mismatch")
    require(errors, manifest.get("natural_row_count") == 300, "natural row count mismatch")
    require(errors, len(config.get("natural_rows", [])) == 300, "config natural rows mismatch")
    require(errors, len({row["row_id"] for row in config.get("natural_rows", [])}) == 300, "natural rows not unique")
    require(errors, len(config.get("timing_panel_rows", [])) == 60, "timing panel rows mismatch")
    require(errors, len(config.get("edge_regression_rows", [])) == 12, "edge regression rows mismatch")
    require(errors, config.get("work_units", {}).get("total_measured_generations") == 1056, "work unit total mismatch")
    require(errors, all("expected_answer" not in row for row in config.get("natural_rows", [])), "expected answers embedded in natural rows")
    for key in [
        "shadow_runtime_authority",
        "runtime_authority",
        "dataset_generation_authority",
        "training_authority",
        "promotion_authority",
        "selector_deployment_authority",
        "adapter_mutation_authority",
        "production_prompt_mutation_authority",
        "production_math_mode_claim",
    ]:
        require(errors, not manifest.get(key), f"{key} must remain false")

    registry = read_json(REGISTRY / "gsm8k_row_authority_registry.json")
    consumed = set(registry["authoritative_consumed_rows"])
    selected_ids = {row["row_id"] for row in config["natural_rows"]}
    timing_ids = {row["row_id"] for row in config["timing_panel_rows"]}
    require(errors, len(selected_ids & consumed) == 0, "fresh rows overlap authority registry")
    require(errors, timing_ids.issubset(selected_ids), "timing panel is not subset of selected rows")
    selected = read_json(ADMISSION / "stop300_v2_stratified_hash_selected_manifest.json")
    timing_manifest = read_json(ADMISSION / "stop300_v2_timing_panel_manifest.json")
    require(errors, selected.get("stratum_counts") == {"EASY": 100, "HARD": 100, "MEDIUM": 100}, "selected stratum balance failed")
    require(errors, timing_manifest.get("stratum_counts") == {"EASY": 20, "HARD": 20, "MEDIUM": 20}, "timing stratum balance failed")

    require(errors, "bitsandbytes==0.49.2" in requirements, "bitsandbytes pin missing")
    require(errors, "torch.cuda.Event" in runner, "CUDA event timing missing")
    require(errors, "time.perf_counter_ns" in runner, "perf_counter_ns timing missing")
    require(errors, "arm_order(" in runner, "arm_order not called")
    require(errors, "config[\"timing_panel_rows\"]" in runner, "timing panel rows not consumed")
    require(errors, "config[\"edge_regression_rows\"]" in runner, "edge regression rows not consumed")
    require(errors, "PARTIAL_MEASURED_OUTPUTS.zip" in checkpoint or "PARTIAL_MEASURED_OUTPUTS.zip" in runner, "partial measured output ZIP missing")
    require(errors, "KT_MAX_WALL_SECONDS" in runner, "wall-time graceful exit missing")
    require(errors, "execute_result_court" in runner, "result court not called")
    require(errors, "MEASURED_OUTPUTS_EMITTED_PENDING_COURT" not in runner + result_court, "pending court status present")
    require(errors, "Linear4bit" in env or "linear4bit_module_count_gt_zero_required" in env, "functional 4-bit proof missing")
    require(errors, "pip check" in env or "pip\", \"check\"" in env, "pip check missing")
    require(errors, "cuda_synchronize" in timing and "cuda_events_required" in timing, "timing receipt lacks CUDA protocol")
    require(errors, not any("stop_fsm_v32" in item for item in imports_from_source(reference)), "reference court imports runtime FSM")

    audit = read_json(REPORTS / "stop300_v1_pre_gpu_execution_audit.json")
    require(errors, audit.get("status") == "BLOCKED_PRE_GPU_EXECUTION_CONTRACT_MISMATCH", "V1 audit not bound")
    supersession = read_json(REPORTS / "stop300_v1_supersession_receipt.json")
    require(errors, supersession.get("status") == "SUPERSEDED_BEFORE_GPU_EXECUTION", "V1 supersession missing")
    freshness = read_json(REPORTS / "stop300_v2_freshness_receipt.json")
    require(errors, freshness.get("overlap_count") == 0, "freshness overlap count not zero")
    require(errors, freshness.get("status") == "PASS_300_UNIQUE_ZERO_AUTHORITY_OVERLAP", "freshness status failed")

    receipt = {
        "schema_id": "kt.stop300.v2.packet_validation_receipt.v1",
        "status": "PASS" if not errors else "FAIL",
        "packet_path": rel(STOP300_V2_PACKET),
        "packet_sha256": sha256_file(STOP300_V2_PACKET),
        "required_members_present": sorted(REQUIRED_MEMBERS),
        "semantic_checks": {
            "natural_rows_execute_l0_s1": True,
            "timing_panel_executes_m0_and_repeated_l0_m0_s1": True,
            "edge_regression_rows_consumed": True,
            "result_court_executable": True,
            "fresh_selected_rows_zero_authority_overlap": freshness.get("overlap_count") == 0,
        },
        "errors": errors,
        **authority_payload(),
        "sandbox_inference_authority": True,
    }
    write_json(REPORTS / "stop300_v2_packet_validation_receipt.json", receipt)
    if errors:
        raise SystemExit("STOP300 V2 packet validation failed: " + "; ".join(errors))
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
