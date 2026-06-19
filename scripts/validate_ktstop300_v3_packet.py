from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from ktstop300_common import (
    REPORTS,
    STOP300_V3_DATASET,
    STOP300_V3_PACKET,
    STOP300_V3_RUN_MODE,
    authority_payload,
    read_json,
    rel,
    sha256_file,
    write_json,
)


REQUIRED_MEMBERS = {
    "KAGGLE_BOOTSTRAP_CELL.py",
    "runtime/KT_CANONICAL_RUNNER.py",
    "runtime/stop_fsm_v33.py",
    "runtime/reference_court_v33.py",
    "runtime/token_boundary_map.py",
    "runtime/output_delivery.py",
    "runtime/environment_preflight.py",
    "runtime/model_runtime_attestation.py",
    "runtime/effective_config_receipt.py",
    "runtime/timing_protocol.py",
    "runtime/work_plan.py",
    "runtime/atomic_record_store.py",
    "runtime/checkpoint_manager.py",
    "runtime/result_court.py",
    "runtime/hf_publisher.py",
    "runtime/ktstop300_v3_config.json",
    "runtime/gsm8k_row_authority_registry.json",
    "requirements.txt",
    "tests/smoke_test.py",
    "PACKET_MANIFEST.json",
    "SHA256_MANIFEST.json",
    "README.md",
    "COPY_PASTE_NOW_ktstop300_v3.txt",
}


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    errors: list[str] = []
    packet_sha = sha256_file(STOP300_V3_PACKET)
    with zipfile.ZipFile(STOP300_V3_PACKET) as zf:
        names = set(zf.namelist())
        require(errors, REQUIRED_MEMBERS.issubset(names), f"missing members: {sorted(REQUIRED_MEMBERS - names)}")
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8-sig"))
        config = json.loads(zf.read("runtime/ktstop300_v3_config.json").decode("utf-8-sig"))
        bootstrap = zf.read("KAGGLE_BOOTSTRAP_CELL.py").decode("utf-8-sig")
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
        fsm = zf.read("runtime/stop_fsm_v33.py").decode("utf-8-sig")
        token_boundary = zf.read("runtime/token_boundary_map.py").decode("utf-8-sig")
        result_court = zf.read("runtime/result_court.py").decode("utf-8-sig")
        hf_publisher = zf.read("runtime/hf_publisher.py").decode("utf-8-sig")
        atomic_store = zf.read("runtime/atomic_record_store.py").decode("utf-8-sig")
        attestation = zf.read("runtime/model_runtime_attestation.py").decode("utf-8-sig")
        work_plan = zf.read("runtime/work_plan.py").decode("utf-8-sig")

    require(errors, manifest.get("run_mode") == STOP300_V3_RUN_MODE, "run mode mismatch")
    require(errors, manifest.get("kaggle_dataset_name") == STOP300_V3_DATASET, "dataset mismatch")
    require(errors, len(config["natural_rows"]) == 300, "natural rows mismatch")
    require(errors, len(config["timing_panel_rows"]) == 60, "timing rows mismatch")
    require(errors, len(config["edge_regression_rows"]) == 12, "edge rows mismatch")
    require(errors, config["work_units"]["total_measured_generations"] == 1176, "measured work unit mismatch")
    require(errors, config["work_units"]["warmups"] == 9, "warmup count mismatch")
    require(errors, config["external_authorized_packet_sha256"] == "__EXTERNAL_LAUNCHER_AUTHORITY__", "external SHA placeholder missing")
    require(errors, "KT_AUTHORIZED_PACKET_SHA256" in bootstrap and "KT_AUTHORIZED_MERGE_HEAD" in bootstrap, "bootstrap lacks external authority checks")
    require(errors, "sys.path.insert(0, str(packet_root))" in bootstrap and "os.chdir(packet_root)" in bootstrap, "bootstrap path/cwd hardening missing")
    require(errors, "preserved != raw[:boundary]" in token_boundary or "raw[:boundary]" in token_boundary, "exact original-token slicing absent")
    require(errors, "first_boundary_decision" in fsm and "last_detector_decision" in fsm, "first/last boundary separation missing")
    require(errors, "range(3)" in work_plan and "warmup" in work_plan, "9 warmups not defined")
    require(errors, "phase\": \"timing\"" in work_plan or '"phase": "timing"' in work_plan, "timing work units absent")
    require(errors, "HfApi" in hf_publisher and ("upload_file" in hf_publisher and "upload_folder" in hf_publisher), "HF API calls missing")
    require(errors, "Linear4bit" in attestation and "functional_one_token_generation" in attestation, "model-level 4-bit attestation missing")
    require(errors, "PENDING" not in result_court, "result court contains pending status")
    require(errors, "BLOCK_CORRECTNESS_DAMAGE" in result_court and "BLOCK_FIRST_ANSWER_CORRECTION_CUT" in result_court, "fail-closed result court statuses missing")
    require(errors, "os.fsync" in atomic_store and "os.replace" in atomic_store, "atomic exactly-once persistence missing")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "packet"
        other = Path(td) / "unrelated"
        root.mkdir()
        other.mkdir()
        with zipfile.ZipFile(STOP300_V3_PACKET) as zf:
            zf.extractall(root)
        env = os.environ.copy()
        env["KT_STOP300_BOOTSTRAP_SMOKE_ONLY"] = "1"
        env["KT_AUTHORIZED_PACKET_SHA256"] = packet_sha
        env["KT_AUTHORIZED_MERGE_HEAD"] = "TEST_HEAD"
        proc = subprocess.run([sys.executable, str(root / "KAGGLE_BOOTSTRAP_CELL.py")], cwd=other, env=env, text=True, capture_output=True, timeout=60)
        require(errors, proc.returncode == 0, "bootstrap subprocess from unrelated cwd failed: " + proc.stderr[-500:])
        sys.path.insert(0, str(root))
        try:
            result_mod = load_module(root / "runtime" / "result_court.py", "ktstop300_v3_result_court_test")
            suite = result_mod.synthetic_mutation_suite()
            require(errors, suite["status"] == "PASS_FAIL_CLOSED_SYNTHETIC_MUTATION_SUITE", "synthetic mutation suite failed")
            boundary_mod = load_module(root / "runtime" / "token_boundary_map.py", "ktstop300_v3_boundary_test")
            fake = type("FakeTok", (), {"decode": lambda self, ids, skip_special_tokens=True: "|".join(map(str, ids))})()
            record = boundary_mod.build_token_boundary_record(tokenizer=fake, raw_generated_token_ids=[1, 2, 3, 4], raw_generated_text="a b c d", boundary_generated_token_index_exclusive=2, trigger_token_start_index=2).to_json()
            require(errors, boundary_mod.validate_token_boundary_record(record) == [], "token boundary invariants failed")
        finally:
            if str(root) in sys.path:
                sys.path.remove(str(root))

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

    receipt = {
        "schema_id": "kt.stop300.v3.packet_validation_receipt.v1",
        "status": "PASS" if not errors else "FAIL",
        "packet_path": rel(STOP300_V3_PACKET),
        "packet_sha256": packet_sha,
        "required_members_present": sorted(REQUIRED_MEMBERS),
        "errors": errors,
        **authority_payload(),
        "sandbox_inference_authority": True,
    }
    write_json(REPORTS / "stop300_v3_packet_validation_receipt.json", receipt)
    if errors:
        raise SystemExit("STOP300 V3 packet validation failed: " + "; ".join(errors))
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
