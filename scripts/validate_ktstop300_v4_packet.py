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
    AUTHORITY_FALSE,
    REPORTS,
    STOP300_V4_DATASET,
    STOP300_V4_PACKET,
    STOP300_V4_RUN_MODE,
    authority_payload,
    read_json,
    rel,
    sha256_file,
    write_json,
)


REQUIRED_MEMBERS = {
    "KAGGLE_BOOTSTRAP_CELL.py",
    "runtime/KT_CANONICAL_RUNNER.py",
    "runtime/dependency_preflight.py",
    "runtime/model_runtime_attestation.py",
    "runtime/stop_fsm_v34.py",
    "runtime/reference_court_v34.py",
    "runtime/boundary_evidence.py",
    "runtime/numeric_normalizer.py",
    "runtime/output_delivery.py",
    "runtime/timing_protocol.py",
    "runtime/work_plan.py",
    "runtime/atomic_record_store.py",
    "runtime/checkpoint_manager.py",
    "runtime/result_court.py",
    "runtime/publication_disposition.py",
    "runtime/hf_publisher.py",
    "runtime/ktstop300_v4_config.json",
    "runtime/gsm8k_row_authority_registry.json",
    "requirements.txt",
    "tests/smoke_test.py",
    "PACKET_MANIFEST.json",
    "SHA256_MANIFEST.json",
    "README.md",
    "COPY_PASTE_NOW_ktstop300_v4.txt",
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


def authority_errors(payload: dict) -> list[str]:
    errors = []
    for key in AUTHORITY_FALSE:
        if key not in payload:
            errors.append(f"missing:{key}")
        elif type(payload[key]) is not bool:
            errors.append(f"not_bool:{key}")
        elif payload[key] is not False:
            errors.append(f"not_false:{key}")
    if payload.get("sandbox_inference_authority") is not True:
        errors.append("sandbox_inference_authority_not_true")
    return errors


def main() -> int:
    errors: list[str] = []
    packet_sha = sha256_file(STOP300_V4_PACKET)
    with zipfile.ZipFile(STOP300_V4_PACKET) as zf:
        names = set(zf.namelist())
        require(errors, REQUIRED_MEMBERS.issubset(names), f"missing members: {sorted(REQUIRED_MEMBERS - names)}")
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8-sig"))
        config = json.loads(zf.read("runtime/ktstop300_v4_config.json").decode("utf-8-sig"))
        bootstrap = zf.read("KAGGLE_BOOTSTRAP_CELL.py").decode("utf-8-sig")
        dependency = zf.read("runtime/dependency_preflight.py").decode("utf-8-sig")
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
        result_court = zf.read("runtime/result_court.py").decode("utf-8-sig")
        hf_publisher = zf.read("runtime/hf_publisher.py").decode("utf-8-sig")
        checkpoint = zf.read("runtime/checkpoint_manager.py").decode("utf-8-sig")
        atomic_store = zf.read("runtime/atomic_record_store.py").decode("utf-8-sig")
        attestation = zf.read("runtime/model_runtime_attestation.py").decode("utf-8-sig")
        boundary = zf.read("runtime/boundary_evidence.py").decode("utf-8-sig")
        reference = zf.read("runtime/reference_court_v34.py").decode("utf-8-sig")
        normalizer = zf.read("runtime/numeric_normalizer.py").decode("utf-8-sig")
        work_plan = zf.read("runtime/work_plan.py").decode("utf-8-sig")

    require(errors, manifest.get("run_mode") == STOP300_V4_RUN_MODE, "run mode mismatch")
    require(errors, manifest.get("kaggle_dataset_name") == STOP300_V4_DATASET, "dataset mismatch")
    require(errors, not authority_errors(manifest), "manifest authority flags are not fail-closed: " + ",".join(authority_errors(manifest)))
    for mutation_key, mutation_value in [
        ("missing", None),
        ("null", None),
        ("string", "false"),
        ("integer", 0),
        ("true", True),
    ]:
        mutated = dict(manifest)
        if mutation_key == "missing":
            mutated.pop("runtime_authority", None)
        else:
            mutated["runtime_authority"] = mutation_value
        require(errors, authority_errors(mutated), f"authority mutation {mutation_key} did not fail")
    require(errors, len(config["natural_rows"]) == 300, "natural rows mismatch")
    require(errors, len(config["timing_panel_rows"]) == 60, "timing rows mismatch")
    require(errors, len(config["edge_regression_rows"]) == 12, "edge rows mismatch")
    require(errors, config["work_units"]["total_measured_generations"] == 1176, "measured work unit mismatch")
    require(errors, config["work_units"]["warmups"] == 9, "warmup count mismatch")
    require(errors, "__BOUND_AFTER_PROTECTED_MERGE__" not in json.dumps(config), "forbidden placeholder in config")
    require(errors, "MERGED_MAIN_HEAD_TO_BIND_AFTER_PROTECTED_MERGE" not in bootstrap, "forbidden placeholder in bootstrap")
    require(errors, "KT_AUTHORIZED_PACKET_SUBJECT_HEAD" in bootstrap and "KT_CURRENT_MAIN_HEAD" in bootstrap, "bootstrap lacks subject/current head authority")
    require(errors, "ensure_dependencies(outdir)" in bootstrap and "native_library_receipt(outdir)" in bootstrap, "bootstrap dependency/native preflight missing")
    require(errors, "--no-deps" in dependency and "new_conflicts" in dependency and "before_conflict_count" in dependency, "dependency delta contract missing")
    require(errors, "raw_generated_token_count" in boundary and "semantic_visible_token_count" in boundary and "trigger_char_offset_within_token_if_any" in boundary, "physical token ledger fields missing")
    require(errors, "terminal_token_id" in reference and "effective_eos_token_ids" in reference and "ended_on_max_new_tokens" in reference, "EOS termination facts not bound to reference court")
    require(errors, "derived_prefix_equivalence" in runner and "derived_runtime_reference_agreement" in runner and '"prefix_equivalence": True' not in runner, "runner trusts hard-coded safe court fields")
    require(errors, "CORE_RESULT_SUMMARY.json" in runner and "FINAL_RUN_DISPOSITION.json" in runner, "non-circular result architecture missing")
    require(errors, "def publish_final_assessment" in hf_publisher and "return receipt" in hf_publisher, "publisher final receipt branch missing")
    require(errors, "PASS_HF_FINAL_ASSESSMENT_UPLOADED" in hf_publisher, "final upload receipt missing")
    require(errors, "self.completed.add(key)" in atomic_store and "runtime_disk_scan_count = 0" in atomic_store, "completed set / no rescan contract missing")
    require(errors, "publisher(path)" in checkpoint and "scope_hash" in checkpoint, "HF-restorable checkpoint contract missing")
    require(errors, "Linear4bit" in attestation and "effective_eos_token_ids" in attestation and "generation_warning_count" in attestation, "model-level 4-bit/eos attestation missing")
    require(errors, "NUMBER_PATTERN" in normalizer and "return normalize_number(match" in normalizer, "numeric normalizer should have bounded fallback and fixtures")
    require(errors, "phase\": \"timing\"" in work_plan or '"phase": "timing"' in work_plan, "timing work units absent")
    require(errors, "PRECEDENCE" in result_court and "BLOCK_CORRECTNESS_DAMAGE" in result_court and "PARTIAL_WALL_TIME_CHECKPOINTED" in result_court, "result court precedence missing")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "packet"
        other = Path(td) / "unrelated"
        root.mkdir()
        other.mkdir()
        with zipfile.ZipFile(STOP300_V4_PACKET) as zf:
            zf.extractall(root)
        env = os.environ.copy()
        env["KT_STOP300_BOOTSTRAP_SMOKE_ONLY"] = "1"
        env["KT_STOP300_SKIP_DEP_INSTALL"] = "1"
        env["KT_AUTHORIZED_PACKET_SHA256"] = packet_sha
        env["KT_AUTHORIZED_PACKET_SUBJECT_HEAD"] = "TEST_SUBJECT_HEAD"
        env["KT_CURRENT_MAIN_HEAD"] = "TEST_CURRENT_HEAD"
        env["KT_EXPECTED_RUN_MODE"] = STOP300_V4_RUN_MODE
        proc = subprocess.run([sys.executable, str(root / "KAGGLE_BOOTSTRAP_CELL.py")], cwd=other, env=env, text=True, capture_output=True, timeout=60)
        require(errors, proc.returncode == 0, "bootstrap subprocess from unrelated cwd failed: " + proc.stderr[-500:])
        sys.path.insert(0, str(root))
        try:
            court = load_module(root / "runtime" / "result_court.py", "ktstop300_v4_result_court_test")
            suite = court.synthetic_mutation_suite()
            require(errors, suite["status"] == "PASS_CONJUNCTIVE_FAIL_CLOSED_MUTATION_SUITE", "synthetic mutation suite failed")
            boundary_mod = load_module(root / "runtime" / "boundary_evidence.py", "ktstop300_v4_boundary_test")
            ledger = boundary_mod.build_physical_token_ledger(
                prompt_token_ids=[10, 11],
                raw_generated_token_ids=[1, 2, 3, 4],
                semantic_visible_text="FINAL_ANSWER: 9",
                canonical_extracted_answer="9",
                generator_termination_source="CUSTOM_STOP_CRITERION",
                boundary_token_index_floor=2,
                boundary_token_index_ceil=3,
                trigger_token_start_index=3,
                trigger_char_offset_within_token_if_any=1,
            ).to_json()
            require(errors, ledger["raw_generated_token_count"] == 4 and ledger["physical_stopped_generated_token_count"] == 3, "physical token accounting used visible/preserved count")
            require(errors, boundary_mod.validate_physical_token_ledger(ledger) == [], "physical token ledger invariant failed")
            ref = load_module(root / "runtime" / "reference_court_v34.py", "ktstop300_v4_reference_test")
            finding = ref.adjudicate_reference_court_v34("FINAL_ANSWER: 42", terminal_token_id=2, effective_eos_token_ids={2})
            require(errors, finding.semantic_boundary_type == "SAFE_EOS_CLOSURE", "terminal EOS closure not recognized")
            norm = load_module(root / "runtime" / "numeric_normalizer.py", "ktstop300_v4_normalizer_test")
            require(errors, norm.oracle_fixture_suite()["status"] == "PASS", "numeric oracle fixture suite failed")
        finally:
            if str(root) in sys.path:
                sys.path.remove(str(root))

    receipt = {
        "schema_id": "kt.stop300.v4.packet_validation_receipt.v1",
        "status": "PASS" if not errors else "FAIL",
        "packet_path": rel(STOP300_V4_PACKET),
        "packet_sha256": packet_sha,
        "required_members_present": sorted(REQUIRED_MEMBERS),
        "errors": errors,
        **authority_payload(),
        "sandbox_inference_authority": True,
    }
    write_json(REPORTS / "stop300_v4_packet_validation_receipt.json", receipt)
    if errors:
        raise SystemExit("STOP300 V4 packet validation failed: " + "; ".join(errors))
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
