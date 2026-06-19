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
    STOP300_V41_DATASET,
    STOP300_V41_PACKET,
    STOP300_V41_RUN_MODE,
    authority_payload,
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
    "runtime/final_answer_stopping_criteria_v41.py",
    "runtime/pairwise_court_v41.py",
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
    "runtime/ktstop300_v41_config.json",
    "runtime/gsm8k_row_authority_registry.json",
    "requirements.txt",
    "tests/smoke_test.py",
    "PACKET_MANIFEST.json",
    "SHA256_MANIFEST.json",
    "README.md",
    "COPY_PASTE_NOW_ktstop300_v4_1.txt",
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
    packet_sha = sha256_file(STOP300_V41_PACKET)
    with zipfile.ZipFile(STOP300_V41_PACKET) as zf:
        names = set(zf.namelist())
        require(errors, REQUIRED_MEMBERS.issubset(names), f"missing members: {sorted(REQUIRED_MEMBERS - names)}")
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8-sig"))
        config = json.loads(zf.read("runtime/ktstop300_v41_config.json").decode("utf-8-sig"))
        bootstrap = zf.read("KAGGLE_BOOTSTRAP_CELL.py").decode("utf-8-sig")
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
        stopping = zf.read("runtime/final_answer_stopping_criteria_v41.py").decode("utf-8-sig")
        court = zf.read("runtime/pairwise_court_v41.py").decode("utf-8-sig")
        timing = zf.read("runtime/timing_protocol.py").decode("utf-8-sig")

    require(errors, manifest.get("run_mode") == STOP300_V41_RUN_MODE, "run mode mismatch")
    require(errors, manifest.get("kaggle_dataset_name") == STOP300_V41_DATASET, "dataset mismatch")
    require(errors, not authority_errors(manifest), "manifest authority flags are not fail-closed: " + ",".join(authority_errors(manifest)))
    require(errors, len(config["natural_rows"]) == 300, "natural rows mismatch")
    require(errors, len(config["timing_panel_rows"]) == 60, "timing rows mismatch")
    require(errors, len(config["edge_regression_rows"]) == 12, "edge rows mismatch")
    require(errors, config["work_units"]["total_measured_generations"] == 1176, "measured work unit mismatch")
    require(errors, config["work_units"]["warmups"] == 9, "warmup count mismatch")
    require(errors, "KT_AUTHORIZED_PACKET_SUBJECT_HEAD" in bootstrap and "KT_CURRENT_MAIN_HEAD" in bootstrap, "bootstrap lacks subject/current head authority")
    require(errors, "StoppingCriteriaList" in runner, "runner does not import StoppingCriteriaList")
    require(errors, "stopping_criteria=criteria" in runner, "runner does not pass stopping_criteria to generate")
    require(errors, "outputs = model.generate(" in runner and "with torch.no_grad()" in runner, "runner generation path missing")
    require(errors, "for index, token_id in enumerate(raw_ids):" not in runner, "posthoc raw_ids detector loop survived")
    require(errors, "KTFinalAnswerStoppingCriteria" in runner and "consume_new_token_ids" in stopping, "online stopping adapter missing")
    require(errors, "KT_STOP300_BATCH_SIZE_ONE_REQUIRED" in stopping, "batch-size-one hard gate missing")
    require(errors, "IMMUTABLE_RAW_L0_S1_TRACES" in court, "pairwise court not bound to immutable raw traces")
    require(errors, "SEPARATE_ARM_CORRECT_COUNTS" in court, "separate TPC denominator marker missing")
    require(errors, "torch.cuda.Event" in runner and "torch.cuda.synchronize()" in runner, "CUDA event timing not executed by runner")
    require(errors, "PASS_EXECUTED_DEVICE_AND_WALL_TIMING" in timing, "timing protocol receipt missing")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "packet"
        other = Path(td) / "unrelated"
        root.mkdir()
        other.mkdir()
        with zipfile.ZipFile(STOP300_V41_PACKET) as zf:
            zf.extractall(root)
        env = os.environ.copy()
        env["KT_STOP300_BOOTSTRAP_SMOKE_ONLY"] = "1"
        env["KT_STOP300_SKIP_DEP_INSTALL"] = "1"
        env["KT_AUTHORIZED_PACKET_SHA256"] = packet_sha
        env["KT_AUTHORIZED_PACKET_SUBJECT_HEAD"] = "TEST_SUBJECT_HEAD"
        env["KT_CURRENT_MAIN_HEAD"] = "TEST_CURRENT_HEAD"
        env["KT_EXPECTED_RUN_MODE"] = STOP300_V41_RUN_MODE
        proc = subprocess.run([sys.executable, str(root / "KAGGLE_BOOTSTRAP_CELL.py")], cwd=other, env=env, text=True, capture_output=True, timeout=60)
        require(errors, proc.returncode == 0, "bootstrap subprocess from unrelated cwd failed: " + proc.stderr[-500:])
        sys.path.insert(0, str(root))
        try:
            stopping_mod = load_module(root / "runtime" / "final_answer_stopping_criteria_v41.py", "ktstop300_v41_stopping_test")
            court_mod = load_module(root / "runtime" / "pairwise_court_v41.py", "ktstop300_v41_pairwise_test")

            class FakeTokenizer:
                def decode(self, ids, skip_special_tokens=False):
                    mapping = {1: "FINAL_ANSWER:", 2: " 42", 3: "\n", 4: " trailer"}
                    return "".join(mapping[int(i)] for i in ids)

            s1 = stopping_mod.KTFinalAnswerStoppingCriteria(tokenizer=FakeTokenizer(), prompt_token_count=2, monitor_only=False)
            require(errors, s1.consume_new_token_ids([1]) is False, "s1 stopped before answer line")
            require(errors, s1.consume_new_token_ids([2]) is False, "s1 stopped before newline")
            require(errors, s1.consume_new_token_ids([3]) is True, "s1 failed to stop at final-answer newline")
            m0 = stopping_mod.KTFinalAnswerStoppingCriteria(tokenizer=FakeTokenizer(), prompt_token_count=2, monitor_only=True)
            require(errors, m0.consume_new_token_ids([1, 2, 3]) is False, "m0 monitor physically stopped")
            try:
                class BadInput:
                    shape = (2, 3)
                s1(BadInput(), None)
                require(errors, False, "batch-size-one gate did not raise")
            except RuntimeError as exc:
                require(errors, "KT_STOP300_BATCH_SIZE_ONE_REQUIRED" in str(exc), "wrong batch-size-one error")
            suite = court_mod.synthetic_mutation_suite()
            require(errors, suite["status"] == "PASS_RAW_TRACE_FAIL_CLOSED_MUTATION_SUITE", "raw trace mutation suite failed")
            base = court_mod._base_rows()
            require(errors, court_mod.full_tpc(base, "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE") < court_mod.full_tpc(base, "L0_LEGACY_NO_DETECTOR"), "separate TPC denominator check failed")
        finally:
            if str(root) in sys.path:
                sys.path.remove(str(root))

    receipt = {
        "schema_id": "kt.stop300.v41.packet_validation_receipt.v1",
        "status": "PASS" if not errors else "FAIL",
        "packet_path": rel(STOP300_V41_PACKET),
        "packet_sha256": packet_sha,
        "required_members_present": sorted(REQUIRED_MEMBERS),
        "errors": errors,
        **authority_payload(),
        "sandbox_inference_authority": True,
    }
    write_json(REPORTS / "stop300_v41_packet_validation_receipt.json", receipt)
    if errors:
        raise SystemExit("STOP300 V4.1 packet validation failed: " + "; ".join(errors))
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
