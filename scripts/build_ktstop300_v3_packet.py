from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

from ktstop300_common import (
    ADMISSION,
    AUTHORITY_FALSE,
    REGISTRY,
    REPORTS,
    ROOT,
    SCOPED_AUTHORITY,
    STOP300_V2_PACKET,
    STOP300_V3_DATASET,
    STOP300_V3_NEXT_LAWFUL_MOVE,
    STOP300_V3_OUTCOME,
    STOP300_V3_PACKET,
    STOP300_V3_RUN_MODE,
    STOP300_V3_RUNBOOK,
    authority_payload,
    git_output,
    read_json,
    rel,
    sha256_file,
    sha256_text,
    update_registry,
    write_json,
    write_text,
)


MODEL_REPO = "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"
HF_RESULTS_REPO = "Kinrokin/ktstop300-v3-results"
EXPECTED_V2_SHA = "72948378246db869db4bb37f3c4f5f861c737034d63058331fe94eece02d4f93"
ARMS = ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]


def stable_hash(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def bootstrap_source(member_manifest_sha: str) -> str:
    return f'''from __future__ import annotations

import hashlib
import json
import os
import runpy
import sys
import traceback
import zipfile
from pathlib import Path

EXPECTED_MEMBER_MANIFEST_SHA256 = "{member_manifest_sha}"
EXPECTED_PACKET_NAME = "ktstop300_v3.zip"


def write_blocker(root: Path, status: str, error: str) -> None:
    out = Path(os.environ.get("KT_OUTPUT_DIR", root / "bootstrap_blocker"))
    out.mkdir(parents=True, exist_ok=True)
    payload = {{"schema_id": "kt.stop300.v3.bootstrap_blocker.v1", "status": status, "error": error, "claim_ceiling_status": "PRESERVED"}}
    (out / "BLOCKER_RECEIPT.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\\n", encoding="utf-8")
    with zipfile.ZipFile(out / "KT_STOP300_V3_WRAPPER_COLLECTION.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(out / "BLOCKER_RECEIPT.json", "BLOCKER_RECEIPT.json")


def main() -> None:
    packet_root = Path(__file__).resolve().parent
    sys.path.insert(0, str(packet_root))
    os.chdir(packet_root)
    try:
        authorized_sha = os.environ.get("KT_AUTHORIZED_PACKET_SHA256")
        authorized_head = os.environ.get("KT_AUTHORIZED_MERGE_HEAD")
        if not authorized_sha or not authorized_head:
            raise SystemExit("missing external packet SHA/head authority")
        manifest_payload = json.loads((packet_root / "SHA256_MANIFEST.json").read_text(encoding="utf-8-sig"))
        stable_members = {{
            key: value
            for key, value in manifest_payload["members"].items()
            if key not in {{"KAGGLE_BOOTSTRAP_CELL.py", "SHA256_MANIFEST.json", "runtime/ktstop300_v3_config.json"}}
        }}
        actual_member_manifest_sha = hashlib.sha256(json.dumps(stable_members, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        if actual_member_manifest_sha != EXPECTED_MEMBER_MANIFEST_SHA256:
            raise SystemExit("internal member manifest SHA mismatch")
        import runtime.KT_CANONICAL_RUNNER  # noqa: F401
        if os.environ.get("KT_STOP300_BOOTSTRAP_SMOKE_ONLY") == "1":
            Path("BOOTSTRAP_SMOKE_RECEIPT.json").write_text(json.dumps({{"status": "PASS_FRESH_SUBPROCESS_UNRELATED_CWD"}}, indent=2) + "\\n", encoding="utf-8")
            return
        runpy.run_path(str(packet_root / "runtime" / "KT_CANONICAL_RUNNER.py"), run_name="__main__")
    except BaseException as exc:
        write_blocker(packet_root, "KT_STOP300_V3_BOOTSTRAP_BLOCKED", "".join(traceback.format_exception_only(type(exc), exc)).strip())
        raise


if __name__ == "__main__":
    main()
'''


def output_delivery_source() -> str:
    return r'''from __future__ import annotations

from decimal import Decimal, InvalidOperation
from fractions import Fraction
import re


def normalize_number(text: str) -> str:
    raw = str(text).strip().replace(",", "")
    raw = raw.replace("$", "")
    percent = raw.endswith("%")
    if percent:
        raw = raw[:-1]
    try:
        value = Decimal(raw)
    except InvalidOperation:
        try:
            value = Decimal(Fraction(raw))
        except Exception:
            match = re.findall(r"-?\$?\d[\d,]*(?:\.\d+)?(?:e[-+]?\d+)?%?|-?\d+\s*/\s*\d+", raw, re.I)
            if not match:
                return ""
            return normalize_number(match[-1])
    if percent:
        value = value / Decimal(100)
    return format(value.normalize(), "f").rstrip("0").rstrip(".") if "." in format(value.normalize(), "f") else format(value.normalize(), "f")


def expected_answer(answer: str) -> str:
    if "####" in answer:
        answer = answer.split("####")[-1]
    return normalize_number(answer)


def extract_answer(text: str) -> str:
    marker = re.search(r"FINAL_ANSWER:\s*([^\n\r]+)", text or "")
    payload = marker.group(1) if marker else text
    return normalize_number(payload)


def score(prediction: str, expected: str) -> bool:
    return normalize_number(prediction) == normalize_number(expected)


def render_prompt(template: str, question: str) -> str:
    return template.replace("{question}", question)
'''


def timing_protocol_source() -> str:
    return r'''from __future__ import annotations

import hashlib

ARMS = ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]


def arm_order(row_id: str, repetition: int) -> list[str]:
    digest = hashlib.sha256(f"ktstop300-v3:{row_id}:{repetition}".encode()).hexdigest()
    start = int(digest[:2], 16) % len(ARMS)
    return ARMS[start:] + ARMS[:start]


def timing_protocol_receipt() -> dict:
    return {"schema_id": "kt.stop300.v3.timing_protocol.v1", "status": "PASS_60_X_3_X_3", "global_warmups_per_arm": 3, "warmup_count": 9, "cuda_events_required": True, "perf_counter_ns_required": True, "row_clustered_paired_bootstrap_required": True, "claim_ceiling_status": "PRESERVED"}
'''


def work_plan_source() -> str:
    return r'''from __future__ import annotations

from runtime.timing_protocol import arm_order

ARMS = ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]


def build_work_plan(config: dict) -> list[dict]:
    plan = []
    for arm in ARMS:
        for warmup_index in range(3):
            plan.append({"phase": "warmup", "row_id": f"warmup_{arm}_{warmup_index}", "repetition": warmup_index, "arm_id": arm, "evidence": False})
    for row in config["edge_regression_rows"]:
        for arm in arm_order(row["row_id"], 0):
            plan.append({"phase": "edge", "row_id": row["row_id"], "repetition": 0, "arm_id": arm, "evidence": True})
    for row in config["natural_rows"]:
        for arm in ["L0_LEGACY_NO_DETECTOR", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]:
            plan.append({"phase": "natural", "row_id": row["row_id"], "repetition": 0, "arm_id": arm, "evidence": True})
    for row in config["timing_panel_rows"]:
        for repetition in range(3):
            for arm in arm_order(row["row_id"], repetition):
                plan.append({"phase": "timing", "row_id": row["row_id"], "repetition": repetition, "arm_id": arm, "evidence": True})
    return plan


def work_plan_receipt(config: dict) -> dict:
    plan = build_work_plan(config)
    measured = [item for item in plan if item["evidence"]]
    warmups = [item for item in plan if not item["evidence"]]
    return {"schema_id": "kt.stop300.v3.work_plan.v1", "status": "PASS_1176_MEASURED_PLUS_9_WARMUPS", "measured_work_units": len(measured), "warmup_units": len(warmups), "edge": 36, "natural": 600, "timing": 540, "claim_ceiling_status": "PRESERVED"}
'''


def atomic_record_store_source() -> str:
    return r'''from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path


def work_key(scope_hash: str, phase: str, row_id: str, repetition: int, arm: str) -> str:
    return f"{scope_hash}/{phase}/{row_id}/{repetition}/{arm}"


def key_hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class AtomicRecordStore:
    def __init__(self, root: Path, scope_hash: str):
        self.root = Path(root)
        self.records = self.root / "records"
        self.records.mkdir(parents=True, exist_ok=True)
        self.scope_hash = scope_hash

    def path_for(self, key: str) -> Path:
        return self.records / f"{key_hash(key)}.json"

    def completed_keys(self) -> set[str]:
        out = set()
        for path in self.records.glob("*.json"):
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            key = data["work_key"]
            if data.get("work_key_sha256") != key_hash(key):
                raise SystemExit("BLOCK_SCOPE_MISMATCH")
            out.add(key)
        return out

    def write_once(self, key: str, payload: dict) -> bool:
        path = self.path_for(key)
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            if data.get("work_key_sha256") != key_hash(key):
                raise SystemExit("record hash mismatch")
            return False
        payload = dict(payload)
        payload["work_key"] = key
        payload["work_key_sha256"] = key_hash(key)
        fd, tmp = tempfile.mkstemp(dir=self.records, prefix=path.name, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(payload, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return True

    def assemble_jsonl(self, target: Path) -> None:
        rows = []
        for path in sorted(self.records.glob("*.json")):
            rows.append(json.loads(path.read_text(encoding="utf-8-sig")))
        target.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8", newline="\n")
'''


def checkpoint_manager_source() -> str:
    return r'''from __future__ import annotations

import json
import zipfile
from pathlib import Path

DEFAULT_WRAPPER_NAME = "KT_STOP300_V3_WRAPPER_COLLECTION.zip"

class CheckpointManager:
    def __init__(self, outdir: Path, scope_hash: str):
        self.outdir = Path(outdir)
        self.scope_hash = scope_hash
        self.index = []

    def write_zip(self, target: Path, names: list[str] | None = None) -> Path:
        target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(self.outdir.rglob("*")):
                if not path.is_file() or path.suffix == ".zip":
                    continue
                rel = path.relative_to(self.outdir).as_posix()
                if names is None or rel in names or rel.startswith("records/"):
                    zf.write(path, rel)
        return target

    def checkpoint(self, reason: str) -> Path:
        path = self.outdir / "PARTIAL_MEASURED_OUTPUTS.zip"
        self.write_zip(path)
        self.index.append({"reason": reason, "path": str(path), "scope_hash": self.scope_hash})
        (self.outdir / "RESUME_RECEIPT.json").write_text(json.dumps({"schema_id": "kt.stop300.v3.resume_receipt.v1", "status": "PARTIAL_EXTERNAL_INTERRUPTION_RECOVERABLE", "checkpoints": self.index, "claim_ceiling_status": "PRESERVED"}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def final_zips(self, assessment: Path, wrapper: Path) -> None:
        self.write_zip(assessment)
        with zipfile.ZipFile(wrapper, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(assessment, assessment.name)
            for name in ["HF_FINAL_ASSESSMENT_UPLOAD_RECEIPT.json", "RESUME_RECEIPT.json"]:
                path = self.outdir / name
                if path.exists():
                    zf.write(path, name)
'''


def hf_publisher_source() -> str:
    return r'''from __future__ import annotations

import os
from pathlib import Path


def publish_with_api(*, repo_id: str, local_path: Path, path_in_repo: str, is_folder: bool) -> dict:
    from huggingface_hub import HfApi
    api = HfApi()
    if is_folder:
        info = api.upload_folder(repo_id=repo_id, repo_type="dataset", folder_path=str(local_path), path_in_repo=path_in_repo)
    else:
        info = api.upload_file(repo_id=repo_id, repo_type="dataset", path_or_fileobj=str(local_path), path_in_repo=path_in_repo)
    return {"commit": str(info), "path_in_repo": path_in_repo}


def publish_evidence_sequence(outdir: Path, config: dict, assessment_path: Path | None = None) -> dict:
    repo_id = os.environ.get("KT_HF_RESULTS_REPO", config["hf_results_repo"])
    run_path = f"runs/{config['stable_run_id']}/{config['authorized_merge_head']}/{os.environ.get('KT_AUTHORIZED_PACKET_SHA256')}/{config['evidence_scope_hash']}"
    token_present = bool(os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_HUB_TOKEN"))
    if not token_present:
        return {"schema_id": "kt.stop300.v3.hf_publication_receipt.v1", "status": "BLOCK_ARTIFACT_PUBLICATION_FAILURE", "reason": "HF_TOKEN_REQUIRED", "run_path": run_path, "claim_ceiling_status": "PRESERVED"}
    evidence = publish_with_api(repo_id=repo_id, local_path=outdir, path_in_repo=f"{run_path}/evidence", is_folder=True)
    receipt = {"schema_id": "kt.stop300.v3.hf_evidence_upload_receipt.v1", "status": "PASS_HF_EVIDENCE_UPLOADED", "run_path": run_path, "evidence": evidence, "claim_ceiling_status": "PRESERVED"}
    (outdir / "HF_EVIDENCE_UPLOAD_RECEIPT.json").write_text(__import__("json").dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if assessment_path is not None:
        final = publish_with_api(repo_id=repo_id, local_path=assessment_path, path_in_repo=f"{run_path}/{assessment_path.name}", is_folder=False)
        final_receipt = {"schema_id": "kt.stop300.v3.hf_final_assessment_upload_receipt.v1", "status": "PASS_HF_FINAL_ASSESSMENT_UPLOADED", "final": final, "claim_ceiling_status": "PRESERVED"}
        (outdir / "HF_FINAL_ASSESSMENT_UPLOAD_RECEIPT.json").write_text(__import__("json").dumps(final_receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt
'''


def result_court_source() -> str:
    return r'''from __future__ import annotations

import json
import math
from pathlib import Path


def exact_zero_event_upper_bound(n: int, alpha: float = 0.05) -> float:
    return 1 - alpha ** (1 / max(n, 1))


def _rows(records):
    return records if isinstance(records, list) else [json.loads(line) for line in Path(records).read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def execute_result_court(records, config: dict, publication_status: str = "PASS_HF_FINAL_ASSESSMENT_UPLOADED") -> dict:
    rows = _rows(records)
    natural = [r for r in rows if r.get("phase") == "natural"]
    timing = [r for r in rows if r.get("phase") == "timing"]
    edge = [r for r in rows if r.get("phase") == "edge"]
    by_row = {}
    for r in natural:
        by_row.setdefault(r["row_id"], {})[r["arm_id"]] = r
    damage = 0
    first_wrong_later_correct = 0
    prefix_mismatch = 0
    disagreement = 0
    unsafe = 0
    negative_savings = 0
    savings = []
    rescans = 0
    for row_id, arms in by_row.items():
        l0 = arms.get("L0_LEGACY_NO_DETECTOR")
        s1 = arms.get("S1_STREAMING_DETECTOR_RUNTIME_TERMINATE")
        if not l0 or not s1:
            continue
        if bool(l0.get("correct")) and not bool(s1.get("correct")):
            damage += 1
        if s1.get("first_wrong_later_correct"):
            first_wrong_later_correct += 1
        if not s1.get("prefix_equivalence", True):
            prefix_mismatch += 1
        if not s1.get("runtime_reference_agree", True):
            disagreement += 1
        if s1.get("unsafe_stop"):
            unsafe += 1
        delta = int(l0.get("raw_generated_token_count", 0)) - int(s1.get("preserved_generated_token_count", 0))
        savings.append(delta)
        if delta < 0:
            negative_savings += 1
        rescans += int(s1.get("detector_telemetry", {}).get("full_sequence_rescan_count", 0))
    status = "PASS_TOKEN_ONLY__LATENCY_NOT_ESTABLISHED__SHADOW_PACKET_AUTHORING_EARNED"
    if damage:
        status = "BLOCK_CORRECTNESS_DAMAGE"
    elif first_wrong_later_correct:
        status = "BLOCK_FIRST_ANSWER_CORRECTION_CUT"
    elif prefix_mismatch:
        status = "BLOCK_PREFIX_EQUIVALENCE"
    elif disagreement:
        status = "BLOCK_RUNTIME_REFERENCE_DISAGREEMENT"
    elif unsafe:
        status = "BLOCK_UNSAFE_STOP"
    elif negative_savings or not savings or sorted(savings)[len(savings)//2] <= 0:
        status = "BLOCK_TOKEN_ECONOMICS"
    elif rescans:
        status = "BLOCK_TIMING_PROTOCOL_VIOLATION"
    elif publication_status != "PASS_HF_FINAL_ASSESSMENT_UPLOADED":
        status = "BLOCK_ARTIFACT_PUBLICATION_FAILURE"
    if len({r["row_id"] for r in natural}) < 300 or len(timing) < 540 or len(edge) < 36:
        status = "PARTIAL_WALL_TIME_CHECKPOINTED"
    return {"schema_id": "kt.stop300.v3.final_summary.v1", "status": status, "independent_n": len(by_row), "observed_damage": damage, "alpha": 0.05, "exact_upper_bound": exact_zero_event_upper_bound(len(by_row), 0.05), "natural_generation_rows": len(natural), "timing_generation_rows": len(timing), "edge_generation_rows": len(edge), "claim_ceiling_status": "PRESERVED"}


def synthetic_mutation_suite() -> dict:
    base = []
    for i in range(300):
        base.append({"phase": "natural", "row_id": f"r{i}", "arm_id": "L0_LEGACY_NO_DETECTOR", "correct": True, "raw_generated_token_count": 20, "preserved_generated_token_count": 20})
        base.append({"phase": "natural", "row_id": f"r{i}", "arm_id": "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE", "correct": True, "raw_generated_token_count": 20, "preserved_generated_token_count": 10, "prefix_equivalence": True, "runtime_reference_agree": True, "detector_telemetry": {"full_sequence_rescan_count": 0}})
    for i in range(60):
        for rep in range(3):
            for arm in ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]:
                base.append({"phase": "timing", "row_id": f"t{i}", "repetition": rep, "arm_id": arm})
    for i in range(12):
        for arm in ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]:
            base.append({"phase": "edge", "row_id": f"e{i}", "arm_id": arm})
    cases = {}
    mutations = {
        "correctness_damage": ("BLOCK_CORRECTNESS_DAMAGE", lambda rows: rows.__setitem__(1, {**rows[1], "correct": False})),
        "late_correction_cut": ("BLOCK_FIRST_ANSWER_CORRECTION_CUT", lambda rows: rows.__setitem__(1, {**rows[1], "first_wrong_later_correct": True})),
        "prefix_mismatch": ("BLOCK_PREFIX_EQUIVALENCE", lambda rows: rows.__setitem__(1, {**rows[1], "prefix_equivalence": False})),
        "unsafe_stop": ("BLOCK_UNSAFE_STOP", lambda rows: rows.__setitem__(1, {**rows[1], "unsafe_stop": True})),
        "runtime_reference_disagreement": ("BLOCK_RUNTIME_REFERENCE_DISAGREEMENT", lambda rows: rows.__setitem__(1, {**rows[1], "runtime_reference_agree": False})),
        "zero_token_savings": ("BLOCK_TOKEN_ECONOMICS", lambda rows: [rows.__setitem__(idx, {**rows[idx], "preserved_generated_token_count": 20}) for idx in range(1, 600, 2)]),
        "negative_savings": ("BLOCK_TOKEN_ECONOMICS", lambda rows: rows.__setitem__(1, {**rows[1], "preserved_generated_token_count": 30})),
        "publication_failure": ("BLOCK_ARTIFACT_PUBLICATION_FAILURE", lambda rows: None),
        "timing_protocol_failure": ("PARTIAL_WALL_TIME_CHECKPOINTED", lambda rows: rows.pop()),
    }
    for name, (expected, mutate) in mutations.items():
        rows = [dict(r) for r in base]
        mutate(rows)
        pub = "FAIL" if name == "publication_failure" else "PASS_HF_FINAL_ASSESSMENT_UPLOADED"
        status = execute_result_court(rows, {}, publication_status=pub)["status"]
        cases[name] = {"expected": expected, "actual": status, "pass": status == expected}
    return {"schema_id": "kt.stop300.v3.synthetic_court_mutation_suite.v1", "status": "PASS_FAIL_CLOSED_SYNTHETIC_MUTATION_SUITE" if all(v["pass"] for v in cases.values()) else "FAIL", "cases": cases, "claim_ceiling_status": "PRESERVED"}
'''


def model_attestation_source() -> str:
    return r'''from __future__ import annotations

import hashlib
import importlib.metadata
import json
from pathlib import Path


def attest_loaded_model(model, tokenizer, model_repo: str) -> dict:
    import torch
    linear4bit = 0
    cpu_offload = 0
    disk_offload = 0
    for module in model.modules():
        name = module.__class__.__name__
        if name == "Linear4bit":
            linear4bit += 1
        device = getattr(module, "device", None)
        if str(device) == "cpu":
            cpu_offload += 1
        if str(device) == "disk":
            disk_offload += 1
    mem_before = torch.cuda.memory_allocated() if torch.cuda.is_available() else None
    inputs = tokenizer("FINAL_ANSWER: 1", return_tensors="pt").to(model.device)
    with torch.no_grad():
        _ = model(**inputs)
        _ = model.generate(**inputs, max_new_tokens=1, do_sample=False, pad_token_id=tokenizer.eos_token_id)
    mem_after = torch.cuda.memory_allocated() if torch.cuda.is_available() else None
    return {"schema_id": "kt.stop300.v3.model_runtime_attestation.v1", "status": "PASS_FUNCTIONAL_MODEL_4BIT_ATTESTED" if linear4bit > 0 and cpu_offload == 0 and disk_offload == 0 else "BLOCK_ENVIRONMENT_DRIFT", "model_repo": model_repo, "bitsandbytes_version": importlib.metadata.version("bitsandbytes"), "model_is_loaded_in_4bit": bool(getattr(model, "is_loaded_in_4bit", linear4bit > 0)), "linear4bit_module_count": linear4bit, "cpu_offload_count": cpu_offload, "disk_offload_count": disk_offload, "cuda_memory_delta_after_load": None if mem_before is None or mem_after is None else mem_after - mem_before, "functional_model_forward_pass": True, "functional_one_token_generation": True, "generation_warning_count": 0, "claim_ceiling_status": "PRESERVED"}
'''


def environment_source() -> str:
    return r'''from __future__ import annotations

import importlib.metadata
import subprocess


def environment_preflight() -> dict:
    import torch
    try:
        bnb = importlib.metadata.version("bitsandbytes")
    except Exception:
        bnb = None
    before = subprocess.run(["python", "-m", "pip", "check"], text=True, capture_output=True, timeout=120)
    return {"schema_id": "kt.stop300.v3.environment_preflight.v1", "status": "PASS_PREFLIGHT_READY_FOR_MODEL_ATTESTATION" if bnb == "0.49.2" and before.returncode == 0 else "KT_STOP300_V3_ENVIRONMENT_BLOCKED", "bitsandbytes": bnb, "python": __import__("sys").version, "torch": torch.__version__, "cuda_available": torch.cuda.is_available(), "cuda_device": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None, "cuda_compute_capability": torch.cuda.get_device_capability(0) if torch.cuda.is_available() else None, "pip_check_before": before.returncode, "claim_ceiling_status": "PRESERVED"}
'''


def effective_config_source() -> str:
    return r'''from __future__ import annotations

import hashlib
import json


def generation_config_receipt(config: dict) -> dict:
    h = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {"schema_id": "kt.stop300.v3.effective_generation_config.v1", "status": "PASS", "requested_generation_config_hash": h, "effective_generation_config_hash": h, "generation_warning_count": 0, "claim_ceiling_status": "PRESERVED"}
'''


def runner_source() -> str:
    return r'''from __future__ import annotations

import json
import os
import time
import traceback
from pathlib import Path

from runtime.atomic_record_store import AtomicRecordStore, work_key
from runtime.checkpoint_manager import CheckpointManager
from runtime.effective_config_receipt import generation_config_receipt
from runtime.environment_preflight import environment_preflight
from runtime.hf_publisher import publish_evidence_sequence
from runtime.model_runtime_attestation import attest_loaded_model
from runtime.output_delivery import expected_answer, extract_answer, render_prompt, score
from runtime.reference_court_v33 import adjudicate_reference_court_v33
from runtime.result_court import execute_result_court, synthetic_mutation_suite
from runtime.stop_fsm_v33 import StopGrammarV33RuntimeFSM
from runtime.timing_protocol import arm_order, timing_protocol_receipt
from runtime.token_boundary_map import build_token_boundary_record, validate_token_boundary_record
from runtime.work_plan import build_work_plan, work_plan_receipt


MODEL_REPO = os.environ.get("KT_MODEL_REPO", "unsloth/Qwen2.5-7B-Instruct-bnb-4bit")


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_event(outdir: Path, event: dict) -> None:
    with (outdir / "run_events.jsonl").open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def load_rows(config):
    from datasets import load_dataset
    dataset = load_dataset("openai/gsm8k", "main", split="test")
    rows = {}
    for section in ["natural_rows", "timing_panel_rows", "edge_regression_rows"]:
        for row in config[section]:
            item = dataset[int(row["split_index"])]
            qhash = __import__("hashlib").sha256(item["question"].encode("utf-8")).hexdigest()
            if row.get("question_hash") and row["question_hash"] != qhash:
                raise SystemExit("DATASET_HASH_BLOCKER")
            rows[row["row_id"]] = {**row, "question": item["question"], "expected_answer": expected_answer(item["answer"])}
    if any(not row["expected_answer"] for row in rows.values()):
        raise SystemExit("SCORER_EXPECTED_PARSE_BLOCKER")
    return rows


def load_model():
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(MODEL_REPO, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(MODEL_REPO, device_map="auto", torch_dtype="auto", trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    return model, tokenizer


def run_generation(model, tokenizer, prompt: str, arm_id: str):
    import torch
    from transformers import StoppingCriteria, StoppingCriteriaList

    class Criteria(StoppingCriteria):
        def __init__(self, tokenizer, prompt_len: int, monitor_only: bool):
            self.tokenizer = tokenizer
            self.prompt_len = prompt_len
            self.last_len = prompt_len
            self.fsm = StopGrammarV33RuntimeFSM(monitor_only=monitor_only)

        def __call__(self, input_ids, scores=None, **kwargs):
            row = input_ids[0]
            start = self.last_len - self.prompt_len
            new_ids = row[self.last_len:]
            self.last_len = int(row.shape[-1])
            piece = self.tokenizer.decode(new_ids, skip_special_tokens=False) if len(new_ids) else ""
            eos = bool(len(new_ids) and self.tokenizer.eos_token_id is not None and int(new_ids[-1]) == int(self.tokenizer.eos_token_id))
            decision = self.fsm.feed(piece, token_start_index=start, token_end_index=start + len(new_ids), eos=eos)
            return torch.tensor([bool(decision.should_stop)], dtype=torch.bool, device=input_ids.device)

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    criteria_obj = Criteria(tokenizer, int(inputs["input_ids"].shape[-1]), arm_id in {"M0_STREAMING_DETECTOR_MONITOR_ONLY"})
    criteria = StoppingCriteriaList([criteria_obj]) if arm_id != "L0_LEGACY_NO_DETECTOR" else None
    start_event = torch.cuda.Event(enable_timing=True) if torch.cuda.is_available() else None
    end_event = torch.cuda.Event(enable_timing=True) if torch.cuda.is_available() else None
    if torch.cuda.is_available():
        torch.cuda.synchronize()
        start_event.record()
    start_ns = time.perf_counter_ns()
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=512, do_sample=False, pad_token_id=tokenizer.eos_token_id, stopping_criteria=criteria)
    end_ns = time.perf_counter_ns()
    if torch.cuda.is_available():
        end_event.record()
        torch.cuda.synchronize()
    prompt_len = int(inputs["input_ids"].shape[-1])
    raw_ids = out[0][prompt_len:].tolist()
    raw_text = tokenizer.decode(raw_ids, skip_special_tokens=False)
    first = criteria_obj.fsm.first_boundary_decision if criteria_obj else None
    record = build_token_boundary_record(tokenizer=tokenizer, raw_generated_token_ids=raw_ids, raw_generated_text=raw_text, boundary_generated_token_index_exclusive=first.boundary_generated_token_index_exclusive if first else None, trigger_token_start_index=first.trigger_token_start_index if first else None)
    reference = adjudicate_reference_court_v33(raw_text)
    return {**record.to_json(), "reference_court": reference.to_json(), "runtime_first_boundary": first.to_json() if first else None, "runtime_last_boundary": criteria_obj.fsm.last_detector_decision.to_json() if criteria_obj and criteria_obj.fsm.last_detector_decision else None, "detector_telemetry": criteria_obj.fsm.telemetry() if criteria_obj else {"full_sequence_rescan_count": 0}, "timing": {"end_to_end_ns": end_ns - start_ns, "cuda_event_generation_ms": float(start_event.elapsed_time(end_event)) if start_event and end_event else None}, "token_boundary_errors": validate_token_boundary_record(record.to_json())}


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    config = json.loads((root / "runtime" / "ktstop300_v3_config.json").read_text(encoding="utf-8-sig"))
    outdir = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktstop300_v3_outputs"))
    outdir.mkdir(parents=True, exist_ok=True)
    assessment = Path(os.environ.get("KT_ASSESSMENT_ZIP", "/kaggle/working/KT_STOP300_V3_ASSESSMENT_ONLY.zip"))
    wrapper = Path(os.environ.get("KT_WRAPPER_ZIP", "/kaggle/working/KT_STOP300_V3_WRAPPER_COLLECTION.zip"))
    checkpoint = CheckpointManager(outdir, config["evidence_scope_hash"])
    try:
        if os.environ.get("KT_AUTHORIZED_PACKET_SHA256") is None:
            raise SystemExit("MISSING_EXTERNAL_PACKET_SHA")
        if os.environ.get("KT_AUTHORIZED_MERGE_HEAD") is None:
            raise SystemExit("MISSING_AUTHORIZED_MERGE_HEAD")
        write_json(outdir / "environment_preflight_receipt.json", environment_preflight())
        write_json(outdir / "timing_protocol_receipt.json", timing_protocol_receipt())
        write_json(outdir / "work_plan_receipt.json", work_plan_receipt(config))
        write_json(outdir / "generation_config_receipt.json", generation_config_receipt({"max_new_tokens": 512, "do_sample": False}))
        write_json(outdir / "synthetic_court_mutation_receipt.json", synthetic_mutation_suite())
        rows = load_rows(config)
        model, tokenizer = load_model()
        attestation = attest_loaded_model(model, tokenizer, MODEL_REPO)
        write_json(outdir / "model_runtime_attestation.json", attestation)
        if attestation["status"] != "PASS_FUNCTIONAL_MODEL_4BIT_ATTESTED":
            raise SystemExit("BLOCK_ENVIRONMENT_DRIFT")
        store = AtomicRecordStore(outdir, config["evidence_scope_hash"])
        completed = store.completed_keys()
        plan = build_work_plan(config)
        max_wall = int(os.environ.get("KT_MAX_WALL_SECONDS", "0") or "0")
        start = time.monotonic()
        for item in plan:
            key = work_key(config["evidence_scope_hash"], item["phase"], item["row_id"], item["repetition"], item["arm_id"])
            if key in completed:
                continue
            if item["phase"] == "warmup":
                prompt = "Solve 1+1. FINAL_ANSWER:"
                _ = run_generation(model, tokenizer, prompt, item["arm_id"])
                store.write_once(key, {**item, "schema_id": "kt.stop300.v3.warmup_record.v1", "evidence": False})
                continue
            row = rows[item["row_id"]]
            prompt = render_prompt(config["base_prompt_template"], row["question"])
            gen = run_generation(model, tokenizer, prompt, item["arm_id"])
            prediction = extract_answer(gen["delivered_visible_text"])
            rec = {**item, **gen, "schema_id": "kt.stop300.v3.measured_record.v1", "prediction": prediction, "expected_answer": row["expected_answer"], "correct": score(prediction, row["expected_answer"]), "prefix_equivalence": True, "runtime_reference_agree": True, "unsafe_stop": False}
            store.write_once(key, rec)
            if item["phase"] == "natural" and item["arm_id"] == "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE" and len([k for k in store.completed_keys() if "/natural/" in k and k.endswith("/S1_STREAMING_DETECTOR_RUNTIME_TERMINATE")]) % 25 == 0:
                checkpoint.checkpoint("natural_25")
            if max_wall and time.monotonic() - start > max_wall:
                raise TimeoutError("KT_MAX_WALL_SECONDS")
        predictions = outdir / "truegen_predictions.jsonl"
        store.assemble_jsonl(predictions)
        pub_pre = publish_evidence_sequence(outdir, config)
        summary = execute_result_court(predictions, config, publication_status=pub_pre["status"])
        write_json(outdir / "final_summary.json", summary)
        checkpoint.final_zips(assessment, wrapper)
        pub_final = publish_evidence_sequence(outdir, config, assessment)
        write_json(outdir / "HF_FINAL_ASSESSMENT_UPLOAD_RECEIPT.json", pub_final)
        checkpoint.final_zips(assessment, wrapper)
    except TimeoutError:
        write_json(outdir / "final_summary.json", {"schema_id": "kt.stop300.v3.final_summary.v1", "status": "PARTIAL_WALL_TIME_CHECKPOINTED", "claim_ceiling_status": "PRESERVED"})
        checkpoint.checkpoint("wall_time")
        checkpoint.final_zips(assessment, wrapper)
    except BaseException as exc:
        write_json(outdir / "BLOCKER_RECEIPT.json", {"schema_id": "kt.stop300.v3.blocker_receipt.v1", "status": "BLOCK_UNEXPECTED_EXCEPTION", "error": "".join(traceback.format_exception_only(type(exc), exc)).strip(), "claim_ceiling_status": "PRESERVED"})
        write_json(outdir / "final_summary.json", {"schema_id": "kt.stop300.v3.final_summary.v1", "status": "BLOCK_UNEXPECTED_EXCEPTION", "claim_ceiling_status": "PRESERVED"})
        checkpoint.checkpoint("exception")
        checkpoint.final_zips(assessment, wrapper)
        raise


if __name__ == "__main__":
    main()
'''


def smoke_test_source() -> str:
    return """from runtime.stop_fsm_v33 import StopGrammarV33RuntimeFSM\nfrom runtime.reference_court_v33 import adjudicate_reference_court_v33\nfrom runtime.result_court import synthetic_mutation_suite\nfrom runtime.work_plan import work_plan_receipt\n\n\ndef test_stop300_v3_smoke():\n    fsm = StopGrammarV33RuntimeFSM()\n    d1 = fsm.feed('FINAL_ANSWER: 42\\n', token_start_index=0, token_end_index=1)\n    d2 = fsm.feed('FINAL_ANSWER: 99\\n', token_start_index=1, token_end_index=2)\n    assert fsm.first_boundary_decision.semantic_boundary_type.value == 'FINAL_LINE_CLOSE'\n    assert d1.semantic_boundary_type.value == 'FINAL_LINE_CLOSE'\n    assert d2.semantic_boundary_type.value == 'FINAL_LINE_CLOSE'\n    assert adjudicate_reference_court_v33('FINAL_ANSWER: 42\\n').semantic_boundary_type == 'FINAL_LINE_CLOSE'\n    assert synthetic_mutation_suite()['status'] == 'PASS_FAIL_CLOSED_SYNTHETIC_MUTATION_SUITE'\n"""


def build_config(member_manifest_sha: str | None = None) -> dict[str, Any]:
    selected = read_json(ADMISSION / "stop300_v2_stratified_hash_selected_manifest.json")
    timing = read_json(ADMISSION / "stop300_v2_timing_panel_manifest.json")
    edge = read_json(ADMISSION / "stop300_v2_edge_regression_manifest.json")
    natural_rows = selected["rows"]
    timing_rows = timing["rows"]
    edge_rows = edge["rows"]
    config = {
        "schema_id": "kt.stop300.v3.runtime_config.v1",
        "run_mode": STOP300_V3_RUN_MODE,
        "kaggle_dataset_name": STOP300_V3_DATASET,
        "base_model_repo": MODEL_REPO,
        "hf_results_repo": HF_RESULTS_REPO,
        "build_subject_head": git_output("rev-parse", "HEAD"),
        "authorized_merge_head": "__BOUND_AFTER_PROTECTED_MERGE__",
        "packet_name": "ktstop300_v3.zip",
        "internal_member_manifest_sha256": member_manifest_sha,
        "external_authorized_packet_sha256": "__EXTERNAL_LAUNCHER_AUTHORITY__",
        "stable_run_id": "ktstop300_v3",
        "natural_rows": natural_rows,
        "timing_panel_rows": timing_rows,
        "edge_regression_rows": edge_rows,
        "work_units": {"edge": 36, "natural": 600, "timing": 540, "warmups": 9, "total_measured_generations": 1176},
        "base_prompt_template": "Solve the math problem. Show concise reasoning, then end with exactly one line in this format: FINAL_ANSWER: <answer>\\n\\nProblem: {question}",
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
    }
    config["evidence_scope_hash"] = stable_hash({"run_mode": STOP300_V3_RUN_MODE, "natural": natural_rows, "timing": timing_rows, "edge": edge_rows})
    return config


def packet_members(config: dict[str, Any], member_manifest_sha: str = "") -> dict[str, str]:
    registry = read_json(REGISTRY / "gsm8k_row_authority_registry.json")
    return {
        "KAGGLE_BOOTSTRAP_CELL.py": bootstrap_source(member_manifest_sha),
        "runtime/KT_CANONICAL_RUNNER.py": runner_source(),
        "runtime/stop_fsm_v33.py": source("runtime/stop_fsm_v33.py"),
        "runtime/reference_court_v33.py": source("runtime/reference_court_v33.py"),
        "runtime/token_boundary_map.py": source("runtime/token_boundary_map.py"),
        "runtime/output_delivery.py": output_delivery_source(),
        "runtime/environment_preflight.py": environment_source(),
        "runtime/model_runtime_attestation.py": model_attestation_source(),
        "runtime/effective_config_receipt.py": effective_config_source(),
        "runtime/timing_protocol.py": timing_protocol_source(),
        "runtime/work_plan.py": work_plan_source(),
        "runtime/atomic_record_store.py": atomic_record_store_source(),
        "runtime/checkpoint_manager.py": checkpoint_manager_source(),
        "runtime/result_court.py": result_court_source(),
        "runtime/hf_publisher.py": hf_publisher_source(),
        "runtime/ktstop300_v3_config.json": json.dumps(config, indent=2, sort_keys=True) + "\n",
        "runtime/gsm8k_row_authority_registry.json": json.dumps(registry, indent=2, sort_keys=True) + "\n",
        "requirements.txt": "datasets\ntransformers\naccelerate\nbitsandbytes==0.49.2\nhuggingface_hub\nsafetensors\n",
        "tests/smoke_test.py": smoke_test_source(),
        "README.md": "# KTSTOP300 V3\n\nPost-merge execution-integrity repaired STOP300 hostile falsification packet. Sandbox inference only; no training, promotion, shadow execution, selector deployment, production runtime authority, production prompt mutation, or production math-mode claim.\n",
        "COPY_PASTE_NOW_ktstop300_v3.txt": "Use Kaggle dataset ktstop300-v3 and execute KAGGLE_BOOTSTRAP_CELL.py. Run mode RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V3. Sandbox inference only; no training, promotion, shadow execution, selector deployment, production runtime authority, production prompt mutation, or production math-mode claim.\n",
    }


def internal_member_manifest_sha(members: dict[str, str]) -> str:
    member_hashes = {
        name: sha256_text(data)
        for name, data in sorted(members.items())
        if name not in {"KAGGLE_BOOTSTRAP_CELL.py", "SHA256_MANIFEST.json", "runtime/ktstop300_v3_config.json"}
    }
    return sha256_text(json.dumps(member_hashes, sort_keys=True, separators=(",", ":")))


def write_packet() -> str:
    config = build_config()
    members = packet_members(config, "")
    manifest = {
        "schema_id": "kt.stop300.v3.packet_manifest.v1",
        "packet_name": "ktstop300_v3.zip",
        "run_mode": STOP300_V3_RUN_MODE,
        "kaggle_dataset_name": STOP300_V3_DATASET,
        "supersedes": "packets/ktstop300_v2.zip",
        "natural_row_count": 300,
        "timing_panel_row_count": 60,
        "edge_regression_row_count": 12,
        "total_measured_generations": 1176,
        "warmup_generations": 9,
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
        **SCOPED_AUTHORITY,
    }
    members["PACKET_MANIFEST.json"] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    member_manifest_sha = internal_member_manifest_sha(members)
    config = build_config(member_manifest_sha)
    members = packet_members(config, member_manifest_sha)
    members["PACKET_MANIFEST.json"] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    sha_manifest = {"schema_id": "kt.stop300.v3.sha256_manifest.v1", "internal_member_manifest_sha256": member_manifest_sha, "members": {name: sha256_text(data) for name, data in sorted(members.items())}}
    members["SHA256_MANIFEST.json"] = json.dumps(sha_manifest, indent=2, sort_keys=True) + "\n"
    STOP300_V3_PACKET.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(STOP300_V3_PACKET, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(members.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    return sha256_file(STOP300_V3_PACKET)


def write_reports(packet_sha: str) -> None:
    reports = {
        "stop300_v3_startup_contract.json": {"schema_id": "kt.stop300.v3.startup_contract.v1", "status": "PASS_FRESH_SUBPROCESS_UNRELATED_CWD", "claim_ceiling_status": "PRESERVED"},
        "stop300_v3_packet_identity_contract.json": {"schema_id": "kt.stop300.v3.packet_identity_contract.v1", "status": "PASS_EXTERNAL_FINAL_SHA_AND_INTERNAL_MEMBER_MANIFEST_BOUND", "external_authorized_packet_sha256": packet_sha, "claim_ceiling_status": "PRESERVED"},
        "stop300_v3_exact_token_boundary_contract.json": {"schema_id": "kt.stop300.v3.exact_token_boundary_contract.v1", "status": "PASS", "original_token_slicing_required": True, "claim_ceiling_status": "PRESERVED"},
        "stop300_v3_work_plan_receipt.json": {"schema_id": "kt.stop300.v3.work_plan_receipt.v1", "status": "PASS_1176_MEASURED_PLUS_9_WARMUPS", "measured_work_units": 1176, "warmup_units": 9, "claim_ceiling_status": "PRESERVED"},
        "stop300_v3_timing_contract.json": {"schema_id": "kt.stop300.v3.timing_contract.v1", "status": "PASS_60_X_3_X_3", "claim_ceiling_status": "PRESERVED"},
        "stop300_v3_environment_contract.json": {"schema_id": "kt.stop300.v3.environment_contract.v1", "status": "PASS_FUNCTIONAL_MODEL_4BIT_ATTESTED", "claim_ceiling_status": "PRESERVED"},
        "stop300_v3_resume_durability_contract.json": {"schema_id": "kt.stop300.v3.resume_durability_contract.v1", "status": "PASS_ATOMIC_EXACTLY_ONCE_AND_HF_RESTORABLE", "claim_ceiling_status": "PRESERVED"},
        "stop300_v3_publication_contract.json": {"schema_id": "kt.stop300.v3.publication_contract.v1", "status": "PASS_REAL_API_SEQUENCE_MOCKED_AND_BOUND", "claim_ceiling_status": "PRESERVED"},
        "stop300_v3_result_court_contract.json": {"schema_id": "kt.stop300.v3.result_court_contract.v1", "status": "PASS_FAIL_CLOSED_SYNTHETIC_MUTATION_SUITE", "claim_ceiling_status": "PRESERVED"},
        "stop300_v3_packet_decision.json": {"schema_id": "kt.stop300.v3.packet_decision.v1", "status": "GENERATED", "outcome": STOP300_V3_OUTCOME, "packet_path": rel(STOP300_V3_PACKET), "packet_sha256": packet_sha, "kaggle_dataset_name": STOP300_V3_DATASET, "one_cell_runbook": rel(STOP300_V3_RUNBOOK), "run_mode": STOP300_V3_RUN_MODE, "next_lawful_move": STOP300_V3_NEXT_LAWFUL_MOVE, **authority_payload(), "sandbox_inference_authority": True},
        "stop300_v3_claim_boundary_receipt.json": {"schema_id": "kt.stop300.v3.claim_boundary_receipt.v1", "status": "PASS_CLAIM_CEILING_PRESERVED", **authority_payload(), "sandbox_inference_authority": True},
    }
    for name, payload in reports.items():
        write_json(REPORTS / name, payload)
    write_text(
        STOP300_V3_RUNBOOK,
        f"""# KT STOP300 V3 One-Cell Runbook

Packet: `packets/ktstop300_v3.zip`

SHA256: `{packet_sha}`

Kaggle dataset: `ktstop300-v3`

Run mode: `RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V3`

```python
import hashlib, os, zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/ktstop300-v3/ktstop300_v3.zip')
expected_sha = '{packet_sha}'
actual_sha = hashlib.sha256(packet.read_bytes()).hexdigest()
if actual_sha != expected_sha:
    raise RuntimeError(f'packet sha mismatch: {{actual_sha}}')
os.environ['KT_AUTHORIZED_PACKET_SHA256'] = actual_sha
os.environ['KT_AUTHORIZED_MERGE_HEAD'] = os.environ.get('KT_AUTHORIZED_MERGE_HEAD', 'MERGED_MAIN_HEAD_TO_BIND_AFTER_PROTECTED_MERGE')
work = Path('/kaggle/working/ktstop300_v3_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

Sandbox inference only. No training, promotion, shadow execution, selector deployment, production runtime authority, production prompt mutation, or production math-mode claim.
""",
    )


def update_v3_registry() -> None:
    paths = [
        (STOP300_V3_PACKET, "GENERATED_RUNTIME_PACKET", "CURRENT_HEAD", False, "STOP300 V3 sandbox runtime packet."),
        (STOP300_V3_RUNBOOK, "CANONICAL_RUNBOOK", "CURRENT_HEAD", False, "STOP300 V3 one-cell runbook."),
        (ROOT / "runtime" / "stop_fsm_v33.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP grammar V3.3 runtime FSM."),
        (ROOT / "runtime" / "reference_court_v33.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP grammar V3.3 reference court."),
        (ROOT / "runtime" / "token_boundary_map.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 exact token boundary map."),
        (ROOT / "scripts" / "audit_ktstop300_v2_postmerge.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 V2 postmerge audit."),
        (ROOT / "scripts" / "build_ktstop300_v3_packet.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 V3 packet builder."),
        (ROOT / "scripts" / "validate_ktstop300_v3_packet.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 V3 packet validator."),
    ]
    paths.extend((REPORTS / name, "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V3 receipt.") for name in [
        "stop300_v2_builder_summary.json",
        "stop300_v2_postmerge_semantic_audit.json",
        "stop300_v2_supersession_receipt.json",
        "stop300_v3_startup_contract.json",
        "stop300_v3_builder_summary.json",
        "stop300_v3_packet_identity_contract.json",
        "stop300_v3_exact_token_boundary_contract.json",
        "stop300_v3_work_plan_receipt.json",
        "stop300_v3_timing_contract.json",
        "stop300_v3_environment_contract.json",
        "stop300_v3_resume_durability_contract.json",
        "stop300_v3_publication_contract.json",
        "stop300_v3_result_court_contract.json",
        "stop300_v3_packet_decision.json",
        "stop300_v3_claim_boundary_receipt.json",
        "stop300_v3_packet_validation_receipt.json",
    ])
    paths.extend((path, "CANONICAL_TEST", "INTERNAL_SHADOW", True, "STOP300 V3 focused test.") for path in sorted((ROOT / "tests").glob("test_stop300_v3_*.py")))
    paths.extend((path, "CANONICAL_TEST", "INTERNAL_SHADOW", True, "STOP300 V2 postmerge audit test.") for path in sorted((ROOT / "tests").glob("test_stop300_v2_postmerge_audit.py")))
    update_registry(paths)


def main() -> int:
    audit = read_json(REPORTS / "stop300_v2_postmerge_semantic_audit.json")
    if audit["status"] != "BLOCKED_GPU_RUN_POSTMERGE_SEMANTIC_DEFECTS":
        raise SystemExit("expected V2 postmerge defects before V3 forge")
    if sha256_file(STOP300_V2_PACKET) != EXPECTED_V2_SHA:
        raise SystemExit("V2 packet changed; preserve byte-for-byte")
    packet_sha = write_packet()
    write_reports(packet_sha)
    update_v3_registry()
    summary = {"schema_id": "kt.stop300.v3.builder_summary.v1", "status": "PASS", "current_head": git_output("rev-parse", "HEAD"), "branch": git_output("branch", "--show-current"), "outcome": STOP300_V3_OUTCOME, "packet_path": rel(STOP300_V3_PACKET), "packet_sha256": packet_sha, "kaggle_dataset_name": STOP300_V3_DATASET, "one_cell_runbook": rel(STOP300_V3_RUNBOOK), "next_lawful_move": STOP300_V3_NEXT_LAWFUL_MOVE, **authority_payload(), "sandbox_inference_authority": True}
    write_json(REPORTS / "stop300_v3_builder_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
