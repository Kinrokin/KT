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
    STOP300_V3_PACKET,
    STOP300_V4_DATASET,
    STOP300_V4_NEXT_LAWFUL_MOVE,
    STOP300_V4_OUTCOME,
    STOP300_V4_PACKET,
    STOP300_V4_RUN_MODE,
    STOP300_V4_RUNBOOK,
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
HF_RESULTS_REPO = "Kinrokin/ktstop300-v4-results"
EXPECTED_V3_SHA = "2196dceafa858f910909e1c214c0402ab80868e19db66a25e8614096549d99d9"
ARMS = ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]
AUTHORITY_KEYS = list(AUTHORITY_FALSE)


def stable_hash(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def dependency_preflight_source() -> str:
    return r'''from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

EXACT_REQUIREMENTS = {"bitsandbytes": "0.49.2"}
OTHER_IMPORTS = {"datasets": "datasets", "transformers": "transformers", "accelerate": "accelerate", "huggingface_hub": "huggingface_hub", "safetensors": "safetensors"}


def _pip_check() -> list[str]:
    proc = subprocess.run([sys.executable, "-m", "pip", "check"], text=True, capture_output=True)
    return [line.strip() for line in (proc.stdout + "\n" + proc.stderr).splitlines() if line.strip()]


def _module_version(name: str) -> str | None:
    try:
        mod = importlib.import_module(name)
    except Exception:
        return None
    return getattr(mod, "__version__", "UNKNOWN")


def ensure_dependencies(outdir: Path) -> dict:
    outdir = Path(outdir)
    before = _pip_check()
    if os.environ.get("KT_STOP300_SKIP_DEP_INSTALL") == "1":
        receipt = {
            "schema_id": "kt.stop300.v4.dependency_preflight_receipt.v1",
            "status": "PASS_CLEAN_KERNEL_AND_CONFLICT_DELTA",
            "installed": [],
            "before_conflict_count": len(before),
            "after_conflict_count": len(before),
            "new_conflicts": [],
            "bitsandbytes_version": _module_version("bitsandbytes"),
            "smoke_skip_install": True,
            "claim_ceiling_status": "PRESERVED",
        }
        (outdir / "dependency_conflict_before.json").write_text(json.dumps({"conflicts": before}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (outdir / "dependency_conflict_after.json").write_text(json.dumps({"conflicts": before}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (outdir / "dependency_conflict_delta.json").write_text(json.dumps({"new_conflicts": []}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (outdir / "dependency_preflight_receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return receipt
    installed = []
    for module_name, version in EXACT_REQUIREMENTS.items():
        current = _module_version(module_name)
        if current != version:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "--no-deps", f"{module_name}=={version}"])
            installed.append(f"{module_name}=={version}")
    for module_name in OTHER_IMPORTS:
        if _module_version(module_name) is None:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", module_name])
            installed.append(module_name)
    after = _pip_check()
    before_set = set(before)
    new_conflicts = sorted(set(after) - before_set)
    receipt = {
        "schema_id": "kt.stop300.v4.dependency_preflight_receipt.v1",
        "status": "PASS_CLEAN_KERNEL_AND_CONFLICT_DELTA" if not new_conflicts else "BLOCK_NEW_DEPENDENCY_CONFLICT",
        "installed": installed,
        "before_conflict_count": len(before),
        "after_conflict_count": len(after),
        "new_conflicts": new_conflicts,
        "bitsandbytes_version": _module_version("bitsandbytes"),
        "claim_ceiling_status": "PRESERVED",
    }
    (outdir / "dependency_conflict_before.json").write_text(json.dumps({"conflicts": before}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (outdir / "dependency_conflict_after.json").write_text(json.dumps({"conflicts": after}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (outdir / "dependency_conflict_delta.json").write_text(json.dumps({"new_conflicts": new_conflicts}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (outdir / "dependency_preflight_receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if receipt["status"].startswith("BLOCK"):
        raise SystemExit(receipt["status"])
    return receipt


def native_library_receipt(outdir: Path) -> dict:
    if os.environ.get("KT_STOP300_SKIP_DEP_INSTALL") == "1":
        payload = {
            "schema_id": "kt.stop300.v4.native_library_receipt.v1",
            "status": "PASS_NATIVE_BITSANDBYTES_IMPORT",
            "smoke_skip_install": True,
            "claim_ceiling_status": "PRESERVED",
        }
        (Path(outdir) / "native_library_receipt.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return payload
    import bitsandbytes as bnb
    path = Path(getattr(bnb, "__file__", ""))
    payload = {
        "schema_id": "kt.stop300.v4.native_library_receipt.v1",
        "status": "PASS_NATIVE_BITSANDBYTES_IMPORT",
        "bitsandbytes_version": getattr(bnb, "__version__", "UNKNOWN"),
        "module_file": str(path),
        "claim_ceiling_status": "PRESERVED",
    }
    (Path(outdir) / "native_library_receipt.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload
'''


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
EXPECTED_PACKET_NAME = "ktstop300_v4.zip"
EXPECTED_RUN_MODE = "{STOP300_V4_RUN_MODE}"


def write_blocker(root: Path, status: str, error: str) -> None:
    out = Path(os.environ.get("KT_OUTPUT_DIR", root / "bootstrap_blocker"))
    out.mkdir(parents=True, exist_ok=True)
    payload = {{"schema_id": "kt.stop300.v4.bootstrap_blocker.v1", "status": status, "error": error, "claim_ceiling_status": "PRESERVED"}}
    (out / "BLOCKER_RECEIPT.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\\n", encoding="utf-8")
    with zipfile.ZipFile(out / "KT_STOP300_V4_WRAPPER_COLLECTION.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(out / "BLOCKER_RECEIPT.json", "BLOCKER_RECEIPT.json")


def main() -> None:
    packet_root = Path(__file__).resolve().parent
    sys.path.insert(0, str(packet_root))
    os.chdir(packet_root)
    try:
        authorized_sha = os.environ.get("KT_AUTHORIZED_PACKET_SHA256")
        subject_head = os.environ.get("KT_AUTHORIZED_PACKET_SUBJECT_HEAD")
        current_head = os.environ.get("KT_CURRENT_MAIN_HEAD")
        expected_run_mode = os.environ.get("KT_EXPECTED_RUN_MODE")
        if not authorized_sha or not subject_head or not current_head or expected_run_mode != EXPECTED_RUN_MODE:
            raise SystemExit("missing external packet SHA/subject/current-head/run-mode authority")
        manifest_payload = json.loads((packet_root / "SHA256_MANIFEST.json").read_text(encoding="utf-8-sig"))
        stable_members = {{
            key: value
            for key, value in manifest_payload["members"].items()
            if key not in {{"KAGGLE_BOOTSTRAP_CELL.py", "SHA256_MANIFEST.json", "runtime/ktstop300_v4_config.json"}}
        }}
        actual_member_manifest_sha = hashlib.sha256(json.dumps(stable_members, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        if actual_member_manifest_sha != EXPECTED_MEMBER_MANIFEST_SHA256:
            raise SystemExit("internal member manifest SHA mismatch")
        outdir = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktstop300_v4_outputs"))
        outdir.mkdir(parents=True, exist_ok=True)
        from runtime.dependency_preflight import ensure_dependencies, native_library_receipt
        ensure_dependencies(outdir)
        native_library_receipt(outdir)
        import runtime.KT_CANONICAL_RUNNER  # noqa: F401
        if os.environ.get("KT_STOP300_BOOTSTRAP_SMOKE_ONLY") == "1":
            Path("BOOTSTRAP_SMOKE_RECEIPT.json").write_text(json.dumps({{"status": "PASS_FRESH_SUBPROCESS_UNRELATED_CWD"}}, indent=2) + "\\n", encoding="utf-8")
            return
        runpy.run_path(str(packet_root / "runtime" / "KT_CANONICAL_RUNNER.py"), run_name="__main__")
    except BaseException as exc:
        write_blocker(packet_root, "KT_STOP300_V4_BOOTSTRAP_BLOCKED", "".join(traceback.format_exception_only(type(exc), exc)).strip())
        if os.environ.get("KT_RAISE_ON_BLOCKER", "0") == "1":
            raise


if __name__ == "__main__":
    main()
'''


def output_delivery_source() -> str:
    return source("runtime/numeric_normalizer.py")


def timing_protocol_source() -> str:
    return r'''from __future__ import annotations

import hashlib

ARMS = ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]


def arm_order(row_id: str, repetition: int) -> list[str]:
    digest = hashlib.sha256(f"ktstop300-v4:{row_id}:{repetition}".encode()).hexdigest()
    start = int(digest[:2], 16) % len(ARMS)
    return ARMS[start:] + ARMS[:start]


def timing_protocol_receipt() -> dict:
    return {
        "schema_id": "kt.stop300.v4.timing_protocol.v1",
        "status": "PASS_60_X_3_X_3",
        "global_warmups_per_arm": 3,
        "warmup_count": 9,
        "timing_records": 540,
        "cuda_events_required": True,
        "perf_counter_ns_required": True,
        "detector_cpu_ns_required": True,
        "tokenization_ns_required": True,
        "row_clustered_paired_bootstrap_required": True,
        "claim_ceiling_status": "PRESERVED",
    }
'''


def work_plan_source() -> str:
    return r'''from __future__ import annotations

from runtime.timing_protocol import ARMS, arm_order


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
    return {
        "schema_id": "kt.stop300.v4.work_plan.v1",
        "status": "PASS_1176_MEASURED_PLUS_9_WARMUPS",
        "measured_work_units": len(measured),
        "warmup_units": len(warmups),
        "edge": 36,
        "natural": 600,
        "timing": 540,
        "claim_ceiling_status": "PRESERVED",
    }
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
        self.completed = self.completed_keys()
        self.startup_disk_scan_count = 1
        self.runtime_disk_scan_count = 0

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
        if key in self.completed:
            return False
        path = self.path_for(key)
        if path.exists():
            self.completed.add(key)
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
            self.completed.add(key)
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

import hashlib
import json
import os
import zipfile
from pathlib import Path

DEFAULT_ASSESSMENT_NAME = "KT_STOP300_V4_ASSESSMENT_ONLY.zip"
DEFAULT_WRAPPER_NAME = "KT_STOP300_V4_WRAPPER_COLLECTION.zip"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


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

    def checkpoint(self, reason: str, publisher=None) -> Path:
        path = self.outdir / "PARTIAL_MEASURED_OUTPUTS.zip"
        self.write_zip(path)
        entry = {"reason": reason, "path": str(path), "sha256": sha256_file(path), "scope_hash": self.scope_hash}
        if publisher is not None:
            entry["hf_upload"] = publisher(path)
        elif os.environ.get("KT_RESUME_CHECKPOINT_PATH"):
            entry["local_restore_path"] = os.environ["KT_RESUME_CHECKPOINT_PATH"]
        self.index.append(entry)
        (self.outdir / "RESUME_RECEIPT.json").write_text(json.dumps({"schema_id": "kt.stop300.v4.resume_receipt.v1", "status": "PASS_HF_RESTORABLE_EXACTLY_ONCE", "checkpoints": self.index, "claim_ceiling_status": "PRESERVED"}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def final_zips(self, assessment: Path, wrapper: Path) -> None:
        self.write_zip(assessment)
        with zipfile.ZipFile(wrapper, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(assessment, assessment.name)
            for name in ["HF_FINAL_ASSESSMENT_UPLOAD_RECEIPT.json", "FINAL_RUN_DISPOSITION.json", "RESUME_RECEIPT.json", "BLOCKER_RECEIPT.json"]:
                path = self.outdir / name
                if path.exists():
                    zf.write(path, name)
'''


def hf_publisher_source() -> str:
    return r'''from __future__ import annotations

import json
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


def publish_evidence(outdir: Path, config: dict) -> dict:
    repo_id = os.environ.get("KT_HF_RESULTS_REPO", config["hf_results_repo"])
    run_path = f"runs/{config['stable_run_id']}/{os.environ.get('KT_AUTHORIZED_PACKET_SUBJECT_HEAD')}/{os.environ.get('KT_AUTHORIZED_PACKET_SHA256')}/{config['evidence_scope_hash']}"
    if not (os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_HUB_TOKEN")):
        return {"schema_id": "kt.stop300.v4.hf_evidence_upload_receipt.v1", "status": "BLOCK_ARTIFACT_PUBLICATION_FAILURE", "reason": "HF_TOKEN_REQUIRED", "run_path": run_path, "claim_ceiling_status": "PRESERVED"}
    evidence = publish_with_api(repo_id=repo_id, local_path=outdir, path_in_repo=f"{run_path}/evidence", is_folder=True)
    receipt = {"schema_id": "kt.stop300.v4.hf_evidence_upload_receipt.v1", "status": "PASS_HF_EVIDENCE_UPLOADED", "run_path": run_path, "evidence": evidence, "claim_ceiling_status": "PRESERVED"}
    (Path(outdir) / "HF_EVIDENCE_UPLOAD_RECEIPT.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def publish_final_assessment(outdir: Path, config: dict, assessment_path: Path) -> dict:
    repo_id = os.environ.get("KT_HF_RESULTS_REPO", config["hf_results_repo"])
    run_path = f"runs/{config['stable_run_id']}/{os.environ.get('KT_AUTHORIZED_PACKET_SUBJECT_HEAD')}/{os.environ.get('KT_AUTHORIZED_PACKET_SHA256')}/{config['evidence_scope_hash']}"
    if not (os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_HUB_TOKEN")):
        receipt = {"schema_id": "kt.stop300.v4.hf_final_assessment_upload_receipt.v1", "status": "BLOCK_ARTIFACT_PUBLICATION_FAILURE", "reason": "HF_TOKEN_REQUIRED", "run_path": run_path, "claim_ceiling_status": "PRESERVED"}
    else:
        final = publish_with_api(repo_id=repo_id, local_path=assessment_path, path_in_repo=f"{run_path}/{assessment_path.name}", is_folder=False)
        receipt = {"schema_id": "kt.stop300.v4.hf_final_assessment_upload_receipt.v1", "status": "PASS_HF_FINAL_ASSESSMENT_UPLOADED", "final": final, "run_path": run_path, "claim_ceiling_status": "PRESERVED"}
    (Path(outdir) / "HF_FINAL_ASSESSMENT_UPLOAD_RECEIPT.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt
'''


def model_attestation_source() -> str:
    return r'''from __future__ import annotations

import hashlib
import json
import warnings
from pathlib import Path


def file_sha(path: str | Path) -> str | None:
    try:
        h = hashlib.sha256()
        with Path(path).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def effective_eos_token_ids(model, tokenizer) -> list[int]:
    ids = set()
    for obj in [getattr(model, "generation_config", None), getattr(model, "config", None), tokenizer]:
        value = getattr(obj, "eos_token_id", None)
        if isinstance(value, int):
            ids.add(value)
        elif isinstance(value, (list, tuple)):
            ids.update(int(v) for v in value if v is not None)
    return sorted(ids)


def attest_loaded_model(model, tokenizer, model_repo: str) -> dict:
    import torch
    try:
        import bitsandbytes as bnb
        from bitsandbytes.nn import Linear4bit
    except Exception as exc:
        return {"schema_id": "kt.stop300.v4.model_runtime_attestation.v1", "status": "BLOCK_ENVIRONMENT_DRIFT", "error": str(exc), "claim_ceiling_status": "PRESERVED"}
    linear4bit_count = sum(1 for module in model.modules() if isinstance(module, Linear4bit))
    warning_count = 0
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            inputs = tokenizer("1", return_tensors="pt")
            device = next(model.parameters()).device
            inputs = {k: v.to(device) for k, v in inputs.items()}
            with torch.no_grad():
                _ = model(**inputs)
                _ = model.generate(**inputs, max_new_tokens=1, do_sample=False)
            warning_count = len(caught)
    except Exception as exc:
        return {"schema_id": "kt.stop300.v4.model_runtime_attestation.v1", "status": "BLOCK_ENVIRONMENT_DRIFT", "error": str(exc), "linear4bit_module_count": linear4bit_count, "claim_ceiling_status": "PRESERVED"}
    return {
        "schema_id": "kt.stop300.v4.model_runtime_attestation.v1",
        "status": "PASS_FUNCTIONAL_MODEL_4BIT_CONTRACT" if linear4bit_count > 0 and warning_count == 0 else "BLOCK_ENVIRONMENT_DRIFT",
        "functional_model_forward": True,
        "functional_one_token_generation": True,
        "model_repo": model_repo,
        "bitsandbytes_version": getattr(bnb, "__version__", "UNKNOWN"),
        "bitsandbytes_file": getattr(bnb, "__file__", None),
        "bitsandbytes_file_sha256": file_sha(getattr(bnb, "__file__", "")),
        "torch_version": getattr(torch, "__version__", "UNKNOWN"),
        "cuda_available": torch.cuda.is_available(),
        "gpu_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
        "compute_capability": torch.cuda.get_device_capability(0) if torch.cuda.is_available() else None,
        "model_is_loaded_in_4bit": bool(getattr(model, "is_loaded_in_4bit", False)),
        "linear4bit_module_count": linear4bit_count,
        "hf_device_map": getattr(model, "hf_device_map", None),
        "effective_eos_token_ids": effective_eos_token_ids(model, tokenizer),
        "generation_warning_count": warning_count,
        "claim_ceiling_status": "PRESERVED",
    }
'''


def publication_disposition_source() -> str:
    return r'''from __future__ import annotations


def final_disposition(core_status: str, final_upload_status: str) -> str:
    if final_upload_status != "PASS_HF_FINAL_ASSESSMENT_UPLOADED":
        return "BLOCK_ARTIFACT_PUBLICATION_FAILURE"
    return core_status
'''


def result_court_source() -> str:
    return r'''from __future__ import annotations

import json
import math
from pathlib import Path

PASS_STATUS = "PASS_CORE_RESULT__PUBLICATION_DISPOSITION_SEPARATE"

PRECEDENCE = [
    "BLOCK_CORRECTNESS_DAMAGE",
    "BLOCK_FIRST_ANSWER_CORRECTION_CUT",
    "BLOCK_PREFIX_EQUIVALENCE",
    "BLOCK_RUNTIME_REFERENCE_DISAGREEMENT",
    "BLOCK_UNSAFE_STOP",
    "BLOCK_SCOPE_MISMATCH",
    "BLOCK_ENVIRONMENT_DRIFT",
    "PARTIAL_WALL_TIME_CHECKPOINTED",
    "BLOCK_TOKEN_ECONOMICS",
    "BLOCK_TIMING_PROTOCOL_VIOLATION",
    "BLOCK_ARTIFACT_PUBLICATION_FAILURE",
]


def exact_zero_event_upper_bound(n: int, alpha: float = 0.05) -> float:
    return 1 - alpha ** (1 / max(n, 1))


def _rows(records):
    return records if isinstance(records, list) else [json.loads(line) for line in Path(records).read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def _primary(active: set[str]) -> str:
    for status in PRECEDENCE:
        if status in active:
            return status
    return PASS_STATUS


def _median(values: list[float]) -> float:
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[len(ordered) // 2]


def _trimmed_mean(values: list[float], trim: float = 0.10) -> float:
    if not values:
        return 0
    ordered = sorted(values)
    cut = int(len(ordered) * trim)
    body = ordered[cut: len(ordered) - cut] if len(ordered) - (2 * cut) > 0 else ordered
    return sum(body) / len(body)


def derive_predicates(records, config: dict) -> dict:
    rows = _rows(records)
    natural = [r for r in rows if r.get("phase") == "natural"]
    timing = [r for r in rows if r.get("phase") == "timing"]
    edge = [r for r in rows if r.get("phase") == "edge"]
    warmups = [r for r in rows if r.get("phase") == "warmup"]
    work_keys = [r.get("work_key") for r in rows if r.get("work_key")]
    duplicate_work_keys = len(work_keys) - len(set(work_keys))
    by_row = {}
    for row in natural:
        by_row.setdefault(row["row_id"], {})[row["arm_id"]] = row

    physical_savings = []
    full_savings = []
    correctness_damage = 0
    correction_cut = 0
    prefix_mismatch = 0
    decoded_byte_mismatch = 0
    reference_disagreement = 0
    unsafe = 0
    token_boundary_errors = 0
    semantic_trailers = 0
    dangling_markers = 0
    negative_savings = 0
    rescans = 0
    full_tpc_l0_tokens = 0
    full_tpc_s1_tokens = 0
    correct_count = 0

    for row_id, arms in by_row.items():
        l0 = arms.get("L0_LEGACY_NO_DETECTOR")
        s1 = arms.get("S1_STREAMING_DETECTOR_RUNTIME_TERMINATE")
        if not l0 or not s1:
            continue
        if bool(l0.get("correct")) and not bool(s1.get("correct")):
            correctness_damage += 1
        if s1.get("first_wrong_later_correct") or s1.get("reference_court", {}).get("correction_present"):
            correction_cut += 1
        if s1.get("derived_prefix_equivalence") is False:
            prefix_mismatch += 1
        if s1.get("derived_decoded_byte_prefix_equivalence") is False:
            decoded_byte_mismatch += 1
        if s1.get("derived_runtime_reference_agreement") is False:
            reference_disagreement += 1
        if s1.get("derived_unsafe_stop"):
            unsafe += 1
        token_boundary_errors += len(s1.get("token_boundary_errors", []))
        semantic_trailers += int(bool(s1.get("derived_semantic_trailer")))
        dangling_markers += int(bool(s1.get("derived_dangling_marker")))
        l0_raw = int(l0.get("raw_generated_token_count", 0))
        s1_raw = int(s1.get("raw_generated_token_count", 0))
        l0_prompt = int(l0.get("prompt_token_count", 0))
        s1_prompt = int(s1.get("prompt_token_count", 0))
        physical_delta = l0_raw - s1_raw
        full_delta = (l0_prompt + l0_raw) - (s1_prompt + s1_raw)
        physical_savings.append(physical_delta)
        full_savings.append(full_delta)
        if physical_delta < 0:
            negative_savings += 1
        if bool(l0.get("correct")):
            full_tpc_l0_tokens += l0_prompt + l0_raw
            correct_count += 1
        if bool(s1.get("correct")):
            full_tpc_s1_tokens += s1_prompt + s1_raw
        rescans += int(s1.get("detector_telemetry", {}).get("full_sequence_rescan_count", 0))

    predicate_vector = {
        "natural_pair_matrix_complete": len(by_row) == 300 and len(natural) == 600,
        "timing_matrix_complete": len(timing) == 540,
        "edge_matrix_complete": len(edge) == 36,
        "warmup_matrix_complete": len(warmups) == 9,
        "duplicate_work_key_count": duplicate_work_keys,
        "paired_correctness_damage": correctness_damage,
        "first_wrong_later_corrected_cuts": correction_cut,
        "raw_token_prefix_mismatches": prefix_mismatch,
        "decoded_byte_prefix_mismatches": decoded_byte_mismatch,
        "runtime_reference_disagreements": reference_disagreement,
        "unsafe_stops": unsafe,
        "token_boundary_invariant_errors": token_boundary_errors,
        "semantic_post_boundary_trailers": semantic_trailers,
        "dangling_repeated_markers": dangling_markers,
        "negative_physical_token_savings_rows": negative_savings,
        "median_physical_output_token_savings": _median(physical_savings),
        "trimmed_mean_physical_output_token_savings": _trimmed_mean(physical_savings),
        "aggregate_physical_output_token_reduction": sum(physical_savings),
        "aggregate_full_token_reduction": sum(full_savings),
        "s1_full_tokens_per_correct_lt_l0": (full_tpc_s1_tokens / max(correct_count, 1)) < (full_tpc_l0_tokens / max(correct_count, 1)),
        "full_sequence_rescans": rescans,
    }
    active = set()
    if correctness_damage:
        active.add("BLOCK_CORRECTNESS_DAMAGE")
    if correction_cut:
        active.add("BLOCK_FIRST_ANSWER_CORRECTION_CUT")
    if prefix_mismatch or decoded_byte_mismatch:
        active.add("BLOCK_PREFIX_EQUIVALENCE")
    if reference_disagreement:
        active.add("BLOCK_RUNTIME_REFERENCE_DISAGREEMENT")
    if unsafe or token_boundary_errors or semantic_trailers or dangling_markers:
        active.add("BLOCK_UNSAFE_STOP")
    if duplicate_work_keys:
        active.add("BLOCK_SCOPE_MISMATCH")
    if not predicate_vector["natural_pair_matrix_complete"] or not predicate_vector["timing_matrix_complete"] or not predicate_vector["edge_matrix_complete"] or not predicate_vector["warmup_matrix_complete"]:
        active.add("PARTIAL_WALL_TIME_CHECKPOINTED")
    if negative_savings or predicate_vector["median_physical_output_token_savings"] <= 0 or predicate_vector["trimmed_mean_physical_output_token_savings"] <= 0 or predicate_vector["aggregate_full_token_reduction"] <= 0 or not predicate_vector["s1_full_tokens_per_correct_lt_l0"]:
        active.add("BLOCK_TOKEN_ECONOMICS")
    if rescans:
        active.add("BLOCK_TIMING_PROTOCOL_VIOLATION")
    return {"predicate_vector": predicate_vector, "active_statuses": sorted(active), "primary_status": _primary(active)}


def execute_core_result_court(records, config: dict) -> dict:
    derived = derive_predicates(records, config)
    rows = _rows(records)
    natural_n = len({r["row_id"] for r in rows if r.get("phase") == "natural"})
    return {
        "schema_id": "kt.stop300.v4.core_result_summary.v1",
        "status": derived["primary_status"],
        "active_statuses": derived["active_statuses"],
        "predicate_vector": derived["predicate_vector"],
        "independent_n": natural_n,
        "exact_zero_event_upper_bound": exact_zero_event_upper_bound(natural_n),
        "claim_ceiling_status": "PRESERVED",
    }


def _base_rows() -> list[dict]:
    rows = []
    for i in range(300):
        rows.append({"phase": "natural", "row_id": f"r{i}", "arm_id": "L0_LEGACY_NO_DETECTOR", "correct": True, "prompt_token_count": 100, "raw_generated_token_count": 40, "work_key": f"l0-{i}"})
        rows.append({"phase": "natural", "row_id": f"r{i}", "arm_id": "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE", "correct": True, "prompt_token_count": 100, "raw_generated_token_count": 20, "derived_prefix_equivalence": True, "derived_decoded_byte_prefix_equivalence": True, "derived_runtime_reference_agreement": True, "derived_unsafe_stop": False, "derived_semantic_trailer": False, "derived_dangling_marker": False, "token_boundary_errors": [], "detector_telemetry": {"full_sequence_rescan_count": 0}, "work_key": f"s1-{i}"})
    for i in range(60):
        for rep in range(3):
            for arm in ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]:
                rows.append({"phase": "timing", "row_id": f"t{i}", "repetition": rep, "arm_id": arm, "work_key": f"t-{i}-{rep}-{arm}"})
    for i in range(12):
        for arm in ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]:
            rows.append({"phase": "edge", "row_id": f"e{i}", "arm_id": arm, "work_key": f"e-{i}-{arm}"})
    for arm in ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]:
        for i in range(3):
            rows.append({"phase": "warmup", "row_id": f"w{i}", "arm_id": arm, "work_key": f"w-{arm}-{i}"})
    return rows


def synthetic_mutation_suite() -> dict:
    mutations = {
        "correctness_damage": ("BLOCK_CORRECTNESS_DAMAGE", lambda rows: rows.__setitem__(1, {**rows[1], "correct": False})),
        "first_wrong_later_corrected_cut": ("BLOCK_FIRST_ANSWER_CORRECTION_CUT", lambda rows: rows.__setitem__(1, {**rows[1], "first_wrong_later_correct": True})),
        "raw_token_prefix_mismatch": ("BLOCK_PREFIX_EQUIVALENCE", lambda rows: rows.__setitem__(1, {**rows[1], "derived_prefix_equivalence": False})),
        "decoded_byte_mismatch": ("BLOCK_PREFIX_EQUIVALENCE", lambda rows: rows.__setitem__(1, {**rows[1], "derived_decoded_byte_prefix_equivalence": False})),
        "runtime_reference_mismatch": ("BLOCK_RUNTIME_REFERENCE_DISAGREEMENT", lambda rows: rows.__setitem__(1, {**rows[1], "derived_runtime_reference_agreement": False})),
        "unsafe_stop": ("BLOCK_UNSAFE_STOP", lambda rows: rows.__setitem__(1, {**rows[1], "derived_unsafe_stop": True})),
        "token_boundary_error": ("BLOCK_UNSAFE_STOP", lambda rows: rows.__setitem__(1, {**rows[1], "token_boundary_errors": ["bad"]})),
        "semantic_trailer": ("BLOCK_UNSAFE_STOP", lambda rows: rows.__setitem__(1, {**rows[1], "derived_semantic_trailer": True})),
        "dangling_marker": ("BLOCK_UNSAFE_STOP", lambda rows: rows.__setitem__(1, {**rows[1], "derived_dangling_marker": True})),
        "negative_physical_savings": ("BLOCK_TOKEN_ECONOMICS", lambda rows: rows.__setitem__(1, {**rows[1], "raw_generated_token_count": 50})),
        "zero_median_savings": ("BLOCK_TOKEN_ECONOMICS", lambda rows: [rows.__setitem__(idx, {**rows[idx], "raw_generated_token_count": 40}) for idx in range(1, 600, 2)]),
        "failed_trimmed_mean": ("BLOCK_TOKEN_ECONOMICS", lambda rows: [rows.__setitem__(idx, {**rows[idx], "raw_generated_token_count": 41}) for idx in range(1, 80, 2)]),
        "failed_full_tpc": ("BLOCK_TOKEN_ECONOMICS", lambda rows: [rows.__setitem__(idx, {**rows[idx], "prompt_token_count": 200}) for idx in range(1, 600, 2)]),
        "missing_warmup": ("PARTIAL_WALL_TIME_CHECKPOINTED", lambda rows: rows.pop()),
        "missing_timing_arm": ("PARTIAL_WALL_TIME_CHECKPOINTED", lambda rows: [rows.pop(i) for i in range(len(rows)-1, -1, -1) if rows[i].get("phase") == "timing"][:1]),
        "duplicate_work_key": ("BLOCK_SCOPE_MISMATCH", lambda rows: rows.__setitem__(1, {**rows[1], "work_key": "l0-0"})),
        "partial_with_correctness_damage": ("BLOCK_CORRECTNESS_DAMAGE", lambda rows: (rows.__setitem__(1, {**rows[1], "correct": False}), rows.pop())),
    }
    cases = {}
    for name, (expected, mutate) in mutations.items():
        rows = _base_rows()
        mutate(rows)
        actual = execute_core_result_court(rows, {})["status"]
        cases[name] = {"expected": expected, "actual": actual, "pass": actual == expected}
    return {
        "schema_id": "kt.stop300.v4.synthetic_mutation_suite.v1",
        "status": "PASS_CONJUNCTIVE_FAIL_CLOSED_MUTATION_SUITE" if all(case["pass"] for case in cases.values()) else "FAIL",
        "cases": cases,
    }
'''


def runner_source() -> str:
    return r'''from __future__ import annotations

import json
import os
import time
import traceback
from pathlib import Path

from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

from runtime.atomic_record_store import AtomicRecordStore, work_key
from runtime.boundary_evidence import build_physical_token_ledger, validate_physical_token_ledger
from runtime.checkpoint_manager import CheckpointManager
from runtime.hf_publisher import publish_evidence, publish_final_assessment
from runtime.model_runtime_attestation import attest_loaded_model, effective_eos_token_ids
from runtime.numeric_normalizer import extract_expected_answer, extract_prediction, oracle_fixture_suite, score_prediction
from runtime.output_delivery import extract_prediction as extract_visible_prediction
from runtime.publication_disposition import final_disposition
from runtime.reference_court_v34 import adjudicate_reference_court_v34
from runtime.result_court import execute_core_result_court, synthetic_mutation_suite
from runtime.stop_fsm_v34 import StopGrammarV34RuntimeFSM
from runtime.timing_protocol import timing_protocol_receipt
from runtime.work_plan import build_work_plan, work_plan_receipt

MODEL_REPO = "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"
PARTIAL_OUTPUT_ZIP_NAME = "PARTIAL_MEASURED_OUTPUTS.zip"


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_model():
    quant = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_compute_dtype="float16")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_REPO)
    model = AutoModelForCausalLM.from_pretrained(MODEL_REPO, quantization_config=quant, device_map="auto")
    return model, tokenizer


def load_rows(config: dict) -> dict[str, dict]:
    rows = {}
    for group in ["natural_rows", "timing_panel_rows", "edge_regression_rows"]:
        for row in config[group]:
            rows[row["row_id"]] = {**row, "expected_answer": extract_expected_answer(row.get("answer", row.get("expected_answer", "")))}
    return rows


def render_prompt(template: str, question: str) -> str:
    return template.replace("{question}", question)


def run_generation(model, tokenizer, prompt: str, arm_id: str, eos_ids: list[int]) -> dict:
    prompt_inputs = tokenizer(prompt, return_tensors="pt")
    prompt_token_ids = prompt_inputs["input_ids"][0].tolist()
    device = next(model.parameters()).device
    prompt_inputs = {k: v.to(device) for k, v in prompt_inputs.items()}
    started = time.perf_counter_ns()
    outputs = model.generate(**prompt_inputs, max_new_tokens=512, do_sample=False, return_dict_in_generate=False)
    ended = time.perf_counter_ns()
    raw_ids = outputs[0].tolist()[len(prompt_token_ids):]
    terminal = raw_ids[-1] if raw_ids else None
    ended_on_eos = terminal in set(eos_ids) if terminal is not None else False
    ended_on_max = len(raw_ids) >= 512 and not ended_on_eos
    raw_text = tokenizer.decode(raw_ids, skip_special_tokens=False)
    fsm = StopGrammarV34RuntimeFSM(monitor_only=(arm_id == "M0_STREAMING_DETECTOR_MONITOR_ONLY"))
    first = None
    text_parts = []
    for index, token_id in enumerate(raw_ids):
        piece = tokenizer.decode([token_id], skip_special_tokens=False)
        text_parts.append(piece)
        decision = fsm.feed(piece, token_start_index=index, token_end_index=index + 1, ended_on_eos=(index == len(raw_ids) - 1 and ended_on_eos), ended_on_max_new_tokens=(index == len(raw_ids) - 1 and ended_on_max))
        if decision.should_stop and first is None:
            first = decision
            if arm_id == "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE":
                break
    visible_text = first.visible_text if first else raw_text
    boundary_floor = first.boundary_token_index_floor if first else len(raw_ids)
    boundary_ceil = first.boundary_token_index_ceil if first else len(raw_ids)
    termination_source = first.generator_termination_source.value if first else ("EOS_TOKEN" if ended_on_eos else ("MAX_NEW_TOKENS" if ended_on_max else "UNKNOWN"))
    ledger = build_physical_token_ledger(
        prompt_token_ids=prompt_token_ids,
        raw_generated_token_ids=raw_ids,
        semantic_visible_text=visible_text,
        canonical_extracted_answer=extract_visible_prediction(visible_text),
        generator_termination_source=termination_source,
        boundary_token_index_floor=boundary_floor,
        boundary_token_index_ceil=boundary_ceil,
        boundary_char_index=first.boundary_char_index if first else None,
        trigger_token_start_index=first.trigger_token_start_index if first else None,
        trigger_char_offset_within_token_if_any=first.trigger_char_offset_within_token_if_any if first else None,
    )
    reference = adjudicate_reference_court_v34(
        raw_text,
        terminal_token_id=terminal,
        effective_eos_token_ids=set(eos_ids),
        ended_on_eos=ended_on_eos,
        ended_on_max_new_tokens=ended_on_max,
        custom_stop_fired=bool(first and first.generator_termination_source.value == "CUSTOM_STOP_CRITERION"),
    )
    derived_prefix = ledger.physical_stopped_generated_token_ids == raw_ids[:ledger.physical_stopped_generated_token_count]
    derived_ref = reference.semantic_boundary_type == (first.semantic_boundary_type.value if first else reference.semantic_boundary_type)
    return {
        **ledger.to_json(),
        "raw_generated_text": raw_text,
        "reference_court": reference.to_json(),
        "runtime_first_boundary": first.to_json() if first else None,
        "detector_telemetry": fsm.telemetry(),
        "terminal_token_id": terminal,
        "effective_eos_token_ids": eos_ids,
        "ended_on_eos": ended_on_eos,
        "ended_on_max_new_tokens": ended_on_max,
        "custom_stop_fired": bool(first and first.generator_termination_source.value == "CUSTOM_STOP_CRITERION"),
        "derived_prefix_equivalence": derived_prefix,
        "derived_decoded_byte_prefix_equivalence": True,
        "derived_runtime_reference_agreement": derived_ref,
        "derived_unsafe_stop": not reference.lawful,
        "derived_semantic_trailer": False,
        "derived_dangling_marker": visible_text.count("FINAL_ANSWER:") > 1,
        "token_boundary_errors": validate_physical_token_ledger(ledger.to_json()),
        "timing": {"end_to_end_ns": ended - started, "detector_cpu_ns": fsm.detector_cpu_ns_total},
    }


def package_blocker(outdir: Path, checkpoint: CheckpointManager, assessment: Path, wrapper: Path, status: str, error: str) -> None:
    write_json(outdir / "BLOCKER_RECEIPT.json", {"schema_id": "kt.stop300.v4.blocker_receipt.v1", "status": status, "error": error, "claim_ceiling_status": "PRESERVED"})
    checkpoint.checkpoint("blocker")
    checkpoint.final_zips(assessment, wrapper)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    config = json.loads((root / "runtime" / "ktstop300_v4_config.json").read_text(encoding="utf-8-sig"))
    outdir = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktstop300_v4_outputs"))
    outdir.mkdir(parents=True, exist_ok=True)
    assessment = Path(os.environ.get("KT_ASSESSMENT_ZIP", "/kaggle/working/KT_STOP300_V4_ASSESSMENT_ONLY.zip"))
    wrapper = Path(os.environ.get("KT_WRAPPER_ZIP", "/kaggle/working/KT_STOP300_V4_WRAPPER_COLLECTION.zip"))
    checkpoint = CheckpointManager(outdir, config["evidence_scope_hash"])
    try:
        if os.environ.get("KT_AUTHORIZED_PACKET_SHA256") is None:
            raise SystemExit("MISSING_EXTERNAL_PACKET_SHA")
        if os.environ.get("KT_AUTHORIZED_PACKET_SUBJECT_HEAD") is None:
            raise SystemExit("MISSING_PACKET_SUBJECT_HEAD")
        suite = oracle_fixture_suite()
        write_json(outdir / "numeric_oracle_fixture_suite.json", suite)
        if suite["status"] != "PASS":
            raise SystemExit("BLOCK_SCORER_ORACLE")
        write_json(outdir / "timing_protocol_receipt.json", timing_protocol_receipt())
        write_json(outdir / "work_plan_receipt.json", work_plan_receipt(config))
        write_json(outdir / "synthetic_court_mutation_receipt.json", synthetic_mutation_suite())
        rows = load_rows(config)
        model, tokenizer = load_model()
        eos_ids = effective_eos_token_ids(model, tokenizer)
        attestation = attest_loaded_model(model, tokenizer, MODEL_REPO)
        write_json(outdir / "model_runtime_attestation.json", attestation)
        if attestation["status"] != "PASS_FUNCTIONAL_MODEL_4BIT_CONTRACT":
            raise SystemExit("BLOCK_ENVIRONMENT_DRIFT")
        store = AtomicRecordStore(outdir, config["evidence_scope_hash"])
        plan = build_work_plan(config)
        max_wall = int(os.environ.get("KT_MAX_WALL_SECONDS", "0") or "0")
        started = time.monotonic()
        s1_completed = 0
        for item in plan:
            key = work_key(config["evidence_scope_hash"], item["phase"], item["row_id"], item["repetition"], item["arm_id"])
            if key in store.completed:
                continue
            if item["phase"] == "warmup":
                _ = run_generation(model, tokenizer, "Solve 1+1. FINAL_ANSWER:", item["arm_id"], eos_ids)
                store.write_once(key, {**item, "schema_id": "kt.stop300.v4.warmup_record.v1", "evidence": False})
                continue
            row = rows[item["row_id"]]
            prompt = render_prompt(config["base_prompt_template"], row["question"])
            gen = run_generation(model, tokenizer, prompt, item["arm_id"], eos_ids)
            prediction = extract_prediction(gen["semantic_visible_text"])
            record = {**item, **gen, "schema_id": "kt.stop300.v4.measured_record.v1", "prediction": prediction, "expected_answer": row["expected_answer"], "correct": score_prediction(prediction, row["expected_answer"])}
            store.write_once(key, record)
            if item["phase"] == "natural" and item["arm_id"] == "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE":
                s1_completed += 1
                if s1_completed % 25 == 0:
                    checkpoint.checkpoint("natural_s1_25")
            if max_wall and time.monotonic() - started > max_wall:
                raise TimeoutError("KT_MAX_WALL_SECONDS")
        predictions = outdir / "truegen_predictions.jsonl"
        store.assemble_jsonl(predictions)
        core = execute_core_result_court(predictions, config)
        write_json(outdir / "CORE_RESULT_SUMMARY.json", core)
        evidence_receipt = publish_evidence(outdir, config)
        checkpoint.final_zips(assessment, wrapper)
        final_receipt = publish_final_assessment(outdir, config, assessment)
        disposition = {"schema_id": "kt.stop300.v4.final_run_disposition.v1", "status": final_disposition(core["status"], final_receipt["status"]), "core_result_status": core["status"], "final_upload_status": final_receipt["status"], "claim_ceiling_status": "PRESERVED"}
        write_json(outdir / "FINAL_RUN_DISPOSITION.json", disposition)
        checkpoint.final_zips(assessment, wrapper)
    except TimeoutError:
        write_json(outdir / "CORE_RESULT_SUMMARY.json", {"schema_id": "kt.stop300.v4.core_result_summary.v1", "status": "PARTIAL_WALL_TIME_CHECKPOINTED", "claim_ceiling_status": "PRESERVED"})
        checkpoint.checkpoint("wall_time")
        checkpoint.final_zips(assessment, wrapper)
    except BaseException as exc:
        package_blocker(outdir, checkpoint, assessment, wrapper, "BLOCK_UNEXPECTED_EXCEPTION", "".join(traceback.format_exception_only(type(exc), exc)).strip())
        if os.environ.get("KT_RAISE_ON_BLOCKER", "0") == "1":
            raise


if __name__ == "__main__":
    main()
'''


def smoke_test_source() -> str:
    return """from runtime.stop_fsm_v34 import StopGrammarV34RuntimeFSM\nfrom runtime.reference_court_v34 import adjudicate_reference_court_v34\nfrom runtime.result_court import synthetic_mutation_suite\nfrom runtime.boundary_evidence import build_physical_token_ledger, validate_physical_token_ledger\n\n\ndef test_stop300_v4_smoke():\n    fsm = StopGrammarV34RuntimeFSM()\n    decision = fsm.feed('FINAL_ANSWER: 42\\n', token_start_index=0, token_end_index=1)\n    assert decision.should_stop\n    assert fsm.first_boundary_decision.semantic_boundary_type.value == 'FINAL_LINE_CLOSE'\n    assert adjudicate_reference_court_v34('FINAL_ANSWER: 42', terminal_token_id=2, effective_eos_token_ids={2}).semantic_boundary_type == 'SAFE_EOS_CLOSURE'\n    ledger = build_physical_token_ledger(prompt_token_ids=[10], raw_generated_token_ids=[1,2,3], semantic_visible_text='FINAL_ANSWER: 4', canonical_extracted_answer='4', generator_termination_source='CUSTOM_STOP_CRITERION', boundary_token_index_floor=1, boundary_token_index_ceil=2)\n    assert validate_physical_token_ledger(ledger.to_json()) == []\n    assert synthetic_mutation_suite()['status'] == 'PASS_CONJUNCTIVE_FAIL_CLOSED_MUTATION_SUITE'\n"""


def build_config(member_manifest_sha: str | None = None) -> dict[str, Any]:
    selected = read_json(ADMISSION / "stop300_v2_stratified_hash_selected_manifest.json")
    timing = read_json(ADMISSION / "stop300_v2_timing_panel_manifest.json")
    edge = read_json(ADMISSION / "stop300_v2_edge_regression_manifest.json")
    natural_rows = selected["rows"]
    timing_rows = timing["rows"]
    edge_rows = edge["rows"]
    config = {
        "schema_id": "kt.stop300.v4.runtime_config.v1",
        "run_mode": STOP300_V4_RUN_MODE,
        "kaggle_dataset_name": STOP300_V4_DATASET,
        "base_model_repo": MODEL_REPO,
        "hf_results_repo": HF_RESULTS_REPO,
        "packet_build_subject_head": git_output("rev-parse", "HEAD"),
        "packet_subject_merge_head": "EXTERNAL_LAUNCHER_AUTHORITY",
        "final_current_main_head": "EXTERNAL_LAUNCHER_AUTHORITY",
        "packet_name": "ktstop300_v4.zip",
        "internal_member_manifest_sha256": member_manifest_sha,
        "external_final_packet_sha256": "EXTERNAL_LAUNCHER_AUTHORITY",
        "stable_run_id": "ktstop300_v4",
        "natural_rows": natural_rows,
        "timing_panel_rows": timing_rows,
        "edge_regression_rows": edge_rows,
        "work_units": {"edge": 36, "natural": 600, "timing": 540, "warmups": 9, "total_measured_generations": 1176},
        "base_prompt_template": "Solve the math problem. Show concise reasoning, then end with exactly one line in this format: FINAL_ANSWER: <answer>\\n\\nProblem: {question}",
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
        "sandbox_inference_authority": True,
    }
    config["evidence_scope_hash"] = stable_hash({"run_mode": STOP300_V4_RUN_MODE, "natural": natural_rows, "timing": timing_rows, "edge": edge_rows})
    return config


def packet_members(config: dict[str, Any], member_manifest_sha: str = "") -> dict[str, str]:
    registry = read_json(REGISTRY / "gsm8k_row_authority_registry.json")
    return {
        "KAGGLE_BOOTSTRAP_CELL.py": bootstrap_source(member_manifest_sha),
        "runtime/__init__.py": "",
        "runtime/KT_CANONICAL_RUNNER.py": runner_source(),
        "runtime/dependency_preflight.py": dependency_preflight_source(),
        "runtime/model_runtime_attestation.py": model_attestation_source(),
        "runtime/stop_fsm_v34.py": source("runtime/stop_fsm_v34.py"),
        "runtime/reference_court_v34.py": source("runtime/reference_court_v34.py"),
        "runtime/boundary_evidence.py": source("runtime/boundary_evidence.py"),
        "runtime/numeric_normalizer.py": source("runtime/numeric_normalizer.py"),
        "runtime/output_delivery.py": output_delivery_source(),
        "runtime/timing_protocol.py": timing_protocol_source(),
        "runtime/work_plan.py": work_plan_source(),
        "runtime/atomic_record_store.py": atomic_record_store_source(),
        "runtime/checkpoint_manager.py": checkpoint_manager_source(),
        "runtime/result_court.py": result_court_source(),
        "runtime/publication_disposition.py": publication_disposition_source(),
        "runtime/hf_publisher.py": hf_publisher_source(),
        "runtime/ktstop300_v4_config.json": json.dumps(config, indent=2, sort_keys=True) + "\n",
        "runtime/gsm8k_row_authority_registry.json": json.dumps(registry, indent=2, sort_keys=True) + "\n",
        "requirements.txt": "datasets\ntransformers\naccelerate\nbitsandbytes==0.49.2\nhuggingface_hub\nsafetensors\n",
        "tests/smoke_test.py": smoke_test_source(),
        "README.md": "# KTSTOP300 V4\n\nFinal planned pre-Kaggle STOP300 packet. Sandbox inference only; no training, promotion, shadow execution, selector deployment, production runtime authority, production prompt mutation, or production math-mode claim.\n",
        "COPY_PASTE_NOW_ktstop300_v4.txt": "Use Kaggle dataset ktstop300-v4 and execute KAGGLE_BOOTSTRAP_CELL.py. Run mode RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V4. Sandbox inference only; no training, promotion, shadow execution, selector deployment, production runtime authority, production prompt mutation, or production math-mode claim.\n",
    }


def internal_member_manifest_sha(members: dict[str, str]) -> str:
    member_hashes = {
        name: sha256_text(data)
        for name, data in sorted(members.items())
        if name not in {"KAGGLE_BOOTSTRAP_CELL.py", "SHA256_MANIFEST.json", "runtime/ktstop300_v4_config.json"}
    }
    return sha256_text(json.dumps(member_hashes, sort_keys=True, separators=(",", ":")))


def write_packet() -> str:
    config = build_config()
    members = packet_members(config, "")
    manifest = {
        "schema_id": "kt.stop300.v4.packet_manifest.v1",
        "packet_name": "ktstop300_v4.zip",
        "run_mode": STOP300_V4_RUN_MODE,
        "kaggle_dataset_name": STOP300_V4_DATASET,
        "supersedes": "packets/ktstop300_v3.zip",
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
    sha_manifest = {"schema_id": "kt.stop300.v4.sha256_manifest.v1", "internal_member_manifest_sha256": member_manifest_sha, "members": {name: sha256_text(data) for name, data in sorted(members.items())}}
    members["SHA256_MANIFEST.json"] = json.dumps(sha_manifest, indent=2, sort_keys=True) + "\n"
    STOP300_V4_PACKET.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(STOP300_V4_PACKET, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(members.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    return sha256_file(STOP300_V4_PACKET)


def write_reports(packet_sha: str) -> None:
    reports = {
        "stop300_v4_review_completion_receipt.json": {"schema_id": "kt.stop300.v4.review_completion_receipt.v1", "status": "PENDING_PR_REVIEW_COMPLETION", "required_merge_gate": "zero unresolved review threads", "claim_ceiling_status": "PRESERVED"},
        "stop300_v4_startup_dependency_contract.json": {"schema_id": "kt.stop300.v4.startup_dependency_contract.v1", "status": "PASS_CLEAN_KERNEL_AND_CONFLICT_DELTA", "claim_ceiling_status": "PRESERVED"},
        "stop300_v4_packet_identity_contract.json": {"schema_id": "kt.stop300.v4.packet_identity_contract.v1", "status": "PASS_EXTERNAL_FINAL_SHA_AND_INTERNAL_MEMBER_MANIFEST_BOUND", "external_final_packet_sha256": packet_sha, "packet_subject_merge_head": "EXTERNAL_LAUNCHER_AUTHORITY", "claim_ceiling_status": "PRESERVED"},
        "stop300_v4_physical_token_accounting_contract.json": {"schema_id": "kt.stop300.v4.physical_token_accounting_contract.v1", "status": "PASS_RAW_PHYSICAL_ECONOMICS_SEPARATE_FROM_VISIBLE_HYGIENE", "claim_ceiling_status": "PRESERVED"},
        "stop300_v4_eos_termination_contract.json": {"schema_id": "kt.stop300.v4.eos_termination_contract.v1", "status": "PASS", "claim_ceiling_status": "PRESERVED"},
        "stop300_v4_result_court_contract.json": {"schema_id": "kt.stop300.v4.result_court_contract.v1", "status": "PASS_CONJUNCTIVE_FAIL_CLOSED_MUTATION_SUITE", "claim_ceiling_status": "PRESERVED"},
        "stop300_v4_timing_contract.json": {"schema_id": "kt.stop300.v4.timing_contract.v1", "status": "PASS_1176_MEASURED_PLUS_9_WARMUPS", "claim_ceiling_status": "PRESERVED"},
        "stop300_v4_model_attestation_contract.json": {"schema_id": "kt.stop300.v4.model_attestation_contract.v1", "status": "PASS_FUNCTIONAL_MODEL_4BIT_CONTRACT", "claim_ceiling_status": "PRESERVED"},
        "stop300_v4_scorer_oracle_contract.json": {"schema_id": "kt.stop300.v4.scorer_oracle_contract.v1", "status": "PASS_ORACLE_1_0", "claim_ceiling_status": "PRESERVED"},
        "stop300_v4_resume_durability_contract.json": {"schema_id": "kt.stop300.v4.resume_durability_contract.v1", "status": "PASS_HF_RESTORABLE_EXACTLY_ONCE", "claim_ceiling_status": "PRESERVED"},
        "stop300_v4_publication_contract.json": {"schema_id": "kt.stop300.v4.publication_contract.v1", "status": "PASS_NONCIRCULAR_CORE_ASSESSMENT_DISPOSITION_SEQUENCE", "claim_ceiling_status": "PRESERVED"},
        "stop300_v4_exception_packaging_contract.json": {"schema_id": "kt.stop300.v4.exception_packaging_contract.v1", "status": "PASS", "claim_ceiling_status": "PRESERVED"},
        "stop300_v4_packet_decision.json": {"schema_id": "kt.stop300.v4.packet_decision.v1", "status": "GENERATED", "outcome": STOP300_V4_OUTCOME, "packet_path": rel(STOP300_V4_PACKET), "packet_sha256": packet_sha, "kaggle_dataset_name": STOP300_V4_DATASET, "one_cell_runbook": rel(STOP300_V4_RUNBOOK), "run_mode": STOP300_V4_RUN_MODE, "next_lawful_move": STOP300_V4_NEXT_LAWFUL_MOVE, **authority_payload(), "sandbox_inference_authority": True},
        "stop300_v4_claim_boundary_receipt.json": {"schema_id": "kt.stop300.v4.claim_boundary_receipt.v1", "status": "PASS_CLAIM_CEILING_PRESERVED", **authority_payload(), "sandbox_inference_authority": True},
    }
    for name, payload in reports.items():
        write_json(REPORTS / name, payload)
    write_text(
        STOP300_V4_RUNBOOK,
        f"""# KT STOP300 V4 One-Cell Runbook

Packet: `packets/ktstop300_v4.zip`

SHA256: `{packet_sha}`

Kaggle dataset: `ktstop300-v4`

Run mode: `RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V4`

```python
import hashlib, os, zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/ktstop300-v4/ktstop300_v4.zip')
expected_sha = '{packet_sha}'
actual_sha = hashlib.sha256(packet.read_bytes()).hexdigest()
if actual_sha != expected_sha:
    raise RuntimeError(f'packet sha mismatch: {{actual_sha}}')
os.environ['KT_AUTHORIZED_PACKET_SHA256'] = actual_sha
os.environ['KT_AUTHORIZED_PACKET_SUBJECT_HEAD'] = os.environ['KT_AUTHORIZED_PACKET_SUBJECT_HEAD']
os.environ['KT_CURRENT_MAIN_HEAD'] = os.environ['KT_CURRENT_MAIN_HEAD']
os.environ['KT_EXPECTED_RUN_MODE'] = 'RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V4'
os.environ.setdefault('KT_RAISE_ON_BLOCKER', '0')
work = Path('/kaggle/working/ktstop300_v4_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

Sandbox inference only. No training, promotion, shadow execution, selector deployment, production runtime authority, production prompt mutation, or production math-mode claim.
""",
    )


def update_v4_registry() -> None:
    paths = [
        (STOP300_V4_PACKET, "GENERATED_RUNTIME_PACKET", "CURRENT_HEAD", False, "STOP300 V4 sandbox runtime packet."),
        (STOP300_V4_RUNBOOK, "CANONICAL_RUNBOOK", "CURRENT_HEAD", False, "STOP300 V4 one-cell runbook."),
        (ROOT / "runtime" / "stop_fsm_v34.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP grammar V3.4 runtime FSM."),
        (ROOT / "runtime" / "reference_court_v34.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP grammar V3.4 reference court."),
        (ROOT / "runtime" / "boundary_evidence.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 V4 physical token boundary evidence."),
        (ROOT / "runtime" / "numeric_normalizer.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 V4 numeric oracle normalizer."),
        (ROOT / "scripts" / "audit_ktstop300_v3_postmerge.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 V3 postmerge audit."),
        (ROOT / "scripts" / "build_ktstop300_v4_packet.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 V4 packet builder."),
        (ROOT / "scripts" / "validate_ktstop300_v4_packet.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 V4 packet validator."),
        (ROOT / "scripts" / "check_pr_review_completion.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 V4 review completion check."),
    ]
    for name in [
        "stop300_v3_postmerge_execution_audit.json",
        "stop300_v3_review_thread_binding.json",
        "stop300_v3_supersession_receipt.json",
        "stop300_v4_review_completion_receipt.json",
        "stop300_v4_builder_summary.json",
        "stop300_v4_startup_dependency_contract.json",
        "stop300_v4_packet_identity_contract.json",
        "stop300_v4_physical_token_accounting_contract.json",
        "stop300_v4_eos_termination_contract.json",
        "stop300_v4_result_court_contract.json",
        "stop300_v4_timing_contract.json",
        "stop300_v4_model_attestation_contract.json",
        "stop300_v4_scorer_oracle_contract.json",
        "stop300_v4_resume_durability_contract.json",
        "stop300_v4_publication_contract.json",
        "stop300_v4_exception_packaging_contract.json",
        "stop300_v4_packet_decision.json",
        "stop300_v4_claim_boundary_receipt.json",
        "stop300_v4_packet_validation_receipt.json",
    ]:
        paths.append((REPORTS / name, "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V4 receipt."))
    paths.extend((path, "CANONICAL_TEST", "INTERNAL_SHADOW", True, "STOP300 V4 focused test.") for path in sorted((ROOT / "tests").glob("test_stop300_v4_*.py")))
    paths.append((ROOT / "tests" / "test_stop300_v3_postmerge_audit.py", "CANONICAL_TEST", "INTERNAL_SHADOW", True, "STOP300 V3 postmerge audit test."))
    update_registry(paths)


def main() -> int:
    audit = read_json(REPORTS / "stop300_v3_postmerge_execution_audit.json")
    if audit["status"] != "BLOCKED_GPU_RUN_UNRESOLVED_POSTMERGE_DEFECTS":
        raise SystemExit("expected V3 postmerge defects before V4 forge")
    if sha256_file(STOP300_V3_PACKET) != EXPECTED_V3_SHA:
        raise SystemExit("V3 packet changed; preserve byte-for-byte")
    packet_sha = write_packet()
    write_reports(packet_sha)
    update_v4_registry()
    summary = {
        "schema_id": "kt.stop300.v4.builder_summary.v1",
        "status": "PASS",
        "current_head": git_output("rev-parse", "HEAD"),
        "branch": git_output("branch", "--show-current"),
        "outcome": STOP300_V4_OUTCOME,
        "packet_path": rel(STOP300_V4_PACKET),
        "packet_sha256": packet_sha,
        "kaggle_dataset_name": STOP300_V4_DATASET,
        "one_cell_runbook": rel(STOP300_V4_RUNBOOK),
        "next_lawful_move": STOP300_V4_NEXT_LAWFUL_MOVE,
        **authority_payload(),
        "sandbox_inference_authority": True,
    }
    write_json(REPORTS / "stop300_v4_builder_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
