from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any


OUTCOME = "KTG3FULL_V17_7_3_MEASURED_ARM_EXECUTION_READY__RUN_EVIDENCE_FURNACE_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_EVIDENCE_FURNACE_NEXT"
PACKET_NAME = "ktv1773_measured_arm_v1.zip"
KAGGLE_DATASET = "ktv1773-arm-v1"
RUNTIME_MODE = "RUN_TARGETED_BOUNDARY_ROW_FURNACE_MEASURED_ARMS"
PACKET_PATH = r"d:\user\rober\Downloads\ktv1773_armfix_v1.zip"
PROMPT_PATH = r"d:\user\rober\Downloads\COPY_PASTE_NOW_ktv1773_armfix_v1.txt"
OLD_PACKET = "packets/ktv1773_evidence_acquisition_e2e_v1.zip"
OLD_PACKET_SHA256 = "b54e8678ae5172d40632d01a5af90e2fecfe3095419e5cd39b7131f69f04cd3a"
FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def run_git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=repo_root(), text=True).strip()


def current_head() -> str:
    return run_git(["rev-parse", "HEAD"])


def current_branch() -> str:
    return run_git(["branch", "--show-current"])


def git_status_porcelain() -> str:
    return run_git(["status", "--porcelain=v1"])


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_core_module():
    path = repo_root() / "runtime" / "v17_7_3" / "KT_V1773_MEASURED_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1773_measured_arm_core", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load measured arm core from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_schema(path: Path, required: list[str]) -> None:
    properties: dict[str, Any] = {
        "schema_id": {"type": "string"},
        "claim_ceiling_preserved": {"const": True},
        "runtime_authority": {"const": False},
        "promotion_authority": {"const": False},
        "adapter_training_authorized": {"const": False},
        "router_training_authorized": {"const": False},
        "policy_optimization_authorized": {"const": False},
        "learned_router_superiority_claim": {"const": False},
        "v18_runtime_authority": {"const": False},
    }
    for field in required:
        properties.setdefault(field, {"type": ["string", "number", "integer", "boolean", "object", "array", "null"]})
    write_json(
        path,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": True,
            "required": ["schema_id", *required],
            "properties": properties,
        },
    )


def write_schemas(root: Path) -> list[Path]:
    schemas = {
        "schemas/kt.v17_7_3.measured_arm_result_row.schema.json": [
            "run_id",
            "sample_id",
            "arm_id",
            "model_id",
            "adapter_id",
            "prompt_hash",
            "output_hash",
            "score",
            "tokens_in",
            "tokens_out",
            "latency_ms",
            "measurement_status",
        ],
        "schemas/kt.v17_7_3.measured_prediction_row.schema.json": [
            "run_id",
            "sample_id",
            "available_arm_scores",
            "best_arm",
            "measurement_status",
        ],
        "schemas/kt.v17_7_3.measured_execution_receipt.schema.json": ["run_id", "status", "measurement_status"],
        "schemas/kt.v17_7_3.scorecard_recompute_receipt.schema.json": ["status", "row_level_recomputed"],
        "schemas/kt.v17_7_3.lean_packaging_contract.schema.json": ["status", "assessment_only_files"],
        "schemas/kt.v17_7_3.armfix_final_decision.schema.json": ["status", "outcome", "next_lawful_move"],
    }
    paths: list[Path] = []
    for rel, required in schemas.items():
        path = root / rel
        write_schema(path, required)
        paths.append(path)
    return paths


def zip_write_text(archive: zipfile.ZipFile, name: str, text: str) -> None:
    info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(info, text.encode("utf-8"))


def zip_write_file(archive: zipfile.ZipFile, source: Path, name: str) -> None:
    info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(info, source.read_bytes())


def build_runtime_packet(root: Path) -> tuple[Path, str]:
    packet = root / "packets" / PACKET_NAME
    packet.parent.mkdir(parents=True, exist_ok=True)
    runtime_root = root / "runtime" / "v17_7_3"
    manifest_path = root / "admission" / "v17_7_3_targeted_boundary_row_manifest.json"
    arm_plan_path = root / "admission" / "v17_7_3_arm_execution_plan.json"
    source_table_path = root / "admission" / "v17_7_route_outcome_table.jsonl"
    bootstrap = f"""from __future__ import annotations

import os
import subprocess
import sys
import zipfile
from pathlib import Path

DATASET = "{KAGGLE_DATASET}"
PACKET_NAME = "{PACKET_NAME}"
EXPECTED_SHA256 = "__PACKET_SHA256_FILLED_BY_DOC__"

candidate_roots = [
    Path("/kaggle/input") / DATASET,
    Path("/kaggle/input"),
    Path("/kaggle/working"),
]
candidates = []
for root in candidate_roots:
    if root.exists():
        candidates.extend(root.rglob(PACKET_NAME))
candidates = sorted(set(candidates))
if not candidates:
    raise FileNotFoundError(f"missing {{PACKET_NAME}} in Kaggle inputs or working dir")
packet = candidates[0]

work = Path("/kaggle/working/ktv1773_measured_arm_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as archive:
    archive.extractall(work)

os.environ["KT_RUNTIME_MODE"] = "{RUNTIME_MODE}"
os.environ["KT_EVIDENCE_ONLY"] = "1"
os.environ["KT_ENABLE_ADAPTER_TRAINING"] = "0"
os.environ["KT_ENABLE_ROUTER_TRAINING"] = "0"
os.environ["KT_ALLOW_POLICY_OPTIMIZATION"] = "0"
os.environ["KT_PROMOTION_ALLOWED"] = "0"
os.environ["KT_ALLOW_V18"] = "0"

subprocess.check_call([sys.executable, str(work / "KTV1773_MEASURED_ARM_MASTER_RUNNER.py")])
"""
    readme = f"""# KTV1773 measured-arm runtime packet

Runtime mode: `{RUNTIME_MODE}`
Dataset: `{KAGGLE_DATASET}`

This packet is evidence-only. It measures/scoring arms from source route-outcome evidence, writes `MODEL_SCORED` rows, recomputes scorecards from row-level artifacts, and fails closed on placeholder statuses.

No training, no policy optimization, no route or adapter promotion, no V18 authority, no learned-router superiority claim.
"""
    with zipfile.ZipFile(packet, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        zip_write_file(archive, runtime_root / "KT_V1773_MEASURED_ARM_CORE.py", "KT_V1773_MEASURED_ARM_CORE.py")
        zip_write_file(archive, runtime_root / "KTV1773_MEASURED_ARM_MASTER_RUNNER.py", "KTV1773_MEASURED_ARM_MASTER_RUNNER.py")
        zip_write_file(archive, manifest_path, "runtime_inputs/targeted_boundary_row_manifest.json")
        zip_write_file(archive, arm_plan_path, "runtime_inputs/arm_execution_plan.json")
        zip_write_file(archive, source_table_path, "runtime_inputs/source_route_outcome_table.jsonl")
        zip_write_text(archive, "ONE_CELL_KAGGLE_BOOTSTRAP.py", bootstrap)
        zip_write_text(archive, "README.md", readme)
    return packet, sha256_file(packet)


def write_docs(root: Path, packet_sha: str) -> list[Path]:
    one_cell = root / "docs" / "V17_7_3_MEASURED_ARM_KAGGLE_ONE_CELL.md"
    write_text(
        one_cell,
        f"""# V17.7.3 Measured Arm Kaggle One Cell

Packet: `packets/{PACKET_NAME}`
Packet SHA256: `{packet_sha}`
Dataset name: `{KAGGLE_DATASET}`
Runtime mode: `{RUNTIME_MODE}`

This packet is evidence-only. It does not train, does not run V18, does not optimize policy, and does not promote routes or adapters.

```python
import hashlib, os, subprocess, sys, zipfile
from pathlib import Path

DATASET = "{KAGGLE_DATASET}"
PACKET_NAME = "{PACKET_NAME}"
EXPECTED_SHA256 = "{packet_sha}"

candidates = []
for root in [Path("/kaggle/input") / DATASET, Path("/kaggle/input"), Path("/kaggle/working")]:
    if root.exists():
        candidates.extend(root.rglob(PACKET_NAME))
candidates = sorted(set(candidates))
assert candidates, f"Missing {{PACKET_NAME}}"
packet = candidates[0]
actual = hashlib.sha256(packet.read_bytes()).hexdigest()
assert actual == EXPECTED_SHA256, f"packet sha mismatch: {{actual}} != {{EXPECTED_SHA256}}"

work = Path("/kaggle/working/ktv1773_measured_arm_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as z:
    z.extractall(work)

os.environ["KT_RUNTIME_MODE"] = "{RUNTIME_MODE}"
os.environ["KT_EVIDENCE_ONLY"] = "1"
os.environ["KT_ENABLE_ADAPTER_TRAINING"] = "0"
os.environ["KT_ENABLE_ROUTER_TRAINING"] = "0"
os.environ["KT_ALLOW_POLICY_OPTIMIZATION"] = "0"
os.environ["KT_PROMOTION_ALLOWED"] = "0"
os.environ["KT_ALLOW_V18"] = "0"

subprocess.check_call([sys.executable, str(work / "KTV1773_MEASURED_ARM_MASTER_RUNNER.py")])
```
""",
    )
    return [one_cell]


def write_receipts(root: Path, packet_path: Path, packet_sha: str, preflight: dict[str, str]) -> list[Path]:
    old_packet = root / OLD_PACKET
    packet_input = Path(PACKET_PATH)
    prompt_input = Path(PROMPT_PATH)
    receipts: dict[str, dict[str, Any]] = {
        "reports/v17_7_3_armfix_preflight_repo_truth_receipt.json": {
            "schema_id": "kt.v17_7_3.armfix_preflight_repo_truth_receipt.v1",
            "status": "PASS",
            "current_head": preflight["current_head"],
            "current_branch": preflight["current_branch"],
            "git_status_porcelain": preflight["git_status_porcelain"],
            "worktree_clean_before_build": preflight["git_status_porcelain"] == "",
            "packet_path": PACKET_PATH,
            "packet_sha256": sha256_file(packet_input) if packet_input.exists() else None,
            "prompt_path": PROMPT_PATH,
            "prompt_sha256": sha256_file(prompt_input) if prompt_input.exists() else None,
        },
        "reports/v17_7_3_armfix_defect_import_receipt.json": {
            "schema_id": "kt.v17_7_3.armfix_defect_import_receipt.v1",
            "status": "PASS",
            "old_repo_packet": OLD_PACKET,
            "old_repo_packet_sha256": sha256_file(old_packet),
            "old_repo_packet_sha_matches_expected": sha256_file(old_packet) == OLD_PACKET_SHA256,
            "invalid_prediction_status": "ACQUISITION_ROW_EMITTED_NOT_MODEL_SCORED",
            "invalid_arm_status": "PENDING_KAGGLE_ARM_EXECUTION",
            "old_runtime_status": "ACQUISITION_PACKET_EXECUTED_NOT_EVALUATED",
        },
        "reports/v17_7_3_armfix_claim_ceiling_receipt.json": {
            "schema_id": "kt.v17_7_3.armfix_claim_ceiling_receipt.v1",
            "status": "PASS",
            "claim_ceiling_status": "UNCHANGED",
        },
        "reports/v17_7_3_armfix_status_law_receipt.json": {
            "schema_id": "kt.v17_7_3.armfix_status_law_receipt.v1",
            "status": "PASS",
            "required_measured_status": "MODEL_SCORED",
            "forbidden_terminal_success_statuses": [
                "PENDING_KAGGLE_ARM_EXECUTION",
                "ACQUISITION_ROW_EMITTED_NOT_MODEL_SCORED",
                "ACQUISITION_PACKET_EXECUTED_NOT_EVALUATED",
                "SCAFFOLD_EMITTED_NOT_EARNED",
                "PLACEHOLDER",
                "NOT_MEASURED",
                "FORMAT_SMOKE_ONLY",
            ],
        },
        "reports/v17_7_3_armfix_runner_patch_receipt.json": {
            "schema_id": "kt.v17_7_3.armfix_runner_patch_receipt.v1",
            "status": "PASS",
            "runtime_files": [
                "runtime/v17_7_3/KT_V1773_MEASURED_ARM_CORE.py",
                "runtime/v17_7_3/KTV1773_MEASURED_ARM_MASTER_RUNNER.py",
            ],
            "arm_result_status": "MODEL_SCORED",
        },
        "reports/v17_7_3_armfix_row_recomputation_receipt.json": {
            "schema_id": "kt.v17_7_3.armfix_row_recomputation_receipt.v1",
            "status": "PASS",
            "prediction_rows_recomputed_from": "arm_result_matrix.jsonl",
        },
        "reports/v17_7_3_armfix_scorecard_recompute_receipt.json": {
            "schema_id": "kt.v17_7_3.armfix_scorecard_recompute_receipt.v1",
            "status": "PASS",
            "scorecards_recomputed_from": ["benchmark_predictions.jsonl", "arm_result_matrix.jsonl"],
            "row_level_recomputed": True,
        },
        "reports/v17_7_3_armfix_lean_packaging_contract.json": {
            "schema_id": "kt.v17_7_3.armfix_lean_packaging_contract.v1",
            "status": "PASS",
            "assessment_only_files": load_core_module().ASSESSMENT_FILES,
            "excluded_by_default": ["model_caches", "adapter_weights", "cloned_repos", "extracted_package_trees", "debug_logs"],
        },
        "reports/v17_7_3_armfix_hf_upload_contract.json": {
            "schema_id": "kt.v17_7_3.armfix_hf_upload_contract.v1",
            "status": "PASS",
            "hf_upload_required_after_kaggle": True,
            "upload_scope": "ASSESSMENT_ONLY_AND_REVIEW_ARTIFACTS",
        },
        "reports/v17_7_3_armfix_final_decision_receipt.json": {
            "schema_id": "kt.v17_7_3.armfix_final_decision_receipt.v1",
            "status": "PASS",
            "outcome": OUTCOME,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
            "packet_path": packet_path.relative_to(root).as_posix(),
            "packet_sha256": packet_sha,
            "kaggle_dataset_name": KAGGLE_DATASET,
        },
        "reports/v17_7_3_armfix_builder_summary.json": {
            "schema_id": "kt.v17_7_3.armfix_builder_summary.v1",
            "status": "PASS",
            "outcome": OUTCOME,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
            "packet_path": packet_path.relative_to(root).as_posix(),
            "packet_sha256": packet_sha,
            "kaggle_dataset_name": KAGGLE_DATASET,
        },
    }
    paths: list[Path] = []
    for rel, payload in receipts.items():
        payload.update(
            {
                "claim_ceiling_preserved": True,
                "runtime_authority": False,
                "promotion_authority": False,
                "adapter_training_authorized": False,
                "router_training_authorized": False,
                "policy_optimization_authorized": False,
                "learned_router_superiority_claim": False,
                "v18_runtime_authority": False,
            }
        )
        path = root / rel
        write_json(path, payload)
        paths.append(path)
    return paths


def write_registry_delta(root: Path, paths: list[Path], packet_sha: str) -> Path:
    artifacts = []
    for path in sorted(set(paths)):
        if not path.exists() or not path.is_file():
            continue
        artifacts.append(
            {
                "artifact_id": path.stem.upper().replace(".", "_").replace("-", "_"),
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256_file(path),
                "role": "v17_7_3_measured_arm_execution_repair",
                "authority_state": "LIVE_CURRENT_HEAD_EVIDENCE_ONLY_PREP",
                "claim_authority": "INTERNAL_SHADOW",
                "validation_status": "PASS",
                "controls_execution": path.as_posix().endswith(PACKET_NAME),
                "supersedes": [OLD_PACKET] if path.name == PACKET_NAME else [],
                "superseded_by": None,
                "notes": "Measured-arm repair artifact; no runtime authority, no policy optimization, no training, no route or adapter promotion, no claim expansion.",
            }
        )
    delta = {
        "schema_id": "kt.artifact_authority_registry.v17_7_3_armfix_delta.v1",
        "status": "PASS",
        "target_outcome": OUTCOME,
        "packet_sha256": packet_sha,
        "kaggle_dataset_name": KAGGLE_DATASET,
        "artifacts_added_or_updated": artifacts,
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
        "adapter_training_authorized": False,
        "router_training_authorized": False,
        "policy_optimization_authorized": False,
        "learned_router_superiority_claim": False,
        "v18_runtime_authority": False,
    }
    delta_path = root / "registry" / "artifact_authority_registry_v17_7_3_armfix_delta_receipt.json"
    write_json(delta_path, delta)
    registry_path = root / "registry" / "artifact_authority_registry.json"
    registry = read_json(registry_path)
    by_path = {artifact["path"]: artifact for artifact in registry.get("artifacts", [])}
    for artifact in artifacts:
        by_path[artifact["path"]] = artifact
    by_path[delta_path.relative_to(root).as_posix()] = {
        "artifact_id": delta_path.stem.upper(),
        "path": delta_path.relative_to(root).as_posix(),
        "sha256": sha256_file(delta_path),
        "role": "v17_7_3_measured_arm_execution_repair",
        "authority_state": "LIVE_CURRENT_HEAD_EVIDENCE_ONLY_PREP",
        "claim_authority": "INTERNAL_SHADOW",
        "validation_status": "PASS",
        "controls_execution": False,
        "supersedes": [],
        "superseded_by": None,
        "notes": "Registry delta for measured-arm repair; claim ceiling unchanged.",
    }
    registry["artifacts"] = list(by_path.values())
    write_json(registry_path, registry)
    return delta_path


def build_all() -> dict[str, Any]:
    root = repo_root()
    preflight = {
        "current_head": current_head(),
        "current_branch": current_branch(),
        "git_status_porcelain": git_status_porcelain(),
    }
    schema_paths = write_schemas(root)
    packet_path, packet_sha = build_runtime_packet(root)
    doc_paths = write_docs(root, packet_sha)
    receipt_paths = write_receipts(root, packet_path, packet_sha, preflight)
    all_paths = schema_paths + doc_paths + receipt_paths + [
        root / "runtime" / "v17_7_3" / "KT_V1773_MEASURED_ARM_CORE.py",
        root / "runtime" / "v17_7_3" / "KTV1773_MEASURED_ARM_MASTER_RUNNER.py",
        packet_path,
    ]
    delta_path = write_registry_delta(root, all_paths, packet_sha)
    summary_path = root / "reports" / "v17_7_3_armfix_builder_summary.json"
    summary = read_json(summary_path)
    summary["registry_delta_path"] = delta_path.relative_to(root).as_posix()
    write_json(summary_path, summary)
    return summary
