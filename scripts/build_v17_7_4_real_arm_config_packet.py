from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any


PROGRAM_ID = "AUTHOR_KT_V17_7_4_REINHERIT_PROVEN_KT13_HF_VAULT_AND_MEMORY_EXECUTION_PATTERN"
OUTCOME = "KT_V17_7_4_HF_VAULT_MEMORY_PATTERN_REINHERITED__RUN_MEMORY_SAFE_COMPRESSION_FRONTIER_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_KTV1774_HF_VAULT_MEMORY_SAFE_TRUEGEN_PACKET_V1"
PACKET_NAME = "ktv1774_hf_vault_memory_v1.zip"
KAGGLE_DATASET_NAME = "ktv1774-hf-vault-memory-v1"

AUTHORITY_FALSE = {
    "claim_ceiling_preserved": True,
    "runtime_authority": False,
    "promotion_authority": False,
    "adapter_training_authorized": False,
    "router_training_authorized": False,
    "policy_optimization_authorized": False,
    "learned_router_superiority_claim": False,
    "v18_runtime_authority": False,
}


def root() -> Path:
    return Path(__file__).resolve().parents[1]


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(AUTHORITY_FALSE)
    payload.update(extra)
    return payload


def write_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_zip_member(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def run_git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=root(), text=True, stderr=subprocess.DEVNULL).strip()


def current_head() -> str:
    return run_git(["rev-parse", "HEAD"])


def current_branch() -> str:
    return run_git(["branch", "--show-current"])


def git_status() -> str:
    return run_git(["status", "--porcelain=v1"])


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_packet(repo: Path) -> tuple[Path, str]:
    packet = repo / "packets" / PACKET_NAME
    packet.parent.mkdir(parents=True, exist_ok=True)
    members = {
        "README.md": (
            "# KTV1774 HF-Vault Memory-Safe Compression Frontier True-Generation Mini-Furnace V1\n\n"
            "This packet preserves the V17.7.4 real-arm model-load repair and re-inherits the proven KT13 HF-vault "
            "and assessment-only execution pattern. It binds the truegen runner to the intended Qwen 7B substrate, "
            "prefers the HF final-only adapter vault, keeps local adapter paths as fallback only, and runs arms one at a time. "
            "The model loader uses `AutoModelForCausalLM.from_pretrained` and places 4-bit loading inside "
            "`BitsAndBytesConfig(..., load_in_4bit=True)` via `quantization_config`. It never forwards "
            "`load_in_4bit` as a raw Qwen constructor/from_pretrained kwarg. It performs fresh generation or fails closed. "
            "It measures token economics, ablation-ladder performance, bloat attribution, parser drift, and compression frontier status. "
            "It streams rows to disk, writes a GPU memory ledger, rescues partial rows on blockers, and returns only an assessment ZIP. "
            "It does not train, promote, authorize V18, or claim learned-router superiority.\n\n"
            "Default row ladder stage is 3 rows. Set `KT_TRUEGEN_LADDER_STAGE=10`, `25`, `50`, or `100` only after memory telemetry passes. "
            "Set `KT_TRUEGEN_ADAPTER_SOURCE=local` and `KT_TRUEGEN_ADAPTER_ROOT` only if HF vault access is unavailable.\n"
        ).encode("utf-8"),
        "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py": (repo / "runtime" / "v17_7_4" / "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py").read_bytes(),
        "KT_V1774_TRUEGEN_ARM_CORE.py": (repo / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py").read_bytes(),
        "runtime_inputs/truegen_row_manifest.json": (repo / "admission" / "v17_7_4_truegen_row_manifest.json").read_bytes(),
        "runtime_inputs/arm_model_config.json": (repo / "configs" / "v17_7_4" / "arm_model_config.json").read_bytes(),
        "runtime_inputs/arm_model_config.example.json": (repo / "configs" / "v17_7_4" / "arm_model_config.example.json").read_bytes(),
        "run_manifest.json": json.dumps(
            authority(
                schema_id="kt.v17_7_4.compression_frontier_truegen_packet_manifest.v1",
                status="READY_FOR_COMPRESSION_FRONTIER_REAL_ARM_TRUEGEN_MINIFURNACE",
                run_mode="RUN_KTV1774_COMPRESSION_FRONTIER_TRUEGEN_MINIFURNACE",
                model_loader_contract="AutoModelForCausalLM.from_pretrained",
                quantization_contract="BitsAndBytesConfig via quantization_config",
                bad_load_in_4bit_kwarg_forwarded=False,
                compression_frontier_gate_required=True,
                hf_vault_source_of_truth=True,
                adapter_source_preference="HF_VAULT_FIRST",
                arm_isolation_mode="ARM_MAJOR_UNLOAD_AFTER_EACH_ARM",
                stream_rows_to_disk=True,
                row_ladder=[3, 10, 25, 50, 100],
                default_row_ladder_stage=3,
                partial_output_rescue_required=True,
                gpu_memory_ledger_required=True,
                assessment_only_return_required=True,
                g2_compression_anchor_internal_sentinel=True,
                token_economics_required=True,
                ablation_ladder_required=True,
                real_arm_authority_requested=True,
                require_real_arm_config=True,
                required_adapter_source_env="KT_TRUEGEN_ADAPTER_SOURCE",
                optional_adapter_root_env="KT_TRUEGEN_ADAPTER_ROOT",
                default_adapter_root="/kaggle/input/datasets/robertking1995/adapterssafetensors",
                kaggle_dataset_name=KAGGLE_DATASET_NAME,
                no_training=True,
                no_promotion=True,
                no_v18=True,
                no_fake_pass=True,
            ),
            indent=2,
            sort_keys=True,
        ).encode("utf-8"),
    }
    with zipfile.ZipFile(packet, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            write_zip_member(archive, name, data)
    return packet, sha256_file(packet)


def write_doc(repo: Path, packet_sha: str) -> Path:
    text = f"""# V17.7.4 HF-Vault Memory-Safe Compression Frontier Truegen One Cell

Packet: `packets/{PACKET_NAME}`

Kaggle dataset name: `{KAGGLE_DATASET_NAME}`

SHA256: `{packet_sha}`

This packet is not the smoke packet. It requires the real-arm config and fails closed if adapter-source bindings are missing. It prefers the HF final-only adapter vault, runs one arm at a time, streams rows to disk, emits GPU memory telemetry, and returns only an assessment ZIP. It also emits token-economics, bloat-attribution, ablation-ladder, router-admission, and compression-frontier receipts.

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "RUN_KTV1774_COMPRESSION_FRONTIER_TRUEGEN_MINIFURNACE"
os.environ["KT_NO_TRAINING"] = "1"
os.environ["KT_NO_PROMOTION"] = "1"
os.environ["KT_NO_V18"] = "1"
os.environ["KT_TRUEGEN_REQUIRE_REAL_ARM_CONFIG"] = "1"
os.environ["KT_FORBID_SMOKE_CONFIG"] = "1"
os.environ["KT_FORBID_BASE_FALLBACK_AS_ADAPTER"] = "1"
os.environ.setdefault("KT_TRUEGEN_ADAPTER_SOURCE", "hf")
os.environ.setdefault("KT_TRUEGEN_LADDER_STAGE", "3")
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True,max_split_size_mb:64")
# Use local only if HF is unavailable and a Kaggle adapter dataset is attached.
# os.environ["KT_TRUEGEN_ADAPTER_SOURCE"] = "local"
# os.environ.setdefault("KT_TRUEGEN_ADAPTER_ROOT", "/kaggle/input/datasets/robertking1995/adapterssafetensors")

candidates = [
    Path("/kaggle/input/{KAGGLE_DATASET_NAME}/{PACKET_NAME}"),
    Path("/kaggle/working/{PACKET_NAME}"),
]
packet = next((p for p in candidates if p.exists()), None)
if packet is None:
    raise FileNotFoundError("missing {PACKET_NAME}")

work = Path("/kaggle/working/ktv1774_hf_vault_memory_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as archive:
    archive.extractall(work)

runner = work / "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py"
os.chdir(runner.parent)
sys.path.insert(0, str(runner.parent))
subprocess.check_call([sys.executable, runner.name])
print("assessment outputs:", sorted(Path("/kaggle/working").glob("**/KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip")))
print("hf_dataset_url:", os.environ.get("KT_HF_DATASET_URL", "HF_UPLOAD_NOT_RUN_BY_REPO_SIDE_LANE"))
```
"""
    return write_text(repo / "docs" / "V17_7_4_HF_VAULT_MEMORY_TRUEGEN_ONE_CELL.md", text)


def write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def update_registry(repo: Path, packet: Path, packet_sha: str, doc: Path) -> Path:
    registry_path = repo / "registry" / "artifact_authority_registry.json"
    registry = read_json(registry_path)
    artifacts = registry.setdefault("artifacts", [])
    existing = {item.get("path"): item for item in artifacts}
    additions = [
        (repo / "configs" / "v17_7_4" / "arm_model_config.json", "real_arm_model_config"),
        (repo / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py", "truegen_model_loader_runtime"),
        (packet, "hf_vault_memory_safe_truegen_runtime_packet"),
        (doc, "hf_vault_memory_safe_truegen_one_cell_runbook"),
        (repo / "reports" / "g2_compression_anchor_receipt.json", "g2_compression_anchor_receipt"),
        (repo / "reports" / "kt_system_wiring_map.json", "kt_system_wiring_map"),
        (repo / "reports" / "kt_hat_compact_contract_receipt.json", "kt_hat_compact_contract_receipt"),
        (repo / "reports" / "router_admission_cost_gate_receipt.json", "router_admission_cost_gate_receipt"),
        (repo / "reports" / "compression_frontier_gate_receipt.json", "compression_frontier_gate_receipt"),
        (repo / "reports" / "v17_7_4_loadfix_preflight_repo_truth_receipt.json", "loadfix_preflight_repo_truth_receipt"),
        (repo / "reports" / "v17_7_4_loadfix_blocker_import_receipt.json", "loadfix_blocker_import_receipt"),
        (repo / "reports" / "v17_7_4_model_loader_contract_receipt.json", "model_loader_contract_receipt"),
        (repo / "reports" / "v17_7_4_adapter_load_contract_receipt.json", "adapter_load_contract_receipt"),
        (repo / "reports" / "v17_7_4_loadfix_claim_ceiling_receipt.json", "loadfix_claim_ceiling_receipt"),
        (repo / "reports" / "v17_7_4_real_arm_config_binding_receipt.json", "real_arm_config_binding_receipt"),
        (repo / "reports" / "v17_7_4_adapter_source_authority_receipt.json", "adapter_source_authority_receipt"),
        (repo / "reports" / "v17_7_4_model_source_authority_receipt.json", "model_source_authority_receipt"),
        (repo / "reports" / "v17_7_4_smoke_vs_real_config_separation_receipt.json", "smoke_vs_real_config_separation_receipt"),
        (repo / "reports" / "v17_7_4_truegen_smoke_assessment_import_receipt.json", "smoke_assessment_import_receipt"),
        (repo / "reports" / "v17_7_4_truegen_smoke_limitations_receipt.json", "smoke_limitations_receipt"),
        (repo / "reports" / "v17_7_4_hf_vault_memory_pattern_receipt.json", "hf_vault_memory_pattern_receipt"),
        (repo / "reports" / "v17_7_4_hf_vault_adapter_manifest_receipt.json", "hf_vault_adapter_manifest_receipt"),
        (repo / "reports" / "v17_7_4_memory_execution_policy_receipt.json", "memory_execution_policy_receipt"),
    ]
    changed = []
    for path, role in additions:
        rel = path.relative_to(repo).as_posix()
        payload = authority(
            artifact_id=f"v17_7_4_compression_frontier::{rel}",
            path=rel,
            role=role,
            status="LIVE_CURRENT_HEAD_PREP_ONLY",
            authority_state="LIVE_CURRENT_HEAD_PREP_ONLY",
            sha256=sha256_file(path),
            notes="Compression-frontier prep artifact; no promotion, runtime authority, V18 authority, or superiority claim.",
        )
        if rel in existing:
            existing[rel].update(payload)
        else:
            artifacts.append(payload)
        changed.append(rel)
    registry["current_head"] = current_head()
    registry["updated_by"] = PROGRAM_ID
    registry["claim_ceiling_preserved"] = True
    write_json(registry_path, registry)
    return write_json(
        repo / "registry" / "artifact_authority_registry_v17_7_4_real_arm_config_delta_receipt.json",
        authority(
        schema_id="kt.v17_7_4.compression_frontier_artifact_authority_delta_receipt.v1",
            status="PASS",
            current_head=current_head(),
            artifacts_added_or_updated=changed,
            packet_path=packet.relative_to(repo).as_posix(),
            packet_sha256=packet_sha,
            claim_ceiling_unchanged=True,
            no_runtime_authority_added=True,
            no_promotion_authority_added=True,
        ),
    )


def build() -> dict[str, Any]:
    repo = root()
    packet, packet_sha = write_packet(repo)
    doc = write_doc(repo, packet_sha)
    config = read_json(repo / "configs" / "v17_7_4" / "arm_model_config.json")
    write_json(
        repo / "reports" / "v17_7_4_hf_vault_memory_pattern_receipt.json",
        authority(
            schema_id="kt.v17_7_4.hf_vault_memory_pattern_receipt.v1",
            status="PASS",
            historical_pattern_reinherited="KT13_FINAL_ONLY_HF_VAULT_ASSESSMENT_ONLY",
            hf_vault_source_of_truth=True,
            adapter_source_preference=config.get("adapter_source_preference"),
            arm_isolation_mode=config.get("arm_isolation_mode"),
            stream_rows_to_disk=config.get("stream_rows_to_disk") is True,
            row_ladder=config.get("row_ladder"),
            default_row_ladder_stage=config.get("default_row_ladder_stage"),
            no_heavy_artifact_return=True,
            claim_ceiling_preserved=True,
        ),
    )
    write_json(
        repo / "reports" / "v17_7_4_hf_vault_adapter_manifest_receipt.json",
        authority(
            schema_id="kt.v17_7_4.hf_vault_adapter_manifest_receipt.v1",
            status="PASS",
            hf_vault_repo=config.get("hf_vault_repo"),
            adapter_source_preference=config.get("adapter_source_preference"),
            adapter_arms=[
                {
                    "arm_id": arm.get("arm_id"),
                    "adapter_hf_repo": arm.get("adapter_hf_repo"),
                    "adapter_hf_subfolder": arm.get("adapter_hf_subfolder", ""),
                    "adapter_path_fallback": arm.get("adapter_path", ""),
                    "adapter_sha256_expected": arm.get("adapter_sha256_optional", ""),
                }
                for arm in config.get("arms", [])
                if arm.get("adapter_required_for_real_authority") is True
            ],
            claim_ceiling_preserved=True,
        ),
    )
    write_json(
        repo / "reports" / "v17_7_4_memory_execution_policy_receipt.json",
        authority(
            schema_id="kt.v17_7_4.memory_execution_policy_receipt.v1",
            status="PASS",
            arm_execution_order="ARM_MAJOR_ONE_ARM_AT_A_TIME",
            unload_between_arms=True,
            gpu_memory_ledger_required=True,
            partial_output_rescue_required=True,
            assessment_only_return_required=True,
            row_ladder=config.get("row_ladder"),
            default_row_ladder_stage=config.get("default_row_ladder_stage"),
            max_new_tokens=config.get("max_new_tokens"),
            claim_ceiling_preserved=True,
        ),
    )
    registry_delta = update_registry(repo, packet, packet_sha, doc)
    summary = authority(
        schema_id="kt.v17_7_4.compression_frontier_builder_summary.v1",
        status="PASS",
        current_head=current_head(),
        current_branch=current_branch(),
        git_status_porcelain=git_status(),
        outcome=OUTCOME,
        next_lawful_move=NEXT_LAWFUL_MOVE,
        packet_path=packet.relative_to(repo).as_posix(),
        packet_sha256=packet_sha,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
        registry_delta_path=registry_delta.relative_to(repo).as_posix(),
        blockers=[],
    )
    write_json(repo / "reports" / "v17_7_4_compression_frontier_builder_summary.json", summary)
    write_json(
        repo / "reports" / "v17_7_4_real_arm_next_move_decision_receipt.json",
        authority(
            schema_id="kt.v17_7_4.compression_frontier_next_move_decision_receipt.v1",
            status="PASS",
            outcome=OUTCOME,
            next_lawful_move=NEXT_LAWFUL_MOVE,
            packet_path=packet.relative_to(repo).as_posix(),
            packet_sha256=packet_sha,
            kaggle_dataset_name=KAGGLE_DATASET_NAME,
            blockers=[],
        ),
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def main() -> int:
    build()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
