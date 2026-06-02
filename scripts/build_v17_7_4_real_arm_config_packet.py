from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any


PROGRAM_ID = "AUTHOR_KTV1774_REAL_ARM_CONFIG_BINDING_PACKET"
OUTCOME = "KTG3FULL_V17_7_4_REAL_ARM_CONFIG_READY__RUN_TRUEGEN_MINIFURNACE_REAL_ARMS_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_KTV1774_REAL_ARM_TRUEGEN_PACKET"
PACKET_NAME = "ktv1774_real_arm_truegen_v1.zip"
KAGGLE_DATASET_NAME = "ktv1774-real-arms-v1"

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
            "# KTV1774 Real-Arm True-Generation Mini-Furnace\n\n"
            "This packet binds the V17.7.4 truegen runner to the intended Qwen 7B substrate and real adapter-source paths. "
            "It performs fresh generation or fails closed. It does not train, promote, authorize V18, or claim learned-router superiority.\n\n"
            "Set `KT_TRUEGEN_ADAPTER_ROOT` if the Kaggle adapter dataset path differs from the bundled default.\n"
        ).encode("utf-8"),
        "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py": (repo / "runtime" / "v17_7_4" / "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py").read_bytes(),
        "KT_V1774_TRUEGEN_ARM_CORE.py": (repo / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py").read_bytes(),
        "runtime_inputs/truegen_row_manifest.json": (repo / "admission" / "v17_7_4_truegen_row_manifest.json").read_bytes(),
        "runtime_inputs/arm_model_config.json": (repo / "configs" / "v17_7_4" / "arm_model_config.json").read_bytes(),
        "runtime_inputs/arm_model_config.example.json": (repo / "configs" / "v17_7_4" / "arm_model_config.example.json").read_bytes(),
        "run_manifest.json": json.dumps(
            authority(
                schema_id="kt.v17_7_4.real_arm_truegen_packet_manifest.v1",
                status="READY_FOR_REAL_ARM_FRESH_GENERATION_MINIFURNACE",
                run_mode="RUN_KTV1774_REAL_ARM_TRUEGEN_MINIFURNACE",
                real_arm_authority_requested=True,
                require_real_arm_config=True,
                required_adapter_root_env="KT_TRUEGEN_ADAPTER_ROOT",
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
            archive.writestr(name, data)
    return packet, sha256_file(packet)


def write_doc(repo: Path, packet_sha: str) -> Path:
    text = f"""# V17.7.4 Real-Arm Truegen One Cell

Packet: `packets/{PACKET_NAME}`

Kaggle dataset name: `{KAGGLE_DATASET_NAME}`

SHA256: `{packet_sha}`

This packet is not the smoke packet. It requires the real-arm config and fails closed if adapter-source bindings are missing.

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "RUN_KTV1774_REAL_ARM_TRUEGEN_MINIFURNACE"
os.environ["KT_NO_TRAINING"] = "1"
os.environ["KT_NO_PROMOTION"] = "1"
os.environ["KT_NO_V18"] = "1"
os.environ["KT_TRUEGEN_REQUIRE_REAL_ARM_CONFIG"] = "1"
os.environ.setdefault("KT_TRUEGEN_ADAPTER_ROOT", "/kaggle/input/datasets/robertking1995/adapterssafetensors")

candidates = [
    Path("/kaggle/input/{KAGGLE_DATASET_NAME}/{PACKET_NAME}"),
    Path("/kaggle/working/{PACKET_NAME}"),
]
packet = next((p for p in candidates if p.exists()), None)
if packet is None:
    raise FileNotFoundError("missing {PACKET_NAME}")

work = Path("/kaggle/working/ktv1774_real_arm_truegen_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as archive:
    archive.extractall(work)

os.chdir(work)
sys.path.insert(0, str(work))
subprocess.check_call([sys.executable, "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py"])
print("assessment outputs:", sorted(Path("/kaggle/working").glob("**/KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip")))
```
"""
    return write_text(repo / "docs" / "V17_7_4_REAL_ARM_TRUEGEN_ONE_CELL.md", text)


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
        (packet, "real_arm_truegen_runtime_packet"),
        (doc, "real_arm_truegen_one_cell_runbook"),
        (repo / "reports" / "v17_7_4_real_arm_config_binding_receipt.json", "real_arm_config_binding_receipt"),
        (repo / "reports" / "v17_7_4_adapter_source_authority_receipt.json", "adapter_source_authority_receipt"),
        (repo / "reports" / "v17_7_4_model_source_authority_receipt.json", "model_source_authority_receipt"),
        (repo / "reports" / "v17_7_4_smoke_vs_real_config_separation_receipt.json", "smoke_vs_real_config_separation_receipt"),
        (repo / "reports" / "v17_7_4_truegen_smoke_assessment_import_receipt.json", "smoke_assessment_import_receipt"),
        (repo / "reports" / "v17_7_4_truegen_smoke_limitations_receipt.json", "smoke_limitations_receipt"),
    ]
    changed = []
    for path, role in additions:
        rel = path.relative_to(repo).as_posix()
        payload = authority(
            artifact_id=f"v17_7_4_real_arm_binding::{rel}",
            path=rel,
            role=role,
            status="LIVE_CURRENT_HEAD_PREP_ONLY",
            authority_state="LIVE_CURRENT_HEAD_PREP_ONLY",
            sha256=sha256_file(path),
            notes="Real-arm config binding artifact; no promotion, runtime authority, V18 authority, or superiority claim.",
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
            schema_id="kt.v17_7_4.real_arm_config_artifact_authority_delta_receipt.v1",
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
    registry_delta = update_registry(repo, packet, packet_sha, doc)
    summary = authority(
        schema_id="kt.v17_7_4.real_arm_config_builder_summary.v1",
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
    write_json(repo / "reports" / "v17_7_4_real_arm_config_builder_summary.json", summary)
    write_json(
        repo / "reports" / "v17_7_4_real_arm_next_move_decision_receipt.json",
        authority(
            schema_id="kt.v17_7_4.real_arm_next_move_decision_receipt.v1",
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
