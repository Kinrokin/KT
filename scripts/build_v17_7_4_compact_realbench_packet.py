from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PACKET_NAME = "ktv1774_realbench_compact_v1.zip"
KAGGLE_DATASET_NAME = "ktv1774-realbench-compact-v1"
OUTCOME = "KTG3FULL_V17_7_4_INTELLIGENCE_MOVED__COMPACT_PATH_REPAIR_READY__RUN_COMPACT_REALBENCH_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_KTV1774_REALBENCH_COMPACT_50"
REGISTRY_DELTA_NAME = "artifact_authority_registry_v17_7_4_compact_realbench_delta_receipt.json"


def authority(**extra: Any) -> dict[str, Any]:
    payload = {
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
        "adapter_training_authorized": False,
        "router_training_authorized": False,
        "policy_optimization_authorized": False,
        "learned_router_superiority_claim": False,
        "v18_runtime_authority": False,
    }
    payload.update(extra)
    return payload


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_zip_member(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def run_git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def compact_config() -> dict[str, Any]:
    config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.json").read_text(encoding="utf-8"))
    config["measurement_mode"] = "REAL_BENCHMARK_GAUGE"
    config["compact_answer_contract"] = True
    config["row_limit"] = 50
    config["default_row_ladder_stage"] = None
    config["max_new_tokens"] = 16
    for arm in config.get("arms", []):
        arm["max_new_tokens"] = 16
    return config


def build_packet() -> tuple[Path, str]:
    packet = ROOT / "packets" / PACKET_NAME
    packet.parent.mkdir(parents=True, exist_ok=True)
    config = compact_config()
    run_manifest = authority(
        schema_id="kt.v17_7_4.compact_realbench_packet_manifest.v1",
        status="READY_FOR_COMPACT_REALBENCH_TRUEGEN",
        run_mode="RUN_KTV1774_REALBENCH_COMPACT_TRUEGEN",
        measurement_mode="REAL_BENCHMARK_GAUGE",
        compact_answer_contract=True,
        default_requested_rows=50,
        token_accounting_ledger_required=True,
        visible_answer_tokens_required=True,
        oracle_route_table_required=True,
        specialist_admission_atlas_required=True,
        g2_compact_path_gap_analysis_required=True,
        hf_vault_source_of_truth=True,
        assessment_only_return_required=True,
        no_training=True,
        no_promotion=True,
        no_v18=True,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
    )
    members = {
        "README.md": (
            "# KTV1774 RealBench Compact V1\n\n"
            "Runs the same RealBench 50 gauge with compact final-answer contract enabled. "
            "It measures full prompt+output tokens separately from visible final-answer tokens, emits an oracle route table, "
            "specialist admission atlas, token accounting ledger, finalizer receipt, and G2 compact-path gap analysis. "
            "No training, promotion, V18, router-superiority, commercial, frontier, S-tier, 7B, or multi-lobe claim is authorized.\n"
        ).encode("utf-8"),
        "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py": (ROOT / "runtime" / "v17_7_4" / "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py").read_bytes(),
        "KT_V1774_TRUEGEN_ARM_CORE.py": (ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py").read_bytes(),
        "runtime_inputs/truegen_row_manifest.json": (ROOT / "admission" / "v17_7_4_realbench_row_manifest.json").read_bytes(),
        "runtime_inputs/arm_model_config.json": json.dumps(config, indent=2, sort_keys=True).encode("utf-8"),
        "runtime_inputs/compact_answer_contract.json": (ROOT / "configs" / "v17_7_4" / "compact_answer_contract.json").read_bytes(),
        "run_manifest.json": json.dumps(run_manifest, indent=2, sort_keys=True).encode("utf-8"),
    }
    with zipfile.ZipFile(packet, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            write_zip_member(archive, name, data)
    return packet, sha256_file(packet)


def write_runbook(packet_sha: str) -> Path:
    path = ROOT / "docs" / "V17_7_4_REALBENCH_COMPACT_ONE_CELL.md"
    write_text(
        path,
        f"""# V17.7.4 RealBench Compact One Cell

Packet: `packets/{PACKET_NAME}`

Kaggle dataset name: `{KAGGLE_DATASET_NAME}`

SHA256: `{packet_sha}`

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "RUN_KTV1774_REALBENCH_COMPACT_TRUEGEN"
os.environ["KT_TRUEGEN_MEASUREMENT_MODE"] = "REAL_BENCHMARK_GAUGE"
os.environ["KT_COMPACT_ANSWER_CONTRACT"] = "1"
os.environ["KT_TRUEGEN_TARGET_ROWS"] = "50"
os.environ["KT_MINIFURNACE_ROWS"] = "50"
os.environ["KT_TRUEGEN_REQUIRE_REAL_ARM_CONFIG"] = "1"
os.environ["KT_FORBID_SMOKE_CONFIG"] = "1"
os.environ["KT_FORBID_BASE_FALLBACK_AS_ADAPTER"] = "1"
os.environ["KT_NO_TRAINING"] = "1"
os.environ["KT_NO_PROMOTION"] = "1"
os.environ["KT_NO_V18"] = "1"
os.environ.setdefault("KT_TRUEGEN_ADAPTER_SOURCE", "hf")
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True,max_split_size_mb:64")

packet = Path("/kaggle/input/{KAGGLE_DATASET_NAME}/{PACKET_NAME}")
if not packet.exists():
    raise FileNotFoundError(packet)
work = Path("/kaggle/working/ktv1774_realbench_compact_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as archive:
    archive.extractall(work)
runner = work / "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py"
os.chdir(runner.parent)
sys.path.insert(0, str(runner.parent))
subprocess.check_call([sys.executable, runner.name])
print("assessment outputs:", sorted(Path("/kaggle/working").glob("**/KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip")))
```
""",
    )
    return path


def write_registry_delta(summary_path: Path, packet: Path, runbook: Path, packet_sha: str) -> Path:
    artifacts = []
    for path, role in [
        (packet, "compact_realbench_kaggle_packet"),
        (runbook, "compact_realbench_one_cell_runbook"),
        (summary_path, "compact_realbench_builder_summary"),
        (ROOT / "configs" / "v17_7_4" / "compact_answer_contract.json", "compact_answer_contract"),
    ]:
        artifacts.append(
            {
                "path": path.relative_to(ROOT).as_posix(),
                "role": role,
                "sha256": packet_sha if path == packet else sha256_file(path),
                "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
                "claim_expansion": False,
                "production_authority": False,
                "commercial_authority": False,
                "router_superiority_authority": False,
                "adapter_promotion_authority": False,
            }
        )
    delta = authority(
        schema_id="kt.artifact_authority_registry.delta_receipt.v17_7_4_compact_realbench.v1",
        status="PASS",
        current_head=run_git(["rev-parse", "HEAD"]),
        artifacts_added=artifacts,
        artifacts_modified=[],
        artifacts_superseded=[],
        packet_sha256=packet_sha,
        outcome=OUTCOME,
        next_lawful_move=NEXT_LAWFUL_MOVE,
        central_registry_mutated=False,
        central_registry_mutation_reason="Skipped because registry/artifact_authority_registry.json already had unrelated live 13-lobe readiness changes in the working tree.",
        no_commercial_claim=True,
        no_external_validation_claim=True,
        no_s_tier_claim=True,
        no_frontier_parity_claim=True,
        no_7b_amplification_claim=True,
        no_router_superiority_claim=True,
        no_multi_lobe_superiority_claim=True,
        no_production_readiness_claim=True,
    )
    path = ROOT / "registry" / REGISTRY_DELTA_NAME
    write_json(path, delta)
    return path


def main() -> int:
    packet, packet_sha = build_packet()
    runbook = write_runbook(packet_sha)
    summary_path = ROOT / "reports" / "v17_7_4_compact_realbench_builder_summary.json"
    registry_delta_path = ROOT / "registry" / REGISTRY_DELTA_NAME
    summary = authority(
        schema_id="kt.v17_7_4.compact_realbench_builder_summary.v1",
        status="PASS",
        current_head=run_git(["rev-parse", "HEAD"]),
        current_branch=run_git(["branch", "--show-current"]),
        outcome=OUTCOME,
        next_lawful_move=NEXT_LAWFUL_MOVE,
        packet_path=packet.relative_to(ROOT).as_posix(),
        packet_sha256=packet_sha,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
        one_cell_runbook=runbook.relative_to(ROOT).as_posix(),
        artifact_authority_delta_receipt=registry_delta_path.relative_to(ROOT).as_posix(),
        claim_ceiling_preserved=True,
        blockers=[],
    )
    write_json(summary_path, summary)
    write_registry_delta(summary_path, packet, runbook, packet_sha)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
