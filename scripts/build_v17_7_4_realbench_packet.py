from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any


PROGRAM_ID = "AUTHOR_KTV1774_REAL_BENCHMARK_GAUGE_AND_G2_SENTINEL_REINHERITANCE_V1"
OUTCOME = "KTG3FULL_V17_7_4_REAL_BENCHMARK_GAUGE_READY__RUN_50_OR_200_ROW_COMPRESSION_FRONTIER_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_KTV1774_REALBENCH_50_COMPRESSION_FRONTIER"
PACKET_NAME = "ktv1774_realbench_v1.zip"
KAGGLE_DATASET_NAME = "ktv1774-realbench-v1"

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


def write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
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


def write_zip_member(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def realbench_integrity_receipt(repo: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    defects = []
    for row in manifest.get("rows", []):
        row_defects = []
        if row.get("benchmark_source") != "REAL_BENCHMARK_ROW":
            row_defects.append("benchmark_source_not_real")
        if not str(row.get("question_text", "")).strip():
            row_defects.append("question_text_missing")
        if not str(row.get("expected_answer", "")).strip():
            row_defects.append("expected_answer_missing")
        if str(row.get("sample_id", "")).startswith("v1773-acq-"):
            row_defects.append("diagnostic_acquisition_row_forbidden")
        if row_defects:
            defects.append({"sample_id": row.get("sample_id"), "defects": row_defects})
    return authority(
        schema_id="kt.v17_7_4.realbench_source_integrity_receipt.v1",
        status="PASS" if not defects else "BLOCKED",
        manifest_path="admission/v17_7_4_realbench_row_manifest.json",
        manifest_sha256=sha256_file(repo / "admission" / "v17_7_4_realbench_row_manifest.json"),
        row_count=len(manifest.get("rows", [])),
        datasets=sorted({row.get("dataset") for row in manifest.get("rows", [])}),
        defects=defects,
    )


def write_packet(repo: Path) -> tuple[Path, str]:
    packet = repo / "packets" / PACKET_NAME
    packet.parent.mkdir(parents=True, exist_ok=True)
    run_manifest = authority(
        schema_id="kt.v17_7_4.realbench_truegen_packet_manifest.v1",
        status="READY_FOR_REAL_BENCHMARK_GAUGE_TRUEGEN",
        run_mode="RUN_KTV1774_REALBENCH_TRUEGEN_COMPRESSION_FRONTIER",
        measurement_mode="REAL_BENCHMARK_GAUGE",
        default_requested_rows=50,
        row_request_envs=[
            "KT_TRUEGEN_TARGET_ROWS",
            "KT_MINIFURNACE_ROWS",
            "KT_TRUEGEN_MIN_ROWS",
            "KT_BENCH_SAMPLES_PER_DATASET",
            "KT_TRUEGEN_ROW_LIMIT",
        ],
        row_request_must_be_honored=True,
        prompt_integrity_required=True,
        benchmark_source_integrity_required=True,
        g2_sentinel_mode_available=True,
        g2_sentinel_source_required_for_g2_mode=True,
        hf_vault_source_of_truth=True,
        adapter_source_preference="LOCAL_NORMALIZED_ROOT_WHEN_PRESENT_ELSE_HF_VAULT_SUBFOLDER",
        arm_isolation_mode="ARM_MAJOR_UNLOAD_AFTER_EACH_ARM",
        stream_rows_to_disk=True,
        gpu_memory_ledger_required=True,
        assessment_only_return_required=True,
        no_training=True,
        no_promotion=True,
        no_v18=True,
        no_fake_pass=True,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
    )
    members = {
        "README.md": (
            "# KTV1774 Real Benchmark Gauge TrueGen V1\n\n"
            "This packet repairs the V17.7.4 measurement surface. It uses real benchmark rows with `question_text` "
            "and scorer-only `expected_answer`, honors operator row-count environment overrides exactly, emits "
            "row/source/prompt integrity receipts, and fails closed if diagnostic metadata rows are used as a "
            "compression gauge. It preserves HF-vault adapter loading, local normalized adapter roots, memory-safe "
            "arm isolation, streaming rows, partial rescue, and assessment-only return. It does not train, promote, "
            "authorize V18, or create router-superiority/commercial/frontier claims.\n"
        ).encode("utf-8"),
        "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py": (repo / "runtime" / "v17_7_4" / "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py").read_bytes(),
        "KT_V1774_TRUEGEN_ARM_CORE.py": (repo / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py").read_bytes(),
        "runtime_inputs/truegen_row_manifest.json": (repo / "admission" / "v17_7_4_realbench_row_manifest.json").read_bytes(),
        "runtime_inputs/arm_model_config.json": (repo / "configs" / "v17_7_4" / "arm_model_config.json").read_bytes(),
        "runtime_inputs/arm_model_config.example.json": (repo / "configs" / "v17_7_4" / "arm_model_config.example.json").read_bytes(),
        "run_manifest.json": json.dumps(run_manifest, indent=2, sort_keys=True).encode("utf-8"),
    }
    with zipfile.ZipFile(packet, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            write_zip_member(archive, name, data)
    return packet, sha256_file(packet)


def write_doc(repo: Path, packet_sha: str) -> Path:
    return write_text(
        repo / "docs" / "V17_7_4_REALBENCH_TRUEGEN_ONE_CELL.md",
        f"""# V17.7.4 RealBench TrueGen One Cell

Packet: `packets/{PACKET_NAME}`

Kaggle dataset name: `{KAGGLE_DATASET_NAME}`

SHA256: `{packet_sha}`

This is the real benchmark gauge packet, not the diagnostic acquisition packet.

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "RUN_KTV1774_REALBENCH_TRUEGEN_COMPRESSION_FRONTIER"
os.environ["KT_TRUEGEN_MEASUREMENT_MODE"] = "REAL_BENCHMARK_GAUGE"
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

work = Path("/kaggle/working/ktv1774_realbench_packet")
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


def update_registry(repo: Path, packet: Path, packet_sha: str, doc: Path) -> Path:
    registry_path = repo / "registry" / "artifact_authority_registry.json"
    registry = read_json(registry_path)
    artifacts = registry.setdefault("artifacts", [])
    existing = {item.get("path"): item for item in artifacts}
    changed = []
    for path, role in [
        (repo / "admission" / "v17_7_4_realbench_row_manifest.json", "real_benchmark_row_manifest"),
        (repo / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py", "realbench_truegen_runtime"),
        (packet, "realbench_truegen_runtime_packet"),
        (doc, "realbench_truegen_one_cell_runbook"),
    ]:
        rel = path.relative_to(repo).as_posix()
        payload = authority(
            artifact_id=f"v17_7_4_realbench::{rel}",
            path=rel,
            role=role,
            status="LIVE_CURRENT_HEAD_PREP_ONLY",
            authority_state="LIVE_CURRENT_HEAD_PREP_ONLY",
            sha256=sha256_file(path),
            notes="Real benchmark gauge prep artifact; no promotion, V18, commercial, or superiority authority.",
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
        repo / "registry" / "artifact_authority_registry_v17_7_4_realbench_delta_receipt.json",
        authority(
            schema_id="kt.v17_7_4.realbench_artifact_authority_delta_receipt.v1",
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
    manifest = read_json(repo / "admission" / "v17_7_4_realbench_row_manifest.json")
    integrity = realbench_integrity_receipt(repo, manifest)
    if integrity["status"] != "PASS":
        raise RuntimeError(f"realbench source integrity failed: {integrity['defects'][:5]}")
    write_json(repo / "reports" / "v17_7_4_realbench_source_integrity_receipt.json", integrity)
    write_json(
        repo / "reports" / "g2_sentinel_replay_manifest.json",
        authority(
            schema_id="kt.v17_7_4.g2_sentinel_replay_manifest.v1",
            status="BLOCKED",
            outcome="KT_BLOCKED__G2_SENTINEL_SOURCE_MISSING",
            exact_g2_sample_ids_recovered=False,
            note="Historical G2 aggregate anchor exists, but exact prompt/sample replay manifest is not bound in current repo evidence.",
        ),
    )
    write_json(
        repo / "reports" / "g2_sentinel_replay_scorecard.json",
        authority(
            schema_id="kt.v17_7_4.g2_sentinel_replay_scorecard.v1",
            status="BLOCKED",
            outcome="KT_BLOCKED__G2_SENTINEL_SOURCE_MISSING",
            current_stack_replay_authority=False,
        ),
    )
    packet, packet_sha = write_packet(repo)
    doc = write_doc(repo, packet_sha)
    registry_delta = update_registry(repo, packet, packet_sha, doc)
    summary = authority(
        schema_id="kt.v17_7_4.realbench_builder_summary.v1",
        status="PASS",
        current_head=current_head(),
        current_branch=current_branch(),
        git_status_porcelain=git_status(),
        outcome=OUTCOME,
        next_lawful_move=NEXT_LAWFUL_MOVE,
        packet_path=packet.relative_to(repo).as_posix(),
        packet_sha256=packet_sha,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
        one_cell_runbook=doc.relative_to(repo).as_posix(),
        row_authority_status="ENV_OVERRIDE_EXACT_FAIL_CLOSED",
        benchmark_source_integrity_status=integrity["status"],
        prompt_integrity_status="RUNTIME_GATE_BOUND",
        g2_sentinel_status="BLOCKED_UNTIL_EXACT_G2_SAMPLE_PROMPTS_BOUND",
        registry_delta_path=registry_delta.relative_to(repo).as_posix(),
        blockers=[],
    )
    write_json(repo / "reports" / "v17_7_4_realbench_builder_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def main() -> int:
    build()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
