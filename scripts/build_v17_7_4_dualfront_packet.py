from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PACKET_NAME = "ktv1774_dualfront_v1.zip"
KAGGLE_DATASET_NAME = "ktv1774-dualfront-v1"
RUNBOOK = "V17_7_4_DUALFRONT_TRUEGEN_ONE_CELL.md"
OUTCOME = "KT_DUAL_FRONTIER_ROUTER_SUBSTRATE_READY__RUN_REASONING_PRESERVING_ADMISSION_BENCH_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_KTV1774_DUALFRONT_50"


def authority(**extra: Any) -> dict[str, Any]:
    payload = {
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
        "adapter_training_authorized": False,
        "router_training_authorized": False,
        "policy_optimization_authorized": False,
        "learned_router_superiority_claim": False,
        "multi_lobe_superiority_claim": False,
        "v18_runtime_authority": False,
    }
    payload.update(extra)
    return payload


def git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


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


def arm_by_id(base_config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {arm["arm_id"]: arm for arm in base_config["arms"]}


def dualfront_config() -> dict[str, Any]:
    base_config = json.loads((ROOT / "configs" / "v17_7_4" / "arm_model_config.json").read_text(encoding="utf-8"))
    arms = arm_by_id(base_config)
    math_act = dict(arms["math_act_adapter_global"])
    formal_math = dict(arms["formal_math_repair_adapter_global"])
    route_regret = dict(arms["route_regret_policy_adapter_global"])
    def base_arm(arm_id: str, template: str, compact_mode: str, max_new_tokens: int = 16) -> dict[str, Any]:
        return {
            "adapter_binding_status": "BASELINE_NO_ADAPTER_REQUIRED",
            "adapter_hf_repo": "",
            "adapter_path": "",
            "adapter_required_for_real_authority": False,
            "adapter_sha256_optional": "",
            "arm_id": arm_id,
            "arm_kind": "base_model",
            "compact_mode": compact_mode,
            "enabled": True,
            "max_new_tokens": max_new_tokens,
            "model_repo_or_base": "BASE",
            "prompt_template_id": template,
            "scoring_method": "contains_expected_label",
        }
    def prompt_arm(arm_id: str, template: str, compact_mode: str, max_new_tokens: int = 32) -> dict[str, Any]:
        row = base_arm(arm_id, template, compact_mode, max_new_tokens)
        row["adapter_binding_status"] = "PROMPT_OVERLAY_ONLY_NO_ADAPTER_REQUIRED"
        row["arm_kind"] = "prompt_overlay"
        row["prompt_overlay_authority"] = "DUALFRONT_PROMPT_OVERLAY_CANDIDATE_ONLY"
        return row
    def adapter_arm(source: dict[str, Any], arm_id: str, template: str, compact_mode: str, max_new_tokens: int) -> dict[str, Any]:
        row = dict(source)
        row.update(
            arm_id=arm_id,
            compact_mode=compact_mode,
            enabled=True,
            max_new_tokens=max_new_tokens,
            prompt_template_id=template,
            scoring_method="contains_expected_label",
        )
        return row
    config = dict(base_config)
    config.update(
        schema_id="kt.v17_7_4.arm_model_config.dualfront.v1",
        config_profile="REAL_ARM_DUALFRONT",
        measurement_mode="DUALFRONT_REASONING_PRESERVING_ADMISSION_BENCH",
        compact_answer_contract=True,
        reasoning_preserving_compact=True,
        row_limit=50,
        default_row_ladder_stage=None,
        max_new_tokens=64,
        required_arm_ids=[
            "A0_base_raw",
            "A1_base_raw_finalizer_only",
            "A2_math_act_full_reasoning",
            "A3_math_act_reasoning_preserving_compact",
            "A4_formal_math_reasoning_preserving_compact",
            "A5_specialist_admission_controller_v1",
            "A6_kt_hat_compact_risk_gated",
            "A7_oracle_shadow_not_runtime",
        ],
        arms=[
            base_arm("A0_base_raw", "raw", "SHORT_ANSWER_FINAL_ONLY", max_new_tokens=64),
            base_arm("A1_base_raw_finalizer_only", "base_raw_finalizer_only", "MCQ_ANSWER_ONLY", max_new_tokens=16),
            adapter_arm(math_act, "A2_math_act_full_reasoning", "math_act_full_reasoning", "NUMERIC_BOUNDED_SCRATCH_THEN_FINAL", 64),
            adapter_arm(math_act, "A3_math_act_reasoning_preserving_compact", "math_act_reasoning_preserving_compact", "NUMERIC_BOUNDED_SCRATCH_THEN_FINAL", 64),
            adapter_arm(formal_math, "A4_formal_math_reasoning_preserving_compact", "formal_math_reasoning_preserving_compact", "NUMERIC_BOUNDED_SCRATCH_THEN_FINAL", 64),
            adapter_arm(route_regret, "A5_specialist_admission_controller_v1", "specialist_admission_controller", "EVIDENCE_GROUNDED_BRIEF_THEN_FINAL", 64),
            prompt_arm("A6_kt_hat_compact_risk_gated", "kt_hat_compact_risk_gated", "SHORT_ANSWER_FINAL_ONLY", max_new_tokens=32),
            prompt_arm("A7_oracle_shadow_not_runtime", "oracle_shadow_not_runtime", "EVIDENCE_GROUNDED_BRIEF_THEN_FINAL", max_new_tokens=64),
        ],
    )
    return config


def build_packet() -> tuple[Path, str]:
    packet = ROOT / "packets" / PACKET_NAME
    packet.parent.mkdir(parents=True, exist_ok=True)
    config = dualfront_config()
    run_manifest = authority(
        schema_id="kt.v17_7_4.dualfront_packet_manifest.v1",
        status="READY_FOR_DUALFRONT_TRUEGEN",
        run_mode="RUN_KTV1774_DUALFRONT_50",
        measurement_mode="DUALFRONT_REASONING_PRESERVING_ADMISSION_BENCH",
        default_requested_rows=50,
        compact_answer_contract=True,
        reasoning_preserving_compact=True,
        dual_frontier_scorecard_required=True,
        visible_answer_ledger_required=True,
        reasoning_preserving_compact_receipt_required=True,
        route_margin_scorecard_required=True,
        oracle_shadow_not_runtime=True,
        hf_vault_source_of_truth=True,
        assessment_only_return_required=True,
        no_training=True,
        no_promotion=True,
        no_v18=True,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
    )
    members = {
        "README.md": (
            "# KTV1774 DualFront V1\n\n"
            "Runs the reasoning-preserving admission bench: correctness and compression are measured together. "
            "The packet preserves bounded reasoning for math, emits compact visible answers, scores final visible answers, "
            "and keeps oracle shadow non-runtime. No training, promotion, V18, router-superiority, commercial, frontier, "
            "S-tier, 7B, or multi-lobe claim is authorized.\n"
        ).encode("utf-8"),
        "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py": (ROOT / "runtime" / "v17_7_4" / "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py").read_bytes(),
        "KT_V1774_TRUEGEN_ARM_CORE.py": (ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py").read_bytes(),
        "runtime_inputs/truegen_row_manifest.json": (ROOT / "admission" / "v17_7_4_realbench_row_manifest.json").read_bytes(),
        "runtime_inputs/arm_model_config.json": json.dumps(config, indent=2, sort_keys=True).encode("utf-8"),
        "runtime_inputs/reasoning_preserving_compact_contract.json": (ROOT / "configs" / "v17_7_4" / "reasoning_preserving_compact_contract.json").read_bytes(),
        "runtime_inputs/task_family_reasoning_budget.json": (ROOT / "configs" / "v17_7_4" / "task_family_reasoning_budget.json").read_bytes(),
        "run_manifest.json": json.dumps(run_manifest, indent=2, sort_keys=True).encode("utf-8"),
    }
    with zipfile.ZipFile(packet, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            write_zip_member(archive, name, data)
    return packet, sha256_file(packet)


def write_runbook(packet_sha: str) -> Path:
    path = ROOT / "docs" / RUNBOOK
    write_text(
        path,
        f"""# V17.7.4 DualFront TrueGen One Cell

Packet: `packets/{PACKET_NAME}`

Kaggle dataset name: `{KAGGLE_DATASET_NAME}`

SHA256: `{packet_sha}`

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "RUN_KTV1774_DUALFRONT_50"
os.environ["KT_TRUEGEN_MEASUREMENT_MODE"] = "DUALFRONT_REASONING_PRESERVING_ADMISSION_BENCH"
os.environ["KT_COMPACT_ANSWER_CONTRACT"] = "1"
os.environ["KT_REASONING_PRESERVING_COMPACT"] = "1"
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
work = Path("/kaggle/working/ktv1774_dualfront_packet")
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


def main() -> int:
    packet, packet_sha = build_packet()
    runbook = write_runbook(packet_sha)
    summary_path = ROOT / "reports" / "v17_7_4_dualfront_builder_summary.json"
    summary = authority(
        schema_id="kt.v17_7_4.dualfront_builder_summary.v1",
        status="PASS",
        current_head=git(["rev-parse", "HEAD"]),
        current_branch=git(["branch", "--show-current"]),
        outcome=OUTCOME,
        next_lawful_move=NEXT_LAWFUL_MOVE,
        packet_path=packet.relative_to(ROOT).as_posix(),
        packet_sha256=packet_sha,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
        one_cell_runbook=runbook.relative_to(ROOT).as_posix(),
        claim_ceiling_preserved=True,
        blockers=[],
    )
    write_json(summary_path, summary)
    delta = authority(
        schema_id="kt.artifact_authority_registry.delta_receipt.v17_7_4_dualfront.v1",
        status="PASS",
        current_head=summary["current_head"],
        artifacts_added=[
            {"path": packet.relative_to(ROOT).as_posix(), "role": "dualfront_kaggle_packet", "sha256": packet_sha, "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY", "claim_expansion": False},
            {"path": runbook.relative_to(ROOT).as_posix(), "role": "dualfront_one_cell_runbook", "sha256": sha256_file(runbook), "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY", "claim_expansion": False},
            {"path": summary_path.relative_to(ROOT).as_posix(), "role": "dualfront_builder_summary", "sha256": sha256_file(summary_path), "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY", "claim_expansion": False},
        ],
        outcome=OUTCOME,
        next_lawful_move=NEXT_LAWFUL_MOVE,
        no_commercial_claim=True,
        no_external_validation_claim=True,
        no_router_superiority_claim=True,
        no_multi_lobe_superiority_claim=True,
    )
    write_json(ROOT / "registry" / "artifact_authority_registry_v17_7_4_dualfront_delta_receipt.json", delta)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
