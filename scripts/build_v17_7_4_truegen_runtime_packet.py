from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any


PROGRAM_ID = "KT_V17_7_4_TRUEGEN_MINIFURNACE_EXECUTION_PATCH"
OUTCOME = "KTG3FULL_V17_7_4_TRUEGEN_MINIFURNACE_EXECUTION_READY__RUN_FRESH_GENERATION_MINIFURNACE_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_KTV1774_TRUEGEN_E2E_PACKET"
PACKET_NAME = "ktv1774_truegen_e2e_v1.zip"
KAGGLE_DATASET_NAME = "ktv1774-truegen-v1"
OLD_PACKET = "ktv1774_truegen_minifurnace_v1.zip"
OLD_PACKET_SHA = "a128dea677ba31f49abff56fa85206487557d1a5827f1daecda295d7f898ca64"
ARM_IDS = [
    "base_raw",
    "route_regret_policy_adapter_global",
    "formal_math_repair_adapter_global",
    "base_kt_hat_compact",
    "math_act_adapter_global",
]

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


def core_module():
    path = root() / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=root(), text=True, stderr=subprocess.DEVNULL).strip()


def current_head() -> str:
    return run_git(["rev-parse", "HEAD"])


def current_branch() -> str:
    return run_git(["branch", "--show-current"])


def git_status() -> str:
    return run_git(["status", "--porcelain=v1"])


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(AUTHORITY_FALSE)
    payload.update(extra)
    return payload


def write_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    return path


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def packet_hashes() -> dict[str, Any]:
    packet = Path(r"D:\user\rober\Downloads\ktv1774_execfix_v1 (1).zip")
    prompt = Path(r"D:\user\rober\Downloads\COPY_PASTE_NOW_ktv1774_execfix_v1 (1).txt")
    return {
        "packet_path": str(packet),
        "packet_sha256": sha256_file(packet) if packet.exists() else None,
        "prompt_path": str(prompt),
        "prompt_sha256": sha256_file(prompt) if prompt.exists() else None,
    }


def generic_schema(schema_id: str, required: list[str], properties: dict[str, Any] | None = None) -> dict[str, Any]:
    base = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": schema_id,
        "type": "object",
        "additionalProperties": True,
        "properties": {
            "schema_id": {"type": "string"},
            "claim_ceiling_preserved": {"const": True},
            "adapter_training_authorized": {"const": False},
            "router_training_authorized": {"const": False},
            "promotion_authority": {"const": False},
            "runtime_authority": {"const": False},
            "v18_runtime_authority": {"const": False},
        },
        "required": required,
    }
    if properties:
        base["properties"].update(properties)
    return base


def write_schemas(repo: Path) -> list[Path]:
    schemas = {
        "kt.v17_7_4.arm_model_config.schema.json": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "kt.v17_7_4.arm_model_config.v1",
            "type": "object",
            "additionalProperties": True,
            "required": ["base_model_repo", "load_in_4bit", "torch_dtype", "max_new_tokens", "batch_size", "device_map", "generation_seed", "arms"],
            "properties": {
                "base_model_repo": {"type": "string", "minLength": 1},
                "load_in_4bit": {"type": "boolean"},
                "torch_dtype": {"type": "string"},
                "max_new_tokens": {"type": "integer", "minimum": 1},
                "batch_size": {"type": "integer", "minimum": 1},
                "device_map": {"type": "string"},
                "generation_seed": {"type": "integer"},
                "arms": {
                    "type": "array",
                    "minItems": 5,
                    "items": {
                        "type": "object",
                        "required": [
                            "arm_id",
                            "model_repo_or_base",
                            "adapter_hf_repo",
                            "adapter_path",
                            "adapter_sha256_optional",
                            "enabled",
                            "prompt_template_id",
                            "scoring_method",
                            "max_new_tokens",
                        ],
                    },
                },
            },
        },
        "kt.v17_7_4.truegen_row.schema.json": generic_schema(
            "kt.v17_7_4.truegen_row.v1",
            [
                "schema_id",
                "sample_id",
                "dataset",
                "task_family",
                "prompt_hash",
                "prompt",
                "expected_label_or_oracle_label",
                "label_source",
                "scoring_rule",
                "holdout_status",
                "source_replay_reference_if_any",
                "claim_ceiling_preserved",
            ],
            {
                "schema_id": {"const": "kt.v17_7_4.truegen_row.v1"},
                "sample_id": {"type": "string"},
                "prompt_hash": {"type": "string"},
                "holdout_status": {"enum": ["TRAINING_SEARCH_DIAGNOSTIC", "HELDOUT_NOT_FOR_PROMOTION"]},
            },
        ),
        "kt.v17_7_4.truegen_prediction.schema.json": generic_schema("kt.v17_7_4.truegen_prediction.v1", ["schema_id", "sample_id", "measurement_source", "measurement_status", "generation_artifacts_present", "claim_ceiling_preserved"]),
        "kt.v17_7_4.truegen_arm_result.schema.json": generic_schema("kt.v17_7_4.truegen_arm_result.v1", ["schema_id", "sample_id", "arm_id", "prompt_hash", "output_hash", "measurement_source", "measurement_status", "generation_artifacts_present", "claim_ceiling_preserved"]),
        "kt.v17_7_4.truegen_final_summary.schema.json": generic_schema("kt.v17_7_4.truegen_final_summary.v1", ["schema_id", "status", "outcome", "measurement_source", "generation_artifacts_present", "claim_ceiling_preserved"]),
    }
    return [write_json(repo / "schemas" / name, payload) for name, payload in schemas.items()]


def arm_config_example() -> dict[str, Any]:
    arms = [
        ("base_raw", "raw"),
        ("route_regret_policy_adapter_global", "route_regret"),
        ("formal_math_repair_adapter_global", "formal_math"),
        ("base_kt_hat_compact", "kt_hat_compact"),
        ("math_act_adapter_global", "math_act"),
    ]
    return authority(
        schema_id="kt.v17_7_4.arm_model_config.example.v1",
        base_model_repo="sshleifer/tiny-gpt2",
        load_in_4bit=False,
        torch_dtype="auto",
        max_new_tokens=32,
        batch_size=1,
        device_map="auto",
        generation_seed=1337,
        row_limit=100,
        arms=[
            {
                "arm_id": arm_id,
                "model_repo_or_base": "BASE",
                "adapter_hf_repo": "",
                "adapter_path": "",
                "adapter_sha256_optional": "",
                "enabled": True,
                "prompt_template_id": template,
                "scoring_method": "contains_expected_label",
                "max_new_tokens": 32,
            }
            for arm_id, template in arms
        ],
    )


def source_rows_by_id(repo: Path) -> dict[str, dict[str, Any]]:
    rows = read_jsonl(repo / "admission" / "v17_7_route_outcome_table.jsonl")
    return {row["sample_id"]: row for row in rows}


def select_manifest_rows(repo: Path, limit: int = 100) -> list[dict[str, Any]]:
    acquisition = read_json(repo / "admission" / "v17_7_3_targeted_boundary_row_manifest.json")["rows"]
    source = source_rows_by_id(repo)

    def priority(row: dict[str, Any]) -> tuple[float, int, str]:
        tags = set(row.get("boundary_tags", [])) | set(row.get("slice_tags", []))
        score = float(row.get("eig_score", 0.0))
        score += 0.2 if "math_numeric" in tags else 0.0
        score += 0.15 if "base_raw__route_regret" in tags else 0.0
        score += 0.15 if "math_act_boundary" in tags else 0.0
        score += 0.1 if "hat_act_boundary" in tags else 0.0
        score += 0.1 if row.get("state_diff_required") else 0.0
        return (-score, int(row["acquisition_row_id"].rsplit("-", 1)[-1]), row["acquisition_row_id"])

    selected = sorted(acquisition, key=priority)[:limit]
    rows: list[dict[str, Any]] = []
    for row in selected:
        source_ref = source.get(row["source_seed_sample_id"], {})
        expected = row["source_seed_sample_id"]
        prompt = (
            "Fresh-generation diagnostic boundary row. "
            f"dataset={row['source_seed_dataset']}; "
            f"boundaries={','.join(row.get('boundary_tags', []))}; "
            "produce a concise answer without making promotion, superiority, or deployment claims."
        )
        rows.append(
            authority(
                schema_id="kt.v17_7_4.truegen_row.v1",
                sample_id=row["acquisition_row_id"],
                dataset=row["source_seed_dataset"],
                task_family=source_ref.get("task_family", "unknown_task_family"),
                evidence_band=row["primary_band"],
                route_boundary_class="+".join(sorted(row.get("boundary_tags", ["unclassified_boundary"]))),
                prompt=prompt,
                prompt_hash=hashlib.sha256(prompt.encode()).hexdigest(),
                expected_label_or_oracle_label=expected,
                label_source="SOURCE_SEED_SAMPLE_ID_DIAGNOSTIC_LABEL",
                scoring_rule="contains_expected_label",
                holdout_status="TRAINING_SEARCH_DIAGNOSTIC",
                source_replay_reference_if_any={
                    "source_seed_sample_id": row["source_seed_sample_id"],
                    "route_values_pre_generation": source_ref.get("route_values_pre_generation", {}),
                    "route_correctness": source_ref.get("route_correctness", {}),
                    "oracle_route_for_evaluation_only": source_ref.get("oracle_route_for_evaluation_only"),
                },
            )
        )
    return rows


def inspect_old_packet(repo: Path) -> dict[str, Any]:
    packet = repo / "packets" / OLD_PACKET
    if not packet.exists():
        return {"exists": False, "defect_confirmed": True, "reason": "old packet missing"}
    with zipfile.ZipFile(packet) as archive:
        names = archive.namelist()
        text = "\n".join(archive.read(name).decode("utf-8", errors="ignore") for name in names if name.endswith((".py", ".json", ".md")))
    defect = "CONFIG_BOUND_NOT_EXECUTED_BY_REPO_SIDE_LANE" in text and "FRESH_MODEL_GENERATION" not in text
    return {
        "exists": True,
        "sha256": sha256_file(packet),
        "members": names,
        "config_bound_status_present": "CONFIG_BOUND_NOT_EXECUTED_BY_REPO_SIDE_LANE" in text,
        "fresh_generation_source_present": "FRESH_MODEL_GENERATION" in text,
        "defect_confirmed": defect,
    }


def write_runtime_packet(repo: Path) -> tuple[Path, str]:
    packet = repo / "packets" / PACKET_NAME
    packet.parent.mkdir(parents=True, exist_ok=True)
    members = {
        "README.md": (
            "# KTV1774 True-Generation Mini-Furnace\n\n"
            "This packet performs fresh model generation or fails closed. It does not train, promote, authorize V18, or claim learned-router superiority.\n"
        ).encode("utf-8"),
        "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py": (repo / "runtime" / "v17_7_4" / "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py").read_bytes(),
        "KT_V1774_TRUEGEN_ARM_CORE.py": (repo / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py").read_bytes(),
        "runtime_inputs/truegen_row_manifest.json": (repo / "admission" / "v17_7_4_truegen_row_manifest.json").read_bytes(),
        "runtime_inputs/arm_model_config.example.json": (repo / "configs" / "v17_7_4" / "arm_model_config.example.json").read_bytes(),
        "run_manifest.json": json.dumps(
            authority(
                schema_id="kt.v17_7_4.truegen_e2e_packet_manifest.v1",
                status="READY_FOR_FRESH_GENERATION_MINIFURNACE",
                run_mode="RUN_KTV1774_TRUEGEN_MINIFURNACE",
                required_or_bundled_input="arm_model_config.json or complete bundled safe example",
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
    text = f"""# V17.7.4 True-Generation Mini-Furnace One Cell

Packet: `packets/{PACKET_NAME}`

Kaggle dataset name: `{KAGGLE_DATASET_NAME}`

SHA256: `{packet_sha}`

This runner performs fresh generation or fails closed. It does not train, promote routes/adapters, authorize V18, or expand the claim ceiling.

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "RUN_KTV1774_TRUEGEN_MINIFURNACE"
os.environ["KT_NO_TRAINING"] = "1"
os.environ["KT_NO_PROMOTION"] = "1"
os.environ["KT_NO_V18"] = "1"

candidates = [
    Path("/kaggle/input/{KAGGLE_DATASET_NAME}/{PACKET_NAME}"),
    Path("/kaggle/working/{PACKET_NAME}"),
]
packet = next((p for p in candidates if p.exists()), None)
if packet is None:
    raise FileNotFoundError("missing {PACKET_NAME}")

work = Path("/kaggle/working/ktv1774_truegen_e2e_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as archive:
    archive.extractall(work)

os.chdir(work)
sys.path.insert(0, str(work))
subprocess.check_call([sys.executable, "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py"])
print("assessment outputs:", sorted(Path("/kaggle/working").glob("**/KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip")))
```
"""
    path = repo / "docs" / "V17_7_4_TRUEGEN_MINIFURNACE_ONE_CELL.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def update_registry(repo: Path, paths: list[Path], packet: Path, packet_sha: str) -> Path:
    registry_path = repo / "registry" / "artifact_authority_registry.json"
    registry = read_json(registry_path)
    existing = {item.get("path") for item in registry.get("artifacts", [])}
    added = []
    for path in paths:
        rel = path.relative_to(repo).as_posix()
        if rel not in existing:
            item = authority(
                artifact_id=f"v17_7_4_truegen_execfix::{rel}",
                path=rel,
                role="true_generation_minifurnace_execution_patch",
                status="LIVE_CURRENT_HEAD_PREP_ONLY",
                authority_state="LIVE_CURRENT_HEAD_PREP_ONLY",
                sha256=sha256_file(path),
            )
            registry.setdefault("artifacts", []).append(item)
            added.append(rel)
    rel_packet = packet.relative_to(repo).as_posix()
    if rel_packet not in existing:
        registry.setdefault("artifacts", []).append(
            authority(
                artifact_id="KTV1774_TRUEGEN_E2E_PACKET",
                path=rel_packet,
                role="fresh_generation_minifurnace_runtime_packet",
                status="LIVE_CURRENT_HEAD_PREP_ONLY",
                authority_state="LIVE_CURRENT_HEAD_PREP_ONLY",
                sha256=packet_sha,
            )
        )
        added.append(rel_packet)
    registry["current_head"] = current_head()
    registry["updated_by"] = PROGRAM_ID
    registry["claim_ceiling_preserved"] = True
    write_json(registry_path, registry)
    delta = authority(
        schema_id="kt.v17_7_4.artifact_authority_delta_receipt.v1",
        status="PASS",
        current_head=current_head(),
        artifacts_added=added,
        artifacts_modified=[rel_packet],
        artifacts_superseded=[f"packets/{OLD_PACKET}"],
        old_packet_sha256=OLD_PACKET_SHA,
        new_packet_sha256=packet_sha,
        no_claim_ceiling_expansion=True,
    )
    return write_json(repo / "registry" / "artifact_authority_registry_v17_7_4_truegen_execfix_delta_receipt.json", delta)


def build(preflight_status: str | None = None) -> dict[str, Any]:
    repo = root()
    old = inspect_old_packet(repo)
    if old.get("exists") and not old.get("defect_confirmed"):
        outcome = "NOOP_EXISTING_PACKET_ALREADY_TRUEGEN"
    else:
        outcome = OUTCOME
    schemas = write_schemas(repo)
    config_path = write_json(repo / "configs" / "v17_7_4" / "arm_model_config.example.json", arm_config_example())
    rows = select_manifest_rows(repo, limit=100)
    manifest = authority(
        schema_id="kt.v17_7_4.truegen_row_manifest.v1",
        status="PASS",
        row_count=len(rows),
        row_target_default=100,
        row_target_allowed=[50, 200],
        selection_source="V17.7.3 authority decision needs",
        rows=rows,
    )
    manifest_path = write_json(repo / "admission" / "v17_7_4_truegen_row_manifest.json", manifest)
    packet, packet_sha = write_runtime_packet(repo)
    doc_path = write_doc(repo, packet_sha)
    reports = [
        write_json(
            repo / "reports" / "v17_7_4_preflight_repo_truth_receipt.json",
            authority(
                schema_id="kt.v17_7_4.preflight_repo_truth_receipt.v1",
                status="PASS",
                current_head=current_head(),
                current_branch=current_branch(),
                git_status_porcelain=preflight_status if preflight_status is not None else git_status(),
                worktree_clean_before_build=(preflight_status == "" if preflight_status is not None else git_status() == ""),
                **packet_hashes(),
            ),
        ),
        write_json(repo / "reports" / "v17_7_4_truegen_packet_defect_receipt.json", authority(schema_id="kt.v17_7_4.truegen_packet_defect_receipt.v1", status="PASS", defect_confirmed=old.get("defect_confirmed") is True, old_packet=old, selected_patch="replace config-bound packet with true-generation E2E runtime packet")),
        write_json(repo / "reports" / "v17_7_4_claim_ceiling_receipt.json", authority(schema_id="kt.v17_7_4.claim_ceiling_receipt.v1", status="PASS", no_kaggle_run=True, no_training=True, no_route_promotion=True, no_adapter_promotion=True, no_v18=True)),
        write_json(repo / "reports" / "v17_7_4_arm_model_config_contract_receipt.json", authority(schema_id="kt.v17_7_4.arm_model_config_contract_receipt.v1", status="PASS", required_arms=ARM_IDS, config_example_path=config_path.relative_to(repo).as_posix(), base_fallback_marks_non_adapter_evidence=True)),
        write_json(repo / "reports" / "v17_7_4_truegen_row_manifest_receipt.json", authority(schema_id="kt.v17_7_4.truegen_row_manifest_receipt.v1", status="PASS", row_count=len(rows), selected_from_v17_7_3_decision_needs=True, manifest_path=manifest_path.relative_to(repo).as_posix())),
        write_json(repo / "reports" / "v17_7_4_scorecard_recompute_contract.json", authority(schema_id="kt.v17_7_4.scorecard_recompute_contract.v1", status="PASS", required_outputs=["truegen_benchmark_scorecard.json", "truegen_replay_correlation_scorecard.json"], scorecards_recomputed_from_fresh_rows=True)),
        write_json(repo / "reports" / "v17_7_4_replay_vs_truegen_correlation.json", authority(schema_id="kt.v17_7_4.replay_vs_truegen_correlation_contract.v1", status="AWAITING_RUNTIME_FRESH_GENERATION", measured_now=False, runtime_output_required="truegen_replay_correlation_scorecard.json")),
        write_json(repo / "reports" / "v17_7_4_measurement_authority_update.json", authority(schema_id="kt.v17_7_4.measurement_authority_update_contract.v1", status="READY_FOR_RUNTIME_MEASUREMENT", current_authority="EXECUTION_PACKET_READY_ONLY", fresh_generation_authority_earned=False)),
        write_json(repo / "reports" / "v17_7_4_next_move_decision_receipt.json", authority(schema_id="kt.v17_7_4.next_move_decision_receipt.v1", status="PASS", outcome=outcome, next_lawful_move=NEXT_LAWFUL_MOVE, packet_path=packet.relative_to(repo).as_posix(), packet_sha256=packet_sha, kaggle_dataset_name=KAGGLE_DATASET_NAME, blockers=[])),
    ]
    registry_delta = update_registry(repo, schemas + [config_path, manifest_path, doc_path] + reports, packet, packet_sha)
    summary = authority(
        schema_id="kt.v17_7_4.truegen_execfix_builder_summary.v1",
        status="PASS",
        outcome=outcome,
        current_head=current_head(),
        packet_path=packet.relative_to(repo).as_posix(),
        packet_sha256=packet_sha,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
        registry_delta_path=registry_delta.relative_to(repo).as_posix(),
        next_lawful_move=NEXT_LAWFUL_MOVE,
    )
    write_json(repo / "reports" / "v17_7_4_truegen_execfix_builder_summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight-status", default=None)
    args = parser.parse_args()
    print(json.dumps(build(args.preflight_status), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
