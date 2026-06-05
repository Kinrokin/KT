from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
PACKET_NAME = "ktv1774_oracle_academy_reentry_v1.zip"
KAGGLE_DATASET_NAME = "ktv1774-oracle-academy-v1"
RUNBOOK = "V17_7_4_ORACLE_ACADEMY_REENTRY_ONE_CELL.md"
OUTCOME = "KT_ORACLE_AUTOPSY_ACADEMY_REENTRY_READY__RUN_KNOWN_GOOD_REPRO_AND_SCAR_REPAIR_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_KTV1774_ORACLE_ACADEMY_REENTRY_50"


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
        "commercial_claim": False,
        "external_validation_claim": False,
        "g2_recovered_claim": False,
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


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_zip_member(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def arm_by_id(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {arm["arm_id"]: arm for arm in config["arms"]}


def base_arm(arm_id: str, template: str = "raw", max_new_tokens: int = 64) -> dict[str, Any]:
    return {
        "adapter_binding_status": "BASELINE_NO_ADAPTER_REQUIRED",
        "adapter_hf_repo": "",
        "adapter_path": "",
        "adapter_required_for_real_authority": False,
        "adapter_sha256_optional": "",
        "arm_id": arm_id,
        "arm_kind": "base_model",
        "compact_mode": "RAW_KNOWN_GOOD_REPRODUCTION",
        "compact_scoring_disabled": True,
        "enabled": True,
        "max_new_tokens": max_new_tokens,
        "model_repo_or_base": "BASE",
        "prompt_template_id": template,
        "score_from_visible_answer": False,
        "scoring_method": "contains_expected_label",
        "scoring_surface": "RAW_OUTPUT",
    }


def prompt_arm(arm_id: str, template: str, compact_mode: str, max_new_tokens: int = 64) -> dict[str, Any]:
    row = base_arm(arm_id, template, max_new_tokens)
    row.update(
        adapter_binding_status="PROMPT_OVERLAY_ONLY_NO_ADAPTER_REQUIRED",
        arm_kind="prompt_overlay",
        compact_mode=compact_mode,
        compact_scoring_disabled=False,
        prompt_overlay_authority="ORACLE_ACADEMY_PROMPT_OVERLAY_CANDIDATE_ONLY",
        score_from_visible_answer=True,
        scoring_surface="FINAL_VISIBLE_ANSWER",
    )
    return row


def adapter_arm(source: dict[str, Any], arm_id: str, template: str, compact_mode: str, max_new_tokens: int, *, score_visible: bool) -> dict[str, Any]:
    row = dict(source)
    row.update(
        arm_id=arm_id,
        compact_mode=compact_mode,
        compact_scoring_disabled=not score_visible,
        enabled=True,
        max_new_tokens=max_new_tokens,
        prompt_template_id=template,
        score_from_visible_answer=score_visible,
        scoring_method="contains_expected_label",
        scoring_surface="FINAL_VISIBLE_ANSWER" if score_visible else "RAW_OUTPUT",
    )
    return row


def oracle_academy_config() -> dict[str, Any]:
    base_config = read_json(ROOT / "configs" / "v17_7_4" / "arm_model_config.json")
    arms = arm_by_id(base_config)
    math_act = arms["math_act_adapter_global"]
    route_regret = arms["route_regret_policy_adapter_global"]
    config = dict(base_config)
    required = [
        "A0_base_raw",
        "A1_prior_realbench_base_raw_reproduction",
        "A_known_good_math_act_reproduction",
        "A3_prior_math_act_plus_finalizer_only",
        "A4_math_act_reasoning_preserving_compact_v2",
        "A5_kt_hat_risk_gated_v2",
        "A6_specialist_admission_candidate_v2",
        "A7_oracle_shadow",
    ]
    config.update(
        schema_id="kt.v17_7_4.arm_model_config.oracle_academy_reentry.v1",
        config_profile="REAL_ARM_ORACLE_ACADEMY_REENTRY",
        measurement_mode="ORACLE_AUTOPSY_ACADEMY_REENTRY",
        compact_answer_contract=True,
        reasoning_preserving_compact=True,
        row_limit=50,
        default_row_ladder_stage=None,
        required_arm_ids=required,
        oracle_correctness_used_as_runtime_feature=False,
        known_good_reproduction_required=True,
        no_training=True,
        no_promotion=True,
        no_v18=True,
        arms=[
            base_arm("A0_base_raw", "raw", 64),
            base_arm("A1_prior_realbench_base_raw_reproduction", "raw", 64),
            adapter_arm(math_act, "A_known_good_math_act_reproduction", math_act["prompt_template_id"], "RAW_KNOWN_GOOD_REPRODUCTION", int(math_act["max_new_tokens"]), score_visible=False),
            adapter_arm(math_act, "A3_prior_math_act_plus_finalizer_only", math_act["prompt_template_id"], "POST_FINALIZER_ONLY", int(math_act["max_new_tokens"]), score_visible=True),
            adapter_arm(math_act, "A4_math_act_reasoning_preserving_compact_v2", "math_act_reasoning_preserving_compact", "NUMERIC_BOUNDED_SCRATCH_THEN_FINAL", 64, score_visible=True),
            prompt_arm("A5_kt_hat_risk_gated_v2", "kt_hat_compact_risk_gated", "SHORT_ANSWER_FINAL_ONLY", 32),
            adapter_arm(route_regret, "A6_specialist_admission_candidate_v2", "specialist_admission_controller", "EVIDENCE_GROUNDED_BRIEF_THEN_FINAL", 64, score_visible=True),
            prompt_arm("A7_oracle_shadow", "oracle_shadow_not_runtime", "EVIDENCE_GROUNDED_BRIEF_THEN_FINAL", 64),
        ],
    )
    return config


def runtime_required_receipt(schema_id: str, artifact: str, purpose: str) -> dict[str, Any]:
    return authority(
        schema_id=schema_id,
        status="RUNTIME_MEASUREMENT_REQUIRED",
        artifact=artifact,
        purpose=purpose,
        measured_runtime_evidence_present=False,
        promotion_eligible=False,
        requires_followup_measurement=True,
    )


def write_prep_reports(config: dict[str, Any]) -> None:
    write_json(
        ROOT / "reports" / "v17_7_4_known_good_lobe_reproduction_receipt.json",
        runtime_required_receipt(
            "kt.v17_7_4.known_good_lobe_reproduction_receipt.prep.v1",
            "known_good_lobe_reproduction_receipt.json",
            "Kaggle runtime must reproduce prior math_act_adapter_global 41/50 path before compact/admission repair is meaningful.",
        )
        | {
            "reproduction_arm_id": "A_known_good_math_act_reproduction",
            "prior_anchor": {"math_act_adapter_global": "41/50", "gsm8k": "11/20", "oracle": "42/50"},
            "allowed_blocker": "KT_BLOCKED__KNOWN_GOOD_INTELLIGENCE_PATH_NOT_REPRODUCED",
        },
    )
    from runtime.v17_7_4.KT_V1774_TRUEGEN_ARM_CORE import realbench_vs_dualfront_arm_diff_receipt

    write_json(ROOT / "reports" / "v17_7_4_realbench_vs_dualfront_arm_diff_receipt.json", realbench_vs_dualfront_arm_diff_receipt(config))
    write_json(
        ROOT / "reports" / "v17_7_4_oracle_autopsy_table_receipt.json",
        runtime_required_receipt(
            "kt.v17_7_4.oracle_autopsy_table_receipt.prep.v1",
            "oracle_autopsy_table.jsonl",
            "Runtime must compare base, lobe/adaptor arms, router choice, KT-hat choice, and oracle shadow row by row.",
        ),
    )
    for name, schema, purpose in [
        ("v17_7_4_scar_delta_registry.json", "kt.v17_7_4.scar_delta_registry.prep.v1", "Compile row-level failures into scar/delta repair fuel."),
        ("v17_7_4_recursive_learning_delta_manifest.json", "kt.v17_7_4.recursive_learning_delta_manifest.prep.v1", "Bind scars to future repair deltas without authorizing training."),
        ("v17_7_4_academy_repair_plan.json", "kt.v17_7_4.academy_repair_plan.prep.v1", "Classify repair ownership before Academy/training."),
        ("v17_7_4_lobe_tournament_reentry_plan.json", "kt.v17_7_4.lobe_tournament_reentry_plan.prep.v1", "Prepare tournament/tie/merge reentry gates."),
        ("v17_7_4_tie_merge_child_lobe_plan.json", "kt.v17_7_4.tie_merge_child_lobe_plan.prep.v1", "Prevent child-lobe replacement without lineage/no-regression/tournament receipts."),
        ("v17_7_4_kt_hat_mount_comparison_plan.json", "kt.v17_7_4.kt_hat_mount_comparison_plan.prep.v1", "Distinguish base, trained substrate, router, KT-hat, and oracle costs."),
        ("v17_7_4_gsm8k_regression_autopsy.json", "kt.v17_7_4.gsm8k_regression_autopsy.prep.v1", "Explain GSM8K regression from prior 11/20 math_act to current failed DualFront math arms."),
        ("v17_7_4_parser_failure_repair_plan.json", "kt.v17_7_4.parser_failure_repair_plan.prep.v1", "Fail closed if parser/finalizer failures exceed threshold."),
    ]:
        write_json(ROOT / "reports" / name, runtime_required_receipt(schema, name, purpose))


def build_packet(config: dict[str, Any]) -> tuple[Path, str]:
    packet = ROOT / "packets" / PACKET_NAME
    packet.parent.mkdir(parents=True, exist_ok=True)
    run_manifest = authority(
        schema_id="kt.v17_7_4.oracle_academy_packet_manifest.v1",
        status="READY_FOR_ORACLE_AUTOPSY_ACADEMY_REENTRY_TRUEGEN",
        run_mode="RUN_KTV1774_ORACLE_ACADEMY_REENTRY_50",
        measurement_mode="ORACLE_AUTOPSY_ACADEMY_REENTRY",
        default_requested_rows=50,
        known_good_reproduction_required=True,
        oracle_autopsy_table_required=True,
        scar_delta_registry_required=True,
        academy_repair_plan_required=True,
        tournament_reentry_plan_required=True,
        kt_hat_mount_comparison_required=True,
        compact_answer_contract=True,
        reasoning_preserving_compact=True,
        hf_vault_source_of_truth=True,
        assessment_only_return_required=True,
        no_training=True,
        no_promotion=True,
        no_v18=True,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
        target_outcome=OUTCOME,
        next_lawful_move="RUN_KNOWN_GOOD_REPRO_AND_SCAR_REPAIR_NEXT",
    )
    members = {
        "README.md": (
            "# KTV1774 Oracle Academy Reentry V1\n\n"
            "Restores the KT organism loop after DualFront failed to preserve the known-good math_act path. "
            "This packet reproduces the prior known-good lobe path, builds oracle autopsy rows, compiles scar/delta "
            "repair fuel, creates Academy and tournament reentry plans, and compares KT-hat mounted-system costs. "
            "It does not train, promote, authorize V18, claim router superiority, claim G2 recovery, or expand claim ceiling.\n"
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
        f"""# V17.7.4 Oracle Academy Reentry One Cell

Packet: `packets/{PACKET_NAME}`

Kaggle dataset name: `{KAGGLE_DATASET_NAME}`

SHA256: `{packet_sha}`

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "RUN_KTV1774_ORACLE_ACADEMY_REENTRY_50"
os.environ["KT_TRUEGEN_MEASUREMENT_MODE"] = "ORACLE_AUTOPSY_ACADEMY_REENTRY"
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
work = Path("/kaggle/working/ktv1774_oracle_academy_packet")
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
    config = oracle_academy_config()
    write_prep_reports(config)
    packet, packet_sha = build_packet(config)
    runbook = write_runbook(packet_sha)
    summary_path = ROOT / "reports" / "v17_7_4_oracle_academy_reentry_builder_summary.json"
    summary = authority(
        schema_id="kt.v17_7_4.oracle_academy_reentry_builder_summary.v1",
        status="PASS",
        current_head=git(["rev-parse", "HEAD"]),
        current_branch=git(["branch", "--show-current"]),
        outcome=OUTCOME,
        next_lawful_move=NEXT_LAWFUL_MOVE,
        packet_path=packet.relative_to(ROOT).as_posix(),
        packet_sha256=packet_sha,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
        one_cell_runbook=runbook.relative_to(ROOT).as_posix(),
        known_good_reproduction_status="RUNTIME_REQUIRED",
        oracle_autopsy_status="RUNTIME_REQUIRED",
        scar_delta_compiler_status="RUNTIME_REQUIRED",
        academy_repair_plan_status="RUNTIME_REQUIRED",
        tournament_reentry_status="RUNTIME_REQUIRED",
        kt_hat_mount_comparison_status="RUNTIME_REQUIRED",
        blockers=[],
    )
    write_json(summary_path, summary)
    write_json(
        ROOT / "registry" / "artifact_authority_registry_v17_7_4_oracle_academy_delta_receipt.json",
        authority(
            schema_id="kt.artifact_authority_registry.delta_receipt.v17_7_4_oracle_academy.v1",
            status="PASS",
            current_head=summary["current_head"],
            artifacts_added=[
                {"path": packet.relative_to(ROOT).as_posix(), "role": "oracle_academy_kaggle_packet", "sha256": packet_sha, "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY", "claim_expansion": False},
                {"path": runbook.relative_to(ROOT).as_posix(), "role": "oracle_academy_one_cell_runbook", "sha256": sha256_file(runbook), "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY", "claim_expansion": False},
                {"path": summary_path.relative_to(ROOT).as_posix(), "role": "oracle_academy_builder_summary", "sha256": sha256_file(summary_path), "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY", "claim_expansion": False},
            ],
            outcome=OUTCOME,
            next_lawful_move=NEXT_LAWFUL_MOVE,
            no_commercial_claim=True,
            no_external_validation_claim=True,
            no_router_superiority_claim=True,
            no_multi_lobe_superiority_claim=True,
            no_g2_recovered_claim=True,
        ),
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
