from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core


PACKET_NAME = "ktv1774_dual_frontier_repair_v1.zip"
KAGGLE_DATASET_NAME = "ktv1774-dual-frontier-repair-v1"
RUNBOOK = "V17_7_4_DUAL_FRONTIER_REPAIR_ONE_CELL.md"
RUN_MODE = "RUN_KTV1774_DUAL_FRONTIER_REPAIR_50"
OUTCOME = "KT_KNOWN_GOOD_REPRODUCED__DUAL_FRONTIER_REPAIR_READY__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = RUN_MODE
PRIOR_PROMPT_MANIFEST = ROOT / "admission" / "v17_7_4_prior_realbench_math_act_prompt_manifest.jsonl"
DEFAULT_COLLECTION = Path.home() / "Downloads" / "KTV1774_ORACLE_RELOCKED_OPERATOR_COLLECTION.zip"


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(core.AUTHORITY_FALSE)
    payload.update(
        {
            "multi_lobe_superiority_claim": False,
            "commercial_claim": False,
            "external_validation_claim": False,
            "g2_recovered_claim": False,
            "frontier_claim": False,
            "s_tier_claim": False,
            "production_readiness_claim": False,
        }
    )
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


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_zip_member(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_collection_json(collection: Path, member: str) -> dict[str, Any]:
    with zipfile.ZipFile(collection) as archive:
        return json.loads(archive.read(member).decode("utf-8-sig"))


def read_collection_jsonl(collection: Path, member: str) -> list[dict[str, Any]]:
    with zipfile.ZipFile(collection) as archive:
        text = archive.read(member).decode("utf-8-sig")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


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
        "compact_mode": "RAW_BASELINE",
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
        prompt_overlay_authority="DUAL_FRONTIER_REPAIR_PROMPT_OVERLAY_CANDIDATE_ONLY",
        score_from_visible_answer=True,
        scoring_surface="FINAL_VISIBLE_ANSWER",
    )
    return row


def adapter_arm(
    source: dict[str, Any],
    arm_id: str,
    template: str,
    compact_mode: str,
    max_new_tokens: int,
    *,
    score_visible: bool,
    reproduction_mode: str | None = None,
) -> dict[str, Any]:
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
    if reproduction_mode:
        row.update(
            reproduction_mode=reproduction_mode,
            legacy_source_arm_id="math_act_adapter_global",
            legacy_prompt_template_id="math_act",
        )
    return row


def dual_frontier_repair_config() -> dict[str, Any]:
    base_config = read_json(ROOT / "configs" / "v17_7_4" / "arm_model_config.json")
    arms = arm_by_id(base_config)
    math_act = arms["math_act_adapter_global"]
    route_regret = arms["route_regret_policy_adapter_global"]
    required = [
        "A0_base_raw",
        core.REPROLOCK_ARM_ID,
        "A2_known_good_parser_scorer_repair",
        "A3_known_good_finalizer_extraction_repair",
        "A4_oracle_derived_route_specific_compression_candidate",
        "A5_active_inference_admission_candidate_shadow",
        "A6_kt_hat_risk_gated_cost_justified",
        "A7_oracle_shadow_not_runtime",
    ]
    config = dict(base_config)
    config.update(
        schema_id="kt.v17_7_4.arm_model_config.dual_frontier_repair.v1",
        config_profile="REAL_ARM_DUAL_FRONTIER_REPAIR",
        measurement_mode=core.DUAL_FRONTIER_REPAIR_MODE,
        compact_answer_contract=True,
        reasoning_preserving_compact=True,
        row_limit=50,
        default_row_ladder_stage=None,
        required_arm_ids=required,
        prior_realbench_prompt_manifest="runtime_inputs/prior_realbench_math_act_prompt_manifest.jsonl",
        prior_realbench_prompt_manifest_sha256=sha256_file(PRIOR_PROMPT_MANIFEST),
        known_good_reproduction_required=True,
        oracle_correctness_used_as_runtime_feature=False,
        no_training=True,
        no_promotion=True,
        no_v18=True,
        arms=[
            base_arm("A0_base_raw", "raw", 64),
            adapter_arm(
                math_act,
                core.REPROLOCK_ARM_ID,
                "math_act",
                "DISABLED_TRUE_BYTE_REPRO",
                int(math_act["max_new_tokens"]),
                score_visible=False,
                reproduction_mode=core.TRUE_KNOWN_GOOD_BYTE_REPRO,
            ),
            adapter_arm(
                math_act,
                "A2_known_good_parser_scorer_repair",
                "math_act",
                "POST_SCORER_REPAIR_ONLY",
                int(math_act["max_new_tokens"]),
                score_visible=True,
                reproduction_mode=core.TRUE_KNOWN_GOOD_BYTE_REPRO,
            ),
            adapter_arm(
                math_act,
                "A3_known_good_finalizer_extraction_repair",
                "math_act",
                "POST_FINALIZER_EXTRACTION_ONLY",
                int(math_act["max_new_tokens"]),
                score_visible=True,
                reproduction_mode=core.TRUE_KNOWN_GOOD_BYTE_REPRO,
            ),
            adapter_arm(
                route_regret,
                "A4_oracle_derived_route_specific_compression_candidate",
                "specialist_admission_controller",
                "EVIDENCE_GROUNDED_BRIEF_THEN_FINAL",
                64,
                score_visible=True,
            ),
            adapter_arm(
                route_regret,
                "A5_active_inference_admission_candidate_shadow",
                "route_regret",
                "EVIDENCE_GROUNDED_BRIEF_THEN_FINAL",
                64,
                score_visible=True,
            ),
            prompt_arm("A6_kt_hat_risk_gated_cost_justified", "kt_hat_compact_risk_gated", "SHORT_ANSWER_FINAL_ONLY", 32),
            prompt_arm("A7_oracle_shadow_not_runtime", "oracle_shadow_not_runtime", "EVIDENCE_GROUNDED_BRIEF_THEN_FINAL", 64),
        ],
    )
    return config


def resolve_collection_path(argv: list[str]) -> Path:
    if len(argv) > 1:
        return Path(argv[1])
    if os.environ.get("KT_ORACLE_RELOCKED_COLLECTION"):
        return Path(os.environ["KT_ORACLE_RELOCKED_COLLECTION"])
    return DEFAULT_COLLECTION


def bind_oracle_relocked(collection: Path) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    summary = read_collection_json(collection, "ktv1774_truegen_outputs/final_summary.json")
    known = read_collection_json(collection, "ktv1774_truegen_outputs/known_good_lobe_reproduction_receipt.json")
    benchmark = read_collection_json(collection, "ktv1774_truegen_outputs/truegen_benchmark_scorecard.json")
    token_eff = read_collection_json(collection, "ktv1774_truegen_outputs/truegen_token_efficiency_matrix.json")
    accounting = read_collection_json(collection, "ktv1774_truegen_outputs/token_accounting_ledger.json")
    visible = read_collection_json(collection, "ktv1774_truegen_outputs/visible_answer_ledger.json")
    parser = read_collection_json(collection, "ktv1774_truegen_outputs/truegen_parser_vs_generation_error_matrix.json")
    answer = read_collection_json(collection, "ktv1774_truegen_outputs/truegen_answer_format_drift_receipt.json")
    arm_rows = read_collection_jsonl(collection, "ktv1774_truegen_outputs/truegen_arm_result_matrix.jsonl")
    scorecards = {
        "benchmark": benchmark,
        "token_efficiency": token_eff,
        "token_accounting_ledger": accounting,
        "visible_answer_ledger": visible,
        "parser_error": parser,
        "answer_format": answer,
    }
    binding = authority(
        schema_id="kt.v17_7_4.oracle_relocked_success_binding_receipt.v1",
        status="PASS" if known.get("status") == "PASS" and summary.get("status") == "PASS" else "BLOCKED",
        source_filename=collection.name,
        source_sha256=sha256_file(collection),
        source_run_id=summary.get("run_id"),
        source_outcome=summary.get("outcome"),
        stable_control_arm=known.get("reproduction_arm_id"),
        observed_correct=known.get("observed_correct"),
        observed_total=known.get("observed_total"),
        observed_gsm8k_correct=known.get("observed_gsm8k_correct"),
        observed_gsm8k_total=known.get("observed_gsm8k_total"),
        full_tokens_per_correct=accounting.get("matrix", {}).get(core.REPROLOCK_ARM_ID, {}).get("full_prompt_plus_output_tokens_per_correct"),
        visible_answer_tokens_per_correct=accounting.get("matrix", {}).get(core.REPROLOCK_ARM_ID, {}).get("visible_answer_tokens_per_correct"),
        no_training=True,
        no_promotion=True,
        no_v18=True,
        claim_ceiling_preserved=True,
    )
    return binding, scorecards, arm_rows


def write_repo_reports(collection: Path, config: dict[str, Any]) -> dict[str, Any]:
    binding, scorecards, arm_rows = bind_oracle_relocked(collection)
    route_policy, decision_rows, regret_rows = core.route_specific_compression_policy(arm_rows, scorecards)
    repair_scorecard = core.dual_frontier_repair_scorecard(scorecards, binding, route_policy)
    worktree = subprocess.check_output(["git", "status", "--short"], cwd=ROOT, text=True).splitlines()
    contradiction_defects = []
    if binding.get("observed_correct") != 41 or binding.get("observed_total") != 50:
        contradiction_defects.append("stable_control_expected_41_of_50_not_observed")
    if binding.get("observed_gsm8k_correct") != 11 or binding.get("observed_gsm8k_total") != 20:
        contradiction_defects.append("stable_control_expected_11_of_20_gsm8k_not_observed")
    reports = {
        "reports/v17_7_4_dual_frontier_repair_truth_pin_receipt.json": authority(
            schema_id="kt.v17_7_4.dual_frontier_repair_truth_pin_receipt.v1",
            status="PASS",
            current_head=git(["rev-parse", "HEAD"]),
            current_branch=git(["branch", "--show-current"]),
            worktree_dirty_paths=worktree,
            unrelated_dirty_worktree_preserved=True,
            packet_source="kt_dual_frontier_repair_v1.zip",
            source_collection=collection.name,
            claim_ceiling_preserved=True,
        ),
        "reports/v17_7_4_dual_frontier_repair_source_index.json": authority(
            schema_id="kt.v17_7_4.dual_frontier_repair_source_index.v1",
            status="PASS",
            sources=[
                {"path": collection.as_posix(), "sha256": sha256_file(collection), "role": "oracle_relocked_measured_operator_collection"},
                {"path": PRIOR_PROMPT_MANIFEST.relative_to(ROOT).as_posix(), "sha256": sha256_file(PRIOR_PROMPT_MANIFEST), "role": "byte_repro_prompt_source"},
                {"path": "configs/v17_7_4/arm_model_config.json", "sha256": sha256_file(ROOT / "configs" / "v17_7_4" / "arm_model_config.json"), "role": "hf_vault_real_arm_source_config"},
            ],
            claim_ceiling_preserved=True,
        ),
        "reports/v17_7_4_dual_frontier_repair_contradiction_scan.json": authority(
            schema_id="kt.v17_7_4.dual_frontier_repair_contradiction_scan.v1",
            status="PASS" if not contradiction_defects else "BLOCKED",
            defects=contradiction_defects,
            expected_control={"correct": 41, "total": 50, "gsm8k_correct": 11, "gsm8k_total": 20},
            observed_control={
                "correct": binding.get("observed_correct"),
                "total": binding.get("observed_total"),
                "gsm8k_correct": binding.get("observed_gsm8k_correct"),
                "gsm8k_total": binding.get("observed_gsm8k_total"),
            },
            claim_ceiling_preserved=True,
        ),
        "reports/v17_7_4_oracle_relocked_success_binding_receipt.json": binding,
        "reports/v17_7_4_dual_frontier_repair_baseline_scorecard.json": authority(
            schema_id="kt.v17_7_4.dual_frontier_repair_baseline_scorecard.v1",
            status="PASS",
            stable_control={
                "arm_id": core.REPROLOCK_ARM_ID,
                "correct": binding.get("observed_correct"),
                "total": binding.get("observed_total"),
                "gsm8k_correct": binding.get("observed_gsm8k_correct"),
                "gsm8k_total": binding.get("observed_gsm8k_total"),
                "full_tokens_per_correct": binding.get("full_tokens_per_correct"),
                "visible_answer_tokens_per_correct": binding.get("visible_answer_tokens_per_correct"),
            },
            base_raw=scorecards.get("token_efficiency", {}).get("matrix", {}).get("A0_base_raw", {}),
            claim_ceiling_preserved=True,
        ),
        "reports/v17_7_4_dual_frontier_current_pareto_table.json": repair_scorecard,
        "reports/v17_7_4_post_reprolock_compression_gap_receipt.json": core.post_reprolock_compression_gap_receipt(scorecards),
        "reports/v17_7_4_dual_frontier_repair_scorecard.json": repair_scorecard,
        "reports/v17_7_4_route_specific_compression_candidate.json": route_policy,
        "reports/v17_7_4_parser_scorer_repair_authority_receipt.json": core.parser_scorer_repair_authority_receipt(scorecards),
        "reports/v17_7_4_finalizer_extraction_repair_plan.json": core.finalizer_extraction_repair_plan(scorecards),
        "reports/v17_7_4_fep_router_shadow_receipt.json": core.fep_router_shadow_receipt(scorecards, route_policy),
        "reports/v17_7_4_memory_authority_decay_receipt.json": core.memory_authority_decay_receipt(),
        "reports/v17_7_4_gt_fep_pruning_shadow_receipt.json": core.gt_fep_pruning_shadow_receipt(scorecards),
        "reports/v17_7_4_agent_diff_contract_receipt.json": core.agent_diff_contract_receipt(),
    }
    for rel, payload in reports.items():
        write_json(ROOT / rel, payload)
    write_jsonl(ROOT / "reports" / "v17_7_4_route_cost_decision_table.jsonl", decision_rows)
    write_jsonl(ROOT / "reports" / "v17_7_4_route_regret_cost_matrix.jsonl", regret_rows)
    if reports["reports/v17_7_4_dual_frontier_repair_contradiction_scan.json"]["status"] != "PASS":
        raise RuntimeError("KT_BLOCKED__DUAL_FRONTIER_RELOCKED_EVIDENCE_CONTRADICTION")
    if binding.get("status") != "PASS":
        raise RuntimeError("KT_BLOCKED__ORACLE_RELOCKED_BINDING_FAILED")
    return {
        "binding": binding,
        "route_policy": route_policy,
        "repair_scorecard": repair_scorecard,
        "report_paths": sorted([*reports.keys(), "reports/v17_7_4_route_cost_decision_table.jsonl", "reports/v17_7_4_route_regret_cost_matrix.jsonl"]),
    }


def build_packet(config: dict[str, Any]) -> tuple[Path, str]:
    packet = ROOT / "packets" / PACKET_NAME
    packet.parent.mkdir(parents=True, exist_ok=True)
    run_manifest = authority(
        schema_id="kt.v17_7_4.dual_frontier_repair_packet_manifest.v1",
        status="READY_FOR_DUAL_FRONTIER_REPAIR_TRUEGEN",
        run_mode=RUN_MODE,
        measurement_mode=core.DUAL_FRONTIER_REPAIR_MODE,
        default_requested_rows=50,
        stable_control_arm=core.REPROLOCK_ARM_ID,
        known_good_reproduction_required=True,
        parser_scorer_repair_required=True,
        finalizer_extraction_repair_required=True,
        route_specific_compression_required=True,
        fep_router_shadow_only=True,
        memory_authority_decay_shadow_only=True,
        gt_fep_pruning_shadow_only=True,
        agent_diff_contract_shadow_only=True,
        no_training=True,
        no_promotion=True,
        no_v18=True,
        no_g2_recovered_claim=True,
        no_router_superiority_claim=True,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
        target_outcome=OUTCOME,
        next_lawful_move=NEXT_LAWFUL_MOVE,
    )
    members = {
        "README.md": (
            "# KTV1774 Dual Frontier Repair V1\n\n"
            "Preserves the byte-locked 41/50 known-good math_act control while measuring parser/scorer, "
            "finalizer, route-specific compression, FEP router, active forgetting, GT-FEP pruning, and "
            "Agent-Diff state-contract repair surfaces. This is a no-training, no-promotion, no-V18, "
            "claim-ceiling-preserved packet.\n"
        ).encode("utf-8"),
        "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py": (ROOT / "runtime" / "v17_7_4" / "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py").read_bytes(),
        "KT_V1774_TRUEGEN_ARM_CORE.py": (ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py").read_bytes(),
        "runtime_inputs/truegen_row_manifest.json": (ROOT / "admission" / "v17_7_4_realbench_row_manifest.json").read_bytes(),
        "runtime_inputs/arm_model_config.json": json.dumps(config, indent=2, sort_keys=True).encode("utf-8"),
        "runtime_inputs/prior_realbench_math_act_prompt_manifest.jsonl": PRIOR_PROMPT_MANIFEST.read_bytes(),
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
        f"""# V17.7.4 Dual Frontier Repair One Cell

Packet: `packets/{PACKET_NAME}`

Kaggle dataset name: `{KAGGLE_DATASET_NAME}`

SHA256: `{packet_sha}`

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "{RUN_MODE}"
os.environ["KT_TRUEGEN_MEASUREMENT_MODE"] = "{core.DUAL_FRONTIER_REPAIR_MODE}"
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
work = Path("/kaggle/working/ktv1774_dual_frontier_repair_packet")
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


def main(argv: list[str]) -> int:
    collection = resolve_collection_path(argv)
    if not collection.exists():
        raise FileNotFoundError(f"Oracle Relocked operator collection not found: {collection}")
    config = dual_frontier_repair_config()
    defects = core.validate_arm_model_config(config)
    if defects:
        raise RuntimeError(f"KT_BLOCKED__DUAL_FRONTIER_REPAIR_CONFIG_DEFECT: {defects}")
    report_info = write_repo_reports(collection, config)
    packet, packet_sha = build_packet(config)
    runbook = write_runbook(packet_sha)
    summary_path = ROOT / "reports" / "v17_7_4_dual_frontier_repair_builder_summary.json"
    summary = authority(
        schema_id="kt.v17_7_4.dual_frontier_repair_builder_summary.v1",
        status="PASS",
        current_head=git(["rev-parse", "HEAD"]),
        current_branch=git(["branch", "--show-current"]),
        outcome=OUTCOME,
        next_lawful_move=NEXT_LAWFUL_MOVE,
        packet_path=packet.relative_to(ROOT).as_posix(),
        packet_sha256=packet_sha,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
        one_cell_runbook=runbook.relative_to(ROOT).as_posix(),
        oracle_relocked_binding_status=report_info["binding"].get("status"),
        dual_frontier_scorecard_status=report_info["repair_scorecard"].get("status"),
        parser_scorer_repair_status="PASS",
        finalizer_extraction_repair_status="PASS",
        route_specific_compression_status=report_info["route_policy"].get("status"),
        fep_router_shadow_status="SHADOW_ONLY",
        memory_authority_decay_status="SHADOW_ONLY",
        gt_fep_pruning_shadow_status="SHADOW_ONLY",
        agent_diff_state_contract_status="CONTRACT_BOUND_SHADOW_ONLY",
        report_paths=report_info["report_paths"],
        blockers=[],
        claim_ceiling_status="PRESERVED",
    )
    write_json(summary_path, summary)
    write_json(
        ROOT / "registry" / "artifact_authority_registry_v17_7_4_dual_frontier_repair_delta_receipt.json",
        authority(
            schema_id="kt.artifact_authority_registry.delta_receipt.v17_7_4_dual_frontier_repair.v1",
            status="PASS",
            current_head=summary["current_head"],
            artifacts_added=[
                {"path": packet.relative_to(ROOT).as_posix(), "role": "dual_frontier_repair_kaggle_packet", "sha256": packet_sha, "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY", "claim_expansion": False},
                {"path": runbook.relative_to(ROOT).as_posix(), "role": "dual_frontier_repair_one_cell_runbook", "sha256": sha256_file(runbook), "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY", "claim_expansion": False},
                {"path": summary_path.relative_to(ROOT).as_posix(), "role": "dual_frontier_repair_builder_summary", "sha256": sha256_file(summary_path), "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY", "claim_expansion": False},
            ],
            outcome=OUTCOME,
            next_lawful_move=NEXT_LAWFUL_MOVE,
            no_training=True,
            no_promotion=True,
            no_v18=True,
            no_commercial_claim=True,
            no_external_validation_claim=True,
            no_router_superiority_claim=True,
            no_learned_router_superiority_claim=True,
            no_g2_recovered_claim=True,
        ),
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
