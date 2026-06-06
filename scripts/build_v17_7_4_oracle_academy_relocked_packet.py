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


PACKET_NAME = "ktv1774_oracle_academy_relocked_v1.zip"
KAGGLE_DATASET_NAME = "ktv1774-oracle-relocked-v1"
RUNBOOK = "V17_7_4_ORACLE_ACADEMY_RELOCKED_ONE_CELL.md"
RUN_MODE = "RUN_KTV1774_ORACLE_ACADEMY_RELOCKED_50"
OUTCOME = "KT_KNOWN_GOOD_REPRODUCED__ORACLE_ACADEMY_RELOCK_READY__SCAR_DELTA_REPAIR_AUTHORITY_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = RUN_MODE
PRIOR_PROMPT_MANIFEST = ROOT / "admission" / "v17_7_4_prior_realbench_math_act_prompt_manifest.jsonl"


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
        prompt_overlay_authority="ORACLE_ACADEMY_RELOCK_PROMPT_OVERLAY_CANDIDATE_ONLY",
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


def relocked_config() -> dict[str, Any]:
    base_config = read_json(ROOT / "configs" / "v17_7_4" / "arm_model_config.json")
    arms = arm_by_id(base_config)
    math_act = arms["math_act_adapter_global"]
    route_regret = arms["route_regret_policy_adapter_global"]
    required = [
        "A0_base_raw",
        core.REPROLOCK_ARM_ID,
        "A2_true_known_good_math_act_finalizer_only",
        "A3_true_known_good_math_act_reasoning_preserving_compact",
        "A4_kt_hat_risk_gated_after_reprolock",
        "A5_specialist_admission_after_reprolock",
        "A7_oracle_shadow",
    ]
    config = dict(base_config)
    config.update(
        schema_id="kt.v17_7_4.arm_model_config.oracle_academy_relocked.v1",
        config_profile="REAL_ARM_ORACLE_ACADEMY_RELOCKED",
        measurement_mode=core.ORACLE_ACADEMY_RELOCKED_MODE,
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
                "A2_true_known_good_math_act_finalizer_only",
                "math_act",
                "POST_FINALIZER_ONLY",
                int(math_act["max_new_tokens"]),
                score_visible=True,
                reproduction_mode=core.TRUE_KNOWN_GOOD_BYTE_REPRO,
            ),
            adapter_arm(
                math_act,
                "A3_true_known_good_math_act_reasoning_preserving_compact",
                "math_act_reasoning_preserving_compact",
                "NUMERIC_BOUNDED_SCRATCH_THEN_FINAL",
                64,
                score_visible=True,
            ),
            prompt_arm("A4_kt_hat_risk_gated_after_reprolock", "kt_hat_compact_risk_gated", "SHORT_ANSWER_FINAL_ONLY", 32),
            adapter_arm(
                route_regret,
                "A5_specialist_admission_after_reprolock",
                "specialist_admission_controller",
                "EVIDENCE_GROUNDED_BRIEF_THEN_FINAL",
                64,
                score_visible=True,
            ),
            prompt_arm("A7_oracle_shadow", "oracle_shadow_not_runtime", "EVIDENCE_GROUNDED_BRIEF_THEN_FINAL", 64),
        ],
    )
    return config


def resolve_collection_path(argv: list[str]) -> Path:
    if len(argv) > 1:
        return Path(argv[1])
    if os.environ.get("KT_REPROLOCK_OPERATOR_COLLECTION"):
        return Path(os.environ["KT_REPROLOCK_OPERATOR_COLLECTION"])
    default = Path.home() / "Downloads" / "KTV1774_ORACLE_REPROLOCK_OPERATOR_COLLECTION.zip"
    return default


def read_collection_json(collection: Path, member: str) -> dict[str, Any]:
    with zipfile.ZipFile(collection) as archive:
        return json.loads(archive.read(member).decode("utf-8-sig"))


def bind_reprolock_success(collection: Path) -> dict[str, Any]:
    summary = read_collection_json(collection, "ktv1774_truegen_outputs/final_summary.json")
    known = read_collection_json(collection, "ktv1774_truegen_outputs/known_good_lobe_reproduction_receipt.json")
    stage = read_collection_json(collection, "ktv1774_truegen_outputs/v17_7_4_reproduction_stage_ladder_receipt.json")
    ope = read_collection_json(collection, "ktv1774_truegen_outputs/v17_7_4_ope_authority_decision_receipt.json")
    token_eff = read_collection_json(collection, "ktv1774_truegen_outputs/truegen_token_efficiency_matrix.json")
    accounting = read_collection_json(collection, "ktv1774_truegen_outputs/token_accounting_ledger.json")
    parser = read_collection_json(collection, "ktv1774_truegen_outputs/truegen_parser_vs_generation_error_matrix.json")
    answer_format = read_collection_json(collection, "ktv1774_truegen_outputs/truegen_answer_format_drift_receipt.json")
    scorecards = {
        "token_efficiency": token_eff,
        "token_accounting_ledger": accounting,
        "parser_error": parser,
        "answer_format": answer_format,
    }
    stage_update = core.post_runtime_reproduction_stage_ladder_receipt(known, int(known.get("observed_total", 0)))
    ope_update = core.ope_authority_after_reprolock_receipt(known)
    parser_authority = core.parser_finalizer_repair_authority_receipt(scorecards)
    answer_plan = core.answer_format_drift_repair_plan(scorecards)
    compression_gap = core.post_reprolock_compression_gap_receipt(scorecards)
    binding = authority(
        schema_id="kt.v17_7_4.reprolock_success_binding_receipt.v1",
        status="PASS" if known.get("status") == "PASS" and summary.get("status") == "PASS" else "BLOCKED",
        source_filename=collection.name,
        source_sha256=sha256_file(collection),
        source_run_id=summary.get("run_id"),
        public_head="4361013b30a253cff567d1b47267d79e0aa38691",
        repo_packet_sha256="8fc2e546cc75ef40c75888c0487effeb55681f9ef86680da0788c19f390a1749",
        run_mode="RUN_KTV1774_ORACLE_ACADEMY_REPROLOCK_50",
        prompt_hashes_matched=stage.get("prompt_hash_match_count"),
        rendered_prompt_hashes_matched=stage.get("rendered_prompt_hash_match_count"),
        tokenized_input_hashes_matched=stage.get("tokenized_input_match_count"),
        observed_correct=known.get("observed_correct"),
        observed_total=known.get("observed_total"),
        observed_gsm8k_correct=known.get("observed_gsm8k_correct"),
        observed_gsm8k_total=known.get("observed_gsm8k_total"),
        outcome=known.get("outcome"),
        old_ope_max_authority=ope.get("max_authority"),
        new_ope_max_authority=ope_update.get("max_authority"),
        training_authorized=False,
        promotion_authorized=False,
        claim_ceiling_preserved=True,
    )
    write_json(ROOT / "reports" / "v17_7_4_reprolock_success_binding_receipt.json", binding)
    write_json(ROOT / "reports" / "v17_7_4_reproduction_stage_ladder_receipt.json", stage_update)
    write_json(ROOT / "reports" / "v17_7_4_ope_authority_decision_receipt.json", ope_update)
    write_json(ROOT / "reports" / "v17_7_4_parser_finalizer_repair_authority_receipt.json", parser_authority)
    write_json(ROOT / "reports" / "v17_7_4_answer_format_drift_repair_plan.json", answer_plan)
    write_json(ROOT / "reports" / "v17_7_4_post_reprolock_compression_gap_receipt.json", compression_gap)
    return binding


def runtime_required_receipt(schema_id: str, artifact: str, purpose: str) -> dict[str, Any]:
    return authority(
        schema_id=schema_id,
        status="RUNTIME_MEASUREMENT_REQUIRED",
        artifact=artifact,
        purpose=purpose,
        measured_runtime_evidence_present=False,
        promotion_eligible=False,
        requires_followup_measurement=True,
        claim_ceiling_preserved=True,
    )


def write_prep_reports(config: dict[str, Any], success_binding: dict[str, Any]) -> None:
    for name, schema, purpose in [
        ("v17_7_4_oracle_autopsy_table_relocked.jsonl", "kt.v17_7_4.oracle_autopsy_table_relocked.prep.v1", "Runtime must compare relocked base, stable control, finalizer, compact, KT-hat, specialist admission, and oracle-shadow arms row by row."),
        ("v17_7_4_scar_delta_registry_relocked.json", "kt.v17_7_4.scar_delta_registry_relocked.prep.v1", "Runtime must rebuild scar/delta ownership from the stable byte-repro control."),
        ("v17_7_4_recursive_learning_delta_manifest_relocked.json", "kt.v17_7_4.recursive_learning_delta_manifest_relocked.prep.v1", "Runtime must bind relocked scars to future repair deltas without authorizing training."),
        ("v17_7_4_academy_repair_eligibility_matrix.json", "kt.v17_7_4.academy_repair_eligibility_matrix.prep.v1", "Runtime must classify Academy eligibility by owner; parser/finalizer defects are not lobe-owned."),
        ("v17_7_4_tournament_reentry_after_reprolock_plan.json", "kt.v17_7_4.tournament_reentry_after_reprolock_plan.prep.v1", "Runtime must prepare tournament reentry without promotion authority."),
    ]:
        write_json(ROOT / "reports" / name, runtime_required_receipt(schema, name, purpose))
    write_json(
        ROOT / "reports" / "v17_7_4_oracle_academy_relocked_config_receipt.json",
        authority(
            schema_id="kt.v17_7_4.oracle_academy_relocked_config_receipt.v1",
            status="PASS" if core.validate_arm_model_config(config) == [] and success_binding.get("status") == "PASS" else "BLOCKED",
            enabled_arms=[arm["arm_id"] for arm in config["arms"] if arm.get("enabled") is True],
            stable_control_arm=core.REPROLOCK_ARM_ID,
            measurement_mode=config["measurement_mode"],
            no_training=True,
            no_promotion=True,
            no_v18=True,
            claim_ceiling_preserved=True,
        ),
    )


def build_packet(config: dict[str, Any]) -> tuple[Path, str]:
    packet = ROOT / "packets" / PACKET_NAME
    packet.parent.mkdir(parents=True, exist_ok=True)
    run_manifest = authority(
        schema_id="kt.v17_7_4.oracle_academy_relocked_packet_manifest.v1",
        status="READY_FOR_ORACLE_ACADEMY_RELOCKED_TRUEGEN",
        run_mode=RUN_MODE,
        measurement_mode=core.ORACLE_ACADEMY_RELOCKED_MODE,
        default_requested_rows=50,
        stable_control_arm=core.REPROLOCK_ARM_ID,
        known_good_reproduction_required=True,
        relocked_oracle_autopsy_required=True,
        relocked_scar_delta_required=True,
        parser_finalizer_repair_authority_required=True,
        post_reprolock_compression_gap_required=True,
        no_training=True,
        no_promotion=True,
        no_v18=True,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
        target_outcome=OUTCOME,
        next_lawful_move=NEXT_LAWFUL_MOVE,
    )
    members = {
        "README.md": (
            "# KTV1774 Oracle Academy Relocked V1\n\n"
            "Uses the ReproLock-restored math_act control as the stable known-good arm, then relocks "
            "Oracle/Academy scar-delta ownership around it. This packet tests intelligence preservation "
            "and compression repair surfaces without training, promotion, V18 authority, router-superiority "
            "claims, G2 recovery claims, commercial claims, or external-validation claims.\n"
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
        f"""# V17.7.4 Oracle Academy Relocked One Cell

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
os.environ["KT_TRUEGEN_MEASUREMENT_MODE"] = "{core.ORACLE_ACADEMY_RELOCKED_MODE}"
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
work = Path("/kaggle/working/ktv1774_oracle_relocked_packet")
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
        raise FileNotFoundError(f"ReproLock operator collection not found: {collection}")
    success_binding = bind_reprolock_success(collection)
    if success_binding.get("status") != "PASS":
        raise RuntimeError("KT_BLOCKED__REPROLOCK_SUCCESS_BINDING_FAILED")
    config = relocked_config()
    write_prep_reports(config, success_binding)
    packet, packet_sha = build_packet(config)
    runbook = write_runbook(packet_sha)
    summary_path = ROOT / "reports" / "v17_7_4_oracle_academy_relocked_builder_summary.json"
    summary = authority(
        schema_id="kt.v17_7_4.oracle_academy_relocked_builder_summary.v1",
        status="PASS",
        current_head=git(["rev-parse", "HEAD"]),
        current_branch=git(["branch", "--show-current"]),
        outcome=OUTCOME,
        next_lawful_move=NEXT_LAWFUL_MOVE,
        packet_path=packet.relative_to(ROOT).as_posix(),
        packet_sha256=packet_sha,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
        one_cell_runbook=runbook.relative_to(ROOT).as_posix(),
        reprolock_success_binding_status=success_binding.get("status"),
        stage_ladder_update_status="PASS",
        ope_authority_update_status="PASS_CONTRACT_BOUND",
        oracle_academy_relock_status="RUNTIME_REQUIRED",
        scar_delta_relock_status="RUNTIME_REQUIRED",
        parser_finalizer_repair_authority_status="BOUND_FROM_REPROLOCK_MEASUREMENT",
        post_reprolock_compression_gap_status="BOUND_BLOCKED_NOT_RECOVERED",
        blockers=[],
        claim_ceiling_status="PRESERVED",
    )
    write_json(summary_path, summary)
    write_json(
        ROOT / "registry" / "artifact_authority_registry_v17_7_4_oracle_relocked_delta_receipt.json",
        authority(
            schema_id="kt.artifact_authority_registry.delta_receipt.v17_7_4_oracle_relocked.v1",
            status="PASS",
            current_head=summary["current_head"],
            artifacts_added=[
                {"path": packet.relative_to(ROOT).as_posix(), "role": "oracle_academy_relocked_kaggle_packet", "sha256": packet_sha, "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY", "claim_expansion": False},
                {"path": runbook.relative_to(ROOT).as_posix(), "role": "oracle_academy_relocked_one_cell_runbook", "sha256": sha256_file(runbook), "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY", "claim_expansion": False},
                {"path": summary_path.relative_to(ROOT).as_posix(), "role": "oracle_academy_relocked_builder_summary", "sha256": sha256_file(summary_path), "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY", "claim_expansion": False},
                {"path": "reports/v17_7_4_reprolock_success_binding_receipt.json", "role": "measured_reprolock_success_binding", "sha256": sha256_file(ROOT / "reports" / "v17_7_4_reprolock_success_binding_receipt.json"), "authority_state": "MEASURED_REPROLOCK_CONTROL_ONLY", "claim_expansion": False},
            ],
            outcome=OUTCOME,
            next_lawful_move=NEXT_LAWFUL_MOVE,
            no_training=True,
            no_promotion=True,
            no_v18=True,
            no_commercial_claim=True,
            no_external_validation_claim=True,
            no_router_superiority_claim=True,
            no_g2_recovered_claim=True,
        ),
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
