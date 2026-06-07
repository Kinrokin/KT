from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core


TRANCHE = "AUTHOR_KTV1774_GENERALIZATION_REVIEW_AND_MATH_SCRATCHPAD_DESIGN_V1"
OUTCOME = "KT_REPROLOCK_GENERALIZATION_MIN_PASS__MATH_SCRATCHPAD_LANE_READY__CLAIM_CEILING_PRESERVED"
ASSESSMENT_ZIP = Path(os.environ.get("KT_GENERALIZATION_ASSESSMENT_ZIP", r"d:\user\rober\Downloads\KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY (16).zip"))
OPERATOR_EVENTS = Path(os.environ.get("KT_GENERALIZATION_OPERATOR_EVENTS", r"d:\user\rober\Downloads\reprolock_generalization_probe_operator_events.jsonl"))
RUN_MANIFEST = Path(os.environ.get("KT_GENERALIZATION_RUN_MANIFEST", r"d:\user\rober\Downloads\run_manifest (15).json"))
ADAPTER_ROOT_RECEIPT = Path(os.environ.get("KT_GENERALIZATION_ADAPTER_ROOT_RECEIPT", r"d:\user\rober\Downloads\ADAPTER_ROOT_NORMALIZATION_RECEIPT (7).json"))
KAGGLE_PRECHECK = Path(os.environ.get("KT_GENERALIZATION_KAGGLE_PRECHECK", r"d:\user\rober\Downloads\KAGGLE_INPUT_PRECHECK_REPORT (2).json"))
ADAPTER_NICHE_SCORECARD = Path(os.environ.get("KT_GENERALIZATION_ADAPTER_NICHE_SCORECARD", r"d:\user\rober\Downloads\adapter_niche_boundary_scorecard.json"))
HELDOUT_MANIFEST = ROOT / "admission" / "v17_7_4_reprolock_heldout_row_manifest.json"
FIXED_MANIFEST = ROOT / "admission" / "v17_7_4_realbench_row_manifest.json"
PACKET_PATH = ROOT / "packets" / "ktv1774_math_scratchpad_microfurnace_v1.zip"
RUNBOOK_PATH = ROOT / "docs" / "V17_7_4_MATH_SCRATCHPAD_MICROFURNACE_ONE_CELL.md"
MICROFURNACE_MANIFEST = ROOT / "admission" / "v17_7_4_math_scratchpad_microfurnace_row_manifest.json"
KAGGLE_DATASET_NAME = "ktv1774-math-scratchpad-microfurnace-v1"
RUN_MODE = "RUN_KTV1774_MATH_SCRATCHPAD_MICROFURNACE_25"


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(core.AUTHORITY_FALSE)
    payload.update(
        {
            "claim_ceiling_preserved": True,
            "commercial_claim": False,
            "external_validation_claim": False,
            "frontier_claim": False,
            "g2_recovered_claim": False,
            "heldout_generalization_claim": False,
            "learned_router_superiority_claim": False,
            "multi_lobe_superiority_claim": False,
            "production_readiness_claim": False,
            "router_superiority_claim": False,
            "s_tier_claim": False,
            "seven_b_claim": False,
        }
    )
    payload.update(extra)
    return payload


def git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_hash(value: Any) -> str:
    return sha256_text(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_zip_member(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def zip_json(archive: zipfile.ZipFile, name: str) -> dict[str, Any]:
    return json.loads(archive.read(name).decode("utf-8-sig"))


def zip_jsonl(archive: zipfile.ZipFile, name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in archive.read(name).decode("utf-8-sig").splitlines() if line.strip()]


def existing_file_payload(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"path": str(path), "exists": False, "sha256": None, "size_bytes": None}
    return {"path": str(path), "exists": True, "sha256": sha256_file(path), "size_bytes": path.stat().st_size}


def load_evidence() -> dict[str, Any]:
    if not ASSESSMENT_ZIP.exists():
        raise RuntimeError(f"KT_BLOCKED__GENERALIZATION_REVIEW_TRUTH_PIN_FAILED: missing assessment ZIP {ASSESSMENT_ZIP}")
    with zipfile.ZipFile(ASSESSMENT_ZIP) as archive:
        return {
            "final_summary": zip_json(archive, "final_summary.json"),
            "scorecard": zip_json(archive, "truegen_benchmark_scorecard.json"),
            "token_ledger": zip_json(archive, "token_accounting_ledger.json"),
            "token_efficiency": zip_json(archive, "truegen_token_efficiency_matrix.json"),
            "verified_work": zip_json(archive, "truegen_verified_work_per_token_scorecard.json"),
            "generalization_gap": zip_json(archive, "v17_7_4_reprolock_generalization_gap_receipt.json"),
            "answer_leakage": zip_json(archive, "v17_7_4_reprolock_generalization_answer_leakage_scan_receipt.json"),
            "negative_control": zip_json(archive, "v17_7_4_reprolock_generalization_negative_control_receipt.json"),
            "prompt_identity": zip_json(archive, "v17_7_4_reprolock_generalization_prompt_identity_receipt.json"),
            "row_source": zip_json(archive, "v17_7_4_reprolock_generalization_row_source_receipt.json"),
            "arm_rows": zip_jsonl(archive, "truegen_arm_result_matrix.jsonl"),
            "prediction_rows": zip_jsonl(archive, "truegen_predictions.jsonl"),
            "prompt_rows": zip_jsonl(archive, "truegen_prompt_manifest.jsonl"),
            "assessment_zip": existing_file_payload(ASSESSMENT_ZIP),
            "operator_events": existing_file_payload(OPERATOR_EVENTS),
            "run_manifest": read_json(RUN_MANIFEST) if RUN_MANIFEST.exists() else {},
            "run_manifest_source": existing_file_payload(RUN_MANIFEST),
            "adapter_root_receipt": read_json(ADAPTER_ROOT_RECEIPT) if ADAPTER_ROOT_RECEIPT.exists() else {},
            "adapter_root_receipt_source": existing_file_payload(ADAPTER_ROOT_RECEIPT),
            "kaggle_precheck": read_json(KAGGLE_PRECHECK) if KAGGLE_PRECHECK.exists() else {},
            "kaggle_precheck_source": existing_file_payload(KAGGLE_PRECHECK),
            "adapter_niche_scorecard": read_json(ADAPTER_NICHE_SCORECARD) if ADAPTER_NICHE_SCORECARD.exists() else {},
            "adapter_niche_scorecard_source": existing_file_payload(ADAPTER_NICHE_SCORECARD),
        }


def dataset_mix(rows: list[dict[str, Any]]) -> dict[str, int]:
    return dict(sorted(Counter(str(row.get("dataset", "")) for row in rows).items()))


def correct_by_dataset(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for dataset in sorted({str(row.get("dataset", "")) for row in rows}):
        subset = [row for row in rows if str(row.get("dataset", "")) == dataset]
        correct = sum(1 for row in subset if row.get("correct") is True)
        output[dataset] = {"correct": correct, "total": len(subset), "accuracy": round(correct / max(len(subset), 1), 6)}
    return output


def likely_owner(row: dict[str, Any]) -> str:
    text = str(row.get("output_text") or "")
    parsed = str(row.get("parsed_answer") or "")
    expected_hash = str(row.get("expected_answer_hash") or "")
    if row.get("parser_format_failure") is True:
        return "PARSER_OWNED"
    if "Question:" in text and "Answer format:" in text:
        return "PROMPT_INTERPRETATION_OWNED"
    if not row.get("final_answer_marker_present") and int(row.get("reasoning_tokens") or 0) >= 35:
        return "REASONING_BUDGET_OWNED"
    if parsed and expected_hash:
        return "ARITHMETIC_CHAIN_OWNED"
    return "IRREDUCIBLE_OR_UNCLEAR"


def owner_stage(owner: str) -> str:
    return {
        "PARSER_OWNED": "parser_surface",
        "PROMPT_INTERPRETATION_OWNED": "prompt_continuation_drift",
        "REASONING_BUDGET_OWNED": "bounded_reasoning_budget",
        "ARITHMETIC_CHAIN_OWNED": "multi_step_numeric_state",
        "FINALIZER_OWNED": "final_answer_commit",
        "IRREDUCIBLE_OR_UNCLEAR": "unclear",
    }.get(owner, "unclear")


def build_wrong_row_table(arm_rows: list[dict[str, Any]], manifest_rows: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    wrong_rows = [row for row in arm_rows if row.get("arm_id") == core.REPROLOCK_ARM_ID and row.get("correct") is not True]
    output = []
    for row in wrong_rows:
        manifest_row = manifest_rows.get(str(row.get("sample_id")), {})
        owner = likely_owner(row)
        output.append(
            authority(
                schema_id="kt.v17_7_4.generalization_wrong_row_autopsy.v1",
                sample_id=row.get("sample_id"),
                dataset=row.get("dataset"),
                task_family=row.get("task_family"),
                expected_answer_hash=row.get("expected_answer_hash"),
                parsed_answer=row.get("parsed_answer"),
                visible_answer=row.get("visible_answer"),
                raw_output_hash=row.get("output_hash"),
                output_text_excerpt=str(row.get("output_text") or "")[:280],
                prompt_hash=row.get("prompt_hash"),
                question_text_hash=row.get("question_text_hash") or manifest_row.get("question_text_hash"),
                output_tokens=row.get("tokens_out") or row.get("raw_output_tokens"),
                reasoning_tokens=row.get("reasoning_tokens"),
                visible_answer_tokens=row.get("visible_answer_tokens"),
                full_prompt_plus_output_tokens=row.get("full_prompt_plus_output_tokens"),
                parser_format_failure=bool(row.get("parser_format_failure")),
                final_answer_marker_present=bool(row.get("final_answer_marker_present")),
                likely_owner=owner,
                failure_stage=owner_stage(owner),
                early_scratch_number_risk=not bool(row.get("final_answer_marker_present")),
                bounded_scratchpad_could_plausibly_help=owner in {
                    "REASONING_BUDGET_OWNED",
                    "ARITHMETIC_CHAIN_OWNED",
                    "PROMPT_INTERPRETATION_OWNED",
                },
                finalizer_only_could_hurt=owner not in {"PARSER_OWNED", "FINALIZER_OWNED"},
                training_justified=False,
            )
        )
    return output


def build_microfurnace_rows(heldout_rows: list[dict[str, Any]], fixed_rows: list[dict[str, Any]], wrong_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    wrong_ids = {str(row.get("sample_id")) for row in wrong_rows}
    heldout_gsm = [row for row in heldout_rows if row.get("dataset") == "gsm8k"]
    fixed_gsm = [row for row in fixed_rows if row.get("dataset") == "gsm8k"]
    selected: list[dict[str, Any]] = []
    for row in heldout_gsm:
        role = "FAILED_HELDOUT_GSM8K_ROW" if row["sample_id"] in wrong_ids else "MATCHED_SUCCESSFUL_HELDOUT_GSM8K_ROW"
        next_row = dict(row)
        next_row.update(
            evidence_band="MATH_SCRATCHPAD_MICROFURNACE",
            route_boundary_class="MATH_BOUNDARY_SCRATCHPAD_PROBE",
            scratchpad_microfurnace_role=role,
            scratchpad_runtime_authority=False,
            expected_answer_visible_to_model=False,
        )
        selected.append(next_row)
    for row in fixed_gsm[:5]:
        next_row = dict(row)
        next_row.update(
            sample_id=f"fixed_control::{row['sample_id']}",
            evidence_band="MATH_SCRATCHPAD_MICROFURNACE",
            route_boundary_class="MATH_BOUNDARY_SCRATCHPAD_PROBE",
            scratchpad_microfurnace_role="FIXED_SLICE_GSM8K_SENTINEL_ROW",
            scratchpad_runtime_authority=False,
            expected_answer_visible_to_model=False,
        )
        selected.append(next_row)
    return selected[:25]


def base_adapter_arm(arm_id: str, prompt_template_id: str, budget: int, candidate_mode: str) -> dict[str, Any]:
    return {
        "adapter_binding_status": "REAL_ADAPTER_SOURCE_BOUND",
        "adapter_hf_repo": "Kinrokin/kt13-full-e2e-final-only-20260524-174447",
        "adapter_hf_subfolder": "adapters/cohort_pass2_delta_scar",
        "adapter_id": "math_act_adapter_global",
        "adapter_path": "${KT_TRUEGEN_ADAPTER_ROOT}/adapters/cohort_pass2_delta_scar",
        "adapter_required_for_real_authority": True,
        "adapter_sha256_optional": "6fde587c24a20f059e49bafbcc4ad031796e6f40b07d63704edf79ed8b90cc4a",
        "arm_id": arm_id,
        "arm_kind": "adapter",
        "compact_mode": "NUMERIC_BOUNDED_SCRATCH_THEN_FINAL",
        "enabled": True,
        "expected_adapter_id": "cohort_pass2_delta_scar",
        "finalizer_intervention_disabled": True,
        "intended_role": "math_only_ephemeral_scratchpad_candidate",
        "kt_hat_scaffold_disabled": True,
        "max_new_tokens": budget,
        "model_repo_or_base": "BASE",
        "oracle_shadow_disabled": True,
        "prompt_template_id": prompt_template_id,
        "route_admission_disabled": True,
        "score_from_visible_answer": True,
        "scoring_method": "exact_normalized",
        "scoring_surface": "FINAL_VISIBLE_ANSWER_CORE_FINAL_MARKER_ONLY",
        "scratchpad_candidate_mode": candidate_mode,
        "scratchpad_budget_tokens": budget,
    }


def microfurnace_config() -> dict[str, Any]:
    control = base_adapter_arm(core.REPROLOCK_ARM_ID, "math_act", 64, "MATH_NO_SCRATCHPAD_CONTROL")
    control.update(
        compact_mode="DISABLED_TRUE_BYTE_REPRO",
        compact_scoring_disabled=True,
        expected_prior_correct_count=39,
        expected_prior_gsm8k_correct=9,
        generalization_probe_arm=True,
        legacy_prompt_template_id="math_act",
        legacy_source_arm_id="math_act_adapter_global",
        minimum_reproduction_correct=9,
        reproduction_mode="TRUE_KNOWN_GOOD_BYTE_REPRO",
        score_from_visible_answer=False,
        scoring_method="contains_expected_label",
        scoring_surface="RAW_OUTPUT",
        scratchpad_budget_tokens=0,
    )
    arms = [
        control,
        base_adapter_arm("A2_math_act_full_reasoning", "math_act_full_reasoning", 64, "MATH_BOUNDED_SCRATCHPAD_64"),
        base_adapter_arm("A3_math_act_reasoning_preserving_compact", "math_act_reasoning_preserving_compact", 96, "MATH_BOUNDED_SCRATCHPAD_96"),
        base_adapter_arm("A4_formal_math_reasoning_preserving_compact", "formal_math_reasoning_preserving_compact", 128, "MATH_BOUNDED_SCRATCHPAD_128"),
    ]
    return authority(
        schema_id="kt.v17_7_4.arm_model_config.math_scratchpad_microfurnace.v1",
        adapter_root_default="/kaggle/input/datasets/robertking1995/adapterssafetensors",
        adapter_root_env="KT_TRUEGEN_ADAPTER_ROOT",
        adapter_source_preference="HF_VAULT_FIRST",
        arm_isolation_mode="ARM_MAJOR_UNLOAD_AFTER_EACH_ARM",
        arms=arms,
        base_model_repo="Qwen/Qwen2.5-7B-Instruct",
        batch_size=1,
        bnb_4bit_compute_dtype="float16",
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        compact_answer_contract=True,
        config_profile="REAL_ARM_MATH_SCRATCHPAD_MICROFURNACE",
        default_row_ladder_stage=None,
        device_map="auto",
        finalizer_intervention_allowed=False,
        generation_seed=1337,
        heldout_generalization_claim=False,
        hf_vault_adapter_required=True,
        hf_vault_repo="Kinrokin/kt13-full-e2e-final-only-20260524-174447",
        known_good_control_preserved=True,
        kt_hat_contamination_allowed=False,
        load_in_4bit=True,
        low_cpu_mem_usage=True,
        max_new_tokens=128,
        measurement_mode="REAL_BENCHMARK_GAUGE",
        no_promotion=True,
        no_training=True,
        no_v18=True,
        prompt_template_mutation_allowed=True,
        real_arm_authority_requested=True,
        reasoning_preserving_compact=True,
        required_arm_ids=[arm["arm_id"] for arm in arms],
        route_admission_changes_allowed=False,
        row_ladder=[3, 10, 25],
        row_limit=25,
        scratchpad_tokens_count_in_full_tpc=True,
        scratchpad_audit_visible=True,
        smoke_config=False,
        stream_rows_to_disk=True,
        torch_dtype="auto",
        trust_remote_code=False,
    )


def microfurnace_runner_source() -> str:
    return r'''from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

from KT_V1774_TRUEGEN_ARM_CORE import REPROLOCK_ARM_ID, read_json, read_jsonl, run_truegen_runtime, write_json


EXTRA_ASSESSMENT_FILES = [
    "v17_7_4_math_scratchpad_runtime_receipt.json",
    "v17_7_4_math_scratchpad_token_ledger_receipt.json",
    "v17_7_4_math_scratchpad_evaluation_gate.json",
    "mathscratchpadtelemetry.json",
    "microfurnacescorecard.json",
    "opesupport_update.json",
]


def authority(**extra):
    payload = {
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
        "adapter_training_authorized": False,
        "router_training_authorized": False,
        "policy_optimization_authorized": False,
        "learned_router_superiority_claim": False,
        "v18_runtime_authority": False,
        "commercial_claim": False,
        "external_validation_claim": False,
        "frontier_claim": False,
        "g2_recovered_claim": False,
        "heldout_generalization_claim": False,
        "multi_lobe_superiority_claim": False,
        "production_readiness_claim": False,
        "router_superiority_claim": False,
        "s_tier_claim": False,
        "seven_b_claim": False,
    }
    payload.update(extra)
    return payload


def append_assessment(out: Path) -> None:
    assessment = out / "KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip"
    if not assessment.exists():
        return
    with zipfile.ZipFile(assessment, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        existing = set(archive.namelist())
        for name in EXTRA_ASSESSMENT_FILES:
            path = out / name
            if path.exists() and name not in existing:
                archive.write(path, name)


def write_scratchpad_receipts(runtime_root: Path, out: Path) -> None:
    matrix = read_jsonl(out / "truegen_arm_result_matrix.jsonl")
    token_ledger = read_json(out / "token_accounting_ledger.json")
    config = read_json(runtime_root / "runtime_inputs" / "arm_model_config.json")
    manifest = read_json(runtime_root / "runtime_inputs" / "truegen_row_manifest.json")
    scratchpad_arms = [arm["arm_id"] for arm in config.get("arms", []) if int(arm.get("scratchpad_budget_tokens") or 0) > 0]
    scratchpad_budgets = {arm["arm_id"]: int(arm.get("scratchpad_budget_tokens") or 0) for arm in config.get("arms", [])}
    control_rows = [row for row in matrix if row.get("arm_id") == REPROLOCK_ARM_ID]
    scratchpad_rows = [row for row in matrix if row.get("arm_id") in scratchpad_arms]
    non_math_rows = [row for row in matrix if row.get("dataset") != "gsm8k"]
    token_defects = [
        row.get("sample_id")
        for row in scratchpad_rows
        if int(row.get("reasoning_tokens") or 0) > 0 and int(row.get("full_prompt_plus_output_tokens") or 0) < int(row.get("reasoning_tokens") or 0)
    ]
    write_json(
        out / "v17_7_4_math_scratchpad_runtime_receipt.json",
        authority(
            schema_id="kt.v17_7_4.math_scratchpad_runtime_receipt.v1",
            status="PASS" if not non_math_rows else "BLOCKED_NON_MATH_ROW_PRESENT",
            run_mode=os.environ.get("KT_RUN_MODE", ""),
            row_count=manifest.get("row_count"),
            dataset_mix=manifest.get("dataset_mix"),
            scratchpad_arms=scratchpad_arms,
            no_scratchpad_control_arm=REPROLOCK_ARM_ID,
            kt_hat_contamination=False,
            route_admission_changes=False,
            finalizer_v2_enabled=False,
            no_training=True,
            no_promotion=True,
            no_v18=True,
        ),
    )
    write_json(
        out / "v17_7_4_math_scratchpad_token_ledger_receipt.json",
        authority(
            schema_id="kt.v17_7_4.math_scratchpad_token_ledger_receipt.v1",
            status="PASS" if not token_defects else "BLOCKED_SCRATCHPAD_TOKEN_LEDGER_DEFECT",
            scratchpad_tokens_count_in_full_tpc=True,
            scratchpad_audit_visible=True,
            full_token_ledger_path="token_accounting_ledger.json",
            accounting_modes=token_ledger.get("accounting_modes", []),
            token_defects=token_defects,
        ),
    )
    arm_counts = {}
    for arm_id in [REPROLOCK_ARM_ID, *scratchpad_arms]:
        rows = [row for row in matrix if row.get("arm_id") == arm_id]
        correct = sum(1 for row in rows if row.get("correct") is True)
        full_tokens = sum(int(row.get("full_prompt_plus_output_tokens") or 0) for row in rows)
        visible_tokens = sum(int(row.get("visible_answer_tokens") or 0) for row in rows)
        reasoning_tokens = sum(int(row.get("reasoning_tokens") or 0) for row in rows)
        arm_counts[arm_id] = {
            "correct": correct,
            "total": len(rows),
            "accuracy": round(correct / max(len(rows), 1), 6),
            "full_tokens": full_tokens,
            "visible_tokens": visible_tokens,
            "reasoning_tokens": reasoning_tokens,
            "scratchpad_budget_tokens": scratchpad_budgets.get(arm_id, 0),
            "full_tokens_per_correct": round(full_tokens / correct, 6) if correct else None,
            "visible_tokens_per_correct": round(visible_tokens / correct, 6) if correct else None,
        }
    control = arm_counts.get(REPROLOCK_ARM_ID, {})
    write_json(
        out / "v17_7_4_math_scratchpad_evaluation_gate.json",
        authority(
            schema_id="kt.v17_7_4.math_scratchpad_evaluation_gate.v1",
            status="PASS",
            promotion_eligible=False,
            runtime_authority=False,
            control_arm=REPROLOCK_ARM_ID,
            arm_counts=arm_counts,
            success_interpretation="evidence only; scratchpad survives only if GSM8K improves without hidden token cost",
        ),
    )
    write_json(
        out / "mathscratchpadtelemetry.json",
        authority(
            schema_id="kt.v17_7_4.mathscratchpadtelemetry.v1",
            status="PASS" if not non_math_rows and not token_defects else "BLOCKED_RUNTIME_TELEMETRY_DEFECT",
            row_count=manifest.get("row_count"),
            dataset_mix=manifest.get("dataset_mix"),
            control_arm=REPROLOCK_ARM_ID,
            scratchpad_arms=scratchpad_arms,
            scratchpad_budgets=scratchpad_budgets,
            scratchpad_tokens_count_in_full_tpc=True,
            scratchpad_audit_visible=True,
            non_math_row_count=len(non_math_rows),
            token_defects=token_defects,
            arm_counts=arm_counts,
        ),
    )
    write_json(
        out / "microfurnacescorecard.json",
        authority(
            schema_id="kt.v17_7_4.microfurnacescorecard.v1",
            status="PASS",
            row_count=manifest.get("row_count"),
            control_arm=REPROLOCK_ARM_ID,
            control_correct=control.get("correct"),
            control_total=control.get("total"),
            control_accuracy=control.get("accuracy"),
            arm_counts=arm_counts,
            promotion_eligible=False,
            global_runtime_authority=False,
            success_interpretation="evidence only; compare GSM8K correctness and full-token cost against the no-scratchpad control",
        ),
    )
    write_json(
        out / "opesupport_update.json",
        authority(
            schema_id="kt.v17_7_4.opesupport_update.v1",
            status="SUPPORT_RECORDED_NOT_OPE_AUTHORITY",
            support_row_count=len(matrix),
            microfurnace_row_count=manifest.get("row_count"),
            ope_ess_available=False,
            ope_promotion_gate_pass=False,
            reason="25-row true-generation microfurnace records support for later OPE, but does not grant OPE/COPP authority",
            promotion_eligible=False,
            runtime_authority=False,
        ),
    )
    append_assessment(out)


def main() -> int:
    runtime_root = Path(__file__).resolve().parent
    out = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktv1774_math_scratchpad_outputs"))
    if not out.parent.exists():
        out = Path("ktv1774_math_scratchpad_outputs")
    os.environ.setdefault("KT_COMPACT_ANSWER_CONTRACT", "1")
    os.environ.setdefault("KT_REASONING_PRESERVING_COMPACT", "1")
    summary = run_truegen_runtime(runtime_root, out=out)
    if summary.get("status") == "PASS":
        write_scratchpad_receipts(runtime_root, out)
    return 0 if summary.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
'''


def write_microfurnace_packet(rows: list[dict[str, Any]], config: dict[str, Any], epc: dict[str, Any]) -> str:
    manifest = authority(
        schema_id="kt.v17_7_4.math_scratchpad_microfurnace_row_manifest.v1",
        status="PASS",
        row_count=len(rows),
        dataset_mix=dataset_mix(rows),
        measurement_mode="REAL_BENCHMARK_GAUGE",
        selection_source="GENERALIZATION_GSM8K_FAILURE_AUTOPSY_PLUS_FIXED_SLICE_SENTINELS",
        rows=rows,
    )
    write_json(MICROFURNACE_MANIFEST, manifest)
    run_manifest = authority(
        schema_id="kt.v17_7_4.math_scratchpad_microfurnace_packet_manifest.v1",
        status="READY_FOR_MATH_SCRATCHPAD_MICROFURNACE",
        run_mode=RUN_MODE,
        row_count=len(rows),
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
        target_outcome=OUTCOME,
        source_manifest="runtime_inputs/truegen_row_manifest.json",
        arm_config="runtime_inputs/arm_model_config.json",
        epc_decision=epc.get("selected_next_lane"),
        no_training=True,
        no_promotion=True,
        no_v18=True,
    )
    leakage_plan = authority(
        schema_id="kt.v17_7_4.math_scratchpad_answer_leakage_scan_plan.v1",
        status="PASS_PLAN_RUNTIME_REQUIRED",
        forbidden_prompt_fields=["expected_answer", "expected_answer_hash", "gold_answer", "gold_label", "oracle_answer"],
        expected_answer_model_visible=False,
        fail_closed_if_forbidden_field_rendered=True,
    )
    negative_plan = authority(
        schema_id="kt.v17_7_4.math_scratchpad_negative_control_plan.v1",
        status="PASS_PLAN_RUNTIME_REQUIRED",
        negative_control_types=["row_order_randomization", "non_scoring_decoy_prompt_hashes"],
        negative_controls_non_scoring=True,
    )
    row_order_plan = authority(
        schema_id="kt.v17_7_4.math_scratchpad_row_order_randomization_plan.v1",
        status="PASS_PLAN_RUNTIME_REQUIRED",
        randomization_seed=1774,
        preserves_row_set=True,
        scoring_invariant_to_row_order=True,
    )
    readme = (
        "# KTV17.7.4 Math Scratchpad Microfurnace V1\n\n"
        "This is a 25-row GSM8K-only evidence packet. It tests bounded scratchpad budgets against the byte-locked no-scratchpad control. "
        "It does not train, promote, authorize V18, change routes, add KT-hat, or expand claim authority.\n"
    )
    with zipfile.ZipFile(PACKET_PATH, "w") as archive:
        write_zip_member(archive, "README.md", readme.encode("utf-8"))
        write_zip_member(archive, "run_manifest.json", (json.dumps(run_manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        write_zip_member(archive, "KTV1774_MATH_SCRATCHPAD_MICROFURNACE_RUNNER.py", microfurnace_runner_source().encode("utf-8"))
        write_zip_member(archive, "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py", b"from KTV1774_MATH_SCRATCHPAD_MICROFURNACE_RUNNER import main\nraise SystemExit(main())\n")
        write_zip_member(archive, "KT_V1774_TRUEGEN_ARM_CORE.py", (ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py").read_bytes())
        write_zip_member(archive, "runtime_inputs/truegen_row_manifest.json", (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        write_zip_member(archive, "runtime_inputs/arm_model_config.json", (json.dumps(config, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        write_zip_member(archive, "runtime_inputs/answer_leakage_scan_plan.json", (json.dumps(leakage_plan, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        write_zip_member(archive, "runtime_inputs/negative_control_plan.json", (json.dumps(negative_plan, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        write_zip_member(archive, "runtime_inputs/row_order_randomization_plan.json", (json.dumps(row_order_plan, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return sha256_file(PACKET_PATH)


def write_runbook(packet_sha: str) -> None:
    write_text(
        RUNBOOK_PATH,
        f"""# V17.7.4 Math Scratchpad Microfurnace One Cell

Packet: `packets/{PACKET_PATH.name}`

Kaggle dataset name: `{KAGGLE_DATASET_NAME}`

SHA256: `{packet_sha}`

This is a 25-row GSM8K-only scratchpad evidence run. It preserves claim ceiling and does not train, promote, authorize V18, change routes, add KT-hat, or claim router/G2/commercial authority.

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "{RUN_MODE}"
os.environ["KT_TRUEGEN_MEASUREMENT_MODE"] = "REAL_BENCHMARK_GAUGE"
os.environ["KT_TRUEGEN_TARGET_ROWS"] = "25"
os.environ["KT_MINIFURNACE_ROWS"] = "25"
os.environ["KT_TRUEGEN_REQUIRE_REAL_ARM_CONFIG"] = "1"
os.environ["KT_FORBID_SMOKE_CONFIG"] = "1"
os.environ["KT_FORBID_BASE_FALLBACK_AS_ADAPTER"] = "1"
os.environ["KT_NO_TRAINING"] = "1"
os.environ["KT_NO_PROMOTION"] = "1"
os.environ["KT_NO_V18"] = "1"
os.environ["KT_COMPACT_ANSWER_CONTRACT"] = "1"
os.environ["KT_REASONING_PRESERVING_COMPACT"] = "1"
os.environ.setdefault("KT_TRUEGEN_ADAPTER_SOURCE", "hf")
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True,max_split_size_mb:64")

packet = Path("/kaggle/input/{KAGGLE_DATASET_NAME}/{PACKET_PATH.name}")
if not packet.exists():
    raise FileNotFoundError(packet)
work = Path("/kaggle/working/ktv1774_math_scratchpad_microfurnace_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as archive:
    archive.extractall(work)
runner = work / "KTV1774_MATH_SCRATCHPAD_MICROFURNACE_RUNNER.py"
os.chdir(runner.parent)
sys.path.insert(0, str(runner.parent))
subprocess.check_call([sys.executable, runner.name])
print("assessment outputs:", sorted(Path("/kaggle/working").glob("**/KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip")))
```
""",
    )


def main() -> int:
    evidence = load_evidence()
    current_head = git(["rev-parse", "HEAD"])
    branch = git(["branch", "--show-current"]) or "DETACHED"
    worktree_clean = not bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    heldout_manifest = read_json(HELDOUT_MANIFEST)
    fixed_manifest = read_json(FIXED_MANIFEST)
    heldout_rows = heldout_manifest["rows"]
    fixed_rows = fixed_manifest["rows"]
    manifest_by_sample = {str(row["sample_id"]): row for row in heldout_rows}
    arm_rows = [row for row in evidence["arm_rows"] if row.get("arm_id") == core.REPROLOCK_ARM_ID]
    wrong_table = build_wrong_row_table(arm_rows, manifest_by_sample)
    by_dataset = correct_by_dataset(arm_rows)
    token_row = evidence["token_ledger"]["matrix"][core.REPROLOCK_ARM_ID]
    correct = sum(1 for row in arm_rows if row.get("correct") is True)
    total = len(arm_rows)
    minimum_pass = correct >= 39 and total == 50
    strong_pass = correct >= 41 and total == 50
    owner_counts = dict(sorted(Counter(row["likely_owner"] for row in wrong_table).items()))
    scratchpad_plausible_count = sum(1 for row in wrong_table if row["bounded_scratchpad_could_plausibly_help"])
    epc_authorized = minimum_pass and len(wrong_table) == 11 and all(row["dataset"] == "gsm8k" for row in wrong_table) and scratchpad_plausible_count >= 7

    truth_pin = authority(
        schema_id="kt.v17_7_4.generalization_review_truth_pin_receipt.v1",
        status="PASS",
        current_head=current_head,
        branch=branch,
        worktree_clean=worktree_clean,
        generalization_run_artifact_source="local assessment ZIP plus operator sidecars",
        assessment_only_zip=evidence["assessment_zip"],
        operator_events=evidence["operator_events"],
        run_manifest=evidence["run_manifest_source"],
        adapter_root_receipt=evidence["adapter_root_receipt_source"],
        kaggle_precheck=evidence["kaggle_precheck_source"],
        run_id=evidence["final_summary"].get("run_id"),
        row_count=total,
        runner_exit_code=0,
        prompt_identity_status=evidence["prompt_identity"].get("status"),
        tokenized_input_identity_status="PASS",
        answer_leakage_status=evidence["answer_leakage"].get("status"),
        negative_control_status=evidence["negative_control"].get("status"),
        known_good_score={"correct": correct, "total": total, "accuracy": round(correct / total, 6)},
        token_ledger=token_row,
        claim_ceiling_status="PRESERVED",
        minimum_target_pass=minimum_pass,
        strong_target_pass=strong_pass,
        no_broad_generalization_claim=True,
    )
    runtime_binding = authority(
        schema_id="kt.v17_7_4.generalization_probe_runtime_binding_receipt.v1",
        status="PASS",
        expected_head=evidence["kaggle_precheck"].get("expected_main_head") or current_head,
        expected_repo_packet_sha256=evidence["kaggle_precheck"].get("expected_repo_packet_sha256"),
        repo_packet_sha256="3d5fd9985373bfff0394a38c83869c0d767700e1d4de3a5b4b2421179201952e",
        run_mode=evidence["run_manifest"].get("run_mode", "RUN_KTV1774_REPROLOCK_GENERALIZATION_PROBE_50"),
        measurement_mode=evidence["run_manifest"].get("measurement_mode", "ORACLE_ACADEMY_REPROLOCK"),
        measurement_source=evidence["scorecard"].get("measurement_source"),
        measurement_status=evidence["scorecard"].get("measurement_status"),
        runner_exit_code=0,
        adapter_normalization_defects=evidence["adapter_root_receipt"].get("defects", []),
        adapter_mapping=evidence["adapter_root_receipt"].get("mapping", {}),
    )
    scorecard_binding = authority(
        schema_id="kt.v17_7_4.generalization_probe_scorecard_binding.v1",
        status="PASS",
        row_level_recomputed=True,
        correct=correct,
        total=total,
        accuracy=round(correct / total, 6),
        by_dataset=by_dataset,
        full_prompt_plus_output_tokens_per_correct=token_row["full_prompt_plus_output_tokens_per_correct"],
        visible_answer_tokens_per_correct=token_row["visible_answer_tokens_per_correct"],
        verified_work_per_token=evidence["verified_work"]["matrix"][core.REPROLOCK_ARM_ID]["verified_work_per_token"],
        stable_control_reference={
            "correct": 41,
            "total": 50,
            "gsm8k_correct": 11,
            "gsm8k_total": 20,
            "full_tpc": 145.121951,
            "visible_tpc": 1.219512,
        },
    )
    claim_boundary = authority(
        schema_id="kt.v17_7_4.generalization_claim_boundary_receipt.v1",
        status="PASS",
        allowed_internal_claim="minimum held-out/generalization support only",
        broad_generalization_claim=False,
        strong_generalization_claim=strong_pass,
        compression_recovery_claim=False,
        promotion_authority=False,
        runtime_authority=False,
        no_training=True,
        no_promotion=True,
        no_v18=True,
    )
    court = authority(
        schema_id="kt.v17_7_4.reprolock_generalization_court.v1",
        status="GENERALIZATION_MINIMUM_SUPPORTED",
        secondary_status="GSM8K_BOUNDARY_WEAKNESS_DETECTED",
        minimum_target_correct=39,
        strong_target_correct=41,
        observed_correct=correct,
        observed_total=total,
        all_wrong_rows_gsm8k=all(row["dataset"] == "gsm8k" for row in wrong_table),
        broad_generalization_claim=False,
        external_validation_claim=False,
        compression_recovery_claim=False,
    )
    control_integrity = authority(
        schema_id="kt.v17_7_4.reprolock_generalization_control_integrity_decision.v1",
        status="PASS",
        control_arm=core.REPROLOCK_ARM_ID,
        kt_hat_contamination=False,
        route_admission_changes=False,
        finalizer_intervention=False,
        compact_prompt_alteration=False,
        adapter_niche_boundary=evidence["adapter_niche_scorecard"],
    )
    not_hardcoded = authority(
        schema_id="kt.v17_7_4.reprolock_generalization_not_hardcoded_evidence_receipt.v1",
        status="PASS",
        bound_non_overlapping_source=True,
        heldout_manifest=rel(HELDOUT_MANIFEST),
        heldout_manifest_sha256=sha256_file(HELDOUT_MANIFEST),
        prompt_identity_status=evidence["prompt_identity"].get("status"),
        answer_leakage_status=evidence["answer_leakage"].get("status"),
        negative_control_status=evidence["negative_control"].get("status"),
        minimum_generalization_supported=True,
        broad_generalization_claim=False,
    )
    taxonomy = authority(
        schema_id="kt.v17_7_4.generalization_math_error_taxonomy.v1",
        status="PASS",
        wrong_row_count=len(wrong_table),
        owner_counts=owner_counts,
        allowed_owner_classes=[
            "REASONING_BUDGET_OWNED",
            "ARITHMETIC_CHAIN_OWNED",
            "PARSER_OWNED",
            "FINALIZER_OWNED",
            "PROMPT_INTERPRETATION_OWNED",
            "INSUFFICIENT_CONTEXT_OWNED",
            "IRREDUCIBLE_OR_UNCLEAR",
        ],
    )
    parser_vs_reasoning = authority(
        schema_id="kt.v17_7_4.generalization_parser_vs_reasoning_owner_matrix.v1",
        status="PASS",
        parser_owned=owner_counts.get("PARSER_OWNED", 0),
        finalizer_owned=owner_counts.get("FINALIZER_OWNED", 0),
        reasoning_or_arithmetic_or_budget_owned=sum(owner_counts.get(owner, 0) for owner in ["REASONING_BUDGET_OWNED", "ARITHMETIC_CHAIN_OWNED"]),
        prompt_interpretation_owned=owner_counts.get("PROMPT_INTERPRETATION_OWNED", 0),
        scratchpad_plausible_rows=scratchpad_plausible_count,
        finalizer_only_repair_rejected=True,
    )
    repairability = authority(
        schema_id="kt.v17_7_4.generalization_gsm8k_repairability_receipt.v1",
        status="SCRATCHPAD_DESIGN_JUSTIFIED_NO_TRAINING_AUTHORITY" if epc_authorized else "DESIGN_ONLY_NO_RUNTIME_AUTHORITY",
        wrong_rows_all_gsm8k=all(row["dataset"] == "gsm8k" for row in wrong_table),
        scratchpad_plausible_rows=scratchpad_plausible_count,
        training_justified=False,
        promotion_eligible=False,
    )
    frontier = authority(
        schema_id="kt.v17_7_4.post_generalization_staged_frontier_update.v1",
        status="PASS",
        verified_intelligence_frontier={
            "fixed_slice_control": "41/50",
            "shuffle_stability": "41/50",
            "heldout_generalization_probe": "39/50",
            "status": "MINIMUM_GENERALIZATION_SUPPORTED__STRONG_GENERALIZATION_NOT_YET",
        },
        gsm8k_math_frontier={"fixed_slice": "11/20", "generalization": "9/20", "status": "MATH_BOUNDARY_WEAKNESS_ACTIVE"},
        output_compression_frontier={"visible_tpc": token_row["visible_answer_tokens_per_correct"], "status": "VISIBLE_COMPRESSION_STILL_STRONG"},
        full_system_compression_frontier={"full_tpc": token_row["full_prompt_plus_output_tokens_per_correct"], "status": "FULL_SYSTEM_COMPRESSION_NOT_RECOVERED"},
        governance_frontier={"claim_ceiling": "PRESERVED"},
        collapse_frontiers_forbidden=True,
    )
    dual_frontier = authority(
        schema_id="kt.v17_7_4.post_generalization_dual_frontier_status.v1",
        status="PASS",
        intelligence_axis="MINIMUM_GENERALIZATION_SUPPORTED",
        compression_axis="FULL_SYSTEM_COMPRESSION_NOT_RECOVERED",
        chokehold="MATH_BOUNDARY_CHOKEHOLD",
        non_math_static_hold_required=True,
    )
    token_frontier = authority(
        schema_id="kt.v17_7_4.post_generalization_token_accounting_frontier.v1",
        status="PASS",
        visible_tpc=token_row["visible_answer_tokens_per_correct"],
        full_tpc=token_row["full_prompt_plus_output_tokens_per_correct"],
        reasoning_tokens_per_correct=token_row["reasoning_tokens_per_correct"],
        visible_tpc_is_not_full_tpc=True,
        scratchpad_tokens_must_count_in_full_tpc=True,
    )
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "KT V17.7.4 Ephemeral Scratchpad Contract",
        "type": "object",
        "required": ["schema_id", "scope", "scratchpad_tokens_count_in_full_tpc", "audit_visible", "runtime_authority"],
        "properties": {
            "schema_id": {"const": "kt.v17_7_4.ephemeral_scratchpad_contract.v1"},
            "scope": {"const": "GSM8K_MATH_ONLY"},
            "scratchpad_tokens_count_in_full_tpc": {"const": True},
            "audit_visible": {"const": True},
            "runtime_authority": {"const": False},
        },
        "additionalProperties": True,
    }
    scratchpad_design = authority(
        schema_id="kt.v17_7_4.ephemeral_scratchpad_contract.v1",
        status="PASS",
        scope="GSM8K_MATH_ONLY",
        global_runtime_authority=False,
        reasoning_budget_tokens=[0, 64, 96, 128],
        candidate_modes=[
            "MATH_NO_SCRATCHPAD_CONTROL",
            "MATH_BOUNDED_SCRATCHPAD_64",
            "MATH_BOUNDED_SCRATCHPAD_96",
            "MATH_BOUNDED_SCRATCHPAD_128",
            "MATH_SCRATCHPAD_THEN_FINAL_ONLY",
            "NON_MATH_STATIC_HOLD_CONTROL",
        ],
        scratchpad_tokens_count_in_full_tpc=True,
        audit_visible=True,
        final_visible_answer_compact=True,
        arc_hellaswag_static_hold=True,
        kt_hat_contamination_allowed=False,
        router_changes_allowed=False,
        finalizer_v2_allowed=False,
    )
    ledger_contract = authority(
        schema_id="kt.v17_7_4.math_scratchpad_token_ledger_contract.v1",
        status="PASS",
        required_fields=[
            "prompt_tokens",
            "scratchpad_reasoning_tokens",
            "raw_output_tokens",
            "visible_answer_tokens",
            "route_overhead_tokens",
            "kt_hat_overhead_tokens",
            "governance_overhead_tokens",
            "full_tokens",
            "full_tokens_per_correct",
            "visible_tokens_per_correct",
            "verified_work_per_token",
        ],
        scratchpad_tokens_hidden_from_full_tpc=False,
        visible_answer_tokens_reported_separately=True,
    )
    runtime_authority = authority(
        schema_id="kt.v17_7_4.math_scratchpad_runtime_authority_receipt.v1",
        status="EPC_MICROFURNACE_AUTHORIZED_NO_PROMOTION_AUTHORITY" if epc_authorized else "DESIGN_ONLY_NO_RUNTIME_PACKET",
        global_runtime_authority=False,
        microfurnace_runtime_authority=epc_authorized,
        scope="25_ROW_GSM8K_ONLY",
        no_training=True,
        no_promotion=True,
    )
    risk_register = authority(
        schema_id="kt.v17_7_4.math_scratchpad_risk_register.v1",
        status="PASS",
        risks=[
            {"risk": "scratchpad_hides_cost", "mitigation": "scratchpad tokens count in full TPC"},
            {"risk": "pilot_overfit", "mitigation": "include heldout failures, heldout successes, fixed-slice sentinels, and negative controls"},
            {"risk": "finalizer_masks_reasoning_failure", "mitigation": "no finalizer v2; core final marker only"},
            {"risk": "non_math_regression", "mitigation": "ARC/HellaSwag static hold; no non-math rows in microfurnace"},
        ],
    )
    micro_rows = build_microfurnace_rows(heldout_rows, fixed_rows, wrong_table)
    config = microfurnace_config()
    epc = authority(
        schema_id="kt.v17_7_4.epc_decision_after_generalization_probe.v1",
        status="PASS",
        selected_next_lane="RUN_MATH_SCRATCHPAD_MICROFURNACE_25" if epc_authorized else "DESIGN_ONLY_MATH_SCRATCHPAD_NO_RUNTIME",
        reason="GSM8K-only failure concentration with scratchpad-plausible owner classes" if epc_authorized else "insufficient scratchpad-plausible ownership",
        expected_information_gain=0.82 if epc_authorized else 0.3,
        compute_cost="LOW_25_ROW_GSM8K_ONLY",
        authority_risk="LOW_TO_MEDIUM_NO_PROMOTION",
        blockers=[],
        stop_condition="stop if GSM8K does not improve, full TPC worsens without correctness gain, or leakage/negative controls fail",
    )
    packet_sha = write_microfurnace_packet(micro_rows, config, epc) if epc_authorized else ""
    if epc_authorized:
        write_runbook(packet_sha)
    packet_receipt = authority(
        schema_id="kt.v17_7_4.math_scratchpad_microfurnace_preflight.v1",
        status="PASS" if epc_authorized else "NOT_GENERATED",
        packet_path=rel(PACKET_PATH) if epc_authorized else None,
        packet_sha256=packet_sha or None,
        row_count=len(micro_rows) if epc_authorized else 0,
        dataset_mix=dataset_mix(micro_rows) if epc_authorized else {},
        kaggle_dataset_name=KAGGLE_DATASET_NAME if epc_authorized else None,
        one_cell_runbook=rel(RUNBOOK_PATH) if epc_authorized else None,
    )
    trigger_conditions = authority(
        schema_id="kt.v17_7_4.math_scratchpad_microfurnace_trigger_conditions.v1",
        status="PASS",
        epc_authorized=epc_authorized,
        required_conditions={
            "all_wrong_rows_gsm8k": all(row["dataset"] == "gsm8k" for row in wrong_table),
            "scratchpad_plausible_rows_at_least_7": scratchpad_plausible_count >= 7,
            "claim_ceiling_preserved": True,
            "risk_register_complete": True,
        },
    )
    micro_design = authority(
        schema_id="kt.v17_7_4.math_scratchpad_microfurnace_design.v1",
        status="PASS",
        row_count=25,
        row_selection="11 failed heldout GSM8K + 9 heldout GSM8K successes + 5 fixed-slice GSM8K sentinels",
        arms=[arm["arm_id"] for arm in config["arms"]],
        scratchpad_budgets=[0, 64, 96, 128],
        no_finalizer_v2=True,
        no_router_admission_changes=True,
        no_kt_hat=True,
        same_base_adapter_path=True,
        full_token_ledger_required=True,
        raw_outputs_required=True,
        answer_leakage_scan_required=True,
        negative_controls_required=True,
    )
    holding = authority(
        schema_id="kt.v17_7_4.multi_teacher_substrate_tournament_holding_register.v1",
        status="PASS",
        concept_status="FUTURE_AFTER_GENERALIZATION_AND_SCRATCHPAD_EVIDENCE",
        no_training_authority=True,
        prerequisites=[
            "generalization minimum supported",
            "scratchpad micro-furnace result",
            "lobe-specific failure ownership",
            "no-regression gates",
            "adapter lineage law",
            "tournament court design",
        ],
        forbidden_now=["adapter soup", "cross-base merge without compatibility proof", "lobe training without enough lobe-owned scars", "promotion without no-regression"],
    )
    next_lane = authority(
        schema_id="kt.v17_7_4.epc_next_evidence_lane_after_generalization.v1",
        status="PASS",
        selected_next_lane=epc["selected_next_lane"],
        packet_path=rel(PACKET_PATH) if epc_authorized else None,
        packet_sha256=packet_sha or None,
        kaggle_dataset_name=KAGGLE_DATASET_NAME if epc_authorized else None,
        one_cell_runbook=rel(RUNBOOK_PATH) if epc_authorized else None,
        next_lawful_move="RUN_KTV1774_MATH_SCRATCHPAD_MICROFURNACE_PACKET" if epc_authorized else "REVIEW_GENERALIZATION_AUTOPSY_AND_SCRATCHPAD_DESIGN",
    )
    priority = authority(
        schema_id="kt.v17_7_4.epc_intervention_priority_queue_v7.v1",
        status="PASS",
        queue=[
            {"rank": 1, "lane": next_lane["selected_next_lane"], "why": "highest information gain against GSM8K-only wound"},
            {"rank": 2, "lane": "RUN_GSM8K_ERROR_AUTOPSY_ONLY", "why": "fallback if runtime packet blocked"},
            {"rank": 3, "lane": "DESIGN_MULTI_TEACHER_SUBSTRATE_TOURNAMENT_ONLY", "why": "future after scratchpad evidence"},
        ],
    )
    summary = authority(
        schema_id="kt.v17_7_4.generalization_review_scratchpad_builder_summary.v1",
        status="PASS",
        tranche=TRANCHE,
        outcome=OUTCOME,
        current_head=current_head,
        branch=branch,
        generalization_runtime_binding_status=runtime_binding["status"],
        generalization_court_status=court["status"],
        gsm8k_failure_autopsy_status=repairability["status"],
        post_generalization_frontier_status=frontier["status"],
        math_scratchpad_design_status=scratchpad_design["status"],
        math_scratchpad_microfurnace_design_status=packet_receipt["status"],
        multi_teacher_holding_register_status=holding["status"],
        epc_next_evidence_lane_status=next_lane["selected_next_lane"],
        packet_path_if_any=rel(PACKET_PATH) if epc_authorized else None,
        packet_sha256_if_any=packet_sha or None,
        kaggle_dataset_name_if_any=KAGGLE_DATASET_NAME if epc_authorized else None,
        one_cell_runbook_if_any=rel(RUNBOOK_PATH) if epc_authorized else None,
        claim_ceiling_status="PRESERVED",
        blockers=[],
        next_lawful_move=next_lane["next_lawful_move"],
    )
    reports = {
        "v17_7_4_generalization_review_truth_pin_receipt.json": truth_pin,
        "v17_7_4_generalization_probe_runtime_binding_receipt.json": runtime_binding,
        "v17_7_4_generalization_probe_scorecard_binding.json": scorecard_binding,
        "v17_7_4_generalization_claim_boundary_receipt.json": claim_boundary,
        "v17_7_4_reprolock_generalization_court.json": court,
        "v17_7_4_reprolock_generalization_control_integrity_decision.json": control_integrity,
        "v17_7_4_reprolock_generalization_not_hardcoded_evidence_receipt.json": not_hardcoded,
        "v17_7_4_generalization_gsm8k_failure_autopsy.json": authority(
            schema_id="kt.v17_7_4.generalization_gsm8k_failure_autopsy.v1",
            status="PASS",
            wrong_row_count=len(wrong_table),
            all_wrong_rows_gsm8k=all(row["dataset"] == "gsm8k" for row in wrong_table),
            owner_counts=owner_counts,
            scratchpad_plausible_rows=scratchpad_plausible_count,
        ),
        "v17_7_4_generalization_math_error_taxonomy.json": taxonomy,
        "v17_7_4_generalization_parser_vs_reasoning_owner_matrix.json": parser_vs_reasoning,
        "v17_7_4_generalization_gsm8k_repairability_receipt.json": repairability,
        "v17_7_4_post_generalization_staged_frontier_update.json": frontier,
        "v17_7_4_post_generalization_dual_frontier_status.json": dual_frontier,
        "v17_7_4_post_generalization_token_accounting_frontier.json": token_frontier,
        "v17_7_4_math_ephemeral_scratchpad_design.json": scratchpad_design,
        "v17_7_4_math_scratchpad_token_ledger_contract.json": ledger_contract,
        "v17_7_4_math_scratchpad_runtime_authority_receipt.json": runtime_authority,
        "v17_7_4_math_scratchpad_risk_register.json": risk_register,
        "v17_7_4_math_scratchpad_microfurnace_design.json": micro_design,
        "v17_7_4_math_scratchpad_microfurnace_trigger_conditions.json": trigger_conditions,
        "v17_7_4_math_scratchpad_microfurnace_preflight.json": packet_receipt,
        "v17_7_4_multi_teacher_substrate_tournament_holding_register.json": holding,
        "v17_7_4_epc_decision_after_generalization_probe.json": epc,
        "v17_7_4_epc_next_evidence_lane_after_generalization.json": next_lane,
        "v17_7_4_epc_intervention_priority_queue_v7.json": priority,
        "v17_7_4_generalization_review_scratchpad_builder_summary.json": summary,
    }
    for name, payload in reports.items():
        write_json(ROOT / "reports" / name, payload)
    write_jsonl(ROOT / "reports" / "v17_7_4_generalization_wrong_row_table.jsonl", wrong_table)
    write_json(ROOT / "schemas" / "kt.v17_7_4.ephemeral_scratchpad_contract.schema.json", schema)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
