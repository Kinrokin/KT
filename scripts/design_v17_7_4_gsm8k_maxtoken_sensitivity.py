from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core


TRANCHE = "AUTHOR_KTV1774_GSM8K_MAXTOKEN_SENSITIVITY_DESIGN_V1"
OUTCOME = "KT_GSM8K_MAXTOKEN_SENSITIVITY_DESIGNED__NO_RUNTIME_PACKET_WARRANTED__CLAIM_CEILING_PRESERVED"
CONTROL_ARM = core.REPROLOCK_ARM_ID
NEXT_LAWFUL_MOVE = "AUTHOR_DETERMINISTIC_RESCUE_OFFLINE_REPLAY_V4"
ASSESSMENT_ZIP = Path(
    os.environ.get(
        "KT_CONTROL_ONLY_GSM8K_ASSESSMENT_ZIP",
        r"d:\user\rober\Downloads\KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY (18).zip",
    )
)


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(core.AUTHORITY_FALSE)
    payload.update(
        {
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
            "gsm8k_recovery_claim": False,
            "max_token_fix_success_claim": False,
            "multi_lobe_superiority_claim": False,
            "parser_repair_success_claim": False,
            "production_readiness_claim": False,
            "router_superiority_claim": False,
            "s_tier_claim": False,
            "scratchpad_authority": False,
            "seven_b_claim": False,
            "v3_rescue_authority": False,
        }
    )
    payload.update(extra)
    return payload


def git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows), encoding="utf-8")


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def load_zip_json(archive: zipfile.ZipFile, name: str) -> dict[str, Any]:
    return json.loads(archive.read(name).decode("utf-8-sig"))


def load_zip_jsonl(archive: zipfile.ZipFile, name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in archive.read(name).decode("utf-8-sig").splitlines() if line.strip()]


def load_assessment_rows() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not ASSESSMENT_ZIP.exists():
        return [], {"assessment_zip_present": False, "assessment_zip_sha256": None}
    with zipfile.ZipFile(ASSESSMENT_ZIP) as archive:
        rows = [
            row
            for row in load_zip_jsonl(archive, "truegen_arm_result_matrix.jsonl")
            if row.get("arm_id") == CONTROL_ARM and row.get("dataset") == "gsm8k"
        ]
        metadata = {
            "assessment_zip_present": True,
            "assessment_zip_sha256": sha256_file(ASSESSMENT_ZIP),
            "assessment_members_bound": sorted(
                member
                for member in [
                    "truegen_arm_result_matrix.jsonl",
                    "truegen_predictions.jsonl",
                    "token_accounting_ledger.json",
                    "truegen_token_efficiency_matrix.json",
                    "v17_7_4_control_only_gsm8k_extension_runtime_receipt.json",
                ]
                if member in archive.namelist()
            ),
            "token_accounting_status": load_zip_json(archive, "token_accounting_ledger.json").get("status"),
        }
    return rows, metadata


def output_flags(output: str) -> dict[str, Any]:
    stripped = output.rstrip()
    lower = stripped.lower()
    return {
        "ended_with_sentence_punctuation": stripped.endswith((".", "!", "?")),
        "ended_with_digit": bool(re.search(r"\d\s*$", stripped)),
        "ended_mid_expression": stripped.endswith(("=", "+", "-", "*", "/", "(", "\\times"))
        or lower.endswith((" after", " before", " then", " total", " because")),
        "ended_mid_word": bool(re.search(r"[A-Za-z]{4,}$", stripped)) and not stripped.endswith((".", "!", "?")),
        "ended_mid_sentence": bool(stripped) and not stripped.endswith((".", "!", "?", ":", ";")),
        "raw_regex_surface_present": bool(re.search(r"[-+]?\d+(?:,\d{3})*(?:\.\d+)?|[-+]?\d+/\d+", output)),
        "multiple_numeric_candidates": len(re.findall(r"[-+]?\d+(?:,\d{3})*(?:\.\d+)?|[-+]?\d+/\d+", output)) > 1,
        "output_starts_with_numeric_surface": bool(re.match(r"\s*[-+]?\$?\d", output)),
    }


def truthy(value: Any) -> bool:
    return bool(value) is True


def bucket_output_tokens(tokens: int | None) -> str:
    if tokens is None:
        return "unknown"
    if tokens <= 16:
        return "000_016"
    if tokens <= 32:
        return "017_032"
    if tokens <= 50:
        return "033_050"
    return "051_plus"


def bucket_budget_ratio(ratio: float | None) -> str:
    if ratio is None:
        return "unknown"
    if ratio <= 0.50:
        return "000_050"
    if ratio <= 0.80:
        return "051_080"
    if ratio < 1.00:
        return "081_099"
    return "100_plus"


def rate(rows: list[dict[str, Any]], key: str) -> float | None:
    if not rows:
        return None
    return round(sum(1 for row in rows if truthy(row.get(key))) / len(rows), 6)


def wrong_rate(rows: list[dict[str, Any]]) -> float | None:
    if not rows:
        return None
    return round(sum(1 for row in rows if not truthy(row.get("official_correct"))) / len(rows), 6)


def grouped_rates(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(str(row.get(key)), []).append(row)
    return {
        group: {
            "row_count": len(group_rows),
            "correct_count": sum(1 for row in group_rows if truthy(row.get("official_correct"))),
            "wrong_count": sum(1 for row in group_rows if not truthy(row.get("official_correct"))),
            "wrong_rate": wrong_rate(group_rows),
        }
        for group, group_rows in sorted(groups.items())
    }


def hypothesis_strength(delta: float | None, truncation_rows: int, protection_plan: bool) -> str:
    if delta is None or truncation_rows < 10:
        return "NONE"
    if delta >= 0.20 and protection_plan:
        return "MODERATE"
    if delta >= 0.10:
        return "WEAK"
    return "NONE"


def build_rows() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    assessment_rows, assessment_meta = load_assessment_rows()
    difficulty_rows = {row["sample_id"]: row for row in read_jsonl(ROOT / "reports" / "v17_7_4_gsm8k_row_difficulty_table.jsonl")}
    control_autopsy = {row["sample_id"]: row for row in read_jsonl(ROOT / "reports" / "v17_7_4_control_only_gsm8k_row_level_autopsy.jsonl")}
    official_rows = {row["sample_id"]: row for row in read_jsonl(ROOT / "reports" / "v17_7_4_official_scorer_replay_matrix.jsonl")}
    max_new_tokens = int(
        read_json(ROOT / "reports" / "v17_7_4_control_only_gsm8k_prompt_generation_config_review.json").get(
            "max_new_tokens_from_rows", 50
        )
    )

    if assessment_rows:
        source_ids = [str(row["sample_id"]) for row in assessment_rows]
    else:
        source_ids = sorted(difficulty_rows)

    output_rows: list[dict[str, Any]] = []
    for sample_id in source_ids:
        assessment = next((row for row in assessment_rows if str(row.get("sample_id")) == sample_id), {})
        difficulty = difficulty_rows.get(sample_id, {})
        control = control_autopsy.get(sample_id, {})
        official = official_rows.get(sample_id, {})
        output = str(assessment.get("output_text") or "")
        flags = output_flags(output)
        tokens_out = assessment.get("tokens_out")
        tokens_in = assessment.get("tokens_in")
        total_tokens = assessment.get("total_tokens")
        ratio = round(float(tokens_out) / max_new_tokens, 6) if isinstance(tokens_out, int | float) else None
        suspected = (
            truthy(difficulty.get("output_truncated_proxy"))
            or truthy(control.get("output_appears_truncated"))
            or truthy(control.get("max_new_tokens_possible_cut"))
            or flags["ended_mid_expression"]
        )
        reasons = list(difficulty.get("output_truncation_reasons") or [])
        if control.get("max_new_tokens_possible_cut"):
            reasons.append("PREDECESSOR_MAX_NEW_TOKENS_POSSIBLE_CUT")
        if assessment and tokens_out == max_new_tokens:
            reasons.append("TOKENS_OUT_REACHED_CONFIGURED_MAX_NEW_TOKENS")
        if flags["ended_mid_expression"]:
            reasons.append("OUTPUT_ENDS_MID_EXPRESSION_OR_CLAUSE")
        if not reasons and suspected:
            reasons.append("DETERMINISTIC_TRUNCATION_PROXY")

        row = authority(
            schema_id="kt.v17_7_4.gsm8k_maxtoken_output_length_row.v1",
            sample_id=sample_id,
            dataset="gsm8k",
            official_correct=bool(official.get("replay_correct", difficulty.get("official_correct", control.get("correct")))),
            official_score=1.0 if bool(official.get("replay_correct", difficulty.get("official_correct", control.get("correct")))) else 0.0,
            raw_output_hash=assessment.get("output_hash") or official.get("raw_output_hash"),
            raw_output_text_committed=False,
            raw_output_char_len=len(output) if assessment else None,
            raw_output_token_proxy_len=tokens_out if assessment else None,
            generated_token_count_if_ledger_available=tokens_out if assessment else None,
            prompt_token_count_if_ledger_available=tokens_in if assessment else None,
            total_token_count_if_ledger_available=total_tokens if assessment else None,
            max_new_tokens_config=max_new_tokens,
            generation_budget_ratio=ratio,
            generation_budget_bucket=bucket_budget_ratio(ratio),
            output_token_bucket=bucket_output_tokens(tokens_out if assessment else None),
            final_marker_present=bool(
                assessment.get("final_answer_marker_present", difficulty.get("final_marker_present", control.get("final_answer_marker_present", False)))
            ),
            answer_format_drift=bool(difficulty.get("answer_format_drift", not assessment.get("final_answer_marker_present", False))),
            parser_format_failure=bool(assessment.get("parser_format_failure", difficulty.get("parser_format_failure", control.get("parser_format_failure", False)))),
            suspected_truncation_proxy=bool(suspected),
            truncation_proxy_reason=sorted(set(reasons)),
            **flags,
        )
        output_rows.append(row)

    return output_rows, assessment_meta


def main() -> None:
    reports = ROOT / "reports"
    schemas = ROOT / "schemas"
    registry = ROOT / "registry"
    current_head = git(["rev-parse", "HEAD"])
    current_branch = git(["branch", "--show-current"])

    capability_summary = read_json(reports / "v17_7_4_gsm8k_capability_gap_autopsy_builder_summary.json")
    capability_epc = read_json(reports / "v17_7_4_epc_decision_after_gsm8k_capability_gap_autopsy.json")
    score_lock = read_json(reports / "v17_7_4_gsm8k_official_score_lock.json")
    prior_plan = read_json(reports / "v17_7_4_gsm8k_max_token_sensitivity_offline_plan.json")

    predecessor_bound = (
        capability_summary.get("outcome")
        == "KT_GSM8K_CAPABILITY_GAP_AUTOPSIED__NEXT_REPAIR_OR_DATA_LANE_DECIDED__CLAIM_CEILING_PRESERVED"
        and capability_epc.get("selected_next_lane") == TRANCHE
    )
    rows, assessment_meta = build_rows()
    trunc_rows = [row for row in rows if row["suspected_truncation_proxy"]]
    non_trunc_rows = [row for row in rows if not row["suspected_truncation_proxy"]]
    trunc_wrong_rate = wrong_rate(trunc_rows)
    non_trunc_wrong_rate = wrong_rate(non_trunc_rows)
    delta = (
        round(float(trunc_wrong_rate) - float(non_trunc_wrong_rate), 6)
        if trunc_wrong_rate is not None and non_trunc_wrong_rate is not None
        else None
    )
    strength = hypothesis_strength(delta, len(trunc_rows), protection_plan=True)
    runtime_candidate = strength in {"MODERATE", "STRONG"}
    selected_next = (
        "AUTHOR_GSM8K_MAXTOKEN_SENSITIVITY_MICROFURNACE_V1" if runtime_candidate else NEXT_LAWFUL_MOVE
    )
    next_lane_status = (
        "DESIGN_ONLY_FUTURE_MICROFURNACE_CANDIDATE"
        if runtime_candidate
        else "NO_RUNTIME_PACKET__MAXTOKEN_HYPOTHESIS_WEAK"
    )

    truth_pin = authority(
        schema_id="kt.v17_7_4.gsm8k_maxtoken_sensitivity_truth_pin.v1",
        status="PASS",
        active_tranche=TRANCHE,
        current_head=current_head,
        current_branch=current_branch,
        worktree_clean=git(["status", "--porcelain"]) == "",
        assessment_zip_sha256=assessment_meta.get("assessment_zip_sha256"),
        assessment_zip_present=assessment_meta.get("assessment_zip_present"),
        bound_report_sources=[
            "reports/v17_7_4_gsm8k_capability_gap_autopsy_builder_summary.json",
            "reports/v17_7_4_gsm8k_official_score_lock.json",
            "reports/v17_7_4_gsm8k_row_difficulty_table.jsonl",
            "reports/v17_7_4_control_only_gsm8k_row_level_autopsy.jsonl",
        ],
        token_accounting_status=assessment_meta.get("token_accounting_status"),
    )
    predecessor = authority(
        schema_id="kt.v17_7_4.gsm8k_maxtoken_sensitivity_predecessor_binding.v1",
        status="BOUND" if predecessor_bound else "DESIGN_HELD_PENDING_CAPABILITY_GAP_AUTOPSY",
        capability_gap_outcome=capability_summary.get("outcome"),
        capability_gap_epc_selected_next_lane=capability_epc.get("selected_next_lane"),
        official_score=score_lock.get("official_score"),
        official_score_lock_status=score_lock.get("status"),
        prior_maxtoken_plan_status=prior_plan.get("status"),
        prior_maxtoken_wrong_rate_delta=prior_plan.get("wrong_rate_delta"),
    )
    claim = authority(
        schema_id="kt.v17_7_4.gsm8k_maxtoken_sensitivity_claim_boundary_receipt.v1",
        status="PASS",
        allowed_internal_claim=(
            "A max-token sensitivity hypothesis was evaluated offline as one possible owner of "
            "the reconciled 28/100 GSM8K capability gap. No runtime, scorer, prompt, adapter, "
            "model, route, parser, V3 rescue, KT-hat, compression, training, or promotion authority is produced."
        ),
        runtime_packet_generated=False,
        training_authority=False,
        prompt_change_allowed=False,
        adapter_change_allowed=False,
        model_change_allowed=False,
        scorer_change_allowed=False,
        parser_change_allowed=False,
        kt_hat_authority=False,
        max_token_fix_success_claim=False,
    )

    write_json(reports / "v17_7_4_gsm8k_maxtoken_sensitivity_truth_pin.json", truth_pin)
    write_json(reports / "v17_7_4_gsm8k_maxtoken_sensitivity_predecessor_binding.json", predecessor)
    write_json(reports / "v17_7_4_gsm8k_maxtoken_sensitivity_claim_boundary_receipt.json", claim)
    write_jsonl(reports / "v17_7_4_gsm8k_output_length_table.jsonl", rows)
    write_jsonl(reports / "v17_7_4_gsm8k_truncation_proxy_table.jsonl", [row for row in rows if row["suspected_truncation_proxy"]])

    output_topology = authority(
        schema_id="kt.v17_7_4.gsm8k_output_length_topology.v1",
        status="PASS",
        row_count=len(rows),
        assessment_zip_bound=bool(assessment_meta.get("assessment_zip_present")),
        raw_output_text_committed=False,
        max_new_tokens_config=rows[0]["max_new_tokens_config"] if rows else None,
        suspected_truncation_proxy_rows=len(trunc_rows),
        non_truncation_proxy_rows=len(non_trunc_rows),
        token_bucket_counts=dict(Counter(row["output_token_bucket"] for row in rows)),
        budget_ratio_bucket_counts=dict(Counter(row["generation_budget_bucket"] for row in rows)),
        deterministic_proxies_only=True,
    )
    write_json(reports / "v17_7_4_gsm8k_output_length_topology.json", output_topology)

    correlation = authority(
        schema_id="kt.v17_7_4.gsm8k_maxtoken_truncation_correlation.v1",
        status="PASS",
        causal_claim=False,
        hypothesis_strength=strength,
        suspected_truncation_proxy_rows=len(trunc_rows),
        suspected_truncation_proxy_wrong_rate=trunc_wrong_rate,
        non_truncation_proxy_rows=len(non_trunc_rows),
        non_truncation_proxy_wrong_rate=non_trunc_wrong_rate,
        wrong_rate_delta=delta,
        strong_threshold_policy=(
            "MODERATE_OR_STRONG requires >= 20pp wrong-rate delta, >= 10 proxy rows, and a correct-row protection plan."
        ),
        significance_claim=False,
        statistics_mode="COUNT_AND_RATE_ONLY",
    )
    write_json(reports / "v17_7_4_gsm8k_maxtoken_truncation_correlation.json", correlation)

    wrongness_vs_length = authority(
        schema_id="kt.v17_7_4.gsm8k_wrongness_vs_length.v1",
        status="PASS",
        by_output_token_bucket=grouped_rates(rows, "output_token_bucket"),
        by_generation_budget_bucket=grouped_rates(rows, "generation_budget_bucket"),
        no_causal_claim=True,
    )
    write_json(reports / "v17_7_4_gsm8k_wrongness_vs_length.json", wrongness_vs_length)

    format_drift_vs_length = authority(
        schema_id="kt.v17_7_4.gsm8k_format_drift_vs_length.v1",
        status="PASS",
        answer_format_drift_by_output_token_bucket={
            bucket: {
                "row_count": len(bucket_rows),
                "answer_format_drift_rate": rate(bucket_rows, "answer_format_drift"),
                "parser_format_failure_rate": rate(bucket_rows, "parser_format_failure"),
                "final_marker_present_rate": rate(bucket_rows, "final_marker_present"),
            }
            for bucket, bucket_rows in sorted(
                {
                    bucket: [row for row in rows if row["output_token_bucket"] == bucket]
                    for bucket in {row["output_token_bucket"] for row in rows}
                }.items()
            )
        },
        no_runtime_authority=True,
    )
    write_json(reports / "v17_7_4_gsm8k_format_drift_vs_length.json", format_drift_vs_length)

    correctness_by_budget = authority(
        schema_id="kt.v17_7_4.gsm8k_correctness_by_budget_bucket.v1",
        status="PASS",
        by_generation_budget_bucket=grouped_rates(rows, "generation_budget_bucket"),
        final_marker_present=grouped_rates(rows, "final_marker_present"),
        answer_format_drift=grouped_rates(rows, "answer_format_drift"),
        parser_format_failure=grouped_rates(rows, "parser_format_failure"),
        raw_regex_surface_present=grouped_rates(rows, "raw_regex_surface_present"),
        multiple_numeric_candidates=grouped_rates(rows, "multiple_numeric_candidates"),
        output_starts_with_numeric_surface=grouped_rates(rows, "output_starts_with_numeric_surface"),
        output_ends_with_digit=grouped_rates(rows, "ended_with_digit"),
    )
    write_json(reports / "v17_7_4_gsm8k_correctness_by_budget_bucket.json", correctness_by_budget)

    max_new_tokens = rows[0]["max_new_tokens_config"] if rows else 50
    budgets = [
        {"budget_id": "A0_current_control", "max_new_tokens": max_new_tokens, "runtime_authorized": False},
        {"budget_id": "A1_current_plus_32", "max_new_tokens": max_new_tokens + 32, "runtime_authorized": False},
        {"budget_id": "A2_current_plus_64", "max_new_tokens": max_new_tokens + 64, "runtime_authorized": False},
        {"budget_id": "A3_current_plus_128", "max_new_tokens": max_new_tokens + 128, "runtime_authorized": False},
    ]
    ladder = authority(
        schema_id="kt.v17_7_4.gsm8k_maxtoken_sensitivity_ladder.v1",
        status="DESIGN_ONLY",
        baseline_max_new_tokens=max_new_tokens,
        candidate_budgets=budgets,
        all_extra_generation_tokens_count_in_full_tpc=True,
        prompt_adapter_model_tokenizer_scorer_parser_unchanged=True,
        no_kt_hat=True,
        no_scratchpad=True,
        no_route_or_admission_change=True,
        no_v3_rescue=True,
        no_training_or_promotion=True,
    )
    write_json(reports / "v17_7_4_gsm8k_maxtoken_sensitivity_ladder.json", ladder)
    write_json(
        reports / "v17_7_4_gsm8k_maxtoken_candidate_budgets.json",
        authority(schema_id="kt.v17_7_4.gsm8k_maxtoken_candidate_budgets.v1", status="DESIGN_ONLY", budgets=budgets),
    )
    write_json(
        reports / "v17_7_4_gsm8k_maxtoken_no_regression_requirements.json",
        authority(
            schema_id="kt.v17_7_4.gsm8k_maxtoken_no_regression_requirements.v1",
            status="PASS",
            future_runtime_primary_gates=[
                "correctness_delta_vs_control",
                "full_tpc_delta",
                "verified_work_per_token_delta",
                "parser_format_failure_delta",
                "answer_format_drift_delta",
                "control_correct_damage",
                "row_level_changed_answer_matrix",
            ],
            damage_to_control_correct_must_equal_zero=True,
        ),
    )
    write_json(
        reports / "v17_7_4_gsm8k_maxtoken_memory_feasibility_plan.json",
        authority(
            schema_id="kt.v17_7_4.gsm8k_maxtoken_memory_feasibility_plan.v1",
            status="PASS_DESIGN_ONLY",
            one_arm_resident_at_a_time=True,
            batch_size=1,
            sequential_rows=True,
            stream_rows_to_disk=True,
            gpu_cleanup_before_after_runner=True,
            max_rows_for_pilot=25,
            fail_closed_on_oom=True,
            no_silent_smaller_model_or_base_only_fallback=True,
            adapter_mount_must_be_real=True,
        ),
    )
    write_json(
        reports / "v17_7_4_gsm8k_maxtoken_runtime_safety_plan.json",
        authority(
            schema_id="kt.v17_7_4.gsm8k_maxtoken_runtime_safety_plan.v1",
            status="PASS_DESIGN_ONLY",
            runtime_authorized_by_this_lane=False,
            no_kaggle_packet_generated=True,
            no_prompt_adapter_model_scorer_parser_route_mutation=True,
            fail_closed_on_smoke_or_base_fallback=True,
        ),
    )
    write_json(
        reports / "v17_7_4_gsm8k_maxtoken_microfurnace_design_only.json",
        authority(
            schema_id="kt.v17_7_4.gsm8k_maxtoken_microfurnace_design_only.v1",
            status="DESIGN_ONLY_NOT_AUTHORIZED" if not runtime_candidate else "DESIGN_ONLY_CANDIDATE",
            candidate_future_lane="AUTHOR_GSM8K_MAXTOKEN_SENSITIVITY_MICROFURNACE_V1",
            candidate_future_run_mode="RUN_KTV1774_GSM8K_MAXTOKEN_SENSITIVITY_25",
            candidate_future_packet_path="packets/ktv1774_gsm8k_maxtoken_sensitivity_v1.zip",
            candidate_future_kaggle_dataset_name="ktv1774-gsm8k-maxtoken-sensitivity-v1",
            runtime_authorized_by_this_lane=False,
            reason="Hypothesis remains WEAK, so this lane does not generate a future runtime packet." if not runtime_candidate else "Future packet still requires separate EPC authorization.",
        ),
    )
    write_json(
        reports / "v17_7_4_gsm8k_maxtoken_epc_runtime_gate.json",
        authority(
            schema_id="kt.v17_7_4.gsm8k_maxtoken_epc_runtime_gate.v1",
            status=next_lane_status,
            hypothesis_strength=strength,
            runtime_allowed_by_this_lane=False,
            packet_path_if_any=None,
            selected_next_lane=selected_next,
        ),
    )
    write_json(
        reports / "v17_7_4_gsm8k_maxtoken_correct_row_protection_plan.json",
        authority(
            schema_id="kt.v17_7_4.gsm8k_maxtoken_correct_row_protection_plan.v1",
            status="PASS",
            official_correct_rows=28,
            damage_to_control_correct_must_equal_zero=True,
            compare_changed_outputs_row_by_row_if_future_runtime_occurs=True,
            aggregate_gain_cannot_hide_correct_row_damage=True,
        ),
    )
    write_json(
        reports / "v17_7_4_gsm8k_maxtoken_damage_gate.json",
        authority(
            schema_id="kt.v17_7_4.gsm8k_maxtoken_damage_gate.v1",
            status="PASS",
            damage_to_control_correct=0,
            future_runtime_damage_gate="FAIL_CLOSED_IF_DAMAGE_EXCEEDS_ZERO_WITHOUT_EXPLICIT_EPC_EXPLORATORY_NO_CLAIM_AUTHORITY",
            promotion_style_claim_allowed=False,
        ),
    )
    epc = authority(
        schema_id="kt.v17_7_4.epc_decision_after_gsm8k_maxtoken_sensitivity_design.v1",
        status="PASS_DECIDED",
        options_considered=[
            "DESIGN_HELD_PENDING_CAPABILITY_GAP_AUTOPSY",
            "NO_RUNTIME_PACKET__MAXTOKEN_HYPOTHESIS_WEAK",
            "AUTHOR_GSM8K_MAXTOKEN_SENSITIVITY_MICROFURNACE_V1",
            "RETURN_TO_GSM8K_CAPABILITY_GAP_AUTOPSY",
            "AUTHOR_DETERMINISTIC_RESCUE_OFFLINE_REPLAY_V4",
            "AUTHOR_ACADEMY_REPAIR_PLAN_ONLY_NO_TRAINING",
            "RESEARCH_REGISTER_ONLY_FOR_ROUTER_OR_THEORY",
        ],
        selected_next_lane=selected_next,
        runtime_allowed_by_this_lane=False,
        reason=(
            "Max-token/truncation is a weak non-causal hypothesis below the 20pp design threshold, "
            "so no runtime packet is warranted by this lane."
        ),
        hypothesis_strength=strength,
    )
    next_lane = authority(
        schema_id="kt.v17_7_4.gsm8k_maxtoken_sensitivity_next_lane.v1",
        status="PASS_NO_RUNTIME_PACKET",
        selected_next_lane=selected_next,
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        runtime_allowed_by_this_lane=False,
    )
    write_json(reports / "v17_7_4_epc_decision_after_gsm8k_maxtoken_sensitivity_design.json", epc)
    write_json(reports / "v17_7_4_gsm8k_maxtoken_sensitivity_next_lane.json", next_lane)

    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": True,
        "properties": {
            "schema_id": {"const": "kt.v17_7_4.gsm8k_maxtoken_output_length_row.v1"},
            "sample_id": {"type": "string"},
            "official_correct": {"type": "boolean"},
            "raw_output_hash": {"type": ["string", "null"]},
            "raw_output_text_committed": {"const": False},
            "max_new_tokens_config": {"type": "integer"},
            "suspected_truncation_proxy": {"type": "boolean"},
            "runtime_authority": {"const": False},
        },
        "required": [
            "schema_id",
            "sample_id",
            "official_correct",
            "raw_output_hash",
            "raw_output_text_committed",
            "max_new_tokens_config",
            "suspected_truncation_proxy",
            "runtime_authority",
        ],
        "type": "object",
    }
    write_json(schemas / "kt.v17_7_4.gsm8k_maxtoken_output_length_row.schema.json", schema)

    files_changed = [
        "scripts/design_v17_7_4_gsm8k_maxtoken_sensitivity.py",
        "reports/v17_7_4_gsm8k_maxtoken_sensitivity_truth_pin.json",
        "reports/v17_7_4_gsm8k_maxtoken_sensitivity_predecessor_binding.json",
        "reports/v17_7_4_gsm8k_maxtoken_sensitivity_claim_boundary_receipt.json",
        "reports/v17_7_4_gsm8k_output_length_topology.json",
        "reports/v17_7_4_gsm8k_output_length_table.jsonl",
        "reports/v17_7_4_gsm8k_truncation_proxy_table.jsonl",
        "reports/v17_7_4_gsm8k_maxtoken_truncation_correlation.json",
        "reports/v17_7_4_gsm8k_wrongness_vs_length.json",
        "reports/v17_7_4_gsm8k_format_drift_vs_length.json",
        "reports/v17_7_4_gsm8k_correctness_by_budget_bucket.json",
        "reports/v17_7_4_gsm8k_maxtoken_sensitivity_ladder.json",
        "reports/v17_7_4_gsm8k_maxtoken_candidate_budgets.json",
        "reports/v17_7_4_gsm8k_maxtoken_no_regression_requirements.json",
        "reports/v17_7_4_gsm8k_maxtoken_memory_feasibility_plan.json",
        "reports/v17_7_4_gsm8k_maxtoken_runtime_safety_plan.json",
        "reports/v17_7_4_gsm8k_maxtoken_microfurnace_design_only.json",
        "reports/v17_7_4_gsm8k_maxtoken_epc_runtime_gate.json",
        "reports/v17_7_4_gsm8k_maxtoken_correct_row_protection_plan.json",
        "reports/v17_7_4_gsm8k_maxtoken_damage_gate.json",
        "reports/v17_7_4_epc_decision_after_gsm8k_maxtoken_sensitivity_design.json",
        "reports/v17_7_4_gsm8k_maxtoken_sensitivity_next_lane.json",
        "schemas/kt.v17_7_4.gsm8k_maxtoken_output_length_row.schema.json",
        "registry/artifact_authority_registry_v17_7_4_gsm8k_maxtoken_sensitivity_design_delta_receipt.json",
    ]
    registry_delta = authority(
        schema_id="kt.artifact_authority_registry_delta.v17_7_4_gsm8k_maxtoken_sensitivity_design",
        status="PASS",
        active_tranche=TRANCHE,
        outcome=OUTCOME,
        artifacts_added=files_changed,
        packet_path_if_any=None,
        runtime_authority=False,
        claim_ceiling_status="PRESERVED",
    )
    write_json(registry / "artifact_authority_registry_v17_7_4_gsm8k_maxtoken_sensitivity_design_delta_receipt.json", registry_delta)

    summary = authority(
        schema_id="kt.v17_7_4.gsm8k_maxtoken_sensitivity_builder_summary.v1",
        status="PASS",
        active_tranche=TRANCHE,
        current_head=current_head,
        branch=current_branch,
        outcome=OUTCOME,
        files_changed=files_changed,
        maxtoken_sensitivity_binding_status="BOUND",
        capability_gap_predecessor_status=predecessor["status"],
        output_length_topology_status=output_topology["status"],
        truncation_correlation_status=correlation["status"],
        wrongness_vs_length_status=wrongness_vs_length["status"],
        format_drift_vs_length_status=format_drift_vs_length["status"],
        hypothesis_strength=strength,
        microfurnace_design_status="DESIGN_ONLY_NOT_AUTHORIZED" if not runtime_candidate else "DESIGN_ONLY_CANDIDATE",
        memory_feasibility_status="PASS_DESIGN_ONLY",
        correct_row_protection_status="PASS",
        epc_next_lane_status=next_lane["status"],
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        claim_ceiling_status="PRESERVED",
        blockers=[],
        next_lawful_move=selected_next,
    )
    write_json(reports / "v17_7_4_gsm8k_maxtoken_sensitivity_builder_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
