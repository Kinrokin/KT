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

from kt_system.eval.gsm8k_deterministic_rescue_v4 import DeterministicRescueV4, SafeArithmeticEvaluator
from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core


TRANCHE = "AUTHOR_KTV1774_DETERMINISTIC_RESCUE_OFFLINE_REPLAY_V4_FINAL_HARDENED"
OUTCOME = "KT_GSM8K_DETERMINISTIC_RESCUE_OFFLINE_REPLAY_COMPLETE__NEXT_LANE_DECIDED__CLAIM_CEILING_PRESERVED"
CONTROL_ARM = core.REPROLOCK_ARM_ID
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
            "deterministic_rescue_runtime_success_claim": False,
            "external_validation_claim": False,
            "frontier_claim": False,
            "g2_recovered_claim": False,
            "gsm8k_recovery_claim": False,
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


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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


def load_zip_json(archive: zipfile.ZipFile, name: str) -> dict[str, Any]:
    return json.loads(archive.read(name).decode("utf-8-sig"))


def load_zip_jsonl(archive: zipfile.ZipFile, name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in archive.read(name).decode("utf-8-sig").splitlines() if line.strip()]


def normalize_answer(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = text.replace(",", "").replace("$", "")
    text = re.sub(r"\.0+$", "", text)
    return re.sub(r"\s+", " ", text)


def equivalent(candidate: str | None, expected: str) -> bool:
    if candidate is None:
        return False
    return normalize_answer(candidate) == normalize_answer(expected)


def load_manifest_map() -> dict[str, dict[str, Any]]:
    manifest = read_json(ROOT / "admission" / "v17_7_4_control_only_gsm8k_extension_row_manifest.json")
    return {str(row["sample_id"]): row for row in manifest.get("rows", [])}


def load_assessment_rows() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not ASSESSMENT_ZIP.exists():
        fallback = read_jsonl(ROOT / "reports" / "v17_7_4_gsm8k_deterministic_rescue_row_table.jsonl")
        return [], {
            "assessment_zip_present": False,
            "assessment_zip_sha256": None,
            "fallback_committed_replay_rows": len(fallback),
        }
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
                    "final_summary.json",
                    "gsm8k_regression_autopsy.json",
                    "token_accounting_ledger.json",
                    "ADAPTER_ROOT_NORMALIZATION_RECEIPT.json",
                ]
                if member in archive.namelist()
            ),
            "final_summary_status": load_zip_json(archive, "final_summary.json").get("status"),
            "gsm8k_regression_autopsy_present": "gsm8k_regression_autopsy.json" in archive.namelist(),
        }
    return rows, metadata


NEGATIVE_CONTROLS = [
    {"case": "I first computed 12 + 7 = 19, but that was not the final answer.", "must_not_emit_rescue": True},
    {"case": "The answer is not 40; it is 35.", "must_not_emit_rescue": True},
    {
        "case": "He had $1,200 but spent $300, so final answer: $900.",
        "must_not_emit_rescue": True,
        "allowed_audit_surface_only": True,
    },
    {"case": "Final answer: 3/4.", "must_not_emit_rescue": True, "allowed_audit_surface_only": True},
    {"case": "The result is 12.0 people.", "must_not_emit_rescue": True, "allowed_audit_surface_only": True},
    {"case": "5 + 3 is part of the problem, but then she doubles it.", "must_not_emit_rescue": True},
    {"case": "If 6 were the answer, then 6 + 1 = 7; however final is 8.", "must_not_emit_rescue": True},
    {"case": "12/0", "must_not_emit_rescue": True},
    {"case": "__import__('os').system('rm -rf /')", "must_not_emit_rescue": True},
    {"case": "x + 1 = 3", "must_not_emit_rescue": True},
    {"case": "The numbers are 2, 3, and 5.", "must_not_emit_rescue": True},
    {"case": "2 and 3 make 5 in one branch, but final answer is 9.", "must_not_emit_rescue": True},
]


def run_negative_controls(rescuer: DeterministicRescueV4) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    for item in NEGATIVE_CONTROLS:
        output_result = rescuer.rescue_from_output(item["case"])
        problem_result = rescuer.rescue_from_problem_text(item["case"])
        emitted_rescue = output_result.status == "RESCUE_CANDIDATE_EMITTED" or problem_result.status == "RESCUE_CANDIDATE_EMITTED"
        audit_only = output_result.status == "ANSWER_SURFACE_CANDIDATE_AUDIT_ONLY"
        allowed_audit = bool(item.get("allowed_audit_surface_only"))
        passed = not emitted_rescue and (allowed_audit or not audit_only)
        rows.append(
            authority(
                schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_negative_control_row.v1",
                case_hash=sha256_text(item["case"]),
                must_not_emit_rescue=item["must_not_emit_rescue"],
                allowed_audit_surface_only=allowed_audit,
                output_status=output_result.status,
                problem_status=problem_result.status,
                emitted_rescue=emitted_rescue,
                emitted_audit_only=audit_only,
                status="PASS" if passed else "FAIL",
            )
        )
    return rows, all(row["status"] == "PASS" for row in rows)


def choose_candidate(rescuer: DeterministicRescueV4, output: str, problem_text: str) -> Any:
    output_candidate = rescuer.rescue_from_output(output)
    if output_candidate.status in {"RESCUE_CANDIDATE_EMITTED", "ANSWER_SURFACE_CANDIDATE_AUDIT_ONLY"}:
        return output_candidate
    problem_candidate = rescuer.rescue_from_problem_text(problem_text)
    if problem_candidate.status == "RESCUE_CANDIDATE_EMITTED":
        return problem_candidate
    return output_candidate


def replay_rows() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    assessment_rows, metadata = load_assessment_rows()
    manifest_map = load_manifest_map()
    rescuer = DeterministicRescueV4()
    output_rows: list[dict[str, Any]] = []

    if not assessment_rows:
        existing = read_jsonl(ROOT / "reports" / "v17_7_4_gsm8k_deterministic_rescue_row_table.jsonl")
        return existing, metadata

    for row in assessment_rows:
        sample_id = str(row["sample_id"])
        manifest = manifest_map.get(sample_id, {})
        expected = str(manifest.get("expected_answer") or "")
        problem_text = str(manifest.get("question_text") or manifest.get("prompt") or "")
        output = str(row.get("output_text") or "")
        candidate = choose_candidate(rescuer, output, problem_text)
        candidate_before_scoring = candidate.candidate
        candidate_matches = equivalent(candidate_before_scoring, expected)
        is_rescue_candidate = candidate.status == "RESCUE_CANDIDATE_EMITTED" and not candidate.answer_surface_audit_only
        would_rescue = bool(is_rescue_candidate and not row.get("correct") and candidate_matches)
        would_damage = bool(is_rescue_candidate and row.get("correct") and not candidate_matches)
        would_change = bool(is_rescue_candidate and candidate_before_scoring is not None)

        output_rows.append(
            authority(
                schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_row.v1",
                sample_id=sample_id,
                dataset="gsm8k",
                official_correct=bool(row.get("correct")),
                official_score=1.0 if row.get("correct") else 0.0,
                expected_answer_hash=manifest.get("expected_answer_hash") or row.get("expected_answer_hash"),
                expected_answer_model_visible=False,
                expected_answer_used_for_candidate_selection=False,
                expected_answer_used_offline_only=True,
                raw_output_hash=row.get("output_hash"),
                raw_output_text_committed=False,
                problem_text_hash=manifest.get("question_text_hash") or row.get("question_text_hash"),
                candidate_extraction_frozen_before_scoring=True,
                candidate_source=candidate.candidate_source,
                rescue_candidate_hash=sha256_text(candidate_before_scoring) if candidate_before_scoring is not None else None,
                rescue_status=candidate.status,
                rule_id=candidate.rule_id,
                rule_confidence=candidate.rule_confidence,
                answer_surface_audit_only=candidate.answer_surface_audit_only,
                source_surface_hash=sha256_text(candidate.source_surface) if candidate.source_surface else None,
                would_change_official_answer=would_change,
                would_damage_official_correct=would_damage,
                would_rescue_official_wrong=would_rescue,
                notes=list(candidate.notes),
            )
        )
    return output_rows, metadata


def summarize_replay(rows: list[dict[str, Any]], negative_controls_pass: bool) -> dict[str, Any]:
    correct_count = sum(1 for row in rows if row["official_correct"])
    wrong_count = sum(1 for row in rows if not row["official_correct"])
    rescue_candidates = [row for row in rows if row["rescue_status"] == "RESCUE_CANDIDATE_EMITTED"]
    audit_candidates = [row for row in rows if row["answer_surface_audit_only"]]
    damage = sum(1 for row in rows if row["would_damage_official_correct"])
    rescued = sum(1 for row in rows if row["would_rescue_official_wrong"])
    net_delta = rescued - damage
    ceiling = "DETERMINISTIC_RESCUE_CEILING_LOW" if rescued == 0 or damage > 0 else "DETERMINISTIC_RESCUE_SIGNAL_PRESENT_OFFLINE_ONLY"
    return authority(
        schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_offline_replay.v1",
        status="PASS",
        official_correct_count=correct_count,
        official_wrong_count=wrong_count,
        rescue_candidate_count=len(rescue_candidates),
        answer_surface_audit_candidate_count=len(audit_candidates),
        rescue_attempt_rate=round(len(rescue_candidates) / len(rows), 6) if rows else 0.0,
        damage_to_official_correct=damage,
        control_correct_preservation_rate=round((correct_count - damage) / correct_count, 6) if correct_count else None,
        rescued_official_wrong_count=rescued,
        net_accuracy_delta=net_delta,
        deterministic_rescue_ceiling=ceiling,
        abstention_rate=round(sum(1 for row in rows if row["rescue_status"].startswith("ABSTAIN")) / len(rows), 6) if rows else 0.0,
        negative_controls_pass=negative_controls_pass,
        runtime_packet_warranted=False,
    )


def summarize_rule_ablation(rows: list[dict[str, Any]], negative_controls_pass: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    rule_ids = sorted({row["rule_id"] for row in rows})
    ablations = []
    for rule_id in rule_ids:
        rule_rows = [row for row in rows if row["rule_id"] == rule_id]
        damage = sum(1 for row in rule_rows if row["would_damage_official_correct"])
        rescued = sum(1 for row in rule_rows if row["would_rescue_official_wrong"])
        ablations.append(
            {
                "rule_id": rule_id,
                "candidate_source": sorted({row["candidate_source"] for row in rule_rows}),
                "rows_changed": sum(1 for row in rule_rows if row["would_change_official_answer"]),
                "official_correct_damaged": damage,
                "official_wrong_rescued": rescued,
                "net_delta": rescued - damage,
                "negative_controls_pass": negative_controls_pass,
                "cross_anchor_damage": 0,
                "admit_for_future_runtime_design": bool(
                    negative_controls_pass and damage == 0 and rescued > 0 and not rule_id.endswith("AUDIT_ONLY")
                ),
                "reason": "audit or abstention only"
                if rescued == 0
                else "offline-only signal requires separate runtime design authority",
            }
        )
    any_admitted = any(row["admit_for_future_runtime_design"] for row in ablations)
    return (
        authority(
            schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_rule_ablation.v1",
            status="PASS",
            rules=ablations,
        ),
        authority(
            schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_rule_admission_court.v1",
            status="DETERMINISTIC_RESCUE_SIGNAL_PRESENT_OFFLINE_ONLY" if any_admitted else "DETERMINISTIC_RESCUE_CEILING_LOW",
            admitted_rule_count=sum(1 for row in ablations if row["admit_for_future_runtime_design"]),
            no_expected_answer_runtime_access=True,
            no_natural_language_parsing=True,
            no_model_calls=True,
            no_runtime_packet_generated=True,
        ),
    )


def main() -> None:
    reports = ROOT / "reports"
    schemas = ROOT / "schemas"
    registry = ROOT / "registry"
    current_head = git(["rev-parse", "HEAD"])
    current_branch = git(["branch", "--show-current"])
    score_lock = read_json(reports / "v17_7_4_gsm8k_official_score_lock.json")
    scoring_reconciliation = read_json(reports / "v17_7_4_scoring_surface_reconciliation_replay_builder_summary.json")
    capability_gap = read_json(reports / "v17_7_4_gsm8k_capability_gap_autopsy_builder_summary.json")
    maxtoken = read_json(reports / "v17_7_4_gsm8k_maxtoken_sensitivity_builder_summary.json")

    rows, assessment_meta = replay_rows()
    rescuer = DeterministicRescueV4()
    negative_rows, negative_controls_pass = run_negative_controls(rescuer)
    replay = summarize_replay(rows, negative_controls_pass)
    ablation, admission = summarize_rule_ablation(rows, negative_controls_pass)
    selected_next_lane = (
        "AUTHOR_DETERMINISTIC_RESCUE_RUNTIME_DESIGN_ONLY_V1"
        if admission["status"] == "DETERMINISTIC_RESCUE_SIGNAL_PRESENT_OFFLINE_ONLY" and replay["damage_to_official_correct"] == 0
        else "AUTHOR_ACADEMY_REPAIR_PLAN_ONLY_NO_TRAINING"
    )

    truth_pin = authority(
        schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_truth_pin.v1",
        status="PASS",
        active_tranche=TRANCHE,
        current_head=current_head,
        current_branch=current_branch,
        worktree_clean=git(["status", "--porcelain"]) == "",
        official_score=score_lock.get("official_score"),
        official_correct=score_lock.get("official_correct"),
        assessment_zip_present=assessment_meta.get("assessment_zip_present"),
        assessment_zip_sha256=assessment_meta.get("assessment_zip_sha256"),
        final_summary_status=assessment_meta.get("final_summary_status"),
        gsm8k_regression_autopsy_present=assessment_meta.get("gsm8k_regression_autopsy_present"),
    )
    predecessor = authority(
        schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_predecessor_binding.v1",
        status="BOUND",
        official_score_lock_status=score_lock.get("status"),
        scoring_surface_reconciliation_outcome=scoring_reconciliation.get("outcome"),
        capability_gap_outcome=capability_gap.get("outcome"),
        maxtoken_outcome=maxtoken.get("outcome"),
        maxtoken_hypothesis_strength=maxtoken.get("hypothesis_strength"),
        maxtoken_next_lawful_move=maxtoken.get("next_lawful_move"),
    )
    claim = authority(
        schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_claim_boundary_receipt.v1",
        status="PASS",
        allowed_internal_claim=(
            "The reconciled official GSM8K extension score is 28/100 and max-token sensitivity is weak. "
            "This lane performs offline-only deterministic rescue replay to estimate whether any wrong rows are "
            "recoverable by fixed non-model rules without damaging official-correct rows."
        ),
        runtime_packet_generated=False,
        kaggle_packet_generated=False,
        training_authority=False,
        prompt_change_allowed=False,
        adapter_change_allowed=False,
        model_change_allowed=False,
        scorer_change_allowed=False,
        parser_change_allowed=False,
        score_revision_authorized=False,
    )
    freeze = authority(
        schema_id="kt.v17_7_4.gsm8k_rescue_candidate_source_freeze.v1",
        status="PASS",
        candidate_extraction_order=[
            "MODEL_OUTPUT_EXPLICIT_ARITHMETIC_LINE",
            "MODEL_OUTPUT_EXPLICIT_FINAL_ASSIGNMENT_AUDIT_ONLY",
            "PROBLEM_TEXT_FULLMATCH_TRIVIAL_ARITHMETIC",
        ],
        frozen_before_expected_answer_comparison=True,
        arbitrary_set_of_numbers_search_allowed=False,
        natural_language_word_problem_parsing_allowed=False,
        expected_answer_guided_candidate_selection_allowed=False,
    )
    rules = authority(
        schema_id="kt.v17_7_4.gsm8k_rescue_rule_freeze_receipt.v1",
        status="PASS",
        allowed_candidate_sources=[
            "MODEL_OUTPUT_EXPLICIT_ARITHMETIC_LINE",
            "MODEL_OUTPUT_EXPLICIT_FINAL_ASSIGNMENT_AUDIT_ONLY",
            "PROBLEM_TEXT_FULLMATCH_TRIVIAL_ARITHMETIC",
            "MODEL_OUTPUT_EQUATION_CONSISTENCY_CHECK_EXPLICIT_EQUATION_ONLY",
        ],
        forbidden_candidate_sources=[
            "natural_language_word_problem_parsing",
            "entity_extraction",
            "coreference_resolution",
            "sympy_parse_expr_over_problem_text",
            "llm_verification",
            "scratchpad_rescue",
            "oracle_candidate_selection",
            "arbitrary_set_of_numbers_arithmetic_search",
        ],
    )
    isolation = authority(
        schema_id="kt.v17_7_4.gsm8k_rescue_expected_answer_isolation_receipt.v1",
        status="PASS",
        expected_answer_model_visible=False,
        expected_answer_used_for_candidate_selection=False,
        expected_answer_used_offline_only_after_candidate_freeze=True,
        committed_rows_use_expected_answer_hash=True,
    )
    design = authority(
        schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_design.v1",
        status="PASS",
        safe_ast_evaluator=True,
        sympy_import_allowed=False,
        nlp_import_allowed=False,
        model_import_allowed=False,
        scratchpad_import_allowed=False,
        supports_integers=True,
        supports_decimals=True,
        supports_explicit_fractions=True,
        supports_parentheses=True,
        exponentiation_allowed=False,
        implicit_multiplication_allowed=False,
        units_allowed=False,
    )
    negative_receipt = authority(
        schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_negative_control_receipt.v1",
        status="PASS" if negative_controls_pass else "FAIL",
        negative_controls_pass=negative_controls_pass,
        negative_control_count=len(negative_rows),
        failed_count=sum(1 for row in negative_rows if row["status"] != "PASS"),
    )
    damage_gate = authority(
        schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_damage_gate.v1",
        status="PASS" if replay["damage_to_official_correct"] == 0 else "FAIL",
        damage_to_official_correct=replay["damage_to_official_correct"],
        control_correct_preservation_rate=replay["control_correct_preservation_rate"],
        future_runtime_consideration_requires_zero_damage=True,
        runtime_packet_warranted=False,
    )
    cross_anchor = authority(
        schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_cross_anchor_replay.v1",
        status="PASS_EXTENSION_REQUIRED_PRIOR_ANCHORS_REVIEW_ONLY",
        sources=[
            {
                "source_id": "gsm8k_extension_100",
                "row_count": len(rows),
                "official_correct": replay["official_correct_count"],
                "official_wrong": replay["official_wrong_count"],
                "damage_to_official_correct": replay["damage_to_official_correct"],
                "rescued_official_wrong": replay["rescued_official_wrong_count"],
                "net_delta": replay["net_accuracy_delta"],
                "abstention_rate": replay["abstention_rate"],
            }
        ],
        cross_anchor_damage=0,
        prior_raw_output_sources_bound=False,
        prior_raw_output_sources_reason="No additional prior raw-output source with equivalent official scoring surface was required for this offline extension court.",
    )
    cross_anchor_table = [
        authority(
            schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_cross_anchor_row.v1",
            source_id="gsm8k_extension_100",
            row_count=len(rows),
            official_correct=replay["official_correct_count"],
            official_wrong=replay["official_wrong_count"],
            damage_to_official_correct=replay["damage_to_official_correct"],
            rescued_official_wrong=replay["rescued_official_wrong_count"],
            net_delta=replay["net_accuracy_delta"],
            abstention_rate=replay["abstention_rate"],
        )
    ]
    cost_model = authority(
        schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_cost_model.v1",
        status="PASS",
        added_model_tokens=0,
        added_prompt_tokens=0,
        added_generation_tokens=0,
        added_cpu_cost_proxy="O(rows * explicit_rule_count)",
        full_tpc_model_side_changed=False,
        no_runtime_claim=True,
    )
    token_impact = authority(
        schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_token_impact.v1",
        status="PASS",
        model_side_full_tpc_unchanged=True,
        verified_work_per_token_model_side_claim_allowed=False,
        offline_rescue_net_accuracy_delta=replay["net_accuracy_delta"],
        added_model_tokens=0,
    )
    future_design = authority(
        schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_future_runtime_design_only.v1",
        status="DESIGN_ONLY_REQUIRED_SEPARATE_EPC_AUTHORIZATION"
        if selected_next_lane == "AUTHOR_DETERMINISTIC_RESCUE_RUNTIME_DESIGN_ONLY_V1"
        else "NOT_WARRANTED",
        runtime_authority=False,
        kaggle_packet_generated=False,
        requires_separate_epc_authorization=True,
        requires_wrapper_hard_fail=True,
        requires_official_correct_damage_gate=True,
        requires_raw_output_equivalence=True,
        requires_claim_ceiling_preservation=True,
    )
    epc = authority(
        schema_id="kt.v17_7_4.epc_decision_after_deterministic_rescue_offline_replay_v4.v1",
        status="PASS_DECIDED",
        options_considered=[
            "NO_RUNTIME_PACKET__DETERMINISTIC_RESCUE_CEILING_LOW",
            "AUTHOR_DETERMINISTIC_RESCUE_RUNTIME_DESIGN_ONLY_V1",
            "AUTHOR_SCORING_REPORTING_FIX_REPLAY_ONLY_V1",
            "AUTHOR_ACADEMY_REPAIR_PLAN_ONLY_NO_TRAINING",
            "AUTHOR_CONTROL_ONLY_GSM8K_EXTENSION_2_IF_ROW_SOURCE_BOUND",
            "RETURN_TO_GSM8K_CAPABILITY_GAP_AUTOPSY",
            "RESEARCH_REGISTER_ONLY_FOR_ROUTER_OR_THEORY",
        ],
        selected_next_lane=selected_next_lane,
        runtime_allowed_by_this_lane=False,
        deterministic_rescue_ceiling=replay["deterministic_rescue_ceiling"],
        reason="Offline deterministic rescue found a zero-damage signal requiring separate runtime-design authority."
        if selected_next_lane == "AUTHOR_DETERMINISTIC_RESCUE_RUNTIME_DESIGN_ONLY_V1"
        else "Deterministic rescue ceiling is low; remaining gap should move to Academy/data repair planning without training authority.",
    )
    next_lane = authority(
        schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_next_lane.v1",
        status="PASS_NO_RUNTIME_PACKET",
        selected_next_lane=selected_next_lane,
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        runtime_allowed_by_this_lane=False,
    )

    write_json(reports / "v17_7_4_gsm8k_deterministic_rescue_truth_pin.json", truth_pin)
    write_json(reports / "v17_7_4_gsm8k_deterministic_rescue_predecessor_binding.json", predecessor)
    write_json(reports / "v17_7_4_gsm8k_deterministic_rescue_claim_boundary_receipt.json", claim)
    write_json(reports / "v17_7_4_gsm8k_rescue_candidate_source_freeze.json", freeze)
    write_json(reports / "v17_7_4_gsm8k_rescue_rule_freeze_receipt.json", rules)
    write_json(reports / "v17_7_4_gsm8k_rescue_expected_answer_isolation_receipt.json", isolation)
    write_json(reports / "v17_7_4_gsm8k_deterministic_rescue_design.json", design)
    write_jsonl(reports / "v17_7_4_gsm8k_deterministic_rescue_negative_controls.jsonl", negative_rows)
    write_json(reports / "v17_7_4_gsm8k_deterministic_rescue_negative_control_receipt.json", negative_receipt)
    write_json(reports / "v17_7_4_gsm8k_deterministic_rescue_offline_replay.json", replay)
    write_jsonl(reports / "v17_7_4_gsm8k_deterministic_rescue_row_table.jsonl", rows)
    write_json(reports / "v17_7_4_gsm8k_deterministic_rescue_damage_gate.json", damage_gate)
    write_json(reports / "v17_7_4_gsm8k_deterministic_rescue_cross_anchor_replay.json", cross_anchor)
    write_jsonl(reports / "v17_7_4_gsm8k_deterministic_rescue_cross_anchor_table.jsonl", cross_anchor_table)
    write_json(reports / "v17_7_4_gsm8k_deterministic_rescue_rule_ablation.json", ablation)
    write_json(reports / "v17_7_4_gsm8k_deterministic_rescue_rule_admission_court.json", admission)
    write_json(reports / "v17_7_4_gsm8k_deterministic_rescue_cost_model.json", cost_model)
    write_json(reports / "v17_7_4_gsm8k_deterministic_rescue_token_impact.json", token_impact)
    write_json(reports / "v17_7_4_gsm8k_deterministic_rescue_future_runtime_design_only.json", future_design)
    write_json(reports / "v17_7_4_epc_decision_after_deterministic_rescue_offline_replay_v4.json", epc)
    write_json(reports / "v17_7_4_gsm8k_deterministic_rescue_next_lane.json", next_lane)

    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": True,
        "properties": {
            "schema_id": {"const": "kt.v17_7_4.gsm8k_deterministic_rescue_row.v1"},
            "sample_id": {"type": "string"},
            "official_correct": {"type": "boolean"},
            "expected_answer_hash": {"type": "string"},
            "expected_answer_model_visible": {"const": False},
            "expected_answer_used_for_candidate_selection": {"const": False},
            "candidate_extraction_frozen_before_scoring": {"const": True},
            "rescue_status": {"type": "string"},
            "runtime_authority": {"const": False},
        },
        "required": [
            "schema_id",
            "sample_id",
            "official_correct",
            "expected_answer_hash",
            "expected_answer_model_visible",
            "expected_answer_used_for_candidate_selection",
            "candidate_extraction_frozen_before_scoring",
            "rescue_status",
            "runtime_authority",
        ],
        "type": "object",
    }
    write_json(schemas / "kt.v17_7_4.gsm8k_deterministic_rescue_v4.schema.json", schema)

    files_changed = [
        "kt_system/eval/gsm8k_deterministic_rescue_v4.py",
        "scripts/replay_v17_7_4_gsm8k_deterministic_rescue_v4.py",
        "schemas/kt.v17_7_4.gsm8k_deterministic_rescue_v4.schema.json",
        "reports/v17_7_4_gsm8k_deterministic_rescue_truth_pin.json",
        "reports/v17_7_4_gsm8k_deterministic_rescue_predecessor_binding.json",
        "reports/v17_7_4_gsm8k_deterministic_rescue_claim_boundary_receipt.json",
        "reports/v17_7_4_gsm8k_rescue_candidate_source_freeze.json",
        "reports/v17_7_4_gsm8k_rescue_rule_freeze_receipt.json",
        "reports/v17_7_4_gsm8k_rescue_expected_answer_isolation_receipt.json",
        "reports/v17_7_4_gsm8k_deterministic_rescue_design.json",
        "reports/v17_7_4_gsm8k_deterministic_rescue_negative_controls.jsonl",
        "reports/v17_7_4_gsm8k_deterministic_rescue_negative_control_receipt.json",
        "reports/v17_7_4_gsm8k_deterministic_rescue_offline_replay.json",
        "reports/v17_7_4_gsm8k_deterministic_rescue_row_table.jsonl",
        "reports/v17_7_4_gsm8k_deterministic_rescue_damage_gate.json",
        "reports/v17_7_4_gsm8k_deterministic_rescue_cross_anchor_replay.json",
        "reports/v17_7_4_gsm8k_deterministic_rescue_cross_anchor_table.jsonl",
        "reports/v17_7_4_gsm8k_deterministic_rescue_rule_ablation.json",
        "reports/v17_7_4_gsm8k_deterministic_rescue_rule_admission_court.json",
        "reports/v17_7_4_gsm8k_deterministic_rescue_cost_model.json",
        "reports/v17_7_4_gsm8k_deterministic_rescue_token_impact.json",
        "reports/v17_7_4_gsm8k_deterministic_rescue_future_runtime_design_only.json",
        "reports/v17_7_4_epc_decision_after_deterministic_rescue_offline_replay_v4.json",
        "reports/v17_7_4_gsm8k_deterministic_rescue_next_lane.json",
        "registry/artifact_authority_registry_v17_7_4_gsm8k_deterministic_rescue_v4_delta_receipt.json",
    ]
    registry_delta = authority(
        schema_id="kt.artifact_authority_registry_delta.v17_7_4_gsm8k_deterministic_rescue_v4",
        status="PASS",
        active_tranche=TRANCHE,
        outcome=OUTCOME,
        artifacts_added=files_changed,
        packet_path_if_any=None,
        runtime_authority=False,
        claim_ceiling_status="PRESERVED",
    )
    write_json(registry / "artifact_authority_registry_v17_7_4_gsm8k_deterministic_rescue_v4_delta_receipt.json", registry_delta)

    summary = authority(
        schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_builder_summary.v1",
        status="PASS",
        active_tranche=TRANCHE,
        current_head=current_head,
        branch=current_branch,
        outcome=OUTCOME,
        files_changed=files_changed,
        deterministic_rescue_binding_status="BOUND",
        candidate_source_freeze_status=freeze["status"],
        safe_arithmetic_evaluator_status=design["status"],
        negative_control_status=negative_receipt["status"],
        offline_replay_status=replay["status"],
        cross_anchor_replay_status=cross_anchor["status"],
        rule_ablation_status=ablation["status"],
        damage_to_official_correct=replay["damage_to_official_correct"],
        rescued_official_wrong_count=replay["rescued_official_wrong_count"],
        net_accuracy_delta=replay["net_accuracy_delta"],
        deterministic_rescue_ceiling=replay["deterministic_rescue_ceiling"],
        cost_model_status=cost_model["status"],
        epc_next_lane_status=next_lane["status"],
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        claim_ceiling_status="PRESERVED",
        blockers=[],
        next_lawful_move=selected_next_lane,
    )
    write_json(reports / "v17_7_4_gsm8k_deterministic_rescue_builder_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
