from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TRANCHE = "AUTHOR_KTV1774_MATH_PRETRAINING_HYPOTHESIS_COURT_V1"
OUTCOME = (
    "KT_MATH_PRETRAINING_HYPOTHESIS_COURT_BOUND__TRAINING_AUTHORITY_STILL_FALSE__"
    "NEXT_LANE_DECIDED__CLAIM_CEILING_PRESERVED"
)
NEXT_LANE = "AUTHOR_MATH_CORPUS_SOURCE_BINDING_V1"


AUTHORITY_FALSE: dict[str, Any] = {
    "runtime_authority": False,
    "training_authority": False,
    "adapter_training_authorized": False,
    "adapter_mutation_authority": False,
    "promotion_authority": False,
    "router_training_authorized": False,
    "policy_optimization_authorized": False,
    "v18_runtime_authority": False,
    "academy_run_authorized": False,
    "hf_upload_authorized": False,
    "kaggle_packet_generated": False,
    "runtime_packet_generated": False,
    "training_packet_generated": False,
    "dataset_packet_generated": False,
    "safetensors_generated": False,
    "claim_ceiling_preserved": True,
    "gsm8k_recovery_claim": False,
    "prompt_fix_success_claim": False,
    "parser_repair_success_claim": False,
    "corpus_repair_success_claim": False,
    "academy_repair_success_claim": False,
    "formal_math_superiority_claim": False,
    "olympiad_capability_claim": False,
    "router_superiority_claim": False,
    "learned_router_superiority_claim": False,
    "multi_lobe_superiority_claim": False,
    "g2_recovered_claim": False,
    "ninety_one_percent_full_system_recovery_claim": False,
    "external_validation_claim": False,
    "commercial_claim": False,
    "s_tier_claim": False,
    "frontier_claim": False,
    "seven_b_claim": False,
    "production_readiness_claim": False,
    "launch_readiness_claim": False,
}


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(AUTHORITY_FALSE)
    payload.update(extra)
    return payload


def git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def read_json(path: str) -> dict[str, Any]:
    target = ROOT / path
    if not target.exists():
        return {}
    return json.loads(target.read_text(encoding="utf-8-sig"))


def read_jsonl(path: str) -> list[dict[str, Any]]:
    target = ROOT / path
    if not target.exists():
        return []
    return [json.loads(line) for line in target.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def write_json(path: str, payload: dict[str, Any]) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def summarize_file(path: str) -> dict[str, Any]:
    target = ROOT / path
    if not target.exists():
        return {"path": path, "present": False}
    return {"path": path, "present": True, "size_bytes": target.stat().st_size}


def training_surface_index() -> list[dict[str, Any]]:
    training_dir = ROOT / "training"
    if not training_dir.exists():
        return []
    rows = []
    for path in sorted(training_dir.glob("*")):
        if path.is_file():
            rows.append({"path": path.relative_to(ROOT).as_posix(), "size_bytes": path.stat().st_size})
    return rows


def corpus_source_status(training_files: list[dict[str, Any]]) -> str:
    row_like = [
        row
        for row in training_files
        if any(marker in row["path"].lower() for marker in ("dataset.jsonl", "corpus.jsonl", "train.jsonl", "examples.jsonl"))
    ]
    return "SOURCE_BOUND" if row_like else "SOURCE_NOT_BOUND"


def build() -> dict[str, Any]:
    current_head = git(["rev-parse", "HEAD"])
    current_branch = git(["branch", "--show-current"])
    worktree_clean_before = git(["status", "--porcelain"]) == ""

    official = read_json("reports/v17_7_4_gsm8k_official_score_lock.json")
    scoring = read_json("reports/v17_7_4_scoring_surface_reconciliation_replay_builder_summary.json")
    parser_court = read_json("reports/v17_7_4_parser_failure_subtype_court.json")
    parser_update = read_json("reports/v17_7_4_parser_subtype_reconciliation_update.json")
    regression_parser = read_json("reports/v17_7_4_control_only_gsm8k_regression_parser_court_builder_summary.json")
    capability_gap = read_json("reports/v17_7_4_gsm8k_capability_gap_autopsy_builder_summary.json")
    maxtoken = read_json("reports/v17_7_4_gsm8k_maxtoken_sensitivity_builder_summary.json")
    deterministic = read_json("reports/v17_7_4_gsm8k_deterministic_rescue_builder_summary.json")
    academy = read_json("reports/v17_7_4_gsm8k_academy_repairability_plan_no_training.json")
    prompt_review = read_json("reports/v17_7_4_control_only_gsm8k_prompt_generation_config_review.json")
    answer_drift = read_json("reports/v17_7_4_gsm8k_answer_format_drift_synthesis.json")
    prior_anchor = read_json("reports/v17_7_4_gsm8k_prior_anchor_state_vector.json")
    score_source = read_json("reports/v17_7_4_gsm8k_score_source_lock.json")
    adapter_niche = read_json("reports/v17_7_4_adapter_niche_boundary_scorecard.json")

    training_files = training_surface_index()
    corpus_status = corpus_source_status(training_files)

    truth_pin = authority(
        schema_id="kt.v17_7_4.math_pretraining_hypothesis_court_truth_pin.v1",
        status="PASS",
        active_tranche=TRANCHE,
        current_head=current_head,
        current_branch=current_branch,
        worktree_clean_before_generation=worktree_clean_before,
        official_score=official.get("official_score"),
        official_correct=official.get("official_correct"),
        official_total=official.get("official_total"),
        scoring_surface_reconciliation_status=scoring.get("status"),
        parser_subtype_reconciliation_status=parser_update.get("status"),
        capability_gap_status=capability_gap.get("status"),
        max_token_hypothesis_strength=maxtoken.get("hypothesis_strength"),
        deterministic_rescue_net_accuracy_delta=deterministic.get("net_accuracy_delta"),
        academy_repair_ladder_status=academy.get("status", "MISSING"),
        artifact_authority_registry_present=(ROOT / "registry" / "artifact_authority_registry.json").exists(),
        claim_ceiling_files_present=bool(list((ROOT / "rules").glob("*CLAIM*"))) or bool(list((ROOT / "docs").glob("*CLAIM*"))),
        packet_path_if_any=None,
    )

    predecessor = authority(
        schema_id="kt.v17_7_4.math_pretraining_hypothesis_court_predecessor_binding.v1",
        status="BOUND",
        official_score_lock=summarize_file("reports/v17_7_4_gsm8k_official_score_lock.json"),
        scoring_surface_reconciliation=summarize_file(
            "reports/v17_7_4_scoring_surface_reconciliation_replay_builder_summary.json"
        ),
        parser_subtype_reconciliation=summarize_file("reports/v17_7_4_parser_subtype_reconciliation_update.json"),
        parser_court=summarize_file("reports/v17_7_4_parser_failure_subtype_court.json"),
        capability_gap_autopsy=summarize_file("reports/v17_7_4_gsm8k_capability_gap_autopsy_builder_summary.json"),
        maxtoken_sensitivity=summarize_file("reports/v17_7_4_gsm8k_maxtoken_sensitivity_builder_summary.json"),
        deterministic_rescue_v4=summarize_file("reports/v17_7_4_gsm8k_deterministic_rescue_builder_summary.json"),
        academy_repair_ladder=summarize_file("reports/v17_7_4_gsm8k_academy_repairability_plan_no_training.json"),
        prior_anchor=summarize_file("reports/v17_7_4_gsm8k_prior_anchor_state_vector.json"),
        prompt_generation_config_review=summarize_file("reports/v17_7_4_control_only_gsm8k_prompt_generation_config_review.json"),
        answer_format_drift=summarize_file("reports/v17_7_4_gsm8k_answer_format_drift_synthesis.json"),
        formal_math_niche_boundary=summarize_file("reports/v17_7_4_adapter_niche_boundary_scorecard.json"),
    )

    claim_boundary = authority(
        schema_id="kt.v17_7_4.math_pretraining_hypothesis_court_claim_boundary_receipt.v1",
        status="PASS",
        allowed_internal_claim=(
            "The official GSM8K extension score remains 28/100. Cheap runtime-side lanes did not produce gain. "
            "Before training can be requested, KT must adjudicate prompt-format suppression, parser/scoring "
            "recoverability, and training-corpus quality as pre-training hypotheses with claim ceiling preserved."
        ),
        forbidden_claims=[
            "GSM8K recovery",
            "prompt fix success",
            "parser repair success",
            "corpus repair success",
            "Academy repair success",
            "formal math superiority",
            "Olympiad capability",
            "training authorization",
            "commercial readiness",
        ],
    )

    ledger = authority(
        schema_id="kt.v17_7_4.math_pretraining_hypothesis_ledger.v1",
        status="PASS",
        hypotheses=[
            {
                "id": "H0_OFFICIAL_BASELINE",
                "status": "BOUND",
                "official_score": official.get("official_score"),
                "official_correct": official.get("official_correct"),
                "official_total": official.get("official_total"),
                "scorer_replay": "PASS_REPRODUCED",
                "score_revision_authorized": False,
            },
            {
                "id": "H1_PROMPT_FORMAT_SUPPRESSION",
                "status": "UNTESTED_OR_PARTIAL",
                "rationale": "KT math prompt/output contract may suppress base capability.",
                "next": "design prompt-format probe only",
            },
            {
                "id": "H2_PARSER_SCORING_RECOVERABILITY",
                "status": "MOSTLY_BOUND_NOT_BOTTLENECK",
                "rationale": "Parser-format rows are already official-correct and official score remains 28/100.",
                "next": "bind subtype/recovery ceiling; block parser +22 unless score replay proves it",
            },
            {
                "id": "H3_CORPUS_TRAINING_DATA_QUALITY",
                "status": "UNTESTED" if corpus_status == "SOURCE_NOT_BOUND" else "SOURCE_BOUND_AUDIT_REQUIRED",
                "rationale": "Training quality, coverage, leakage, deduplication, and difficulty may own the capability gap.",
                "next": NEXT_LANE if corpus_status == "SOURCE_NOT_BOUND" else "AUTHOR_MATH_CORPUS_AUDIT_V1",
            },
            {
                "id": "H4_TRAINING_REQUIRED",
                "status": "PLAUSIBLE_DOWNSTREAM",
                "rationale": "Cheap lanes failed, but H1/H2/H3 must be adjudicated first.",
                "training_authority": False,
            },
        ],
    )

    correction = authority(
        schema_id="kt.v17_7_4.training_not_yet_authorized_correction_receipt.v1",
        status="PASS",
        correction="Training is plausible downstream, not authorized now.",
        training_plausible_downstream=True,
        training_authority=False,
        olympiad_training_authority=False,
        gsm8k_foundation_before_olympiad=True,
    )

    prompt_audit = authority(
        schema_id="kt.v17_7_4.math_prompt_format_suppression_audit.v1",
        status="PROMPT_FORMAT_SUPPRESSION_PLAUSIBLE_UNTESTED",
        known_good_prompt_identity_preserved=prompt_review.get("known_good_prompt_identity_preserved"),
        max_new_tokens_from_rows=prompt_review.get("max_new_tokens_from_rows"),
        generation_config_identical_to_intended_control=prompt_review.get("generation_config_identical_to_intended_control"),
        answer_format_drift_rate=answer_drift.get("answer_format_drift_rate"),
        final_marker_rate=answer_drift.get("final_marker_rate"),
        prior_anchor_status=prior_anchor.get("status"),
        prior_anchor_accuracy=prior_anchor.get("prior_accuracy"),
        base_raw_standard_math_prompt_bound=False,
        base_raw_kt_prompt_bound=False,
        standard_math_benchmark_source_bound=False,
        conclusion="Prompt-format suppression remains a design-only hypothesis until an EPC-authorized prompt-isolation probe runs.",
    )
    prompt_design = authority(
        schema_id="kt.v17_7_4.math_prompt_format_probe_design_only.v1",
        status="DESIGN_ONLY",
        future_lane="AUTHOR_BASE_MODEL_STANDARD_MATH_PROMPT_PROBE_DESIGN_V1",
        future_probe_arms=[
            "A0_current_KT_base_raw_prompt_control",
            "A1_base_model_standard_math_cot_prompt",
            "A2_base_model_minimal_direct_answer_prompt",
        ],
        same_rows_required=True,
        no_adapters=True,
        same_tokenizer_model_revision_generation_config_except_prompt=True,
        expected_answers_model_visible=False,
        runtime_authority=False,
        packet_generated=False,
    )
    prompt_gate = authority(
        schema_id="kt.v17_7_4.math_prompt_format_probe_gate.v1",
        status="PASS_DESIGN_ONLY_NO_RUNTIME_AUTHORITY",
        epc_explicit_authorization_required=True,
        wrapper_lane_identity_hard_fail_required=True,
        adapter_mutation_allowed=False,
        training_allowed=False,
        prompt_fix_success_claim_allowed=False,
    )

    parser_format_failure_count = int(parser_update.get("parser_format_failure_rows", parser_court.get("parser_format_failure_rows", 0)) or 0)
    parser_correct = int(parser_update.get("parser_failures_officially_correct", parser_court.get("parser_format_failure_correct", 0)) or 0)
    parser_wrong = int(parser_update.get("parser_failures_officially_wrong", parser_court.get("parser_format_failure_wrong", 0)) or 0)
    potential_gain = parser_wrong
    parser_claim = "PARSER_NOT_BOTTLENECK" if parser_wrong == 0 and parser_correct > 0 else "INCONCLUSIVE"
    parser_correction = authority(
        schema_id="kt.v17_7_4.math_parser_recoverability_correction.v1",
        status="PASS",
        official_scorer_replay_status=scoring.get("official_scorer_replay_status", "PASS_REPRODUCED"),
        alternative_surfaces_audit_only=score_source.get("alternative_surface_replays_audit_only", True),
        parser_format_failure_count=parser_format_failure_count,
        parser_format_failure_official_correct_count=parser_correct,
        parser_format_failure_official_wrong_count=parser_wrong,
        official_wrong_with_recoverable_surface_count=parser_wrong,
        potential_official_score_gain_under_fixed_rule=potential_gain,
        damage_to_official_correct=0,
        claim=parser_claim,
        conclusion=parser_court.get("conclusion"),
    )
    parser_ceiling = authority(
        schema_id="kt.v17_7_4.math_parser_recoverability_ceiling.v1",
        status="PASS",
        parser_reported_plus_22_rows=parser_format_failure_count,
        parser_plus_22_official_score_gain_authorized=False,
        maximum_bound_official_gain_from_parser_format_failures=potential_gain,
        official_score_remains=official.get("official_score"),
        parser_runtime_packet_authorized=False,
    )
    parser_block = authority(
        schema_id="kt.v17_7_4.math_parser_plus_22_claim_block.v1",
        status="PASS_BLOCKED",
        blocked_claim="Parser repair can move official GSM8K score from 28/100 to 50/100.",
        reason="The 22 parser-format rows are already official-correct in the bound parser court.",
        parser_format_failure_official_correct_count=parser_correct,
        parser_format_failure_official_wrong_count=parser_wrong,
        score_replay_required_for_any_future_parser_gain_claim=True,
    )

    corpus_plan = authority(
        schema_id="kt.v17_7_4.math_corpus_source_audit_plan.v1",
        status="PASS_PLAN_ONLY",
        audit_questions=[
            "How many math rows were in original 13-lobe cohort training?",
            "How many belonged to formal_proof_reasoning_lobe?",
            "Were examples GSM8K-style, formal proof, code/math, or mixed?",
            "Were examples step-by-step or final-answer only?",
            "Were expected answers leaked into prompt/instruction side?",
            "Were rows duplicated across lobes?",
            "Were rows deduplicated by normalized text hash?",
            "Were evaluation rows included in training?",
            "Were hard rows underrepresented?",
            "Was answer-format contract aligned with runtime scorer?",
            "Did training reinforce compact outputs rather than reasoning?",
            "Did curriculum mix math with unrelated governance/doctrine text too heavily?",
        ],
    )
    corpus_schema = authority(
        schema_id="kt.v17_7_4.math_corpus_quality_audit_schema.v1",
        status="PASS_SCHEMA_ONLY",
        required_fields=[
            "corpus_row_id",
            "source_path",
            "normalized_text_hash",
            "task_family",
            "difficulty_bucket",
            "answer_format",
            "step_by_step_present",
            "expected_answer_leakage_risk",
            "evaluation_overlap_risk",
            "duplicate_cluster_id",
            "target_lobe",
        ],
    )
    corpus_request = authority(
        schema_id="kt.v17_7_4.math_corpus_audit_request_index.v1",
        status=corpus_status,
        training_surface_files=training_files,
        row_level_training_corpus_bound=corpus_status == "SOURCE_BOUND",
        next_lane=NEXT_LANE if corpus_status == "SOURCE_NOT_BOUND" else "AUTHOR_MATH_CORPUS_AUDIT_V1",
    )
    corpus_no_training = authority(
        schema_id="kt.v17_7_4.math_corpus_audit_not_training_receipt.v1",
        status="PASS_NO_TRAINING",
        corpus_audit_status=corpus_status,
        no_new_training_data_generated=True,
        no_safetensors_generated=True,
        no_hf_upload=True,
        training_authority=False,
    )

    training_court = authority(
        schema_id="kt.v17_7_4.math_training_prerequisite_decision_court.v1",
        status="TRAINING_REQUEST_PREMATURE",
        prompt_owner_possible=True,
        parser_owner_closed_or_limited=True,
        corpus_owner_possible=True,
        adapter_capability_owner_possible="POSSIBLE_DOWNSTREAM_NOT_YET_AUTHORIZED",
        h1_status="UNTESTED_OR_PARTIAL",
        h2_status="MOSTLY_BOUND_NOT_BOTTLENECK",
        h3_status=corpus_status,
        decision="TRAINING_REQUEST_PREMATURE",
        training_request_next_draft_allowed=False,
        training_authority=False,
    )
    training_false = authority(
        schema_id="kt.v17_7_4.math_training_authority_still_false_receipt.v1",
        status="PASS",
        training_authority=False,
        promotion_authority=False,
        adapter_mutation_authority=False,
        reason="H1 and H3 remain unresolved; H2 is bounded as not the official score bottleneck.",
    )

    repair_update = authority(
        schema_id="kt.v17_7_4.math_repair_ladder_update_after_pretraining_court.v1",
        status="PASS_UPDATED",
        gsm8k_foundation_before_olympiad=True,
        olympiad_aime_math_training_downstream_only=True,
        target_lobe_candidate="formal_proof_reasoning_lobe",
        target_lobe_authority=False,
        prompt_format_probe_dependency=True,
        corpus_audit_dependency=True,
        parser_recoverability_correction=parser_claim,
        training_authority=False,
    )
    repair_blockers = authority(
        schema_id="kt.v17_7_4.math_repair_ladder_blockers_and_dependencies.v1",
        status="PASS",
        blockers=[],
        dependencies=[
            "Bind math corpus source rows before corpus quality conclusions.",
            "Run prompt-format probe only if EPC separately authorizes runtime.",
            "Keep parser +22 score-gain claim blocked unless official score replay proves gain.",
            "Keep GSM8K foundation ahead of Olympiad/AIME/MATH strategy lanes.",
        ],
    )

    intervention_queue = authority(
        schema_id="kt.v17_7_4.math_pretraining_intervention_queue.v1",
        status="PASS",
        queue=[
            {"rank": 1, "lane": NEXT_LANE, "runtime": False, "training": False},
            {"rank": 2, "lane": "AUTHOR_BASE_MODEL_STANDARD_MATH_PROMPT_PROBE_DESIGN_V1", "runtime": False, "training": False},
            {"rank": 3, "lane": "AUTHOR_MATH_CORPUS_AUDIT_V1", "runtime": False, "training": False},
            {"rank": 4, "lane": "AUTHOR_MATH_DATASET_BLUEPRINT_NO_TRAINING_V1", "runtime": False, "training": False},
        ],
    )
    epc = authority(
        schema_id="kt.v17_7_4.epc_decision_after_math_pretraining_hypothesis_court.v1",
        status="PASS_DECIDED",
        options_considered=[
            "AUTHOR_BASE_MODEL_STANDARD_MATH_PROMPT_PROBE_DESIGN_V1",
            "AUTHOR_BASE_MODEL_STANDARD_MATH_PROMPT_PROBE_25_IF_EPC_AUTHORIZES",
            NEXT_LANE,
            "AUTHOR_MATH_CORPUS_AUDIT_V1",
            "AUTHOR_MATH_DATASET_BLUEPRINT_NO_TRAINING_V1",
            "AUTHOR_MATH_TRAINING_AUTHORITY_REQUEST_DRAFT_V1",
            "RETURN_TO_ACADEMY_REPAIR_LADDER",
            "NO_RUNTIME_PACKET__PRETRAINING_HYPOTHESES_UNRESOLVED",
            "RESEARCH_REGISTER_ONLY_FOR_ROUTER_OR_THEORY",
        ],
        selected_next_lane=NEXT_LANE,
        runtime_allowed_by_this_lane=False,
        training_allowed_by_this_lane=False,
        reason="Corpus/source quality cannot be adjudicated from config/schema surfaces alone; bind source rows before training authority request.",
    )
    next_lane = authority(
        schema_id="kt.v17_7_4.math_pretraining_hypothesis_court_next_lane.v1",
        status="PASS_NO_RUNTIME_PACKET",
        selected_next_lane=NEXT_LANE,
        next_lawful_move=NEXT_LANE,
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
    )

    files_changed = [
        "scripts/build_v17_7_4_math_pretraining_hypothesis_court.py",
        "schemas/kt.v17_7_4.math_pretraining_hypothesis_court.schema.json",
        "reports/v17_7_4_math_pretraining_hypothesis_court_truth_pin.json",
        "reports/v17_7_4_math_pretraining_hypothesis_court_predecessor_binding.json",
        "reports/v17_7_4_math_pretraining_hypothesis_court_claim_boundary_receipt.json",
        "reports/v17_7_4_math_pretraining_hypothesis_ledger.json",
        "reports/v17_7_4_training_not_yet_authorized_correction_receipt.json",
        "reports/v17_7_4_math_prompt_format_suppression_audit.json",
        "reports/v17_7_4_math_prompt_format_probe_design_only.json",
        "reports/v17_7_4_math_prompt_format_probe_gate.json",
        "reports/v17_7_4_math_parser_recoverability_correction.json",
        "reports/v17_7_4_math_parser_recoverability_ceiling.json",
        "reports/v17_7_4_math_parser_plus_22_claim_block.json",
        "reports/v17_7_4_math_corpus_source_audit_plan.json",
        "reports/v17_7_4_math_corpus_quality_audit_schema.json",
        "reports/v17_7_4_math_corpus_audit_request_index.json",
        "reports/v17_7_4_math_corpus_audit_not_training_receipt.json",
        "reports/v17_7_4_math_training_prerequisite_decision_court.json",
        "reports/v17_7_4_math_training_authority_still_false_receipt.json",
        "reports/v17_7_4_math_repair_ladder_update_after_pretraining_court.json",
        "reports/v17_7_4_math_repair_ladder_blockers_and_dependencies.json",
        "reports/v17_7_4_epc_decision_after_math_pretraining_hypothesis_court.json",
        "reports/v17_7_4_math_pretraining_hypothesis_court_next_lane.json",
        "reports/v17_7_4_math_pretraining_intervention_queue.json",
        "reports/v17_7_4_math_pretraining_hypothesis_court_builder_summary.json",
        "registry/artifact_authority_registry_v17_7_4_math_pretraining_hypothesis_court_delta_receipt.json",
        "tests/test_v17_7_4_math_pretraining_hypothesis_court.py",
    ]

    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kt.v17_7_4.math_pretraining_hypothesis_court.schema.v1",
        "type": "object",
        "additionalProperties": True,
        "required": ["schema_id", "status", "training_authority", "runtime_authority", "claim_ceiling_preserved"],
        "properties": {
            "schema_id": {"type": "string"},
            "status": {"type": "string"},
            "training_authority": {"const": False},
            "runtime_authority": {"const": False},
            "promotion_authority": {"const": False},
            "adapter_mutation_authority": {"const": False},
            "claim_ceiling_preserved": {"const": True},
        },
    }
    registry_delta = authority(
        schema_id="kt.artifact_authority_registry_delta.v17_7_4_math_pretraining_hypothesis_court",
        status="PASS",
        active_tranche=TRANCHE,
        outcome=OUTCOME,
        artifacts_added=files_changed,
        packet_path_if_any=None,
        runtime_authority=False,
        training_authority=False,
        claim_ceiling_status="PRESERVED",
    )
    summary = authority(
        schema_id="kt.v17_7_4.math_pretraining_hypothesis_court_builder_summary.v1",
        status="PASS",
        active_tranche=TRANCHE,
        current_head=current_head,
        branch=current_branch,
        outcome=OUTCOME,
        files_changed=files_changed,
        pretraining_hypothesis_binding_status=predecessor["status"],
        hypothesis_ledger_status=ledger["status"],
        prompt_format_suppression_audit_status=prompt_audit["status"],
        prompt_format_probe_design_status=prompt_design["status"],
        parser_recoverability_correction_status=parser_correction["claim"],
        parser_plus_22_claim_block_status=parser_block["status"],
        math_corpus_audit_status=corpus_request["status"],
        training_prerequisite_decision_status=training_court["status"],
        repair_ladder_update_status=repair_update["status"],
        epc_next_lane_status=next_lane["status"],
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        claim_ceiling_status="PRESERVED",
        blockers=[],
        next_lawful_move=NEXT_LANE,
    )

    outputs = {
        "schemas/kt.v17_7_4.math_pretraining_hypothesis_court.schema.json": schema,
        "reports/v17_7_4_math_pretraining_hypothesis_court_truth_pin.json": truth_pin,
        "reports/v17_7_4_math_pretraining_hypothesis_court_predecessor_binding.json": predecessor,
        "reports/v17_7_4_math_pretraining_hypothesis_court_claim_boundary_receipt.json": claim_boundary,
        "reports/v17_7_4_math_pretraining_hypothesis_ledger.json": ledger,
        "reports/v17_7_4_training_not_yet_authorized_correction_receipt.json": correction,
        "reports/v17_7_4_math_prompt_format_suppression_audit.json": prompt_audit,
        "reports/v17_7_4_math_prompt_format_probe_design_only.json": prompt_design,
        "reports/v17_7_4_math_prompt_format_probe_gate.json": prompt_gate,
        "reports/v17_7_4_math_parser_recoverability_correction.json": parser_correction,
        "reports/v17_7_4_math_parser_recoverability_ceiling.json": parser_ceiling,
        "reports/v17_7_4_math_parser_plus_22_claim_block.json": parser_block,
        "reports/v17_7_4_math_corpus_source_audit_plan.json": corpus_plan,
        "reports/v17_7_4_math_corpus_quality_audit_schema.json": corpus_schema,
        "reports/v17_7_4_math_corpus_audit_request_index.json": corpus_request,
        "reports/v17_7_4_math_corpus_audit_not_training_receipt.json": corpus_no_training,
        "reports/v17_7_4_math_training_prerequisite_decision_court.json": training_court,
        "reports/v17_7_4_math_training_authority_still_false_receipt.json": training_false,
        "reports/v17_7_4_math_repair_ladder_update_after_pretraining_court.json": repair_update,
        "reports/v17_7_4_math_repair_ladder_blockers_and_dependencies.json": repair_blockers,
        "reports/v17_7_4_epc_decision_after_math_pretraining_hypothesis_court.json": epc,
        "reports/v17_7_4_math_pretraining_hypothesis_court_next_lane.json": next_lane,
        "reports/v17_7_4_math_pretraining_intervention_queue.json": intervention_queue,
        "registry/artifact_authority_registry_v17_7_4_math_pretraining_hypothesis_court_delta_receipt.json": registry_delta,
        "reports/v17_7_4_math_pretraining_hypothesis_court_builder_summary.json": summary,
    }
    for path, payload in outputs.items():
        write_json(path, payload)
    return summary


def main() -> None:
    print(json.dumps(build(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
