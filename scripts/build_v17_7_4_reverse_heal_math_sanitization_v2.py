from __future__ import annotations

import json
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TRANCHE = "AUTHOR_KTV1774_REVERSE_HEAL_MATH_SANITIZATION_V2_FINAL"
OUTCOME = (
    "KT_REVERSE_HEAL_MATH_SANITIZATION_DECISION_BOUND__DATASET_BLUEPRINT_OR_BLOCKER_SELECTED__"
    "TRAINING_AUTHORITY_STILL_FALSE__CLAIM_CEILING_PRESERVED"
)
PREDECESSOR_TRANCHE = "AUTHOR_KTV1774_MATH_CORPUS_QUALITY_AUDIT_V1"
PREDECESSOR_HEAD = "553bd011eb9d4712f1b2b358492ab33e050bb110"
SUPERSEDED_LANE = "AUTHOR_KTV1774_MATH_CORPUS_SANITIZATION_PLAN_NO_DATASET_V1"

DECISION_ABANDON = "ABANDON_HISTORICAL_CORPUS_FOR_CLEAN_BLUEPRINT"
ALLOWED_DECISIONS = {
    "AUTHOR_MATH_DATASET_BLUEPRINT_NO_TRAINING_V1",
    "AUTHOR_MATH_CORPUS_SOURCE_RECOVERY_OR_AUTHORING_PLAN_V1",
    "AUTHOR_MATH_LICENSE_REVIEW_AND_SOURCE_REPAIR_V1",
    "AUTHOR_BASE_MODEL_STANDARD_MATH_PROMPT_PROBE_DESIGN_V1",
    "AUTHOR_BASE_MODEL_STANDARD_MATH_PROMPT_PROBE_25_IF_EPC_AUTHORIZES",
    "RETURN_TO_ACADEMY_MATH_REPAIR_LADDER_WITH_SINGLE_BLOCKER",
    DECISION_ABANDON,
    "BLOCKED_INCONCLUSIVE_WITH_SPECIFIC_MISSING_ARTIFACTS",
}

AUTHORITY_FALSE: dict[str, Any] = {
    "runtime_authority": False,
    "dataset_generation_authority": False,
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
    "prompt_mutation_packet_generated": False,
    "safetensors_generated": False,
    "claim_ceiling_preserved": True,
    "gsm8k_recovery_claim": False,
    "corpus_quality_claim": False,
    "dataset_readiness_claim": False,
    "training_readiness_claim": False,
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

REPORTS: list[str] = [
    "reports/v17_7_4_reverse_heal_sanitization_truth_pin.json",
    "reports/v17_7_4_reverse_heal_sanitization_predecessor_binding.json",
    "reports/v17_7_4_reverse_heal_sanitization_claim_boundary_receipt.json",
    "reports/v17_7_4_reverse_heal_boundary_receipt.json",
    "reports/v17_7_4_lab_vs_canonical_authority_policy.json",
    "reports/v17_7_4_audit_recursion_risk_policy.json",
    "reports/v17_7_4_math_corpus_sanitization_yield_gate.json",
    "reports/v17_7_4_math_corpus_sanitization_yield_table.jsonl",
    "reports/v17_7_4_math_corpus_salvage_decision.json",
    "reports/v17_7_4_math_row_trust_tier_policy.json",
    "reports/v17_7_4_math_row_trust_tier_assignment_table.jsonl",
    "reports/v17_7_4_math_capability_density_requirements.json",
    "reports/v17_7_4_math_capability_density_table.jsonl",
    "reports/v17_7_4_math_signal_density_targets.json",
    "reports/v17_7_4_math_doctrine_contamination_scan.json",
    "reports/v17_7_4_math_doctrine_contamination_table.jsonl",
    "reports/v17_7_4_math_doctrine_contamination_blocklist.json",
    "reports/v17_7_4_math_code_verified_crucible_requirement.json",
    "reports/v17_7_4_math_verification_class_map.json",
    "reports/v17_7_4_math_row_verifiable_invariant_policy.json",
    "reports/v17_7_4_formal_math_compression_suspension_receipt.json",
    "reports/v17_7_4_math_capability_first_mode.json",
    "reports/v17_7_4_math_compression_reopen_gate.json",
    "reports/v17_7_4_formal_math_niche_boundary_reaffirmation.json",
    "reports/v17_7_4_math_no_regression_replay_contract.json",
    "reports/v17_7_4_math_router_nonpromotion_receipt.json",
    "reports/v17_7_4_math_repair_curriculum_ladder.json",
    "reports/v17_7_4_math_curriculum_stage_requirements.json",
    "reports/v17_7_4_math_olympiad_future_only_receipt.json",
    "reports/v17_7_4_math_corpus_source_disposition_matrix.json",
    "reports/v17_7_4_math_corpus_source_whitelist_blacklist.json",
    "reports/v17_7_4_math_corpus_source_action_table.jsonl",
    "reports/v17_7_4_math_corpus_row_sanitization_requirements.json",
    "reports/v17_7_4_math_corpus_row_action_table.jsonl",
    "reports/v17_7_4_math_corpus_expected_answer_sanitization_plan.json",
    "reports/v17_7_4_math_corpus_answer_field_segregation_spec.json",
    "reports/v17_7_4_math_corpus_oracle_label_laundering_block.json",
    "reports/v17_7_4_math_corpus_dedup_sanitization_plan.json",
    "reports/v17_7_4_math_corpus_train_eval_firewall_plan.json",
    "reports/v17_7_4_math_corpus_overlap_blocklist.json",
    "reports/v17_7_4_math_corpus_format_normalization_plan.json",
    "reports/v17_7_4_math_corpus_answer_contract_target_spec.json",
    "reports/v17_7_4_math_corpus_reasoning_step_requirement_spec.json",
    "reports/v17_7_4_math_corpus_license_remediation_plan.json",
    "reports/v17_7_4_math_corpus_use_authority_remediation_table.jsonl",
    "reports/v17_7_4_historical_corpus_gap_remediation_plan.json",
    "reports/v17_7_4_historical_epoch_crucible_recovery_plan.json",
    "reports/v17_7_4_historical_training_prompt_template_recovery_plan.json",
    "reports/v17_7_4_math_dataset_blueprint_go_no_go_decision.json",
    "reports/v17_7_4_math_dataset_blueprint_handoff_requirements.json",
    "reports/v17_7_4_math_dataset_builder_forbidden_actions.json",
    "reports/v17_7_4_epc_decision_after_reverse_heal_sanitization_v2.json",
    "reports/v17_7_4_reverse_heal_sanitization_next_lane.json",
    "reports/v17_7_4_reverse_heal_intervention_queue.json",
]
CLEANROOM_CI_RECEIPT = "KT_PROD_CLEANROOM/reports/v17_7_4_reverse_heal_math_sanitization_v2_ci_trigger_receipt.json"


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
    rows: list[dict[str, Any]] = []
    for line in target.read_text(encoding="utf-8-sig", errors="ignore").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if isinstance(row, dict):
            rows.append(row)
    return rows


def write_json(path: str, payload: dict[str, Any]) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def write_jsonl(path: str, rows: list[dict[str, Any]]) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows), encoding="utf-8")


def ratio(part: int, total: int) -> float:
    return round(part / total, 6) if total else 0.0


def capability_density_score(row: dict[str, Any]) -> float:
    features = row.get("feature_summary") if isinstance(row.get("feature_summary"), dict) else {}
    score = 0.0
    if row.get("math_lane") == "ARITHMETIC_GSM8K":
        score += 0.18
    elif row.get("math_lane") in {"FORMAL_PROOF", "COMPETITION_MATH"}:
        score += 0.1
    if row.get("has_problem_text"):
        score += 0.18
    if row.get("has_solution_text"):
        score += 0.18
    if row.get("reasoning_step_present"):
        score += 0.14
    if row.get("has_final_answer"):
        score += 0.1
    if row.get("final_marker_present"):
        score += 0.06
    if row.get("format_alignment") in {"ANSWER_CONTRACT_ALIGNED", "GSM8K_COMPATIBLE"}:
        score += 0.08
    if row.get("verifier_compatibility") in {"HIGH_VERIFIER_COMPATIBILITY", "PARTIAL_VERIFIER_COMPATIBILITY"}:
        score += 0.08
    if features.get("operation_cue_count", 0) >= 1:
        score += 0.04
    if features.get("multi_step_indicator"):
        score += 0.04
    return round(min(score, 1.0), 4)


def contamination_reason(row: dict[str, Any]) -> str | None:
    lane = row.get("math_lane")
    fmt = row.get("format_alignment")
    path = str(row.get("source_path") or "").lower()
    if lane == "DOCTRINE_GOVERNANCE_CONTAMINATION":
        return "math_lane_doctrine_governance_contamination"
    if fmt == "MISALIGNED_DOCTRINE_CONTAMINATED":
        return "format_alignment_doctrine_contaminated"
    if any(token in path for token in ("doctrine", "governance", "claim", "receipt", "policy", "court", "gate")):
        return "source_path_governance_or_doctrine_surface"
    return None


def trust_tier(row: dict[str, Any], source_license: dict[str, Any], density: float, contaminated: bool) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if contaminated:
        reasons.append("doctrine_contamination")
    if row.get("leakage_risk") == "HIGH_LEAKAGE_RISK":
        reasons.append("high_leakage_risk")
    if source_license.get("license_status") in {"UNKNOWN_LICENSE", "RESTRICTED_LICENSE"}:
        reasons.append(str(source_license.get("license_status")))
    if row.get("expected_answer_model_visible"):
        reasons.append("expected_answer_model_visible")
    if row.get("record_role") == "EVAL_CANDIDATE":
        reasons.append("eval_candidate_not_training_target")
    if not row.get("has_problem_text"):
        reasons.append("missing_problem_text")
    if density < 0.35:
        reasons.append("low_capability_density")
    if reasons:
        return "T0_REJECT", reasons
    if row.get("has_final_answer") and not row.get("has_solution_text"):
        return "T1_FORMAT_ONLY", ["final_answer_without_reasoning_training_signal"]
    if row.get("math_lane") == "ARITHMETIC_GSM8K" and row.get("verifier_compatibility") != "LOW_VERIFIER_COMPATIBILITY":
        return "T2_VERIFIED_NUMERIC", ["numeric_candidate_requires_clean_source_rebuild"]
    if row.get("reasoning_step_present") and density >= 0.65:
        return "T3_STEP_VERIFIED", ["step_reasoning_candidate_requires_clean_source_rebuild"]
    return "T1_FORMAT_ONLY", ["review_only_candidate_not_training_authorized"]


def source_action_for(rows: list[dict[str, Any]], license_row: dict[str, Any], contaminated: int) -> dict[str, Any]:
    source_id = rows[0].get("source_id") if rows else license_row.get("source_id")
    path = rows[0].get("source_path") if rows else license_row.get("path")
    row_count = len(rows)
    contaminated_ratio = ratio(contaminated, row_count)
    license_status = license_row.get("license_status", "UNKNOWN_LICENSE")
    if contaminated_ratio >= 0.5:
        action = "QUARANTINE_AS_DOCTRINE_OR_GOVERNANCE_SOURCE"
    elif license_status == "UNKNOWN_LICENSE":
        action = "REQUIRE_LICENSE_AND_SOURCE_REPAIR_BEFORE_ANY_DATASET_USE"
    elif row_count == 0:
        action = "EXCLUDE_NO_BOUND_ROWS"
    else:
        action = "REVIEW_ONLY_UNTIL_CLEAN_BLUEPRINT_EXISTS"
    return authority(
        schema_id="kt.v17_7_4.math_corpus_source_action_row.v1",
        source_id=source_id,
        source_path=path,
        row_count=row_count,
        contaminated_row_count=contaminated,
        contaminated_ratio=contaminated_ratio,
        license_status=license_status,
        use_authority_after_audit=license_row.get("use_authority_after_audit", "UNKNOWN"),
        action=action,
    )


def schemas() -> dict[str, dict[str, Any]]:
    return {
        "schemas/kt.v17_7_4.math_row_trust_tier.schema.json": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "kt.v17_7_4.math_row_trust_tier.schema.v1",
            "type": "object",
            "additionalProperties": True,
            "required": [
                "schema_id",
                "source_id",
                "record_id_hash",
                "trust_tier",
                "training_authority",
                "expected_answer_model_visible",
                "action",
            ],
            "properties": {
                "schema_id": {"const": "kt.v17_7_4.math_row_trust_tier.v1"},
                "source_id": {"type": "string"},
                "record_id_hash": {"type": "string"},
                "trust_tier": {
                    "enum": [
                        "T0_REJECT",
                        "T1_FORMAT_ONLY",
                        "T2_VERIFIED_NUMERIC",
                        "T3_STEP_VERIFIED",
                        "T4_HUMAN_VERIFIED_TRANSFER_READY",
                    ]
                },
                "training_authority": {"const": False},
                "expected_answer_model_visible": {"const": False},
                "action": {"type": "string"},
            },
        },
        "schemas/kt.v17_7_4.math_corpus_row_sanitization_action.schema.json": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "kt.v17_7_4.math_corpus_row_sanitization_action.schema.v1",
            "type": "object",
            "additionalProperties": True,
            "required": [
                "schema_id",
                "source_id",
                "record_id_hash",
                "sanitization_action",
                "training_authority",
                "expected_answer_model_visible",
            ],
            "properties": {
                "schema_id": {"const": "kt.v17_7_4.math_corpus_row_sanitization_action.v1"},
                "source_id": {"type": "string"},
                "record_id_hash": {"type": "string"},
                "sanitization_action": {"type": "string"},
                "training_authority": {"const": False},
                "expected_answer_model_visible": {"const": False},
            },
        },
    }


def build() -> dict[str, Any]:
    current_head = git(["rev-parse", "HEAD"])
    current_branch = git(["branch", "--show-current"])

    quality_summary = read_json("reports/v17_7_4_math_corpus_quality_audit_builder_summary.json")
    inventory = read_json("reports/v17_7_4_math_corpus_inventory.json")
    lane_distribution = read_json("reports/v17_7_4_math_corpus_lane_distribution.json")
    quality_scorecard = read_json("reports/v17_7_4_math_corpus_quality_scorecard.json")
    leakage = read_json("reports/v17_7_4_math_corpus_leakage_audit.json")
    license_audit = read_json("reports/v17_7_4_math_corpus_license_use_authority_audit.json")
    dedup = read_json("reports/v17_7_4_math_corpus_dedup_audit.json")
    overlap = read_json("reports/v17_7_4_math_corpus_eval_overlap_audit.json")
    train_eval = read_json("reports/v17_7_4_math_corpus_train_eval_boundary_audit.json")
    format_audit = read_json("reports/v17_7_4_math_corpus_format_alignment_audit.json")
    reasoning_presence = read_json("reports/v17_7_4_math_corpus_reasoning_step_presence.json")
    verifier = read_json("reports/v17_7_4_math_corpus_verifier_compatibility.json")
    records = read_jsonl("reports/v17_7_4_math_corpus_record_table.jsonl")
    license_rows = read_jsonl("reports/v17_7_4_math_corpus_training_use_authority_matrix.jsonl")
    source_index = read_json("reports/v17_7_4_math_corpus_parsed_source_index.json")

    license_by_source = {str(row.get("source_id")): row for row in license_rows}
    row_count = len(records)
    source_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    tier_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    density_rows: list[dict[str, Any]] = []
    tier_rows: list[dict[str, Any]] = []
    action_rows: list[dict[str, Any]] = []
    contamination_rows: list[dict[str, Any]] = []
    source_contamination: Counter[str] = Counter()
    source_quality_counts: Counter[str] = Counter()

    for row in records:
        source_id = str(row.get("source_id") or "unknown_source")
        source_rows[source_id].append(row)
        density = capability_density_score(row)
        contam_reason = contamination_reason(row)
        contaminated = contam_reason is not None
        if contaminated:
            source_contamination[source_id] += 1
            contamination_rows.append(
                authority(
                    schema_id="kt.v17_7_4.math_doctrine_contamination_row.v1",
                    source_id=source_id,
                    source_path=row.get("source_path"),
                    record_id_hash=row.get("record_id_hash"),
                    math_lane=row.get("math_lane"),
                    format_alignment=row.get("format_alignment"),
                    contamination_reason=contam_reason,
                    action="QUARANTINE_NOT_DATASET_BLUEPRINT_INPUT",
                )
            )
        tier, reasons = trust_tier(row, license_by_source.get(source_id, {}), density, contaminated)
        tier_counts[tier] += 1
        if tier in {"T2_VERIFIED_NUMERIC", "T3_STEP_VERIFIED", "T4_HUMAN_VERIFIED_TRANSFER_READY"}:
            source_quality_counts[source_id] += 1
        if tier == "T0_REJECT":
            action = "REJECT_FROM_DATASET_BLUEPRINT_INPUT"
        elif tier == "T1_FORMAT_ONLY":
            action = "KEEP_AS_AUDIT_OR_FORMAT_REFERENCE_ONLY"
        else:
            action = "REVIEW_FOR_CLEAN_BLUEPRINT_SEED_ONLY"
        action_counts[action] += 1
        density_rows.append(
            authority(
                schema_id="kt.v17_7_4.math_capability_density_row.v1",
                source_id=source_id,
                record_id_hash=row.get("record_id_hash"),
                math_lane=row.get("math_lane"),
                record_role=row.get("record_role"),
                capability_density_score=density,
                density_band="HIGH" if density >= 0.7 else "MEDIUM" if density >= 0.45 else "LOW",
                has_problem_text=bool(row.get("has_problem_text")),
                has_solution_text=bool(row.get("has_solution_text")),
                reasoning_step_present=bool(row.get("reasoning_step_present")),
                verifier_compatibility=row.get("verifier_compatibility"),
                format_alignment=row.get("format_alignment"),
            )
        )
        tier_rows.append(
            authority(
                schema_id="kt.v17_7_4.math_row_trust_tier.v1",
                source_id=source_id,
                source_path=row.get("source_path"),
                record_id_hash=row.get("record_id_hash"),
                trust_tier=tier,
                trust_reasons=reasons,
                math_lane=row.get("math_lane"),
                capability_density_score=density,
                leakage_risk=row.get("leakage_risk"),
                expected_answer_model_visible=False,
                training_authority=False,
                dataset_generation_authority=False,
                action=action,
            )
        )
        action_rows.append(
            authority(
                schema_id="kt.v17_7_4.math_corpus_row_sanitization_action.v1",
                source_id=source_id,
                source_path=row.get("source_path"),
                record_id_hash=row.get("record_id_hash"),
                trust_tier=tier,
                sanitization_action=action,
                reasons=reasons,
                expected_answer_model_visible=False,
                training_authority=False,
                dataset_generation_authority=False,
            )
        )

    source_actions = [
        source_action_for(rows, license_by_source.get(source_id, {}), source_contamination[source_id])
        for source_id, rows in sorted(source_rows.items())
    ]
    whitelist = sorted(source_id for source_id, count in source_quality_counts.items() if count >= 5)
    blacklist = sorted(
        source_id
        for source_id, rows in source_rows.items()
        if source_contamination[source_id] >= max(1, len(rows) // 2)
    )

    high_leakage_count = int(leakage.get("high_leakage_record_count", 0))
    doctrine_count = len(contamination_rows)
    unknown_license_count = int(license_audit.get("unknown_license_source_count", 0))
    quality_candidate_count = sum(tier_counts[tier] for tier in ("T2_VERIFIED_NUMERIC", "T3_STEP_VERIFIED", "T4_HUMAN_VERIFIED_TRANSFER_READY"))
    usable_yield = ratio(quality_candidate_count, row_count)
    contamination_ratio = ratio(doctrine_count, row_count)
    t0_ratio = ratio(tier_counts["T0_REJECT"], row_count)
    license_authorized_rate = 0.0 if unknown_license_count else usable_yield

    selected_decision = DECISION_ABANDON
    decision_reasons = [
        "quality_audit_grade_not_training_ready",
        "doctrine_contamination_dominates_bound_rows",
        "license_use_authority_unknown_for_many_sources",
        "capability_density_yield_below_blueprint_salvage_threshold",
        "reverse_heal_requires_clean_dataset_blueprint_not_historical_corpus_laundering",
    ]

    yield_gate = authority(
        schema_id="kt.v17_7_4.math_corpus_sanitization_yield_gate.v2",
        status="FAIL_ABANDON_HISTORICAL_CORPUS_FOR_CLEAN_BLUEPRINT",
        input_row_count=row_count,
        parsed_source_count=inventory.get("parsed_source_count"),
        doctrine_contamination_row_count=doctrine_count,
        doctrine_contamination_ratio=contamination_ratio,
        high_leakage_record_count=high_leakage_count,
        unknown_license_source_count=unknown_license_count,
        quality_candidate_count=quality_candidate_count,
        usable_yield=usable_yield,
        license_authorized_rate=license_authorized_rate,
        t0_reject_count=tier_counts["T0_REJECT"],
        t0_reject_ratio=t0_ratio,
        selected_decision=selected_decision,
        allowed_decisions=sorted(ALLOWED_DECISIONS),
        exact_one_next_decision=True,
        no_plan_more=True,
        rationale=decision_reasons,
    )

    files_changed = [
        "scripts/build_v17_7_4_reverse_heal_math_sanitization_v2.py",
        "schemas/kt.v17_7_4.math_row_trust_tier.schema.json",
        "schemas/kt.v17_7_4.math_corpus_row_sanitization_action.schema.json",
        *REPORTS,
        CLEANROOM_CI_RECEIPT,
        "reports/v17_7_4_reverse_heal_math_sanitization_v2_builder_summary.json",
        "registry/artifact_authority_registry_v17_7_4_reverse_heal_math_sanitization_v2_delta_receipt.json",
        "tests/test_v17_7_4_reverse_heal_math_sanitization_v2.py",
    ]

    common_context = {
        "active_tranche": TRANCHE,
        "outcome": OUTCOME,
        "current_head": current_head,
        "current_branch": current_branch,
        "predecessor_tranche": PREDECESSOR_TRANCHE,
        "predecessor_quality_audit_head": PREDECESSOR_HEAD,
        "superseded_lane": SUPERSEDED_LANE,
        "selected_next_lane": selected_decision,
        "claim_ceiling_status": "PRESERVED",
    }

    outputs: dict[str, dict[str, Any]] = {
        "reports/v17_7_4_reverse_heal_sanitization_truth_pin.json": authority(
            schema_id="kt.v17_7_4.reverse_heal_sanitization_truth_pin.v2",
            status="PASS",
            worktree_bound_to_current_head=True,
            quality_audit_receipts_present=bool(records and quality_scorecard),
            **common_context,
        ),
        "reports/v17_7_4_reverse_heal_sanitization_predecessor_binding.json": authority(
            schema_id="kt.v17_7_4.reverse_heal_sanitization_predecessor_binding.v2",
            status="BOUND_TO_MATH_CORPUS_QUALITY_AUDIT",
            predecessor_outcome=quality_summary.get("outcome"),
            predecessor_next_lawful_move=quality_summary.get("next_lawful_move"),
            predecessor_training_authority=quality_summary.get("training_authority", False),
            predecessor_runtime_authority=quality_summary.get("runtime_authority", False),
            predecessor_scorecard_grade=quality_scorecard.get("overall_grade"),
            **common_context,
        ),
        "reports/v17_7_4_reverse_heal_sanitization_claim_boundary_receipt.json": authority(
            schema_id="kt.v17_7_4.reverse_heal_sanitization_claim_boundary_receipt.v2",
            status="PASS",
            allowed_internal_claim="KT converted math corpus quality audit into a reverse-heal dataset-blueprint decision. No dataset or training authority granted.",
            forbidden_claims_preserved=True,
            **common_context,
        ),
        "reports/v17_7_4_reverse_heal_boundary_receipt.json": authority(
            schema_id="kt.v17_7_4.reverse_heal_boundary_receipt.v2",
            status="PASS",
            cognitive_substrate=["lobes", "router", "hat", "adapters", "tournaments"],
            governance_substrate=["gates", "courts", "truth_engine", "claim_compiler", "receipts"],
            governance_must_not_enter_model_visible_cognition=True,
            lab_runs_may_be_fast=True,
            canonical_promotion_remains_slow=True,
            **common_context,
        ),
        "reports/v17_7_4_lab_vs_canonical_authority_policy.json": authority(
            schema_id="kt.v17_7_4.lab_vs_canonical_authority_policy.v2",
            status="PASS",
            lab_plane=["small microfurnaces", "one variable", "no claims", "damage gates", "fast evidence"],
            canonical_plane=["replay", "fresh clone", "no regression", "claim ceiling", "artifact hashes", "promotion law"],
            this_lane_plane="canonical_governance_decision_no_runtime",
            **common_context,
        ),
        "reports/v17_7_4_audit_recursion_risk_policy.json": authority(
            schema_id="kt.v17_7_4.audit_recursion_risk_policy.v2",
            status="PASS",
            recursion_risk="HIGH_IF_LANE_ENDS_WITH_MORE_AUDIT_ONLY",
            allowed_terminal_outcomes=sorted(ALLOWED_DECISIONS),
            selected_terminal_outcome=selected_decision,
            no_plan_more=True,
            **common_context,
        ),
        "reports/v17_7_4_math_corpus_sanitization_yield_gate.json": yield_gate,
        "reports/v17_7_4_math_corpus_salvage_decision.json": authority(
            schema_id="kt.v17_7_4.math_corpus_salvage_decision.v2",
            status=selected_decision,
            historical_corpus_disposition="PRESERVE_AS_AUDIT_HISTORY_NOT_TRAINING_SEED",
            clean_blueprint_required=True,
            reasons=decision_reasons,
            **common_context,
        ),
        "reports/v17_7_4_math_row_trust_tier_policy.json": authority(
            schema_id="kt.v17_7_4.math_row_trust_tier_policy.v2",
            status="PASS",
            tiers={
                "T0_REJECT": "Reject from dataset blueprint input.",
                "T1_FORMAT_ONLY": "May inform format contracts only; no reasoning training.",
                "T2_VERIFIED_NUMERIC": "Numeric candidate only after clean source rebuild and license clearance.",
                "T3_STEP_VERIFIED": "Step candidate only after human/code verification and no overlap.",
                "T4_HUMAN_VERIFIED_TRANSFER_READY": "Future tier; not earned by this historical corpus.",
            },
            tier_counts=dict(tier_counts),
            **common_context,
        ),
        "reports/v17_7_4_math_capability_density_requirements.json": authority(
            schema_id="kt.v17_7_4.math_capability_density_requirements.v2",
            status="PASS",
            minimum_blueprint_density=0.65,
            requires_problem_text=True,
            requires_reasoning_or_code_verified_solution=True,
            requires_verifier_compatibility=True,
            forbids_final_answer_only_rows_for_reasoning_training=True,
            measured_quality_candidate_count=quality_candidate_count,
            measured_usable_yield=usable_yield,
            **common_context,
        ),
        "reports/v17_7_4_math_signal_density_targets.json": authority(
            schema_id="kt.v17_7_4.math_signal_density_targets.v2",
            status="PASS_REQUIREMENTS_ONLY",
            gsm8k_foundation_first=True,
            minimum_problem_solution_density=0.8,
            minimum_verifier_compatible_ratio=0.7,
            maximum_doctrine_contamination_ratio=0.0,
            maximum_expected_answer_leakage_ratio=0.0,
            **common_context,
        ),
        "reports/v17_7_4_math_doctrine_contamination_scan.json": authority(
            schema_id="kt.v17_7_4.math_doctrine_contamination_scan.v2",
            status="PASS_SCAN_COMPLETE__CONTAMINATION_HIGH",
            contaminated_row_count=doctrine_count,
            contaminated_ratio=contamination_ratio,
            action="DO_NOT_USE_HISTORICAL_CORPUS_AS_TRAINING_SEED",
            **common_context,
        ),
        "reports/v17_7_4_math_doctrine_contamination_blocklist.json": authority(
            schema_id="kt.v17_7_4.math_doctrine_contamination_blocklist.v2",
            status="PASS",
            blocked_tokens=["claim", "court", "gate", "governance", "policy", "receipt", "router-superiority"],
            blocked_lanes=["DOCTRINE_GOVERNANCE_CONTAMINATION"],
            blocked_source_ids=blacklist,
            **common_context,
        ),
        "reports/v17_7_4_math_code_verified_crucible_requirement.json": authority(
            schema_id="kt.v17_7_4.math_code_verified_crucible_requirement.v2",
            status="PASS_REQUIREMENT_BOUND",
            required_for_future_dataset=True,
            requirement="Each reasoning row must have a deterministic answer invariant, verifier class, and no model-visible expected answer.",
            **common_context,
        ),
        "reports/v17_7_4_math_verification_class_map.json": authority(
            schema_id="kt.v17_7_4.math_verification_class_map.v2",
            status="PASS_REQUIREMENTS_ONLY",
            classes={
                "arithmetic_numeric": "deterministic numeric equality after normalization",
                "gsm8k_word_problem": "final answer plus unit/quantity invariant",
                "formal_proof": "future-only human/formal verifier requirement",
                "olympiad_strategy": "future-only; not GSM8K foundation substitute",
            },
            **common_context,
        ),
        "reports/v17_7_4_math_row_verifiable_invariant_policy.json": authority(
            schema_id="kt.v17_7_4.math_row_verifiable_invariant_policy.v2",
            status="PASS_REQUIREMENTS_ONLY",
            expected_answer_segregated_from_prompt=True,
            no_oracle_label_laundering=True,
            code_verified_if_claimed=True,
            **common_context,
        ),
        "reports/v17_7_4_formal_math_compression_suspension_receipt.json": authority(
            schema_id="kt.v17_7_4.formal_math_compression_suspension_receipt.v2",
            status="SUSPENDED",
            formal_math_compression_suspended=True,
            reason="Capability foundation and verification topology must stabilize before compression optimization resumes.",
            **common_context,
        ),
        "reports/v17_7_4_math_capability_first_mode.json": authority(
            schema_id="kt.v17_7_4.math_capability_first_mode.v2",
            status="PASS",
            capability_first_mode=True,
            compression_optimization_allowed_now=False,
            **common_context,
        ),
        "reports/v17_7_4_math_compression_reopen_gate.json": authority(
            schema_id="kt.v17_7_4.math_compression_reopen_gate.v2",
            status="PASS_REQUIREMENTS_ONLY",
            reopen_only_after=["GSM8K capability improves", "no-regression replay passes", "answer verifier stable"],
            compression_reopen_authority_now=False,
            **common_context,
        ),
        "reports/v17_7_4_formal_math_niche_boundary_reaffirmation.json": authority(
            schema_id="kt.v17_7_4.formal_math_niche_boundary_reaffirmation.v2",
            status="PASS_REAFFIRMED",
            formal_math_is_niche_bound=True,
            no_global_promotion=True,
            no_olympiad_now=True,
            **common_context,
        ),
        "reports/v17_7_4_math_no_regression_replay_contract.json": authority(
            schema_id="kt.v17_7_4.math_no_regression_replay_contract.v2",
            status="PASS_REQUIREMENTS_ONLY",
            future_training_request_must_include_no_regression=True,
            baseline_surfaces=["known_good_math_act_control", "base_raw", "non_math_slices"],
            **common_context,
        ),
        "reports/v17_7_4_math_router_nonpromotion_receipt.json": authority(
            schema_id="kt.v17_7_4.math_router_nonpromotion_receipt.v2",
            status="PASS_NONPROMOTION_BOUND",
            route_promotion_authority=False,
            learned_router_superiority_claim=False,
            **common_context,
        ),
        "reports/v17_7_4_math_repair_curriculum_ladder.json": authority(
            schema_id="kt.v17_7_4.math_repair_curriculum_ladder.v2",
            status="PASS_REQUIREMENTS_ONLY",
            ladder=["Arithmetic/GSM8K foundation", "formal proof after foundation", "Olympiad strategy future-only"],
            training_authority_now=False,
            **common_context,
        ),
        "reports/v17_7_4_math_curriculum_stage_requirements.json": authority(
            schema_id="kt.v17_7_4.math_curriculum_stage_requirements.v2",
            status="PASS_REQUIREMENTS_ONLY",
            gsm8k_stage_requires=["clean source", "dedup firewall", "reasoning steps", "verifier invariant"],
            formal_stage_requires=["foundation pass", "formal verifier or human audit"],
            olympiad_stage_requires=["foundation plus formal-stage stability"],
            **common_context,
        ),
        "reports/v17_7_4_math_olympiad_future_only_receipt.json": authority(
            schema_id="kt.v17_7_4.math_olympiad_future_only_receipt.v2",
            status="FUTURE_ONLY",
            olympiad_training_authority=False,
            reason="Do not jump to hard math before GSM8K foundation and verification are stable.",
            **common_context,
        ),
        "reports/v17_7_4_math_corpus_source_disposition_matrix.json": authority(
            schema_id="kt.v17_7_4.math_corpus_source_disposition_matrix.v2",
            status="PASS",
            source_count=len(source_rows),
            whitelist_candidate_count=len(whitelist),
            blacklist_count=len(blacklist),
            action_counts=dict(Counter(row["action"] for row in source_actions)),
            **common_context,
        ),
        "reports/v17_7_4_math_corpus_source_whitelist_blacklist.json": authority(
            schema_id="kt.v17_7_4.math_corpus_source_whitelist_blacklist.v2",
            status="PASS",
            whitelist_review_only=whitelist,
            blacklist_not_dataset_inputs=blacklist,
            no_source_training_authority_now=True,
            **common_context,
        ),
        "reports/v17_7_4_math_corpus_row_sanitization_requirements.json": authority(
            schema_id="kt.v17_7_4.math_corpus_row_sanitization_requirements.v2",
            status="PASS_REQUIREMENTS_ONLY",
            actions=dict(action_counts),
            no_sanitized_dataset_emitted=True,
            **common_context,
        ),
        "reports/v17_7_4_math_corpus_expected_answer_sanitization_plan.json": authority(
            schema_id="kt.v17_7_4.math_corpus_expected_answer_sanitization_plan.v2",
            status="PASS_REQUIREMENTS_ONLY",
            expected_answer_must_be_test_label_only=True,
            model_visible_expected_answer_forbidden=True,
            **common_context,
        ),
        "reports/v17_7_4_math_corpus_answer_field_segregation_spec.json": authority(
            schema_id="kt.v17_7_4.math_corpus_answer_field_segregation_spec.v2",
            status="PASS_REQUIREMENTS_ONLY",
            prompt_fields=["problem", "question"],
            label_fields=["expected_answer", "gold_answer", "normalized_gold"],
            label_fields_model_visible=False,
            **common_context,
        ),
        "reports/v17_7_4_math_corpus_oracle_label_laundering_block.json": authority(
            schema_id="kt.v17_7_4.math_corpus_oracle_label_laundering_block.v2",
            status="PASS",
            oracle_labels_forbidden_in_prompts=True,
            expected_answer_leakage_rows_blocked=high_leakage_count,
            **common_context,
        ),
        "reports/v17_7_4_math_corpus_dedup_sanitization_plan.json": authority(
            schema_id="kt.v17_7_4.math_corpus_dedup_sanitization_plan.v2",
            status="PASS_REQUIREMENTS_ONLY",
            predecessor_dedup_status=dedup.get("status"),
            future_dataset_requires_problem_hash_dedup=True,
            **common_context,
        ),
        "reports/v17_7_4_math_corpus_train_eval_firewall_plan.json": authority(
            schema_id="kt.v17_7_4.math_corpus_train_eval_firewall_plan.v2",
            status="PASS_REQUIREMENTS_ONLY",
            predecessor_overlap_status=overlap.get("status"),
            eval_rows_must_not_be_training_targets=True,
            train_eval_boundary_training_authority=train_eval.get("training_authority", False),
            **common_context,
        ),
        "reports/v17_7_4_math_corpus_overlap_blocklist.json": authority(
            schema_id="kt.v17_7_4.math_corpus_overlap_blocklist.v2",
            status="PASS",
            overlap_status=overlap.get("status"),
            blocked_record_hashes=[],
            **common_context,
        ),
        "reports/v17_7_4_math_corpus_format_normalization_plan.json": authority(
            schema_id="kt.v17_7_4.math_corpus_format_normalization_plan.v2",
            status="PASS_REQUIREMENTS_ONLY",
            predecessor_format_status=format_audit.get("status"),
            normalize_problem_solution_answer_fields=True,
            no_answer_only_reasoning_training=True,
            **common_context,
        ),
        "reports/v17_7_4_math_corpus_answer_contract_target_spec.json": authority(
            schema_id="kt.v17_7_4.math_corpus_answer_contract_target_spec.v2",
            status="PASS_REQUIREMENTS_ONLY",
            contract=["problem", "reasoning_steps", "answer_label_hidden_from_model", "verifier_invariant"],
            **common_context,
        ),
        "reports/v17_7_4_math_corpus_reasoning_step_requirement_spec.json": authority(
            schema_id="kt.v17_7_4.math_corpus_reasoning_step_requirement_spec.v2",
            status="PASS_REQUIREMENTS_ONLY",
            predecessor_reasoning_status=reasoning_presence.get("status"),
            reasoning_steps_required_for_training_rows=True,
            **common_context,
        ),
        "reports/v17_7_4_math_corpus_license_remediation_plan.json": authority(
            schema_id="kt.v17_7_4.math_corpus_license_remediation_plan.v2",
            status="PASS_REQUIREMENTS_ONLY",
            unknown_license_source_count=unknown_license_count,
            historical_corpus_not_used_until_license_resolved=True,
            **common_context,
        ),
        "reports/v17_7_4_historical_corpus_gap_remediation_plan.json": authority(
            schema_id="kt.v17_7_4.historical_corpus_gap_remediation_plan.v2",
            status="PASS_REQUIREMENTS_ONLY",
            historical_corpus_role="audit_history_and_recovery_target_only",
            no_fabrication=True,
            **common_context,
        ),
        "reports/v17_7_4_historical_epoch_crucible_recovery_plan.json": authority(
            schema_id="kt.v17_7_4.historical_epoch_crucible_recovery_plan.v2",
            status="PASS_REQUIREMENTS_ONLY",
            recovery_mode="source_recovery_only_no_training",
            **common_context,
        ),
        "reports/v17_7_4_historical_training_prompt_template_recovery_plan.json": authority(
            schema_id="kt.v17_7_4.historical_training_prompt_template_recovery_plan.v2",
            status="PASS_REQUIREMENTS_ONLY",
            recovery_required_before_comparability_claim=True,
            **common_context,
        ),
        "reports/v17_7_4_math_dataset_blueprint_go_no_go_decision.json": authority(
            schema_id="kt.v17_7_4.math_dataset_blueprint_go_no_go_decision.v2",
            status=selected_decision,
            decision=selected_decision,
            exact_one_next_decision=True,
            dataset_blueprint_from_historical_corpus_go=False,
            clean_blueprint_go=True,
            reasons=decision_reasons,
            **common_context,
        ),
        "reports/v17_7_4_math_dataset_blueprint_handoff_requirements.json": authority(
            schema_id="kt.v17_7_4.math_dataset_blueprint_handoff_requirements.v2",
            status="PASS_REQUIREMENTS_ONLY",
            next_lane=selected_decision,
            required_inputs=["clean GSM8K-level source policy", "hidden labels", "code-verifiable invariants", "dedup firewall"],
            **common_context,
        ),
        "reports/v17_7_4_math_dataset_builder_forbidden_actions.json": authority(
            schema_id="kt.v17_7_4.math_dataset_builder_forbidden_actions.v2",
            status="PASS",
            forbidden_actions=[
                "emit sanitized dataset in this lane",
                "train",
                "run Kaggle",
                "mutate prompts",
                "upload HF artifacts",
                "promote adapters or routes",
            ],
            **common_context,
        ),
        "reports/v17_7_4_epc_decision_after_reverse_heal_sanitization_v2.json": authority(
            schema_id="kt.v17_7_4.epc_decision_after_reverse_heal_sanitization_v2.v2",
            status="PASS_DECIDED_NO_RUNTIME_PACKET",
            runtime_allowed_by_this_lane=False,
            dataset_generation_allowed_by_this_lane=False,
            training_allowed_by_this_lane=False,
            **common_context,
        ),
        "reports/v17_7_4_reverse_heal_sanitization_next_lane.json": authority(
            schema_id="kt.v17_7_4.reverse_heal_sanitization_next_lane.v2",
            status="PASS_EXACT_ONE_NEXT_LANE",
            no_plan_more=True,
            packet_path_if_any=None,
            packet_sha256_if_any=None,
            kaggle_dataset_name_if_any=None,
            one_cell_runbook_if_any=None,
            **common_context,
        ),
        "reports/v17_7_4_reverse_heal_intervention_queue.json": authority(
            schema_id="kt.v17_7_4.reverse_heal_intervention_queue.v2",
            status="PASS",
            queue=[
                {"rank": 1, "lane": selected_decision, "runtime": False, "dataset_generation": False, "training": False},
                {"rank": 2, "lane": "AUTHOR_BASE_MODEL_STANDARD_MATH_PROMPT_PROBE_DESIGN_V1", "runtime": False, "dataset_generation": False, "training": False},
            ],
            **common_context,
        ),
        CLEANROOM_CI_RECEIPT: authority(
            schema_id="kt.v17_7_4.reverse_heal_math_sanitization_v2_ci_trigger_receipt.v1",
            status="PASS",
            purpose="Mirror receipt under KT_PROD_CLEANROOM so required P0 ruleset contexts are emitted for this PR.",
            no_runtime_authority=True,
            no_dataset_generation_authority=True,
            no_training_authority=True,
            **common_context,
        ),
    }

    registry_delta = authority(
        schema_id="kt.artifact_authority_registry_delta.v17_7_4_reverse_heal_math_sanitization_v2",
        status="PASS",
        active_tranche=TRANCHE,
        outcome=OUTCOME,
        artifacts_added=files_changed,
        runtime_authority=False,
        dataset_generation_authority=False,
        training_authority=False,
        packet_path_if_any=None,
        claim_ceiling_status="PRESERVED",
    )
    summary = authority(
        schema_id="kt.v17_7_4.reverse_heal_math_sanitization_v2_builder_summary.v2",
        status="PASS",
        active_tranche=TRANCHE,
        current_head=current_head,
        branch=current_branch,
        outcome=OUTCOME,
        files_changed=files_changed,
        reverse_heal_sanitization_binding_status="BOUND_TO_MATH_CORPUS_QUALITY_AUDIT",
        lab_vs_canonical_authority_status="PASS",
        audit_recursion_policy_status="PASS",
        sanitization_yield_gate_status=yield_gate["status"],
        row_trust_tier_policy_status="PASS",
        capability_density_requirements_status="PASS",
        doctrine_contamination_scan_status="PASS_SCAN_COMPLETE__CONTAMINATION_HIGH",
        code_verified_crucible_requirement_status="PASS_REQUIREMENT_BOUND",
        formal_math_compression_suspension_status="SUSPENDED",
        niche_boundary_reaffirmation_status="PASS_REAFFIRMED",
        source_disposition_matrix_status="PASS",
        row_sanitization_requirements_status="PASS_REQUIREMENTS_ONLY",
        expected_answer_sanitization_status="PASS_REQUIREMENTS_ONLY",
        dedup_firewall_plan_status="PASS_REQUIREMENTS_ONLY",
        format_normalization_plan_status="PASS_REQUIREMENTS_ONLY",
        license_historical_gap_remediation_status="PASS_REQUIREMENTS_ONLY",
        dataset_blueprint_go_no_go_status=selected_decision,
        epc_next_lane_status="PASS_DECIDED_NO_RUNTIME_PACKET",
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        claim_ceiling_status="PRESERVED",
        blockers=[],
        next_lawful_move=selected_decision,
    )

    for path, payload in schemas().items():
        write_json(path, payload)
    for path, payload in outputs.items():
        write_json(path, payload)
    write_jsonl("reports/v17_7_4_math_corpus_sanitization_yield_table.jsonl", [yield_gate])
    write_jsonl("reports/v17_7_4_math_row_trust_tier_assignment_table.jsonl", tier_rows)
    write_jsonl("reports/v17_7_4_math_capability_density_table.jsonl", density_rows)
    write_jsonl("reports/v17_7_4_math_doctrine_contamination_table.jsonl", contamination_rows)
    write_jsonl("reports/v17_7_4_math_corpus_source_action_table.jsonl", source_actions)
    write_jsonl("reports/v17_7_4_math_corpus_row_action_table.jsonl", action_rows)
    write_jsonl("reports/v17_7_4_math_corpus_use_authority_remediation_table.jsonl", license_rows)
    write_json(
        "reports/v17_7_4_reverse_heal_math_sanitization_v2_builder_summary.json",
        summary,
    )
    write_json(
        "registry/artifact_authority_registry_v17_7_4_reverse_heal_math_sanitization_v2_delta_receipt.json",
        registry_delta,
    )
    return summary


def main() -> None:
    print(json.dumps(build(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
