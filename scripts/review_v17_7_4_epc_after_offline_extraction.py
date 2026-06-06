from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core


TRANCHE = "AUTHOR_KTV1774_EPC_REVIEW_AFTER_OFFLINE_EXTRACTION_V1"
OUTCOME = "KT_EPC_REVIEW_COMPLETE__HELDOUT_REPROLOCK_GENERALIZATION_READY_OR_NEXT_LANE_SELECTED__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "BIND_HELDOUT_REPROLOCK_ROW_SOURCE_OR_AUTHOR_ROW_ORDER_SHUFFLE_CONTROL_PACKET"
PREVIOUS_PACKET = ROOT / "packets" / "ktv1774_reprolock_oracle_offline_extraction_v1.zip"
ROW_TABLE = ROOT / "reports" / "v17_7_4_reprolock_oracle_offline_extraction_row_table.jsonl"
SCORECARD = ROOT / "reports" / "v17_7_4_reprolock_oracle_offline_extraction_scorecard.json"
PREVIOUS_EPC = ROOT / "reports" / "v17_7_4_epc_decision_after_reprolock_oracle_offline_extraction.json"
CONTRACT_RECEIPT = ROOT / "reports" / "v17_7_4_final_answer_extraction_contract_v2_receipt.json"
ROUTE_SIM = ROOT / "reports" / "v17_7_4_extraction_aware_cheapest_correct_route_simulation_v3.json"
SOURCE_INDEX = ROOT / "reports" / "v17_7_4_reprolock_oracle_raw_output_source_index.json"
REPROLOCK_REALBENCH_MANIFEST = ROOT / "admission" / "v17_7_4_realbench_row_manifest.json"
DIAGNOSTIC_ROW_MANIFEST = ROOT / "admission" / "v17_7_4_truegen_row_manifest.json"
BOUND_HELDOUT_MANIFEST = ROOT / "admission" / "v17_7_4_reprolock_heldout_row_manifest.json"


FORBIDDEN_CLAIMS = [
    "Do not assert runtime eligibility for final-answer extraction v2.",
    "Do not assert router-superiority authority.",
    "Do not assert learned-router authority.",
    "Do not assert G2 recovery.",
    "Do not assert 91-percent full-system compression recovery.",
    "Do not assert commercial readiness.",
    "Do not assert external-validation acceptance.",
    "Do not assert S-tier or frontier-parity status.",
    "Do not assert seven-billion-parameter proof.",
    "Do not assert production readiness.",
]


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(core.AUTHORITY_FALSE)
    payload.update(
        {
            "commercial_claim": False,
            "external_validation_claim": False,
            "frontier_claim": False,
            "g2_recovered_claim": False,
            "multi_lobe_superiority_claim": False,
            "production_readiness_claim": False,
            "router_superiority_claim": False,
            "s_tier_claim": False,
            "seven_b_claim": False,
            "claim_ceiling_preserved": True,
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
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def source_entry(path: Path, role: str, evidence_type: str) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "role": role,
        "evidence_type": evidence_type,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def unexpected_worktree_entries() -> list[str]:
    allowed_prefixes = (
        "docs/REPROLOCK_ORACLE_OFFLINE_EXTRACTION_EPC_REVIEW.md",
        "rules/NO_EXTRACTION_RUNTIME_INTEGRATION_IF_HARMFUL.md",
        "scripts/review_v17_7_4_epc_after_offline_extraction.py",
        "tests/test_v17_7_4_epc_review_heldout.py",
        "schemas/kt.v17_7_4.epc_review_decision.schema.json",
        "schemas/kt.v17_7_4.extraction_failure_autopsy.schema.json",
        "schemas/kt.v17_7_4.final_answer_contract_v2_runtime_eligibility.schema.json",
        "schemas/kt.v17_7_4.heldout_generalization_design.schema.json",
        "reports/v17_7_4_",
        "registry/artifact_authority_registry_v17_7_4_epc_review_heldout_delta_receipt.json",
    )
    entries = []
    for line in git(["status", "--short"]).splitlines():
        path = line[2:].strip().replace("\\", "/")
        if not path.startswith(allowed_prefixes):
            entries.append(line)
    return entries


def build_truth_pin() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    sources = [
        source_entry(PREVIOUS_PACKET, "prior offline extraction packet", "offline evidence packet"),
        source_entry(SCORECARD, "offline extraction replay source", "scorecard"),
        source_entry(CONTRACT_RECEIPT, "final answer contract v2 source", "receipt"),
        source_entry(ROUTE_SIM, "extraction-aware route simulation v3 source", "teacher-only replay"),
        source_entry(PREVIOUS_EPC, "EPC decision source", "decision receipt"),
        source_entry(ROW_TABLE, "offline extraction row table", "row-level replay table"),
        source_entry(REPROLOCK_REALBENCH_MANIFEST, "known-good control source", "row manifest"),
        source_entry(DIAGNOSTIC_ROW_MANIFEST, "diagnostic row source", "not held-out authority"),
        source_entry(ROOT / "rules" / "CLAIM_CEILING.md", "claim ceiling file", "rule"),
        source_entry(ROOT / "governance" / "current_claim_ceiling.json", "claim ceiling state", "governance"),
        source_entry(ROOT / "registry" / "artifact_authority_registry.json", "artifact authority registry", "registry"),
    ]
    sources = [source for source in sources if source is not None]
    scorecard = read_json(SCORECARD)
    previous_epc = read_json(PREVIOUS_EPC)
    contradictions: list[str] = []
    if not PREVIOUS_PACKET.exists():
        contradictions.append("prior_offline_extraction_packet_missing")
    if not ROW_TABLE.exists():
        contradictions.append("offline_extraction_row_table_missing")
    if previous_epc.get("kaggle_packet_warranted_next") is not False:
        contradictions.append("previous_epc_did_not_withhold_runtime_packet")
    if scorecard.get("model_generation_invoked") is not False:
        contradictions.append("offline_extraction_invoked_model_generation")
    if scorecard.get("correctness_replay", 1.0) >= scorecard.get("correctness_original", 0.0):
        contradictions.append("offline_extraction_did_not_reduce_correctness")

    truth_pin = authority(
        schema_id="kt.v17_7_4.epc_review_truth_pin_receipt.v1",
        status="PASS" if not contradictions else "KT_BLOCKED__EPC_REVIEW_TRUTH_PIN_FAILED",
        current_head=git(["rev-parse", "HEAD"]),
        branch=git(["branch", "--show-current"]),
        worktree_clean=len(unexpected_worktree_entries()) == 0,
        unexpected_worktree_entries=unexpected_worktree_entries(),
        prior_offline_extraction_packet_path=PREVIOUS_PACKET.relative_to(ROOT).as_posix() if PREVIOUS_PACKET.exists() else None,
        prior_offline_extraction_packet_sha256=sha256_file(PREVIOUS_PACKET) if PREVIOUS_PACKET.exists() else None,
        offline_extraction_replay_source=SCORECARD.relative_to(ROOT).as_posix(),
        final_answer_contract_v2_source=CONTRACT_RECEIPT.relative_to(ROOT).as_posix(),
        extraction_aware_route_simulation_v3_source=ROUTE_SIM.relative_to(ROOT).as_posix(),
        epc_decision_source=PREVIOUS_EPC.relative_to(ROOT).as_posix(),
        known_good_control_source=REPROLOCK_REALBENCH_MANIFEST.relative_to(ROOT).as_posix(),
        current_claim_ceiling_files=[
            "rules/CLAIM_CEILING.md",
            "governance/current_claim_ceiling.json",
        ],
        artifact_authority_registry="registry/artifact_authority_registry.json",
        stale_superseded_artifacts_excluded=[
            "final-answer extraction v2 as global runtime intervention",
            "offline extraction replay as runtime authority",
            "teacher-only cheapest-correct route simulation as route authority",
        ],
        next_lawful_move_before_patch=previous_epc.get("recommended_next_lane"),
        contradictions=contradictions,
    )
    source_index = authority(
        schema_id="kt.v17_7_4.epc_review_source_index.v1",
        status="PASS" if sources else "BLOCKED",
        sources=sources,
        external_raw_output_text_committed=False,
        source_evidence_index=SOURCE_INDEX.relative_to(ROOT).as_posix() if SOURCE_INDEX.exists() else None,
    )
    contradiction_scan = authority(
        schema_id="kt.v17_7_4.epc_review_contradiction_scan.v1",
        status="PASS" if not contradictions else "BLOCKED",
        contradictions=contradictions,
        required_previous_statuses={
            "offline_extraction_replay_status": "PASS_OFFLINE_ONLY__MODEL_GENERATION_FALSE",
            "epc_next_evidence_lane_status": "PASS__REVIEW_REQUIRED__NO_RUNTIME_PACKET_AUTHORIZED",
            "reason_runtime_packet_withheld": "offline_extraction_reduced_correctness",
        },
    )
    return truth_pin, source_index, contradiction_scan


def bucket_counts(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    counts: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        bucket = tuple(row.get(key) for key in keys)
        if bucket not in counts:
            counts[bucket] = {
                "bucket": {key: value for key, value in zip(keys, bucket)},
                "row_count": 0,
                "original_correct": 0,
                "replay_correct": 0,
                "correct_to_incorrect": 0,
                "incorrect_to_correct": 0,
                "ambiguous": 0,
            }
        item = counts[bucket]
        item["row_count"] += 1
        item["original_correct"] += int(bool(row.get("original_correct")))
        item["replay_correct"] += int(bool(row.get("replay_correct")))
        item["correct_to_incorrect"] += int(bool(row.get("original_correct")) and not bool(row.get("replay_correct")))
        item["incorrect_to_correct"] += int(not bool(row.get("original_correct")) and bool(row.get("replay_correct")))
        item["ambiguous"] += int(bool(row.get("extraction_ambiguous")))
    return sorted(counts.values(), key=lambda item: (-item["correct_to_incorrect"], -item["row_count"], str(item["bucket"])))


def build_extraction_autopsy(rows: list[dict[str, Any]], scorecard: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    correct_to_incorrect = [row for row in rows if row.get("original_correct") and not row.get("replay_correct")]
    incorrect_to_correct = [row for row in rows if not row.get("original_correct") and row.get("replay_correct")]
    preserved = [row for row in rows if bool(row.get("original_correct")) == bool(row.get("replay_correct"))]
    ambiguous = [row for row in rows if row.get("extraction_ambiguous")]
    early_scratch = [
        row
        for row in correct_to_incorrect
        if row.get("extraction_ambiguous") or row.get("extraction_surface") in {"last_numeric_surface", "last_mcq_letter"}
    ]
    over_normalized = [
        row
        for row in correct_to_incorrect
        if row.get("extraction_state") in {"EXTRACTED_NUMERIC", "EXTRACTED_MCQ"}
        and row.get("answer_format_drift_original")
    ]
    original_parser_correct_extraction_harm = [
        row for row in correct_to_incorrect if not row.get("parser_failure_original")
    ]
    harm_rows = []
    for row in correct_to_incorrect:
        harm_rows.append(
            authority(
                schema_id="kt.v17_7_4.extraction_harm_row.v1",
                source_id=row.get("source_id"),
                sample_id=row.get("sample_id"),
                dataset=row.get("dataset"),
                task_family=row.get("task_family"),
                arm_id=row.get("arm_id"),
                original_correct=row.get("original_correct"),
                replay_correct=row.get("replay_correct"),
                extraction_surface=row.get("extraction_surface"),
                extraction_state=row.get("extraction_state"),
                extraction_ambiguous=row.get("extraction_ambiguous"),
                parser_failure_original=row.get("parser_failure_original"),
                raw_output_hash=row.get("raw_output_hash"),
                expected_answer_visible_to_model=False,
                runtime_authority=False,
            )
        )

    candidate_bucket_sets = [
        ("dataset",),
        ("task_family",),
        ("extraction_surface",),
        ("extraction_state",),
        ("dataset", "extraction_surface"),
        ("task_family", "extraction_surface"),
        ("source_id", "dataset", "extraction_surface"),
    ]
    safe_buckets = []
    evaluated_buckets = []
    for keys in candidate_bucket_sets:
        for item in bucket_counts(rows, keys):
            item = dict(item)
            item["runtime_features_only"] = True
            item["expected_answer_used_for_policy"] = False
            item["keys"] = list(keys)
            evaluated_buckets.append(item)
            if (
                item["row_count"] >= 10
                and item["correct_to_incorrect"] == 0
                and item["replay_correct"] >= item["original_correct"]
            ):
                safe_buckets.append(item)

    correctness_reduced = scorecard.get("correctness_replay", 0.0) < scorecard.get("correctness_original", 0.0)
    autopsy = authority(
        schema_id="kt.v17_7_4.extraction_failure_autopsy.v1",
        status="PASS",
        row_count=len(rows),
        original_correct=sum(1 for row in rows if row.get("original_correct")),
        replay_correct=sum(1 for row in rows if row.get("replay_correct")),
        correctness_original=scorecard.get("correctness_original"),
        correctness_replay=scorecard.get("correctness_replay"),
        offline_extraction_reduced_correctness=correctness_reduced,
        preserved_correctness_rows=len(preserved),
        correct_to_incorrect_rows=len(correct_to_incorrect),
        incorrect_to_correct_rows=len(incorrect_to_correct),
        ambiguity_rows=len(ambiguous),
        selected_early_scratch_or_wrong_surface_rows=len(early_scratch),
        over_normalized_rows=len(over_normalized),
        original_parser_correct_and_extraction_harmful_rows=len(original_parser_correct_extraction_harm),
        task_family_sensitivity=bucket_counts(rows, ("task_family",)),
        dataset_sensitivity=bucket_counts(rows, ("dataset",)),
        arm_sensitivity=bucket_counts(rows, ("arm_id",)),
        extraction_surface_sensitivity=bucket_counts(rows, ("extraction_surface",)),
        gsm8k_pressure_point={
            "rows": sum(1 for row in rows if row.get("dataset") == "gsm8k"),
            "correct_to_incorrect": sum(1 for row in correct_to_incorrect if row.get("dataset") == "gsm8k"),
            "incorrect_to_correct": sum(1 for row in incorrect_to_correct if row.get("dataset") == "gsm8k"),
        },
    )
    eligibility = authority(
        schema_id="kt.v17_7_4.final_answer_contract_v2_runtime_eligibility_receipt.v1",
        status="NOT_RUNTIME_ELIGIBLE_REDUCED_CORRECTNESS" if correctness_reduced else "RUNTIME_ELIGIBLE_AFTER_MICROFURNACE",
        global_runtime_integration_allowed=not correctness_reduced,
        offline_only=correctness_reduced,
        safe_subset_candidate_available=bool(safe_buckets),
        safe_subset_candidate_count=len(safe_buckets),
        expected_answers_used_as_runtime_hints=False,
        model_generation_invoked=False,
        correctness_original=scorecard.get("correctness_original"),
        correctness_replay=scorecard.get("correctness_replay"),
        reason="offline_extraction_reduced_correctness" if correctness_reduced else "offline_extraction_non_regressive",
    )
    subset_candidate = authority(
        schema_id="kt.v17_7_4.extraction_safe_subset_candidate.v1",
        status="NO_SAFE_SUBSET_FOUND" if not safe_buckets else "SAFE_SUBSET_CANDIDATE_ONLY",
        global_policy_allowed=False,
        candidate_only=True,
        runtime_authority=False,
        expected_answer_used_for_policy=False,
        bucket_minimum_rows=10,
        safe_buckets=safe_buckets,
        evaluated_bucket_count=len(evaluated_buckets),
        evaluated_buckets_sample=evaluated_buckets[:20],
        blocked_reason=None if safe_buckets else "no runtime-available bucket reached non-regressive harm-free threshold",
    )
    return autopsy, eligibility, harm_rows, subset_candidate


def build_quarantine_receipts(eligibility: dict[str, Any], subset_candidate: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    reduced = eligibility["status"] == "NOT_RUNTIME_ELIGIBLE_REDUCED_CORRECTNESS"
    quarantine = authority(
        schema_id="kt.v17_7_4.final_answer_contract_v2_quarantine_receipt.v1",
        status="PASS",
        global_finalizer_extraction_quarantined=reduced,
        final_answer_contract_v2_runtime_eligibility=eligibility["status"],
        integration_allowed=False if reduced else True,
        allowed_use="OFFLINE_REVIEW_ONLY" if reduced else "MICROFURNACE_REQUIRED_BEFORE_RUNTIME",
        expected_answers_as_hints_allowed=False,
        posthoc_correctness_as_runtime_authority_allowed=False,
    )
    subset_policy = authority(
        schema_id="kt.v17_7_4.final_answer_contract_v2_subset_policy_candidate.v1",
        status=subset_candidate["status"],
        subset_policy_available=subset_candidate["status"] == "SAFE_SUBSET_CANDIDATE_ONLY",
        candidate_only=True,
        global_runtime_authority=False,
        allowed_features=[
            "dataset",
            "task_family",
            "extraction_surface",
            "extraction_state",
            "output_surface_features_without_oracle_labels",
        ],
        forbidden_features=[
            "expected_answer",
            "expected_answer_hash",
            "posthoc_correctness",
            "oracle_route",
            "gold_label",
        ],
        safe_buckets=subset_candidate.get("safe_buckets", []),
        note="No safe subset is proposed unless evidence shows zero harm at bucket level.",
    )
    no_regression = authority(
        schema_id="kt.v17_7_4.final_answer_contract_v2_no_regression_requirements.v1",
        status="PASS",
        required_before_any_runtime_use=[
            "held-out micro-furnace with raw-output preservation",
            "no correctness regression by dataset/task_family/arm",
            "answer leakage scan",
            "negative controls do not score as success",
            "full/output/visible token ledgers remain separate",
        ],
        global_runtime_integration_blocked_until_non_regression=True,
    )
    return quarantine, subset_policy, no_regression


def manifest_summary(path: Path, role: str) -> dict[str, Any]:
    if not path.exists():
        return {"path": path.relative_to(ROOT).as_posix(), "role": role, "exists": False}
    payload = read_json(path)
    rows = payload.get("rows", [])
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "role": role,
        "exists": True,
        "sha256": sha256_file(path),
        "row_count": len(rows),
        "datasets": sorted({row.get("dataset") for row in rows}),
        "holdout_statuses": sorted({row.get("holdout_status") for row in rows}),
        "label_sources": sorted({row.get("label_source") for row in rows}),
        "scoring_rules": sorted({row.get("scoring_rule") for row in rows}),
    }


def heldout_source_is_bound(summary: dict[str, Any]) -> bool:
    return (
        summary.get("exists") is True
        and summary.get("row_count", 0) >= 50
        and "HELDOUT_NOT_FOR_PROMOTION" in summary.get("holdout_statuses", [])
        and "PUBLIC_BENCHMARK_GROUND_TRUTH" in summary.get("label_sources", [])
    )


def build_heldout_design() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    realbench = manifest_summary(REPROLOCK_REALBENCH_MANIFEST, "existing 50-row ReproLock/RealBench control source")
    diagnostic = manifest_summary(DIAGNOSTIC_ROW_MANIFEST, "diagnostic acquisition rows; not valid held-out generalization authority")
    bound_heldout = manifest_summary(BOUND_HELDOUT_MANIFEST, "candidate new held-out ReproLock row source")
    new_heldout_bound = heldout_source_is_bound(bound_heldout)
    design_status = "PASS_HELDOUT_PACKET_AUTHORIZABLE" if new_heldout_bound else "PASS_DESIGN_ONLY__HELDOUT_ROW_SOURCE_NOT_BOUND"
    design = authority(
        schema_id="kt.v17_7_4.heldout_generalization_design.v1",
        status=design_status,
        arm=core.REPROLOCK_ARM_ID,
        row_count=50,
        same_known_good_math_act_prompt_template=True,
        known_good_prompt_unchanged=True,
        finalizer_intervention=False,
        kt_hat_contamination=False,
        route_admission_changes=False,
        expected_answer_leakage_allowed=False,
        answer_leakage_scan_required=True,
        row_order_shuffle_required=True,
        negative_control_required=True,
        full_token_ledger_required=True,
        visible_token_ledger_required=True,
        parser_scorer_artifact_required=True,
        raw_outputs_saved_for_later_offline_replay=True,
        target_if_heldout_50=">=39/50 acceptable; >=41/50 strong",
        gsm8k_tracked_separately=True,
        test_type="generalization/control-integrity test, not compression test",
        current_sources={
            "existing_control": realbench,
            "diagnostic_rows": diagnostic,
            "bound_new_heldout": bound_heldout,
        },
        runtime_packet_authorizable=new_heldout_bound,
        blocked_reason=None if new_heldout_bound else "no bound new held-out ground-truth row manifest found",
    )
    selection = authority(
        schema_id="kt.v17_7_4.heldout_row_selection_receipt.v1",
        status="BOUND" if new_heldout_bound else "HELDOUT_ROW_SOURCE_NOT_BOUND",
        selected_manifest=BOUND_HELDOUT_MANIFEST.relative_to(ROOT).as_posix() if new_heldout_bound else None,
        excluded_sources=[
            {
                "path": REPROLOCK_REALBENCH_MANIFEST.relative_to(ROOT).as_posix(),
                "reason": "already used as current known-good control; eligible for row-order shuffle control, not new held-out generalization",
            },
            {
                "path": DIAGNOSTIC_ROW_MANIFEST.relative_to(ROOT).as_posix(),
                "reason": "diagnostic label source is not held-out public ground truth for ReproLock generalization",
            },
        ],
    )
    leakage_plan = authority(
        schema_id="kt.v17_7_4.reprolock_answer_leakage_negative_control_plan.v1",
        status="PASS",
        answer_leakage_scan_required=True,
        label_swap_negative_control_required=True,
        expected_answer_in_prompt_forbidden=True,
        expected_answer_visible_to_model=False,
        negative_control_success_condition="negative controls must not score as success",
        canary_rows_required=True,
    )
    shuffle_plan = authority(
        schema_id="kt.v17_7_4.reprolock_row_order_shuffle_plan.v1",
        status="PASS",
        row_order_shuffle_required=True,
        deterministic_seed=1774,
        prompt_hash_preservation_required=True,
        row_identity_preservation_required=True,
        known_good_prompt_template_mutation_allowed=False,
    )
    return design, selection, leakage_plan, shuffle_plan


def build_epc_decision(
    eligibility: dict[str, Any],
    subset_candidate: dict[str, Any],
    heldout_design: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if heldout_design.get("runtime_packet_authorizable") is True:
        recommended_lane = "HELD_OUT_REPROLOCK_GENERALIZATION_50"
        warranted = True
        packet_type = "packets/ktv1774_reprolock_heldout_generalization_v1.zip"
        dataset_name = "ktv1774-reprolock-heldout-v1"
        run_mode = "RUN_KTV1774_REPROLOCK_HELDOUT_GENERALIZATION_50"
        next_move = "AUTHOR_KTV1774_REPROLOCK_HELDOUT_GENERALIZATION_RUNTIME_PACKET"
        reason = "new bound held-out row source is present and final-answer extraction is quarantined"
    else:
        recommended_lane = "BIND_HELDOUT_REPROLOCK_ROW_SOURCE"
        warranted = False
        packet_type = None
        dataset_name = None
        run_mode = None
        next_move = NEXT_LAWFUL_MOVE
        reason = "final-answer extraction is harmful and no new bound held-out row source exists"

    decision = authority(
        schema_id="kt.v17_7_4.epc_decision_after_offline_extraction_review.v1",
        status="PASS",
        recommended_next_lane=recommended_lane,
        reason=reason,
        expected_information_gain=0.72 if warranted else 0.58,
        compute_cost="LOW_NARROW_HELDOUT_FURNACE" if warranted else "NONE_UNTIL_ROW_SOURCE_BOUND",
        authority_risk="LOW_INTERNAL_ONLY",
        blockers=[] if warranted else ["HELDOUT_ROW_SOURCE_NOT_BOUND"],
        stop_condition="stop if prompt identity mutates, answer leakage appears, negative controls score as success, or claim ceiling drifts",
        kaggle_packet_warranted_next=warranted,
        packet_type=packet_type,
        kaggle_dataset_name=dataset_name,
        run_mode=run_mode,
        final_answer_contract_v2_runtime_eligibility=eligibility["status"],
        safe_subset_available=subset_candidate["status"] == "SAFE_SUBSET_CANDIDATE_ONLY",
        training_authorized=False,
        promotion_authorized=False,
        route_promotion_authorized=False,
    )
    priority = authority(
        schema_id="kt.v17_7_4.epc_intervention_priority_queue_v5.v1",
        status="PASS",
        interventions=[
            {
                "rank": 1,
                "lane": recommended_lane,
                "reason": reason,
                "runtime_packet_warranted": warranted,
                "authority": "INTERNAL_EVIDENCE_ONLY",
            },
            {
                "rank": 2,
                "lane": "ROW_ORDER_SHUFFLE_AND_LEAKAGE_NEGATIVE_CONTROL_ON_EXISTING_50",
                "reason": "control-integrity test remains useful if new held-out source cannot be bound quickly",
                "runtime_packet_warranted": False,
                "authority": "NEXT_REPO_PACKET_CANDIDATE_ONLY",
            },
            {
                "rank": 3,
                "lane": "ABANDON_GLOBAL_FINALIZER_EXTRACTION_FOR_THIS_GENERATION_PATH",
                "reason": "current v2 extraction reduced correctness and has no harm-free safe subset",
                "runtime_packet_warranted": False,
                "authority": "QUARANTINE",
            },
        ],
    )
    next_lane = authority(
        schema_id="kt.v17_7_4.epc_next_evidence_lane_after_review.v1",
        status="PASS",
        next_lawful_move=next_move,
        no_training=True,
        no_promotion=True,
        no_v18=True,
        no_router_superiority_claim=True,
        no_g2_recovered_claim=True,
        no_commercial_claim=True,
        kaggle_packet_warranted_next=warranted,
        packet_path_if_any=packet_type,
        kaggle_dataset_name_if_any=dataset_name,
        run_mode_if_any=run_mode,
    )
    return decision, priority, next_lane


def write_static_surfaces() -> None:
    (ROOT / "docs").mkdir(exist_ok=True)
    (ROOT / "rules").mkdir(exist_ok=True)
    (ROOT / "schemas").mkdir(exist_ok=True)
    (ROOT / "docs" / "REPROLOCK_ORACLE_OFFLINE_EXTRACTION_EPC_REVIEW.md").write_text(
        """# ReproLock Oracle Offline Extraction EPC Review

This lane reviews the offline final-answer extraction v2 replay after it reduced correctness.
It does not train, promote, authorize V18, assert router superiority, or treat offline replay as runtime authority.

The law is simple: harmful global extraction is quarantined. A held-out ReproLock generalization packet may only be generated after a new held-out ground-truth row source is bound. Existing 50-row rows can support control-integrity checks, but not a new-heldout claim.
""",
        encoding="utf-8",
    )
    (ROOT / "rules" / "NO_EXTRACTION_RUNTIME_INTEGRATION_IF_HARMFUL.md").write_text(
        """# No Extraction Runtime Integration If Harmful

If offline final-answer extraction reduces correctness, it is not globally runtime-eligible.

It may remain offline-only, quarantined, or safe-subset candidate-only. Any safe subset must be proven by row-level evidence, must not use expected answers, oracle correctness, or post-hoc correctness as runtime policy features, and must pass a later no-regression micro-furnace before runtime use.
""",
        encoding="utf-8",
    )
    schema_template = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["schema_id", "status", "claim_ceiling_preserved"],
        "properties": {
            "schema_id": {"type": "string"},
            "status": {"type": "string"},
            "claim_ceiling_preserved": {"const": True},
        },
        "additionalProperties": True,
    }
    schemas = {
        "kt.v17_7_4.epc_review_decision.schema.json": "kt.v17_7_4.epc_decision_after_offline_extraction_review.v1",
        "kt.v17_7_4.extraction_failure_autopsy.schema.json": "kt.v17_7_4.extraction_failure_autopsy.v1",
        "kt.v17_7_4.final_answer_contract_v2_runtime_eligibility.schema.json": "kt.v17_7_4.final_answer_contract_v2_runtime_eligibility_receipt.v1",
        "kt.v17_7_4.heldout_generalization_design.schema.json": "kt.v17_7_4.heldout_generalization_design.v1",
    }
    for filename, schema_id in schemas.items():
        payload = dict(schema_template)
        payload["$id"] = f"https://kt.local/schemas/{filename}"
        payload["title"] = schema_id
        payload["properties"] = dict(schema_template["properties"])
        payload["properties"]["schema_id"] = {"const": schema_id}
        write_json(ROOT / "schemas" / filename, payload)


def artifact_delta(paths: list[Path], summary: dict[str, Any]) -> dict[str, Any]:
    artifacts = []
    for path in paths:
        if path.exists():
            artifacts.append(
                {
                    "path": path.relative_to(ROOT).as_posix(),
                    "sha256": sha256_file(path),
                    "size_bytes": path.stat().st_size,
                    "authority_state": "INTERNAL_REVIEW_RECEIPT_NO_RUNTIME_AUTHORITY",
                    "claim_expansion": False,
                }
            )
    return authority(
        schema_id="kt.artifact_authority_registry.delta.v17_7_4_epc_review_heldout.v1",
        status="PASS",
        current_head=summary["current_head"],
        artifacts_added=artifacts,
        outcome=summary["outcome"],
        next_lawful_move=summary["next_lawful_move"],
        no_training=True,
        no_promotion=True,
        no_v18=True,
        no_commercial_claim=True,
        no_external_validation_claim=True,
        no_router_superiority_claim=True,
        no_g2_recovered_claim=True,
    )


def main() -> int:
    write_static_surfaces()
    rows = read_jsonl(ROW_TABLE)
    scorecard = read_json(SCORECARD)
    if not rows:
        raise RuntimeError("KT_BLOCKED__EXTRACTION_FAILURE_AUTOPSY_DEFECT: offline row table missing")

    truth_pin, source_index, contradiction_scan = build_truth_pin()
    if truth_pin["status"] != "PASS":
        write_json(ROOT / "reports" / "v17_7_4_epc_review_truth_pin_receipt.json", truth_pin)
        write_json(ROOT / "reports" / "v17_7_4_epc_review_source_index.json", source_index)
        write_json(ROOT / "reports" / "v17_7_4_epc_review_contradiction_scan.json", contradiction_scan)
        raise RuntimeError("KT_BLOCKED__EPC_REVIEW_TRUTH_PIN_FAILED")

    autopsy, eligibility, harm_rows, subset_candidate = build_extraction_autopsy(rows, scorecard)
    quarantine, subset_policy, no_regression = build_quarantine_receipts(eligibility, subset_candidate)
    heldout_design, selection, leakage_plan, shuffle_plan = build_heldout_design()
    decision, priority, next_lane = build_epc_decision(eligibility, subset_candidate, heldout_design)

    packet_path = decision["packet_type"] if decision["kaggle_packet_warranted_next"] else None
    packet_sha = sha256_file(ROOT / packet_path) if packet_path and (ROOT / packet_path).exists() else None
    summary = authority(
        schema_id="kt.v17_7_4.epc_review_after_offline_extraction_builder_summary.v1",
        status="PASS",
        current_head=git(["rev-parse", "HEAD"]),
        current_branch=git(["branch", "--show-current"]),
        outcome=OUTCOME,
        files_changed=[
            "scripts/review_v17_7_4_epc_after_offline_extraction.py",
            "tests/test_v17_7_4_epc_review_heldout.py",
            "docs/REPROLOCK_ORACLE_OFFLINE_EXTRACTION_EPC_REVIEW.md",
            "rules/NO_EXTRACTION_RUNTIME_INTEGRATION_IF_HARMFUL.md",
        ],
        epc_review_truth_pin_status=truth_pin["status"],
        extraction_failure_autopsy_status=autopsy["status"],
        final_answer_contract_v2_runtime_eligibility_status=eligibility["status"],
        heldout_generalization_design_status=heldout_design["status"],
        epc_next_evidence_lane_status=next_lane["status"],
        packet_path_if_any=packet_path,
        packet_sha256_if_any=packet_sha,
        kaggle_dataset_name_if_any=decision["kaggle_dataset_name"],
        one_cell_runbook_if_any=None,
        claim_ceiling_status="PRESERVED",
        blockers=decision["blockers"],
        next_lawful_move=next_lane["next_lawful_move"],
        forbidden_claims=FORBIDDEN_CLAIMS,
    )

    outputs: list[tuple[Path, dict[str, Any]]] = [
        (ROOT / "reports" / "v17_7_4_epc_review_truth_pin_receipt.json", truth_pin),
        (ROOT / "reports" / "v17_7_4_epc_review_source_index.json", source_index),
        (ROOT / "reports" / "v17_7_4_epc_review_contradiction_scan.json", contradiction_scan),
        (ROOT / "reports" / "v17_7_4_offline_extraction_failure_autopsy.json", autopsy),
        (ROOT / "reports" / "v17_7_4_final_answer_contract_v2_runtime_eligibility_receipt.json", eligibility),
        (ROOT / "reports" / "v17_7_4_extraction_safe_subset_candidate.json", subset_candidate),
        (ROOT / "reports" / "v17_7_4_final_answer_contract_v2_quarantine_receipt.json", quarantine),
        (ROOT / "reports" / "v17_7_4_final_answer_contract_v2_subset_policy_candidate.json", subset_policy),
        (ROOT / "reports" / "v17_7_4_final_answer_contract_v2_no_regression_requirements.json", no_regression),
        (ROOT / "reports" / "v17_7_4_reprolock_heldout_generalization_design.json", heldout_design),
        (ROOT / "reports" / "v17_7_4_heldout_row_selection_receipt.json", selection),
        (ROOT / "reports" / "v17_7_4_reprolock_answer_leakage_negative_control_plan.json", leakage_plan),
        (ROOT / "reports" / "v17_7_4_reprolock_row_order_shuffle_plan.json", shuffle_plan),
        (ROOT / "reports" / "v17_7_4_epc_decision_after_offline_extraction_review.json", decision),
        (ROOT / "reports" / "v17_7_4_epc_intervention_priority_queue_v5.json", priority),
        (ROOT / "reports" / "v17_7_4_epc_next_evidence_lane_after_review.json", next_lane),
        (ROOT / "reports" / "v17_7_4_epc_review_after_offline_extraction_builder_summary.json", summary),
    ]
    for path, payload in outputs:
        write_json(path, payload)
    write_jsonl(ROOT / "reports" / "v17_7_4_extraction_harm_row_table.jsonl", harm_rows)
    delta = artifact_delta([path for path, _ in outputs] + [ROOT / "reports" / "v17_7_4_extraction_harm_row_table.jsonl"], summary)
    write_json(ROOT / "registry" / "artifact_authority_registry_v17_7_4_epc_review_heldout_delta_receipt.json", delta)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
