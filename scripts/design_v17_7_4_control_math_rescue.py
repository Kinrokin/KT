from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core
from scripts import review_v17_7_4_math_scratchpad_failure as failure
from scripts.verify_v17_7_4_gsm8k_math_sidecar import verify_gsm8k_math_sidecar


TRANCHE = "AUTHOR_KTV1774_CONTROL_PRESERVING_MATH_VERIFIER_RESCUE_V1"
OUTCOME = "KT_CONTROL_PRESERVING_MATH_RESCUE_DESIGNED__OFFLINE_SIM_READY__CLAIM_CEILING_PRESERVED"
CONTROL_ARM = core.REPROLOCK_ARM_ID


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(core.AUTHORITY_FALSE)
    payload.update(
        {
            "claim_ceiling_preserved": True,
            "commercial_claim": False,
            "external_validation_claim": False,
            "frontier_claim": False,
            "g2_recovered_claim": False,
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


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows), encoding="utf-8")


def contract_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kt.v17_7_4.control_preserving_math_rescue_contract.schema.json",
        "type": "object",
        "required": [
            "schema_id",
            "status",
            "first_pass_arm",
            "first_pass_mutation_allowed",
            "expected_answer_visible_to_runtime",
            "rescue_policy",
            "runtime_authority",
        ],
        "properties": {
            "schema_id": {"const": "kt.v17_7_4.control_preserving_math_rescue_contract.v1"},
            "status": {"type": "string"},
            "first_pass_arm": {"const": CONTROL_ARM},
            "first_pass_mutation_allowed": {"const": False},
            "expected_answer_visible_to_runtime": {"const": False},
            "runtime_authority": {"const": False},
        },
        "additionalProperties": True,
    }


def sidecar_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kt.v17_7_4.math_verifier_sidecar.schema.json",
        "type": "object",
        "required": [
            "schema_id",
            "sample_id",
            "arm_id",
            "verdict",
            "rescue_eligible",
            "expected_answer_used",
            "model_generation_invoked",
            "first_pass_mutated",
        ],
        "properties": {
            "schema_id": {"const": "kt.v17_7_4.math_verifier_sidecar_result.v1"},
            "expected_answer_used": {"const": False},
            "model_generation_invoked": {"const": False},
            "first_pass_mutated": {"const": False},
        },
        "additionalProperties": True,
    }


def rescue_policy_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kt.v17_7_4.math_rescue_policy.schema.json",
        "type": "object",
        "required": [
            "schema_id",
            "policy_name",
            "first_pass_preserved",
            "rescue_allowed_only_after_abstain_or_fail",
            "training_authorized",
            "promotion_authority",
        ],
        "properties": {
            "schema_id": {"const": "kt.v17_7_4.math_rescue_policy.v1"},
            "first_pass_preserved": {"const": True},
            "training_authorized": {"const": False},
            "promotion_authority": {"const": False},
        },
        "additionalProperties": True,
    }


def build_offline_simulation(control_rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    row_table: list[dict[str, Any]] = []
    scorer_rows: list[dict[str, Any]] = []
    for row in sorted(control_rows, key=lambda item: str(item.get("sample_id"))):
        sidecar = verify_gsm8k_math_sidecar(row)
        first_pass_correct = row.get("correct") is True
        action = "KEEP_FIRST_PASS"
        if not first_pass_correct and sidecar["rescue_eligible"]:
            action = "RESCUE_ELIGIBLE_NOT_EXECUTED_OFFLINE"
        after_correct = first_pass_correct
        row_table.append(
            authority(
                schema_id="kt.v17_7_4.control_math_rescue_row.v1",
                sample_id=row.get("sample_id"),
                dataset=row.get("dataset"),
                task_family=row.get("task_family"),
                first_pass_arm=CONTROL_ARM,
                first_pass_correct=first_pass_correct,
                first_pass_answer_surface=sidecar["first_pass_answer_surface"],
                expected_answer_hash=row.get("expected_answer_hash"),
                output_hash=row.get("output_hash"),
                sidecar_verdict=sidecar["verdict"],
                rescue_eligible=sidecar["rescue_eligible"],
                policy_action=action,
                simulated_after_correct=after_correct,
                first_pass_mutated=False,
                model_generation_invoked=False,
                expected_answer_used_by_sidecar=False,
            )
        )
        scorer_rows.append(
            authority(
                schema_id="kt.v17_7_4.control_math_rescue_scorer_disagreement_row.v1",
                sample_id=row.get("sample_id"),
                parsed_answer=row.get("parsed_answer"),
                visible_answer=row.get("visible_answer"),
                sidecar_surface=sidecar["first_pass_answer_surface"],
                parser_format_failure=bool(row.get("parser_format_failure")),
                final_answer_marker_present=bool(row.get("final_answer_marker_present")),
                first_pass_correct=first_pass_correct,
                disagreement_type=(
                    "PARSER_OR_SURFACE_UNSTABLE"
                    if bool(row.get("parser_format_failure")) or sidecar["surface_source"] != "VISIBLE_ANSWER_FIELD"
                    else "NO_DISAGREEMENT_DETECTED"
                ),
            )
        )
    before_correct = sum(1 for row in row_table if row["first_pass_correct"])
    after_correct = sum(1 for row in row_table if row["simulated_after_correct"])
    rescue_eligible = sum(1 for row in row_table if row["rescue_eligible"])
    verifier_counts = Counter(row["sidecar_verdict"] for row in row_table)
    simulation = authority(
        schema_id="kt.v17_7_4.control_math_rescue_offline_simulation.v1",
        status="PASS_DESIGN_ONLY_NO_RUNTIME_AUTHORITY",
        row_count=len(row_table),
        first_pass_correct_before=before_correct,
        simulated_correct_after=after_correct,
        first_pass_damage_rows=0,
        rescue_executed_rows=0,
        rescue_eligible_rows=rescue_eligible,
        model_generation_invoked=False,
        expected_answer_visible_to_runtime=False,
        first_pass_mutation_allowed=False,
        runtime_authority=False,
        interpretation="Offline sidecar can identify rescue-eligible rows, but does not prove rescue correctness without a separate EPC-authorized microfurnace.",
        sidecar_verdict_counts=dict(sorted(verifier_counts.items())),
    )
    damage_rescue = authority(
        schema_id="kt.v17_7_4.control_math_rescue_damage_rescue_matrix.v1",
        status="PASS_NO_OFFLINE_DAMAGE_NO_EXECUTED_RESCUE",
        control_preserved=True,
        first_pass_damage_rows=0,
        rescue_eligible_rows=rescue_eligible,
        rescue_executed_rows=0,
        simulated_correct_delta=after_correct - before_correct,
        runtime_rescue_authority=False,
    )
    return simulation, row_table, damage_rescue, scorer_rows


def build_reports() -> dict[str, Any]:
    evidence = failure.load_evidence()
    metrics = failure.per_arm_metrics(evidence["arm_rows"])
    control_rows = [row for row in evidence["arm_rows"] if row.get("arm_id") == CONTROL_ARM]
    current_head = git(["rev-parse", "HEAD"])
    branch = git(["branch", "--show-current"])
    predecessor_summary = read_json(ROOT / "reports" / "v17_7_4_math_scratchpad_failure_review_builder_summary.json")
    predecessor_quarantine = read_json(ROOT / "reports" / "v17_7_4_math_scratchpad_candidate_quarantine_receipt.json")
    predecessor_ok = (
        predecessor_summary.get("status") == "PASS"
        and predecessor_quarantine.get("status") == "PASS"
        and predecessor_quarantine.get("all_candidates_worse_than_control") is True
    )
    simulation, row_table, damage_rescue, scorer_rows = build_offline_simulation(control_rows)
    rescue_verdict_counts = Counter(row["policy_action"] for row in row_table)

    truth_pin = authority(
        schema_id="kt.v17_7_4.control_math_rescue_truth_pin_receipt.v1",
        status="PASS",
        current_head=current_head,
        branch=branch,
        assessment_zip=str(evidence["assessment_zip"]),
        assessment_sha256=evidence["assessment_sha256"],
        predecessor_required=True,
        predecessor_bound=predecessor_ok,
        control_arm=CONTROL_ARM,
        control_rows=len(control_rows),
    )
    predecessor_binding = authority(
        schema_id="kt.v17_7_4.control_math_rescue_predecessor_binding.v1",
        status="PASS" if predecessor_ok else "BLOCKED_PREDECESSOR_FAILURE_REVIEW_NOT_BOUND",
        predecessor_outcome=predecessor_summary.get("outcome"),
        predecessor_next_lawful_move=predecessor_summary.get("next_lawful_move"),
        candidate_quarantine_status=predecessor_quarantine.get("status"),
        candidates_worse_than_control=predecessor_quarantine.get("all_candidates_worse_than_control"),
    )
    claim_boundary = authority(
        schema_id="kt.v17_7_4.control_math_rescue_claim_boundary_receipt.v1",
        status="PASS",
        allowed_claims=[
            "A control-preserving verifier/rescue design was created from the negative scratchpad result.",
            "The design preserves the known-good first pass and is offline-simulation only.",
        ],
        forbidden_claims=[
            "Do not claim rescue improved correctness.",
            "Do not claim runtime authority.",
            "Do not claim training, promotion, V18, router superiority, G2 recovery, commercial readiness, external validation, S-tier, 7B, or production readiness.",
        ],
    )
    contract = authority(
        schema_id="kt.v17_7_4.control_preserving_math_rescue_contract.v1",
        status="PASS",
        first_pass_arm=CONTROL_ARM,
        first_pass_mutation_allowed=False,
        expected_answer_visible_to_runtime=False,
        rescue_policy="SIDE_CAR_VERIFIER_THEN_OPTIONAL_RESCUE_ONLY_ON_FAIL_OR_ABSTAIN",
        runtime_authority=False,
        no_training=True,
        no_promotion=True,
        no_v18=True,
    )
    invariance = authority(
        schema_id="kt.v17_7_4.first_pass_invariance_receipt.v1",
        status="PASS",
        first_pass_arm=CONTROL_ARM,
        first_pass_correct=metrics[CONTROL_ARM]["correct"],
        first_pass_total=metrics[CONTROL_ARM]["total"],
        first_pass_full_tokens_per_correct=metrics[CONTROL_ARM]["full_tokens_per_correct"],
        first_pass_visible_tokens_per_correct=metrics[CONTROL_ARM]["visible_tokens_per_correct"],
        prompt_or_adapter_mutation_allowed=False,
        scratchpad_replacement_allowed=False,
        global_finalizer_allowed=False,
    )
    sidecar_design = authority(
        schema_id="kt.v17_7_4.math_verifier_sidecar_design.v1",
        status="PASS",
        sidecar_script="scripts/verify_v17_7_4_gsm8k_math_sidecar.py",
        expected_answer_used=False,
        model_generation_invoked=False,
        deterministic=True,
        inputs=["output_text", "parsed_answer", "visible_answer", "parser_format_failure", "final_answer_marker_present"],
        outputs=["verdict", "rescue_eligible", "first_pass_answer_surface", "surface_source"],
    )
    sidecar_limitations = authority(
        schema_id="kt.v17_7_4.math_verifier_sidecar_limitations.v1",
        status="PASS",
        limitations=[
            "Sidecar can detect unstable answer surfaces but cannot prove a corrected answer without a second-pass rescue run.",
            "Expected answers are used only for offline scoring, never as sidecar inputs.",
            "No runtime packet is authorized by this design alone.",
        ],
    )
    rescue_policy = authority(
        schema_id="kt.v17_7_4.math_rescue_policy.v1",
        status="PASS",
        policy_name="CONTROL_PRESERVING_FAIL_OR_ABSTAIN_RESCUE_ONLY",
        first_pass_preserved=True,
        rescue_allowed_only_after_abstain_or_fail=True,
        rescue_for_control_correct_rows=False,
        rescue_for_verifier_pass_rows=False,
        training_authorized=False,
        promotion_authority=False,
    )
    abstention = authority(
        schema_id="kt.v17_7_4.math_rescue_abstention_policy.v1",
        status="PASS",
        abstain_conditions=[
            "no numeric surface",
            "prompt echo risk",
            "parser surface unstable without final marker",
            "many numeric candidates without final marker",
        ],
        action_after_abstain="ELIGIBLE_FOR_SEPARATE_EPC_AUTHORIZED_RESCUE_RUN_ONLY",
        first_pass_answer_overwritten=False,
    )
    parser_blindness = authority(
        schema_id="kt.v17_7_4.control_math_rescue_parser_blindness_court.v1",
        status="PASS",
        finding="Parser and answer-surface uncertainty are valid rescue triggers, but not proof of corrected reasoning.",
        parser_blindness_not_runtime_authority=True,
        scorer_disagreement_rows=len([row for row in scorer_rows if row["disagreement_type"] != "NO_DISAGREEMENT_DETECTED"]),
    )
    answer_surface = authority(
        schema_id="kt.v17_7_4.control_math_rescue_answer_surface_audit.v1",
        status="PASS",
        policy_action_counts=dict(sorted(rescue_verdict_counts.items())),
        first_pass_visible_tpc=metrics[CONTROL_ARM]["visible_tokens_per_correct"],
        full_tpc=metrics[CONTROL_ARM]["full_tokens_per_correct"],
        visible_tpc_not_full_tpc=True,
    )
    epc = authority(
        schema_id="kt.v17_7_4.epc_decision_after_control_math_rescue_design.v1",
        status="PASS",
        selected_next_lane="REVIEW_CONTROL_PRESERVING_MATH_RESCUE_OFFLINE_SIMULATION",
        runtime_packet_authorized=False,
        reason="The design is control-preserving and identifies rescue-eligible rows, but no executed rescue correctness has been measured.",
        no_kaggle_runtime_packet=True,
        no_training=True,
        no_promotion=True,
    )
    next_lane = authority(
        schema_id="kt.v17_7_4.control_math_rescue_next_evidence_lane.v1",
        status="PASS",
        next_lawful_move="REVIEW_CONTROL_MATH_RESCUE_OFFLINE_SIMULATION__AUTHORIZE_TINY_RESCUE_FURNACE_ONLY_IF_EPC_APPROVES",
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
    )
    priority = authority(
        schema_id="kt.v17_7_4.control_math_rescue_intervention_priority_queue.v1",
        status="PASS",
        queue=[
            {
                "rank": 1,
                "intervention": "Verify sidecar abstention/rescue eligibility on control-wrong rows.",
                "runtime_authority": False,
            },
            {
                "rank": 2,
                "intervention": "If EPC authorizes, run a tiny rescue-only furnace on abstain/fail rows.",
                "runtime_authority": "REQUIRES_FUTURE_EPC_AUTHORIZATION",
            },
            {
                "rank": 3,
                "intervention": "Do not retry scratchpad arms unchanged.",
                "runtime_authority": False,
            },
        ],
    )
    summary = authority(
        schema_id="kt.v17_7_4.control_math_rescue_builder_summary.v1",
        status="PASS" if predecessor_ok else "BLOCKED_PREDECESSOR_NOT_BOUND",
        tranche=TRANCHE,
        outcome=OUTCOME if predecessor_ok else "KT_CONTROL_PRESERVING_MATH_RESCUE_BLOCKED__PREDECESSOR_NOT_BOUND",
        current_head=current_head,
        branch=branch,
        control_math_rescue_truth_pin_status=truth_pin["status"],
        predecessor_binding_status=predecessor_binding["status"],
        first_pass_invariance_status=invariance["status"],
        math_verifier_sidecar_status=sidecar_design["status"],
        offline_simulation_status=simulation["status"],
        epc_next_evidence_lane_status=next_lane["next_lawful_move"],
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        claim_ceiling_status="PRESERVED",
        blockers=[] if predecessor_ok else ["predecessor failure-review receipt not bound"],
        next_lawful_move=next_lane["next_lawful_move"] if predecessor_ok else "RERUN_MATH_SCRATCHPAD_FAILURE_REVIEW",
    )
    return {
        "reports": {
            "v17_7_4_control_math_rescue_truth_pin_receipt.json": truth_pin,
            "v17_7_4_control_math_rescue_predecessor_binding.json": predecessor_binding,
            "v17_7_4_control_math_rescue_claim_boundary_receipt.json": claim_boundary,
            "v17_7_4_control_preserving_math_rescue_contract.json": contract,
            "v17_7_4_first_pass_invariance_receipt.json": invariance,
            "v17_7_4_math_verifier_sidecar_design.json": sidecar_design,
            "v17_7_4_math_verifier_sidecar_limitations.json": sidecar_limitations,
            "v17_7_4_math_rescue_policy_design.json": rescue_policy,
            "v17_7_4_math_rescue_abstention_policy.json": abstention,
            "v17_7_4_control_math_rescue_offline_simulation.json": simulation,
            "v17_7_4_control_math_rescue_damage_rescue_matrix.json": damage_rescue,
            "v17_7_4_control_math_rescue_parser_blindness_court.json": parser_blindness,
            "v17_7_4_control_math_rescue_answer_surface_audit.json": answer_surface,
            "v17_7_4_epc_decision_after_control_math_rescue_design.json": epc,
            "v17_7_4_control_math_rescue_next_evidence_lane.json": next_lane,
            "v17_7_4_control_math_rescue_intervention_priority_queue.json": priority,
            "v17_7_4_control_math_rescue_builder_summary.json": summary,
        },
        "jsonl": {
            "v17_7_4_control_math_rescue_row_table.jsonl": row_table,
            "v17_7_4_control_math_rescue_scorer_disagreement_table.jsonl": scorer_rows,
        },
        "schemas": {
            "kt.v17_7_4.control_preserving_math_rescue_contract.schema.json": contract_schema(),
            "kt.v17_7_4.math_verifier_sidecar.schema.json": sidecar_schema(),
            "kt.v17_7_4.math_rescue_policy.schema.json": rescue_policy_schema(),
        },
    }


def main() -> int:
    built = build_reports()
    for name, payload in built["reports"].items():
        write_json(ROOT / "reports" / name, payload)
    for name, rows in built["jsonl"].items():
        write_jsonl(ROOT / "reports" / name, rows)
    for name, payload in built["schemas"].items():
        write_json(ROOT / "schemas" / name, payload)
    print(json.dumps(built["reports"]["v17_7_4_control_math_rescue_builder_summary.json"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
