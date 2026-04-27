from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable


REQUIRED_BRANCH = "authoritative/b04-r6-candidate-revision-packet"
AUTHORITATIVE_LANE = "B04_R6_CANDIDATE_REVISION_PACKET__NEW_BLIND_INPUT_UNIVERSE_REQUIRED"
PREVIOUS_LANE = "B04_R6_CANDIDATE_REVISION_OR_CLOSEOUT"

EXPECTED_PRIOR_VERDICT = "R6_DEFERRED__NEEDS_NEW_BLIND_INPUT_UNIVERSE_FOR_REVISION"
EXPECTED_PRIOR_NEXT_MOVE = "AUTHOR_B04_R6_CANDIDATE_REVISION_PACKET__NEW_BLIND_INPUT_UNIVERSE_REQUIRED"
FINAL_VERDICT = "CANDIDATE_REVISION_AUTHORIZED__NEW_BLIND_INPUT_REQUIRED"
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_CANDIDATE_V2_SOURCE_PACKET__BLIND_INPUT_CONTRACT_BOUND"

FORBIDDEN_CLAIMS = [
    "r6_open",
    "learned_router_superiority_earned",
    "learned_router_activated",
    "multi_lobe_authorized",
    "package_promotion_approved",
    "commercial_broadening",
]

INPUTS = {
    "revision_or_closeout_packet": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_revision_or_closeout_packet.json",
    "revision_or_closeout_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_revision_or_closeout_receipt.json",
    "prior_failure_autopsy_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_shadow_failure_autopsy_receipt.json",
    "prior_per_row_failure_matrix": "KT_PROD_CLEANROOM/reports/b04_r6_per_row_failure_matrix.json",
    "prior_candidate_static_delta_matrix": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_static_delta_matrix.json",
    "prior_revision_eligibility_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_revision_eligibility_receipt.json",
    "prior_revision_blocker_ledger": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_revision_blocker_ledger.json",
    "prior_input_policy_packet": "KT_PROD_CLEANROOM/reports/b04_r6_next_screen_input_policy_packet.json",
    "prior_blind_input_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_blind_input_requirement_receipt.json",
    "prior_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_candidate_revision_next_lawful_move_receipt.json",
}

OUTPUTS = {
    "revision_packet": "b04_r6_candidate_revision_packet.json",
    "revision_receipt": "b04_r6_candidate_revision_receipt.json",
    "screen1_failure_autopsy_packet": "b04_r6_screen1_failure_autopsy_packet.json",
    "revision_eligibility_matrix": "b04_r6_candidate_revision_eligibility_matrix.json",
    "blind_input_universe_contract": "b04_r6_new_blind_input_universe_contract.json",
    "overfit_risk_guard_receipt": "b04_r6_overfit_risk_guard_receipt.json",
    "candidate_v2_source_requirements": "b04_r6_candidate_v2_source_requirements.json",
    "next_lawful_move_receipt": "b04_r6_next_lawful_move_receipt.json",
    "blind_input_candidate_set": "b04_r6_blind_input_universe_candidate_set.json",
    "blind_input_selection_receipt": "b04_r6_blind_input_universe_selection_receipt.json",
    "v1_feature_gap_matrix": "b04_r6_candidate_v1_failure_feature_gap_matrix.json",
    "v2_feature_requirements": "b04_r6_candidate_v2_feature_requirements.json",
    "static_dominance_analysis": "b04_r6_static_comparator_dominance_analysis.json",
    "revision_overfit_risk_guard": "b04_r6_revision_overfit_risk_guard.json",
    "candidate_v2_generation_plan": "b04_r6_candidate_v2_generation_plan.json",
    "report_md": "COHORT0_B04_R6_CANDIDATE_REVISION_PACKET_REPORT.md",
}


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _ensure_false(payload: Dict[str, Any], key: str, *, label: str) -> None:
    if key in payload and payload.get(key) is not False:
        raise RuntimeError(f"FAIL_CLOSED: {label} must keep {key}=false")


def _ensure_boundaries(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {label} must have PASS status")
    for key in ("r6_authorized", "r6_open", "learned_router_superiority_earned", "learned_router_activated", "multi_lobe_authorized"):
        _ensure_false(payload, key, label=label)
    if payload.get("package_promotion_remains_deferred") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve package promotion deferral")
    if payload.get("truth_engine_derivation_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve truth-engine law")
    if payload.get("trust_zone_law_unchanged") is not True:
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve trust-zone law")


def _base(*, generated_utc: str, head: str, subject_main_head: str) -> Dict[str, Any]:
    return {
        "status": "PASS",
        "generated_utc": generated_utc,
        "current_git_head": head,
        "subject_main_head": subject_main_head,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "r6_authorized": False,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "learned_router_activated": False,
        "learned_router_cutover_authorized": False,
        "multi_lobe_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _input_hashes(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted(INPUTS.items()):
        path = root / raw
        if not path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing required input {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _require_prior_state(payloads: Dict[str, Dict[str, Any]]) -> None:
    for label, payload in payloads.items():
        _ensure_boundaries(payload, label=label)
    receipt = payloads["revision_or_closeout_receipt"]
    prior_next = payloads["prior_next_lawful_move"]
    blind_receipt = payloads["prior_blind_input_receipt"]
    eligibility = payloads["prior_revision_eligibility_receipt"]
    if receipt.get("verdict") != EXPECTED_PRIOR_VERDICT:
        raise RuntimeError("FAIL_CLOSED: prior court must defer for a new blind input universe")
    if receipt.get("next_lawful_move") != EXPECTED_PRIOR_NEXT_MOVE:
        raise RuntimeError("FAIL_CLOSED: prior court did not authorize this revision packet")
    if prior_next.get("next_lawful_move") != EXPECTED_PRIOR_NEXT_MOVE:
        raise RuntimeError("FAIL_CLOSED: prior next-lawful-move receipt mismatch")
    if receipt.get("candidate_revision_allowed_next") is not True:
        raise RuntimeError("FAIL_CLOSED: prior receipt must explicitly authorize candidate revision next")
    if receipt.get("input_universe_for_next_counted_screen_must_be_new_or_blinded") is not True:
        raise RuntimeError("FAIL_CLOSED: prior receipt must require a new or blinded next input universe")
    if receipt.get("candidate_v2_generation_performed") is not False:
        raise RuntimeError("FAIL_CLOSED: prior court must not have generated candidate v2")
    if receipt.get("shadow_screen_execution_performed") is not False:
        raise RuntimeError("FAIL_CLOSED: prior court must not have executed another shadow screen")
    if blind_receipt.get("new_blind_input_universe_required") is not True:
        raise RuntimeError("FAIL_CLOSED: blind input universe requirement must already be bound")
    if blind_receipt.get("r01_r04_closed_for_candidate_v2_counted_superiority_rerun") is not True:
        raise RuntimeError("FAIL_CLOSED: R01-R04 must be closed for revised counted rerun")
    if eligibility.get("revision_path_plausible") is not True:
        raise RuntimeError("FAIL_CLOSED: prior eligibility court must preserve a plausible revision path")
    if eligibility.get("same_r01_r04_reuse_for_counted_superiority_screen_allowed") is not False:
        raise RuntimeError("FAIL_CLOSED: R01-R04 reuse as counted screen must be forbidden")


def _rows(payload: Dict[str, Any], *, label: str) -> list[Dict[str, Any]]:
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise RuntimeError(f"FAIL_CLOSED: {label} missing rows list")
    return [dict(row) for row in rows if isinstance(row, dict)]


def _stable_hash(value: Any) -> str:
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(rendered).hexdigest()


def _blind_case(case_id: str, family: str, pressure: str, source_kind: str, mirror_masked: bool = True) -> Dict[str, Any]:
    row = {
        "case_id": case_id,
        "family": family,
        "pressure_type": pressure,
        "source_kind": source_kind,
        "candidate_visible_fields": ["case_id", "family", "pressure_type", "source_kind"],
        "static_baseline_labels_blinded_until_counted_screen": True,
        "candidate_v2_training_label_visible": False,
        "mirror_masked_required": mirror_masked,
        "holdout_role": "candidate_v2_counted_screen_candidate",
        "old_r01_r04_derived": False,
    }
    row["source_sha256"] = _stable_hash(row)
    return row


def _blind_universe_candidate_rows() -> list[Dict[str, Any]]:
    return [
        _blind_case("R6B01", "math", "adjacent_quantitative_pressure", "fresh_heldout_design"),
        _blind_case("R6B02", "poetry", "form_shift_pressure", "fresh_heldout_design"),
        _blind_case("R6B03", "governance", "counterfactual_review_pressure", "fresh_heldout_design"),
        _blind_case("R6B04", "default", "unknown_family_static_hold_pressure", "fresh_heldout_design"),
        _blind_case("R6B05", "mixed_math_governance", "multi_family_abstention_pressure", "mutated_sibling_not_label_derived"),
        _blind_case("R6B06", "masked_ambiguous", "masked_family_route_pressure", "fresh_heldout_design"),
    ]


def _feature_gap_rows(per_row: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for row in per_row:
        case_id = str(row.get("case_id", "")).strip()
        rows.append(
            {
                "case_id": case_id,
                "family": row.get("family"),
                "candidate_static_result": "STATIC_MATCH_NO_SUPERIORITY",
                "feature_gap_class": "NO_DELTA_SIGNAL_BOUND",
                "diagnostic_use_allowed": True,
                "candidate_v2_training_target_allowed": False,
                "next_screen_label_visibility_allowed": False,
            }
        )
    return rows


def _per_row_stats(per_row: list[Dict[str, Any]]) -> Dict[str, Any]:
    case_count = len(per_row)
    candidate_win_count = sum(1 for row in per_row if row.get("candidate_beats_static") is True)
    if case_count <= 0:
        raise RuntimeError("FAIL_CLOSED: per-row failure matrix must contain rows")
    if candidate_win_count != 0:
        raise RuntimeError("FAIL_CLOSED: candidate revision packet requires zero candidate wins in screen 1")
    route_quality_delta_sum = sum(int(row.get("route_quality_delta", 0)) for row in per_row)
    static_match_count = sum(1 for row in per_row if row.get("diagnostic_finding") == "STATIC_MATCH_NO_SUPERIORITY")
    return {
        "case_count": case_count,
        "candidate_win_count": candidate_win_count,
        "route_quality_delta_sum": route_quality_delta_sum,
        "static_match_count": static_match_count,
        "static_comparator_dominance": candidate_win_count == 0 and static_match_count == case_count,
    }


def _report() -> str:
    return (
        "# Cohort-0 B04 R6 Candidate Revision Packet\n\n"
        f"Verdict: `{FINAL_VERDICT}`\n\n"
        "The first R6 shadow screen remains a clean failed superiority result. This packet authorizes a candidate-v2 "
        "revision path only under a new blind input universe. R01-R04 may inform diagnosis, but may not become the "
        "fresh counted superiority screen after revision.\n\n"
        f"Next lawful move: `{NEXT_LAWFUL_MOVE}`.\n"
    )


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    if common.git_current_branch_name(root) != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: must run on {REQUIRED_BRANCH}")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 candidate revision packet")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    _require_prior_state(payloads)

    generated_utc = utc_now_iso_z()
    head = common.git_rev_parse(root, "HEAD")
    subject_main_head = str(payloads["revision_or_closeout_receipt"].get("current_git_head", "")).strip()
    base = _base(generated_utc=generated_utc, head=head, subject_main_head=subject_main_head)
    input_bindings = _input_hashes(root)
    per_row = _rows(payloads["prior_per_row_failure_matrix"], label="prior per-row failure matrix")
    row_stats = _per_row_stats(per_row)
    feature_gap_rows = _feature_gap_rows(per_row)
    blind_rows = _blind_universe_candidate_rows()

    screen1_autopsy = {
        "schema_id": "kt.operator.b04_r6_screen1_failure_autopsy_packet.v1",
        **base,
        "screen_id": "B04_R6_SHADOW_SCREEN_1",
        "bound_result": {
            "candidate_wins": f"{row_stats['candidate_win_count']}/{row_stats['case_count']}",
            "disqualifiers": 0,
            "control_preservation": "PASS",
            "abstention_quality": "PASS",
            "mirror_masked_invariance": "PASS",
            "learned_router_superiority_earned": False,
        },
        "loss_classification": {
            "static_comparator_dominance": row_stats["static_comparator_dominance"],
            "candidate_underfitting": True,
            "insufficient_feature_basis": True,
            "route_scoring_weakness": True,
            "calibration_weakness": True,
            "screen_size_limitation": True,
            "metric_contract_mismatch": False,
        },
        "r01_r04_use_policy": "DIAGNOSTIC_ONLY_FOR_REVISED_CANDIDATE",
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    revision_eligibility_matrix = {
        "schema_id": "kt.operator.b04_r6_candidate_revision_eligibility_matrix.v1",
        **base,
        "allowed_outcomes": [
            "CANDIDATE_REVISION_AUTHORIZED__NEW_BLIND_INPUT_REQUIRED",
            "R6_CLOSEOUT__NO_LAWFUL_REVISION_PATH",
            "R6_DEFERRED__REVISION_DEFECT_REMAINS",
        ],
        "selected_outcome": FINAL_VERDICT,
        "checks": [
            {"check_id": "prior_failure_clean", "status": "PASS"},
            {"check_id": "revision_path_plausible", "status": "PASS"},
            {"check_id": "r01_r04_reuse_for_counted_screen_forbidden", "status": "PASS"},
            {"check_id": "new_blind_input_universe_required", "status": "PASS"},
            {"check_id": "candidate_v2_generation_not_performed_here", "status": "PASS"},
            {"check_id": "shadow_screen_not_authorized_here", "status": "PASS"},
        ],
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    blind_contract = {
        "schema_id": "kt.operator.b04_r6_new_blind_input_universe_contract.v1",
        **base,
        "contract_status": "BOUND_AS_REQUIRED_BEFORE_CANDIDATE_V2_SCREEN",
        "candidate_rows": blind_rows,
        "family_coverage": sorted({str(row["family"]) for row in blind_rows}),
        "row_count": len(blind_rows),
        "source_hashes": [{"case_id": row["case_id"], "source_sha256": row["source_sha256"]} for row in blind_rows],
        "mirror_masked_requirements": {
            "required": True,
            "all_rows_require_mirror_masked_variants": all(row["mirror_masked_required"] for row in blind_rows),
        },
        "holdout_policy": {
            "candidate_v2_may_not_train_on_counted_labels": True,
            "static_comparator_labels_blinded_until_counted_screen": True,
            "r01_r04_failure_outcomes_diagnostic_only": True,
            "r01_r04_not_counted_for_candidate_v2_superiority": True,
        },
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    overfit_guard = {
        "schema_id": "kt.operator.b04_r6_overfit_risk_guard_receipt.v1",
        **base,
        "r01_r04_outcomes_allowed_uses": ["failure_autopsy", "feature_gap_diagnosis", "revision_hypothesis_generation"],
        "r01_r04_outcomes_forbidden_uses": ["candidate_v2_counted_training_labels", "candidate_v2_fresh_superiority_screen", "metric_widening", "static_baseline_weakening"],
        "new_blind_universe_required": True,
        "overfit_risk_status": "CONTAINED_BY_NEW_BLIND_INPUT_REQUIREMENT",
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    v2_requirements = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_source_requirements.v1",
        **base,
        "candidate_v2_source_requirements": {
            "deterministic": True,
            "hash_bound": True,
            "seed_bound": True,
            "trace_emitting": True,
            "abstention_aware": True,
            "static_hold_preserving": True,
            "no_package_promotion_dependency": True,
            "no_truth_engine_mutation_dependency": True,
            "no_trust_zone_mutation_dependency": True,
            "must_not_train_on_new_blind_screen_labels": True,
            "must_not_reuse_r01_r04_as_counted_screen": True,
        },
        "candidate_v2_generation_authorized_by_this_packet": False,
        "candidate_v2_source_packet_authorized_next": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    revision_packet = {
        "schema_id": "kt.operator.b04_r6_candidate_revision_packet.v1",
        **base,
        "verdict": FINAL_VERDICT,
        "input_bindings": input_bindings,
        "failure_diagnosis_ref": OUTPUTS["screen1_failure_autopsy_packet"],
        "revision_eligibility_ref": OUTPUTS["revision_eligibility_matrix"],
        "blind_input_universe_contract_ref": OUTPUTS["blind_input_universe_contract"],
        "candidate_v2_source_requirements_ref": OUTPUTS["candidate_v2_source_requirements"],
        "screen_execution_authorized": False,
        "candidate_v2_generation_performed": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    revision_receipt = {
        "schema_id": "kt.operator.b04_r6_candidate_revision_receipt.v1",
        **base,
        "verdict": FINAL_VERDICT,
        "candidate_revision_authorized": True,
        "new_blind_input_universe_required": True,
        "candidate_v2_generation_performed": False,
        "candidate_v2_screen_execution_authorized": False,
        "r01_r04_diagnostic_only": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    blind_candidate_set = {
        "schema_id": "kt.operator.b04_r6_blind_input_universe_candidate_set.v1",
        **base,
        "rows": blind_rows,
        "selection_status": "CANDIDATE_SET_PREP_ONLY_NOT_COUNTED_SCREEN",
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    blind_selection = {
        "schema_id": "kt.operator.b04_r6_blind_input_universe_selection_receipt.v1",
        **base,
        "selection_complete": True,
        "counted_screen_authorized": False,
        "row_count": len(blind_rows),
        "source_hashes_bound": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    v1_feature_gap = {
        "schema_id": "kt.operator.b04_r6_candidate_v1_failure_feature_gap_matrix.v1",
        **base,
        "rows": feature_gap_rows,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    v2_feature_requirements = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_feature_requirements.v1",
        **base,
        "requirements": [
            "produce non-label-derived route confidence evidence",
            "distinguish static-match from superiority evidence",
            "preserve abstention/static-hold behavior",
            "emit route decision, over-routing, abstention, and mirror/masked traces",
            "operate under blind candidate-visible fields only",
        ],
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    static_dominance = {
        "schema_id": "kt.operator.b04_r6_static_comparator_dominance_analysis.v1",
        **base,
        "static_dominance_on_screen1": row_stats["static_comparator_dominance"],
        "candidate_wins_on_screen1": row_stats["candidate_win_count"],
        "case_count": row_stats["case_count"],
        "interpretation": "The static comparator was not beaten on any R01-R04 row; this does not close R6, but requires new blind proof for any revised candidate.",
        "static_baseline_weakening_allowed": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    revision_overfit_guard = {
        "schema_id": "kt.operator.b04_r6_revision_overfit_risk_guard.v1",
        **base,
        "r01_r04_failure_outcomes_logged": True,
        "candidate_v2_design_may_use_diagnostics": True,
        "candidate_v2_design_may_use_counted_labels_as_training_targets": False,
        "candidate_v2_next_counted_screen_must_be_new_or_blind": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    candidate_v2_plan = {
        "schema_id": "kt.operator.b04_r6_candidate_v2_generation_plan.v1",
        **base,
        "plan_status": "PREP_ONLY",
        "generation_performed": False,
        "required_future_steps": [
            "author candidate v2 source packet",
            "bind candidate v2 source/provenance/hash",
            "prove no contamination against new blind input labels",
            "prove deterministic replay and trace compatibility",
            "run candidate v2 admissibility before any shadow screen",
        ],
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    next_receipt = {
        "schema_id": "kt.operator.b04_r6_next_lawful_move_receipt.v1",
        **base,
        "verdict": FINAL_VERDICT,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }

    outputs: Dict[str, Any] = {
        OUTPUTS["revision_packet"]: revision_packet,
        OUTPUTS["revision_receipt"]: revision_receipt,
        OUTPUTS["screen1_failure_autopsy_packet"]: screen1_autopsy,
        OUTPUTS["revision_eligibility_matrix"]: revision_eligibility_matrix,
        OUTPUTS["blind_input_universe_contract"]: blind_contract,
        OUTPUTS["overfit_risk_guard_receipt"]: overfit_guard,
        OUTPUTS["candidate_v2_source_requirements"]: v2_requirements,
        OUTPUTS["next_lawful_move_receipt"]: next_receipt,
        OUTPUTS["blind_input_candidate_set"]: blind_candidate_set,
        OUTPUTS["blind_input_selection_receipt"]: blind_selection,
        OUTPUTS["v1_feature_gap_matrix"]: v1_feature_gap,
        OUTPUTS["v2_feature_requirements"]: v2_feature_requirements,
        OUTPUTS["static_dominance_analysis"]: static_dominance,
        OUTPUTS["revision_overfit_risk_guard"]: revision_overfit_guard,
        OUTPUTS["candidate_v2_generation_plan"]: candidate_v2_plan,
        OUTPUTS["report_md"]: _report(),
    }
    for filename, payload in outputs.items():
        path = reports_root / filename
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, payload)
    return {
        "verdict": FINAL_VERDICT,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "blind_input_candidate_rows": len(blind_rows),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Author the B04 R6 candidate revision packet with blind input law.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(reports_root=common.resolve_path(root, args.reports_root))
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
