from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_PREP_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/router_superiority_recovery_prep_receipt.json"
DEFAULT_DIAGNOSIS_REL = "KT_PROD_CLEANROOM/reports/router_failure_diagnosis_packet.json"
DEFAULT_POLICY_REGISTRY_REL = "KT_PROD_CLEANROOM/reports/route_policy_outcome_registry.json"
DEFAULT_ALPHA_LOSE_REL = "KT_PROD_CLEANROOM/reports/alpha_should_lose_here_manifest.json"
DEFAULT_LOBE_SURVIVAL_REL = "KT_PROD_CLEANROOM/reports/lobe_survival_verdicts.json"
DEFAULT_PREREG_REL = "KT_PROD_CLEANROOM/reports/route_bearing_battery_preregistration.json"
DEFAULT_ORACLE_COUNTERFACTUAL_REL = "KT_PROD_CLEANROOM/reports/oracle_router_counterfactual_matrix.json"
DEFAULT_ABSTENTION_REL = "KT_PROD_CLEANROOM/reports/route_abstention_quality_report.json"
DEFAULT_NEGATIVE_LEDGER_REL = "KT_PROD_CLEANROOM/reports/negative_result_ledger.json"
DEFAULT_CURRENT_OVERLAY_REL = "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json"
DEFAULT_NEXT_WORKSTREAM_REL = "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json"
DEFAULT_RESUME_BLOCKERS_REL = "KT_PROD_CLEANROOM/reports/resume_blockers_receipt.json"

DEFAULT_STAGE_PACK_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/route_bearing_stage_pack_manifest.json"
DEFAULT_STAGE_PACK_INDEX_REL = "KT_PROD_CLEANROOM/reports/route_bearing_stage_pack_index.json"
DEFAULT_ORACLE_PACKET_REL = "KT_PROD_CLEANROOM/reports/oracle_router_local_eval_packet.json"
DEFAULT_ORACLE_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/oracle_router_local_scorecard.json"
DEFAULT_ORACLE_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/oracle_router_local_receipt.json"

OUTCOME_ROUTE = "ROUTE_TO_SPECIALIST"
OUTCOME_STAY = "STAY_STATIC_BASELINE"
OUTCOME_ABSTAIN = "ABSTAIN_FOR_REVIEW"
VISIBLE = "VISIBLE_TO_AUTHORING"
HELD_OUT = "HELD_OUT_FOR_GRADING_ONLY"


def _resolve_path(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _resolve_authoritative(root: Path, tracked_path: Path, ref_field: str, label: str) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(tracked_path, label=f"tracked {label}")
    authoritative_ref = str(tracked.get(ref_field, "")).strip()
    authoritative_path = _resolve_path(root, authoritative_ref) if authoritative_ref else tracked_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")


def _tracked_copy(obj: Dict[str, Any], *, carrier_role: str, ref_field: str, authoritative_path: Path) -> Dict[str, Any]:
    tracked = dict(obj)
    tracked["carrier_surface_role"] = carrier_role
    tracked[ref_field] = authoritative_path.as_posix()
    return tracked


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _resolve_subject_head(*, prep_receipt: Dict[str, Any], diagnosis: Dict[str, Any]) -> str:
    subject_heads = {
        str(prep_receipt.get("subject_head", "")).strip(),
        str(diagnosis.get("subject_head", "")).strip(),
    }
    subject_heads.discard("")
    if not subject_heads:
        raise RuntimeError("FAIL_CLOSED: stage-pack/oracle tranche could not resolve subject head")
    if len(subject_heads) != 1:
        raise RuntimeError("FAIL_CLOSED: stage-pack/oracle tranche requires one consistent subject head")
    return next(iter(subject_heads))


def _validate_inputs(
    *,
    prep_receipt: Dict[str, Any],
    diagnosis: Dict[str, Any],
    policy_registry: Dict[str, Any],
    alpha_manifest: Dict[str, Any],
    lobe_survival: Dict[str, Any],
    prereg: Dict[str, Any],
    oracle_counterfactual: Dict[str, Any],
    abstention_report: Dict[str, Any],
    negative_ledger: Dict[str, Any],
    overlay: Dict[str, Any],
    next_workstream: Dict[str, Any],
    resume_blockers: Dict[str, Any],
) -> None:
    if str(prep_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: router superiority recovery prep receipt must PASS")
    if str(prep_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_PREREGISTERED_ROUTE_BEARING_STAGE_PACK_AND_RUN_ORACLE_ROUTING":
        raise RuntimeError("FAIL_CLOSED: prep receipt must point to stage-pack/oracle tranche")
    if str(prep_receipt.get("prep_posture", "")).strip() != "ROUTER_SUPERIORITY_RECOVERY_PREP_BOUND__COUNTED_LANE_STILL_CLOSED":
        raise RuntimeError("FAIL_CLOSED: prep posture mismatch")

    if str(diagnosis.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: diagnosis packet must PASS")
    if str(diagnosis.get("next_lawful_move", "")).strip() != "AUTHOR_PREREGISTERED_ROUTE_BEARING_STAGE_PACK_AND_RUN_ORACLE_ROUTING":
        raise RuntimeError("FAIL_CLOSED: diagnosis packet next move mismatch")

    if str(policy_registry.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route policy outcome registry must PASS")
    outcome_ids = [str(row.get("outcome_id", "")).strip() for row in policy_registry.get("outcomes", []) if isinstance(row, dict)]
    if outcome_ids != [OUTCOME_ROUTE, OUTCOME_STAY, OUTCOME_ABSTAIN]:
        raise RuntimeError("FAIL_CLOSED: route policy outcomes must remain route/stay-static/abstain")

    if str(alpha_manifest.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: alpha should lose manifest must PASS")
    if not isinstance(alpha_manifest.get("rows"), list) or len(alpha_manifest["rows"]) < 6:
        raise RuntimeError("FAIL_CLOSED: alpha should lose manifest rows missing/invalid")

    if str(lobe_survival.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: lobe survival verdicts must PASS")
    if list(lobe_survival.get("selected_working_set", [])) != [
        "lobe.alpha.v1",
        "lobe.p2.v1",
        "lobe.child.v1",
        "lobe.strategist.v1",
        "lobe.beta.v1",
        "lobe.scout.v1",
        "lobe.auditor.v1",
    ]:
        raise RuntimeError("FAIL_CLOSED: working set mismatch")

    if str(prereg.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route-bearing battery preregistration must PASS")
    theorem_statement = str(prereg.get("theorem_statement", "")).strip().lower()
    if "route-bearing battery" not in theorem_statement:
        raise RuntimeError("FAIL_CLOSED: preregistration theorem statement mismatch")

    if str(oracle_counterfactual.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: oracle counterfactual matrix must PASS")
    if not isinstance(oracle_counterfactual.get("planned_family_rows"), list) or len(oracle_counterfactual["planned_family_rows"]) < 8:
        raise RuntimeError("FAIL_CLOSED: oracle counterfactual planned rows missing/invalid")

    if str(abstention_report.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route abstention quality report must PASS")
    if str(negative_ledger.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: negative result ledger must PASS")

    if bool(overlay.get("repo_state_executable_now")) is not False:
        raise RuntimeError("FAIL_CLOSED: overlay must keep counted lane closed")
    if str(overlay.get("next_counted_workstream_id", "")).strip() != "B04_R6_LEARNED_ROUTER_AUTHORIZATION":
        raise RuntimeError("FAIL_CLOSED: overlay next counted workstream mismatch")

    if bool(next_workstream.get("repo_state_executable_now")) is not False:
        raise RuntimeError("FAIL_CLOSED: next counted workstream contract must keep counted lane closed")
    if str(next_workstream.get("exact_next_counted_workstream_id", "")).strip() != "B04_R6_LEARNED_ROUTER_AUTHORIZATION":
        raise RuntimeError("FAIL_CLOSED: next counted workstream contract mismatch")

    if bool(resume_blockers.get("repo_state_executable_now")) is not False:
        raise RuntimeError("FAIL_CLOSED: resume blockers must keep counted lane closed")
    if str(resume_blockers.get("exact_next_counted_workstream_id", "")).strip() != "B04_R6_LEARNED_ROUTER_AUTHORIZATION":
        raise RuntimeError("FAIL_CLOSED: resume blockers mismatch")


def _specialist_case_prompt(*, row: Dict[str, Any], variant: str) -> str:
    if variant == "ADVERSARIAL":
        objective = str(row.get("adversarial_family", "")).strip()
        extra = "Make the decisive constraint easy to miss if the policy overweights decorative details."
    elif variant == "AMBIGUITY_BOUNDARY":
        objective = str(row.get("ambiguity_boundary_family", "")).strip()
        extra = "Reward lawful uncertainty, missing-variable isolation, and avoidance of premature commitment."
    elif variant == "GOVERNED_EXECUTION":
        objective = str(row.get("governed_execution_family", "")).strip()
        extra = "Make admissibility, receipts, and rollback consequences matter as much as prose quality."
    elif variant == "MIXED_PRESSURE":
        objective = (
            f"{str(row.get('adversarial_family', '')).strip()} Combine that with "
            f"{str(row.get('governed_execution_family', '')).strip().lower()} "
            "so the wrong route incurs visible downstream cost."
        )
        extra = "Pressure the route choice with ambiguity, time pressure, and governance exposure simultaneously."
    elif variant == "HELD_OUT_MUTATION":
        objective = (
            f"Mutation of {str(row.get('ambiguity_boundary_family', '')).strip()} and "
            f"{str(row.get('governed_execution_family', '')).strip().lower()}."
        )
        extra = "Keep the exact trap hidden from authoring-time optimization while preserving the preregistered liability."
    else:
        raise RuntimeError(f"FAIL_CLOSED: unsupported specialist case variant: {variant}")

    return (
        f"family_id={str(row.get('family_id', '')).strip()}; "
        f"target_lobe_id={str(row.get('target_lobe_id', '')).strip()}; "
        f"variant={variant}; "
        f"objective={objective} "
        f"alpha_liability={str(row.get('alpha_should_lose_here_because', '')).strip()} "
        f"acceptance_metric={str(row.get('acceptance_metric', '')).strip()} "
        f"trap_design={extra}"
    )


def _generic_prompt(*, family_id: str, variant: str, rationale: str, objective: str) -> str:
    return f"family_id={family_id}; variant={variant}; objective={objective} rationale={rationale}"


def _case_outcome(row: Dict[str, Any], *, variant: str) -> str:
    expected = str(row.get("expected_route_outcome", "")).strip()
    if expected == "ROUTE_TO_SPECIALIST":
        return OUTCOME_ROUTE
    if expected == "ROUTE_TO_SPECIALIST_OR_ABSTAIN":
        if variant in {"AMBIGUITY_BOUNDARY", "GOVERNED_EXECUTION", "HELD_OUT_MUTATION"}:
            return OUTCOME_ABSTAIN
        return OUTCOME_ROUTE
    raise RuntimeError(f"FAIL_CLOSED: unsupported expected_route_outcome: {expected}")


def _case_record(
    *,
    family_id: str,
    family_category: str,
    case_variant: str,
    pack_visibility: str,
    oracle_policy_outcome: str,
    target_lobe_id: str,
    alpha_liability: str,
    prompt: str,
    acceptance_metric: str,
    scoring_channels: Sequence[str],
    selected_adapter_ids: Sequence[str],
    route_justification: str = "",
    static_baseline_reason: str = "",
    abstention_reason: str = "",
    review_handoff_rule: str = "",
) -> Dict[str, Any]:
    case_id = f"{family_id}__{case_variant}"
    case = {
        "case_id": case_id,
        "family_id": family_id,
        "family_category": family_category,
        "case_variant": case_variant,
        "pack_visibility": pack_visibility,
        "baseline_policy_outcome": OUTCOME_STAY,
        "oracle_policy_outcome": oracle_policy_outcome,
        "target_lobe_id": target_lobe_id,
        "selected_adapter_ids": list(selected_adapter_ids),
        "alpha_liability": alpha_liability,
        "acceptance_metric": acceptance_metric,
        "scoring_channels": list(scoring_channels),
        "case_prompt": prompt,
        "route_justification": route_justification,
        "static_baseline_reason": static_baseline_reason,
        "abstention_reason": abstention_reason,
        "review_handoff_rule": review_handoff_rule,
    }
    case["case_sha256"] = _sha256_text(_canonical_json(case))
    return case


def _build_stage_pack_cases(
    *,
    alpha_manifest: Dict[str, Any],
    prereg: Dict[str, Any],
) -> List[Dict[str, Any]]:
    scoring_channels = [str(item) for item in prereg.get("scoring_channels", []) if str(item).strip()]
    if not scoring_channels:
        raise RuntimeError("FAIL_CLOSED: preregistration scoring channels missing/invalid")

    cases: List[Dict[str, Any]] = []
    variants = [
        ("ADVERSARIAL", VISIBLE),
        ("AMBIGUITY_BOUNDARY", VISIBLE),
        ("GOVERNED_EXECUTION", VISIBLE),
        ("MIXED_PRESSURE", VISIBLE),
        ("HELD_OUT_MUTATION", HELD_OUT),
    ]

    for row in alpha_manifest.get("rows", []):
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: alpha manifest row must be object")
        family_id = str(row.get("family_id", "")).strip()
        target_lobe_id = str(row.get("target_lobe_id", "")).strip()
        alpha_liability = str(row.get("alpha_should_lose_here_because", "")).strip()
        acceptance_metric = str(row.get("acceptance_metric", "")).strip()
        if not family_id or not target_lobe_id or not alpha_liability or not acceptance_metric:
            raise RuntimeError("FAIL_CLOSED: alpha manifest row missing required fields")

        for variant, visibility in variants:
            outcome = _case_outcome(row, variant=variant)
            prompt = _specialist_case_prompt(row=row, variant=variant)
            if outcome == OUTCOME_ROUTE:
                selected_adapter_ids = [target_lobe_id]
                route_justification = f"Route to {target_lobe_id} because {alpha_liability}"
                abstention_reason = ""
                review_handoff_rule = ""
            else:
                selected_adapter_ids = []
                route_justification = ""
                abstention_reason = (
                    "Forced commitment is unsafe here because the preregistered liability says fail-closed review can beat a premature answer."
                )
                review_handoff_rule = "Escalate to manual review and require explicit receipt repair before action."

            cases.append(
                _case_record(
                    family_id=family_id,
                    family_category="SPECIALIST_WEDGE",
                    case_variant=variant,
                    pack_visibility=visibility,
                    oracle_policy_outcome=outcome,
                    target_lobe_id=target_lobe_id,
                    alpha_liability=alpha_liability,
                    prompt=prompt,
                    acceptance_metric=acceptance_metric,
                    scoring_channels=scoring_channels,
                    selected_adapter_ids=selected_adapter_ids,
                    route_justification=route_justification,
                    abstention_reason=abstention_reason,
                    review_handoff_rule=review_handoff_rule,
                )
            )

    abstention_rationale = "Forced commitment under high ambiguity can cost more than lawful abstention."
    abstention_cases = [
        ("BOUNDARY_TRIAGE", VISIBLE, "High ambiguity with insufficient decisive evidence and a live review queue."),
        ("RECEIPT_GAP", VISIBLE, "Missing receipt chain or rollback proof should block action."),
        ("OVERCLAIM_GUARD", VISIBLE, "Content looks acceptable but the admissibility path is broken."),
        ("HELD_OUT_MUTATION", HELD_OUT, "Mutation family that hides the precise ambiguity trigger until grading."),
    ]
    for variant, visibility, objective in abstention_cases:
        cases.append(
            _case_record(
                family_id="BOUNDARY_ABSTENTION_CONTROL",
                family_category="ABSTENTION_CONTROL",
                case_variant=variant,
                pack_visibility=visibility,
                oracle_policy_outcome=OUTCOME_ABSTAIN,
                target_lobe_id="",
                alpha_liability=abstention_rationale,
                prompt=_generic_prompt(
                    family_id="BOUNDARY_ABSTENTION_CONTROL",
                    variant=variant,
                    rationale=abstention_rationale,
                    objective=objective,
                ),
                acceptance_metric="Lower failure cost than forced routing through lawful abstention and explicit review handoff.",
                scoring_channels=scoring_channels,
                selected_adapter_ids=[],
                abstention_reason=abstention_rationale,
                review_handoff_rule="Escalate to manual review and require a missing-evidence receipt before resuming.",
            )
        )

    static_rationale = "No liability should be asserted on true static-control families."
    static_cases = [
        ("DEFAULT_BASELINE", VISIBLE, "Pure control task where the static alpha baseline should remain canonical."),
        ("NO_ROUTE_PARITY", VISIBLE, "Case family that should reject gratuitous intervention and preserve baseline parity."),
        ("LOW_AMBIGUITY", VISIBLE, "High-certainty task where specialist routing adds no measurable value."),
        ("STABLE_GOVERNED", VISIBLE, "Governed execution task already fully handled by the static control path."),
        ("HELD_OUT_MUTATION", HELD_OUT, "Mutation of the control family that should still preserve the static decision."),
    ]
    for variant, visibility, objective in static_cases:
        cases.append(
            _case_record(
                family_id="STATIC_NO_ROUTE_CONTROL",
                family_category="STATIC_CONTROL",
                case_variant=variant,
                pack_visibility=visibility,
                oracle_policy_outcome=OUTCOME_STAY,
                target_lobe_id="lobe.alpha.v1",
                alpha_liability=static_rationale,
                prompt=_generic_prompt(
                    family_id="STATIC_NO_ROUTE_CONTROL",
                    variant=variant,
                    rationale=static_rationale,
                    objective=objective,
                ),
                acceptance_metric="No-regression hold on the static control path.",
                scoring_channels=scoring_channels,
                selected_adapter_ids=["lobe.alpha.v1"],
                static_baseline_reason=static_rationale,
            )
        )

    cases.sort(key=lambda item: (str(item["family_id"]), str(item["case_variant"])))
    return cases


def _index_row(case: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "case_id": str(case.get("case_id", "")).strip(),
        "family_id": str(case.get("family_id", "")).strip(),
        "family_category": str(case.get("family_category", "")).strip(),
        "case_variant": str(case.get("case_variant", "")).strip(),
        "pack_visibility": str(case.get("pack_visibility", "")).strip(),
        "oracle_policy_outcome": str(case.get("oracle_policy_outcome", "")).strip(),
        "target_lobe_id": str(case.get("target_lobe_id", "")).strip(),
        "case_sha256": str(case.get("case_sha256", "")).strip(),
    }


def _build_stage_pack_index(*, cases: Sequence[Dict[str, Any]], subject_head: str, current_head: str) -> Dict[str, Any]:
    rows = [_index_row(case) for case in cases]
    return {
        "schema_id": "kt.operator.route_bearing_stage_pack_index.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "current_git_head": current_head,
        "subject_head": subject_head,
        "claim_boundary": (
            "This tracked index binds the preregistered route-bearing court without exposing held-out prompt text. "
            "It is a carrier surface only."
        ),
        "case_count": len(rows),
        "rows": rows,
    }


def _family_summary_rows(*, cases: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for case in cases:
        grouped.setdefault(str(case["family_id"]), []).append(case)

    rows: List[Dict[str, Any]] = []
    for family_id in sorted(grouped):
        family_cases = grouped[family_id]
        first = family_cases[0]
        outcomes = sorted({str(case["oracle_policy_outcome"]) for case in family_cases})
        rows.append(
            {
                "family_id": family_id,
                "family_category": str(first["family_category"]),
                "target_lobe_id": str(first["target_lobe_id"]),
                "case_count": len(family_cases),
                "visible_case_count": sum(1 for case in family_cases if str(case["pack_visibility"]) == VISIBLE),
                "held_out_case_count": sum(1 for case in family_cases if str(case["pack_visibility"]) == HELD_OUT),
                "oracle_policy_outcomes": outcomes,
                "alpha_liability": str(first["alpha_liability"]),
                "acceptance_metric": str(first["acceptance_metric"]),
                "kaggle_target_eligible": any(
                    str(case["oracle_policy_outcome"]) == OUTCOME_ROUTE and str(case["target_lobe_id"]).strip() not in {"", "lobe.alpha.v1"}
                    for case in family_cases
                ),
            }
        )
    return rows


def _build_stage_pack_manifest(
    *,
    current_head: str,
    subject_head: str,
    prep_receipt: Dict[str, Any],
    diagnosis: Dict[str, Any],
    lobe_survival: Dict[str, Any],
    prereg: Dict[str, Any],
    cases: Sequence[Dict[str, Any]],
    stage_pack_cases_path: Path,
    tracked_stage_pack_index_path: Path,
) -> Dict[str, Any]:
    family_rows = _family_summary_rows(cases=cases)
    outcome_counts = {
        OUTCOME_ROUTE: sum(1 for case in cases if str(case["oracle_policy_outcome"]) == OUTCOME_ROUTE),
        OUTCOME_STAY: sum(1 for case in cases if str(case["oracle_policy_outcome"]) == OUTCOME_STAY),
        OUTCOME_ABSTAIN: sum(1 for case in cases if str(case["oracle_policy_outcome"]) == OUTCOME_ABSTAIN),
    }
    return {
        "schema_id": "kt.operator.route_bearing_stage_pack_manifest.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "current_git_head": current_head,
        "subject_head": subject_head,
        "claim_boundary": (
            "This manifest binds only the preregistered local proof court for oracle routing. "
            "It does not claim learned-router success, R6 authorization, or Gate E/F opening."
        ),
        "prep_posture": str(prep_receipt.get("prep_posture", "")).strip(),
        "proof_ceiling_summary": dict(diagnosis.get("proof_ceiling_summary", {})),
        "selected_working_set": list(lobe_survival.get("selected_working_set", [])),
        "quarantined_set": list(lobe_survival.get("quarantined_set", [])),
        "case_count": len(cases),
        "visible_case_count": sum(1 for case in cases if str(case["pack_visibility"]) == VISIBLE),
        "held_out_case_count": sum(1 for case in cases if str(case["pack_visibility"]) == HELD_OUT),
        "family_count": len(family_rows),
        "outcome_counts": outcome_counts,
        "family_rows": family_rows,
        "scoring_channels": list(prereg.get("scoring_channels", [])),
        "success_thresholds": list(prereg.get("success_thresholds", [])),
        "failure_thresholds": list(prereg.get("failure_thresholds", [])),
        "kaggle_opening_rule": "Only targeted hypertraining on oracle-positive families is admissible. Generic all-13 reruns remain forbidden.",
        "authoritative_stage_pack_cases_ref": stage_pack_cases_path.as_posix(),
        "tracked_stage_pack_index_ref": tracked_stage_pack_index_path.as_posix(),
    }


def _oracle_case_result(case: Dict[str, Any]) -> Dict[str, Any]:
    outcome = str(case["oracle_policy_outcome"])
    selected_adapter_ids = list(case.get("selected_adapter_ids", []))
    divergence_from_static = outcome != OUTCOME_STAY
    if outcome == OUTCOME_ROUTE:
        route_justification = str(case.get("route_justification", "")).strip()
        abstention_reason = ""
        review_handoff_rule = ""
        safety_effect = "ROUTE_EXPECTED_TO_REDUCE_ALPHA_LIABILITY"
    elif outcome == OUTCOME_ABSTAIN:
        route_justification = ""
        abstention_reason = str(case.get("abstention_reason", "")).strip()
        review_handoff_rule = str(case.get("review_handoff_rule", "")).strip()
        safety_effect = "ABSTENTION_EXPECTED_TO_DE_RISK_FORCED_COMMITMENT"
    else:
        route_justification = ""
        abstention_reason = ""
        review_handoff_rule = ""
        safety_effect = "STATIC_CONTROL_EXPECTED_TO_HOLD"

    return {
        "case_id": str(case["case_id"]),
        "family_id": str(case["family_id"]),
        "family_category": str(case["family_category"]),
        "case_variant": str(case["case_variant"]),
        "pack_visibility": str(case["pack_visibility"]),
        "oracle_policy_outcome": outcome,
        "selected_adapter_ids": selected_adapter_ids,
        "divergence_from_static": divergence_from_static,
        "route_justification": route_justification,
        "static_baseline_reason": str(case.get("static_baseline_reason", "")).strip(),
        "abstention_reason": abstention_reason,
        "review_handoff_rule": review_handoff_rule,
        "case_sha256": str(case["case_sha256"]),
        "safety_effect": safety_effect,
        "preregistered_expectation_satisfied": True,
    }


def _build_oracle_packet(
    *,
    current_head: str,
    subject_head: str,
    cases: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.oracle_router_local_eval_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "current_git_head": current_head,
        "subject_head": subject_head,
        "claim_boundary": (
            "This packet records deterministic oracle-policy routing on the preregistered court only. "
            "It does not claim routed-model superiority or learned-router authorization."
        ),
        "case_results": [_oracle_case_result(case) for case in cases],
    }


def _build_oracle_scorecard(
    *,
    current_head: str,
    subject_head: str,
    lobe_survival: Dict[str, Any],
    cases: Sequence[Dict[str, Any]],
    oracle_packet: Dict[str, Any],
) -> Dict[str, Any]:
    case_results = oracle_packet["case_results"]
    route_case_count = sum(1 for row in case_results if str(row["oracle_policy_outcome"]) == OUTCOME_ROUTE)
    stay_case_count = sum(1 for row in case_results if str(row["oracle_policy_outcome"]) == OUTCOME_STAY)
    abstain_case_count = sum(1 for row in case_results if str(row["oracle_policy_outcome"]) == OUTCOME_ABSTAIN)
    route_divergence_count = sum(1 for row in case_results if bool(row["divergence_from_static"]))
    family_rows = _family_summary_rows(cases=cases)
    oracle_positive_family_ids = [
        str(row["family_id"])
        for row in family_rows
        if OUTCOME_STAY not in list(row["oracle_policy_outcomes"]) or len(row["oracle_policy_outcomes"]) > 1
    ]
    kaggle_target_lobe_ids = []
    for adapter_id in lobe_survival.get("selected_working_set", []):
        candidate = str(adapter_id).strip()
        if candidate == "lobe.alpha.v1":
            continue
        if any(
            candidate == str(row["target_lobe_id"]).strip() and bool(row["kaggle_target_eligible"])
            for row in family_rows
        ):
            kaggle_target_lobe_ids.append(candidate)

    static_control_hold_pass = all(
        str(row["oracle_policy_outcome"]) == OUTCOME_STAY
        for row in case_results
        if str(row["family_category"]) == "STATIC_CONTROL"
    )
    held_out_case_count = sum(1 for row in case_results if str(row["pack_visibility"]) == HELD_OUT)
    held_out_mutation_present = held_out_case_count > 0
    abstention_family_present = any(str(row["oracle_policy_outcome"]) == OUTCOME_ABSTAIN for row in case_results)

    kaggle_admissible = all(
        [
            route_divergence_count > 0,
            route_case_count > 0,
            abstain_case_count > 0,
            stay_case_count > 0,
            static_control_hold_pass,
            held_out_mutation_present,
            len(kaggle_target_lobe_ids) > 0,
        ]
    )

    return {
        "schema_id": "kt.operator.oracle_router_local_scorecard.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "current_git_head": current_head,
        "subject_head": subject_head,
        "claim_boundary": (
            "This scorecard proves only that the preregistered local court can differentiate route/stay-static/abstain outcomes. "
            "It does not prove learned routing, superiority against alpha, or counted-lane reopening."
        ),
        "case_count": len(case_results),
        "visible_case_count": sum(1 for row in case_results if str(row["pack_visibility"]) == VISIBLE),
        "held_out_case_count": held_out_case_count,
        "route_case_count": route_case_count,
        "stay_static_case_count": stay_case_count,
        "abstain_case_count": abstain_case_count,
        "route_divergence_count": route_divergence_count,
        "nonzero_route_divergence": route_divergence_count > 0,
        "static_control_hold_pass": static_control_hold_pass,
        "abstention_family_present": abstention_family_present,
        "held_out_mutation_present": held_out_mutation_present,
        "oracle_positive_family_ids": oracle_positive_family_ids,
        "oracle_positive_lobe_ids": kaggle_target_lobe_ids,
        "quarantined_lobe_ids": list(lobe_survival.get("quarantined_set", [])),
        "generic_all_13_heavier_rerun_forbidden": True,
        "learned_router_still_forbidden": True,
        "kaggle_admissibility": "ADMISSIBLE_FOR_TARGETED_HYPERTRAINING_ONLY" if kaggle_admissible else "BLOCKED_PENDING_BETTER_LOCAL_COURT",
        "per_family_rows": family_rows,
    }


def run_route_bearing_stage_pack_oracle_tranche(
    *,
    prep_receipt_path: Path,
    diagnosis_path: Path,
    policy_registry_path: Path,
    alpha_manifest_path: Path,
    lobe_survival_path: Path,
    prereg_path: Path,
    oracle_counterfactual_path: Path,
    abstention_path: Path,
    negative_ledger_path: Path,
    current_overlay_path: Path,
    next_workstream_path: Path,
    resume_blockers_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()

    authoritative_prep_receipt_path, prep_receipt = _resolve_authoritative(
        root,
        prep_receipt_path.resolve(),
        "authoritative_router_superiority_recovery_prep_receipt_ref",
        "router superiority recovery prep receipt",
    )
    authoritative_diagnosis_path, diagnosis = _resolve_authoritative(
        root,
        diagnosis_path.resolve(),
        "authoritative_router_failure_diagnosis_packet_ref",
        "router failure diagnosis packet",
    )
    authoritative_policy_registry_path, policy_registry = _resolve_authoritative(
        root,
        policy_registry_path.resolve(),
        "authoritative_route_policy_outcome_registry_ref",
        "route policy outcome registry",
    )
    authoritative_alpha_manifest_path, alpha_manifest = _resolve_authoritative(
        root,
        alpha_manifest_path.resolve(),
        "authoritative_alpha_should_lose_here_manifest_ref",
        "alpha should lose manifest",
    )
    authoritative_lobe_survival_path, lobe_survival = _resolve_authoritative(
        root,
        lobe_survival_path.resolve(),
        "authoritative_lobe_survival_verdicts_ref",
        "lobe survival verdicts",
    )
    authoritative_prereg_path, prereg = _resolve_authoritative(
        root,
        prereg_path.resolve(),
        "authoritative_route_bearing_battery_preregistration_ref",
        "route-bearing battery preregistration",
    )
    authoritative_oracle_counterfactual_path, oracle_counterfactual = _resolve_authoritative(
        root,
        oracle_counterfactual_path.resolve(),
        "authoritative_oracle_router_counterfactual_matrix_ref",
        "oracle router counterfactual matrix",
    )
    authoritative_abstention_path, abstention_report = _resolve_authoritative(
        root,
        abstention_path.resolve(),
        "authoritative_route_abstention_quality_report_ref",
        "route abstention quality report",
    )
    authoritative_negative_ledger_path, negative_ledger = _resolve_authoritative(
        root,
        negative_ledger_path.resolve(),
        "authoritative_negative_result_ledger_ref",
        "negative result ledger",
    )
    overlay = _load_json_required(current_overlay_path.resolve(), label="current campaign state overlay")
    next_workstream = _load_json_required(next_workstream_path.resolve(), label="next counted workstream contract")
    resume_blockers = _load_json_required(resume_blockers_path.resolve(), label="resume blockers receipt")

    _validate_inputs(
        prep_receipt=prep_receipt,
        diagnosis=diagnosis,
        policy_registry=policy_registry,
        alpha_manifest=alpha_manifest,
        lobe_survival=lobe_survival,
        prereg=prereg,
        oracle_counterfactual=oracle_counterfactual,
        abstention_report=abstention_report,
        negative_ledger=negative_ledger,
        overlay=overlay,
        next_workstream=next_workstream,
        resume_blockers=resume_blockers,
    )

    subject_head = _resolve_subject_head(prep_receipt=prep_receipt, diagnosis=diagnosis)
    current_head = _git_head(root)
    cases = _build_stage_pack_cases(alpha_manifest=alpha_manifest, prereg=prereg)

    target_root = (
        authoritative_root.resolve()
        if authoritative_root is not None
        else (root / "tmp" / "route_bearing_stage_pack_oracle_current_head").resolve()
    )
    target_root.mkdir(parents=True, exist_ok=True)
    reports_root.mkdir(parents=True, exist_ok=True)

    authoritative_paths = {
        "route_bearing_stage_pack_cases": (target_root / "route_bearing_stage_pack_cases.json").resolve(),
        "route_bearing_stage_pack_manifest": (target_root / Path(DEFAULT_STAGE_PACK_MANIFEST_REL).name).resolve(),
        "oracle_router_local_eval_packet": (target_root / Path(DEFAULT_ORACLE_PACKET_REL).name).resolve(),
        "oracle_router_local_scorecard": (target_root / Path(DEFAULT_ORACLE_SCORECARD_REL).name).resolve(),
        "oracle_router_local_receipt": (target_root / Path(DEFAULT_ORACLE_RECEIPT_REL).name).resolve(),
    }
    tracked_stage_pack_index_path = (reports_root / Path(DEFAULT_STAGE_PACK_INDEX_REL).name).resolve()

    write_json_stable(
        authoritative_paths["route_bearing_stage_pack_cases"],
        {
            "schema_id": "kt.operator.route_bearing_stage_pack_cases.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "current_git_head": current_head,
            "subject_head": subject_head,
            "rows": cases,
        },
    )

    stage_pack_index = _build_stage_pack_index(cases=cases, subject_head=subject_head, current_head=current_head)
    stage_pack_manifest = _build_stage_pack_manifest(
        current_head=current_head,
        subject_head=subject_head,
        prep_receipt=prep_receipt,
        diagnosis=diagnosis,
        lobe_survival=lobe_survival,
        prereg=prereg,
        cases=cases,
        stage_pack_cases_path=authoritative_paths["route_bearing_stage_pack_cases"],
        tracked_stage_pack_index_path=tracked_stage_pack_index_path,
    )
    oracle_packet = _build_oracle_packet(current_head=current_head, subject_head=subject_head, cases=cases)
    oracle_scorecard = _build_oracle_scorecard(
        current_head=current_head,
        subject_head=subject_head,
        lobe_survival=lobe_survival,
        cases=cases,
        oracle_packet=oracle_packet,
    )

    receipt = {
        "schema_id": "kt.operator.oracle_router_local_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "current_git_head": current_head,
        "subject_head": subject_head,
        "oracle_stage_pack_posture": "PREREGISTERED_STAGE_PACK_BOUND__LOCAL_ORACLE_PASS__COUNTED_LANE_STILL_CLOSED",
        "claim_boundary": (
            "This tranche only binds a local route-bearing court and deterministic oracle policy. "
            "It does not authorize learned routing, R6, Gate E, Gate F, or commercialization."
        ),
        "counted_lane_guardrail": {
            "overlay_repo_state_executable_now": bool(overlay.get("repo_state_executable_now")),
            "next_counted_workstream_id": str(overlay.get("next_counted_workstream_id", "")).strip(),
            "next_contract_execution_mode": str(next_workstream.get("execution_mode", "")).strip(),
            "resume_blocking_state": str(resume_blockers.get("blocking_state", "")).strip(),
        },
        "source_refs": {
            "authoritative_router_superiority_recovery_prep_receipt_ref": authoritative_prep_receipt_path.as_posix(),
            "authoritative_router_failure_diagnosis_packet_ref": authoritative_diagnosis_path.as_posix(),
            "authoritative_route_policy_outcome_registry_ref": authoritative_policy_registry_path.as_posix(),
            "authoritative_alpha_should_lose_here_manifest_ref": authoritative_alpha_manifest_path.as_posix(),
            "authoritative_lobe_survival_verdicts_ref": authoritative_lobe_survival_path.as_posix(),
            "authoritative_route_bearing_battery_preregistration_ref": authoritative_prereg_path.as_posix(),
            "authoritative_oracle_router_counterfactual_matrix_ref": authoritative_oracle_counterfactual_path.as_posix(),
            "authoritative_route_abstention_quality_report_ref": authoritative_abstention_path.as_posix(),
            "authoritative_negative_result_ledger_ref": authoritative_negative_ledger_path.as_posix(),
        },
        "authoritative_output_refs": {
            "route_bearing_stage_pack_cases_ref": authoritative_paths["route_bearing_stage_pack_cases"].as_posix(),
            "route_bearing_stage_pack_manifest_ref": authoritative_paths["route_bearing_stage_pack_manifest"].as_posix(),
            "oracle_router_local_eval_packet_ref": authoritative_paths["oracle_router_local_eval_packet"].as_posix(),
            "oracle_router_local_scorecard_ref": authoritative_paths["oracle_router_local_scorecard"].as_posix(),
        },
        "kaggle_admissibility": str(oracle_scorecard.get("kaggle_admissibility", "")).strip(),
        "kaggle_target_lobe_ids": list(oracle_scorecard.get("oracle_positive_lobe_ids", [])),
        "quarantined_lobe_ids": list(lobe_survival.get("quarantined_set", [])),
        "generic_all_13_heavier_rerun_forbidden": True,
        "next_lawful_move": (
            "AUTHOR_TARGETED_HYPERTRAINING_STAGE_INPUTS_FOR_ORACLE_POSITIVE_FAMILIES"
            if str(oracle_scorecard.get("kaggle_admissibility", "")).strip() == "ADMISSIBLE_FOR_TARGETED_HYPERTRAINING_ONLY"
            else "REFINE_ROUTE_BEARING_COURT_BEFORE_KAGGLE"
        ),
    }

    write_json_stable(authoritative_paths["route_bearing_stage_pack_manifest"], stage_pack_manifest)
    write_json_stable(authoritative_paths["oracle_router_local_eval_packet"], oracle_packet)
    write_json_stable(authoritative_paths["oracle_router_local_scorecard"], oracle_scorecard)
    write_json_stable(authoritative_paths["oracle_router_local_receipt"], receipt)

    tracked_payloads = {
        Path(DEFAULT_STAGE_PACK_MANIFEST_REL).name: _tracked_copy(
            stage_pack_manifest,
            carrier_role="TRACKED_CARRIER_ONLY_ROUTE_BEARING_STAGE_PACK_MANIFEST",
            ref_field="authoritative_route_bearing_stage_pack_manifest_ref",
            authoritative_path=authoritative_paths["route_bearing_stage_pack_manifest"],
        ),
        Path(DEFAULT_STAGE_PACK_INDEX_REL).name: _tracked_copy(
            stage_pack_index,
            carrier_role="TRACKED_CARRIER_ONLY_ROUTE_BEARING_STAGE_PACK_INDEX",
            ref_field="authoritative_route_bearing_stage_pack_cases_ref",
            authoritative_path=authoritative_paths["route_bearing_stage_pack_cases"],
        ),
        Path(DEFAULT_ORACLE_PACKET_REL).name: _tracked_copy(
            oracle_packet,
            carrier_role="TRACKED_CARRIER_ONLY_ORACLE_ROUTER_LOCAL_EVAL_PACKET",
            ref_field="authoritative_oracle_router_local_eval_packet_ref",
            authoritative_path=authoritative_paths["oracle_router_local_eval_packet"],
        ),
        Path(DEFAULT_ORACLE_SCORECARD_REL).name: _tracked_copy(
            oracle_scorecard,
            carrier_role="TRACKED_CARRIER_ONLY_ORACLE_ROUTER_LOCAL_SCORECARD",
            ref_field="authoritative_oracle_router_local_scorecard_ref",
            authoritative_path=authoritative_paths["oracle_router_local_scorecard"],
        ),
        Path(DEFAULT_ORACLE_RECEIPT_REL).name: _tracked_copy(
            receipt,
            carrier_role="TRACKED_CARRIER_ONLY_ORACLE_ROUTER_LOCAL_RECEIPT",
            ref_field="authoritative_oracle_router_local_receipt_ref",
            authoritative_path=authoritative_paths["oracle_router_local_receipt"],
        ),
    }

    for filename, obj in tracked_payloads.items():
        write_json_stable((reports_root / filename).resolve(), obj)

    return {
        "route_bearing_stage_pack_manifest": stage_pack_manifest,
        "route_bearing_stage_pack_index": stage_pack_index,
        "oracle_router_local_eval_packet": oracle_packet,
        "oracle_router_local_scorecard": oracle_scorecard,
        "oracle_router_local_receipt": receipt,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Bind the local preregistered route-bearing court and run deterministic oracle routing before any Kaggle force step.")
    ap.add_argument("--prep-receipt", default=DEFAULT_PREP_RECEIPT_REL)
    ap.add_argument("--diagnosis", default=DEFAULT_DIAGNOSIS_REL)
    ap.add_argument("--policy-registry", default=DEFAULT_POLICY_REGISTRY_REL)
    ap.add_argument("--alpha-manifest", default=DEFAULT_ALPHA_LOSE_REL)
    ap.add_argument("--lobe-survival", default=DEFAULT_LOBE_SURVIVAL_REL)
    ap.add_argument("--prereg", default=DEFAULT_PREREG_REL)
    ap.add_argument("--oracle-counterfactual", default=DEFAULT_ORACLE_COUNTERFACTUAL_REL)
    ap.add_argument("--abstention-report", default=DEFAULT_ABSTENTION_REL)
    ap.add_argument("--negative-ledger", default=DEFAULT_NEGATIVE_LEDGER_REL)
    ap.add_argument("--current-overlay", default=DEFAULT_CURRENT_OVERLAY_REL)
    ap.add_argument("--next-workstream", default=DEFAULT_NEXT_WORKSTREAM_REL)
    ap.add_argument("--resume-blockers", default=DEFAULT_RESUME_BLOCKERS_REL)
    ap.add_argument(
        "--authoritative-root",
        default="",
        help="Optional authoritative output root. Default: <repo>/tmp/route_bearing_stage_pack_oracle_current_head",
    )
    ap.add_argument(
        "--reports-root",
        default="KT_PROD_CLEANROOM/reports",
        help="Tracked carrier report root. Default: KT_PROD_CLEANROOM/reports",
    )
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_route_bearing_stage_pack_oracle_tranche(
        prep_receipt_path=_resolve_path(root, str(args.prep_receipt)),
        diagnosis_path=_resolve_path(root, str(args.diagnosis)),
        policy_registry_path=_resolve_path(root, str(args.policy_registry)),
        alpha_manifest_path=_resolve_path(root, str(args.alpha_manifest)),
        lobe_survival_path=_resolve_path(root, str(args.lobe_survival)),
        prereg_path=_resolve_path(root, str(args.prereg)),
        oracle_counterfactual_path=_resolve_path(root, str(args.oracle_counterfactual)),
        abstention_path=_resolve_path(root, str(args.abstention_report)),
        negative_ledger_path=_resolve_path(root, str(args.negative_ledger)),
        current_overlay_path=_resolve_path(root, str(args.current_overlay)),
        next_workstream_path=_resolve_path(root, str(args.next_workstream)),
        resume_blockers_path=_resolve_path(root, str(args.resume_blockers)),
        authoritative_root=_resolve_path(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve_path(root, str(args.reports_root)),
        workspace_root=root,
    )
    receipt = payload["oracle_router_local_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "oracle_stage_pack_posture": receipt["oracle_stage_pack_posture"],
                "kaggle_admissibility": receipt["kaggle_admissibility"],
                "kaggle_target_lobe_ids": receipt["kaggle_target_lobe_ids"],
                "next_lawful_move": receipt["next_lawful_move"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
