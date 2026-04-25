from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_R5_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/router_vs_best_adapter_proof_ratification_receipt.json"
DEFAULT_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/router_superiority_scorecard.json"
DEFAULT_SHADOW_MATRIX_REL = "KT_PROD_CLEANROOM/reports/router_shadow_eval_matrix.json"
DEFAULT_ROUTE_HEALTH_REL = "KT_PROD_CLEANROOM/reports/route_distribution_health.json"
DEFAULT_SELECTION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/kt_wave2b_router_selection_receipt.json"
DEFAULT_IMPORT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_adapter_import_receipt.json"
DEFAULT_TOURNAMENT_EXECUTION_REL = "KT_PROD_CLEANROOM/reports/cohort0_tournament_execution_receipt.json"
DEFAULT_FOLLOWTHROUGH_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_tournament_followthrough_packet.json"
DEFAULT_CURRENT_OVERLAY_REL = "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json"
DEFAULT_NEXT_WORKSTREAM_REL = "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json"
DEFAULT_RESUME_BLOCKERS_REL = "KT_PROD_CLEANROOM/reports/resume_blockers_receipt.json"

DEFAULT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/router_superiority_recovery_prep_receipt.json"
DEFAULT_DIAGNOSIS_REL = "KT_PROD_CLEANROOM/reports/router_failure_diagnosis_packet.json"
DEFAULT_POLICY_REGISTRY_REL = "KT_PROD_CLEANROOM/reports/route_policy_outcome_registry.json"
DEFAULT_ALPHA_LOSE_REL = "KT_PROD_CLEANROOM/reports/alpha_should_lose_here_manifest.json"
DEFAULT_LOBE_SURVIVAL_REL = "KT_PROD_CLEANROOM/reports/lobe_survival_verdicts.json"
DEFAULT_PREREG_REL = "KT_PROD_CLEANROOM/reports/route_bearing_battery_preregistration.json"
DEFAULT_ORACLE_COUNTERFACTUAL_REL = "KT_PROD_CLEANROOM/reports/oracle_router_counterfactual_matrix.json"
DEFAULT_ABSTENTION_REL = "KT_PROD_CLEANROOM/reports/route_abstention_quality_report.json"
DEFAULT_NEGATIVE_LEDGER_REL = "KT_PROD_CLEANROOM/reports/negative_result_ledger.json"

KEEP_ACTIVE_WEDGE_CANDIDATE = "KEEP_ACTIVE_WEDGE_CANDIDATE"
CONTROL_ANCHOR = "CONTROL_ANCHOR__STATIC_BEST_ADAPTER_CURRENT_CYCLE"
QUARANTINE_STATIC_DEP = "QUARANTINE__STATIC_DEPENDENCY_ONLY_UNTIL_NEW_COURT"
QUARANTINE_NO_SIGNAL = "QUARANTINE__INSUFFICIENT_ROUTE_SIGNAL"


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


def _append_unique(items: List[str], extra: str) -> None:
    candidate = str(extra).strip()
    if candidate and candidate not in items:
        items.append(candidate)


def _resolve_subject_head(*, packets: Sequence[Dict[str, Any]]) -> str:
    subject_heads = {
        str(packet.get("subject_head", "")).strip()
        for packet in packets
        if isinstance(packet, dict) and str(packet.get("subject_head", "")).strip()
    }
    if not subject_heads:
        raise RuntimeError("FAIL_CLOSED: router recovery prep could not resolve any subject head")
    if len(subject_heads) != 1:
        raise RuntimeError("FAIL_CLOSED: router recovery prep requires one consistent subject head")
    return next(iter(subject_heads))


def _validate_selection_receipt_head_alignment(
    *,
    selection_receipt: Dict[str, Any],
    current_head: str,
    subject_head: str,
) -> None:
    selection_subject_head = str(selection_receipt.get("subject_head", "")).strip()
    if selection_subject_head and selection_subject_head not in {current_head, subject_head}:
        raise RuntimeError(
            "FAIL_CLOSED: router selection receipt subject_head must stay on the authoritative subject head "
            "or the current carrier head"
        )


def _validate_inputs(
    *,
    r5_receipt: Dict[str, Any],
    scorecard: Dict[str, Any],
    shadow_matrix: Dict[str, Any],
    route_health: Dict[str, Any],
    selection_receipt: Dict[str, Any],
    import_receipt: Dict[str, Any],
    tournament_execution: Dict[str, Any],
    followthrough_packet: Dict[str, Any],
    overlay: Dict[str, Any],
    next_workstream: Dict[str, Any],
    resume_blockers: Dict[str, Any],
) -> None:
    if str(r5_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: router proof receipt must PASS")
    if bool(r5_receipt.get("router_proof_summary", {}).get("router_superiority_earned")) is not False:
        raise RuntimeError("FAIL_CLOSED: router recovery prep only applies after non-earned superiority")
    if str(r5_receipt.get("next_lawful_move", "")).strip() != "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF":
        raise RuntimeError("FAIL_CLOSED: router proof receipt must leave R6 blocked")

    if str(scorecard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: router superiority scorecard must PASS")
    if bool(scorecard.get("superiority_earned")) is not False:
        raise RuntimeError("FAIL_CLOSED: scorecard must keep superiority unearned")

    if str(shadow_matrix.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: router shadow eval matrix must PASS")
    if not isinstance(shadow_matrix.get("rows"), list) or not shadow_matrix["rows"]:
        raise RuntimeError("FAIL_CLOSED: router shadow eval matrix rows missing/invalid")

    if str(route_health.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route distribution health must PASS")
    if str(selection_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: router selection receipt must PASS")

    if str(import_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: current-head import receipt must PASS")
    if int(import_receipt.get("adapter_count", 0)) != 13:
        raise RuntimeError("FAIL_CLOSED: current-head import receipt must bind 13 adapters")

    if str(tournament_execution.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: tournament execution receipt must PASS")
    if str(followthrough_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: tournament followthrough packet must PASS")

    if overlay.get("repo_state_executable_now") is not False:
        raise RuntimeError("FAIL_CLOSED: current overlay must keep counted lane closed")
    if str(overlay.get("next_counted_workstream_id", "")).strip() != "B04_R6_LEARNED_ROUTER_AUTHORIZATION":
        raise RuntimeError("FAIL_CLOSED: current overlay next counted workstream mismatch")

    if next_workstream.get("repo_state_executable_now") is not False:
        raise RuntimeError("FAIL_CLOSED: next counted workstream contract must keep counted lane closed")
    if str(next_workstream.get("exact_next_counted_workstream_id", "")).strip() != "B04_R6_LEARNED_ROUTER_AUTHORIZATION":
        raise RuntimeError("FAIL_CLOSED: next counted workstream contract next step mismatch")

    if resume_blockers.get("repo_state_executable_now") is not False:
        raise RuntimeError("FAIL_CLOSED: resume blockers must keep counted lane closed")
    if str(resume_blockers.get("exact_next_counted_workstream_id", "")).strip() != "B04_R6_LEARNED_ROUTER_AUTHORIZATION":
        raise RuntimeError("FAIL_CLOSED: resume blockers next step mismatch")


def _load_tournament_result(root: Path, execution_receipt: Dict[str, Any]) -> Dict[str, Any]:
    result_ref = str(execution_receipt.get("tournament_result_ref", "")).strip()
    if not result_ref:
        raise RuntimeError("FAIL_CLOSED: tournament execution receipt missing tournament_result_ref")
    return _load_json_required(_resolve_path(root, result_ref), label="tournament result")


def _load_eval_reports(root: Path, import_receipt: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    full_run_root_raw = str(import_receipt.get("full_run_root", "")).strip()
    if not full_run_root_raw:
        raise RuntimeError("FAIL_CLOSED: import receipt missing full_run_root")
    full_run_root = _resolve_path(root, full_run_root_raw)
    adapters_root = (full_run_root / "adapters").resolve()
    if not adapters_root.is_dir():
        raise RuntimeError(f"FAIL_CLOSED: missing adapters directory under full_run_root: {adapters_root.as_posix()}")

    out: Dict[str, Dict[str, Any]] = {}
    for adapter_root in sorted(adapters_root.iterdir()):
        if not adapter_root.is_dir():
            continue
        adapter_id = adapter_root.name
        out[adapter_id] = _load_json_required(adapter_root / "eval_report.json", label=f"{adapter_id} eval_report")
    if len(out) != 13:
        raise RuntimeError("FAIL_CLOSED: expected 13 eval_report.json files in imported run root")
    return out


def _rank_tournament(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    entrants = result.get("entrants")
    pairs = result.get("dominance_pairs")
    if not isinstance(entrants, list) or not isinstance(pairs, list):
        raise RuntimeError("FAIL_CLOSED: tournament result entrants/dominance_pairs missing/invalid")
    name_by_hash = {}
    for row in entrants:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: tournament entrant must be object")
        adapter_id = str(row.get("adapter_id", "")).strip()
        root_hash = str(row.get("adapter_root_hash", "")).strip()
        if not adapter_id or not root_hash:
            raise RuntimeError("FAIL_CLOSED: tournament entrant missing adapter_id/adapter_root_hash")
        name_by_hash[root_hash] = adapter_id

    wins: Dict[str, int] = {adapter_id: 0 for adapter_id in name_by_hash.values()}
    losses: Dict[str, int] = {adapter_id: 0 for adapter_id in name_by_hash.values()}
    for pair in pairs:
        if not isinstance(pair, dict):
            raise RuntimeError("FAIL_CLOSED: dominance pair must be object")
        dominant = name_by_hash[str(pair.get("dominant_adapter_root_hash", "")).strip()]
        dominated = name_by_hash[str(pair.get("dominated_adapter_root_hash", "")).strip()]
        wins[dominant] += 1
        losses[dominated] += 1

    ranked: List[Dict[str, Any]] = []
    for row in entrants:
        adapter_id = str(row.get("adapter_id", "")).strip()
        ranked.append(
            {
                "adapter_id": adapter_id,
                "adapter_root_hash": str(row.get("adapter_root_hash", "")).strip(),
                "wins": wins[adapter_id],
                "losses": losses[adapter_id],
                "net": wins[adapter_id] - losses[adapter_id],
            }
        )
    ranked.sort(key=lambda item: (-int(item["wins"]), int(item["losses"]), str(item["adapter_id"])))
    for idx, row in enumerate(ranked, start=1):
        row["rank"] = idx
    return ranked


def _baseline_dependency_ids(selection_receipt: Dict[str, Any]) -> List[str]:
    rows = selection_receipt.get("case_rows")
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: router selection receipt case_rows missing/invalid")
    found: List[str] = []
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: router selection case row must be object")
        baseline = row.get("baseline_static_adapter_path") if isinstance(row.get("baseline_static_adapter_path"), dict) else {}
        for adapter_id in baseline.get("selected_adapter_ids", []):
            _append_unique(found, str(adapter_id))
    return found


def _survival_template(adapter_id: str) -> Dict[str, str]:
    templates = {
        "lobe.p2.v1": {
            "wedge_hypothesis": "Signal-noise separation under decoy constraints.",
            "anti_alpha_hypothesis": "Alpha looks broadly competent but can compress decisive and non-decisive constraints into the same answer.",
            "liability_type": "over_generalization_under_noisy_constraints",
        },
        "lobe.child.v1": {
            "wedge_hypothesis": "Anomaly preservation and non-flattened edge-case retention.",
            "anti_alpha_hypothesis": "Alpha can smooth away rare but decisive anomalies when trying to stay coherent.",
            "liability_type": "anomaly_flattening",
        },
        "lobe.strategist.v1": {
            "wedge_hypothesis": "Sequencing and downstream-consequence discipline across multi-step tasks.",
            "anti_alpha_hypothesis": "Alpha can converge too early on a plausible local answer without pricing later-stage cost.",
            "liability_type": "premature_convergence",
        },
        "lobe.beta.v1": {
            "wedge_hypothesis": "Second-order reframing and counter-position stabilization.",
            "anti_alpha_hypothesis": "Alpha can overcommit to the first clean framing instead of testing a rival interpretation.",
            "liability_type": "single_frame_lock_in",
        },
        "lobe.scout.v1": {
            "wedge_hypothesis": "Sparse search and candidate-space exploration before commitment.",
            "anti_alpha_hypothesis": "Alpha can undersample the candidate space when a better path requires exploration before synthesis.",
            "liability_type": "insufficient_exploration",
        },
        "lobe.auditor.v1": {
            "wedge_hypothesis": "Admissibility, traceability, and fail-closed procedure under pressure.",
            "anti_alpha_hypothesis": "Alpha can produce acceptable prose while underpricing missing receipts, broken procedures, or overclaim risk.",
            "liability_type": "procedural_admissibility_drift",
        },
    }
    return templates.get(
        adapter_id,
        {
            "wedge_hypothesis": "Unspecified wedge.",
            "anti_alpha_hypothesis": "No admissible anti-alpha hypothesis has been registered yet.",
            "liability_type": "UNSPECIFIED",
        },
    )


def _build_lobe_survival_verdicts(
    *,
    ranked: List[Dict[str, Any]],
    eval_reports: Dict[str, Dict[str, Any]],
    baseline_dependency_ids: List[str],
) -> Dict[str, Any]:
    verdict_rows: List[Dict[str, Any]] = []
    keep_ids: List[str] = []
    quarantine_ids: List[str] = []
    for row in ranked:
        adapter_id = str(row["adapter_id"])
        eval_report = eval_reports.get(adapter_id, {})
        utility_floor_score = float(eval_report.get("utility_floor_score", 0.0))
        if adapter_id == "lobe.alpha.v1":
            verdict = CONTROL_ANCHOR
            reason = "Current tournament champion and control anchor for alpha-liability testing."
            _append_unique(keep_ids, adapter_id)
        elif int(row["wins"]) >= int(row["losses"]):
            verdict = KEEP_ACTIVE_WEDGE_CANDIDATE
            reason = "Current graph shows non-negative competitive signal; keep as live wedge candidate."
            _append_unique(keep_ids, adapter_id)
        elif adapter_id in baseline_dependency_ids:
            verdict = QUARANTINE_STATIC_DEP
            reason = "Present in the current static router baseline, but current graph signal is too weak to fund direct wedge training yet."
            _append_unique(quarantine_ids, adapter_id)
        else:
            verdict = QUARANTINE_NO_SIGNAL
            reason = "Current graph signal is too weak to justify direct route-bearing investment."
            _append_unique(quarantine_ids, adapter_id)

        template = _survival_template(adapter_id)
        verdict_rows.append(
            {
                "adapter_id": adapter_id,
                "rank": int(row["rank"]),
                "wins": int(row["wins"]),
                "losses": int(row["losses"]),
                "net": int(row["net"]),
                "utility_floor_score": utility_floor_score,
                "current_static_baseline_dependency": adapter_id in baseline_dependency_ids,
                "survival_verdict": verdict,
                "reason": reason,
                "wedge_hypothesis": template["wedge_hypothesis"],
                "anti_alpha_hypothesis": template["anti_alpha_hypothesis"],
                "liability_type": template["liability_type"],
            }
        )

    return {
        "schema_id": "kt.operator.lobe_survival_verdicts.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "claim_boundary": (
            "These verdicts are branch-planning surfaces only. They do not retire or ratify lobes by themselves, "
            "and they do not reopen the counted lane."
        ),
        "control_anchor_adapter_id": "lobe.alpha.v1",
        "selected_working_set": keep_ids,
        "quarantined_set": quarantine_ids,
        "verdict_rows": verdict_rows,
    }


def _build_alpha_should_lose_manifest(*, lobe_survival: Dict[str, Any]) -> Dict[str, Any]:
    rows = []
    for row in lobe_survival["verdict_rows"]:
        adapter_id = str(row["adapter_id"])
        if adapter_id == "lobe.alpha.v1":
            continue
        if str(row["survival_verdict"]) != KEEP_ACTIVE_WEDGE_CANDIDATE:
            continue

        if adapter_id == "lobe.p2.v1":
            rows.append(
                {
                    "family_id": "P2_SIGNAL_NOISE_SEPARATION",
                    "target_lobe_id": adapter_id,
                    "alpha_should_lose_here_because": "Alpha can blur decisive and decorative constraints into one plausible plan when the court is too soft.",
                    "adversarial_family": "Prompt sets with decoy constraints and one hidden decisive constraint.",
                    "ambiguity_boundary_family": "Underspecified tasks where the correct move is to isolate the missing decisive variable instead of answering confidently.",
                    "governed_execution_family": "Operator triage tasks where evidence ranking matters before action.",
                    "acceptance_metric": "Lower failure cost than alpha with equal-or-better traceability and constraint fidelity.",
                    "expected_route_outcome": "ROUTE_TO_SPECIALIST",
                }
            )
        elif adapter_id == "lobe.child.v1":
            rows.append(
                {
                    "family_id": "CHILD_ANOMALY_PRESERVATION",
                    "target_lobe_id": adapter_id,
                    "alpha_should_lose_here_because": "Alpha can flatten rare anomalies into a coherent median answer even when the anomaly is the point.",
                    "adversarial_family": "Cases where one rare observation invalidates the default summary.",
                    "ambiguity_boundary_family": "Boundary prompts where correct behavior is to preserve anomaly structure instead of normalizing it away.",
                    "governed_execution_family": "Receipt review tasks where a small mismatch should halt execution.",
                    "acceptance_metric": "Higher anomaly retention and lower silent-normalization rate than alpha.",
                    "expected_route_outcome": "ROUTE_TO_SPECIALIST",
                }
            )
        elif adapter_id == "lobe.strategist.v1":
            rows.append(
                {
                    "family_id": "STRATEGIST_CONSEQUENCE_CHAIN",
                    "target_lobe_id": adapter_id,
                    "alpha_should_lose_here_because": "Alpha can stop at a locally good answer without pricing downstream failure cost.",
                    "adversarial_family": "Multi-step work-order problems where sequence quality dominates single-step cleverness.",
                    "ambiguity_boundary_family": "Tasks where several plausible starts exist but only one preserves later optionality.",
                    "governed_execution_family": "Gate-order tasks where missing a dependency should count as a loss even if the prose sounds strong.",
                    "acceptance_metric": "Lower downstream-error rate and better step-order discipline than alpha.",
                    "expected_route_outcome": "ROUTE_TO_SPECIALIST",
                }
            )
        elif adapter_id == "lobe.beta.v1":
            rows.append(
                {
                    "family_id": "BETA_SECOND_ORDER_REFRAME",
                    "target_lobe_id": adapter_id,
                    "alpha_should_lose_here_because": "Alpha can overcommit to the first clean framing instead of holding a live rival interpretation.",
                    "adversarial_family": "Prompts with two plausible framings where the safer or stronger answer requires second-order reframing.",
                    "ambiguity_boundary_family": "Cases where wrong early framing amplifies overclaim risk.",
                    "governed_execution_family": "Decision memos that should preserve alternatives rather than collapse them prematurely.",
                    "acceptance_metric": "Better rival-frame preservation and lower framing-lock error cost than alpha.",
                    "expected_route_outcome": "ROUTE_TO_SPECIALIST",
                }
            )
        elif adapter_id == "lobe.scout.v1":
            rows.append(
                {
                    "family_id": "SCOUT_SPARSE_SEARCH",
                    "target_lobe_id": adapter_id,
                    "alpha_should_lose_here_because": "Alpha can synthesize too early when the right move is to widen the search before choosing.",
                    "adversarial_family": "Sparse candidate tasks where the winning option is not the first plausible option.",
                    "ambiguity_boundary_family": "Prompts where evidence is too thin for immediate commitment and exploration should dominate synthesis.",
                    "governed_execution_family": "Investigation tasks where missing candidate coverage is itself a failure.",
                    "acceptance_metric": "Higher candidate coverage and lower early-commit error cost than alpha.",
                    "expected_route_outcome": "ROUTE_TO_SPECIALIST",
                }
            )
        elif adapter_id == "lobe.auditor.v1":
            rows.append(
                {
                    "family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
                    "target_lobe_id": adapter_id,
                    "alpha_should_lose_here_because": "Alpha can sound acceptable while underpricing receipt gaps, policy breaks, or overclaim risk.",
                    "adversarial_family": "Tasks where the answer looks fine but the admissibility path is broken.",
                    "ambiguity_boundary_family": "Cases where the correct move is to abstain or fail closed instead of improvising.",
                    "governed_execution_family": "Operator tasks where missing evidence, rollback, or traceability should dominate content quality.",
                    "acceptance_metric": "Higher fail-closed correctness and lower overclaim rate than alpha.",
                    "expected_route_outcome": "ROUTE_TO_SPECIALIST_OR_ABSTAIN",
                }
            )

    return {
        "schema_id": "kt.operator.alpha_should_lose_here_manifest.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "claim_boundary": (
            "This manifest preregisters only branch hypotheses for where the current alpha control should lose or be de-risked. "
            "It is not earned superiority evidence."
        ),
        "control_anchor_adapter_id": "lobe.alpha.v1",
        "rows": rows,
    }


def _build_route_policy_outcome_registry() -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.route_policy_outcome_registry.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "claim_boundary": "These outcomes define the next proof court only. They do not by themselves authorize routing, cutover, or counted progression.",
        "outcomes": [
            {
                "outcome_id": "ROUTE_TO_SPECIALIST",
                "description": "Actively route to a specialist or bounded multi-lobe composition because static alpha is expected to incur a measurable loss.",
                "required_fields": ["selected_adapter_ids", "predicted_alpha_liability", "route_justification"],
                "counts_as_intervention": True,
            },
            {
                "outcome_id": "STAY_STATIC_BASELINE",
                "description": "Preserve the static baseline because no admissible wedge advantage has been established.",
                "required_fields": ["static_baseline_reason"],
                "counts_as_intervention": False,
            },
            {
                "outcome_id": "ABSTAIN_FOR_REVIEW",
                "description": "Escalate or abstain because ambiguity or failure cost makes forced routing unsafe.",
                "required_fields": ["abstention_reason", "review_handoff_rule"],
                "counts_as_intervention": True,
            },
        ],
    }


def _build_oracle_counterfactual_matrix(
    *,
    selection_receipt: Dict[str, Any],
    alpha_manifest: Dict[str, Any],
) -> Dict[str, Any]:
    current_rows = []
    case_rows = selection_receipt.get("case_rows")
    if not isinstance(case_rows, list):
        raise RuntimeError("FAIL_CLOSED: router selection receipt case_rows missing/invalid")
    for row in case_rows:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: router selection case row must be object")
        shadow = row.get("shadow_selection") if isinstance(row.get("shadow_selection"), dict) else {}
        current_rows.append(
            {
                "case_id": str(row.get("case_id", "")).strip(),
                "baseline_domain_tag": str(row.get("baseline_static_adapter_path", {}).get("domain_tag", "")).strip(),
                "current_exact_path_match": bool(row.get("comparison_to_best_static_adapter_path", {}).get("exact_path_match")),
                "fallback_engaged": bool(shadow.get("fallback_engaged")),
                "current_oracle_policy_outcome": "STAY_STATIC_BASELINE",
                "reason": (
                    "Current court only demonstrates baseline shadow match or fallback preservation, "
                    "so no admissible route intervention is yet earned."
                ),
            }
        )

    planned_rows = []
    for row in alpha_manifest.get("rows", []):
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: alpha should lose row must be object")
        planned_rows.append(
            {
                "family_id": str(row.get("family_id", "")).strip(),
                "target_lobe_id": str(row.get("target_lobe_id", "")).strip(),
                "expected_oracle_policy_outcome": (
                    "ABSTAIN_FOR_REVIEW"
                    if str(row.get("expected_route_outcome", "")).strip().endswith("_ABSTAIN")
                    else "ROUTE_TO_SPECIALIST"
                ),
                "alpha_liability": str(row.get("alpha_should_lose_here_because", "")).strip(),
            }
        )
    planned_rows.append(
        {
            "family_id": "BOUNDARY_ABSTENTION_CONTROL",
            "target_lobe_id": "",
            "expected_oracle_policy_outcome": "ABSTAIN_FOR_REVIEW",
            "alpha_liability": "Forced commitment under high ambiguity can cost more than lawful abstention.",
        }
    )
    planned_rows.append(
        {
            "family_id": "STATIC_NO_ROUTE_CONTROL",
            "target_lobe_id": "lobe.alpha.v1",
            "expected_oracle_policy_outcome": "STAY_STATIC_BASELINE",
            "alpha_liability": "No liability should be asserted on true static-control families.",
        }
    )

    return {
        "schema_id": "kt.operator.oracle_router_counterfactual_matrix.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "claim_boundary": (
            "This matrix is an oracle-planning scaffold only. It does not claim that the planned policy outcomes are earned yet."
        ),
        "current_court_counterfactual_rows": current_rows,
        "planned_family_rows": planned_rows,
    }


def _build_route_abstention_quality_report(
    *,
    route_health: Dict[str, Any],
    shadow_matrix: Dict[str, Any],
) -> Dict[str, Any]:
    rows = shadow_matrix.get("rows")
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: router shadow matrix rows missing/invalid")
    fallback_case_ids = [str(item).strip() for item in route_health.get("fallback_case_ids", []) if str(item).strip()]
    return {
        "schema_id": "kt.operator.route_abstention_quality_report.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "claim_boundary": (
            "This report characterizes only the current abstention surface. It does not claim a mature abstention regime already exists."
        ),
        "current_case_count": int(len(rows)),
        "fallback_case_count": int(len(fallback_case_ids)),
        "fallback_case_ids": fallback_case_ids,
        "abstention_outcome_present_in_current_court": False,
        "current_assessment": "INSUFFICIENT_CURRENT_COURT__ABSTENTION_NOT_EXPLICITLY_SCORED",
        "next_branch_requirement": [
            "Score abstention correctness directly instead of treating fallback as a proxy.",
            "Bind at least one ambiguity family where abstention should beat forced routing.",
            "Require explicit abstention reasons and review handoff rules.",
        ],
    }


def _build_negative_result_ledger(
    *,
    r5_receipt: Dict[str, Any],
    scorecard: Dict[str, Any],
    route_health: Dict[str, Any],
    shadow_matrix: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.negative_result_ledger.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "preservation_rule": "Negative rows must remain visible even when later cycles improve on them.",
        "entries": [
            {
                "entry_id": "NEG_R5_STATIC_HOLD_CURRENT_HEAD",
                "verdict": str(r5_receipt.get("router_proof_summary", {}).get("exact_superiority_outcome", "")).strip(),
                "implication": "R6 remains blocked until superiority is actually earned.",
                "source_ref": DEFAULT_R5_RECEIPT_REL,
            },
            {
                "entry_id": "NEG_ROUTE_DELTA_ZERO",
                "verdict": f"route_distribution_delta_count={int(route_health.get('route_distribution_delta_count', 0))}",
                "implication": "Current court is not forcing plural route behavior.",
                "source_ref": DEFAULT_ROUTE_HEALTH_REL,
            },
            {
                "entry_id": "NEG_SHADOW_MATCH_ONLY",
                "verdict": str(scorecard.get("route_quality_win_status", "")).strip(),
                "implication": "Current shadow routing mirrors the static baseline instead of beating it.",
                "source_ref": DEFAULT_SCORECARD_REL,
            },
            {
                "entry_id": "NEG_NO_ELIGIBLE_LEARNED_ROUTER",
                "verdict": str(scorecard.get("learned_router_candidate", {}).get("candidate_status", "")).strip(),
                "implication": "Learned router work is still blocked on better substrate evidence.",
                "source_ref": DEFAULT_SCORECARD_REL,
            },
            {
                "entry_id": "NEG_CURRENT_BATTERY_TOO_SMALL",
                "verdict": f"case_count={int(scorecard.get('case_count', 0))}",
                "implication": "The current proof court is too small to carry a broad routing theorem.",
                "source_ref": DEFAULT_SHADOW_MATRIX_REL,
            },
        ],
    }


def _build_route_bearing_preregistration(
    *,
    policy_registry_path: Path,
    alpha_manifest_path: Path,
    lobe_survival_path: Path,
    oracle_matrix_path: Path,
    abstention_path: Path,
    negative_ledger_path: Path,
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.route_bearing_battery_preregistration.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "theorem_statement": (
            "On a pre-registered, adversarial, route-bearing battery, a governed routing policy can beat or safely de-risk "
            "the best static adapter on at least one fenced task family."
        ),
        "allowed_claims": [
            "Oracle or governed routing beats or safely de-risks static control on at least one fenced family.",
            "Static control remains canonical on families where no wedge advantage is demonstrated.",
            "Abstention is better than forced routing on families explicitly preregistered for abstention.",
        ],
        "disallowed_claims": [
            "General modular superiority across all tasks.",
            "Learned-router authorization before oracle success on the new court.",
            "Gate E or Gate F opening from prep artifacts alone.",
        ],
        "task_families": [
            "specialist wedge families registered in alpha_should_lose_here_manifest.json",
            "ambiguity and boundary families with abstention as a lawful outcome",
            "mixed-pressure families where wrong routing incurs downstream cost",
            "governed-execution families where admissibility and traceability matter as much as answer quality",
            "held-out mutation families not visible during pack construction",
            "static no-route control families",
        ],
        "scoring_channels": [
            "task_quality",
            "proof_completeness",
            "traceability",
            "failure_containment",
            "abstention_correctness",
            "overclaim_penalty",
            "route_justification_quality",
            "cost_delta",
            "latency_delta",
        ],
        "route_outcome_vocabulary_ref": policy_registry_path.as_posix(),
        "alpha_liability_manifest_ref": alpha_manifest_path.as_posix(),
        "lobe_survival_verdicts_ref": lobe_survival_path.as_posix(),
        "oracle_counterfactual_matrix_ref": oracle_matrix_path.as_posix(),
        "route_abstention_quality_report_ref": abstention_path.as_posix(),
        "negative_result_ledger_ref": negative_ledger_path.as_posix(),
        "success_thresholds": [
            "Nonzero route divergence from the current static baseline on the new battery.",
            "At least one fenced family where oracle routing beats or safely de-risks the best static path.",
            "No-regression hold remains intact on static-control families.",
            "Learned routing remains forbidden until the oracle result is positive.",
        ],
        "failure_thresholds": [
            "All families collapse back to stay-static with no measurable advantage.",
            "Abstention never wins where preregistered ambiguity families say it should.",
            "The held-out mutation family is reused during pack authoring or grading.",
        ],
        "publication_rule_for_negative_rows": "Negative rows must remain visible in negative_result_ledger.json even if later cycles improve on them.",
    }


def _build_router_failure_diagnosis_packet(
    *,
    current_head: str,
    subject_head: str,
    r5_receipt: Dict[str, Any],
    scorecard: Dict[str, Any],
    shadow_matrix: Dict[str, Any],
    route_health: Dict[str, Any],
    selection_receipt: Dict[str, Any],
    tournament_ranking: List[Dict[str, Any]],
    lobe_survival: Dict[str, Any],
    overlay: Dict[str, Any],
    next_workstream: Dict[str, Any],
    resume_blockers: Dict[str, Any],
) -> Dict[str, Any]:
    case_classifications = []
    for row in shadow_matrix["rows"]:
        if bool(row.get("fallback_engaged")):
            label = "NO_ROUTE_CORRECT__STATIC_FALLBACK_REQUIRED"
        elif bool(row.get("exact_path_match")):
            label = "ROUTE_SHOULD_MATTER_BUT_CURRENT_COURT_REWARDS_MATCH_ONLY"
        else:
            label = "DIVERGENCE_ALREADY_PRESENT"
        case_classifications.append(
            {
                "case_id": str(row.get("case_id", "")).strip(),
                "domain_tag": str(row.get("baseline_domain_tag", "")).strip(),
                "classification": label,
                "shadow_adapter_ids": [str(item) for item in row.get("shadow_adapter_ids", [])],
            }
        )

    top_blockers = [
        {
            "blocker_id": "BATTERY_TOO_SMALL",
            "evidence": f"case_count={int(scorecard.get('case_count', 0))}",
            "why_it_matters": "The current court is too small to force real route-bearing differentiation.",
        },
        {
            "blocker_id": "EXACT_PATH_MATCH_ONLY",
            "evidence": f"shadow_match_rate={float(route_health.get('shadow_match_rate', 0.0))}",
            "why_it_matters": "Current shadow routing is surviving by matching the baseline instead of beating it.",
        },
        {
            "blocker_id": "ROUTE_DELTA_ZERO",
            "evidence": f"route_distribution_delta_count={int(route_health.get('route_distribution_delta_count', 0))}",
            "why_it_matters": "Plural routing is not yet creating detectable decisions that matter.",
        },
        {
            "blocker_id": "NO_COST_OR_LATENCY_GAIN",
            "evidence": (
                f"cost_win_status={str(scorecard.get('cost_win_status', '')).strip()} | "
                f"latency_win_status={str(scorecard.get('latency_win_status', '')).strip()}"
            ),
            "why_it_matters": "The current proof object shows no efficiency upside to routing.",
        },
        {
            "blocker_id": "NO_ELIGIBLE_LEARNED_ROUTER",
            "evidence": str(scorecard.get("learned_router_candidate", {}).get("candidate_status", "")).strip(),
            "why_it_matters": "The substrate has not yet produced a lawful learned-router candidate.",
        },
    ]

    static_domain_tags = []
    selection_rows = selection_receipt.get("case_rows")
    if not isinstance(selection_rows, list):
        raise RuntimeError("FAIL_CLOSED: router selection receipt case_rows missing/invalid")
    for row in selection_rows:
        baseline = row.get("baseline_static_adapter_path") if isinstance(row.get("baseline_static_adapter_path"), dict) else {}
        _append_unique(static_domain_tags, str(baseline.get("domain_tag", "")).strip())

    return {
        "schema_id": "kt.operator.router_failure_diagnosis_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "current_git_head": current_head,
        "subject_head": subject_head,
        "claim_boundary": (
            "This packet diagnoses only why the current R5 proof held static baseline canonical. "
            "It does not reopen the counted lane or claim future superiority."
        ),
        "proof_ceiling_summary": {
            "router_superiority_earned": bool(scorecard.get("superiority_earned")),
            "overall_outcome": str(scorecard.get("overall_outcome", "")).strip(),
            "route_quality_win_status": str(scorecard.get("route_quality_win_status", "")).strip(),
            "learned_router_candidate_status": str(scorecard.get("learned_router_candidate", {}).get("candidate_status", "")).strip(),
            "current_tournament_champion_adapter_id": str(lobe_survival.get("control_anchor_adapter_id", "")).strip(),
            "current_best_static_provider_adapter_id": str(scorecard.get("best_static_baseline", {}).get("provider_underlay", {}).get("adapter_id", "")).strip(),
        },
        "case_classifications": case_classifications,
        "top_blockers": top_blockers,
        "current_static_route_families": static_domain_tags,
        "tournament_ranking": tournament_ranking,
        "live_signal_working_set": list(lobe_survival.get("selected_working_set", [])),
        "truth_surface_guardrails": {
            "overlay_repo_state_executable_now": bool(overlay.get("repo_state_executable_now")),
            "overlay_next_counted_workstream_id": str(overlay.get("next_counted_workstream_id", "")).strip(),
            "next_contract_execution_mode": str(next_workstream.get("execution_mode", "")).strip(),
            "resume_blocking_state": str(resume_blockers.get("blocking_state", "")).strip(),
        },
        "next_branch_requirements": [
            "Preregister a route-bearing battery before heavy-data authoring.",
            "Add explicit route, stay-static, and abstain outcomes.",
            "Train only wedges that survive the oracle-routing fork.",
            "Keep the counted lane closed until a future same-head proof actually flips.",
        ],
        "next_lawful_move": "AUTHOR_PREREGISTERED_ROUTE_BEARING_STAGE_PACK_AND_RUN_ORACLE_ROUTING",
        "source_refs": [
            DEFAULT_R5_RECEIPT_REL,
            DEFAULT_SCORECARD_REL,
            DEFAULT_SHADOW_MATRIX_REL,
            DEFAULT_ROUTE_HEALTH_REL,
            DEFAULT_SELECTION_RECEIPT_REL,
            DEFAULT_TOURNAMENT_EXECUTION_REL,
            DEFAULT_CURRENT_OVERLAY_REL,
            DEFAULT_NEXT_WORKSTREAM_REL,
            DEFAULT_RESUME_BLOCKERS_REL,
        ],
    }


def _tracked_copy(obj: Dict[str, Any], *, carrier_role: str, ref_field: str, authoritative_path: Path) -> Dict[str, Any]:
    tracked = dict(obj)
    tracked["carrier_surface_role"] = carrier_role
    tracked[ref_field] = authoritative_path.as_posix()
    return tracked


def run_router_superiority_recovery_prep_tranche(
    *,
    router_proof_receipt_path: Path,
    scorecard_path: Path,
    shadow_matrix_path: Path,
    route_health_path: Path,
    selection_receipt_path: Path,
    import_receipt_path: Path,
    tournament_execution_receipt_path: Path,
    followthrough_report_path: Path,
    current_overlay_path: Path,
    next_workstream_path: Path,
    resume_blockers_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()

    r5_receipt = _load_json_required(router_proof_receipt_path.resolve(), label="router proof receipt")
    scorecard = _load_json_required(scorecard_path.resolve(), label="router superiority scorecard")
    shadow_matrix = _load_json_required(shadow_matrix_path.resolve(), label="router shadow eval matrix")
    route_health = _load_json_required(route_health_path.resolve(), label="route distribution health")
    selection_receipt = _load_json_required(selection_receipt_path.resolve(), label="router selection receipt")
    authoritative_import_receipt_path, import_receipt = _resolve_authoritative(
        root,
        import_receipt_path.resolve(),
        "authoritative_import_receipt_ref",
        "cohort0 real-engine adapter import receipt",
    )
    authoritative_tournament_execution_path, tournament_execution = _resolve_authoritative(
        root,
        tournament_execution_receipt_path.resolve(),
        "authoritative_tournament_execution_receipt_ref",
        "cohort0 tournament execution receipt",
    )
    authoritative_followthrough_path, followthrough_packet = _resolve_authoritative(
        root,
        followthrough_report_path.resolve(),
        "authoritative_followthrough_packet_ref",
        "cohort0 tournament followthrough packet",
    )
    overlay = _load_json_required(current_overlay_path.resolve(), label="current campaign state overlay")
    next_workstream = _load_json_required(next_workstream_path.resolve(), label="next counted workstream contract")
    resume_blockers = _load_json_required(resume_blockers_path.resolve(), label="resume blockers receipt")

    _validate_inputs(
        r5_receipt=r5_receipt,
        scorecard=scorecard,
        shadow_matrix=shadow_matrix,
        route_health=route_health,
        selection_receipt=selection_receipt,
        import_receipt=import_receipt,
        tournament_execution=tournament_execution,
        followthrough_packet=followthrough_packet,
        overlay=overlay,
        next_workstream=next_workstream,
        resume_blockers=resume_blockers,
    )

    subject_head = _resolve_subject_head(
        packets=[
            r5_receipt,
            scorecard,
            shadow_matrix,
            route_health,
            import_receipt,
            tournament_execution,
            followthrough_packet,
        ]
    )
    current_head = _git_head(root)
    _validate_selection_receipt_head_alignment(
        selection_receipt=selection_receipt,
        current_head=current_head,
        subject_head=subject_head,
    )

    tournament_result = _load_tournament_result(root, tournament_execution)
    eval_reports = _load_eval_reports(root, import_receipt)
    tournament_ranking = _rank_tournament(tournament_result)
    baseline_dependency_ids = _baseline_dependency_ids(selection_receipt)

    lobe_survival = _build_lobe_survival_verdicts(
        ranked=tournament_ranking,
        eval_reports=eval_reports,
        baseline_dependency_ids=baseline_dependency_ids,
    )
    alpha_manifest = _build_alpha_should_lose_manifest(lobe_survival=lobe_survival)
    policy_registry = _build_route_policy_outcome_registry()
    oracle_matrix = _build_oracle_counterfactual_matrix(selection_receipt=selection_receipt, alpha_manifest=alpha_manifest)
    abstention_report = _build_route_abstention_quality_report(route_health=route_health, shadow_matrix=shadow_matrix)
    negative_ledger = _build_negative_result_ledger(
        r5_receipt=r5_receipt,
        scorecard=scorecard,
        route_health=route_health,
        shadow_matrix=shadow_matrix,
    )

    target_root = (
        authoritative_root.resolve()
        if authoritative_root is not None
        else (root / "tmp" / "router_superiority_recovery_prep_current_head").resolve()
    )
    target_root.mkdir(parents=True, exist_ok=True)
    reports_root.mkdir(parents=True, exist_ok=True)

    authoritative_paths = {
        "route_policy_outcome_registry": (target_root / Path(DEFAULT_POLICY_REGISTRY_REL).name).resolve(),
        "alpha_should_lose_here_manifest": (target_root / Path(DEFAULT_ALPHA_LOSE_REL).name).resolve(),
        "lobe_survival_verdicts": (target_root / Path(DEFAULT_LOBE_SURVIVAL_REL).name).resolve(),
        "oracle_router_counterfactual_matrix": (target_root / Path(DEFAULT_ORACLE_COUNTERFACTUAL_REL).name).resolve(),
        "route_abstention_quality_report": (target_root / Path(DEFAULT_ABSTENTION_REL).name).resolve(),
        "negative_result_ledger": (target_root / Path(DEFAULT_NEGATIVE_LEDGER_REL).name).resolve(),
    }

    write_json_stable(authoritative_paths["route_policy_outcome_registry"], policy_registry)
    write_json_stable(authoritative_paths["alpha_should_lose_here_manifest"], alpha_manifest)
    write_json_stable(authoritative_paths["lobe_survival_verdicts"], lobe_survival)
    write_json_stable(authoritative_paths["oracle_router_counterfactual_matrix"], oracle_matrix)
    write_json_stable(authoritative_paths["route_abstention_quality_report"], abstention_report)
    write_json_stable(authoritative_paths["negative_result_ledger"], negative_ledger)

    prereg = _build_route_bearing_preregistration(
        policy_registry_path=authoritative_paths["route_policy_outcome_registry"],
        alpha_manifest_path=authoritative_paths["alpha_should_lose_here_manifest"],
        lobe_survival_path=authoritative_paths["lobe_survival_verdicts"],
        oracle_matrix_path=authoritative_paths["oracle_router_counterfactual_matrix"],
        abstention_path=authoritative_paths["route_abstention_quality_report"],
        negative_ledger_path=authoritative_paths["negative_result_ledger"],
    )
    authoritative_paths["route_bearing_battery_preregistration"] = (target_root / Path(DEFAULT_PREREG_REL).name).resolve()
    write_json_stable(authoritative_paths["route_bearing_battery_preregistration"], prereg)

    diagnosis = _build_router_failure_diagnosis_packet(
        current_head=current_head,
        subject_head=subject_head,
        r5_receipt=r5_receipt,
        scorecard=scorecard,
        shadow_matrix=shadow_matrix,
        route_health=route_health,
        selection_receipt=selection_receipt,
        tournament_ranking=tournament_ranking,
        lobe_survival=lobe_survival,
        overlay=overlay,
        next_workstream=next_workstream,
        resume_blockers=resume_blockers,
    )
    authoritative_paths["router_failure_diagnosis_packet"] = (target_root / Path(DEFAULT_DIAGNOSIS_REL).name).resolve()
    write_json_stable(authoritative_paths["router_failure_diagnosis_packet"], diagnosis)

    receipt = {
        "schema_id": "kt.operator.router_superiority_recovery_prep_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "current_git_head": current_head,
        "subject_head": subject_head,
        "prep_posture": "ROUTER_SUPERIORITY_RECOVERY_PREP_BOUND__COUNTED_LANE_STILL_CLOSED",
        "claim_boundary": (
            "This tranche prepares a harsher router proof court and recovery branch only. "
            "It does not reopen R6, Gate E, Gate F, or commercialization."
        ),
        "counted_lane_guardrail": {
            "overlay_repo_state_executable_now": bool(overlay.get("repo_state_executable_now")),
            "next_counted_workstream_id": str(overlay.get("next_counted_workstream_id", "")).strip(),
            "next_contract_execution_mode": str(next_workstream.get("execution_mode", "")).strip(),
            "resume_blocking_state": str(resume_blockers.get("blocking_state", "")).strip(),
        },
        "source_refs": {
            "router_vs_best_adapter_proof_receipt_ref": router_proof_receipt_path.resolve().as_posix(),
            "router_superiority_scorecard_ref": scorecard_path.resolve().as_posix(),
            "router_shadow_eval_matrix_ref": shadow_matrix_path.resolve().as_posix(),
            "route_distribution_health_ref": route_health_path.resolve().as_posix(),
            "router_selection_receipt_ref": selection_receipt_path.resolve().as_posix(),
            "authoritative_import_receipt_ref": authoritative_import_receipt_path.as_posix(),
            "authoritative_tournament_execution_receipt_ref": authoritative_tournament_execution_path.as_posix(),
            "authoritative_followthrough_packet_ref": authoritative_followthrough_path.as_posix(),
        },
        "authoritative_output_refs": {
            "router_failure_diagnosis_packet_ref": authoritative_paths["router_failure_diagnosis_packet"].as_posix(),
            "route_policy_outcome_registry_ref": authoritative_paths["route_policy_outcome_registry"].as_posix(),
            "alpha_should_lose_here_manifest_ref": authoritative_paths["alpha_should_lose_here_manifest"].as_posix(),
            "lobe_survival_verdicts_ref": authoritative_paths["lobe_survival_verdicts"].as_posix(),
            "route_bearing_battery_preregistration_ref": authoritative_paths["route_bearing_battery_preregistration"].as_posix(),
            "oracle_router_counterfactual_matrix_ref": authoritative_paths["oracle_router_counterfactual_matrix"].as_posix(),
            "route_abstention_quality_report_ref": authoritative_paths["route_abstention_quality_report"].as_posix(),
            "negative_result_ledger_ref": authoritative_paths["negative_result_ledger"].as_posix(),
        },
        "working_set": list(lobe_survival.get("selected_working_set", [])),
        "next_lawful_move": "AUTHOR_PREREGISTERED_ROUTE_BEARING_STAGE_PACK_AND_RUN_ORACLE_ROUTING",
    }
    authoritative_paths["router_superiority_recovery_prep_receipt"] = (target_root / Path(DEFAULT_RECEIPT_REL).name).resolve()
    write_json_stable(authoritative_paths["router_superiority_recovery_prep_receipt"], receipt)

    tracked_payloads = {
        Path(DEFAULT_RECEIPT_REL).name: _tracked_copy(
            receipt,
            carrier_role="TRACKED_CARRIER_ONLY_ROUTER_SUPERIORITY_RECOVERY_PREP_RECEIPT",
            ref_field="authoritative_router_superiority_recovery_prep_receipt_ref",
            authoritative_path=authoritative_paths["router_superiority_recovery_prep_receipt"],
        ),
        Path(DEFAULT_DIAGNOSIS_REL).name: _tracked_copy(
            diagnosis,
            carrier_role="TRACKED_CARRIER_ONLY_ROUTER_FAILURE_DIAGNOSIS_PACKET",
            ref_field="authoritative_router_failure_diagnosis_packet_ref",
            authoritative_path=authoritative_paths["router_failure_diagnosis_packet"],
        ),
        Path(DEFAULT_POLICY_REGISTRY_REL).name: _tracked_copy(
            policy_registry,
            carrier_role="TRACKED_CARRIER_ONLY_ROUTE_POLICY_OUTCOME_REGISTRY",
            ref_field="authoritative_route_policy_outcome_registry_ref",
            authoritative_path=authoritative_paths["route_policy_outcome_registry"],
        ),
        Path(DEFAULT_ALPHA_LOSE_REL).name: _tracked_copy(
            alpha_manifest,
            carrier_role="TRACKED_CARRIER_ONLY_ALPHA_SHOULD_LOSE_HERE_MANIFEST",
            ref_field="authoritative_alpha_should_lose_here_manifest_ref",
            authoritative_path=authoritative_paths["alpha_should_lose_here_manifest"],
        ),
        Path(DEFAULT_LOBE_SURVIVAL_REL).name: _tracked_copy(
            lobe_survival,
            carrier_role="TRACKED_CARRIER_ONLY_LOBE_SURVIVAL_VERDICTS",
            ref_field="authoritative_lobe_survival_verdicts_ref",
            authoritative_path=authoritative_paths["lobe_survival_verdicts"],
        ),
        Path(DEFAULT_PREREG_REL).name: _tracked_copy(
            prereg,
            carrier_role="TRACKED_CARRIER_ONLY_ROUTE_BEARING_BATTERY_PREREGISTRATION",
            ref_field="authoritative_route_bearing_battery_preregistration_ref",
            authoritative_path=authoritative_paths["route_bearing_battery_preregistration"],
        ),
        Path(DEFAULT_ORACLE_COUNTERFACTUAL_REL).name: _tracked_copy(
            oracle_matrix,
            carrier_role="TRACKED_CARRIER_ONLY_ORACLE_ROUTER_COUNTERFACTUAL_MATRIX",
            ref_field="authoritative_oracle_router_counterfactual_matrix_ref",
            authoritative_path=authoritative_paths["oracle_router_counterfactual_matrix"],
        ),
        Path(DEFAULT_ABSTENTION_REL).name: _tracked_copy(
            abstention_report,
            carrier_role="TRACKED_CARRIER_ONLY_ROUTE_ABSTENTION_QUALITY_REPORT",
            ref_field="authoritative_route_abstention_quality_report_ref",
            authoritative_path=authoritative_paths["route_abstention_quality_report"],
        ),
        Path(DEFAULT_NEGATIVE_LEDGER_REL).name: _tracked_copy(
            negative_ledger,
            carrier_role="TRACKED_CARRIER_ONLY_NEGATIVE_RESULT_LEDGER",
            ref_field="authoritative_negative_result_ledger_ref",
            authoritative_path=authoritative_paths["negative_result_ledger"],
        ),
    }

    for filename, obj in tracked_payloads.items():
        write_json_stable((reports_root / filename).resolve(), obj)

    return {
        "router_superiority_recovery_prep_receipt": receipt,
        "router_failure_diagnosis_packet": diagnosis,
        "route_policy_outcome_registry": policy_registry,
        "alpha_should_lose_here_manifest": alpha_manifest,
        "lobe_survival_verdicts": lobe_survival,
        "route_bearing_battery_preregistration": prereg,
        "oracle_router_counterfactual_matrix": oracle_matrix,
        "route_abstention_quality_report": abstention_report,
        "negative_result_ledger": negative_ledger,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Prepare the lab-only router-superiority recovery branch after a truthful R5 static hold.")
    ap.add_argument("--router-proof-receipt", default=DEFAULT_R5_RECEIPT_REL)
    ap.add_argument("--scorecard", default=DEFAULT_SCORECARD_REL)
    ap.add_argument("--shadow-matrix", default=DEFAULT_SHADOW_MATRIX_REL)
    ap.add_argument("--route-health", default=DEFAULT_ROUTE_HEALTH_REL)
    ap.add_argument("--selection-receipt", default=DEFAULT_SELECTION_RECEIPT_REL)
    ap.add_argument("--import-receipt", default=DEFAULT_IMPORT_RECEIPT_REL)
    ap.add_argument("--tournament-execution-receipt", default=DEFAULT_TOURNAMENT_EXECUTION_REL)
    ap.add_argument("--followthrough-report", default=DEFAULT_FOLLOWTHROUGH_REL)
    ap.add_argument("--current-overlay", default=DEFAULT_CURRENT_OVERLAY_REL)
    ap.add_argument("--next-workstream", default=DEFAULT_NEXT_WORKSTREAM_REL)
    ap.add_argument("--resume-blockers", default=DEFAULT_RESUME_BLOCKERS_REL)
    ap.add_argument(
        "--authoritative-root",
        default="",
        help="Optional authoritative output root. Default: <repo>/tmp/router_superiority_recovery_prep_current_head",
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
    payload = run_router_superiority_recovery_prep_tranche(
        router_proof_receipt_path=_resolve_path(root, str(args.router_proof_receipt)),
        scorecard_path=_resolve_path(root, str(args.scorecard)),
        shadow_matrix_path=_resolve_path(root, str(args.shadow_matrix)),
        route_health_path=_resolve_path(root, str(args.route_health)),
        selection_receipt_path=_resolve_path(root, str(args.selection_receipt)),
        import_receipt_path=_resolve_path(root, str(args.import_receipt)),
        tournament_execution_receipt_path=_resolve_path(root, str(args.tournament_execution_receipt)),
        followthrough_report_path=_resolve_path(root, str(args.followthrough_report)),
        current_overlay_path=_resolve_path(root, str(args.current_overlay)),
        next_workstream_path=_resolve_path(root, str(args.next_workstream)),
        resume_blockers_path=_resolve_path(root, str(args.resume_blockers)),
        authoritative_root=_resolve_path(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve_path(root, str(args.reports_root)),
        workspace_root=root,
    )
    receipt = payload["router_superiority_recovery_prep_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "prep_posture": receipt["prep_posture"],
                "next_lawful_move": receipt["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
