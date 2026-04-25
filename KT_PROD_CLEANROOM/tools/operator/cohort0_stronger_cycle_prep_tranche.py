from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_R5_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/router_vs_best_adapter_proof_ratification_receipt.json"
DEFAULT_ORDERED_PROOF_REL = "KT_PROD_CLEANROOM/reports/router_ordered_proof_receipt.json"
DEFAULT_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/router_superiority_scorecard.json"
DEFAULT_NON_STUB_EVAL_REL = "KT_PROD_CLEANROOM/reports/cohort0_non_stub_eval_emission_receipt.json"
DEFAULT_FOLLOWTHROUGH_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_tournament_followthrough_packet.json"
DEFAULT_MERGE_OUTCOME_REL = "KT_PROD_CLEANROOM/reports/cohort0_merge_outcome_binding_receipt.json"
DEFAULT_PROOF_BINDING_REL = "KT_PROD_CLEANROOM/reports/cohort0_router_proof_state_binding_receipt.json"
DEFAULT_PREP_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_stronger_cycle_prep_packet.json"


def _resolve_path(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    else:
        path = path.resolve()
    return path


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _resolve_authoritative(root: Path, tracked_path: Path, ref_field: str, label: str) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(tracked_path, label=f"tracked {label}")
    authoritative_ref = str(tracked.get(ref_field, "")).strip()
    authoritative_path = _resolve_path(root, authoritative_ref) if authoritative_ref else tracked_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")


def _validate_inputs(
    *,
    r5_receipt: Dict[str, Any],
    ordered_receipt: Dict[str, Any],
    scorecard: Dict[str, Any],
    non_stub_eval: Dict[str, Any],
    followthrough_packet: Dict[str, Any],
    merge_outcome: Dict[str, Any],
    proof_binding: Dict[str, Any],
) -> None:
    if str(r5_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: router proof receipt must PASS")
    if str(r5_receipt.get("workstream_id", "")).strip() != "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF":
        raise RuntimeError("FAIL_CLOSED: router proof receipt must bind B04.R5")
    if bool(r5_receipt.get("router_proof_summary", {}).get("router_superiority_earned")) is not False:
        raise RuntimeError("FAIL_CLOSED: stronger-cycle prep only applies after non-earned router superiority")
    if str(r5_receipt.get("next_lawful_move", "")).strip() != "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF":
        raise RuntimeError("FAIL_CLOSED: router proof receipt must leave R6 blocked")

    if str(ordered_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: ordered proof receipt must PASS")
    if str(ordered_receipt.get("ordered_proof_outcome", "")).strip() != "PASS_HOLD_STATIC_CANONICAL_BASELINE":
        raise RuntimeError("FAIL_CLOSED: ordered proof receipt must hold static canonical baseline")

    if str(scorecard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: router superiority scorecard must PASS")
    if bool(scorecard.get("superiority_earned")) is not False:
        raise RuntimeError("FAIL_CLOSED: router superiority scorecard must remain unearned")

    if str(non_stub_eval.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: non-stub eval emission receipt must PASS")
    if int(non_stub_eval.get("entry_count", -1)) != 13:
        raise RuntimeError("FAIL_CLOSED: non-stub eval emission receipt must bind 13 entries")

    if str(followthrough_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: tournament followthrough packet must PASS")
    if str(merge_outcome.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: merge outcome binding receipt must PASS")
    if str(merge_outcome.get("merge_outcome_posture", "")).strip() != "MERGE_OUTCOME_BOUND__PASS__ROLLBACK_READY":
        raise RuntimeError("FAIL_CLOSED: merge outcome must remain merge-bound PASS with rollback ready")

    if str(proof_binding.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: router proof state binding receipt must PASS")
    if str(proof_binding.get("binding_posture", "")).strip() != "R5_STATIC_HOLD__R6_NEXT_IN_ORDER_ONLY_BLOCKED":
        raise RuntimeError("FAIL_CLOSED: router proof state binding receipt must bind the post-R5 hold")


def _build_prep_packet(
    *,
    current_head: str,
    proof_head: str,
    imported_subject_head: str,
    r5_receipt_path: Path,
    ordered_receipt_path: Path,
    scorecard_path: Path,
    non_stub_eval_path: Path,
    followthrough_path: Path,
    merge_outcome_path: Path,
    proof_binding_path: Path,
    non_stub_eval: Dict[str, Any],
    followthrough_packet: Dict[str, Any],
    merge_outcome: Dict[str, Any],
    scorecard: Dict[str, Any],
    ordered_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    merge_followthrough = followthrough_packet.get("merge_followthrough") if isinstance(followthrough_packet.get("merge_followthrough"), dict) else {}
    tournament_followthrough = followthrough_packet.get("tournament_followthrough") if isinstance(followthrough_packet.get("tournament_followthrough"), dict) else {}
    promotion_followthrough = followthrough_packet.get("promotion_followthrough") if isinstance(followthrough_packet.get("promotion_followthrough"), dict) else {}

    current_ceiling_summary = {
        "proof_head": proof_head,
        "imported_substrate_subject_head": imported_subject_head,
        "router_superiority_earned": bool(scorecard.get("superiority_earned")),
        "canonical_router_status": str(ordered_receipt.get("canonical_router_status", "")).strip(),
        "exact_superiority_outcome": str(ordered_receipt.get("exact_superiority_outcome", "")).strip(),
        "learned_router_cutover_allowed": bool(ordered_receipt.get("learned_router_cutover_allowed")),
        "multi_lobe_promotion_allowed": bool(ordered_receipt.get("multi_lobe_promotion_allowed")),
        "non_stub_eval_entry_count": int(non_stub_eval.get("entry_count", 0)),
        "metric_probe_agreement_true_count": int(non_stub_eval.get("metric_probe_agreement_true_count", 0)),
        "current_tournament_champion_adapter_id": str(promotion_followthrough.get("candidate_adapter_id", "")).strip(),
        "current_tournament_dominance_pair_count": int(tournament_followthrough.get("dominance_pair_count", 0)),
        "merge_outcome_posture": str(merge_outcome.get("merge_outcome_posture", "")).strip(),
        "admissible_parent_pair_count": int(merge_followthrough.get("admissible_parent_pair_count", 0)),
        "child_candidate_adapter_id": str(merge_outcome.get("child_candidate", {}).get("adapter_id", "")).strip(),
    }

    cycle_sequence = [
        {
            "stage_id": "CHAOS_ROUND_A__ALL_13_SHARED_PRESSURE",
            "purpose": "Create a broader shared-pressure substrate across all 13 adapters so the next cycle is not a replay of the current proof line.",
            "required_outputs": [
                "13 adapter_training_receipt.json",
                "13 adapter_reload_receipt.json",
                "13 adapter_eval_receipt.json",
                "run_manifest.json",
                "adapter_registry.json",
            ],
        },
        {
            "stage_id": "INDIVIDUAL_HYPERTRAINING__13_ISOLATED_SPECIALIZATION_LANES",
            "purpose": "Deepen specialization in separate lanes so the downstream civilization graph can change structurally rather than cosmetically.",
            "required_outputs": [
                "13 train_manifest.json",
                "13 training_run_manifest.PASS.json",
                "13 job_dir_manifest.json",
                "13 adapter bundles with non-stub engine receipts",
            ],
        },
        {
            "stage_id": "CHAOS_ROUND_B__REINTEGRATED_SHARED_PRESSURE",
            "purpose": "Recombine the specialized set under shared pressure to produce a materially new graph substrate.",
            "required_outputs": [
                "13 adapter_training_receipt.json for reintegrated round",
                "13 adapter_eval_receipt.json for reintegrated round",
                "cycle comparison manifest against Chaos Round A",
            ],
        },
        {
            "stage_id": "NON_STUB_EVAL_AND_JOB_MANIFEST_EMISSION",
            "purpose": "Emit the schema-bound non-stub eval and job manifest family required for a new graph rerun.",
            "required_outputs": [
                "13 eval_report.json",
                "13 job_dir_manifest.json",
                "13 train_manifest.json",
                "13 training_run_manifest.PASS.json",
            ],
        },
        {
            "stage_id": "NEW_TOURNAMENT_GRAPH_RERUN",
            "purpose": "Build and execute a new tournament graph on the stronger substrate rather than replaying the current graph.",
            "required_outputs": [
                "tournament_result.json",
                "cohort0_tournament_execution_receipt.json",
                "graph comparison packet against current dominance structure",
            ],
        },
        {
            "stage_id": "MERGE_REENTRY_AND_CHILD_EVAL_CHECK",
            "purpose": "Recheck merge admissibility and bounded child evaluation on the new graph before any router rerun.",
            "required_outputs": [
                "cohort0_merge_parent_pair_admissibility_receipt.json",
                "cohort0_merge_child_evaluation_receipt.json",
                "cohort0_merge_outcome_binding_receipt.json",
            ],
        },
        {
            "stage_id": "ROUTER_SHADOW_AND_R5_RERUN",
            "purpose": "Re-earn router shadow and router-versus-best-adapter proof on the new stronger same-head substrate.",
            "required_outputs": [
                "router_shadow_evaluation_ratification_receipt.json",
                "router_ordered_proof_receipt.json",
                "router_superiority_scorecard.json",
                "router_vs_best_adapter_proof_ratification_receipt.json",
            ],
        },
    ]

    success_criteria = [
        "The stronger cycle must run on a new authoritative head distinct from the current proof head.",
        "All 13 adapters must produce non-stub training, reload, eval, job_dir_manifest, train_manifest, and training_run_manifest artifacts.",
        "The new tournament graph must differ materially from the current graph: the new tournament result root must differ and at least one of champion set, dominance_pair_count, admissible_parent_pair_count, or merge outcome posture must change.",
        "Router shadow and router-versus-best-adapter proof must be rerun on the same new proof head rather than narrated from old receipts.",
        "Only an actually earned `router_superiority_earned = true` result may reopen consideration of B04.R6, Gate E, or Gate F.",
    ]

    non_forward_motion_classes = [
        "Reusing the current proof head or current imported substrate without new training/eval artifacts.",
        "Stub-engine or stub-eval reruns that only repackage receipts.",
        "Skipping tournament or merge checks and jumping directly from training into router proof.",
        "Treating improved vibes, larger bundles, or new receipts as enough without changed proof objects.",
        "Narrating B04.R6, Gate E, Gate F, or commercialization from another non-earned router proof.",
    ]

    return {
        "schema_id": "kt.operator.cohort0_stronger_cycle_prep_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "current_git_head": current_head,
        "subject_head": proof_head,
        "prep_posture": "STRONGER_NEW_CYCLE_REQUIRED__CHAOS_SPECIALIZE_CHAOS_TARGET_BOUND",
        "branch_selection_posture": "CHAOS_A_INDIVIDUAL_HYPERTRAINING_CHAOS_B_BRANCH_SELECTED",
        "claim_boundary": (
            "This packet prepares only a bounded stronger-cycle lab branch after a truthful non-earned B04.R5 result. "
            "It does not reopen B04.R6, Gate E, Gate F, or commercialization."
        ),
        "current_cycle_ceiling_summary": current_ceiling_summary,
        "cycle_objective": (
            "Produce a stronger same-head substrate that can materially change the downstream proof objects and give a future "
            "router-versus-best-adapter rerun a lawful chance to flip `router_superiority_earned = true`."
        ),
        "stronger_cycle_sequence": cycle_sequence,
        "success_criteria": success_criteria,
        "non_forward_motion_classes": non_forward_motion_classes,
        "source_packet_refs": {
            "router_vs_best_adapter_proof_receipt_ref": r5_receipt_path.as_posix(),
            "router_ordered_proof_receipt_ref": ordered_receipt_path.as_posix(),
            "router_superiority_scorecard_ref": scorecard_path.as_posix(),
            "non_stub_eval_emission_receipt_ref": non_stub_eval_path.as_posix(),
            "tournament_followthrough_packet_ref": followthrough_path.as_posix(),
            "merge_outcome_binding_receipt_ref": merge_outcome_path.as_posix(),
            "router_proof_state_binding_receipt_ref": proof_binding_path.as_posix(),
        },
        "next_lawful_move": "PREPARE_SCHEMA_BOUND_CHAOS_A_INDIVIDUAL_HYPERTRAINING_CHAOS_B_EVIDENCE",
    }


def run_stronger_cycle_prep_tranche(
    *,
    router_proof_receipt_path: Path,
    ordered_proof_receipt_path: Path,
    scorecard_path: Path,
    non_stub_eval_receipt_path: Path,
    followthrough_report_path: Path,
    merge_outcome_report_path: Path,
    proof_binding_report_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()

    r5_receipt = _load_json_required(router_proof_receipt_path.resolve(), label="router proof receipt")
    ordered_receipt = _load_json_required(ordered_proof_receipt_path.resolve(), label="router ordered proof receipt")
    scorecard = _load_json_required(scorecard_path.resolve(), label="router superiority scorecard")
    authoritative_non_stub_eval_path, non_stub_eval = _resolve_authoritative(
        root,
        non_stub_eval_receipt_path.resolve(),
        "authoritative_non_stub_eval_emission_receipt_ref",
        "cohort0 non-stub eval emission receipt",
    )
    authoritative_followthrough_path, followthrough_packet = _resolve_authoritative(
        root,
        followthrough_report_path.resolve(),
        "authoritative_followthrough_packet_ref",
        "cohort0 tournament followthrough packet",
    )
    authoritative_merge_outcome_path, merge_outcome = _resolve_authoritative(
        root,
        merge_outcome_report_path.resolve(),
        "authoritative_merge_outcome_binding_receipt_ref",
        "cohort0 merge outcome binding receipt",
    )
    proof_binding = _load_json_required(proof_binding_report_path.resolve(), label="router proof state binding receipt")

    _validate_inputs(
        r5_receipt=r5_receipt,
        ordered_receipt=ordered_receipt,
        scorecard=scorecard,
        non_stub_eval=non_stub_eval,
        followthrough_packet=followthrough_packet,
        merge_outcome=merge_outcome,
        proof_binding=proof_binding,
    )

    target_root = authoritative_root.resolve() if authoritative_root is not None else (root / "tmp" / "cohort0_stronger_cycle_prep_current_head").resolve()
    target_root.mkdir(parents=True, exist_ok=True)

    prep_packet = _build_prep_packet(
        current_head=str(r5_receipt.get("current_git_head", "")).strip(),
        proof_head=str(r5_receipt.get("subject_head", "")).strip(),
        imported_subject_head=str(merge_outcome.get("subject_head", "")).strip(),
        r5_receipt_path=router_proof_receipt_path.resolve(),
        ordered_receipt_path=ordered_proof_receipt_path.resolve(),
        scorecard_path=scorecard_path.resolve(),
        non_stub_eval_path=authoritative_non_stub_eval_path,
        followthrough_path=authoritative_followthrough_path,
        merge_outcome_path=authoritative_merge_outcome_path,
        proof_binding_path=proof_binding_report_path.resolve(),
        non_stub_eval=non_stub_eval,
        followthrough_packet=followthrough_packet,
        merge_outcome=merge_outcome,
        scorecard=scorecard,
        ordered_receipt=ordered_receipt,
    )

    authoritative_packet_path = (target_root / "cohort0_stronger_cycle_prep_packet.json").resolve()
    write_json_stable(authoritative_packet_path, prep_packet)

    tracked_packet = dict(prep_packet)
    tracked_packet["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_STRONGER_CYCLE_PREP_PACKET"
    tracked_packet["authoritative_stronger_cycle_prep_packet_ref"] = authoritative_packet_path.as_posix()
    reports_root.mkdir(parents=True, exist_ok=True)
    tracked_packet_path = (reports_root / Path(DEFAULT_PREP_PACKET_REL).name).resolve()
    write_json_stable(tracked_packet_path, tracked_packet)

    return {
        "stronger_cycle_prep_packet": prep_packet,
        "tracked_stronger_cycle_prep_packet": tracked_packet,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Prepare the bounded stronger-cycle branch after a truthful non-earned B04.R5 result.")
    ap.add_argument("--router-proof-receipt", default=DEFAULT_R5_RECEIPT_REL)
    ap.add_argument("--ordered-proof-receipt", default=DEFAULT_ORDERED_PROOF_REL)
    ap.add_argument("--scorecard", default=DEFAULT_SCORECARD_REL)
    ap.add_argument("--non-stub-eval-receipt", default=DEFAULT_NON_STUB_EVAL_REL)
    ap.add_argument("--followthrough-report", default=DEFAULT_FOLLOWTHROUGH_REL)
    ap.add_argument("--merge-outcome-report", default=DEFAULT_MERGE_OUTCOME_REL)
    ap.add_argument("--proof-binding-report", default=DEFAULT_PROOF_BINDING_REL)
    ap.add_argument(
        "--authoritative-root",
        default="",
        help="Optional authoritative output root. Default: <repo>/tmp/cohort0_stronger_cycle_prep_current_head",
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
    payload = run_stronger_cycle_prep_tranche(
        router_proof_receipt_path=_resolve_path(root, str(args.router_proof_receipt)),
        ordered_proof_receipt_path=_resolve_path(root, str(args.ordered_proof_receipt)),
        scorecard_path=_resolve_path(root, str(args.scorecard)),
        non_stub_eval_receipt_path=_resolve_path(root, str(args.non_stub_eval_receipt)),
        followthrough_report_path=_resolve_path(root, str(args.followthrough_report)),
        merge_outcome_report_path=_resolve_path(root, str(args.merge_outcome_report)),
        proof_binding_report_path=_resolve_path(root, str(args.proof_binding_report)),
        authoritative_root=_resolve_path(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve_path(root, str(args.reports_root)),
        workspace_root=root,
    )
    prep_packet = payload["stronger_cycle_prep_packet"]
    print(
        json.dumps(
            {
                "status": prep_packet["status"],
                "prep_posture": prep_packet["prep_posture"],
                "next_lawful_move": prep_packet["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
