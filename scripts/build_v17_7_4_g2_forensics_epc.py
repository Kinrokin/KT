from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core


OUTCOME = "KT_G2_PATH_FORENSICS_BOUND__EXPERIMENT_POLICY_CONTROLLER_READY__CLAIM_CEILING_PRESERVED"
NEXT_WHEN_BLOCKED = "BIND_EXACT_G2_STATE_VECTOR_AND_RAW_OUTPUTS_FOR_OFFLINE_REPLAY"
G2_ROUTE = "routed_13_lobe_kt_hat_compact"
STABLE_CONTROL = core.REPROLOCK_ARM_ID


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(core.AUTHORITY_FALSE)
    payload.update(
        {
            "multi_lobe_superiority_claim": False,
            "commercial_claim": False,
            "external_validation_claim": False,
            "g2_recovered_claim": False,
            "frontier_claim": False,
            "s_tier_claim": False,
            "production_readiness_claim": False,
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


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def source_entry(path: Path, role: str, evidence_type: str) -> dict[str, Any]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": sha256_file(path),
        "role": role,
        "evidence_type": evidence_type,
        "size_bytes": path.stat().st_size,
    }


def build_truth_pin() -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.g2_forensics_truth_pin_receipt.v1",
        status="PASS",
        current_head=git(["rev-parse", "HEAD"]),
        current_branch=git(["branch", "--show-current"]),
        worktree_clean=not bool(git(["status", "--short"])),
        active_tranche="AUTHOR_KTV1774_G2_PATH_FORENSICS_AND_EXPERIMENT_POLICY_CONTROLLER_V1",
        no_runtime_generation_until_forensics=True,
        claim_ceiling_preserved=True,
    )


def build_g2_artifact_source_index() -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    candidates = [
        ("runtime/v17_7_4/KT_V1774_TRUEGEN_ARM_CORE.py", "g2_anchor_constant_and_runtime_accounting", "ANCHOR_CODE"),
        ("reports/v17_7_4_post_reprolock_compression_gap_receipt.json", "current_vs_g2_gap_receipt", "CURRENT_GAP_RECEIPT"),
        ("reports/v17_7_4_dual_frontier_repair_scorecard.json", "current_dual_frontier_scorecard", "CURRENT_MEASURED_SUMMARY"),
        ("reports/v17_7_4_route_specific_compression_candidate.json", "cheapest_correct_teacher_policy", "CURRENT_TEACHER_SIMULATION"),
        ("reports/v17_7_4_route_cost_decision_table.jsonl", "row_level_route_cost_decisions", "CURRENT_ROW_TABLE"),
        ("reports/v17_7_4_token_accounting_reconciliation.json", "prior_token_accounting_reconciliation", "TOKEN_ACCOUNTING_HINT"),
        ("reports/v17_7_4_realbench_builder_summary.json", "g2_sentinel_missing_receipt", "MISSING_SOURCE_RECEIPT"),
    ]
    for rel, role, evidence_type in candidates:
        path = ROOT / rel
        if path.exists():
            sources.append(source_entry(path, role, evidence_type))
    exact_g2_sources = [
        entry
        for entry in sources
        if entry["evidence_type"] in {"EXACT_G2_PROMPT_MANIFEST", "EXACT_G2_TOKEN_LEDGER", "EXACT_G2_RAW_OUTPUTS"}
    ]
    return authority(
        schema_id="kt.v17_7_4.g2_artifact_source_index.v1",
        status="PARTIAL_ANCHOR_ONLY",
        sources=sources,
        source_count=len(sources),
        exact_g2_state_sources_bound=bool(exact_g2_sources),
        missing_exact_g2_sources=[
            "exact_g2_prompt_manifest",
            "exact_g2_row_ids",
            "exact_g2_raw_outputs",
            "exact_g2_token_ledger",
            "exact_g2_router_policy",
            "exact_g2_hat_mode",
            "exact_g2_scorer_parser",
        ],
        no_fabricated_g2_source=True,
        claim_ceiling_preserved=True,
    )


def build_g2_state_vector(source_index: dict[str, Any]) -> dict[str, Any]:
    anchor = core.G2_COMPRESSION_ANCHOR
    components = [
        {"component": "headline_anchor", "status": "RECOVERED", "evidence": anchor},
        {"component": "prompt_contract", "status": "MISSING_EXACT_SOURCE"},
        {"component": "token_accounting_mode", "status": "PARTIAL_HINT_ONLY"},
        {"component": "router_policy", "status": "MISSING_EXACT_SOURCE"},
        {"component": "kt_hat_behavior", "status": "MISSING_EXACT_SOURCE"},
        {"component": "scorer_parser", "status": "MISSING_EXACT_SOURCE"},
        {"component": "row_ids", "status": "MISSING_EXACT_SOURCE"},
        {"component": "raw_outputs", "status": "MISSING_EXACT_SOURCE"},
    ]
    missing = [row["component"] for row in components if str(row["status"]).startswith("MISSING")]
    return authority(
        schema_id="kt.v17_7_4.g2_state_vector_recovery_receipt.v1",
        status="PARTIAL_BLOCKED",
        recovered_components=components,
        missing_components=missing,
        g2_anchor=anchor,
        exact_state_vector_recovered=False,
        conclusion="G2 compression remains a hypothesis anchor until exact prompt, row, raw-output, route, scorer, and token-ledger surfaces are bound.",
        source_index_status=source_index["status"],
        g2_recovered_claim=False,
        claim_ceiling_preserved=True,
    )


def current_scorecard() -> dict[str, Any]:
    path = ROOT / "reports" / "v17_7_4_dual_frontier_repair_scorecard.json"
    return read_json(path)


def token_reconciliation(scorecard: dict[str, Any]) -> dict[str, Any]:
    g2 = core.G2_COMPRESSION_ANCHOR[G2_ROUTE]
    base_g2 = core.G2_COMPRESSION_ANCHOR["base_raw"]
    stable_full = float(scorecard.get("stable_control_full_tokens_per_correct", 0.0))
    stable_visible = float(scorecard.get("stable_control_visible_tokens_per_correct", 0.0))
    g2_tpc = float(g2["tokens_per_correct"])
    return authority(
        schema_id="kt.v17_7_4.g2_token_accounting_reconciliation.v1",
        status="BLOCKED_UNTIL_EXACT_G2_ACCOUNTING_METHOD_RECOVERED",
        g2_routed_tokens_per_correct=g2_tpc,
        g2_base_tokens_per_correct=base_g2["tokens_per_correct"],
        stable_control_full_tokens_per_correct=stable_full,
        stable_control_visible_answer_tokens_per_correct=stable_visible,
        full_tpc_ratio_current_over_g2=round(stable_full / g2_tpc, 6) if g2_tpc else None,
        visible_tpc_ratio_current_over_g2=round(stable_visible / g2_tpc, 6) if g2_tpc else None,
        visible_answer_compression_signal=stable_visible > 0 and stable_visible <= g2_tpc,
        full_system_compression_recovered=stable_full > 0 and stable_full <= g2_tpc,
        accounting_modes_must_not_be_collapsed=[
            "full_prompt_plus_output_tokens_per_correct",
            "prompt_tokens_per_correct",
            "output_tokens_per_correct",
            "visible_answer_tokens_per_correct",
            "route_overhead_tokens_per_correct",
            "hat_overhead_tokens_per_correct",
        ],
        calling_visible_tpc_full_tpc_forbidden=True,
        g2_recovered_claim=False,
        claim_ceiling_preserved=True,
    )


def g2_vs_reprolock_diff(scorecard: dict[str, Any]) -> dict[str, Any]:
    g2 = core.G2_COMPRESSION_ANCHOR[G2_ROUTE]
    stable_correct = int(scorecard.get("known_good_correct", 0))
    stable_total = int(scorecard.get("known_good_total", 0))
    stable_accuracy = stable_correct / max(stable_total, 1)
    return authority(
        schema_id="kt.v17_7_4.g2_vs_reprolock_path_diff.v1",
        status="PASS_DIFF_BOUND_NOT_COMPARABILITY_PROOF",
        g2_path={
            "route": G2_ROUTE,
            "correct": g2["correct"],
            "total": g2["total"],
            "accuracy": g2["accuracy"],
            "tokens_per_correct": g2["tokens_per_correct"],
        },
        reprolock_path={
            "route": STABLE_CONTROL,
            "correct": stable_correct,
            "total": stable_total,
            "accuracy": round(stable_accuracy, 6),
            "full_tokens_per_correct": scorecard.get("stable_control_full_tokens_per_correct"),
            "visible_answer_tokens_per_correct": scorecard.get("stable_control_visible_tokens_per_correct"),
        },
        row_set_comparable=False,
        prompt_contract_comparable=False,
        token_accounting_comparable=False,
        scorer_parser_comparable=False,
        conclusion="ReproLock restored the known-good 41/50 path; it did not prove the old G2 compression state is recovered.",
        claim_ceiling_preserved=True,
    )


def offline_extraction_replay() -> dict[str, Any]:
    raw_candidates = [
        ROOT / "reports" / "truegen_arm_result_matrix.jsonl",
        ROOT / "reports" / "v17_7_4_truegen_arm_result_matrix.jsonl",
    ]
    present = [path for path in raw_candidates if path.exists()]
    return authority(
        schema_id="kt.v17_7_4.offline_final_answer_extraction_replay.v1",
        status="BLOCKED_RAW_OUTPUTS_NOT_BOUND" if not present else "READY_FOR_OFFLINE_REPLAY",
        raw_output_sources=[path.relative_to(ROOT).as_posix() for path in present],
        required_missing=[] if present else ["row_level_raw_outputs_for_stable_control_and_candidates"],
        no_generation_required=True,
        model_runtime_invoked=False,
        expected_answer_visible_to_model=False,
        training_authorized=False,
        claim_ceiling_preserved=True,
    )


def cheapest_correct_route_simulation() -> dict[str, Any]:
    rows = read_jsonl(ROOT / "reports" / "v17_7_4_route_cost_decision_table.jsonl")
    if not rows:
        return authority(
            schema_id="kt.v17_7_4.cheapest_correct_route_simulation.v1",
            status="BLOCKED_ROW_TABLE_MISSING",
            row_count=0,
            runtime_authority=False,
            claim_ceiling_preserved=True,
        )
    stable_correct = sum(1 for row in rows if row.get("stable_control_correct") is True)
    stable_tokens = sum(int(row.get("stable_control_tokens", 0)) for row in rows if row.get("stable_control_correct") is True)
    candidate_correct = sum(1 for row in rows if row.get("route_specific_candidate_correct") is True)
    candidate_tokens = sum(int(row.get("route_specific_candidate_tokens", 0)) for row in rows if row.get("route_specific_candidate_correct") is True)
    cost_recovery_rows = [row for row in rows if int(row.get("token_delta_vs_stable", 0)) < 0 and row.get("route_specific_candidate_correct") is True]
    return authority(
        schema_id="kt.v17_7_4.cheapest_correct_route_simulation.v1",
        status="PASS_TEACHER_ONLY_NOT_RUNTIME",
        row_count=len(rows),
        stable_control_correct=stable_correct,
        stable_control_tokens_per_correct=round(stable_tokens / stable_correct, 6) if stable_correct else None,
        cheapest_correct_candidate_correct=candidate_correct,
        cheapest_correct_candidate_tokens_per_correct=round(candidate_tokens / candidate_correct, 6) if candidate_correct else None,
        cost_recovery_row_count=len(cost_recovery_rows),
        oracle_correctness_used_as_runtime_feature=False,
        runtime_authority=False,
        promotion_authority=False,
        required_next_step="derive pre-generation feature policy and validate on held-out rows before runtime use",
        claim_ceiling_preserved=True,
    )


def ope_authority_hardening() -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.ope_replay_authority_hardening.v1",
        status="PASS",
        replay_is_not_fresh_generation=True,
        source_replay_cannot_authorize_training=True,
        cheapest_correct_teacher_policy_cannot_be_runtime_policy=True,
        visible_tpc_cannot_be_reported_as_full_tpc=True,
        g2_anchor_is_historical_hypothesis_not_recovered_claim=True,
        claim_ceiling_preserved=True,
    )


def experiment_policy_controller(
    state_vector: dict[str, Any],
    extraction: dict[str, Any],
    route_sim: dict[str, Any],
    token_report: dict[str, Any],
) -> dict[str, Any]:
    interventions = [
        {
            "intervention_id": "BIND_EXACT_G2_STATE_VECTOR",
            "expected_information_gain": 0.95,
            "compute_cost": "LOW",
            "risk": "LOW",
            "allowed": True,
            "reason": "Missing G2 prompt, row, route, scorer, and token-ledger surfaces dominate uncertainty.",
        },
        {
            "intervention_id": "BIND_RAW_OUTPUTS_FOR_OFFLINE_EXTRACTION_REPLAY",
            "expected_information_gain": 0.90,
            "compute_cost": "LOW",
            "risk": "LOW",
            "allowed": extraction["status"] == "BLOCKED_RAW_OUTPUTS_NOT_BOUND",
            "reason": "Offline extraction can test parser/finalizer hypotheses without generation.",
        },
        {
            "intervention_id": "DERIVE_PRE_GENERATION_ROUTE_FEATURES_FROM_TEACHER_TABLE",
            "expected_information_gain": 0.72,
            "compute_cost": "LOW",
            "risk": "MEDIUM",
            "allowed": route_sim["status"] == "PASS_TEACHER_ONLY_NOT_RUNTIME",
            "reason": "Cheapest-correct simulation shows small cost opportunity but no runtime authority.",
        },
        {
            "intervention_id": "RUN_NEW_MICRO_FURNACE",
            "expected_information_gain": 0.35,
            "compute_cost": "MEDIUM",
            "risk": "MEDIUM",
            "allowed": False,
            "reason": "Blocked until G2 state vector and raw-output offline replay are bound.",
        },
        {
            "intervention_id": "TRAIN_ADAPTER_OR_ROUTER",
            "expected_information_gain": 0.10,
            "compute_cost": "HIGH",
            "risk": "HIGH",
            "allowed": False,
            "reason": "No lobe/adapter-owned scar with minimum viable signal; training forbidden in this lane.",
        },
    ]
    selected = [row for row in interventions if row["allowed"]]
    selected.sort(key=lambda row: (-float(row["expected_information_gain"]), row["intervention_id"]))
    next_intervention = selected[0]["intervention_id"] if selected else NEXT_WHEN_BLOCKED
    return authority(
        schema_id="kt.v17_7_4.experiment_policy_controller_decision.v1",
        status="PASS",
        decision="FORENSICS_AND_OFFLINE_REPLAY_BEFORE_RUNTIME_GENERATION",
        next_intervention=next_intervention,
        interventions=interventions,
        state_vector_status=state_vector["status"],
        offline_extraction_replay_status=extraction["status"],
        cheapest_correct_route_simulation_status=route_sim["status"],
        full_system_compression_recovered=token_report["full_system_compression_recovered"],
        no_runtime_generation_until_forensics=True,
        training_authorized=False,
        promotion_authority=False,
        claim_ceiling_preserved=True,
    )


def micro_furnace_design(epc: dict[str, Any]) -> dict[str, Any]:
    allowed = epc.get("next_intervention") == "RUN_NEW_MICRO_FURNACE"
    return authority(
        schema_id="kt.v17_7_4.micro_furnace_design_decision.v1",
        status="HELD_BY_EPC" if not allowed else "READY_FOR_DESIGN",
        micro_furnace_packet_generated=False,
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        hold_reasons=[] if allowed else ["exact_g2_state_vector_missing", "offline_raw_output_extraction_replay_missing"],
        claim_ceiling_preserved=True,
    )


def write_docs() -> None:
    write_text(
        ROOT / "docs" / "G2_PATH_FORENSICS_AND_EPC.md",
        """# G2 Path Forensics And Experiment Policy Controller

G2 compression is treated as a hypothesis to recover, not as a current capability claim.

The controller blocks new generation while exact G2 state-vector surfaces are missing:
prompt contract, row IDs, raw outputs, route policy, KT-hat behavior, scorer/parser, and token ledger.

Allowed work is offline and forensic: bind sources, replay final-answer extraction from raw outputs,
simulate cheapest-correct route tables, and choose the next intervention by expected information gain.

Forbidden work: training, promotion, V18 authorization, router superiority claims, G2 recovered claims,
commercial/external/S-tier/frontier/production claims, and collapsing visible TPC into full-system TPC.
""",
    )
    write_text(
        ROOT / "rules" / "NO_RUNTIME_GENERATION_UNTIL_G2_FORENSICS.md",
        """# No Runtime Generation Until G2 Forensics

Runtime generation is held until the Experiment Policy Controller confirms that a micro-furnace has
higher expected information gain than offline source recovery and extraction replay.

Replay and OPE are not fresh-generation authority. Oracle/cheapest-correct choices are teacher
signals only and cannot be runtime features.
""",
    )


def write_reports() -> dict[str, Any]:
    truth = build_truth_pin()
    source_index = build_g2_artifact_source_index()
    state_vector = build_g2_state_vector(source_index)
    scorecard = current_scorecard()
    token_report = token_reconciliation(scorecard)
    diff = g2_vs_reprolock_diff(scorecard)
    extraction = offline_extraction_replay()
    route_sim = cheapest_correct_route_simulation()
    ope = ope_authority_hardening()
    epc = experiment_policy_controller(state_vector, extraction, route_sim, token_report)
    micro = micro_furnace_design(epc)
    reports = {
        "reports/v17_7_4_g2_forensics_truth_pin_receipt.json": truth,
        "reports/v17_7_4_g2_artifact_source_index.json": source_index,
        "reports/v17_7_4_g2_state_vector_recovery_receipt.json": state_vector,
        "reports/v17_7_4_g2_token_accounting_reconciliation.json": token_report,
        "reports/v17_7_4_g2_vs_reprolock_path_diff.json": diff,
        "reports/v17_7_4_offline_final_answer_extraction_replay.json": extraction,
        "reports/v17_7_4_cheapest_correct_route_simulation.json": route_sim,
        "reports/v17_7_4_experiment_policy_controller_decision.json": epc,
        "reports/v17_7_4_ope_replay_authority_hardening.json": ope,
        "reports/v17_7_4_micro_furnace_design_decision.json": micro,
    }
    for rel, payload in reports.items():
        write_json(ROOT / rel, payload)
    summary = authority(
        schema_id="kt.v17_7_4.g2_forensics_epc_builder_summary.v1",
        status="PASS",
        current_head=truth["current_head"],
        current_branch=truth["current_branch"],
        outcome=OUTCOME,
        next_lawful_move=epc["next_intervention"],
        g2_forensics_truth_pin_status=truth["status"],
        g2_artifact_source_status=source_index["status"],
        g2_state_vector_recovery_status=state_vector["status"],
        g2_token_accounting_status=token_report["status"],
        g2_vs_reprolock_diff_status=diff["status"],
        offline_extraction_replay_status=extraction["status"],
        cheapest_correct_route_simulation_status=route_sim["status"],
        experiment_policy_controller_status=epc["status"],
        ope_authority_status=ope["status"],
        micro_furnace_design_status=micro["status"],
        packet_path_if_any=micro["packet_path_if_any"],
        packet_sha256_if_any=micro["packet_sha256_if_any"],
        kaggle_dataset_name_if_any=micro["kaggle_dataset_name_if_any"],
        one_cell_runbook_if_any=micro["one_cell_runbook_if_any"],
        blockers=[],
        claim_ceiling_status="PRESERVED",
    )
    write_json(ROOT / "reports" / "v17_7_4_g2_forensics_epc_builder_summary.json", summary)
    write_json(
        ROOT / "registry" / "artifact_authority_registry_v17_7_4_g2_forensics_epc_delta_receipt.json",
        authority(
            schema_id="kt.artifact_authority_registry.delta_receipt.v17_7_4_g2_forensics_epc.v1",
            status="PASS",
            current_head=truth["current_head"],
            artifacts_added=[
                {"path": rel, "role": "g2_forensics_epc_report", "sha256": sha256_file(ROOT / rel), "authority_state": "LIVE_CURRENT_HEAD_FORENSIC_ONLY", "claim_expansion": False}
                for rel in [*reports, "reports/v17_7_4_g2_forensics_epc_builder_summary.json"]
            ],
            outcome=OUTCOME,
            next_lawful_move=epc["next_intervention"],
            no_training=True,
            no_promotion=True,
            no_v18=True,
            no_router_superiority_claim=True,
            no_g2_recovered_claim=True,
        ),
    )
    return summary


def main() -> int:
    write_docs()
    summary = write_reports()
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
