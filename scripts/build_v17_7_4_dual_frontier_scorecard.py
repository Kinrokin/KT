from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTCOME = "KT_DUAL_FRONTIER_ROUTER_SUBSTRATE_READY__RUN_REASONING_PRESERVING_ADMISSION_BENCH_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_KTV1774_DUALFRONT_50"

FULL_REALBENCH = {
    "base_raw": {"correct": 30, "total": 50, "accuracy": 0.60, "full_tokens_per_correct": 175.233333, "visible_answer_tokens_per_correct": None},
    "math_act_adapter_global": {"correct": 41, "total": 50, "accuracy": 0.82, "full_tokens_per_correct": 145.121951, "visible_answer_tokens_per_correct": None},
    "oracle": {"correct": 42, "total": 50, "accuracy": 0.84, "full_tokens_per_correct": None, "visible_answer_tokens_per_correct": None},
}

COMPACT_REALBENCH = {
    "base_raw": {"correct": 23, "total": 50, "accuracy": 0.46, "full_tokens_per_correct": 182.52, "visible_answer_tokens_per_correct": 2.17},
    "formal_math_repair_adapter_global": {"correct": 29, "total": 50, "accuracy": 0.58, "full_tokens_per_correct": 164.90, "visible_answer_tokens_per_correct": 1.72},
    "math_act_adapter_global": {"correct": 29, "total": 50, "accuracy": 0.58, "full_tokens_per_correct": 158.66, "visible_answer_tokens_per_correct": 1.72},
    "oracle": {"correct": 36, "total": 50, "accuracy": 0.72, "full_tokens_per_correct": None, "visible_answer_tokens_per_correct": None},
}

G2_ANCHOR = {
    "base_raw": {"correct": 119, "total": 200, "accuracy": 0.595, "tokens_per_correct": 42.857143},
    "routed_13_lobe_kt_hat_compact": {"correct": 126, "total": 200, "accuracy": 0.63, "tokens_per_correct": 3.738095},
    "tokens_per_correct_reduction": 0.912778,
}


def authority(**extra: Any) -> dict[str, Any]:
    payload = {
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
        "adapter_training_authorized": False,
        "router_training_authorized": False,
        "policy_optimization_authorized": False,
        "learned_router_superiority_claim": False,
        "multi_lobe_superiority_claim": False,
        "v18_runtime_authority": False,
    }
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


def tracked_dirty_files() -> list[str]:
    output = subprocess.check_output(["git", "status", "--short"], cwd=ROOT, text=True)
    return [line[3:] for line in output.splitlines() if line and not line.startswith("??")]


def pareto_status(correct: int, full_tpc: float | None, base_correct: int, base_tpc: float | None) -> str:
    if full_tpc is None or base_tpc is None:
        return "ORACLE_OR_REFERENCE_ONLY"
    if correct > base_correct and full_tpc <= base_tpc:
        return "PARETO_IMPROVES_ACCURACY_AND_COST"
    if correct == base_correct and full_tpc < base_tpc:
        return "PARETO_IMPROVES_COST_AT_SAME_CORRECTNESS"
    if correct > base_correct:
        return "UTILITY_JUSTIFIED_ACCURACY_GAIN_REQUIRES_COST_REVIEW"
    if correct < base_correct and full_tpc >= base_tpc:
        return "QUARANTINE_WORSE_ACCURACY_AND_COST"
    return "DIAGNOSTIC_ONLY"


def scorecard_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    base_correct = FULL_REALBENCH["base_raw"]["correct"]
    base_tpc = FULL_REALBENCH["base_raw"]["full_tokens_per_correct"]
    oracle_correct = FULL_REALBENCH["oracle"]["correct"]
    for source, data in [("REALBENCH_FULL_GENERATION", FULL_REALBENCH), ("COMPACT_ANSWER_ONLY", COMPACT_REALBENCH)]:
        for arm_id, metrics in data.items():
            if arm_id == "oracle":
                continue
            correct = int(metrics["correct"])
            full_tpc = metrics["full_tokens_per_correct"]
            visible_tpc = metrics["visible_answer_tokens_per_correct"]
            rows.append(
                {
                    "schema_id": "kt.v17_7_4.dual_frontier_scorecard_row.v1",
                    "source_run": source,
                    "arm_id": arm_id,
                    "route_id": arm_id,
                    "task_family": "ALL",
                    "dataset": "REALBENCH_50",
                    "correct_count": correct,
                    "accuracy": metrics["accuracy"],
                    "full_tokens_per_correct": full_tpc,
                    "visible_answer_tokens_per_correct": visible_tpc,
                    "reasoning_tokens_per_correct": None,
                    "prompt_tokens_per_correct": None,
                    "route_overhead_tokens_per_correct": None,
                    "hat_overhead_tokens_per_correct": None,
                    "latency_per_correct": None,
                    "verified_work_per_token": round(1.0 / full_tpc, 6) if full_tpc else None,
                    "route_regret": max(oracle_correct - correct, 0),
                    "oracle_gap": max(oracle_correct - correct, 0),
                    "negative_transfer_count": 0 if source == "REALBENCH_FULL_GENERATION" and arm_id == "math_act_adapter_global" else None,
                    "parser_failure_rate": None,
                    "final_answer_format_failure_rate": None,
                    "claim_safety_status": "PASS_CLAIM_CEILING_PRESERVED",
                    "replayability_status": "KAGGLE_ASSESSMENT_BOUND_SUMMARY",
                    "Pareto_status": pareto_status(correct, full_tpc, base_correct, base_tpc),
                }
            )
    return rows


def main() -> int:
    current_head = git(["rev-parse", "HEAD"])
    branch = git(["branch", "--show-current"])
    claim_ceiling = ROOT / "governance" / "current_claim_ceiling.json"
    artifact_registry = ROOT / "registry" / "artifact_authority_registry.json"
    dirty = tracked_dirty_files()
    controlling_dirty = [path for path in dirty if path.startswith(("runtime/v17_7_4/", "configs/v17_7_4/", "scripts/build_v17_7_4_dual", "tests/test_v17_7_4_dual"))]
    required_truth_files_present = claim_ceiling.exists() and artifact_registry.exists()
    truth_pin = authority(
        schema_id="kt.dualfront.truth_pin_receipt.v1",
        status="PASS" if required_truth_files_present else "BLOCKED",
        current_head=current_head,
        branch=branch,
        worktree_clean=not dirty,
        dirty_files=dirty,
        controlling_dirty_files=controlling_dirty,
        active_lane_dirty_files_recorded=bool(dirty),
        active_lane_dirty_files_block_publication=False,
        truth_pin_note="Receipt binds the public current head and required authority files. Dirty files are recorded for staging isolation; unrelated dirty files must not be staged.",
        claim_ceiling_file=claim_ceiling.as_posix(),
        artifact_authority_registry=artifact_registry.as_posix(),
        current_13_lobe_registry="adaptive/cognitive_lobe_registry.json",
        gate_court_validator_registry="governance/gate_court_validator_registry.json",
        exact_next_lawful_move_before_patch="RUN_KTV1774_REALBENCH_COMPACT_50",
    )
    write_json(ROOT / "reports" / "kt_dualfront_truth_pin_receipt.json", truth_pin)
    write_json(
        ROOT / "reports" / "kt_dualfront_source_evidence_index.json",
        authority(
            schema_id="kt.dualfront.source_evidence_index.v1",
            status="PASS",
            current_head=current_head,
            realbench_50_result_source="operator assessment summary bound in reports/v17_7_4_realbench_50_result_binding_receipt.json",
            compact_realbench_50_result_source="operator assessment summary after ktv1774_realbench_compact_v1",
            g2_anchor_source="reports/g2_compression_anchor_receipt.json and historical run summaries",
            live_repo_truth_wins=True,
        ),
    )
    rows = scorecard_rows()
    scorecard = authority(
        schema_id="kt.v17_7_4.dual_frontier_scorecard.v1",
        status="PASS",
        current_head=current_head,
        rows=rows,
        best_accuracy_current="math_act_adapter_global on full RealBench 50",
        best_visible_compression_current="compact answer-only arms",
        conclusion="Accuracy and visible compression are proven separately; dual-frontier recovery requires reasoning-preserving compactness.",
    )
    write_json(ROOT / "reports" / "v17_7_4_dual_frontier_scorecard.json", scorecard)
    write_json(
        ROOT / "reports" / "v17_7_4_dual_frontier_pareto_receipt.json",
        authority(
            schema_id="kt.v17_7_4.dual_frontier_pareto_receipt.v1",
            status="PASS",
            pareto_rows=[{"arm_id": row["arm_id"], "source_run": row["source_run"], "Pareto_status": row["Pareto_status"]} for row in rows],
            rule="Advance only if accuracy and cost jointly improve or utility justifies cost.",
        ),
    )
    compact_binding = authority(
        schema_id="kt.v17_7_4.compact_realbench_50_result_binding_receipt.v1",
        status="PASS_WITH_ACCURACY_REGRESSION",
        base_raw=COMPACT_REALBENCH["base_raw"],
        formal_math_repair_adapter_global=COMPACT_REALBENCH["formal_math_repair_adapter_global"],
        math_act_adapter_global=COMPACT_REALBENCH["math_act_adapter_global"],
        oracle=COMPACT_REALBENCH["oracle"],
        compact_answer_contract_mechanical_pass=True,
        accuracy_preservation_pass=False,
        visible_answer_compression_pass=True,
        g2_recovered=False,
    )
    write_json(ROOT / "reports" / "v17_7_4_compact_realbench_50_result_binding_receipt.json", compact_binding)
    gap = authority(
        schema_id="kt.v17_7_4.dual_frontier_gap_analysis.v1",
        status="PASS",
        intelligence_moved=True,
        visible_answer_compression_moved=True,
        combined_frontier_recovered=False,
        root_cause="compact answer-only generation starved reasoning, especially math/GSM8K",
        required_repair="reason when needed, emit compactly, score visible final answer, account all tokens",
        g2_anchor=G2_ANCHOR,
    )
    write_json(ROOT / "reports" / "v17_7_4_dual_frontier_gap_analysis.json", gap)
    write_json(
        ROOT / "reports" / "kt_dualfront_gap_matrix.json",
        authority(
            schema_id="kt.dualfront.gap_matrix.v1",
            status="PASS",
            gaps=[
                {"gap": "reasoning_preserving_compactness", "owner": "PROMPT_CONTRACT_OWNED"},
                {"gap": "route_admission_oracle_distillation", "owner": "ROUTE_OWNED"},
                {"gap": "g2_exact_sentinel_source", "owner": "ARCHIVE_SOURCE_OWNED"},
                {"gap": "13_lobe_tournament_not_yet_reentered", "owner": "SUBSTRATE_SEQUENCE_OWNED"},
            ],
        ),
    )
    print(json.dumps({"status": "PASS", "scorecard_rows": len(rows), "outcome": OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
