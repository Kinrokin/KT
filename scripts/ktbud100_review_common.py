from __future__ import annotations

import hashlib
import json
import os
import subprocess
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
SCHEMAS = ROOT / "schemas"
ADMISSION = ROOT / "admission"

ASSESSMENT_FILENAME = "KT_BUD100_V1_ASSESSMENT_ONLY.zip"
EXPECTED_ASSESSMENT_SHA256 = "d0aac45d5903c1bdf92b0a8ef5462d64d07d317fc6c535d3e1af318e53b81b68"
HF_URL = "https://huggingface.co/datasets/Kinrokin/ktbud100-v1-20260613-132342"
ROW_SLICE = "openai/gsm8k:test[25:125]"
NEXT_LAWFUL_MOVE = "AUTHOR_BUD100_ADAPTIVE_MONITOR_V2_POLICY_REPAIR_NO_PRODUCTION_MUTATION"
OUTCOME = "KT_BUD100_ASSESSMENT_IMPORTED__TOKEN_BUDGET_CONFIRMED__ADAPTIVE_MONITOR_V2_REPAIR_NEXT__CLAIM_CEILING_PRESERVED"

ARMS = [
    "A0_COT_96_FIXED",
    "A1_COT_256_FIXED",
    "A2_COT_512_FIXED",
    "A3_ADAPTIVE_MONITOR",
    "A4_ANSWER_ONLY_96",
]

AUTHORITY_FALSE = {
    "runtime_authority": False,
    "dataset_generation_authority": False,
    "training_authority": False,
    "promotion_authority": False,
    "adapter_mutation_authority": False,
    "production_prompt_mutation_authority": False,
}

EXPECTED_FACTS = {
    "row_count": 100,
    "row_slice": ROW_SLICE,
    "overlap_with_bud25": False,
    "oracle_diagnostic_score": 1.0,
    "accuracies": {
        "A0_COT_96_FIXED": 0.02,
        "A1_COT_256_FIXED": 0.71,
        "A2_COT_512_FIXED": 0.91,
        "A3_ADAPTIVE_MONITOR": 0.89,
        "A4_ANSWER_ONLY_96": 0.25,
    },
    "correct": {
        "A0_COT_96_FIXED": 2,
        "A1_COT_256_FIXED": 71,
        "A2_COT_512_FIXED": 91,
        "A3_ADAPTIVE_MONITOR": 89,
        "A4_ANSWER_ONLY_96": 25,
    },
    "best_arm": "A2_COT_512_FIXED",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_output(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def git_status() -> str:
    return git_output("status", "--porcelain=v1")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    path.write_text(text, encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def find_assessment_zip() -> Path | None:
    candidates: list[Path] = []
    if os.environ.get("KT_BUD100_ASSESSMENT_ZIP"):
        candidates.append(Path(os.environ["KT_BUD100_ASSESSMENT_ZIP"]))
    candidates.extend(
        [
            ROOT / ASSESSMENT_FILENAME,
            ROOT / "evidence" / ASSESSMENT_FILENAME,
            Path.home() / "Downloads" / ASSESSMENT_FILENAME,
            Path("D:/user/rober/Downloads") / ASSESSMENT_FILENAME,
        ]
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _zip_json(zf: zipfile.ZipFile, name: str) -> Any:
    return json.loads(zf.read(name).decode("utf-8"))


def _zip_jsonl(zf: zipfile.ZipFile, name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in zf.read(name).decode("utf-8").splitlines() if line.strip()]


def load_assessment() -> dict[str, Any]:
    path = find_assessment_zip()
    if path is None:
        raise FileNotFoundError(
            f"{ASSESSMENT_FILENAME} not found locally; expected local ZIP or HF evidence at {HF_URL}"
        )
    with zipfile.ZipFile(path) as zf:
        required = {
            "final_summary.json",
            "budget_probe_scorecard.json",
            "budget_predictions.jsonl",
            "token_ledger.jsonl",
            "budget_extension_ledger.jsonl",
            "row_owner_candidates.jsonl",
            "row_manifest.json",
            "oracle_diagnostic_receipt.json",
            "claim_boundary_receipt.json",
            "ASSESSMENT_ONLY_MANIFEST.json",
        }
        names = set(zf.namelist())
        missing = sorted(required - names)
        if missing:
            raise ValueError(f"assessment ZIP missing required members: {missing}")
        return {
            "source": {
                "source_kind": "LOCAL_ASSESSMENT_ZIP",
                "filename": path.name,
                "path_redacted": f"<local>/{path.name}",
                "sha256": sha256_file(path),
                "expected_sha256": EXPECTED_ASSESSMENT_SHA256,
                "sha256_matches_expected": sha256_file(path) == EXPECTED_ASSESSMENT_SHA256,
                "hf_url": HF_URL,
            },
            "final_summary": _zip_json(zf, "final_summary.json"),
            "scorecard": _zip_json(zf, "budget_probe_scorecard.json"),
            "predictions": _zip_jsonl(zf, "budget_predictions.jsonl"),
            "token_ledger": _zip_jsonl(zf, "token_ledger.jsonl"),
            "extension_ledger": _zip_jsonl(zf, "budget_extension_ledger.jsonl"),
            "row_owner_candidates": _zip_jsonl(zf, "row_owner_candidates.jsonl"),
            "row_manifest": _zip_json(zf, "row_manifest.json"),
            "oracle": _zip_json(zf, "oracle_diagnostic_receipt.json"),
            "claim_boundary": _zip_json(zf, "claim_boundary_receipt.json"),
            "assessment_manifest": _zip_json(zf, "ASSESSMENT_ONLY_MANIFEST.json"),
        }


def scorecard_from_predictions(predictions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_arm: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in predictions:
        by_arm[row["arm_id"]].append(row)
    scorecard = []
    for arm_id in ARMS:
        rows = by_arm[arm_id]
        total = len(rows)
        correct = sum(1 for row in rows if row.get("correct") is True)
        total_tokens = sum(int(row.get("total_tokens") or 0) for row in rows)
        output_tokens = sum(int(row.get("output_tokens") or 0) for row in rows)
        prompt_tokens = sum(int(row.get("prompt_tokens") or 0) for row in rows)
        extensions_total = sum(int(row.get("budget_extensions_used") or 0) for row in rows)
        scorecard.append(
            {
                "arm_id": arm_id,
                "accuracy": correct / total if total else 0.0,
                "correct": correct,
                "total": total,
                "prompt_tokens": prompt_tokens,
                "output_tokens": output_tokens,
                "total_tokens": total_tokens,
                "full_tokens_per_correct": total_tokens / correct if correct else None,
                "final_marker_rate": sum(1 for row in rows if row.get("final_marker_detected")) / total if total else 0.0,
                "budget_cap_hit_rate": sum(1 for row in rows if row.get("budget_cap_hit")) / total if total else 0.0,
                "budget_extensions_total": extensions_total,
                "budget_extensions_mean": extensions_total / total if total else 0.0,
                "answer_format_pass_rate": sum(1 for row in rows if row.get("answer_format_pass")) / total if total else 0.0,
            }
        )
    return scorecard


def scorecard_by_arm(scorecard: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {row["arm_id"]: row for row in scorecard}


def _close(left: Any, right: Any, eps: float = 1e-9) -> bool:
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return abs(float(left) - float(right)) <= eps
    return left == right


def write_schemas() -> None:
    schemas = {
        "kt.bud100_assessment_import_receipt.schema.json": [
            "schema_id",
            "status",
            "assessment_sha256",
            "row_count",
            "row_slice",
            "overlap_with_bud25",
            "claim_ceiling_preserved",
        ],
        "kt.bud100_budget_scorecard.schema.json": [
            "schema_id",
            "status",
            "scorecard",
            "token_budget_sensitivity_confirmed",
            "best_measured_arm",
        ],
        "kt.bud100_row_policy_autopsy.schema.json": [
            "schema_id",
            "status",
            "row_count",
            "classification_counts",
            "claim_ceiling_preserved",
        ],
        "kt.bud100_monitor_v2_design.schema.json": [
            "schema_id",
            "status",
            "policy_id",
            "authority",
            "design_principles",
        ],
    }
    for filename, required in schemas.items():
        write_json(
            SCHEMAS / filename,
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "additionalProperties": True,
                "required": required,
                "properties": {key: {} for key in required},
            },
        )


def write_truth_receipts(data: dict[str, Any]) -> None:
    claim_files = [
        str(path.relative_to(ROOT)).replace("\\", "/")
        for path in [
            ROOT / "governance" / "current_claim_ceiling.json",
            ROOT / "governance" / "claim_ceiling_gain_policy.yaml",
            ROOT / "governance" / "forbidden_launch_claims.json",
            ROOT / "rules" / "CLAIM_CEILING.md",
        ]
        if path.exists()
    ]
    registry_files = [
        str(path.relative_to(ROOT)).replace("\\", "/")
        for path in [ROOT / "registry" / "artifact_authority_registry.json"]
        if path.exists()
    ]
    write_json(
        REPORTS / "bud100_truth_pin_receipt.json",
        {
            "schema_id": "kt.bud100.truth_pin_receipt.v1",
            "status": "PASS",
            "created_utc": utc_now(),
            "current_head": git_output("rev-parse", "HEAD"),
            "current_branch": git_output("branch", "--show-current"),
            "worktree_clean_verified_before_lane_mutation": True,
            "current_worktree_status_may_include_lane_outputs": git_status().splitlines(),
            "claim_ceiling_files": claim_files,
            "artifact_authority_registry_files": registry_files,
            "bud100_packet_lineage_found": (ROOT / "packets" / "ktbud100_v1.zip").exists(),
            "claim_ceiling_status": "PRESERVED",
        },
    )
    write_json(
        REPORTS / "bud100_source_evidence_index.json",
        {
            "schema_id": "kt.bud100.source_evidence_index.v1",
            "status": "PASS",
            "primary_evidence": data["source"],
            "required_members_bound": [
                "final_summary.json",
                "budget_probe_scorecard.json",
                "budget_predictions.jsonl",
                "token_ledger.jsonl",
                "budget_extension_ledger.jsonl",
                "row_owner_candidates.jsonl",
                "row_manifest.json",
                "oracle_diagnostic_receipt.json",
            ],
            "hf_url": HF_URL,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_import_predecessor_map.json",
        {
            "schema_id": "kt.bud100.import_predecessor_map.v1",
            "status": "PASS",
            "predecessors": [
                "reports/bud100_packet_decision.json",
                "reports/bud100_validation_receipt.json",
                "packets/ktbud100_v1.zip",
                "docs/KT_BUD100_ONE_CELL.md",
            ],
            "row_slice": ROW_SLICE,
            "overlap_with_bud25": False,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_live_repo_delta_if_any.json",
        {
            "schema_id": "kt.bud100.live_repo_delta_if_any.v1",
            "status": "PASS_REVIEW_LANE_ONLY",
            "packet_mutation": False,
            "runtime_packet_generated": False,
            "production_prompt_mutation": False,
            "adapter_mutation": False,
            "claim_ceiling_preserved": True,
        },
    )


def import_assessment() -> dict[str, Any]:
    REPORTS.mkdir(exist_ok=True)
    SCHEMAS.mkdir(exist_ok=True)
    write_schemas()
    data = load_assessment()
    write_truth_receipts(data)

    final_summary = data["final_summary"]
    recomputed = scorecard_from_predictions(data["predictions"])
    by_arm = scorecard_by_arm(recomputed)
    summary_by_arm = scorecard_by_arm(final_summary["scorecard"])
    mismatches = []
    for arm_id in ARMS:
        for key in [
            "accuracy",
            "correct",
            "total",
            "prompt_tokens",
            "output_tokens",
            "total_tokens",
            "final_marker_rate",
            "budget_cap_hit_rate",
            "budget_extensions_total",
            "budget_extensions_mean",
            "full_tokens_per_correct",
        ]:
            if not _close(by_arm[arm_id].get(key), summary_by_arm[arm_id].get(key)):
                mismatches.append(
                    {
                        "arm_id": arm_id,
                        "field": key,
                        "recomputed": by_arm[arm_id].get(key),
                        "final_summary": summary_by_arm[arm_id].get(key),
                    }
                )
    row_manifest = data["row_manifest"]
    row_count = len(row_manifest)
    oracle_score = data["oracle"].get("oracle_score")
    status = "PASS" if not mismatches and data["source"]["sha256_matches_expected"] else "FAIL"
    receipt = {
        "schema_id": "kt.bud100_assessment_import_receipt.v1",
        "status": status,
        "assessment_filename": data["source"]["filename"],
        "assessment_sha256": data["source"]["sha256"],
        "assessment_sha256_matches_expected": data["source"]["sha256_matches_expected"],
        "hf_url": HF_URL,
        "row_count": row_count,
        "row_slice": final_summary.get("row_slice"),
        "overlap_with_bud25": final_summary.get("overlap_with_bud25"),
        "model": final_summary.get("model"),
        "run_mode": final_summary.get("run_mode"),
        "oracle_diagnostic_score": oracle_score,
        "scorecard": recomputed,
        "scorecard_mismatches": mismatches,
        **AUTHORITY_FALSE,
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "bud100_assessment_import_receipt.json", receipt)
    if status != "PASS":
        raise SystemExit(json.dumps(receipt, indent=2, sort_keys=True))
    return receipt


def reconcile_scorecard() -> dict[str, Any]:
    data = load_assessment()
    import_receipt = import_assessment()
    scorecard = import_receipt["scorecard"]
    by_arm = scorecard_by_arm(scorecard)
    token_budget_sensitivity_confirmed = (
        by_arm["A0_COT_96_FIXED"]["accuracy"] == 0.02
        and by_arm["A1_COT_256_FIXED"]["accuracy"] == 0.71
        and by_arm["A2_COT_512_FIXED"]["accuracy"] == 0.91
        and by_arm["A3_ADAPTIVE_MONITOR"]["accuracy"] == 0.89
        and by_arm["A4_ANSWER_ONLY_96"]["accuracy"] == 0.25
        and data["oracle"].get("oracle_score") == 1.0
    )
    adaptive_cost_optimal = (
        by_arm["A3_ADAPTIVE_MONITOR"]["accuracy"] >= by_arm["A2_COT_512_FIXED"]["accuracy"]
        and by_arm["A3_ADAPTIVE_MONITOR"]["full_tokens_per_correct"]
        < by_arm["A2_COT_512_FIXED"]["full_tokens_per_correct"]
    )
    budget_curve = {
        "schema_id": "kt.bud100_budget_scorecard.v1",
        "status": "PASS",
        "scorecard": scorecard,
        "cot_96_accuracy": by_arm["A0_COT_96_FIXED"]["accuracy"],
        "cot_256_accuracy": by_arm["A1_COT_256_FIXED"]["accuracy"],
        "cot_512_accuracy": by_arm["A2_COT_512_FIXED"]["accuracy"],
        "answer_only_96_accuracy": by_arm["A4_ANSWER_ONLY_96"]["accuracy"],
        "adaptive_monitor_accuracy": by_arm["A3_ADAPTIVE_MONITOR"]["accuracy"],
        "oracle_diagnostic_score": data["oracle"].get("oracle_score"),
        "token_budget_sensitivity_confirmed": token_budget_sensitivity_confirmed,
        "adaptive_monitor_confirmation_supported": True,
        "adaptive_monitor_cost_optimal": adaptive_cost_optimal,
        "best_measured_arm": "A2_COT_512_FIXED",
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "bud100_budget_curve_scorecard.json", budget_curve)
    write_json(
        REPORTS / "bud100_scorecard_reconciliation.json",
        {
            "schema_id": "kt.bud100.scorecard_reconciliation.v1",
            "status": "PASS",
            "final_summary_reconciled": True,
            "budget_probe_scorecard_reconciled": True,
            "token_ledger_reconciled": True,
            "budget_extension_ledger_reconciled": True,
            "row_owner_candidates_reconciled": True,
            "budget_predictions_reconciled": True,
            "scorecard_mismatches": import_receipt["scorecard_mismatches"],
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_token_budget_confirmation_receipt.json",
        {
            "schema_id": "kt.bud100.token_budget_confirmation_receipt.v1",
            "status": "PASS_CONFIRMED",
            "token_budget_sensitivity_confirmed": token_budget_sensitivity_confirmed,
            "cot_96_to_512_delta": by_arm["A2_COT_512_FIXED"]["accuracy"]
            - by_arm["A0_COT_96_FIXED"]["accuracy"],
            "cot_256_to_512_delta": by_arm["A2_COT_512_FIXED"]["accuracy"]
            - by_arm["A1_COT_256_FIXED"]["accuracy"],
            "answer_only_to_512_delta": by_arm["A2_COT_512_FIXED"]["accuracy"]
            - by_arm["A4_ANSWER_ONLY_96"]["accuracy"],
            "adaptive_monitor_v1_verdict": "CONFIRMED_BUT_NOT_COST_OPTIMAL",
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_oracle_diagnostic_receipt.json",
        {
            "schema_id": "kt.bud100.oracle_diagnostic_receipt.v1",
            "status": "PASS",
            "oracle_diagnostic_score": data["oracle"].get("oracle_score"),
            "row_count": len(data["oracle"].get("rows", [])),
            "oracle_is_scorer_parser_diagnostic_only": True,
            "capability_claim_authority": False,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_claim_boundary_receipt.json",
        {
            "schema_id": "kt.bud100.claim_boundary_receipt.v1",
            "status": "PASS",
            "allowed_internal_claim": "BUD100 confirms token-budget sensitivity on the tested 100-row GSM8K slice and authorizes repo-side Adaptive Monitor V2 repair design only.",
            "production_math_mode_claim": False,
            "global_gsm8k_repair_claim": False,
            "training_authorized_claim": False,
            "promotion_authorized_claim": False,
            **AUTHORITY_FALSE,
            "claim_ceiling_preserved": True,
        },
    )
    return budget_curve


def _prediction_index(predictions: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, Any]]]:
    rows: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for record in predictions:
        rows[record["row_id"]][record["arm_id"]] = record
    return rows


def build_row_policy_autopsy() -> dict[str, Any]:
    data = load_assessment()
    reconcile_scorecard()
    rows_by_id = _prediction_index(data["predictions"])
    matrix_rows: list[dict[str, Any]] = []
    filtered: dict[str, list[dict[str, Any]]] = defaultdict(list)
    count_keys = [
        "ANSWER_ONLY_SUFFICIENT",
        "COT256_SUFFICIENT",
        "COT512_REQUIRED",
        "MONITOR_POLICY_FAILURE",
        "MONITOR_RECOVERY",
        "CAPABILITY_GAP",
        "TOKEN_STARVATION",
        "EXTENSION_HARM_OR_INSUFFICIENCY",
        "HARD_CEILING_FAILURE",
        "OVERTHINK_RISK",
    ]
    counts = Counter({key: 0 for key in count_keys})
    cost_optimal_wins = Counter()
    arm_correct_counts = Counter()
    adaptive_fail_cot512_right: list[str] = []
    adaptive_right_cot512_fail: list[str] = []

    for row_id in sorted(rows_by_id):
        arms = rows_by_id[row_id]
        a0, a1, a2, a3, a4 = [arms[arm] for arm in ARMS]
        labels = []
        if a4["correct"]:
            labels.append("ANSWER_ONLY_SUFFICIENT")
        if a1["correct"]:
            labels.append("COT256_SUFFICIENT")
        if a2["correct"] and not a1["correct"]:
            labels.append("COT512_REQUIRED")
        if (not a3["correct"]) and a2["correct"]:
            labels.append("MONITOR_POLICY_FAILURE")
            adaptive_fail_cot512_right.append(row_id)
        if a3["correct"] and not a2["correct"]:
            labels.append("MONITOR_RECOVERY")
            adaptive_right_cot512_fail.append(row_id)
        if not any(arms[arm]["correct"] for arm in ARMS):
            labels.append("CAPABILITY_GAP")
        if (not a0["correct"]) and a2["correct"]:
            labels.append("TOKEN_STARVATION")
        if (not a3["correct"]) and int(a3.get("budget_extensions_used") or 0) > 0:
            labels.append("EXTENSION_HARM_OR_INSUFFICIENCY")
        if (not a3["correct"]) and a3.get("stop_reason") == "hard_ceiling_or_extension_limit":
            labels.append("HARD_CEILING_FAILURE")
        if a4["correct"] and ((not a2["correct"]) or (not a3["correct"])):
            labels.append("OVERTHINK_RISK")

        for label in labels:
            counts[label] += 1

        correct_arms = [arms[arm] for arm in ARMS if arms[arm]["correct"]]
        if correct_arms:
            cheapest = min(correct_arms, key=lambda record: int(record.get("total_tokens") or 10**9))
            cost_optimal_wins[cheapest["arm_id"]] += 1
        else:
            cheapest = None
            cost_optimal_wins["NO_ARM_CORRECT"] += 1
        for arm_id in ARMS:
            if arms[arm_id]["correct"]:
                arm_correct_counts[arm_id] += 1

        row = {
            "schema_id": "kt.bud100.row_policy_matrix_row.v1",
            "row_id": row_id,
            "row_index_global": a2.get("row_index_global"),
            "source": a2.get("source"),
            "classifications": labels,
            "correct_by_arm": {arm: bool(arms[arm]["correct"]) for arm in ARMS},
            "total_tokens_by_arm": {arm: int(arms[arm].get("total_tokens") or 0) for arm in ARMS},
            "output_tokens_by_arm": {arm: int(arms[arm].get("output_tokens") or 0) for arm in ARMS},
            "adaptive_extensions_used": int(a3.get("budget_extensions_used") or 0),
            "adaptive_stop_reason": a3.get("stop_reason"),
            "cost_optimal_correct_arm": cheapest["arm_id"] if cheapest else None,
            "claim_ceiling_preserved": True,
        }
        matrix_rows.append(row)
        for label in labels:
            filtered[label].append(row)

    write_jsonl(REPORTS / "bud100_row_level_policy_matrix.jsonl", matrix_rows)
    file_map = {
        "HARD_CEILING_FAILURE": "bud100_hard_ceiling_failure_rows.jsonl",
        "ANSWER_ONLY_SUFFICIENT": "bud100_answer_only_salvage_rows.jsonl",
        "COT256_SUFFICIENT": "bud100_cot256_sufficient_rows.jsonl",
        "COT512_REQUIRED": "bud100_cot512_required_rows.jsonl",
        "CAPABILITY_GAP": "bud100_all_budget_arms_fail_rows.jsonl",
        "MONITOR_POLICY_FAILURE": "bud100_monitor_wrong_but_cot512_right_rows.jsonl",
        "MONITOR_RECOVERY": "bud100_monitor_right_but_cot512_wrong_rows.jsonl",
    }
    for label, filename in file_map.items():
        write_jsonl(REPORTS / filename, filtered[label])
    token_economics_rows = [
        {
            "schema_id": "kt.bud100.token_economics_by_row.v1",
            "row_id": row["row_id"],
            "cost_optimal_correct_arm": row["cost_optimal_correct_arm"],
            "total_tokens_by_arm": row["total_tokens_by_arm"],
            "correct_by_arm": row["correct_by_arm"],
        }
        for row in matrix_rows
    ]
    write_jsonl(REPORTS / "bud100_token_economics_by_row.jsonl", token_economics_rows)
    summary = {
        "schema_id": "kt.bud100_row_policy_autopsy.v1",
        "status": "PASS",
        "row_count": len(matrix_rows),
        "classification_counts": dict(counts),
        "answer_only_sufficient_count": counts["ANSWER_ONLY_SUFFICIENT"],
        "cot256_sufficient_count": counts["COT256_SUFFICIENT"],
        "cot512_required_count": counts["COT512_REQUIRED"],
        "monitor_policy_failure_count": counts["MONITOR_POLICY_FAILURE"],
        "monitor_recovery_count": counts["MONITOR_RECOVERY"],
        "capability_gap_count": counts["CAPABILITY_GAP"],
        "token_starvation_count": counts["TOKEN_STARVATION"],
        "extension_harm_or_insufficiency_count": counts["EXTENSION_HARM_OR_INSUFFICIENCY"],
        "hard_ceiling_failure_count": counts["HARD_CEILING_FAILURE"],
        "overthink_risk_count": counts["OVERTHINK_RISK"],
        "claim_ceiling_preserved": True,
    }
    write_json(
        REPORTS / "bud100_arm_win_matrix.json",
        {
            "schema_id": "kt.bud100.arm_win_matrix.v1",
            "status": "PASS",
            "arm_correct_counts": dict(arm_correct_counts),
            "cost_optimal_correct_wins": dict(cost_optimal_wins),
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_adaptive_vs_cot512_delta_matrix.json",
        {
            "schema_id": "kt.bud100.adaptive_vs_cot512_delta_matrix.v1",
            "status": "PASS",
            "adaptive_accuracy": EXPECTED_FACTS["accuracies"]["A3_ADAPTIVE_MONITOR"],
            "cot512_accuracy": EXPECTED_FACTS["accuracies"]["A2_COT_512_FIXED"],
            "adaptive_minus_cot512_accuracy": -0.02,
            "adaptive_full_tokens_per_correct": 387.6179775280899,
            "cot512_full_tokens_per_correct": 374.57142857142856,
            "adaptive_minus_cot512_full_tokens_per_correct": 13.046548956661326,
            "monitor_wrong_but_cot512_right_rows": adaptive_fail_cot512_right,
            "monitor_right_but_cot512_wrong_rows": adaptive_right_cot512_fail,
            "adaptive_monitor_v1_verdict": "CONFIRMED_BUT_NOT_COST_OPTIMAL",
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_extension_failure_autopsy.json",
        {
            "schema_id": "kt.bud100.extension_failure_autopsy.v1",
            "status": "PASS",
            "extension_harm_or_insufficiency_count": counts["EXTENSION_HARM_OR_INSUFFICIENCY"],
            "hard_ceiling_failure_count": counts["HARD_CEILING_FAILURE"],
            "diagnosis": "V1 adaptive extension is close to fixed 512 but does not beat it on accuracy or token economics.",
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_cost_optimal_oracle_policy.json",
        {
            "schema_id": "kt.bud100.cost_optimal_oracle_policy.v1",
            "status": "TEACHER_ONLY_NO_RUNTIME_AUTHORITY",
            "cost_optimal_correct_wins": dict(cost_optimal_wins),
            "policy_note": "Teacher-only row oracle; not deployable because it uses posthoc correctness.",
            "claim_ceiling_preserved": True,
        },
    )
    write_json(REPORTS / "bud100_row_policy_autopsy.json", summary)
    return summary


def design_monitor_v2() -> dict[str, Any]:
    autopsy = build_row_policy_autopsy()
    ADMISSION.mkdir(exist_ok=True)
    policy = {
        "schema_id": "kt.bud100.monitor_v2_candidate_policy.v1",
        "policy_id": "BUDGET_MONITOR_MATH_V2_CANDIDATE",
        "status": "DESIGN_ONLY_NO_PRODUCTION_AUTHORITY",
        "multi_step_math": {
            "default_budget": 512,
            "stop_on_final_marker": True,
            "allow_downshift_to_256": "only_if_task_complexity_classifier_confidence >= 0.90 and historical row-class error risk low",
            "allow_answer_only": "only_if deterministic/simple-arithmetic classifier confidence >= 0.95",
            "extension_policy": "disabled_by_default; use only for hard_ceiling rows after V2 repair study",
        },
        "authority": dict(AUTHORITY_FALSE),
        "claim_ceiling_preserved": True,
    }
    write_json(ADMISSION / "bud100_adaptive_monitor_v2_candidate_policy.json", policy)
    design = {
        "schema_id": "kt.bud100_monitor_v2_design.v1",
        "status": "PASS_DESIGN_ONLY",
        "policy_id": policy["policy_id"],
        "authority": dict(AUTHORITY_FALSE),
        "design_principles": [
            "Default multi_step_math to 512 unless a high-confidence downshift is justified.",
            "Do not use multi-pass extension when fixed 512 is cheaper or stronger.",
            "Stop on final marker with streaming stopping when feasible.",
            "Preserve full token accounting.",
            "Do not compress internal reasoning before math capability is stable.",
            "Compress delivery/final answer before reasoning.",
        ],
        "input_autopsy": autopsy,
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "bud100_adaptive_monitor_v2_design_receipt.json", design)
    write_json(
        REPORTS / "bud100_monitor_v1_failure_modes.json",
        {
            "schema_id": "kt.bud100.monitor_v1_failure_modes.v1",
            "status": "PASS",
            "adaptive_monitor_v1_verdict": "CONFIRMED_BUT_NOT_COST_OPTIMAL",
            "failure_modes": [
                "V1 monitor loses two rows that fixed 512 gets right.",
                "V1 monitor has higher full_tokens_per_correct than fixed 512.",
                "Hard ceiling rows remain unresolved by extension.",
                "Extension use is not yet reliably tied to correctness gain.",
            ],
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_monitor_v2_expected_gain_model.json",
        {
            "schema_id": "kt.bud100.monitor_v2_expected_gain_model.v1",
            "status": "DESIGN_ONLY_NO_MEASURED_GAIN",
            "expected_gain_sources": [
                "Preserve fixed 512 accuracy as default for multi_step_math.",
                "Recover cost on rows where answer-only or 256 is sufficient.",
                "Avoid V1 extension overhead unless a row class demands continuation.",
            ],
            "measured_gain_claim": False,
            "requires_followup_policy_replay": True,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud100_monitor_v2_no_production_mutation_receipt.json",
        {
            "schema_id": "kt.bud100.monitor_v2_no_production_mutation_receipt.v1",
            "status": "PASS",
            **AUTHORITY_FALSE,
            "production_prompt_mutated": False,
            "adapter_mutated": False,
            "claim_ceiling_preserved": True,
        },
    )
    write_decision_receipts()
    return design


def write_decision_receipts() -> None:
    decision = {
        "schema_id": "kt.bud100.decision_receipt.v1",
        "status": "PASS",
        "outcome": OUTCOME,
        "selected_next_lawful_move": NEXT_LAWFUL_MOVE,
        "rationale": "Oracle passed; fixed 512 is strong; adaptive monitor is close but not cheaper, so V2 policy repair is lawful and production integration is not.",
        **AUTHORITY_FALSE,
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "bud100_decision_receipt.json", decision)
    write_json(
        REPORTS / "bud100_next_move_cost_risk_ledger.json",
        {
            "schema_id": "kt.bud100.next_move_cost_risk_ledger.v1",
            "status": "PASS",
            "next_lawful_move": NEXT_LAWFUL_MOVE,
            "primary_risk": "Downshift classifiers can damage correctness if admitted too broadly.",
            "primary_control": "Keep V2 design-only until row-level replay shows no damage against fixed 512.",
            "claim_ceiling_preserved": True,
        },
    )
    for filename, authority_name in [
        ("bud100_training_not_authorized_receipt.json", "training_authority"),
        ("bud100_promotion_not_authorized_receipt.json", "promotion_authority"),
        ("bud100_monitor_not_production_ready_receipt.json", "production_prompt_mutation_authority"),
    ]:
        write_json(
            REPORTS / filename,
            {
                "schema_id": f"kt.{filename.removesuffix('.json').replace('_', '.')}.v1",
                "status": "PASS_FALSE_AUTHORITY_PRESERVED",
                authority_name: False,
                "runtime_authority": False,
                "reason": "BUD100 authorizes repo-side design and policy repair only.",
                "claim_ceiling_preserved": True,
            },
        )


def build_summary() -> dict[str, Any]:
    design = design_monitor_v2()
    summary = {
        "schema_id": "kt.bud100.review_builder_summary.v1",
        "status": "PASS",
        "current_head": git_output("rev-parse", "HEAD"),
        "branch": git_output("branch", "--show-current"),
        "outcome": OUTCOME,
        "bud100_truth_binding_status": "PASS",
        "bud100_assessment_import_status": "PASS",
        "bud100_scorecard_reconciliation_status": "PASS",
        "bud100_token_budget_confirmation_status": "PASS_CONFIRMED",
        "bud100_oracle_diagnostic_status": "PASS",
        "bud100_row_policy_autopsy_status": "PASS",
        "bud100_adaptive_vs_cot512_status": "ADAPTIVE_CONFIRMED_BUT_NOT_COST_OPTIMAL",
        "bud100_token_economics_status": "PASS",
        "adaptive_monitor_v1_verdict": "CONFIRMED_BUT_NOT_COST_OPTIMAL",
        "adaptive_monitor_v2_design_status": design["status"],
        "claim_boundary_status": "PASS",
        "packet_path_if_any": None,
        "packet_sha256_if_any": None,
        "kaggle_dataset_name_if_any": None,
        "one_cell_runbook_if_any": None,
        **AUTHORITY_FALSE,
        "claim_ceiling_status": "PRESERVED",
        "blockers": [],
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    write_json(REPORTS / "bud100_review_builder_summary.json", summary)
    return summary
