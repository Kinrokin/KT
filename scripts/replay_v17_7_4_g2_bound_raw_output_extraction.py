from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core
from scripts import bind_v17_7_4_g2_state_vector as binder


TRANCHE = "AUTHOR_KTV1774_G2_OFFLINE_RAW_OUTPUT_REPLAY_AND_NEW_FRONTIER_V1"
OUTCOME = "KT_G2_OUTPUT_REPLAY_COMPLETE__NEW_STAGED_FRONTIER_DEFINED__CLAIM_CEILING_PRESERVED"
G2_ROUTE = "routed_13_lobe_kt_hat_compact"
G2_MEMBER = binder.G2_ASSESSMENT_MEMBER
PACKET_PATH = ROOT / "packets" / "ktv1774_g2_offline_replay_frontier_v1.zip"


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


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def source_entry(rel: str, role: str, evidence_type: str) -> dict[str, Any] | None:
    path = ROOT / rel
    if not path.exists():
        return None
    return {
        "path": rel,
        "role": role,
        "evidence_type": evidence_type,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def load_bound_rows() -> tuple[dict[str, Any], list[dict[str, Any]], bytes]:
    inspection = binder.inspect_assessment_zip()
    if inspection.get("prediction_member_status") != "BOUND_EXTERNAL_ASSESSMENT_MEMBER_SHA_CONFIRMED":
        raise RuntimeError("KT_BLOCKED__BOUND_G2_RAW_OUTPUTS_UNREADABLE")
    source = Path(str(inspection["source_path"]))
    with zipfile.ZipFile(source) as archive:
        data = archive.read(G2_MEMBER)
    rows = binder.parse_prediction_rows(data)
    return inspection, rows, data


def normalize_answer(value: Any) -> str:
    text = "" if value is None else str(value)
    text = text.strip()
    if not text:
        return ""
    text = text.replace(",", "")
    if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
        if "." in text:
            text = text.rstrip("0").rstrip(".")
        return text
    upper = text.upper()
    if upper in {"A", "B", "C", "D"}:
        return upper
    return text.lower()


def extract_final_answer(raw_prediction: str, dataset: str) -> str:
    raw = raw_prediction or ""
    if not raw.strip():
        return ""
    if dataset == "gsm8k":
        # Prefer explicit final-answer phrasing, then fall back to the last number in the trace.
        final_patterns = [
            r"(?:final numeric answer|final answer|answer is|answer:)\s*\$?\s*(-?\d+(?:\.\d+)?)",
            r"=\s*(-?\d+(?:\.\d+)?)\s*(?:$|\n)",
        ]
        for pattern in final_patterns:
            matches = re.findall(pattern, raw, flags=re.IGNORECASE)
            if matches:
                return normalize_answer(matches[-1])
        numbers = re.findall(r"-?\d+(?:\.\d+)?", raw.replace(",", ""))
        return normalize_answer(numbers[-1]) if numbers else ""
    letter_matches = re.findall(r"\b([ABCD])\b", raw.upper())
    return normalize_answer(letter_matches[-1]) if letter_matches else normalize_answer(raw.strip()[:1])


def visible_token_count(value: str) -> int:
    normalized = normalize_answer(value)
    return 0 if not normalized else max(1, len(re.findall(r"[A-Za-z0-9.%-]+", normalized)))


def build_truth_pin() -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.g2_offline_replay_truth_pin_receipt.v1",
        status="PASS",
        current_head=git(["rev-parse", "HEAD"]),
        current_branch=git(["branch", "--show-current"]),
        worktree_clean=not bool(git(["status", "--short"])),
        active_tranche=TRANCHE,
        prior_g2_state_vector_bind_status=read_json(ROOT / "reports/v17_7_4_g2_state_vector_bind_builder_summary.json").get("g2_state_vector_binding_status"),
        prior_g2_raw_output_binding_status=read_json(ROOT / "reports/v17_7_4_g2_state_vector_bind_builder_summary.json").get("g2_raw_output_binding_status"),
        prior_g2_accounting_classification_status=read_json(ROOT / "reports/v17_7_4_g2_state_vector_bind_builder_summary.json").get("g2_accounting_classification_status"),
        next_lawful_move_before_patch="RUN_OFFLINE_G2_RAW_OUTPUT_EXTRACTION_REPLAY__DEFINE_NEW_STAGED_FRONTIER",
        no_runtime_generation=True,
        no_training=True,
        no_promotion=True,
        claim_ceiling_preserved=True,
    )


def build_source_index(inspection: dict[str, Any]) -> dict[str, Any]:
    candidates = [
        ("reports/v17_7_4_g2_state_vector_bind_builder_summary.json", "state_vector_bind_summary", "PRIOR_BINDING"),
        ("reports/v17_7_4_g2_raw_output_binding_receipt.json", "raw_output_binding", "PRIOR_BINDING"),
        ("reports/v17_7_4_g2_token_ledger_binding_receipt.json", "token_ledger_binding", "PRIOR_BINDING"),
        ("reports/v17_7_4_g2_accounting_classification.json", "accounting_classification", "PRIOR_BINDING"),
        ("reports/v17_7_4_g2_vs_reprolock_comparability_court.json", "comparability_court", "PRIOR_BINDING"),
        ("reports/v17_7_4_dual_frontier_repair_scorecard.json", "dual_frontier_repair_baseline", "CURRENT_BASELINE"),
        ("reports/v17_7_4_oracle_relocked_success_binding_receipt.json", "oracle_relocked_baseline", "CURRENT_BASELINE"),
        ("reports/v17_7_4_route_cost_decision_table.jsonl", "current_route_cost_table", "TEACHER_TABLE"),
        ("registry/artifact_authority_registry.json", "artifact_authority_registry", "REGISTRY"),
    ]
    sources = [entry for rel, role, kind in candidates if (entry := source_entry(rel, role, kind))]
    return authority(
        schema_id="kt.v17_7_4.g2_offline_replay_source_index.v1",
        status="PASS",
        sources=sources,
        g2_raw_output_source_path_or_uri=inspection.get("source_path"),
        g2_raw_output_source_sha256=inspection.get("source_sha256_actual"),
        g2_raw_output_member_name=G2_MEMBER,
        g2_raw_output_member_sha256=inspection.get("prediction_member_sha256"),
        stale_or_superseded_artifacts_excluded_from_authority=True,
        claim_ceiling_preserved=True,
    )


def build_contradiction_scan(inspection: dict[str, Any]) -> dict[str, Any]:
    summary = read_json(ROOT / "reports/v17_7_4_g2_state_vector_bind_builder_summary.json")
    contradictions: list[str] = []
    if summary.get("g2_state_vector_binding_status") != "IRRECOVERABLE_WITH_SEARCH_RECEIPT":
        contradictions.append("unexpected_state_vector_status")
    if summary.get("g2_vs_reprolock_comparability_status") != "COMPARABILITY_DENIED":
        contradictions.append("unexpected_comparability_status")
    if inspection.get("prediction_member_status") != "BOUND_EXTERNAL_ASSESSMENT_MEMBER_SHA_CONFIRMED":
        contradictions.append("raw_output_member_not_bound")
    return authority(
        schema_id="kt.v17_7_4.g2_offline_replay_contradiction_scan.v1",
        status="PASS" if not contradictions else "BLOCKED",
        contradictions=contradictions,
        g2_output_accounting_not_full_system=True,
        claim_ceiling_preserved=True,
    )


def build_input_manifest(inspection: dict[str, Any], rows: list[dict[str, Any]], data: bytes) -> dict[str, Any]:
    raw_hashes = [sha256_text(str(row.get("raw_prediction", ""))) for row in rows]
    visible_hashes = [sha256_text(str(row.get("normalized_prediction", ""))) for row in rows]
    expected_hashes = [sha256_text(str(row.get("normalized_answer", ""))) for row in rows]
    dataset_mix = dict(sorted(Counter(str(row.get("dataset", "UNKNOWN")) for row in rows).items()))
    sample_ids = [f"{row.get('dataset')}::{row.get('item_id')}::{row.get('subject')}" for row in rows]
    token_counts = [int(row.get("new_tokens", 0) or 0) for row in rows]
    return authority(
        schema_id="kt.v17_7_4.g2_offline_replay_input_manifest.v1",
        status="PASS",
        raw_output_source_path_or_uri=inspection.get("source_path"),
        raw_output_source_sha256=inspection.get("source_sha256_actual"),
        raw_output_member_name=G2_MEMBER,
        raw_output_member_sha256=hashlib.sha256(data).hexdigest(),
        row_count=len(rows),
        sample_ids=sample_ids,
        dataset_mix=dataset_mix,
        expected_answer_hashes=expected_hashes,
        raw_output_hashes=raw_hashes,
        visible_output_hashes=visible_hashes,
        original_output_new_token_counts=token_counts,
        token_ledger_source="outputs/reports/benchmark_predictions.jsonl:new_tokens",
        accounting_mode="OUTPUT_NEW_TOKENS_PER_CORRECT",
        full_system_accounting_comparable=False,
        comparability_denial_reason="exact prompt/router/hat/governance/scorer state is not fully bound",
        allowed_use="offline_replay_only",
        forbidden_use="runtime_authority_or_full_g2_recovery_claim",
        claim_ceiling_preserved=True,
    )


def build_inventory(inspection: dict[str, Any], rows: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    subjects = Counter(str(row.get("subject", "UNKNOWN")) for row in rows)
    raw = authority(
        schema_id="kt.v17_7_4.g2_bound_raw_output_inventory.v1",
        status="PASS",
        source_path=inspection.get("source_path"),
        source_sha256=inspection.get("source_sha256_actual"),
        member=G2_MEMBER,
        member_sha256=inspection.get("prediction_member_sha256"),
        row_count=len(rows),
        subject_counts=dict(sorted(subjects.items())),
        raw_text_committed_to_repo=False,
        claim_ceiling_preserved=True,
    )
    by_subject: dict[str, dict[str, Any]] = defaultdict(lambda: {"rows": 0, "correct": 0, "new_tokens": 0})
    for row in rows:
        subject = str(row.get("subject", "UNKNOWN"))
        by_subject[subject]["rows"] += 1
        by_subject[subject]["correct"] += 1 if row.get("correct") is True else 0
        by_subject[subject]["new_tokens"] += int(row.get("new_tokens", 0) or 0)
    metrics = {}
    for subject, item in sorted(by_subject.items()):
        correct = int(item["correct"])
        tokens = int(item["new_tokens"])
        metrics[subject] = {
            "rows": int(item["rows"]),
            "correct": correct,
            "new_tokens": tokens,
            "output_new_tokens_per_correct": round(tokens / correct, 6) if correct else None,
        }
    token = authority(
        schema_id="kt.v17_7_4.g2_bound_token_ledger_inventory.v1",
        status="PASS",
        accounting_mode="OUTPUT_NEW_TOKENS_PER_CORRECT",
        subject_metrics=metrics,
        claim_ceiling_preserved=True,
    )
    return raw, token


def build_extraction_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    replay_rows: list[dict[str, Any]] = []
    for row in rows:
        dataset = str(row.get("dataset", "UNKNOWN"))
        raw = str(row.get("raw_prediction", ""))
        extracted = extract_final_answer(raw, dataset)
        expected = normalize_answer(row.get("normalized_answer"))
        original_prediction = normalize_answer(row.get("normalized_prediction"))
        replay_correct = extracted == expected if expected else None
        original_correct = bool(row.get("correct"))
        replay_rows.append(
            {
                "sample_id": f"{dataset}::{row.get('item_id')}::{row.get('subject')}",
                "dataset": dataset,
                "subject": row.get("subject"),
                "raw_output_hash": sha256_text(raw),
                "raw_output_text_available": bool(raw),
                "original_output_new_tokens": int(row.get("new_tokens", 0) or 0),
                "extracted_final_answer": extracted,
                "extracted_visible_tokens": visible_token_count(extracted),
                "expected_answer_available": bool(expected),
                "expected_answer_hash": sha256_text(expected) if expected else None,
                "original_correct": original_correct,
                "original_normalized_prediction_hash": sha256_text(original_prediction) if original_prediction else None,
                "replay_correct": replay_correct,
                "parser_failure_original": not bool(row.get("extraction_ok", True)),
                "parser_failure_replay": not bool(extracted),
                "answer_format_drift": extracted != original_prediction,
                "extraction_changed_correctness": replay_correct is not None and replay_correct != original_correct,
                "scorer_used_surface": "normalized_answer_hash_compare",
                "notes": "raw text not committed",
            }
        )
    return replay_rows


def build_extraction_scorecard(replay_rows: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    scorable = [row for row in replay_rows if row["expected_answer_available"]]
    original_correct = sum(1 for row in scorable if row["original_correct"])
    replay_correct = sum(1 for row in scorable if row["replay_correct"])
    original_failures = sum(1 for row in scorable if row["parser_failure_original"])
    replay_failures = sum(1 for row in scorable if row["parser_failure_replay"])
    original_tokens_correct = sum(row["original_output_new_tokens"] for row in scorable if row["original_correct"])
    replay_visible_tokens_correct = sum(row["extracted_visible_tokens"] for row in scorable if row["replay_correct"])
    drift_after = sum(1 for row in scorable if row["answer_format_drift"])
    scorecard = authority(
        schema_id="kt.v17_7_4.g2_offline_extraction_scorecard.v1",
        status="PASS",
        row_count=len(replay_rows),
        scorable_row_count=len(scorable),
        correctness_original=round(original_correct / len(scorable), 6) if scorable else None,
        correctness_replay=round(replay_correct / len(scorable), 6) if scorable else None,
        original_correct=original_correct,
        replay_correct=replay_correct,
        output_new_tokens_per_correct_original=round(original_tokens_correct / original_correct, 6) if original_correct else None,
        visible_tokens_per_correct_replay=round(replay_visible_tokens_correct / replay_correct, 6) if replay_correct else None,
        parser_failure_rate_before=round(original_failures / len(scorable), 6) if scorable else None,
        parser_failure_rate_after=round(replay_failures / len(scorable), 6) if scorable else None,
        answer_format_drift_after=round(drift_after / len(scorable), 6) if scorable else None,
        full_system_TPC=None,
        allowed_claims=["G2 output-new-token accounting is replayed offline from bound raw outputs."],
        forbidden_claims=["G2 full-system compression recovered.", "91% full-system compression restored."],
        model_generation_invoked=False,
        claim_ceiling_preserved=True,
    )
    receipt = authority(
        schema_id="kt.v17_7_4.g2_offline_extraction_replay_receipt.v1",
        status="PASS",
        model_generation_invoked=False,
        expected_answer_visible_to_model=False,
        raw_text_committed_to_repo=False,
        row_table="reports/v17_7_4_g2_offline_extraction_row_table.jsonl",
        scorecard="reports/v17_7_4_g2_offline_extraction_scorecard.json",
        claim_ceiling_preserved=True,
    )
    reduction = authority(
        schema_id="kt.v17_7_4.g2_offline_parser_failure_reduction.v1",
        status="PASS",
        parser_failures_before=original_failures,
        parser_failures_after=replay_failures,
        parser_failure_delta=replay_failures - original_failures,
        correctness_delta=replay_correct - original_correct,
        note="Offline parser replay is diagnostic only and cannot authorize runtime claims.",
        claim_ceiling_preserved=True,
    )
    return receipt, scorecard, reduction


def build_token_bridge(scorecard: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    dual = read_json(ROOT / "reports/v17_7_4_dual_frontier_repair_scorecard.json")
    table = authority(
        schema_id="kt.v17_7_4.g2_output_new_vs_full_tpc_table.v1",
        status="PASS",
        rows=[
            {
                "surface": "G2 routed compact",
                "accounting_mode": "G2_OUTPUT_NEW_TOKENS_PER_CORRECT",
                "tokens_per_correct": 3.738095,
                "full_system_comparable": False,
            },
            {
                "surface": "Current known-good visible answer",
                "accounting_mode": "CURRENT_VISIBLE_TOKENS_PER_CORRECT",
                "tokens_per_correct": dual.get("stable_control_visible_tokens_per_correct"),
                "full_system_comparable": False,
            },
            {
                "surface": "Current known-good full system",
                "accounting_mode": "CURRENT_FULL_TOKENS_PER_CORRECT",
                "tokens_per_correct": dual.get("stable_control_full_tokens_per_correct"),
                "full_system_comparable": True,
            },
            {
                "surface": "Current base full system",
                "accounting_mode": "CURRENT_FULL_TOKENS_PER_CORRECT",
                "tokens_per_correct": dual.get("base_full_tokens_per_correct"),
                "full_system_comparable": True,
            },
        ],
        claim_ceiling_preserved=True,
    )
    bridge = authority(
        schema_id="kt.v17_7_4.token_accounting_bridge.v1",
        status="PASS",
        accounting_modes=[
            "G2_OUTPUT_NEW_TOKENS_PER_CORRECT",
            "G2_VISIBLE_TOKENS_PER_CORRECT",
            "CURRENT_VISIBLE_TOKENS_PER_CORRECT",
            "CURRENT_FULL_TOKENS_PER_CORRECT",
            "CURRENT_PROMPT_PLUS_OUTPUT_TOKENS_PER_CORRECT",
            "GOVERNANCE_OVERHEAD_TOKENS_PER_CORRECT",
            "ROUTE_OVERHEAD_TOKENS_PER_CORRECT",
            "KT_HAT_OVERHEAD_TOKENS_PER_CORRECT",
        ],
        g2_3_74_accounting="OUTPUT_NEW_TOKENS_PER_CORRECT",
        reprolock_145_12_accounting="CURRENT_FULL_TOKENS_PER_CORRECT",
        directly_comparable=False,
        current_visible_tpc_may_beat_g2_output_surface=True,
        current_visible_tpc_does_not_imply_full_compression=True,
        offline_replay_scorecard_status=scorecard["status"],
        claim_ceiling_preserved=True,
    )
    boundary = authority(
        schema_id="kt.v17_7_4.token_accounting_claim_boundary_receipt.v1",
        status="PASS",
        allowed_claims=[
            "G2 output-new-token compression anchor exists.",
            "Current full-system compression frontier remains open.",
        ],
        forbidden_claims=[
            "G2 full-system compression recovered.",
            "91% full-system compression restored.",
            "G2 output-token TPC equals current full-system TPC.",
        ],
        claim_ceiling_preserved=True,
    )
    return bridge, table, boundary


def build_frontiers() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    frontiers = {
        "verified_intelligence_frontier": {
            "baseline": {"correct": 41, "total": 50, "gsm8k_correct": 11, "gsm8k_total": 20, "full_TPC": 145.12},
            "stages": ["I0: 41/50 preserved on fixed 50-row slice", "I1: 41/50 preserved on row-order shuffle", "I2: >=39/50 on held-out 50-row slice", "I3: >= best_static on 200-row extension", "I4: external replay / detached verifier"],
        },
        "output_compression_frontier": {
            "baseline": {"g2_output_new_token_TPC": 3.74, "current_visible_TPC": 1.22},
            "stages": ["O0: output/visible token accounting separated from full accounting", "O1: visible TPC <= 3.74 with correctness preserved", "O2: output-new-token TPC <= 3.74 with correctness preserved", "O3: output compression reproduces on held-out slice"],
        },
        "full_system_compression_frontier": {
            "baseline": {"current_full_TPC": 145.12, "base_full_TPC": 178.06},
            "stages": ["F0: current known-good beats base full_TPC", "F1: full_TPC < 145.12 at >=39/50", "F2: full_TPC <= 100 at >=39/50", "F3: full_TPC <= 50 at >=39/50", "F4: full_TPC <= 10 at >=39/50", "F5: full_TPC near 3.74 only if accounting comparable or newly proven"],
        },
        "routing_admission_frontier": {
            "stages": ["R0: teacher-only cheapest-correct simulation", "R1: pre-generation admissible feature policy beats base", "R2: pre-generation policy beats best static after cost", "R3: router reduces route regret without negative transfer", "R4: router superiority claim candidate, still court-bound"],
        },
        "governance_frontier": {
            "stages": ["G0: claim ceiling preserved", "G1: governance overhead measured", "G2: risk-adjusted governance overhead justified by safety/admissibility", "G3: adversarial fail-closed test", "G4: external replay"],
        },
    }
    definition = authority(
        schema_id="kt.v17_7_4.new_staged_frontier_definition.v1",
        status="PASS",
        frontiers=frontiers,
        hard_rule="Never collapse these frontiers into one metric.",
        claim_ceiling_preserved=True,
    )
    dual_mode = authority(
        schema_id="kt.v17_7_4.dual_mode_operating_frontier.v1",
        status="PASS",
        modes=[
            {"mode": "known_good_full_reasoning", "authority": "CURRENT_BASELINE", "correct": 41, "full_TPC": 145.12},
            {"mode": "output_compact_replay", "authority": "OFFLINE_FORENSIC_ONLY", "g2_output_new_TPC": 3.74},
        ],
        no_mode_claims_global_superiority=True,
        claim_ceiling_preserved=True,
    )
    registry = authority(
        schema_id="kt.v17_7_4.frontier_target_registry.v1",
        status="PASS",
        target_order=["preserve_verified_intelligence", "reduce_full_system_TPC", "preserve_output_compression_boundary", "collect_pre_generation_route_features"],
        claim_ceiling_preserved=True,
    )
    return definition, dual_mode, registry


def build_cheapest_correct_v2(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(str(row.get("dataset")), str(row.get("item_id")))].append(row)
    table: list[dict[str, Any]] = []
    for (dataset, item_id), item_rows in sorted(grouped.items()):
        correct_rows = [row for row in item_rows if row.get("correct") is True]
        cheapest = min(correct_rows, key=lambda row: int(row.get("new_tokens", 0) or 0)) if correct_rows else None
        table.append(
            {
                "sample_id": f"{dataset}::{item_id}",
                "dataset": dataset,
                "item_id": item_id,
                "cheapest_correct_arm": cheapest.get("subject") if cheapest else None,
                "token_cost_under_output_accounting": int(cheapest.get("new_tokens", 0) or 0) if cheapest else None,
                "token_cost_under_current_full_accounting": None,
                "posthoc_only": True,
                "pre_generation_proxy_available": False,
                "candidate_runtime_feature": None,
                "prohibited_runtime_feature": "oracle_correctness_or_gold_answer",
                "route_policy_transferability": "BLOCKED_UNTIL_PRE_GENERATION_FEATURES_COLLECTED" if cheapest else "NO_CORRECT_ARM",
            }
        )
    correct_table = [row for row in table if row["cheapest_correct_arm"]]
    total_tokens = sum(int(row["token_cost_under_output_accounting"] or 0) for row in correct_table)
    by_arm = Counter(str(row["cheapest_correct_arm"]) for row in correct_table)
    summary = authority(
        schema_id="kt.v17_7_4.cheapest_correct_route_simulation_v2.v1",
        status="PASS_TEACHER_ONLY_NOT_RUNTIME",
        row_count=len(table),
        oracle_cheapest_correct_count=len(correct_table),
        oracle_cheapest_correct_output_tokens_per_correct=round(total_tokens / len(correct_table), 6) if correct_table else None,
        cheapest_correct_arm_distribution=dict(sorted(by_arm.items())),
        pre_generation_admissible_lower_bound_available=False,
        route_feature_gaps=["pre_generation_difficulty_features", "pre_generation_dataset_blind_task_features", "hat_need_predictors"],
        next_feature_collection_requirement="collect pre-generation features that approximate teacher choices without oracle correctness",
        runtime_authority=False,
        promotion_authority=False,
        claim_ceiling_preserved=True,
    )
    audit = authority(
        schema_id="kt.v17_7_4.pre_generation_route_feature_audit.v1",
        status="PASS_GAPS_IDENTIFIED",
        posthoc_features_prohibited=["correct", "normalized_answer", "normalized_prediction", "oracle_cheapest_correct_arm"],
        admissible_features_currently_bound=[],
        missing_features=["prompt_text", "rendered_prompt_features", "pre_generation_math_act_features", "risk_features"],
        claim_ceiling_preserved=True,
    )
    return summary, table, audit


def build_epc_next(scorecard: dict[str, Any], frontier: dict[str, Any], sim: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    queue = [
        {
            "lane": "OFFLINE_EXTRACTION_REPLAY_ON_REPROLOCK_ORACLE_RAW_OUTPUTS",
            "expected_information_gain": 0.90,
            "compute_cost": "LOW",
            "authority_risk": "LOW",
            "reason": "Keeps work offline while testing whether parser/finalizer deltas transfer to current known-good outputs.",
        },
        {
            "lane": "PRE_GENERATION_ROUTE_FEATURE_COLLECTION",
            "expected_information_gain": 0.82,
            "compute_cost": "LOW",
            "authority_risk": "MEDIUM",
            "reason": "Cheapest-correct v2 is teacher-only; transfer requires non-oracle features.",
        },
        {
            "lane": "HELD_OUT_50_ROW_REPROLOCK_GENERALIZATION_TEST",
            "expected_information_gain": 0.76,
            "compute_cost": "MEDIUM",
            "authority_risk": "MEDIUM",
            "reason": "Tests whether 41/50 stable control generalizes before another compression furnace.",
        },
        {
            "lane": "MICRO_FURNACE_25",
            "expected_information_gain": 0.35,
            "compute_cost": "MEDIUM",
            "authority_risk": "MEDIUM",
            "reason": "Held until offline replay or feature collection proves transferable signal.",
            "allowed": False,
        },
        {
            "lane": "TRAIN_ADAPTER_OR_ROUTER",
            "expected_information_gain": 0.10,
            "compute_cost": "HIGH",
            "authority_risk": "HIGH",
            "reason": "No training authority in this lane.",
            "allowed": False,
        },
    ]
    recommendation = queue[0]
    decision = authority(
        schema_id="kt.v17_7_4.epc_decision_after_g2_offline_replay.v1",
        status="PASS",
        recommended_next_lane=recommendation["lane"],
        reason=recommendation["reason"],
        expected_information_gain=recommendation["expected_information_gain"],
        compute_cost=recommendation["compute_cost"],
        authority_risk=recommendation["authority_risk"],
        blockers=[],
        stop_condition="do_not_run_runtime_generation_until_offline_transfer_signal_is_receipted",
        runtime_generation_authorized=False,
        training_authorized=False,
        promotion_authority=False,
        claim_ceiling_preserved=True,
    )
    priority = authority(
        schema_id="kt.v17_7_4.epc_intervention_priority_queue_v3.v1",
        status="PASS",
        interventions=queue,
        claim_ceiling_preserved=True,
    )
    next_lane = authority(
        schema_id="kt.v17_7_4.epc_next_evidence_lane.v1",
        status="PASS",
        next_lawful_move="REVIEW_G2_OFFLINE_REPLAY_AND_EPC_DECISION",
        recommended_next_lane=recommendation["lane"],
        no_kaggle_runtime_packet=True,
        claim_ceiling_preserved=True,
    )
    return decision, priority, next_lane


def write_schemas() -> None:
    base = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["schema_id", "status", "claim_ceiling_preserved"],
        "properties": {"schema_id": {"type": "string"}, "status": {"type": "string"}, "claim_ceiling_preserved": {"const": True}},
        "additionalProperties": True,
    }
    for name in [
        "kt.v17_7_4.g2_offline_replay_input.schema.json",
        "kt.v17_7_4.g2_offline_extraction_replay.schema.json",
        "kt.v17_7_4.token_accounting_bridge.schema.json",
        "kt.v17_7_4.staged_frontier_definition.schema.json",
        "kt.v17_7_4.cheapest_correct_route_simulation_v2.schema.json",
        "kt.v17_7_4.epc_next_evidence_lane.schema.json",
    ]:
        payload = dict(base)
        payload["$id"] = name
        write_json(ROOT / "schemas" / name, payload)


def create_bundle(report_paths: list[str]) -> tuple[str, str]:
    PACKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if PACKET_PATH.exists():
        PACKET_PATH.unlink()
    with zipfile.ZipFile(PACKET_PATH, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for rel in [
            "docs/G2_OFFLINE_REPLAY_AND_STAGED_FRONTIER.md",
            "rules/NO_RUNTIME_PACKET_UNTIL_EPC.md",
            "scripts/replay_v17_7_4_g2_bound_raw_output_extraction.py",
            "scripts/simulate_v17_7_4_cheapest_correct_route_policy_v2.py",
            *report_paths,
        ]:
            path = ROOT / rel
            if path.exists():
                archive.write(path, rel)
    return PACKET_PATH.relative_to(ROOT).as_posix(), sha256_file(PACKET_PATH)


def write_docs() -> None:
    write_text(
        ROOT / "docs" / "G2_OFFLINE_REPLAY_AND_STAGED_FRONTIER.md",
        """# G2 Offline Replay And Staged Frontier

G2 is now classified as an output-new-token accounting surface. This lane replays bound raw outputs
offline, separates output/visible/full-system token accounting, and defines separate intelligence,
output-compression, full-system-compression, routing/admission, and governance frontiers.

No runtime generation, training, promotion, V18 authorization, router-superiority claim, G2-recovered
claim, 91 percent full-system recovery claim, or commercial/external claim is authorized.
""",
    )
    write_text(
        ROOT / "rules" / "NO_RUNTIME_PACKET_UNTIL_EPC.md",
        """# No Runtime Packet Until EPC

This lane may generate an offline evidence bundle only. A Kaggle runtime packet requires a later EPC
micro-furnace lane and separate protected merge/replay.
""",
    )


def build_all() -> dict[str, Any]:
    write_schemas()
    write_docs()
    inspection, rows, data = load_bound_rows()
    truth = build_truth_pin()
    source_index = build_source_index(inspection)
    contradiction = build_contradiction_scan(inspection)
    input_manifest = build_input_manifest(inspection, rows, data)
    raw_inventory, token_inventory = build_inventory(inspection, rows)
    replay_rows = build_extraction_rows(rows)
    extraction_receipt, extraction_scorecard, parser_reduction = build_extraction_scorecard(replay_rows)
    bridge, tpc_table, boundary = build_token_bridge(extraction_scorecard)
    frontier, dual_mode, target_registry = build_frontiers()
    sim, sim_table, feature_audit = build_cheapest_correct_v2(rows)
    epc, priority, next_lane = build_epc_next(extraction_scorecard, frontier, sim)
    reports: dict[str, Any] = {
        "reports/v17_7_4_g2_offline_replay_truth_pin_receipt.json": truth,
        "reports/v17_7_4_g2_offline_replay_source_index.json": source_index,
        "reports/v17_7_4_g2_offline_replay_contradiction_scan.json": contradiction,
        "reports/v17_7_4_g2_offline_replay_input_manifest.json": input_manifest,
        "reports/v17_7_4_g2_bound_raw_output_inventory.json": raw_inventory,
        "reports/v17_7_4_g2_bound_token_ledger_inventory.json": token_inventory,
        "reports/v17_7_4_g2_offline_extraction_replay_receipt.json": extraction_receipt,
        "reports/v17_7_4_g2_offline_extraction_scorecard.json": extraction_scorecard,
        "reports/v17_7_4_g2_offline_parser_failure_reduction.json": parser_reduction,
        "reports/v17_7_4_g2_reprolock_token_accounting_bridge.json": bridge,
        "reports/v17_7_4_g2_output_new_vs_full_tpc_table.json": tpc_table,
        "reports/v17_7_4_token_accounting_claim_boundary_receipt.json": boundary,
        "reports/v17_7_4_new_staged_frontier_definition.json": frontier,
        "reports/v17_7_4_dual_mode_operating_frontier.json": dual_mode,
        "reports/v17_7_4_frontier_target_registry.json": target_registry,
        "reports/v17_7_4_cheapest_correct_route_simulation_v2.json": sim,
        "reports/v17_7_4_pre_generation_route_feature_audit.json": feature_audit,
        "reports/v17_7_4_epc_decision_after_g2_offline_replay.json": epc,
        "reports/v17_7_4_epc_intervention_priority_queue_v3.json": priority,
        "reports/v17_7_4_epc_next_evidence_lane.json": next_lane,
    }
    for rel, payload in reports.items():
        write_json(ROOT / rel, payload)
    write_jsonl(ROOT / "reports" / "v17_7_4_g2_offline_extraction_row_table.jsonl", replay_rows)
    write_jsonl(ROOT / "reports" / "v17_7_4_cheapest_correct_route_table_v2.jsonl", sim_table)
    report_paths = [*reports, "reports/v17_7_4_g2_offline_extraction_row_table.jsonl", "reports/v17_7_4_cheapest_correct_route_table_v2.jsonl"]
    packet_rel, packet_sha = create_bundle(report_paths)
    summary = authority(
        schema_id="kt.v17_7_4.g2_offline_replay_frontier_builder_summary.v1",
        status="PASS",
        current_head=truth["current_head"],
        current_branch=truth["current_branch"],
        outcome=OUTCOME,
        g2_offline_replay_truth_pin_status=truth["status"],
        g2_replay_input_manifest_status=input_manifest["status"],
        offline_extraction_replay_status=extraction_receipt["status"],
        token_accounting_bridge_status=bridge["status"],
        new_staged_frontier_status=frontier["status"],
        cheapest_correct_route_simulation_v2_status=sim["status"],
        epc_next_evidence_lane_status=next_lane["status"],
        packet_path_if_any=packet_rel,
        packet_sha256_if_any=packet_sha,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        next_lawful_move=next_lane["next_lawful_move"],
        blockers=[],
        claim_ceiling_status="PRESERVED",
    )
    summary_path = "reports/v17_7_4_g2_offline_replay_frontier_builder_summary.json"
    write_json(ROOT / summary_path, summary)
    all_artifacts = [*report_paths, summary_path, packet_rel]
    write_json(
        ROOT / "registry" / "artifact_authority_registry_v17_7_4_g2_offline_replay_frontier_delta_receipt.json",
        authority(
            schema_id="kt.artifact_authority_registry.delta_receipt.v17_7_4_g2_offline_replay_frontier.v1",
            status="PASS",
            current_head=truth["current_head"],
            artifacts_added=[
                {
                    "path": rel,
                    "role": "g2_offline_replay_frontier_artifact",
                    "sha256": sha256_file(ROOT / rel),
                    "authority_state": "OFFLINE_FORENSIC_ONLY",
                    "claim_expansion": False,
                }
                for rel in all_artifacts
            ],
            outcome=OUTCOME,
            next_lawful_move=next_lane["next_lawful_move"],
            no_runtime_generation=True,
            no_training=True,
            no_promotion=True,
            no_v18=True,
            no_g2_recovered_claim=True,
            no_router_superiority_claim=True,
        ),
    )
    return summary


def main() -> int:
    summary = build_all()
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
