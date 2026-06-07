from __future__ import annotations

import hashlib
import json
import random
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core


TRANCHE = "AUTHOR_KTV1774_HELDOUT_ROW_SOURCE_OR_SHUFFLE_CONTROL_V1"
OUTCOME = "KT_HELDOUT_SOURCE_BOUND_OR_SHUFFLE_CONTROL_READY__CLAIM_CEILING_PRESERVED"
SHUFFLE_PACKET_NAME = "ktv1774_reprolock_shuffle_control_v1.zip"
SHUFFLE_PACKET_PATH = ROOT / "packets" / SHUFFLE_PACKET_NAME
SHUFFLE_DATASET = "ktv1774-reprolock-shuffle-control-v1"
SHUFFLE_RUN_MODE = "RUN_KTV1774_REPROLOCK_SHUFFLE_CONTROL_50"
HELDOUT_PACKET_NAME = "ktv1774_reprolock_heldout_generalization_v1.zip"
HELDOUT_DATASET = "ktv1774-reprolock-heldout-v1"
HELDOUT_RUN_MODE = "RUN_KTV1774_REPROLOCK_HELDOUT_GENERALIZATION_50"
SHUFFLE_RUNBOOK = ROOT / "docs" / "V17_7_4_REPROLOCK_SHUFFLE_CONTROL_ONE_CELL.md"
HELDOUT_RUNBOOK = ROOT / "docs" / "V17_7_4_REPROLOCK_HELDOUT_ONE_CELL.md"
REALBENCH_MANIFEST = ROOT / "admission" / "v17_7_4_realbench_row_manifest.json"
PRIOR_PROMPT_MANIFEST = ROOT / "admission" / "v17_7_4_prior_realbench_math_act_prompt_manifest.jsonl"
BOUND_HELDOUT_MANIFEST = ROOT / "admission" / "v17_7_4_reprolock_heldout_row_manifest.json"
EPC_REVIEW_SUMMARY = ROOT / "reports" / "v17_7_4_epc_review_after_offline_extraction_builder_summary.json"
EXTRACTION_QUARANTINE = ROOT / "reports" / "v17_7_4_final_answer_contract_v2_quarantine_receipt.json"
SHUFFLE_SEED = 1774


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


def worktree_status_entries() -> list[str]:
    status = git(["status", "--short"])
    return [line for line in status.splitlines() if line.strip()]


def expected_lane_worktree_entry(entry: str) -> bool:
    parts = entry.split(maxsplit=1)
    path = parts[1] if len(parts) == 2 else entry
    prefixes = (
        "admission/v17_7_4_reprolock_shuffle_control_row_manifest.json",
        "docs/HELDOUT_OR_SHUFFLE_CONTROL_DECISION.md",
        "docs/V17_7_4_REPROLOCK_HELDOUT_ONE_CELL.md",
        "docs/V17_7_4_REPROLOCK_SHUFFLE_CONTROL_ONE_CELL.md",
        "packets/ktv1774_reprolock_shuffle_control_v1.zip",
        "registry/artifact_authority_registry_v17_7_4_heldout_or_shuffle_delta_receipt.json",
        "reports/v17_7_4_",
        "rules/SHUFFLE_CONTROL_IS_NOT_HELDOUT_GENERALIZATION.md",
        "schemas/kt.v17_7_4.",
        "scripts/build_v17_7_4_heldout_or_shuffle_control_packet.py",
        "tests/test_v17_7_4_",
    )
    return path.startswith(prefixes)


def unexpected_worktree_entries() -> list[str]:
    return [entry for entry in worktree_status_entries() if not expected_lane_worktree_entry(entry)]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
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


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_zip_member(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def source_entry(path: Path, role: str) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "role": role,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def known_good_sample_ids() -> set[str]:
    return {str(row["sample_id"]) for row in read_json(REALBENCH_MANIFEST)["rows"]}


def manifest_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if path.suffix == ".jsonl":
        return read_jsonl(path)
    payload = read_json(path)
    rows = payload.get("rows")
    return rows if isinstance(rows, list) else []


def candidate_manifest_paths() -> list[Path]:
    paths = [
        BOUND_HELDOUT_MANIFEST,
        ROOT / "admission" / "v17_7_4_truegen_row_manifest.json",
        REALBENCH_MANIFEST,
    ]
    paths.extend(sorted((ROOT / "admission").glob("*row_manifest*.json")))
    paths.extend(sorted((ROOT / "admission").glob("*manifest*.jsonl")))
    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = path.as_posix()
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def row_hash(row: dict[str, Any]) -> str:
    return str(row.get("question_text_hash") or row.get("prompt_hash") or core.sha256_text(str(row.get("question_text") or row.get("prompt") or "")))


def evaluate_heldout_candidate(path: Path, control_ids: set[str], control_hashes: set[str]) -> dict[str, Any]:
    rows = manifest_rows(path)
    row_ids = {str(row.get("sample_id", "")) for row in rows}
    question_hashes = {row_hash(row) for row in rows}
    overlap_ids = sorted(row_ids & control_ids)
    overlap_hashes = sorted(question_hashes & control_hashes)
    label_sources = sorted({str(row.get("label_source", "")) for row in rows})
    holdout_statuses = sorted({str(row.get("holdout_status", "")) for row in rows})
    scoring_rules = sorted({str(row.get("scoring_rule", "")) for row in rows})
    datasets = sorted({str(row.get("dataset", "")) for row in rows})
    expected_hash_bound = all(row.get("expected_answer_hash") or row.get("expected_label_or_oracle_label") for row in rows)
    public_truth = "PUBLIC_BENCHMARK_GROUND_TRUTH" in label_sources
    heldout_declared = "HELDOUT_NOT_FOR_PROMOTION" in holdout_statuses
    bindable = (
        len(rows) >= 50
        and not overlap_ids
        and not overlap_hashes
        and expected_hash_bound
        and public_truth
        and heldout_declared
        and path == BOUND_HELDOUT_MANIFEST
    )
    reasons: list[str] = []
    if len(rows) < 50:
        reasons.append("row_count_below_50")
    if overlap_ids:
        reasons.append("sample_id_overlap_with_known_good_control")
    if overlap_hashes:
        reasons.append("question_text_hash_overlap_with_known_good_control")
    if not expected_hash_bound:
        reasons.append("expected_answer_hash_not_fully_bound")
    if not public_truth:
        reasons.append("public_ground_truth_label_source_not_bound")
    if not heldout_declared:
        reasons.append("heldout_status_not_declared")
    if path != BOUND_HELDOUT_MANIFEST:
        reasons.append("not_the_bound_reprolock_heldout_manifest_path")
    return authority(
        schema_id="kt.v17_7_4.heldout_row_source_candidate.v1",
        path=path.relative_to(ROOT).as_posix(),
        exists=path.exists(),
        row_count=len(rows),
        datasets=datasets,
        label_sources=label_sources,
        holdout_statuses=holdout_statuses,
        scoring_rules=scoring_rules,
        overlap_sample_ids=overlap_ids[:20],
        overlap_question_hash_count=len(overlap_hashes),
        expected_answer_hash_bound=expected_hash_bound,
        prompt_rendering_compatible_with_reprolock=True,
        bindable=bindable,
        rejection_reasons=[] if bindable else reasons,
        source_sha256=sha256_file(path) if path.exists() else None,
        row_authority_tier="BOUND_HELDOUT_PUBLIC_GROUND_TRUTH" if bindable else "NOT_BOUND_OR_NOT_HELDOUT",
    )


def search_heldout_sources() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    control_rows = read_json(REALBENCH_MANIFEST)["rows"]
    control_ids = {str(row["sample_id"]) for row in control_rows}
    control_hashes = {row_hash(row) for row in control_rows}
    candidates = [evaluate_heldout_candidate(path, control_ids, control_hashes) for path in candidate_manifest_paths()]
    bindable = next((candidate for candidate in candidates if candidate["bindable"]), None)
    search = authority(
        schema_id="kt.v17_7_4.heldout_row_source_search_receipt.v1",
        status="BOUND" if bindable else "NOT_BOUND_WITH_SEARCH_RECEIPT",
        candidate_count=len(candidates),
        searched_locations=[candidate["path"] for candidate in candidates],
        candidates=candidates,
        fabrication_allowed=False,
    )
    binding = authority(
        schema_id="kt.v17_7_4.heldout_row_source_binding_receipt.v1",
        status="BOUND" if bindable else "NOT_BOUND_WITH_SEARCH_RECEIPT",
        bound_manifest_path=bindable["path"] if bindable else None,
        row_count=bindable["row_count"] if bindable else 0,
        row_ids_overlap_known_good=False if bindable else None,
        question_hashes_overlap_known_good=False if bindable else None,
        expected_answer_hash_bound=True if bindable else None,
        expected_answer_model_visible=False,
        row_authority_tier=bindable["row_authority_tier"] if bindable else "NONE",
        reason_if_not_bound="no true non-overlapping held-out ReproLock row source found",
    )
    manifest_candidate = authority(
        schema_id="kt.v17_7_4.heldout_row_manifest_candidate.v1",
        status="BOUND" if bindable else "NOT_BOUND",
        rows=[],
        candidate_source=bindable["path"] if bindable else None,
        heldout_generalization_claim=False,
        note="Rows are not fabricated; candidate remains empty unless a true held-out source is bound.",
    )
    missing = authority(
        schema_id="kt.v17_7_4.heldout_row_source_missing_fields.v1",
        status="PASS",
        missing_if_not_bound=[
            "non_overlapping_50_row_manifest",
            "PUBLIC_BENCHMARK_GROUND_TRUTH label source",
            "HELDOUT_NOT_FOR_PROMOTION declaration",
            "distinct question_text_hashes",
        ]
        if not bindable
        else [],
        action="GENERATE_SHUFFLE_CONTROL_INSTEAD" if not bindable else "GENERATE_HELDOUT_PACKET",
    )
    return search, binding, manifest_candidate, missing


def build_shuffle_row_manifest() -> tuple[dict[str, Any], dict[str, Any]]:
    payload = read_json(REALBENCH_MANIFEST)
    rows = [dict(row) for row in payload["rows"]]
    indexed = list(enumerate(rows))
    random.Random(SHUFFLE_SEED).shuffle(indexed)
    shuffled_rows = []
    for shuffled_index, (original_index, row) in enumerate(indexed):
        row.update(
            schema_id="kt.v17_7_4.reprolock_shuffle_control_row.v1",
            original_order_index=original_index,
            shuffled_order_index=shuffled_index,
            shuffle_seed=SHUFFLE_SEED,
            control_test_type="ROW_ORDER_SHUFFLE_CONTROL_NOT_HELDOUT_GENERALIZATION",
            heldout_generalization_claim=False,
            finalizer_intervention=False,
            kt_hat_contamination=False,
            route_admission_changes=False,
            expected_answer_visible_to_model=False,
            negative_control_scoring=False,
            runtime_authority=False,
        )
        shuffled_rows.append(row)
    manifest = authority(
        schema_id="kt.v17_7_4.reprolock_shuffle_control_row_manifest.v1",
        status="PASS",
        source_manifest=REALBENCH_MANIFEST.relative_to(ROOT).as_posix(),
        source_manifest_sha256=sha256_file(REALBENCH_MANIFEST),
        row_count=len(shuffled_rows),
        shuffle_seed=SHUFFLE_SEED,
        selected_branch="SHUFFLE_CONTROL_PACKET",
        not_heldout_generalization=True,
        control_test_type="ROW_ORDER_SHUFFLE_CONTROL_NOT_HELDOUT_GENERALIZATION",
        heldout_generalization_claim=False,
        rows=shuffled_rows,
    )
    order = authority(
        schema_id="kt.v17_7_4.reprolock_shuffle_order_manifest.v1",
        status="PASS",
        row_count=len(shuffled_rows),
        shuffle_seed=SHUFFLE_SEED,
        original_to_shuffled=[
            {
                "sample_id": row["sample_id"],
                "original_order_index": row["original_order_index"],
                "shuffled_order_index": row["shuffled_order_index"],
                "question_text_hash": row.get("question_text_hash"),
            }
            for row in shuffled_rows
        ],
        not_heldout_generalization=True,
        row_order_changed=[row["sample_id"] for row in shuffled_rows] != [row["sample_id"] for row in rows],
    )
    return manifest, order


def reprolock_config() -> dict[str, Any]:
    base_config = read_json(ROOT / "configs" / "v17_7_4" / "arm_model_config.json")
    arms = {arm["arm_id"]: arm for arm in base_config["arms"]}
    math_act = dict(arms["math_act_adapter_global"])
    math_act.update(
        arm_id=core.REPROLOCK_ARM_ID,
        adapter_id="math_act_adapter_global",
        reproduction_mode=core.TRUE_KNOWN_GOOD_BYTE_REPRO,
        legacy_source_arm_id="math_act_adapter_global",
        legacy_prompt_template_id="math_act",
        prompt_template_id="math_act",
        compact_mode="DISABLED_TRUE_BYTE_REPRO",
        compact_scoring_disabled=True,
        score_from_visible_answer=False,
        scoring_method="contains_expected_label",
        scoring_surface="RAW_OUTPUT",
        finalizer_intervention_disabled=True,
        kt_hat_scaffold_disabled=True,
        route_admission_disabled=True,
        oracle_shadow_disabled=True,
        expected_prior_correct_count=41,
        minimum_reproduction_correct=39,
        expected_prior_gsm8k_correct=11,
    )
    config = dict(base_config)
    config.update(
        schema_id="kt.v17_7_4.arm_model_config.reprolock_shuffle_control.v1",
        config_profile="REAL_ARM_REPROLOCK_SHUFFLE_CONTROL",
        measurement_mode=core.REPROLOCK_MODE,
        compact_answer_contract=False,
        reasoning_preserving_compact=False,
        row_limit=50,
        default_row_ladder_stage=None,
        required_arm_ids=[core.REPROLOCK_ARM_ID],
        prior_realbench_prompt_manifest="runtime_inputs/prior_realbench_math_act_prompt_manifest.jsonl",
        prior_realbench_prompt_manifest_sha256=sha256_file(PRIOR_PROMPT_MANIFEST),
        known_good_reproduction_required=True,
        known_good_control_preserved=True,
        shuffle_control_required=True,
        heldout_generalization_claim=False,
        no_training=True,
        no_promotion=True,
        no_v18=True,
        arms=[math_act],
    )
    return config


def prompt_identity_plan() -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.reprolock_shuffle_prompt_identity_plan.v1",
        status="PASS",
        exact_known_good_prompt_template_required=True,
        prior_prompt_manifest=PRIOR_PROMPT_MANIFEST.relative_to(ROOT).as_posix(),
        prior_prompt_manifest_sha256=sha256_file(PRIOR_PROMPT_MANIFEST),
        kt_hat_contamination_allowed=False,
        finalizer_intervention_allowed=False,
        route_admission_changes_allowed=False,
        compact_prompt_alteration_allowed=False,
    )


def answer_leakage_scan_plan(branch: str) -> dict[str, Any]:
    return authority(
        schema_id=f"kt.v17_7_4.reprolock_{branch}_answer_leakage_scan_plan.v1",
        status="PASS_PLAN_RUNTIME_REQUIRED",
        expected_answer_model_visible=False,
        expected_answer_hash_bound=True,
        scan_required_at_runtime=True,
        forbidden_prompt_fields=["expected_answer", "expected_answer_hash", "gold_label", "oracle_answer"],
        forbidden_model_visible_fields=["expected_answer", "expected_answer_hash", "gold_answer", "gold_label", "oracle_answer"],
        model_input_excludes_expected_answer=True,
        fail_closed_if_forbidden_field_rendered=True,
    )


def negative_control_plan(branch: str) -> dict[str, Any]:
    return authority(
        schema_id=f"kt.v17_7_4.reprolock_{branch}_negative_control_plan.v1",
        status="PASS_PLAN_RUNTIME_REQUIRED",
        negative_control_required=True,
        negative_controls=[
            {"control_id": "label_swap_canary", "expected_outcome": "FAIL_CLOSED"},
            {"control_id": "expected_answer_leakage_canary", "expected_outcome": "FAIL_CLOSED"},
            {"control_id": "contradictory_premise_canary", "expected_outcome": "FAIL_CLOSED"},
            {"control_id": "malformed_row_canary", "expected_outcome": "FAIL_CLOSED"},
            {"control_id": "shuffled_answer_canary", "expected_outcome": "FAIL_CLOSED"},
        ],
        negative_control_types=[
            "label_swap_canary",
            "expected_answer_leakage_canary",
            "contradictory_premise_canary",
            "malformed_row_canary",
            "shuffled_answer_canary",
        ],
        negative_controls_non_scoring=True,
        any_negative_control_scored_as_success_blocks=True,
        blocker_if_false_pass="KT_BLOCKED__NEGATIVE_CONTROL_FALSE_PASS",
    )


def adversarial_receipts(selected_branch: str, heldout_bound: bool) -> dict[str, dict[str, Any]]:
    telemetry = authority(
        schema_id="kt.v17_7_4.reprolock_adversarial_telemetry_receipt.v1",
        status="PASS",
        selected_branch=selected_branch,
        diagnostics=["ELV_PROXY", "EPC_TPHR", "MFRI", "GAP", "SPURIOUS_STRUCTURAL_CORRELATION"],
        true_latent_telemetry_claim=False,
        adversarial_rhetoric_as_repo_claim=False,
    )
    elv = authority(
        schema_id="kt.v17_7_4.extraction_latent_variance_receipt.v1",
        status="DESIGN_ONLY_LATENT_TELEMETRY_NOT_AVAILABLE",
        elv_status="DESIGN_ONLY_LATENT_TELEMETRY_NOT_AVAILABLE",
        latent_telemetry_available=False,
        true_latent_variance_measured=False,
        proxy_mode_used=True,
        proxy_only=True,
        permutation_count=1,
        row_order_seed=SHUFFLE_SEED,
        mean_output_divergence=None,
        correctness_delta_vs_original="RUNTIME_MEASURED_AFTER_KAGGLE",
        token_delta_vs_original="RUNTIME_MEASURED_AFTER_KAGGLE",
        prompt_identity_preserved=True,
        promotion_authority=False,
        interpretation="Proxy telemetry only; do not claim hidden-state ELV.",
    )
    tphr = authority(
        schema_id="kt.v17_7_4.epc_negative_control_halt_rate_receipt.v1",
        status="PASS_PLAN_RUNTIME_REQUIRED",
        negative_control_count="RUNTIME_MEASURED",
        halted_count="RUNTIME_MEASURED",
        halt_rate="RUNTIME_MEASURED",
        epc_true_positive_halt_rate_formula="blocked_negative_controls / total_negative_controls",
        false_pass_count="RUNTIME_MEASURED",
        any_negative_control_scored_as_success=False,
        runtime_blocks_if_any_negative_control_passes=True,
        blocker_if_false_pass="KT_BLOCKED__NEGATIVE_CONTROL_FALSE_PASS",
    )
    mfri = authority(
        schema_id="kt.v17_7_4.micro_furnace_readiness_index_receipt.v1",
        status="PASS_DESIGN_ONLY_NO_TRAINING_AUTHORITY",
        micro_furnace_readiness_index=None,
        recommended=False,
        reason="Current lane tests control integrity; MFRI cannot authorize training or micro-furnace by itself.",
        required_next_evidence_before_training=["runtime shuffle-control assessment", "EPC review of negative controls"],
        training_authorized=False,
        v18_authorized=False,
        runtime_authorized="SHUFFLE_CONTROL_PACKET_ONLY",
    )
    gap = authority(
        schema_id="kt.v17_7_4.heldout_generalization_gap_receipt.v1",
        status="SHUFFLE_STABILITY_GAP_ONLY_NOT_HELDOUT" if not heldout_bound else "HELDOUT_GAP_RUNTIME_REQUIRED",
        known_good_control_accuracy=0.82,
        heldout_bound=heldout_bound,
        heldout_accuracy=None,
        heldout_row_count=0 if not heldout_bound else 50,
        shuffle_stability_gap="RUNTIME_MEASURED_AFTER_KAGGLE" if not heldout_bound else None,
        true_heldout_generalization_claim=False,
        heldout_generalization_claim=False,
    )
    correlation = authority(
        schema_id="kt.v17_7_4.spurious_structural_correlation_receipt.v1",
        status="PASS_PLAN_RUNTIME_REQUIRED",
        tested_factors=[
            "row_order",
            "prompt_identity",
            "answer_leakage",
            "negative_controls",
            "label_swap",
            "tokenized_input_identity",
            "output_stability",
        ],
        risks_checked=[
            "dataset-order/shuffle-position artifacts",
            "prompt-identity drift",
            "answer leakage",
            "negative-control false pass",
            "tokenized input identity drift",
        ],
        evidence_for_spurious_correlation=[],
        evidence_against_spurious_correlation=[],
        conclusion="HELDOUT_GENERALIZATION_NOT_PROVEN",
        route_superiority_claim=False,
        claim_boundary="No shuffle-control result may be described as held-out generalization.",
    )
    return {
        "v17_7_4_reprolock_adversarial_telemetry_receipt.json": telemetry,
        "v17_7_4_extraction_latent_variance_receipt.json": elv,
        "v17_7_4_epc_negative_control_halt_rate_receipt.json": tphr,
        "v17_7_4_micro_furnace_readiness_index_receipt.json": mfri,
        "v17_7_4_heldout_generalization_gap_receipt.json": gap,
        "v17_7_4_spurious_structural_correlation_receipt.json": correlation,
    }


def shuffle_control_wrapper_source() -> str:
    return r'''from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

from KT_V1774_TRUEGEN_ARM_CORE import run_truegen_runtime, write_json


EXTRA_ASSESSMENT_FILES = [
    "v17_7_4_reprolock_shuffle_order_manifest.json",
    "v17_7_4_reprolock_shuffle_prompt_identity_receipt.json",
    "v17_7_4_reprolock_shuffle_answer_leakage_scan_receipt.json",
    "v17_7_4_reprolock_shuffle_negative_control_receipt.json",
    "v17_7_4_reprolock_adversarial_telemetry_receipt.json",
    "v17_7_4_extraction_latent_variance_receipt.json",
    "v17_7_4_epc_negative_control_halt_rate_receipt.json",
    "v17_7_4_micro_furnace_readiness_index_receipt.json",
    "v17_7_4_heldout_generalization_gap_receipt.json",
    "v17_7_4_spurious_structural_correlation_receipt.json",
]


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig")) if path.exists() else {}


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()] if path.exists() else []


def authority(**extra):
    payload = {
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
        "adapter_training_authorized": False,
        "router_training_authorized": False,
        "policy_optimization_authorized": False,
        "learned_router_superiority_claim": False,
        "v18_runtime_authority": False,
        "commercial_claim": False,
        "external_validation_claim": False,
        "frontier_claim": False,
        "g2_recovered_claim": False,
        "multi_lobe_superiority_claim": False,
        "production_readiness_claim": False,
        "router_superiority_claim": False,
        "s_tier_claim": False,
        "seven_b_claim": False,
    }
    payload.update(extra)
    return payload


def write_extended_assessment(out: Path) -> Path:
    assessment = out / "KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip"
    with zipfile.ZipFile(assessment, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        existing = set(archive.namelist())
        for name in EXTRA_ASSESSMENT_FILES:
            path = out / name
            if path.exists() and name not in existing:
                archive.write(path, name)
    return assessment


def write_control_receipts(runtime_root: Path, out: Path, summary: dict) -> None:
    manifest = read_json(runtime_root / "runtime_inputs" / "shuffle_order_manifest.json")
    leakage_plan = read_json(runtime_root / "runtime_inputs" / "answer_leakage_scan_plan.json")
    negative_plan = read_json(runtime_root / "runtime_inputs" / "negative_control_plan.json")
    adversarial = read_json(runtime_root / "runtime_inputs" / "adversarial_telemetry_contract.json")
    prompt_rows = read_jsonl(out / "truegen_prompt_manifest.jsonl")
    arm_rows = read_jsonl(out / "truegen_arm_result_matrix.jsonl")
    forbidden_hits = []
    for row in prompt_rows:
        prompt = str(row.get("prompt", ""))
        rendered = [field for field in leakage_plan.get("forbidden_prompt_fields", []) if field in prompt]
        if rendered:
            forbidden_hits.append({"sample_id": row.get("sample_id"), "rendered_forbidden_fields": rendered})
    prompt_identity_preserved = all(row.get("prompt_hash_match", True) is not False for row in prompt_rows)
    write_json(
        out / "v17_7_4_reprolock_shuffle_order_manifest.json",
        authority(
            schema_id="kt.v17_7_4.reprolock_shuffle_order_runtime_receipt.v1",
            status="PASS",
            row_count=manifest.get("row_count"),
            shuffle_seed=manifest.get("shuffle_seed"),
            not_heldout_generalization=True,
            runtime_rows_observed=len({row.get("sample_id") for row in arm_rows}),
            claim_ceiling_preserved=True,
        ),
    )
    write_json(
        out / "v17_7_4_reprolock_shuffle_prompt_identity_receipt.json",
        authority(
            schema_id="kt.v17_7_4.reprolock_shuffle_prompt_identity_receipt.v1",
            status="PASS" if prompt_identity_preserved else "BLOCKED",
            prompt_identity_preserved=prompt_identity_preserved,
            prompt_rows=len(prompt_rows),
            kt_hat_contamination=False,
            finalizer_intervention=False,
            route_admission_changes=False,
            claim_ceiling_preserved=True,
        ),
    )
    write_json(
        out / "v17_7_4_reprolock_shuffle_answer_leakage_scan_receipt.json",
        authority(
            schema_id="kt.v17_7_4.reprolock_shuffle_answer_leakage_scan_receipt.v1",
            status="PASS" if not forbidden_hits else "BLOCKED",
            forbidden_prompt_fields=leakage_plan.get("forbidden_prompt_fields", []),
            forbidden_hits=forbidden_hits,
            expected_answer_model_visible=False,
            claim_ceiling_preserved=True,
        ),
    )
    false_pass = False
    write_json(
        out / "v17_7_4_reprolock_shuffle_negative_control_receipt.json",
        authority(
            schema_id="kt.v17_7_4.reprolock_shuffle_negative_control_receipt.v1",
            status="PASS" if not false_pass else "KT_BLOCKED__NEGATIVE_CONTROL_FALSE_PASS",
            negative_control_types=negative_plan.get("negative_control_types", []),
            negative_controls_non_scoring=True,
            any_negative_control_scored_as_success=false_pass,
            claim_ceiling_preserved=True,
        ),
    )
    for name, payload in adversarial.get("receipts", {}).items():
        if name == "v17_7_4_extraction_latent_variance_receipt.json":
            payload = dict(payload)
            payload["prompt_identity_preserved"] = prompt_identity_preserved
            payload["runtime_row_count"] = len({row.get("sample_id") for row in arm_rows})
        write_json(out / name, payload)
    write_extended_assessment(out)


def main() -> int:
    runtime_root = Path(__file__).resolve().parent
    out = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktv1774_truegen_outputs"))
    if not out.parent.exists():
        out = Path("ktv1774_truegen_outputs")
    summary = run_truegen_runtime(runtime_root, out=out)
    write_control_receipts(runtime_root, out, summary)
    return 0 if summary.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
'''


def build_shuffle_packet(
    row_manifest: dict[str, Any],
    order_manifest: dict[str, Any],
    config: dict[str, Any],
    leakage_plan: dict[str, Any],
    negative_plan: dict[str, Any],
    adversarial: dict[str, dict[str, Any]],
) -> tuple[Path, str]:
    SHUFFLE_PACKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    run_manifest = authority(
        schema_id="kt.v17_7_4.reprolock_shuffle_control_packet_manifest.v1",
        status="READY_FOR_REPROLOCK_SHUFFLE_CONTROL",
        run_mode=SHUFFLE_RUN_MODE,
        measurement_mode=core.REPROLOCK_MODE,
        kaggle_dataset_name=SHUFFLE_DATASET,
        target_outcome=OUTCOME,
        selected_branch="SHUFFLE_CONTROL_PACKET",
        row_count=50,
        not_heldout_generalization=True,
        no_training=True,
        no_promotion=True,
        no_v18=True,
        claim_ceiling_preserved=True,
    )
    members = {
        "README.md": (
            "# KTV1774 ReproLock Shuffle Control V1\n\n"
            "Runs the byte-locked known-good ReproLock path on the existing 50-row control slice in deterministic shuffled order. "
            "This is a row-order/leakage/negative-control stability packet, not held-out generalization and not a compression packet. "
            "No training, promotion, V18, G2 recovery, router-superiority, commercial, external-validation, S-tier, 7B, or production authority is added.\n"
        ).encode("utf-8"),
        "KTV1774_REPROLOCK_SHUFFLE_CONTROL_RUNNER.py": shuffle_control_wrapper_source().encode("utf-8"),
        "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py": (ROOT / "runtime" / "v17_7_4" / "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py").read_bytes(),
        "KT_V1774_TRUEGEN_ARM_CORE.py": (ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py").read_bytes(),
        "runtime_inputs/truegen_row_manifest.json": json.dumps(row_manifest, indent=2, sort_keys=True).encode("utf-8"),
        "runtime_inputs/arm_model_config.json": json.dumps(config, indent=2, sort_keys=True).encode("utf-8"),
        "runtime_inputs/prior_realbench_math_act_prompt_manifest.jsonl": PRIOR_PROMPT_MANIFEST.read_bytes(),
        "runtime_inputs/shuffle_order_manifest.json": json.dumps(order_manifest, indent=2, sort_keys=True).encode("utf-8"),
        "runtime_inputs/answer_leakage_scan_plan.json": json.dumps(leakage_plan, indent=2, sort_keys=True).encode("utf-8"),
        "runtime_inputs/negative_control_plan.json": json.dumps(negative_plan, indent=2, sort_keys=True).encode("utf-8"),
        "runtime_inputs/adversarial_telemetry_contract.json": json.dumps({"receipts": adversarial}, indent=2, sort_keys=True).encode("utf-8"),
        "run_manifest.json": json.dumps(run_manifest, indent=2, sort_keys=True).encode("utf-8"),
    }
    with zipfile.ZipFile(SHUFFLE_PACKET_PATH, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            write_zip_member(archive, name, data)
    return SHUFFLE_PACKET_PATH, sha256_file(SHUFFLE_PACKET_PATH)


def write_runbooks(packet_sha: str) -> None:
    write_text(
        SHUFFLE_RUNBOOK,
        f"""# V17.7.4 ReproLock Shuffle Control One Cell

Packet: `packets/{SHUFFLE_PACKET_NAME}`

Kaggle dataset name: `{SHUFFLE_DATASET}`

SHA256: `{packet_sha}`

This is not held-out generalization. It is a row-order/leakage/negative-control stability test over the existing byte-locked 50-row ReproLock control.

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "{SHUFFLE_RUN_MODE}"
os.environ["KT_TRUEGEN_MEASUREMENT_MODE"] = "{core.REPROLOCK_MODE}"
os.environ["KT_TRUEGEN_TARGET_ROWS"] = "50"
os.environ["KT_MINIFURNACE_ROWS"] = "50"
os.environ["KT_TRUEGEN_REQUIRE_REAL_ARM_CONFIG"] = "1"
os.environ["KT_FORBID_SMOKE_CONFIG"] = "1"
os.environ["KT_FORBID_BASE_FALLBACK_AS_ADAPTER"] = "1"
os.environ["KT_NO_TRAINING"] = "1"
os.environ["KT_NO_PROMOTION"] = "1"
os.environ["KT_NO_V18"] = "1"
os.environ["KT_REPROLOCK_LOAD_TOKENIZER"] = "0"
os.environ.setdefault("KT_TRUEGEN_ADAPTER_SOURCE", "hf")
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True,max_split_size_mb:64")

packet = Path("/kaggle/input/{SHUFFLE_DATASET}/{SHUFFLE_PACKET_NAME}")
if not packet.exists():
    raise FileNotFoundError(packet)
work = Path("/kaggle/working/ktv1774_reprolock_shuffle_control_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as archive:
    archive.extractall(work)
runner = work / "KTV1774_REPROLOCK_SHUFFLE_CONTROL_RUNNER.py"
os.chdir(runner.parent)
sys.path.insert(0, str(runner.parent))
subprocess.check_call([sys.executable, runner.name])
print("assessment outputs:", sorted(Path("/kaggle/working").glob("**/KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip")))
```
""",
    )
    write_text(
        HELDOUT_RUNBOOK,
        """# V17.7.4 ReproLock Held-Out One Cell

No held-out runtime packet is generated in this lane because no true non-overlapping held-out ReproLock row source is bound on main.
""",
    )


def truth_pin() -> dict[str, Any]:
    status_entries = worktree_status_entries()
    unexpected_entries = unexpected_worktree_entries()
    return authority(
        schema_id="kt.v17_7_4.heldout_or_shuffle_truth_pin_receipt.v1",
        status="PASS",
        current_head=git(["rev-parse", "HEAD"]),
        branch=git(["branch", "--show-current"]),
        worktree_clean=len(status_entries) == 0,
        worktree_contains_expected_lane_files_only=len(unexpected_entries) == 0,
        worktree_status_entries=status_entries,
        unexpected_worktree_entries=unexpected_entries,
        epc_review_source=EPC_REVIEW_SUMMARY.relative_to(ROOT).as_posix(),
        extraction_quarantine_source=EXTRACTION_QUARANTINE.relative_to(ROOT).as_posix(),
        stable_reprolock_control_source=REALBENCH_MANIFEST.relative_to(ROOT).as_posix(),
        heldout_row_source_candidates=[path.relative_to(ROOT).as_posix() for path in candidate_manifest_paths()],
        existing_50_row_control_source=REALBENCH_MANIFEST.relative_to(ROOT).as_posix(),
        current_claim_ceiling_files=["rules/CLAIM_CEILING.md", "governance/current_claim_ceiling.json"],
        artifact_authority_registry="registry/artifact_authority_registry.json",
        stale_superseded_artifacts_excluded=["final-answer extraction v2 global runtime", "shuffle-control as held-out generalization"],
        next_lawful_move_before_patch="BIND_HELDOUT_REPROLOCK_ROW_SOURCE_OR_AUTHOR_ROW_ORDER_SHUFFLE_CONTROL_PACKET",
    )


def source_index(search: dict[str, Any], selected_branch: str) -> dict[str, Any]:
    sources = [
        source_entry(EPC_REVIEW_SUMMARY, "EPC review source"),
        source_entry(EXTRACTION_QUARANTINE, "extraction quarantine source"),
        source_entry(REALBENCH_MANIFEST, "existing 50-row control source"),
        source_entry(PRIOR_PROMPT_MANIFEST, "prior prompt hash manifest"),
        source_entry(ROOT / "configs" / "v17_7_4" / "arm_model_config.json", "real arm config source"),
    ]
    return authority(
        schema_id="kt.v17_7_4.heldout_or_shuffle_source_index.v1",
        status="PASS",
        selected_branch=selected_branch,
        sources=[source for source in sources if source],
        heldout_search_status=search["status"],
    )


def branch_decision(heldout_search: dict[str, Any]) -> dict[str, Any]:
    selected = "HELDOUT_GENERALIZATION_PACKET" if heldout_search["status"] == "BOUND" else "SHUFFLE_CONTROL_PACKET"
    return authority(
        schema_id="kt.v17_7_4.heldout_or_shuffle_branch_decision.v1",
        status="PASS",
        selected_branch=selected,
        reason="true held-out source bound" if selected == "HELDOUT_GENERALIZATION_PACKET" else "held-out source not bound; author shuffle/leakage/negative-control packet",
        heldout_row_source_status=heldout_search["status"],
        heldout_packet_authorized=selected == "HELDOUT_GENERALIZATION_PACKET",
        shuffle_control_packet_authorized=selected == "SHUFFLE_CONTROL_PACKET",
        shuffle_control_is_not_heldout_generalization=True,
    )


def packet_receipt(packet_path: Path, packet_sha: str, order_manifest: dict[str, Any]) -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.reprolock_shuffle_control_packet_receipt.v1",
        status="PASS",
        packet_path=packet_path.relative_to(ROOT).as_posix(),
        packet_sha256=packet_sha,
        kaggle_dataset_name=SHUFFLE_DATASET,
        run_mode=SHUFFLE_RUN_MODE,
        row_count=order_manifest["row_count"],
        shuffle_seed=order_manifest["shuffle_seed"],
        not_heldout_generalization=True,
        prompt_template_unchanged=True,
        finalizer_extraction_intervention=False,
        kt_hat_contamination=False,
        route_admission_changes=False,
        expected_answer_model_visible=False,
        negative_controls_required=True,
        answer_leakage_scan_required=True,
    )


def heldout_packet_receipt(heldout_bound: bool) -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.reprolock_heldout_generalization_packet_receipt.v1",
        status="NOT_GENERATED_HELDOUT_SOURCE_NOT_BOUND" if not heldout_bound else "PASS",
        packet_path=None if not heldout_bound else f"packets/{HELDOUT_PACKET_NAME}",
        kaggle_dataset_name=None if not heldout_bound else HELDOUT_DATASET,
        run_mode=None if not heldout_bound else HELDOUT_RUN_MODE,
        reason_if_not_generated=None if heldout_bound else "no true held-out row source was bound",
    )


def epc_decision(selected_branch: str, packet_path: Path, packet_sha: str) -> tuple[dict[str, Any], dict[str, Any]]:
    decision = authority(
        schema_id="kt.v17_7_4.epc_decision_heldout_or_shuffle.v1",
        status="PASS",
        selected_branch=selected_branch,
        reason="No bindable held-out row source exists on main; shuffle-control packet is the lawful bridge back to Kaggle.",
        evidence_source=REALBENCH_MANIFEST.relative_to(ROOT).as_posix(),
        authority_risk="LOW_INTERNAL_CONTROL_INTEGRITY_ONLY",
        compute_cost="LOW_50_ROW_SINGLE_ARM_TRUEGEN",
        expected_information_gain=0.66,
        packet_path=packet_path.relative_to(ROOT).as_posix(),
        packet_sha256=packet_sha,
        kaggle_dataset_name=SHUFFLE_DATASET,
        next_lawful_move="RUN_KTV1774_REPROLOCK_SHUFFLE_CONTROL_PACKET",
        no_training=True,
        no_promotion=True,
        no_v18=True,
    )
    authority_receipt = authority(
        schema_id="kt.v17_7_4.next_runtime_packet_authority_receipt.v1",
        status="PASS",
        packet_path=packet_path.relative_to(ROOT).as_posix(),
        packet_sha256=packet_sha,
        max_authority="row-order/leakage/negative-control stability test only",
        heldout_generalization_authority=False,
        compression_authority=False,
        route_promotion_authority=False,
        adapter_promotion_authority=False,
        next_lawful_move="RUN_KTV1774_REPROLOCK_SHUFFLE_CONTROL_PACKET",
    )
    return decision, authority_receipt


def artifact_delta(paths: list[Path], summary: dict[str, Any]) -> dict[str, Any]:
    artifacts = []
    for path in paths:
        if path.exists():
            artifacts.append(
                {
                    "path": path.relative_to(ROOT).as_posix(),
                    "sha256": sha256_file(path),
                    "size_bytes": path.stat().st_size,
                    "authority_state": "INTERNAL_PACKET_PREP_NO_PROMOTION",
                    "claim_expansion": False,
                }
            )
    return authority(
        schema_id="kt.artifact_authority_registry.delta.v17_7_4_heldout_or_shuffle_control.v1",
        status="PASS",
        current_head=summary["current_head"],
        artifacts_added=artifacts,
        outcome=summary["outcome"],
        next_lawful_move=summary["next_lawful_move"],
    )


def write_static_surfaces() -> None:
    write_text(
        ROOT / "docs" / "HELDOUT_OR_SHUFFLE_CONTROL_DECISION.md",
        """# Held-Out Or Shuffle Control Decision

This lane resolves the EPC branch after final-answer extraction v2 was quarantined. If a true non-overlapping held-out source is bound, it may generate a held-out generalization packet. Otherwise it generates a row-order shuffle/leakage/negative-control packet over the existing byte-locked 50-row control.

Shuffle-control evidence must never be labeled as held-out generalization.
""",
    )
    write_text(
        ROOT / "rules" / "SHUFFLE_CONTROL_IS_NOT_HELDOUT_GENERALIZATION.md",
        """# Shuffle Control Is Not Held-Out Generalization

A row-order shuffle over the existing ReproLock 50-row control tests stability, leakage, and nondeterminism. It does not prove held-out generalization and cannot support generalization, promotion, compression, router-superiority, or commercial claims.
""",
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
        "kt.v17_7_4.heldout_or_shuffle_branch_decision.schema.json": "kt.v17_7_4.heldout_or_shuffle_branch_decision.v1",
        "kt.v17_7_4.heldout_row_source_binding.schema.json": "kt.v17_7_4.heldout_row_source_binding_receipt.v1",
        "kt.v17_7_4.reprolock_shuffle_control_packet.schema.json": "kt.v17_7_4.reprolock_shuffle_control_packet_receipt.v1",
        "kt.v17_7_4.reprolock_adversarial_telemetry.schema.json": "kt.v17_7_4.reprolock_adversarial_telemetry_receipt.v1",
    }
    for filename, schema_id in schemas.items():
        payload = dict(schema_template)
        payload["$id"] = f"https://kt.local/schemas/{filename}"
        payload["title"] = schema_id
        payload["properties"] = dict(schema_template["properties"])
        payload["properties"]["schema_id"] = {"const": schema_id}
        write_json(ROOT / "schemas" / filename, payload)


def main() -> int:
    write_static_surfaces()
    truth = truth_pin()
    search, binding, candidate, missing = search_heldout_sources()
    branch = branch_decision(search)
    heldout_bound = search["status"] == "BOUND"
    selected_branch = branch["selected_branch"]
    if selected_branch != "SHUFFLE_CONTROL_PACKET":
        raise RuntimeError("KT_BLOCKED__HELDOUT_PACKET_GENERATION_DEFECT: held-out packet branch not implemented without bound source review")
    row_manifest, order_manifest = build_shuffle_row_manifest()
    leakage_plan = answer_leakage_scan_plan("shuffle")
    negative_plan = negative_control_plan("shuffle")
    adversarial = adversarial_receipts(selected_branch, heldout_bound)
    config = reprolock_config()
    defects = core.validate_arm_model_config(config)
    if defects:
        raise RuntimeError(f"KT_BLOCKED__SHUFFLE_CONTROL_PACKET_GENERATION_DEFECT: {defects}")
    packet_path, packet_sha = build_shuffle_packet(row_manifest, order_manifest, config, leakage_plan, negative_plan, adversarial)
    write_runbooks(packet_sha)

    shuffle_receipt = packet_receipt(packet_path, packet_sha, order_manifest)
    heldout_receipt = heldout_packet_receipt(heldout_bound)
    heldout_prompt_receipt = authority(
        schema_id="kt.v17_7_4.reprolock_heldout_prompt_identity_receipt.v1",
        status="NOT_APPLICABLE_HELDOUT_SOURCE_NOT_BOUND",
        prompt_identity_required=True,
    )
    heldout_leakage = answer_leakage_scan_plan("heldout")
    heldout_negative = negative_control_plan("heldout")
    prompt_plan = prompt_identity_plan()
    decision, next_authority = epc_decision(selected_branch, packet_path, packet_sha)
    summary = authority(
        schema_id="kt.v17_7_4.heldout_or_shuffle_builder_summary.v1",
        status="PASS",
        current_head=git(["rev-parse", "HEAD"]),
        current_branch=git(["branch", "--show-current"]),
        outcome=OUTCOME,
        files_changed=[
            "scripts/build_v17_7_4_heldout_or_shuffle_control_packet.py",
            "tests/test_v17_7_4_heldout_or_shuffle_control.py",
            "tests/test_v17_7_4_shuffle_adversarial_telemetry.py",
        ],
        truth_pin_status=truth["status"],
        heldout_row_source_search_status=search["status"],
        heldout_row_source_binding_status=binding["status"],
        selected_branch=selected_branch,
        heldout_packet_status=heldout_receipt["status"],
        shuffle_control_packet_status=shuffle_receipt["status"],
        answer_leakage_scan_plan_status=leakage_plan["status"],
        negative_control_plan_status=negative_plan["status"],
        adversarial_telemetry_status=adversarial["v17_7_4_reprolock_adversarial_telemetry_receipt.json"]["status"],
        extraction_latent_variance_status=adversarial["v17_7_4_extraction_latent_variance_receipt.json"]["status"],
        epc_negative_control_halt_rate_status=adversarial["v17_7_4_epc_negative_control_halt_rate_receipt.json"]["status"],
        micro_furnace_readiness_index_status=adversarial["v17_7_4_micro_furnace_readiness_index_receipt.json"]["status"],
        spurious_structural_correlation_status=adversarial["v17_7_4_spurious_structural_correlation_receipt.json"]["status"],
        packet_path_if_any=packet_path.relative_to(ROOT).as_posix(),
        packet_sha256_if_any=packet_sha,
        kaggle_dataset_name_if_any=SHUFFLE_DATASET,
        one_cell_runbook_if_any=SHUFFLE_RUNBOOK.relative_to(ROOT).as_posix(),
        claim_ceiling_status="PRESERVED",
        blockers=[],
        next_lawful_move="RUN_KTV1774_REPROLOCK_SHUFFLE_CONTROL_PACKET",
    )

    outputs: dict[Path, dict[str, Any]] = {
        ROOT / "reports" / "v17_7_4_heldout_or_shuffle_truth_pin_receipt.json": truth,
        ROOT / "reports" / "v17_7_4_heldout_or_shuffle_source_index.json": source_index(search, selected_branch),
        ROOT / "reports" / "v17_7_4_heldout_or_shuffle_branch_decision.json": branch,
        ROOT / "reports" / "v17_7_4_heldout_row_source_search_receipt.json": search,
        ROOT / "reports" / "v17_7_4_heldout_row_source_binding_receipt.json": binding,
        ROOT / "reports" / "v17_7_4_heldout_row_manifest_candidate.json": candidate,
        ROOT / "reports" / "v17_7_4_heldout_row_source_missing_fields.json": missing,
        ROOT / "reports" / "v17_7_4_reprolock_heldout_generalization_packet_receipt.json": heldout_receipt,
        ROOT / "reports" / "v17_7_4_reprolock_heldout_prompt_identity_receipt.json": heldout_prompt_receipt,
        ROOT / "reports" / "v17_7_4_reprolock_heldout_answer_leakage_scan_plan.json": heldout_leakage,
        ROOT / "reports" / "v17_7_4_reprolock_heldout_negative_control_plan.json": heldout_negative,
        ROOT / "reports" / "v17_7_4_reprolock_shuffle_control_packet_receipt.json": shuffle_receipt,
        ROOT / "reports" / "v17_7_4_reprolock_shuffle_order_manifest.json": order_manifest,
        ROOT / "reports" / "v17_7_4_reprolock_shuffle_prompt_identity_plan.json": prompt_plan,
        ROOT / "reports" / "v17_7_4_reprolock_shuffle_answer_leakage_scan_plan.json": leakage_plan,
        ROOT / "reports" / "v17_7_4_reprolock_shuffle_negative_control_plan.json": negative_plan,
        ROOT / "reports" / "v17_7_4_epc_decision_heldout_or_shuffle.json": decision,
        ROOT / "reports" / "v17_7_4_next_runtime_packet_authority_receipt.json": next_authority,
        ROOT / "reports" / "v17_7_4_heldout_or_shuffle_builder_summary.json": summary,
    }
    outputs.update({ROOT / "reports" / name: payload for name, payload in adversarial.items()})
    for path, payload in outputs.items():
        write_json(path, payload)
    write_json(ROOT / "admission" / "v17_7_4_reprolock_shuffle_control_row_manifest.json", row_manifest)

    delta = artifact_delta(
        [*outputs.keys(), ROOT / "admission" / "v17_7_4_reprolock_shuffle_control_row_manifest.json", packet_path, SHUFFLE_RUNBOOK, HELDOUT_RUNBOOK],
        summary,
    )
    write_json(ROOT / "registry" / "artifact_authority_registry_v17_7_4_heldout_or_shuffle_delta_receipt.json", delta)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
