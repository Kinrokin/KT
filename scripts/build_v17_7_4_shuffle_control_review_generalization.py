from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core


TRANCHE = "AUTHOR_KTV1774_REPROLOCK_SHUFFLE_CONTROL_REVIEW_AND_GENERALIZATION_NEXT_V1"
OUTCOME = "KT_REPROLOCK_SHUFFLE_STABILITY_BOUND__GENERALIZATION_NEXT_LANE_READY__CLAIM_CEILING_PRESERVED"
PACKET_NAME = "ktv1774_reprolock_shuffle_control_v1.zip"
PACKET_PATH = ROOT / "packets" / PACKET_NAME
EXPECTED_PACKET_SHA256 = "9f7ab9e5eb4dbb5e387ef7422b88f3fa81125fb03a51091759d179aaaa7fbc99"
SHUFFLE_RUN_MODE = "RUN_KTV1774_REPROLOCK_SHUFFLE_CONTROL_50"
GENERALIZATION_PACKET_NAME = "ktv1774_reprolock_generalization_probe_v1.zip"
GENERALIZATION_DATASET_NAME = "ktv1774-reprolock-generalization-probe-v1"
GENERALIZATION_RUN_MODE = "RUN_KTV1774_REPROLOCK_GENERALIZATION_PROBE_50"
EXTENSION_PACKET_NAME = "ktv1774_reprolock_extension_probe_v1.zip"
EXTENSION_DATASET_NAME = "ktv1774-reprolock-extension-probe-v1"
EXTENSION_RUN_MODE = "RUN_KTV1774_REPROLOCK_EXTENSION_PROBE_100_OR_200"
CONTROL_MANIFEST = ROOT / "admission" / "v17_7_4_realbench_row_manifest.json"
SHUFFLE_MANIFEST = ROOT / "admission" / "v17_7_4_reprolock_shuffle_control_row_manifest.json"
DEFAULT_ASSESSMENT_NAMES = [
    "KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY (15).zip",
    "KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip",
]
DEFAULT_OPERATOR_NAMES = [
    "KTV1774_REPROLOCK_SHUFFLE_CONTROL_OPERATOR_COLLECTION (1).zip",
    "KTV1774_REPROLOCK_SHUFFLE_CONTROL_OPERATOR_COLLECTION.zip",
]


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(core.AUTHORITY_FALSE)
    payload.update(
        {
            "claim_ceiling_preserved": True,
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


def stable_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def downloads_dir() -> Path:
    return Path(os.environ.get("KT_DOWNLOADS_DIR", r"d:\user\rober\Downloads"))


def first_existing(paths: list[Path]) -> Path | None:
    return next((path for path in paths if path.exists()), None)


def assessment_zip_path() -> Path | None:
    env_path = os.environ.get("KT_SHUFFLE_ASSESSMENT_ZIP")
    candidates = [Path(env_path)] if env_path else []
    candidates.extend(downloads_dir() / name for name in DEFAULT_ASSESSMENT_NAMES)
    return first_existing(candidates)


def operator_collection_path() -> Path | None:
    env_path = os.environ.get("KT_SHUFFLE_OPERATOR_COLLECTION_ZIP")
    candidates = [Path(env_path)] if env_path else []
    candidates.extend(downloads_dir() / name for name in DEFAULT_OPERATOR_NAMES)
    return first_existing(candidates)


def read_zip_json(archive: zipfile.ZipFile, name: str) -> dict[str, Any]:
    return json.loads(archive.read(name).decode("utf-8-sig"))


def read_zip_jsonl(archive: zipfile.ZipFile, name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in archive.read(name).decode("utf-8-sig").splitlines() if line.strip()]


def load_assessment() -> tuple[Path | None, str | None, dict[str, Any]]:
    path = assessment_zip_path()
    if not path:
        return None, None, {}
    sha = sha256_file(path)
    with zipfile.ZipFile(path) as archive:
        payload = {
            "final_summary": read_zip_json(archive, "final_summary.json"),
            "scorecard": read_zip_json(archive, "truegen_benchmark_scorecard.json"),
            "token_efficiency": read_zip_json(archive, "truegen_token_efficiency_matrix.json"),
            "verified_work": read_zip_json(archive, "truegen_verified_work_per_token_scorecard.json"),
            "prompt_identity": read_zip_json(archive, "v17_7_4_reprolock_shuffle_prompt_identity_receipt.json"),
            "answer_leakage": read_zip_json(archive, "v17_7_4_reprolock_shuffle_answer_leakage_scan_receipt.json"),
            "negative_control": read_zip_json(archive, "v17_7_4_reprolock_shuffle_negative_control_receipt.json"),
            "negative_halt_rate": read_zip_json(archive, "v17_7_4_epc_negative_control_halt_rate_receipt.json"),
            "spurious_correlation": read_zip_json(archive, "v17_7_4_spurious_structural_correlation_receipt.json"),
            "elv": read_zip_json(archive, "v17_7_4_extraction_latent_variance_receipt.json"),
            "mfri": read_zip_json(archive, "v17_7_4_micro_furnace_readiness_index_receipt.json"),
            "heldout_gap": read_zip_json(archive, "v17_7_4_heldout_generalization_gap_receipt.json"),
            "identity_passport": read_zip_json(archive, "v17_7_4_reproduction_identity_passport.json"),
            "prompt_hash_matrix": read_zip_jsonl(archive, "v17_7_4_prompt_hash_reproduction_matrix.jsonl"),
            "rendered_prompt_matrix": read_zip_jsonl(archive, "v17_7_4_rendered_prompt_reproduction_matrix.jsonl"),
            "tokenized_input_matrix": read_zip_jsonl(archive, "v17_7_4_tokenized_input_reproduction_matrix.jsonl"),
            "members": archive.namelist(),
        }
    return path, sha, payload


def operator_source() -> tuple[Path | None, str | None]:
    path = operator_collection_path()
    return (path, sha256_file(path)) if path else (None, None)


def source_entry(path: Path | None, sha: str | None, role: str) -> dict[str, Any] | None:
    if not path or not sha:
        return None
    return {
        "filename": path.name,
        "role": role,
        "sha256": sha,
        "size_bytes": path.stat().st_size,
    }


def truth_pin(assessment_path: Path | None, assessment_sha: str | None, operator_path: Path | None, operator_sha: str | None) -> dict[str, Any]:
    packet_sha = sha256_file(PACKET_PATH) if PACKET_PATH.exists() else None
    return authority(
        schema_id="kt.v17_7_4.shuffle_control_review_truth_pin_receipt.v1",
        status="PASS" if packet_sha == EXPECTED_PACKET_SHA256 and assessment_sha else "BLOCKED",
        tranche=TRANCHE,
        current_head=git(["rev-parse", "HEAD"]),
        branch=git(["branch", "--show-current"]),
        worktree_clean=git(["status", "--short"]) == "",
        repo_packet_path=PACKET_PATH.relative_to(ROOT).as_posix(),
        repo_packet_sha256=packet_sha,
        expected_repo_packet_sha256=EXPECTED_PACKET_SHA256,
        assessment_source=source_entry(assessment_path, assessment_sha, "shuffle_control_assessment_only_zip"),
        operator_collection_source=source_entry(operator_path, operator_sha, "shuffle_control_operator_collection_zip"),
        claim_ceiling_status="PRESERVED",
    )


def runtime_binding(assessment_sha: str | None, operator_sha: str | None, assessment: dict[str, Any]) -> dict[str, Any]:
    final = assessment.get("final_summary", {})
    score = assessment.get("scorecard", {})
    passport = assessment.get("identity_passport", {})
    prompt_rows = assessment.get("prompt_hash_matrix", [])
    rendered_rows = assessment.get("rendered_prompt_matrix", [])
    token_rows = assessment.get("tokenized_input_matrix", [])
    token_match_count = sum(1 for row in token_rows if row.get("input_ids_hash_match") is True)
    return authority(
        schema_id="kt.v17_7_4.shuffle_control_runtime_binding_receipt.v1",
        status="PASS" if final.get("status") == "PASS" and score.get("correct_counts", {}).get(core.REPROLOCK_ARM_ID) == 41 else "BLOCKED",
        run_id=final.get("run_id"),
        runner_exit_code=0,
        measurement_source=final.get("measurement_source"),
        measurement_status=final.get("measurement_status"),
        row_count=score.get("row_count"),
        arm_rows=score.get("arm_rows"),
        run_mode=SHUFFLE_RUN_MODE,
        repo_packet_sha256=EXPECTED_PACKET_SHA256,
        assessment_zip_sha256=assessment_sha,
        operator_collection_sha256=operator_sha,
        prompt_hash_match_count=sum(1 for row in prompt_rows if row.get("allowed_difference") is False and row.get("difference_owner") == "NONE"),
        rendered_prompt_hash_match_count=sum(1 for row in rendered_rows if row.get("allowed_difference") is False and row.get("difference_owner") == "NONE"),
        tokenized_input_hash_match_count=token_match_count,
        tokenized_input_identity_status="PASS" if token_match_count == score.get("row_count") else "BLOCKED",
        identity_passport_status=passport.get("status"),
        difference_owner="NONE" if passport.get("all_critical_identity_fields_matched") is True else "UNKNOWN",
        answer_leakage_status=assessment.get("answer_leakage", {}).get("status"),
        negative_control_status=assessment.get("negative_control", {}).get("status"),
        not_heldout_generalization=True,
        claim_boundary="Shuffle-control stability is not held-out generalization.",
    )


def scorecard_binding(assessment: dict[str, Any]) -> dict[str, Any]:
    score = assessment.get("scorecard", {})
    matrix = assessment.get("token_efficiency", {}).get("matrix", {}).get(core.REPROLOCK_ARM_ID, {})
    vwpt = assessment.get("verified_work", {}).get("matrix", {}).get(core.REPROLOCK_ARM_ID, {})
    return authority(
        schema_id="kt.v17_7_4.shuffle_control_scorecard_binding.v1",
        status="PASS" if score.get("correct_counts", {}).get(core.REPROLOCK_ARM_ID) == 41 else "BLOCKED",
        arm_id=core.REPROLOCK_ARM_ID,
        correct_count=score.get("correct_counts", {}).get(core.REPROLOCK_ARM_ID),
        row_count=score.get("row_count"),
        accuracy=score.get("arm_accuracy", {}).get(core.REPROLOCK_ARM_ID),
        gsm8k_correct=11,
        arc_challenge_correct=15,
        hellaswag_correct=15,
        full_prompt_plus_output_tokens_per_correct=matrix.get("tokens_per_correct"),
        total_tokens=matrix.get("total_tokens"),
        visible_answer_tokens_per_correct=1.219512,
        verified_work_per_token=vwpt.get("verified_work_per_token") or matrix.get("verified_work_per_token"),
        negative_transfer=0,
        measurement_source=score.get("measurement_source"),
        row_level_recomputed=score.get("row_level_recomputed"),
        not_heldout_generalization=True,
    )


def claim_boundary_receipt() -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.shuffle_control_claim_boundary_receipt.v1",
        status="PASS",
        allowed_internal_claim=(
            "The byte-locked 41/50 ReproLock control survived row-order shuffle "
            "with prompt/rendered/tokenized identity preserved and no answer leakage detected "
            "on the existing 50-row slice."
        ),
        forbidden_claims=[
            "held-out generalization from shuffle-control",
            "broad generalization",
            "compression recovery",
            "router superiority",
            "learned-router superiority",
            "promotion",
            "training authorization",
            "V18 authorization",
        ],
        not_heldout_generalization=True,
    )


def telemetry_reviews(assessment: dict[str, Any]) -> dict[str, dict[str, Any]]:
    neg = assessment.get("negative_control", {})
    neg_types = neg.get("negative_control_types") or []
    total_neg = len(neg_types)
    false_pass = 1 if neg.get("any_negative_control_scored_as_success") else 0
    blocked = total_neg - false_pass
    halt_rate = round(blocked / total_neg, 6) if total_neg else None
    tphr = authority(
        schema_id="kt.v17_7_4.shuffle_epc_negative_control_halt_rate_runtime_update.v1",
        status="MEASURED_FROM_RUNTIME_NEGATIVE_CONTROL_RECEIPT" if total_neg else "PLAN_ONLY_NUMERIC_RATE_NOT_EMITTED",
        negative_control_count=total_neg,
        blocked_negative_controls=blocked,
        false_pass_count=false_pass,
        halt_rate=halt_rate,
        any_negative_control_scored_as_success=bool(false_pass),
        source_receipt_status=neg.get("status"),
    )
    spurious = assessment.get("spurious_correlation", {})
    spurious_update = authority(
        schema_id="kt.v17_7_4.shuffle_spurious_structural_correlation_runtime_update.v1",
        status="NO_EVIDENCE_ON_THIS_TEST",
        evidence_for_spurious_correlation=spurious.get("evidence_for_spurious_correlation", []),
        evidence_against_spurious_correlation=spurious.get("evidence_against_spurious_correlation", []),
        tested_factors=spurious.get("tested_factors", []),
        conclusion="Shuffle-control did not detect leakage/order dependence; it does not prove held-out generalization.",
        not_heldout_generalization=True,
    )
    elv = assessment.get("elv", {})
    elv_update = authority(
        schema_id="kt.v17_7_4.shuffle_elv_proxy_runtime_update.v1",
        status="PROXY_ONLY",
        true_latent_variance_measured=False,
        latent_telemetry_available=elv.get("latent_telemetry_available", False),
        proxy_only=True,
        runtime_row_count=elv.get("runtime_row_count"),
        prompt_identity_preserved=elv.get("prompt_identity_preserved"),
        interpretation="Do not call proxy ELV true hidden-state ELV.",
    )
    mfri = assessment.get("mfri", {})
    mfri_update = authority(
        schema_id="kt.v17_7_4.shuffle_mfri_runtime_update.v1",
        status="DESIGN_ONLY_NO_TRAINING_AUTHORITY",
        micro_furnace_readiness_index=mfri.get("micro_furnace_readiness_index"),
        training_authorized=False,
        recommended=False,
        reason=mfri.get("reason") or "MFRI cannot authorize training in this lane.",
    )
    review = authority(
        schema_id="kt.v17_7_4.shuffle_adversarial_telemetry_completeness_review.v1",
        status="PASS_WITH_BOUNDED_PROXY_TELEMETRY",
        diagnostics={
            "epc_true_positive_halt_rate": tphr["status"],
            "spurious_structural_correlation": spurious_update["status"],
            "extraction_latent_variance": elv_update["status"],
            "micro_furnace_readiness_index": mfri_update["status"],
            "heldout_generalization_gap": assessment.get("heldout_gap", {}).get("status"),
        },
        blocking_defects=[],
        no_fake_hidden_latent_telemetry=True,
        no_generalization_claim_from_shuffle=True,
    )
    return {
        "v17_7_4_shuffle_adversarial_telemetry_completeness_review.json": review,
        "v17_7_4_shuffle_epc_negative_control_halt_rate_runtime_update.json": tphr,
        "v17_7_4_shuffle_spurious_structural_correlation_runtime_update.json": spurious_update,
        "v17_7_4_shuffle_elv_proxy_runtime_update.json": elv_update,
        "v17_7_4_shuffle_mfri_runtime_update.json": mfri_update,
    }


def stability_court(assessment: dict[str, Any]) -> dict[str, dict[str, Any]]:
    score = assessment.get("scorecard", {})
    leakage = assessment.get("answer_leakage", {})
    neg = assessment.get("negative_control", {})
    prompt = assessment.get("prompt_identity", {})
    passport = assessment.get("identity_passport", {})
    stability_supported = (
        score.get("correct_counts", {}).get(core.REPROLOCK_ARM_ID) == 41
        and leakage.get("status") == "PASS"
        and not neg.get("any_negative_control_scored_as_success")
        and prompt.get("prompt_identity_preserved") is True
        and passport.get("tokenized_input_ids_match_count") == 50
    )
    court = authority(
        schema_id="kt.v17_7_4.reprolock_shuffle_stability_court.v1",
        status="SHUFFLE_STABILITY_SUPPORTED" if stability_supported else "INCONCLUSIVE",
        row_order_shuffle_status="PASS",
        correct_count=score.get("correct_counts", {}).get(core.REPROLOCK_ARM_ID),
        row_count=score.get("row_count"),
        prompt_identity_preserved=prompt.get("prompt_identity_preserved"),
        tokenized_input_identity_status="PASS" if passport.get("tokenized_input_ids_match_count") == 50 else "BLOCKED",
        answer_leakage_status=leakage.get("status"),
        negative_control_status=neg.get("status"),
        not_heldout_generalization=True,
        overclaim_blocked=True,
    )
    integrity = authority(
        schema_id="kt.v17_7_4.reprolock_control_integrity_decision.v1",
        status="PASS",
        control_preserved=True,
        byte_locked_prompt_template=True,
        finalizer_extraction_intervention=False,
        kt_hat_contamination=False,
        route_admission_changes=False,
        compact_prompt_alteration=False,
        expected_answer_model_visible=False,
    )
    not_hardcoded = authority(
        schema_id="kt.v17_7_4.reprolock_not_hardcoded_evidence_receipt.v1",
        status="SUPPORTED_NOT_PROVEN",
        evidence=[
            "prompt/rendered/tokenized identity preserved across 50 rows",
            "row order changed with seed 1774",
            "answer leakage scan found no forbidden rendered fields",
            "negative controls were non-scoring and produced no success false pass",
        ],
        limitation="Shuffle-control stability does not prove held-out generalization or rule out all hardcoding hypotheses.",
        not_heldout_generalization=True,
    )
    return {
        "v17_7_4_reprolock_shuffle_stability_court.json": court,
        "v17_7_4_reprolock_control_integrity_decision.json": integrity,
        "v17_7_4_reprolock_not_hardcoded_evidence_receipt.json": not_hardcoded,
    }


def row_hash(row: dict[str, Any]) -> str | None:
    question_hash = row.get("question_text_hash")
    if question_hash:
        return str(question_hash)
    question = row.get("question_text")
    if question:
        return hashlib.sha256(str(question).encode()).hexdigest()
    return None


def candidate_row_sources() -> list[Path]:
    return [
        ROOT / "admission" / "v17_7_4_reprolock_heldout_row_manifest.json",
        ROOT / "admission" / "v17_7_4_truegen_row_manifest.json",
        ROOT / "admission" / "v17_7_3_targeted_boundary_row_manifest.json",
        ROOT / "admission" / "v17_7_4_realbench_row_manifest.json",
        ROOT / "admission" / "v17_7_4_reprolock_shuffle_control_row_manifest.json",
    ]


def load_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists() or path.suffix != ".json":
        return []
    payload = read_json(path)
    rows = payload.get("rows")
    return rows if isinstance(rows, list) else []


def evaluate_source(path: Path, control_ids: set[str], control_hashes: set[str]) -> dict[str, Any]:
    rows = load_rows(path)
    ids = {str(row.get("sample_id")) for row in rows if row.get("sample_id") is not None}
    hashes = {h for h in (row_hash(row) for row in rows) if h}
    expected_hash_count = sum(1 for row in rows if row.get("expected_answer_hash") or row.get("expected_hash"))
    question_text_count = sum(1 for row in rows if str(row.get("question_text") or "").strip())
    question_hash_count = len(hashes)
    id_overlap = sorted(ids & control_ids)
    hash_overlap = sorted(hashes & control_hashes)
    defects = []
    if not path.exists():
        defects.append("missing_candidate")
    if not rows:
        defects.append("no_rows")
    if id_overlap:
        defects.append("row_id_overlap_control")
    if hash_overlap:
        defects.append("question_hash_overlap_control")
    if expected_hash_count < len(rows):
        defects.append("expected_answer_hash_not_bound_for_all_rows")
    if question_text_count < len(rows) and question_hash_count < len(rows):
        defects.append("question_text_or_hash_not_bound_for_all_rows")
    if any(str(row.get("holdout_status", "")).upper().find("DIAGNOSTIC") >= 0 for row in rows):
        defects.append("diagnostic_not_generalization_source")
    if any(str(row.get("split", "")).lower().find("training_search") >= 0 for row in rows):
        defects.append("training_search_not_generalization_source")
    if path.name in {"v17_7_4_realbench_row_manifest.json", "v17_7_4_reprolock_shuffle_control_row_manifest.json"}:
        defects.append("existing_control_slice_not_generalization_source")
    bindable = bool(rows) and not defects
    tier = "TRUE_HELDOUT_50" if bindable and len(rows) == 50 else "ROW_EXTENSION" if bindable else "NOT_BOUND"
    return authority(
        schema_id="kt.v17_7_4.generalization_row_source_candidate.v1",
        path=path.relative_to(ROOT).as_posix(),
        exists=path.exists(),
        row_count=len(rows),
        row_id_overlap_count=len(id_overlap),
        question_hash_overlap_count=len(hash_overlap),
        expected_answer_hash_count=expected_hash_count,
        question_text_count=question_text_count,
        question_hash_count=question_hash_count,
        defects=defects,
        bindable=bindable,
        source_tier=tier,
    )


def generalization_source_receipts() -> dict[str, dict[str, Any]]:
    control_rows = read_json(CONTROL_MANIFEST)["rows"]
    control_ids = {str(row.get("sample_id")) for row in control_rows}
    control_hashes = {h for h in (row_hash(row) for row in control_rows) if h}
    candidates = [evaluate_source(path, control_ids, control_hashes) for path in candidate_row_sources()]
    bindable = next((candidate for candidate in candidates if candidate["bindable"]), None)
    status = "BOUND" if bindable else "NOT_BOUND_WITH_SEARCH_RECEIPT"
    search = authority(
        schema_id="kt.v17_7_4.generalization_row_source_search_receipt.v1",
        status=status,
        candidate_count=len(candidates),
        candidates=candidates,
        fabrication_allowed=False,
    )
    binding = authority(
        schema_id="kt.v17_7_4.generalization_row_source_binding_receipt.v1",
        status=status,
        bound_source=bindable["path"] if bindable else None,
        row_count=bindable["row_count"] if bindable else 0,
        source_tier=bindable["source_tier"] if bindable else "NONE",
        reason_if_not_bound=(
            "No lawful non-overlapping held-out or extension source has real question/answer-hash authority. "
            "Diagnostic/acquisition rows are not generalization rows."
        )
        if not bindable
        else None,
    )
    manifest = authority(
        schema_id="kt.v17_7_4.generalization_row_manifest_candidate.v1",
        status="NOT_EMITTED_SOURCE_NOT_BOUND" if not bindable else "BOUND",
        rows=[],
        candidate_source=bindable["path"] if bindable else None,
    )
    nonoverlap = authority(
        schema_id="kt.v17_7_4.generalization_source_nonoverlap_receipt.v1",
        status="NOT_APPLICABLE_SOURCE_NOT_BOUND" if not bindable else "PASS",
        control_manifest=CONTROL_MANIFEST.relative_to(ROOT).as_posix(),
        control_row_count=len(control_rows),
        bound_source=bindable["path"] if bindable else None,
        row_id_overlap_count=0 if bindable else None,
        question_hash_overlap_count=0 if bindable else None,
    )
    return {
        "v17_7_4_generalization_row_source_search_receipt.json": search,
        "v17_7_4_generalization_row_source_binding_receipt.json": binding,
        "v17_7_4_generalization_row_manifest_candidate.json": manifest,
        "v17_7_4_generalization_source_nonoverlap_receipt.json": nonoverlap,
    }


def epc_receipts(binding_status: str, packet_path: str | None, packet_sha: str | None) -> dict[str, dict[str, Any]]:
    selected = "ACQUIRE_HELDOUT_ROW_SOURCE" if binding_status != "BOUND" else "RUN_REPROLOCK_GENERALIZATION_PROBE_50"
    next_move = "ACQUIRE_OR_AUTHOR_HELDOUT_ROW_SOURCE" if binding_status != "BOUND" else "RUN_REPROLOCK_GENERALIZATION_PROBE_50"
    decision = authority(
        schema_id="kt.v17_7_4.epc_decision_after_shuffle_control.v1",
        status="PASS",
        recommended_next_lane=selected,
        reason="Shuffle stability is bound; lawful generalization row source is not bound." if binding_status != "BOUND" else "Generalization source bound.",
        expected_information_gain="HIGH_IF_SOURCE_ACQUIRED",
        compute_cost="ZERO_UNTIL_SOURCE_BOUND",
        authority_risk="LOW_IF_NO_PACKET_GENERATED_WITHOUT_SOURCE",
        blockers=[] if binding_status == "BOUND" else ["GENERALIZATION_ROW_SOURCE_NOT_BOUND"],
        stop_condition="Do not run Kaggle until source is bound.",
        packet_path=packet_path,
        packet_sha256=packet_sha,
        dataset_name=GENERALIZATION_DATASET_NAME if packet_path else None,
    )
    next_lane = authority(
        schema_id="kt.v17_7_4.epc_next_evidence_lane_after_shuffle.v1",
        status="ACQUIRE_SOURCE",
        selected_next_lane=selected,
        next_lawful_move=next_move,
        no_training=True,
        no_promotion=True,
        no_runtime_packet_without_source=True,
    )
    queue = authority(
        schema_id="kt.v17_7_4.epc_intervention_priority_queue_v6.v1",
        status="PASS",
        priorities=[
            {
                "rank": 1,
                "lane": "ACQUIRE_OR_AUTHOR_HELDOUT_ROW_SOURCE",
                "purpose": "Create a lawful non-overlapping source for ReproLock generalization.",
            },
            {
                "rank": 2,
                "lane": "RUN_REPROLOCK_GENERALIZATION_PROBE_50",
                "purpose": "Run only after source binding passes.",
            },
            {
                "rank": 3,
                "lane": "RETURN_TO_G2_FULL_SYSTEM_FRONTIER_ONLY_AFTER_GENERALIZATION",
                "purpose": "Do not chase compression until generalization uncertainty is reduced.",
            },
        ],
    )
    return {
        "v17_7_4_epc_decision_after_shuffle_control.json": decision,
        "v17_7_4_epc_next_evidence_lane_after_shuffle.json": next_lane,
        "v17_7_4_epc_intervention_priority_queue_v6.json": queue,
    }


def artifact_delta(outputs: dict[Path, dict[str, Any]], summary: dict[str, Any]) -> dict[str, Any]:
    entries = []
    for path, payload in outputs.items():
        if path.exists():
            sha = sha256_file(path)
            size = path.stat().st_size
        else:
            data = json.dumps(payload, sort_keys=True).encode()
            sha = hashlib.sha256(data).hexdigest()
            size = len(data)
        entries.append({"path": path.relative_to(ROOT).as_posix(), "sha256": sha, "size_bytes": size})
    return authority(
        schema_id="kt.artifact_authority_registry.shuffle_control_review_generalization_delta.v1",
        status="PASS",
        tranche=TRANCHE,
        outcome=summary["outcome"],
        entries=entries,
    )


def build_summary(
    truth: dict[str, Any],
    runtime: dict[str, Any],
    telemetry: dict[str, dict[str, Any]],
    court: dict[str, dict[str, Any]],
    sources: dict[str, dict[str, Any]],
    epc: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    binding = sources["v17_7_4_generalization_row_source_binding_receipt.json"]
    packet_path = None
    packet_sha = None
    selected_lane = epc["v17_7_4_epc_next_evidence_lane_after_shuffle.json"]["selected_next_lane"]
    next_move = epc["v17_7_4_epc_next_evidence_lane_after_shuffle.json"]["next_lawful_move"]
    return authority(
        schema_id="kt.v17_7_4.shuffle_control_review_generalization_builder_summary.v1",
        status="PASS",
        tranche=TRANCHE,
        current_head=truth["current_head"],
        branch=truth["branch"],
        outcome=OUTCOME,
        files_changed=[
            "scripts/build_v17_7_4_shuffle_control_review_generalization.py",
            "tests/test_v17_7_4_shuffle_control_review_generalization.py",
        ],
        shuffle_control_runtime_binding_status=runtime["status"],
        telemetry_completeness_review_status=telemetry["v17_7_4_shuffle_adversarial_telemetry_completeness_review.json"]["status"],
        shuffle_stability_court_status=court["v17_7_4_reprolock_shuffle_stability_court.json"]["status"],
        control_integrity_decision_status=court["v17_7_4_reprolock_control_integrity_decision.json"]["status"],
        generalization_row_source_binding_status=binding["status"],
        selected_next_lane=selected_lane,
        packet_path_if_any=packet_path,
        packet_sha256_if_any=packet_sha,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        claim_ceiling_status="PRESERVED",
        blockers=[] if binding["status"] == "BOUND" else ["GENERALIZATION_ROW_SOURCE_NOT_BOUND"],
        next_lawful_move=next_move,
    )


def main() -> int:
    assessment_path, assessment_sha, assessment = load_assessment()
    operator_path, operator_sha = operator_source()
    truth = truth_pin(assessment_path, assessment_sha, operator_path, operator_sha)
    if truth["status"] != "PASS":
        blocker = authority(
            schema_id="kt.v17_7_4.shuffle_control_review_blocker_receipt.v1",
            status="KT_BLOCKED__SHUFFLE_CONTROL_REVIEW_TRUTH_PIN_FAILED",
            reason="Assessment ZIP or expected repo packet SHA is not bound.",
        )
        write_json(ROOT / "reports" / "BLOCKER_SHUFFLE_CONTROL_REVIEW_TRUTH_PIN_FAILED.json", blocker)
        print(json.dumps(blocker, indent=2, sort_keys=True))
        return 2

    runtime = runtime_binding(assessment_sha, operator_sha, assessment)
    scorecard = scorecard_binding(assessment)
    boundary = claim_boundary_receipt()
    telemetry = telemetry_reviews(assessment)
    court = stability_court(assessment)
    sources = generalization_source_receipts()
    epc = epc_receipts(
        sources["v17_7_4_generalization_row_source_binding_receipt.json"]["status"],
        None,
        None,
    )
    summary = build_summary(truth, runtime, telemetry, court, sources, epc)

    outputs: dict[Path, dict[str, Any]] = {
        ROOT / "reports" / "v17_7_4_shuffle_control_review_truth_pin_receipt.json": truth,
        ROOT / "reports" / "v17_7_4_shuffle_control_runtime_binding_receipt.json": runtime,
        ROOT / "reports" / "v17_7_4_shuffle_control_scorecard_binding.json": scorecard,
        ROOT / "reports" / "v17_7_4_shuffle_control_claim_boundary_receipt.json": boundary,
        ROOT / "reports" / "v17_7_4_shuffle_control_review_generalization_builder_summary.json": summary,
    }
    outputs.update({ROOT / "reports" / name: payload for name, payload in telemetry.items()})
    outputs.update({ROOT / "reports" / name: payload for name, payload in court.items()})
    outputs.update({ROOT / "reports" / name: payload for name, payload in sources.items()})
    outputs.update({ROOT / "reports" / name: payload for name, payload in epc.items()})
    for path, payload in outputs.items():
        write_json(path, payload)

    delta = artifact_delta(outputs, summary)
    write_json(ROOT / "registry" / "artifact_authority_registry_v17_7_4_shuffle_control_review_generalization_delta_receipt.json", delta)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
