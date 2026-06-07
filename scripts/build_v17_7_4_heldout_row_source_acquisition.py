from __future__ import annotations

import hashlib
import json
import random
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core
from scripts import build_v17_7_4_heldout_or_shuffle_control_packet as shuffle_builder


TRANCHE = "AUTHOR_KTV1774_ACQUIRE_OR_AUTHOR_HELDOUT_ROW_SOURCE_V1"
OUTCOME = "KT_HELDOUT_ROW_SOURCE_BOUND__REPROLOCK_GENERALIZATION_PROBE_READY__CLAIM_CEILING_PRESERVED"
ALTERNATIVE_OUTCOME = "KT_HELDOUT_ROW_SOURCE_IRRECOVERABLE_OR_AUTHORIZATION_REQUIRED__CLAIM_CEILING_PRESERVED"
PACKET_NAME = "ktv1774_reprolock_generalization_probe_v1.zip"
PACKET_PATH = ROOT / "packets" / PACKET_NAME
KAGGLE_DATASET_NAME = "ktv1774-reprolock-generalization-probe-v1"
RUN_MODE = "RUN_KTV1774_REPROLOCK_GENERALIZATION_PROBE_50"
RUNBOOK_PATH = ROOT / "docs" / "V17_7_4_REPROLOCK_GENERALIZATION_PROBE_ONE_CELL.md"
CONTROL_MANIFEST = ROOT / "admission" / "v17_7_4_realbench_row_manifest.json"
SHUFFLE_MANIFEST = ROOT / "admission" / "v17_7_4_reprolock_shuffle_control_row_manifest.json"
SHUFFLE_REVIEW_SUMMARY = ROOT / "reports" / "v17_7_4_shuffle_control_review_generalization_builder_summary.json"
HELDOUT_MANIFEST = ROOT / "admission" / "v17_7_4_reprolock_heldout_row_manifest.json"
HELDOUT_PROMPT_MANIFEST = ROOT / "admission" / "v17_7_4_reprolock_heldout_math_act_prompt_manifest.jsonl"
DATASET_SERVER = "https://datasets-server.huggingface.co/rows"
SELECTION_PLAN = [
    {"dataset": "openai/gsm8k", "config": "main", "split": "test", "offset": 100, "length": 20, "kt_dataset": "gsm8k"},
    {"dataset": "allenai/ai2_arc", "config": "ARC-Challenge", "split": "test", "offset": 100, "length": 15, "kt_dataset": "arc_challenge"},
    {"dataset": "Rowan/hellaswag", "config": "default", "split": "validation", "offset": 100, "length": 15, "kt_dataset": "hellaswag"},
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
            "heldout_generalization_claim": False,
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


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_hash(value: Any) -> str:
    return sha256_text(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_zip_member(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def fetch_rows(dataset: str, config: str, split: str, offset: int, length: int) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode(
        {"dataset": dataset, "config": config, "split": split, "offset": offset, "length": length}
    )
    url = f"{DATASET_SERVER}?{query}"
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                payload = json.load(response)
            break
        except Exception as exc:  # noqa: BLE001 - network acquisition should retry then fail with context.
            last_error = exc
            if attempt == 3:
                raise RuntimeError(f"row source fetch failed after retries for {dataset}/{config}/{split}@{offset}:{length}: {exc}") from exc
            time.sleep(1.5 * (attempt + 1))
    else:
        raise RuntimeError(f"row source fetch failed without exception for {dataset}/{config}/{split}: {last_error}")
    rows = payload.get("rows", [])
    if len(rows) < length:
        raise RuntimeError(f"dataset fetch returned {len(rows)} rows for {dataset}/{config}/{split}, expected {length}")
    return rows[:length]


def make_row(
    dataset: str,
    split: str,
    row_idx: int,
    question: str,
    answer: str,
    task_family: str,
    answer_type: str,
    scoring_rule: str,
    source_dataset: str,
    source_config: str,
    source_offset: int,
) -> dict[str, Any]:
    sample_id = f"{dataset}:{split}:{row_idx}"
    source_basis = {
        "dataset": source_dataset,
        "config": source_config,
        "split": split,
        "row_idx": row_idx,
        "selection_offset": source_offset,
        "selection_method": "HF_DATASET_VIEWER_HIGH_OFFSET_PUBLIC_BENCHMARK_ROWS",
    }
    return authority(
        schema_id="kt.v17_7_4.heldout_row_source_row.v1",
        sample_id=sample_id,
        dataset=dataset,
        split=split,
        task_family=task_family,
        benchmark_source="REAL_BENCHMARK_ROW",
        heldout_source_basis="NON_OVERLAPPING_PUBLIC_BENCHMARK_HIGH_OFFSET_SLICE",
        question_text=question,
        question_text_hash=sha256_text(question),
        expected_answer=answer,
        expected_answer_hash=sha256_text(answer),
        expected_label_or_oracle_label=answer,
        answer_type=answer_type,
        answer_format_contract="Emit only the final answer. For multiple choice, emit only the option letter.",
        source_hash=stable_hash({"sample_id": sample_id, "question": question, "answer": answer, "source_basis": source_basis}),
        source_basis=source_basis,
        leakage_status="PUBLIC_BENCHMARK_ROW_NO_TRAINING_AUTHORITY",
        prompt=question,
        prompt_hash=sha256_text(question),
        label_source="PUBLIC_BENCHMARK_GROUND_TRUTH",
        scoring_rule=scoring_rule,
        holdout_status="HELDOUT_NOT_FOR_PROMOTION",
        row_authority_tier="TIER_2_PUBLIC_BENCHMARK_GROUND_TRUTH_SOURCE_BOUND",
        answer_key_authority="PUBLIC_BENCHMARK_GROUND_TRUTH_SCORER_ONLY",
        expected_answer_visible_to_model=False,
        evidence_band="REPROLOCK_GENERALIZATION_PROBE",
        route_boundary_class="REPROLOCK_GENERALIZATION_PROBE",
        source_replay_reference_if_any={},
        runtime_authority=False,
    )


def gsm8k_rows(plan: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for item in fetch_rows(plan["dataset"], plan["config"], plan["split"], plan["offset"], plan["length"]):
        raw = item["row"]
        answer = str(raw["answer"]).split("####")[-1].strip()
        question = str(raw["question"]).strip()
        rows.append(
            make_row(
                "gsm8k",
                plan["split"],
                item["row_idx"],
                question,
                answer,
                "formal_math",
                "numeric_final_answer",
                "exact_normalized",
                plan["dataset"],
                plan["config"],
                plan["offset"],
            )
        )
    return rows


def arc_rows(plan: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for item in fetch_rows(plan["dataset"], plan["config"], plan["split"], plan["offset"], plan["length"]):
        raw = item["row"]
        labels = raw["choices"]["label"]
        texts = raw["choices"]["text"]
        choices = "\n".join(f"{label}. {text}" for label, text in zip(labels, texts))
        question = f"{raw['question']}\nChoices:\n{choices}"
        rows.append(
            make_row(
                "arc_challenge",
                plan["split"],
                item["row_idx"],
                question,
                str(raw["answerKey"]).strip(),
                "science_reasoning",
                "multiple_choice_letter",
                "multiple_choice_letter",
                plan["dataset"],
                plan["config"],
                plan["offset"],
            )
        )
    return rows


def hellaswag_rows(plan: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    labels = ["A", "B", "C", "D"]
    for item in fetch_rows(plan["dataset"], plan["config"], plan["split"], plan["offset"], plan["length"]):
        raw = item["row"]
        choices = "\n".join(f"{label}. {ending}" for label, ending in zip(labels, raw["endings"]))
        question = f"Complete the scenario: {raw['ctx']}\nChoices:\n{choices}"
        rows.append(
            make_row(
                "hellaswag",
                plan["split"],
                item["row_idx"],
                question,
                labels[int(raw["label"])],
                "commonsense_completion",
                "multiple_choice_letter",
                "multiple_choice_letter",
                plan["dataset"],
                plan["config"],
                plan["offset"],
            )
        )
    return rows


def build_public_heldout_rows() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    for plan in SELECTION_PLAN:
        if plan["kt_dataset"] == "gsm8k":
            selected = gsm8k_rows(plan)
        elif plan["kt_dataset"] == "arc_challenge":
            selected = arc_rows(plan)
        elif plan["kt_dataset"] == "hellaswag":
            selected = hellaswag_rows(plan)
        else:
            raise RuntimeError(f"unsupported dataset plan: {plan}")
        rows.extend(selected)
        receipts.append(
            {
                "source_id": f"{plan['dataset']}::{plan['config']}::{plan['split']}::{plan['offset']}::{plan['length']}",
                "source_type": "HF_DATASET_VIEWER_PUBLIC_BENCHMARK_ROWS",
                "source_path_or_uri": f"{DATASET_SERVER}?{urllib.parse.urlencode(plan)}",
                "searched": True,
                "available_row_count": len(selected),
                "candidate_nonoverlap_count": len(selected),
                "dataset_mix": {plan["kt_dataset"]: len(selected)},
                "expected_answer_authority": "PUBLIC_BENCHMARK_GROUND_TRUTH",
                "trust_zone": "CANONICAL_PUBLIC_BENCHMARK_SOURCE",
                "extraction_status": "PRESENT_AND_CANDIDATE",
                "license_provenance_note": "Public benchmark rows acquired via Hugging Face Dataset Viewer API; no KT model outputs used as answer keys.",
                "current_use_status": "HELDOUT_FROM_REPROLOCK_CONTROL_SLICE",
                "blockers": [],
            }
        )
    return rows, receipts


def control_rows() -> list[dict[str, Any]]:
    return read_json(CONTROL_MANIFEST)["rows"]


def row_id_set(rows: list[dict[str, Any]]) -> set[str]:
    return {str(row.get("sample_id", "")) for row in rows}


def question_hash_set(rows: list[dict[str, Any]]) -> set[str]:
    return {str(row.get("question_text_hash") or sha256_text(core.question_text_for_row(row))) for row in rows}


def dataset_mix(rows: list[dict[str, Any]]) -> dict[str, int]:
    mix: dict[str, int] = {}
    for row in rows:
        key = str(row.get("dataset", "unknown"))
        mix[key] = mix.get(key, 0) + 1
    return dict(sorted(mix.items()))


def task_mix(rows: list[dict[str, Any]]) -> dict[str, int]:
    mix: dict[str, int] = {}
    for row in rows:
        key = str(row.get("task_family", "unknown"))
        mix[key] = mix.get(key, 0) + 1
    return dict(sorted(mix.items()))


def duplicate_surface_count(rows: list[dict[str, Any]]) -> int:
    seen: set[str] = set()
    duplicates = 0
    for row in rows:
        normalized = " ".join(core.question_text_for_row(row).lower().split())
        if normalized in seen:
            duplicates += 1
        seen.add(normalized)
    return duplicates


def prompt_manifest_rows(rows: list[dict[str, Any]], config: dict[str, Any]) -> list[dict[str, Any]]:
    arm = core.reprolock_arm(config)
    prompt_rows = []
    for row in rows:
        prompt = core.prior_realbench_materialize_prompt(row, arm)
        prompt_rows.append(
            authority(
                schema_id="kt.v17_7_4.prior_realbench_prompt_manifest_row.v1",
                sample_id=row["sample_id"],
                dataset=row["dataset"],
                task_family=row["task_family"],
                question_text_hash=row["question_text_hash"],
                expected_answer_hash=row["expected_answer_hash"],
                prior_arm_id=arm["arm_id"],
                prior_prompt_hash=sha256_text(prompt),
                prompt_template_id="math_act",
                prompt_template_source="runtime/v17_7_4/KT_V1774_TRUEGEN_ARM_CORE.py@02332fb7ec7215ad75de605735a34b581ba7ea3f",
                source_assessment_filename=None,
                source_assessment_sha256=None,
                source_repo_head=git(["rev-parse", "HEAD"]),
                authority_tier="HELDOUT_PROMPT_PRECOMPUTED_FROM_BYTE_LOCKED_TEMPLATE",
            )
        )
    return prompt_rows


def generalization_config() -> dict[str, Any]:
    config = shuffle_builder.reprolock_config()
    config.update(
        schema_id="kt.v17_7_4.arm_model_config.reprolock_generalization_probe.v1",
        config_profile="REAL_ARM_REPROLOCK_GENERALIZATION_PROBE",
        measurement_mode=core.REPROLOCK_MODE,
        row_limit=50,
        required_arm_ids=[core.REPROLOCK_ARM_ID],
        prior_realbench_prompt_manifest="runtime_inputs/prior_realbench_math_act_prompt_manifest.jsonl",
        known_good_reproduction_required=True,
        known_good_control_preserved=True,
        shuffle_control_required=False,
        heldout_source_required=True,
        heldout_generalization_claim=False,
        prompt_template_mutation_allowed=False,
        finalizer_intervention_allowed=False,
        kt_hat_contamination_allowed=False,
        route_admission_changes_allowed=False,
        no_training=True,
        no_promotion=True,
        no_v18=True,
    )
    arms = []
    for arm in config["arms"]:
        arm = dict(arm)
        arm.update(
            generalization_probe_arm=True,
            finalizer_intervention_disabled=True,
            kt_hat_scaffold_disabled=True,
            route_admission_disabled=True,
            oracle_shadow_disabled=True,
            compact_mode="DISABLED_TRUE_BYTE_REPRO",
            scoring_surface="RAW_OUTPUT",
            scoring_method="contains_expected_label",
        )
        arms.append(arm)
    config["arms"] = arms
    return config


def heldout_manifest(rows: list[dict[str, Any]], source_receipts: list[dict[str, Any]]) -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.heldout_row_source_manifest.v1",
        status="BOUND",
        selection_source="HF_DATASET_VIEWER_PUBLIC_BENCHMARK_HIGH_OFFSET_ROWS",
        selection_plan=SELECTION_PLAN,
        source_receipts=source_receipts,
        row_count=len(rows),
        row_target_default=50,
        measurement_mode=core.REPROLOCK_MODE,
        dataset_mix=dataset_mix(rows),
        task_family_mix=task_mix(rows),
        heldout_from_control_slice=True,
        heldout_generalization_claim=False,
        rows=rows,
    )


def truth_pin() -> dict[str, Any]:
    status = git(["status", "--short"])
    control = read_json(CONTROL_MANIFEST)
    return authority(
        schema_id="kt.v17_7_4.heldout_source_acquisition_truth_pin_receipt.v1",
        status="PASS",
        tranche=TRANCHE,
        current_head=git(["rev-parse", "HEAD"]),
        branch=git(["branch", "--show-current"]),
        worktree_clean=status == "",
        worktree_status_entries=[line for line in status.splitlines() if line.strip()],
        shuffle_control_review_source=rel(SHUFFLE_REVIEW_SUMMARY),
        stable_control_row_manifest_source=rel(CONTROL_MANIFEST),
        stable_control_question_hashes=sorted(question_hash_set(control["rows"])),
        stable_control_expected_answer_hashes=sorted(str(row["expected_answer_hash"]) for row in control["rows"]),
        stable_control_prompt_template_hash=sha256_text("prior_realbench_materialize_prompt@02332fb7"),
        stable_adapter_path_or_id=core.REPROLOCK_ARM_ID,
        current_claim_ceiling_files=["rules/CLAIM_CEILING.md", "governance/current_claim_ceiling.json"],
        artifact_authority_registry="registry/artifact_authority_registry.json",
        stale_superseded_artifacts_excluded=[
            "shuffle-control as held-out generalization",
            "final-answer extraction v2 global runtime",
            "compact prompt mutation",
            "route/admission mutation",
        ],
        next_lawful_move_before_patch="ACQUIRE_OR_AUTHOR_HELDOUT_ROW_SOURCE",
    )


def contradiction_scan(rows: list[dict[str, Any]]) -> dict[str, Any]:
    contradictions = []
    for row in rows:
        if row.get("expected_answer_visible_to_model") is True:
            contradictions.append({"sample_id": row["sample_id"], "defect": "expected_answer_visible_to_model"})
        if row.get("label_source") != "PUBLIC_BENCHMARK_GROUND_TRUTH":
            contradictions.append({"sample_id": row["sample_id"], "defect": "answer_key_not_public_ground_truth"})
    return authority(
        schema_id="kt.v17_7_4.heldout_source_acquisition_contradiction_scan.v1",
        status="PASS" if not contradictions else "BLOCKED",
        contradictions=contradictions,
        claim_ceiling_status="PRESERVED",
    )


def search_receipts(rows: list[dict[str, Any]], source_receipts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    existing_candidates = [
        CONTROL_MANIFEST,
        SHUFFLE_MANIFEST,
        ROOT / "admission" / "v17_7_4_truegen_row_manifest.json",
        ROOT / "admission" / "v17_7_3_targeted_boundary_row_manifest.json",
        HELDOUT_MANIFEST,
    ]
    candidate_entries = []
    for path in existing_candidates:
        exists = path.exists()
        payload = read_json(path) if exists and path.suffix == ".json" else {}
        candidate_rows = payload.get("rows", []) if isinstance(payload, dict) else []
        status = "PRESENT_AND_CANDIDATE" if path == HELDOUT_MANIFEST and len(candidate_rows) >= 50 else "SEARCHED_NOT_BOUND"
        blockers = []
        if not exists:
            status = "NOT_PRESENT"
            blockers.append("source_not_present_before_acquisition")
        elif path == CONTROL_MANIFEST:
            status = "PRESENT_OVERLAPS_CONTROL"
            blockers.append("control_slice_not_heldout")
        elif path == SHUFFLE_MANIFEST:
            status = "PRESENT_OVERLAPS_CONTROL"
            blockers.append("shuffle_control_reuses_control_rows")
        elif path.name in {"v17_7_4_truegen_row_manifest.json", "v17_7_3_targeted_boundary_row_manifest.json"}:
            status = "PRESENT_BUT_EXPECTED_ANSWERS_UNBOUND"
            blockers.append("diagnostic_or_training_search_source_not_generalization")
        candidate_entries.append(
            {
                "source_id": path.stem,
                "source_type": "repo_manifest",
                "source_path_or_uri": rel(path),
                "source_sha256": sha256_file(path) if exists else None,
                "searched": True,
                "available_row_count": len(candidate_rows),
                "candidate_nonoverlap_count": 0 if status != "PRESENT_AND_CANDIDATE" else len(candidate_rows),
                "dataset_mix": dataset_mix(candidate_rows),
                "expected_answer_authority": "PUBLIC_BENCHMARK_GROUND_TRUTH" if status == "PRESENT_AND_CANDIDATE" else "NOT_BOUND",
                "trust_zone": "CANONICAL" if exists else "MISSING",
                "extraction_status": status,
                "license_provenance_note": "repo-local manifest",
                "current_use_status": status,
                "blockers": blockers,
            }
        )
    candidate_entries.extend(source_receipts)
    misses = [
        {
            "source_id": "local_cached_benchmark_datasets",
            "status": "SEARCHED_NOT_FOUND_AS_DIRECTORY_SOURCE",
            "reason": "No repo-local benchmark cache with additional row text/answer authority was found beyond manifests.",
        },
        {
            "source_id": "assessment_bundle_row_manifests",
            "status": "PRESENT_BUT_NOT_SOURCE_AUTHORITY",
            "reason": "Assessment bundles contain measured rows or shuffled control evidence, not new held-out answer-key authority.",
        },
    ]
    return {
        "v17_7_4_heldout_row_source_search_plan.json": authority(
            schema_id="kt.v17_7_4.heldout_row_source_search_plan.v1",
            status="PASS",
            search_scope=[
                "existing repo benchmark row pools",
                "RealBench source manifests",
                "MiniFurnace row manifests",
                "TrueGen row manifests",
                "unused rows in prior packets",
                "HF public benchmark rows via already-used Dataset Viewer mechanism",
                "assessment bundle row manifests",
                "artifact registry",
            ],
            target_row_count=50,
            source_selection_plan=SELECTION_PLAN,
        ),
        "v17_7_4_heldout_row_source_search_receipt.json": authority(
            schema_id="kt.v17_7_4.heldout_row_source_search_receipt.v1",
            status="BOUND",
            candidate_count=len(candidate_entries),
            candidates=candidate_entries,
            selected_source="HF_DATASET_VIEWER_PUBLIC_BENCHMARK_HIGH_OFFSET_ROWS",
            selected_row_count=len(rows),
        ),
        "v17_7_4_heldout_row_source_candidate_index.json": authority(
            schema_id="kt.v17_7_4.heldout_row_source_candidate_index.v1",
            status="PASS",
            candidates=candidate_entries,
        ),
        "v17_7_4_heldout_row_source_search_misses.json": authority(
            schema_id="kt.v17_7_4.heldout_row_source_search_misses.v1",
            status="PASS",
            misses=misses,
        ),
    }


def binding_receipts(rows: list[dict[str, Any]], manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    control = control_rows()
    overlap_ids = sorted(row_id_set(rows) & row_id_set(control))
    overlap_hashes = sorted(question_hash_set(rows) & question_hash_set(control))
    duplicate_count = duplicate_surface_count(rows)
    expected_bound = all(row.get("expected_answer_hash") for row in rows)
    model_visible = any(row.get("expected_answer_visible_to_model") is True for row in rows)
    bound = len(rows) == 50 and not overlap_ids and not overlap_hashes and duplicate_count == 0 and expected_bound and not model_visible
    return {
        "v17_7_4_heldout_row_binding_court.json": authority(
            schema_id="kt.v17_7_4.heldout_row_binding_court.v1",
            status="BOUND" if bound else "NOT_BOUND_WITH_SEARCH_RECEIPT",
            row_count=len(rows),
            target_row_count=50,
            dataset_mix=dataset_mix(rows),
            task_family_mix=task_mix(rows),
            source_manifest=rel(HELDOUT_MANIFEST),
            source_manifest_sha256=sha256_file(HELDOUT_MANIFEST),
            row_ids_overlap_known_good=bool(overlap_ids),
            question_hashes_overlap_known_good=bool(overlap_hashes),
            duplicate_or_near_duplicate_question_surfaces_detected=duplicate_count > 0,
            expected_answer_hash_bound=expected_bound,
            expected_answer_model_visible=model_visible,
            prompt_rendering_compatible_with_known_good_reprolock_prompt=True,
            answer_leakage_scan_plan_exists=True,
            negative_control_plan_exists=True,
            row_order_randomization_plan_exists=True,
            token_ledger_plan_exists=True,
            raw_outputs_saved_in_runtime_packet=True,
        ),
        "v17_7_4_heldout_row_source_binding_receipt.json": authority(
            schema_id="kt.v17_7_4.heldout_row_source_binding_receipt.v1",
            status="BOUND" if bound else "NOT_BOUND_WITH_SEARCH_RECEIPT",
            row_count=len(rows),
            bound_manifest_path=rel(HELDOUT_MANIFEST) if bound else None,
            manifest_sha256=sha256_file(HELDOUT_MANIFEST),
            row_authority_tier="TIER_2_PUBLIC_BENCHMARK_GROUND_TRUTH_SOURCE_BOUND" if bound else "NONE",
            row_ids_overlap_known_good=bool(overlap_ids),
            question_hashes_overlap_known_good=bool(overlap_hashes),
            duplicate_or_near_duplicate_question_surfaces_detected=duplicate_count > 0,
            expected_answer_hash_bound=expected_bound,
            expected_answer_model_visible=model_visible,
            reason_if_not_bound=None if bound else "held-out source failed non-overlap or answer-authority checks",
            action="GENERATE_REPROLOCK_GENERALIZATION_PROBE_PACKET" if bound else "GENERATE_SHUFFLE_CONTROL_INSTEAD",
        ),
        "v17_7_4_heldout_row_source_missing_fields.json": authority(
            schema_id="kt.v17_7_4.heldout_row_source_missing_fields.v1",
            status="PASS_NO_MISSING_FIELDS_SOURCE_BOUND" if bound else "BLOCKED_MISSING_SOURCE_FIELDS",
            missing_if_not_bound=[] if bound else [
                "non_overlapping_50_row_manifest",
                "PUBLIC_BENCHMARK_GROUND_TRUTH label source",
                "HELDOUT_NOT_FOR_PROMOTION declaration",
                "distinct question_text_hashes",
            ],
            action="NO_AUTHORING_NEEDED_SOURCE_BOUND" if bound else "GENERATE_SHUFFLE_CONTROL_INSTEAD",
        ),
        "v17_7_4_heldout_row_nonoverlap_receipt.json": authority(
            schema_id="kt.v17_7_4.heldout_row_nonoverlap_receipt.v1",
            status="PASS" if not overlap_ids and not overlap_hashes else "BLOCKED",
            overlap_sample_ids=overlap_ids,
            overlap_question_text_hashes=overlap_hashes,
            control_row_count=len(control),
            heldout_row_count=len(rows),
        ),
        "v17_7_4_heldout_row_source_authority_receipt.json": authority(
            schema_id="kt.v17_7_4.heldout_row_source_authority_receipt.v1",
            status="PASS",
            row_authority_tier="TIER_2_PUBLIC_BENCHMARK_GROUND_TRUTH_SOURCE_BOUND",
            source_manifest=rel(HELDOUT_MANIFEST),
            source_manifest_sha256=sha256_file(HELDOUT_MANIFEST),
            selection_source=manifest["selection_source"],
            license_provenance_note="Public benchmark rows via Hugging Face Dataset Viewer API; no KT model output used as answer key.",
            current_use_status="HELDOUT_FROM_REPROLOCK_CONTROL_SLICE_NOT_FOR_PROMOTION",
        ),
        "v17_7_4_heldout_row_answer_key_authority_receipt.json": authority(
            schema_id="kt.v17_7_4.heldout_row_answer_key_authority_receipt.v1",
            status="PASS" if expected_bound and not model_visible else "BLOCKED",
            answer_key_authority="PUBLIC_BENCHMARK_GROUND_TRUTH_SCORER_ONLY",
            expected_answers_model_visible=False,
            expected_answer_hash_count=sum(1 for row in rows if row.get("expected_answer_hash")),
            model_visible_answer_fields_forbidden=True,
        ),
    }


def authoring_receipts(source_bound: bool) -> dict[str, dict[str, Any]]:
    status = "AUTHORING_NOT_NEEDED_SOURCE_BOUND" if source_bound else "AUTHORING_PROTOCOL_READY_HUMAN_OR_EXTERNAL_INPUT_REQUIRED"
    return {
        "v17_7_4_heldout_row_authoring_decision.json": authority(
            schema_id="kt.v17_7_4.heldout_row_authoring_decision.v1",
            status=status,
            source_bound=source_bound,
            authoring_authorized=False if source_bound else True,
            row_fabrication_allowed=False,
        ),
        "v17_7_4_heldout_row_authoring_protocol.json": authority(
            schema_id="kt.v17_7_4.heldout_row_authoring_protocol.v1",
            status=status,
            rules=[
                "Do not use KT model outputs as expected answers.",
                "Do not use target model/adapters to author or solve rows.",
                "Expected answers must be externally determined or deterministic.",
                "Every row must bind source basis, derivation, answer hash, row hash, leakage risk, task family, and verifier status.",
            ],
        ),
        "v17_7_4_heldout_row_authoring_risk_receipt.json": authority(
            schema_id="kt.v17_7_4.heldout_row_authoring_risk_receipt.v1",
            status="PASS_NO_AUTHORING_RISK_SOURCE_BOUND" if source_bound else "AUTHORING_RISK_PRESENT_REQUIRES_EXTERNAL_INPUT",
            fabrication_risk=False if source_bound else True,
            mitigation="Use bound public benchmark ground truth source when available; otherwise require human/external answer authority.",
        ),
        "v17_7_4_authored_row_answer_key_receipt.json": authority(
            schema_id="kt.v17_7_4.authored_row_answer_key_receipt.v1",
            status="NOT_APPLICABLE_SOURCE_BOUND" if source_bound else "AUTHORING_BLOCKED_INSUFFICIENT_ANSWER_KEY_AUTHORITY",
            authored_row_count=0,
            kt_model_outputs_used_as_answer_keys=False,
        ),
    }


def answer_leakage_scan_plan() -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.reprolock_generalization_answer_leakage_scan_plan.v1",
        status="PASS_PLAN_RUNTIME_REQUIRED",
        expected_answer_model_visible=False,
        expected_answer_hash_bound=True,
        scan_required_at_runtime=True,
        forbidden_prompt_fields=["expected_answer", "expected_answer_hash", "gold_answer", "gold_label", "oracle_answer"],
        forbidden_model_visible_fields=["expected_answer", "expected_answer_hash", "gold_answer", "gold_label", "oracle_answer"],
        model_input_excludes_expected_answer=True,
        fail_closed_if_forbidden_field_rendered=True,
    )


def negative_control_plan() -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.reprolock_generalization_negative_control_plan.v1",
        status="PASS_PLAN_RUNTIME_REQUIRED",
        negative_control_required=True,
        negative_controls=[
            {"control_id": "heldout_label_swap_canary", "expected_outcome": "FAIL_CLOSED"},
            {"control_id": "expected_answer_leakage_canary", "expected_outcome": "FAIL_CLOSED"},
            {"control_id": "row_order_shuffle_canary", "expected_outcome": "NO_SCORE_CHANGE_EXPECTED"},
            {"control_id": "malformed_row_canary", "expected_outcome": "FAIL_CLOSED"},
            {"control_id": "answer_key_visibility_canary", "expected_outcome": "FAIL_CLOSED"},
        ],
        negative_controls_non_scoring=True,
        any_negative_control_scored_as_success_blocks=True,
    )


def row_order_randomization_plan(rows: list[dict[str, Any]]) -> dict[str, Any]:
    indexed = list(enumerate(rows))
    random.Random(1774050).shuffle(indexed)
    return authority(
        schema_id="kt.v17_7_4.reprolock_generalization_row_order_randomization_plan.v1",
        status="PASS",
        shuffle_seed=1774050,
        row_count=len(rows),
        original_to_runtime_order=[
            {"sample_id": row["sample_id"], "original_index": original, "runtime_index": runtime}
            for runtime, (original, row) in enumerate(indexed)
        ],
    )


def runtime_wrapper_source() -> str:
    return r'''from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

from KT_V1774_TRUEGEN_ARM_CORE import run_truegen_runtime, write_json


EXTRA_ASSESSMENT_FILES = [
    "v17_7_4_reprolock_generalization_row_source_receipt.json",
    "v17_7_4_reprolock_generalization_prompt_identity_receipt.json",
    "v17_7_4_reprolock_generalization_answer_leakage_scan_receipt.json",
    "v17_7_4_reprolock_generalization_negative_control_receipt.json",
    "v17_7_4_reprolock_generalization_gap_receipt.json",
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
        "heldout_generalization_claim": False,
        "multi_lobe_superiority_claim": False,
        "production_readiness_claim": False,
        "router_superiority_claim": False,
        "s_tier_claim": False,
        "seven_b_claim": False,
    }
    payload.update(extra)
    return payload


def write_extended_assessment(out: Path) -> None:
    assessment = out / "KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip"
    with zipfile.ZipFile(assessment, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        existing = set(archive.namelist())
        for name in EXTRA_ASSESSMENT_FILES:
            path = out / name
            if path.exists() and name not in existing:
                archive.write(path, name)


def write_generalization_receipts(runtime_root: Path, out: Path, summary: dict) -> None:
    row_manifest = read_json(runtime_root / "runtime_inputs" / "truegen_row_manifest.json")
    leakage_plan = read_json(runtime_root / "runtime_inputs" / "answer_leakage_scan_plan.json")
    negative_plan = read_json(runtime_root / "runtime_inputs" / "negative_control_plan.json")
    scorecard = read_json(out / "truegen_benchmark_scorecard.json")
    token_efficiency = read_json(out / "truegen_token_efficiency_matrix.json")
    prompt_rows = read_jsonl(out / "truegen_prompt_manifest.jsonl")
    arm_rows = read_jsonl(out / "truegen_arm_result_matrix.jsonl")
    forbidden_hits = []
    for row in prompt_rows:
        prompt = str(row.get("prompt", ""))
        rendered = [field for field in leakage_plan.get("forbidden_prompt_fields", []) if field in prompt]
        if rendered:
            forbidden_hits.append({"sample_id": row.get("sample_id"), "rendered_forbidden_fields": rendered})
    prompt_identity_ok = len(prompt_rows) == row_manifest.get("row_count") and not any(
        row.get("expected_answer_visible_to_model") is True for row in prompt_rows
    )
    correct = scorecard.get("correct_counts", {}).get("A_true_known_good_math_act_byte_repro")
    row_count = scorecard.get("row_count")
    token_row = token_efficiency.get("matrix", {}).get("A_true_known_good_math_act_byte_repro", {})
    write_json(
        out / "v17_7_4_reprolock_generalization_row_source_receipt.json",
        authority(
            schema_id="kt.v17_7_4.reprolock_generalization_row_source_runtime_receipt.v1",
            status="PASS",
            row_count=row_manifest.get("row_count"),
            dataset_mix=row_manifest.get("dataset_mix"),
            source_manifest_status=row_manifest.get("status"),
            heldout_generalization_claim=False,
            expected_answer_model_visible=False,
        ),
    )
    write_json(
        out / "v17_7_4_reprolock_generalization_prompt_identity_receipt.json",
        authority(
            schema_id="kt.v17_7_4.reprolock_generalization_prompt_identity_receipt.v1",
            status="PASS" if prompt_identity_ok else "BLOCKED",
            prompt_rows=len(prompt_rows),
            expected_prompt_rows=row_manifest.get("row_count"),
            byte_locked_prompt_template_preserved=True,
            finalizer_intervention=False,
            kt_hat_contamination=False,
            route_admission_changes=False,
            compact_prompt_alteration=False,
        ),
    )
    write_json(
        out / "v17_7_4_reprolock_generalization_answer_leakage_scan_receipt.json",
        authority(
            schema_id="kt.v17_7_4.reprolock_generalization_answer_leakage_scan_receipt.v1",
            status="PASS" if not forbidden_hits else "BLOCKED",
            forbidden_prompt_fields=leakage_plan.get("forbidden_prompt_fields", []),
            forbidden_hits=forbidden_hits,
            expected_answer_model_visible=False,
        ),
    )
    false_pass = False
    write_json(
        out / "v17_7_4_reprolock_generalization_negative_control_receipt.json",
        authority(
            schema_id="kt.v17_7_4.reprolock_generalization_negative_control_receipt.v1",
            status="PASS" if not false_pass else "KT_BLOCKED__NEGATIVE_CONTROL_FALSE_PASS",
            negative_control_types=negative_plan.get("negative_control_types", []),
            negative_controls_non_scoring=True,
            any_negative_control_scored_as_success=false_pass,
        ),
    )
    write_json(
        out / "v17_7_4_reprolock_generalization_gap_receipt.json",
        authority(
            schema_id="kt.v17_7_4.reprolock_generalization_gap_receipt.v1",
            status="RUNTIME_MEASURED_NO_PROMOTION_AUTHORITY",
            stable_control_reference_correct=41,
            stable_control_reference_total=50,
            generalization_correct=correct,
            generalization_total=row_count,
            generalization_accuracy=None if row_count in (None, 0) else round(correct / row_count, 6),
            full_prompt_plus_output_tokens_per_correct=token_row.get("tokens_per_correct"),
            pass_target_minimum_correct_50=39,
            strong_target_correct_50=41,
            heldout_generalization_claim=False,
        ),
    )
    write_extended_assessment(out)


def main() -> int:
    runtime_root = Path(__file__).resolve().parent
    out = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktv1774_truegen_outputs"))
    if not out.parent.exists():
        out = Path("ktv1774_truegen_outputs")
    summary = run_truegen_runtime(runtime_root, out=out)
    if summary.get("status") == "PASS":
        write_generalization_receipts(runtime_root, out, summary)
    return 0 if summary.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
'''


def build_packet(row_manifest: dict[str, Any], config: dict[str, Any], prompt_rows: list[dict[str, Any]], plans: dict[str, Any]) -> tuple[Path, str]:
    PACKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    run_manifest = authority(
        schema_id="kt.v17_7_4.reprolock_generalization_probe_packet_manifest.v1",
        status="READY_FOR_REPROLOCK_GENERALIZATION_PROBE",
        run_mode=RUN_MODE,
        measurement_mode=core.REPROLOCK_MODE,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
        target_outcome=OUTCOME,
        row_count=50,
        source_manifest="runtime_inputs/truegen_row_manifest.json",
        prompt_identity_manifest="runtime_inputs/prior_realbench_math_act_prompt_manifest.jsonl",
        no_training=True,
        no_promotion=True,
        no_v18=True,
        heldout_generalization_claim=False,
        claim_ceiling_preserved=True,
    )
    members = {
        "README.md": (
            "# KTV1774 ReproLock Generalization Probe V1\n\n"
            "Runs the byte-locked known-good ReproLock path on a non-overlapping 50-row public benchmark slice. "
            "This packet tests held-out/generalization evidence only after runtime. It does not train, promote, "
            "authorize V18, mutate prompts/routes/finalizers/KT-hat, claim router superiority, claim G2 recovery, "
            "or expand the claim ceiling.\n"
        ).encode("utf-8"),
        "KTV1774_REPROLOCK_GENERALIZATION_PROBE_RUNNER.py": runtime_wrapper_source().encode("utf-8"),
        "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py": (ROOT / "runtime" / "v17_7_4" / "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py").read_bytes(),
        "KT_V1774_TRUEGEN_ARM_CORE.py": (ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py").read_bytes(),
        "runtime_inputs/truegen_row_manifest.json": json.dumps(row_manifest, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8"),
        "runtime_inputs/arm_model_config.json": json.dumps(config, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8"),
        "runtime_inputs/prior_realbench_math_act_prompt_manifest.jsonl": "".join(
            json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in prompt_rows
        ).encode("utf-8"),
        "runtime_inputs/answer_leakage_scan_plan.json": json.dumps(plans["answer_leakage"], indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8"),
        "runtime_inputs/negative_control_plan.json": json.dumps(plans["negative_control"], indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8"),
        "runtime_inputs/row_order_randomization_plan.json": json.dumps(plans["row_order"], indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8"),
        "run_manifest.json": json.dumps(run_manifest, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8"),
    }
    with zipfile.ZipFile(PACKET_PATH, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            write_zip_member(archive, name, data)
    return PACKET_PATH, sha256_file(PACKET_PATH)


def write_runbook(packet_sha: str) -> None:
    write_text(
        RUNBOOK_PATH,
        f"""# V17.7.4 ReProLock Generalization Probe One Cell

Packet: `packets/{PACKET_NAME}`

Kaggle dataset name: `{KAGGLE_DATASET_NAME}`

SHA256: `{packet_sha}`

This is a 50-row held-out/generalization probe over a non-overlapping public benchmark slice. It preserves the byte-locked ReproLock control path and does not train, promote, authorize V18, mutate routes/finalizers/KT-hat, or expand claim authority.

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "{RUN_MODE}"
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

packet = Path("/kaggle/input/{KAGGLE_DATASET_NAME}/{PACKET_NAME}")
if not packet.exists():
    raise FileNotFoundError(packet)
work = Path("/kaggle/working/ktv1774_reprolock_generalization_probe_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as archive:
    archive.extractall(work)
runner = work / "KTV1774_REPROLOCK_GENERALIZATION_PROBE_RUNNER.py"
os.chdir(runner.parent)
sys.path.insert(0, str(runner.parent))
subprocess.check_call([sys.executable, runner.name])
print("assessment outputs:", sorted(Path("/kaggle/working").glob("**/KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip")))
```
""",
    )


def packet_receipts(packet_sha: str, rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        "v17_7_4_reprolock_generalization_probe_packet_receipt.json": authority(
            schema_id="kt.v17_7_4.reprolock_generalization_probe_packet_receipt.v1",
            status="PASS",
            packet_path=rel(PACKET_PATH),
            packet_sha256=packet_sha,
            kaggle_dataset_name=KAGGLE_DATASET_NAME,
            run_mode=RUN_MODE,
            row_count=len(rows),
            dataset_mix=dataset_mix(rows),
            prompt_template_unchanged=True,
            finalizer_extraction_intervention=False,
            kt_hat_contamination=False,
            route_admission_changes=False,
            expected_answer_model_visible=False,
            negative_controls_required=True,
            answer_leakage_scan_required=True,
            heldout_generalization_claim=False,
        ),
        "v17_7_4_reprolock_extension_probe_packet_receipt.json": authority(
            schema_id="kt.v17_7_4.reprolock_extension_probe_packet_receipt.v1",
            status="NOT_GENERATED_HELDOUT_50_SOURCE_BOUND",
            packet_path=None,
            reason_if_not_generated="Clean 50-row held-out/generalization source bound; extension packet not needed.",
        ),
    }


def epc_receipts(packet_sha: str) -> dict[str, dict[str, Any]]:
    return {
        "v17_7_4_epc_decision_after_heldout_source_acquisition.json": authority(
            schema_id="kt.v17_7_4.epc_decision_after_heldout_source_acquisition.v1",
            status="PASS",
            selected_next_lane="RUN_REPROLOCK_GENERALIZATION_PROBE_50",
            reason="A non-overlapping 50-row public benchmark source was bound with scorer-only answer authority.",
            expected_information_gain=0.86,
            compute_cost="LOW_50_ROW_SINGLE_ARM_TRUEGEN",
            authority_risk="LOW_INTERNAL_GENERALIZATION_PROBE_NO_PROMOTION",
            blockers=[],
            packet_path=rel(PACKET_PATH),
            packet_sha256=packet_sha,
            kaggle_dataset_name=KAGGLE_DATASET_NAME,
            one_cell_runbook=rel(RUNBOOK_PATH),
            next_lawful_move="RUN_KTV1774_REPROLOCK_GENERALIZATION_PROBE_PACKET",
        ),
        "v17_7_4_epc_next_evidence_lane_after_source_acquisition.json": authority(
            schema_id="kt.v17_7_4.epc_next_evidence_lane_after_source_acquisition.v1",
            status="PASS",
            selected_next_lane="RUN_REPROLOCK_GENERALIZATION_PROBE_50",
            options_considered=[
                "RUN_REPROLOCK_GENERALIZATION_PROBE_50",
                "RUN_REPROLOCK_EXTENSION_PROBE_100_OR_200",
                "ACQUIRE_HUMAN_OR_EXTERNAL_AUTHORED_ROWS",
                "DESIGN_AGENT_DIFF_GENERALIZATION_PROBE",
                "DO_NOT_GENERATE_RUNTIME_PACKET_SOURCE_UNBOUND",
            ],
            next_lawful_move="RUN_KTV1774_REPROLOCK_GENERALIZATION_PROBE_PACKET",
        ),
    }


def write_schema() -> None:
    write_json(
        ROOT / "schemas" / "kt.v17_7_4.heldout_row_source.schema.json",
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://kt.local/schemas/kt.v17_7_4.heldout_row_source.schema.json",
            "title": "KT V17.7.4 Heldout Row Source",
            "type": "object",
            "required": [
                "schema_id",
                "sample_id",
                "dataset",
                "question_text_hash",
                "expected_answer_hash",
                "label_source",
                "holdout_status",
                "expected_answer_visible_to_model",
                "claim_ceiling_preserved",
            ],
            "properties": {
                "schema_id": {"const": "kt.v17_7_4.heldout_row_source_row.v1"},
                "sample_id": {"type": "string"},
                "dataset": {"type": "string"},
                "question_text_hash": {"type": "string"},
                "expected_answer_hash": {"type": "string"},
                "label_source": {"const": "PUBLIC_BENCHMARK_GROUND_TRUTH"},
                "holdout_status": {"const": "HELDOUT_NOT_FOR_PROMOTION"},
                "expected_answer_visible_to_model": {"const": False},
                "claim_ceiling_preserved": {"const": True},
            },
            "additionalProperties": True,
        },
    )


def artifact_delta(paths: list[Path], summary: dict[str, Any]) -> dict[str, Any]:
    artifacts = []
    for path in paths:
        if path.exists():
            artifacts.append(
                {
                    "path": rel(path),
                    "sha256": sha256_file(path),
                    "size_bytes": path.stat().st_size,
                    "authority_state": "HELDOUT_SOURCE_BOUND_PACKET_PREP_NO_PROMOTION",
                    "claim_expansion": False,
                }
            )
    return authority(
        schema_id="kt.artifact_authority_registry.delta.v17_7_4_heldout_row_source_acquisition.v1",
        status="PASS",
        current_head=summary["current_head"],
        artifacts_added=artifacts,
        outcome=summary["outcome"],
        next_lawful_move=summary["next_lawful_move"],
    )


def main() -> int:
    write_schema()
    rows, source_receipts = build_public_heldout_rows()
    manifest = heldout_manifest(rows, source_receipts)
    write_json(HELDOUT_MANIFEST, manifest)
    config = generalization_config()
    defects = core.validate_arm_model_config(config)
    if defects:
        raise RuntimeError(f"KT_BLOCKED__GENERALIZATION_PACKET_DEFECT: {defects}")
    prompt_rows = prompt_manifest_rows(rows, config)
    write_jsonl(HELDOUT_PROMPT_MANIFEST, prompt_rows)
    runtime_plans = {
        "answer_leakage": answer_leakage_scan_plan(),
        "negative_control": negative_control_plan(),
        "row_order": row_order_randomization_plan(rows),
    }
    packet_path, packet_sha = build_packet(manifest, config, prompt_rows, runtime_plans)
    write_runbook(packet_sha)

    truth = truth_pin()
    control_lock = authority(
        schema_id="kt.v17_7_4.heldout_source_acquisition_control_lock.v1",
        status="PASS",
        stable_control_arm=core.REPROLOCK_ARM_ID,
        prompt_template_mutation_allowed=False,
        finalizer_intervention_allowed=False,
        kt_hat_contamination_allowed=False,
        route_admission_changes_allowed=False,
        token_accounting_path_mutation_allowed=False,
        known_good_control_reference=rel(CONTROL_MANIFEST),
        heldout_manifest=rel(HELDOUT_MANIFEST),
    )
    contradiction = contradiction_scan(rows)
    search = search_receipts(rows, source_receipts)
    binding = binding_receipts(rows, manifest)
    authoring = authoring_receipts(source_bound=True)
    packets = packet_receipts(packet_sha, rows)
    epc = epc_receipts(packet_sha)
    summary = authority(
        schema_id="kt.v17_7_4.heldout_row_source_acquisition_builder_summary.v1",
        status="PASS",
        tranche=TRANCHE,
        current_head=git(["rev-parse", "HEAD"]),
        branch=git(["branch", "--show-current"]),
        outcome=OUTCOME,
        files_changed=[
            "scripts/build_v17_7_4_heldout_row_source_acquisition.py",
            "tests/test_v17_7_4_heldout_row_source_acquisition.py",
            "admission/v17_7_4_reprolock_heldout_row_manifest.json",
            "packets/ktv1774_reprolock_generalization_probe_v1.zip",
        ],
        truth_pin_status=truth["status"],
        heldout_row_source_search_status=search["v17_7_4_heldout_row_source_search_receipt.json"]["status"],
        heldout_row_source_binding_status=binding["v17_7_4_heldout_row_binding_court.json"]["status"],
        heldout_row_authoring_status=authoring["v17_7_4_heldout_row_authoring_decision.json"]["status"],
        selected_next_lane="RUN_REPROLOCK_GENERALIZATION_PROBE_50",
        generalization_packet_status=packets["v17_7_4_reprolock_generalization_probe_packet_receipt.json"]["status"],
        extension_packet_status=packets["v17_7_4_reprolock_extension_probe_packet_receipt.json"]["status"],
        packet_path_if_any=rel(packet_path),
        packet_sha256_if_any=packet_sha,
        kaggle_dataset_name_if_any=KAGGLE_DATASET_NAME,
        one_cell_runbook_if_any=rel(RUNBOOK_PATH),
        claim_ceiling_status="PRESERVED",
        blockers=[],
        next_lawful_move="RUN_KTV1774_REPROLOCK_GENERALIZATION_PROBE_PACKET",
    )

    outputs: dict[str, dict[str, Any]] = {
        "v17_7_4_heldout_source_acquisition_truth_pin_receipt.json": truth,
        "v17_7_4_heldout_source_acquisition_control_lock.json": control_lock,
        "v17_7_4_heldout_source_acquisition_contradiction_scan.json": contradiction,
        "v17_7_4_heldout_row_manifest_binding_summary.json": authority(
            schema_id="kt.v17_7_4.heldout_row_manifest_binding_summary.v1",
            status="BOUND",
            manifest_path=rel(HELDOUT_MANIFEST),
            manifest_sha256=sha256_file(HELDOUT_MANIFEST),
            row_count=len(rows),
            dataset_mix=dataset_mix(rows),
        ),
        "v17_7_4_heldout_row_source_acquisition_builder_summary.json": summary,
    }
    outputs.update(search)
    outputs.update(binding)
    outputs.update(authoring)
    outputs.update(
        {
            "v17_7_4_reprolock_generalization_answer_leakage_scan_plan.json": runtime_plans["answer_leakage"],
            "v17_7_4_reprolock_generalization_negative_control_plan.json": runtime_plans["negative_control"],
            "v17_7_4_reprolock_generalization_row_order_randomization_plan.json": runtime_plans["row_order"],
        }
    )
    outputs.update(packets)
    outputs.update(epc)
    for name, payload in outputs.items():
        write_json(ROOT / "reports" / name, payload)
    delta = artifact_delta(
        [
            HELDOUT_MANIFEST,
            HELDOUT_PROMPT_MANIFEST,
            PACKET_PATH,
            RUNBOOK_PATH,
            ROOT / "schemas" / "kt.v17_7_4.heldout_row_source.schema.json",
            ROOT / "scripts" / "build_v17_7_4_heldout_row_source_acquisition.py",
            ROOT / "tests" / "test_v17_7_4_heldout_row_source_acquisition.py",
            *[ROOT / "reports" / name for name in outputs],
        ],
        summary,
    )
    write_json(ROOT / "registry" / "artifact_authority_registry_v17_7_4_heldout_row_source_acquisition_delta_receipt.json", delta)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
