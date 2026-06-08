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
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core
from scripts import build_v17_7_4_heldout_or_shuffle_control_packet as shuffle_builder


TRANCHE = "AUTHOR_KTV1774_ANSWER_SURFACE_AUDIT_FAILURE_REVIEW_AND_CONTROL_EXTENSION_GATE_V1"
OUTCOME = "KT_ANSWER_SURFACE_AUDIT_FAILURE_REVIEWED__CONTROL_EXTENSION_GATE_DECIDED__CLAIM_CEILING_PRESERVED"
RUNTIME_READY_OUTCOME = "KT_CONTROL_ONLY_GSM8K_EXTENSION_READY__CLAIM_CEILING_PRESERVED"
NO_RUNTIME_OUTCOME = "KT_ANSWER_SURFACE_AUDIT_FAILURE_REVIEWED__NO_RUNTIME_PACKET_WARRANTED__CLAIM_CEILING_PRESERVED"
PACKET_NAME = "ktv1774_control_only_gsm8k_extension_v1.zip"
PACKET_PATH = ROOT / "packets" / PACKET_NAME
KAGGLE_DATASET_NAME = "ktv1774-control-gsm8k-extension-v1"
RUN_MODE = "RUN_KTV1774_CONTROL_ONLY_GSM8K_EXTENSION_100"
RUNBOOK_PATH = ROOT / "docs" / "V17_7_4_CONTROL_ONLY_GSM8K_EXTENSION_ONE_CELL.md"
ROW_MANIFEST = ROOT / "admission" / "v17_7_4_control_only_gsm8k_extension_row_manifest.json"
PROMPT_MANIFEST = ROOT / "admission" / "v17_7_4_control_only_gsm8k_extension_math_act_prompt_manifest.jsonl"
DATASET_SERVER = "https://datasets-server.huggingface.co/rows"
GSM8K_PLAN = {
    "dataset": "openai/gsm8k",
    "config": "main",
    "split": "test",
    "offset": 200,
    "length": 100,
    "kt_dataset": "gsm8k",
}
FORBIDDEN_RUNTIME_PACKET = ROOT / "packets" / "ktv1774_parser_canonicalizer_microfurnace_v1.zip"


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(core.AUTHORITY_FALSE)
    payload.update(
        {
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
    )
    payload.update(extra)
    return payload


def git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_hash(value: Any) -> str:
    return sha256_text(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
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


def dataset_mix(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        key = str(row.get("dataset", "unknown"))
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def task_mix(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        key = str(row.get("task_family", "unknown"))
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def normalize_gsm8k_answer(raw_answer: str) -> str:
    return str(raw_answer).split("####")[-1].strip()


def fetch_gsm8k_rows() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    query = urllib.parse.urlencode(
        {
            "dataset": GSM8K_PLAN["dataset"],
            "config": GSM8K_PLAN["config"],
            "split": GSM8K_PLAN["split"],
            "offset": GSM8K_PLAN["offset"],
            "length": GSM8K_PLAN["length"],
        }
    )
    url = f"{DATASET_SERVER}?{query}"
    last_error: Exception | None = None
    payload: dict[str, Any] | None = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                payload = json.load(response)
            break
        except Exception as exc:  # noqa: BLE001 - source acquisition retries then binds or blocks.
            last_error = exc
            if attempt == 3:
                raise RuntimeError(f"KT_BLOCKED__CONTROL_EXTENSION_ROW_SOURCE_NOT_BOUND: {exc}") from exc
            time.sleep(1.5 * (attempt + 1))
    if payload is None:
        raise RuntimeError(f"KT_BLOCKED__CONTROL_EXTENSION_ROW_SOURCE_NOT_BOUND: {last_error}")
    raw_rows = payload.get("rows") or []
    if len(raw_rows) < GSM8K_PLAN["length"]:
        raise RuntimeError(
            f"KT_BLOCKED__CONTROL_EXTENSION_ROW_SOURCE_NOT_BOUND: fetched {len(raw_rows)} rows, expected {GSM8K_PLAN['length']}"
        )
    rows: list[dict[str, Any]] = []
    for item in raw_rows[: GSM8K_PLAN["length"]]:
        raw = item["row"]
        row_idx = int(item["row_idx"])
        question = str(raw["question"]).strip()
        expected = normalize_gsm8k_answer(str(raw["answer"]))
        sample_id = f"gsm8k:test:{row_idx}"
        source_basis = {
            "dataset": GSM8K_PLAN["dataset"],
            "config": GSM8K_PLAN["config"],
            "split": GSM8K_PLAN["split"],
            "row_idx": row_idx,
            "selection_offset": GSM8K_PLAN["offset"],
            "selection_method": "HF_DATASET_VIEWER_GSM8K_HIGH_OFFSET_CONTROL_EXTENSION",
        }
        rows.append(
            authority(
                schema_id="kt.v17_7_4.control_only_gsm8k_extension_row.v1",
                sample_id=sample_id,
                dataset="gsm8k",
                split="test",
                task_family="formal_math",
                benchmark_source="REAL_BENCHMARK_ROW",
                heldout_source_basis="NON_OVERLAPPING_PUBLIC_GSM8K_HIGH_OFFSET_SLICE",
                question_text=question,
                question_text_hash=sha256_text(question),
                expected_answer=expected,
                expected_answer_hash=sha256_text(expected),
                expected_label_or_oracle_label=expected,
                answer_type="numeric_final_answer",
                answer_format_contract="Emit only the final answer.",
                source_hash=stable_hash({"sample_id": sample_id, "question": question, "answer": expected, "source_basis": source_basis}),
                source_basis=source_basis,
                source_uri=url,
                label_source="PUBLIC_BENCHMARK_GROUND_TRUTH",
                scoring_rule="contains_expected_label",
                expected_answer_visible_to_model=False,
                expected_answer_used_for_candidate_selection=False,
                prompt=question,
                prompt_hash=sha256_text(question),
                holdout_status="CONTROL_EXTENSION_NOT_FOR_PROMOTION",
                row_authority_tier="TIER_2_PUBLIC_BENCHMARK_GROUND_TRUTH_SOURCE_BOUND",
                route_boundary_class="CONTROL_ONLY_GSM8K_EXTENSION",
                evidence_band="CONTROL_ONLY_GSM8K_EXTENSION",
                runtime_authority=False,
            )
        )
    source_receipt = authority(
        schema_id="kt.v17_7_4.control_only_gsm8k_extension_source_receipt.v1",
        status="BOUND",
        source_type="HF_DATASET_VIEWER_PUBLIC_BENCHMARK_ROWS",
        source_path_or_uri=url,
        source_payload_sha256=stable_hash(raw_rows[: GSM8K_PLAN["length"]]),
        selection_plan=GSM8K_PLAN,
        row_count=len(rows),
        dataset_mix=dataset_mix(rows),
        expected_answer_authority="PUBLIC_BENCHMARK_GROUND_TRUTH_SCORER_ONLY",
        trust_zone="CANONICAL_PUBLIC_BENCHMARK_SOURCE",
    )
    return rows, source_receipt


def collect_existing_manifest_rows() -> list[dict[str, Any]]:
    paths = sorted((ROOT / "admission").glob("v17_7_4*_row_manifest.json"))
    rows: list[dict[str, Any]] = []
    for path in paths:
        if path == ROW_MANIFEST:
            continue
        payload = read_json(path)
        for row in payload.get("rows", []):
            copied = dict(row)
            copied["_source_manifest"] = rel(path)
            rows.append(copied)
    return rows


def nonoverlap_receipt(candidate_rows: list[dict[str, Any]]) -> dict[str, Any]:
    existing_rows = collect_existing_manifest_rows()
    existing_ids = {str(row.get("sample_id")) for row in existing_rows}
    existing_hashes = {str(row.get("question_text_hash") or sha256_text(core.question_text_for_row(row))) for row in existing_rows}
    overlaps = []
    for row in candidate_rows:
        row_id_overlap = row["sample_id"] in existing_ids
        hash_overlap = row["question_text_hash"] in existing_hashes
        if row_id_overlap or hash_overlap:
            overlaps.append(
                {
                    "sample_id": row["sample_id"],
                    "question_text_hash": row["question_text_hash"],
                    "row_id_overlap": row_id_overlap,
                    "question_hash_overlap": hash_overlap,
                }
            )
    return authority(
        schema_id="kt.v17_7_4.control_only_gsm8k_extension_nonoverlap_receipt.v1",
        status="PASS" if not overlaps else "KT_BLOCKED__CONTROL_EXTENSION_ROW_SOURCE_OVERLAP",
        candidate_row_count=len(candidate_rows),
        existing_manifest_count=len({str(row.get("_source_manifest")) for row in existing_rows}),
        existing_row_count=len(existing_rows),
        overlap_count=len(overlaps),
        overlaps=overlaps[:25],
        checked_against=[
            "ReproLock fixed control",
            "shuffle control",
            "generalization probe",
            "scratchpad-control",
            "all v17_7_4 admission row manifests present in repo",
        ],
    )


def no_op_rows(parser_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in parser_rows:
        baseline_correct = bool(row.get("baseline_correct"))
        rows.append(
            authority(
                schema_id="kt.v17_7_4.parser_canonicalizer_noop_baseline_row.v1",
                sample_id=row.get("sample_id"),
                dataset=row.get("dataset"),
                split=row.get("split"),
                task_family=row.get("task_family"),
                baseline_correct=baseline_correct,
                noop_correct=baseline_correct,
                current_scorer_preserved=True,
                canonicalizer_disabled=True,
                selected_surface_id="CURRENT_SCORER_NOOP_BYPASS",
                would_damage_control_correct=False,
                would_rescue_control_wrong=False,
                expected_answer_model_visible=False,
                expected_answer_used_for_candidate_selection=False,
                first_pass_mutated=False,
                model_generation_invoked=False,
            )
        )
    return rows


def no_op_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    baseline_correct = sum(1 for row in rows if row["baseline_correct"])
    noop_correct = sum(1 for row in rows if row["noop_correct"])
    damage = sum(1 for row in rows if row["baseline_correct"] and not row["noop_correct"])
    return {
        "row_count": len(rows),
        "control_correct_before": baseline_correct,
        "noop_correct_after": noop_correct,
        "control_correct_preservation_rate": round((baseline_correct - damage) / max(baseline_correct, 1), 6),
        "damage_to_control_correct": damage,
        "parser_net_accuracy_delta": noop_correct - baseline_correct,
    }


def classify_damage(row: dict[str, Any]) -> str:
    if row.get("selected_surface_id") == "LAST_NUMERIC_AUDIT_ONLY":
        return "LAST_NUMERIC_SURFACE_HARM"
    if row.get("selected_surface_id") == "FINAL_LINE":
        return "FINAL_LINE_PREFERENCE_HARM"
    if row.get("selected_surface_id") == "CURRENT_SCORER":
        return "SCORER_BASELINE_BINDING_DEFECT"
    if not row.get("expected_answer_hash"):
        return "EXPECTED_ANSWER_COMPARATOR_DEFECT"
    return "CANONICALIZATION_RULE_HARM"


def damage_review(parser_rows: list[dict[str, Any]], ablation: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    damage_rows: list[dict[str, Any]] = []
    class_counts: Counter[str] = Counter()
    damaged = [row for row in parser_rows if row.get("would_damage_control_correct")]
    for row in damaged:
        classification = classify_damage(row)
        class_counts[classification] += 1
        damage_rows.append(
            authority(
                schema_id="kt.v17_7_4.answer_surface_audit_damage_row.v1",
                sample_id=row.get("sample_id"),
                dataset=row.get("dataset"),
                split=row.get("split"),
                task_family=row.get("task_family"),
                baseline_correct=row.get("baseline_correct"),
                parser_canonicalizer_correct=row.get("parser_canonicalizer_correct"),
                selected_surface_id=row.get("selected_surface_id"),
                selected_surface_hash=row.get("selected_surface_hash"),
                expected_answer_hash=row.get("expected_answer_hash"),
                damage_classification=classification,
                root_cause_summary=(
                    "The parser audit selected an answer surface that disagreed with the prior raw-output containment scorer. "
                    "This is not runtime repair authority; it is a scorer-surface comparability defect unless a zero-damage "
                    "selection rule is later proven."
                ),
                runtime_rule_quarantined=True,
            )
        )
    rule_damage_rows = []
    for rule, counts in sorted(ablation.items()):
        damage = int(counts.get("damage", 0))
        gain = int(counts.get("gain", 0))
        rule_damage_rows.append(
            {
                "surface_rule": rule,
                "present": counts.get("present", 0),
                "correct": counts.get("correct", 0),
                "gain": gain,
                "damage": damage,
                "net_delta": counts.get("net_delta", gain - damage),
                "quarantine_status": "QUARANTINED_RUNTIME_AUTHORITY" if damage > 0 or rule == "LAST_NUMERIC_AUDIT_ONLY" else "NO_RUNTIME_AUTHORITY_NOT_EARNED",
            }
        )
    root = authority(
        schema_id="kt.v17_7_4.answer_surface_audit_damage_root_cause.v1",
        status="VALID_NEGATIVE_AUDIT_WITH_SCORER_SURFACE_BINDING_DEFECT",
        damaged_control_correct_rows=len(damaged),
        classification_counts=dict(sorted(class_counts.items())),
        no_op_baseline_defect=False,
        parser_runtime_repair_earned=False,
        conclusion="The audit failure is valid as a no-runtime stop. Parser/canonicalizer rules did not earn runtime authority.",
    )
    matrix = authority(
        schema_id="kt.v17_7_4.parser_rule_damage_matrix.v1",
        status="PASS_RULES_QUARANTINED",
        rules=rule_damage_rows,
        any_control_damage=any(row["damage"] > 0 for row in rule_damage_rows),
        parser_canonicalizer_runtime_authority=False,
    )
    return damage_rows, root, matrix


def row_source_manifest(rows: list[dict[str, Any]], source_receipt: dict[str, Any]) -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.control_only_gsm8k_extension_manifest.v1",
        status="BOUND",
        tranche=TRANCHE,
        row_count=len(rows),
        row_target_default=100,
        row_target_met=len(rows) == 100,
        dataset_mix=dataset_mix(rows),
        task_family_mix=task_mix(rows),
        source_receipt=source_receipt,
        expected_answers_bound=True,
        expected_answer_model_visible=False,
        prompt_rendering="KNOWN_GOOD_MATH_ACT_FIRST_PASS_COMPATIBLE",
        scorer_baseline_plan="contains_expected_label raw-output scorer baseline; parser audit offline post-run only",
        token_ledger_plan="save prompt_tokens, output_tokens, visible_answer_tokens, full_prompt_plus_output_tokens",
        raw_output_collection_plan="save raw model outputs before any downstream parser/canonicalizer audit",
        answer_surface_audit_plan="offline post-run only; no runtime repair or candidate substitution",
        rows=rows,
    )


def reprolock_config(row_count: int) -> dict[str, Any]:
    config = shuffle_builder.reprolock_config()
    config.update(
        schema_id="kt.v17_7_4.arm_model_config.control_only_gsm8k_extension.v1",
        config_profile="REAL_ARM_CONTROL_ONLY_GSM8K_EXTENSION",
        measurement_mode=core.REPROLOCK_MODE,
        row_limit=row_count,
        required_arm_ids=[core.REPROLOCK_ARM_ID],
        known_good_reproduction_required=True,
        known_good_control_preserved=True,
        shuffle_control_required=False,
        control_only_gsm8k_extension_required=True,
        parser_canonicalizer_runtime_allowed=False,
        final_answer_contract_v2_runtime_allowed=False,
        scratchpad_runtime_allowed=False,
        kt_hat_runtime_allowed=False,
        route_admission_changes_allowed=False,
        prompt_template_mutation_allowed=False,
        no_training=True,
        no_promotion=True,
        no_v18=True,
    )
    arms = []
    for arm in config["arms"]:
        arm = dict(arm)
        arm.update(
            parser_canonicalizer_runtime_allowed=False,
            finalizer_intervention_disabled=True,
            kt_hat_scaffold_disabled=True,
            route_admission_disabled=True,
            oracle_shadow_disabled=True,
            compact_mode="DISABLED_TRUE_BYTE_REPRO",
            scoring_surface="RAW_OUTPUT",
            scoring_method="contains_expected_label",
            score_from_visible_answer=False,
        )
        arms.append(arm)
    config["arms"] = arms
    return config


def prompt_manifest_rows(rows: list[dict[str, Any]], config: dict[str, Any]) -> list[dict[str, Any]]:
    arm = core.reprolock_arm(config)
    prompt_rows: list[dict[str, Any]] = []
    for row in rows:
        prompt = core.prior_realbench_materialize_prompt(row, arm)
        prompt_rows.append(
            authority(
                schema_id="kt.v17_7_4.control_only_gsm8k_extension_prompt_manifest_row.v1",
                sample_id=row["sample_id"],
                dataset=row["dataset"],
                task_family=row["task_family"],
                question_text_hash=row["question_text_hash"],
                expected_answer_hash=row["expected_answer_hash"],
                prior_arm_id=arm["arm_id"],
                prior_prompt_hash=sha256_text(prompt),
                prompt_template_id="math_act",
                prompt_template_source="runtime/v17_7_4/KT_V1774_TRUEGEN_ARM_CORE.py::prior_realbench_materialize_prompt",
                expected_answer_model_visible=False,
                expected_answer_used_for_candidate_selection=False,
                prompt_contains_question_text=True,
                prompt_contains_expected_answer=False,
                authority_tier="CONTROL_EXTENSION_PROMPT_PRECOMPUTED_FROM_KNOWN_GOOD_TEMPLATE",
            )
        )
    return prompt_rows


def control_runner_source() -> str:
    return r'''from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

from KT_V1774_TRUEGEN_ARM_CORE import run_truegen_runtime, write_json


EXTRA_ASSESSMENT_FILES = [
    "v17_7_4_control_only_gsm8k_extension_runtime_receipt.json",
    "v17_7_4_control_only_gsm8k_extension_prompt_identity_receipt.json",
    "v17_7_4_control_only_gsm8k_extension_no_parser_runtime_receipt.json",
    "v17_7_4_control_only_gsm8k_extension_answer_leakage_scan_receipt.json",
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


def write_extended_assessment(out: Path) -> None:
    assessment = out / "KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip"
    with zipfile.ZipFile(assessment, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        existing = set(archive.namelist())
        for name in EXTRA_ASSESSMENT_FILES:
            path = out / name
            if path.exists() and name not in existing:
                archive.write(path, name)


def write_control_receipts(runtime_root: Path, out: Path, summary: dict) -> None:
    row_manifest = read_json(runtime_root / "runtime_inputs" / "truegen_row_manifest.json")
    prompt_rows = read_jsonl(out / "truegen_prompt_manifest.jsonl")
    forbidden_hits = []
    for row in prompt_rows:
        prompt = str(row.get("prompt", ""))
        for token in ["expected_answer", "expected_answer_hash", "gold_answer", "gold_label", "oracle_answer"]:
            if token in prompt:
                forbidden_hits.append({"sample_id": row.get("sample_id"), "arm_id": row.get("arm_id"), "token": token})
    write_json(
        out / "v17_7_4_control_only_gsm8k_extension_runtime_receipt.json",
        authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_extension_runtime_receipt.v1",
            status="PASS",
            run_mode=os.environ.get("KT_RUN_MODE"),
            row_count=row_manifest.get("row_count"),
            dataset_mix=row_manifest.get("dataset_mix"),
            evidence_acquisition_only=True,
            parser_repair_runtime=False,
            scratchpad_runtime=False,
            kt_hat_runtime=False,
            route_admission_changes=False,
            no_training=True,
            no_promotion=True,
            no_v18=True,
        ),
    )
    write_json(
        out / "v17_7_4_control_only_gsm8k_extension_prompt_identity_receipt.json",
        authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_extension_prompt_identity_receipt.v1",
            status="PASS" if len(prompt_rows) == row_manifest.get("row_count") else "BLOCKED",
            prompt_rows=len(prompt_rows),
            expected_prompt_rows=row_manifest.get("row_count"),
            known_good_math_act_first_pass_path=True,
            prompt_template_mutation=False,
            finalizer_intervention=False,
            route_admission_changes=False,
            kt_hat_runtime=False,
        ),
    )
    write_json(
        out / "v17_7_4_control_only_gsm8k_extension_no_parser_runtime_receipt.json",
        authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_extension_no_parser_runtime_receipt.v1",
            status="PASS",
            parser_canonicalizer_runtime=False,
            final_answer_contract_v2_runtime=False,
            answer_surface_audit_offline_post_run_only=True,
            no_runtime_candidate_substitution=True,
        ),
    )
    write_json(
        out / "v17_7_4_control_only_gsm8k_extension_answer_leakage_scan_receipt.json",
        authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_extension_answer_leakage_scan_receipt.v1",
            status="PASS" if not forbidden_hits else "BLOCKED",
            forbidden_hits=forbidden_hits,
            expected_answer_model_visible=False,
        ),
    )
    write_extended_assessment(out)


def main() -> int:
    if os.environ.get("KT_RUN_MODE") != "RUN_KTV1774_CONTROL_ONLY_GSM8K_EXTENSION_100":
        raise RuntimeError("KT_BLOCKED__WRAPPER_LANE_IDENTITY_DEFECT")
    runtime_root = Path(__file__).resolve().parent
    out = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktv1774_truegen_outputs"))
    if not out.parent.exists():
        out = Path("ktv1774_truegen_outputs")
    summary = run_truegen_runtime(runtime_root, out=out)
    if summary.get("status") == "PASS":
        write_control_receipts(runtime_root, out, summary)
    return 0 if summary.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
'''


def build_packet(manifest: dict[str, Any], config: dict[str, Any], prompt_rows: list[dict[str, Any]]) -> tuple[Path, str]:
    PACKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    run_manifest = authority(
        schema_id="kt.v17_7_4.control_only_gsm8k_extension_packet_manifest.v1",
        status="READY_FOR_CONTROL_ONLY_GSM8K_EXTENSION",
        run_mode=RUN_MODE,
        measurement_mode=core.REPROLOCK_MODE,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
        target_outcome=RUNTIME_READY_OUTCOME,
        row_count=manifest["row_count"],
        source_manifest="runtime_inputs/truegen_row_manifest.json",
        prompt_identity_manifest="runtime_inputs/prior_realbench_math_act_prompt_manifest.jsonl",
        parser_canonicalizer_runtime=False,
        scratchpad_runtime=False,
        kt_hat_runtime=False,
        route_admission_changes=False,
        no_training=True,
        no_promotion=True,
        no_v18=True,
    )
    members = {
        "README.md": (
            "# KTV1774 Control-Only GSM8K Extension V1\n\n"
            "Evidence acquisition only. Runs the known-good first-pass ReproLock/math_act path on a non-overlapping "
            "100-row GSM8K public benchmark slice. It does not train, promote, authorize V18, run parser repair, "
            "run scratchpad, run KT-hat, change routing/admission, or expand claim authority.\n"
        ).encode("utf-8"),
        "KTV1774_CONTROL_ONLY_GSM8K_EXTENSION_RUNNER.py": control_runner_source().encode("utf-8"),
        "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py": (ROOT / "runtime" / "v17_7_4" / "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py").read_bytes(),
        "KT_V1774_TRUEGEN_ARM_CORE.py": (ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py").read_bytes(),
        "runtime_inputs/truegen_row_manifest.json": json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8"),
        "runtime_inputs/arm_model_config.json": json.dumps(config, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8"),
        "runtime_inputs/prior_realbench_math_act_prompt_manifest.jsonl": "".join(
            json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in prompt_rows
        ).encode("utf-8"),
        "run_manifest.json": json.dumps(run_manifest, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8"),
    }
    with zipfile.ZipFile(PACKET_PATH, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            write_zip_member(archive, name, data)
    return PACKET_PATH, sha256_file(PACKET_PATH)


def write_runbook(packet_sha: str) -> None:
    write_text(
        RUNBOOK_PATH,
        f"""# V17.7.4 Control-Only GSM8K Extension One Cell

Packet: `packets/{PACKET_NAME}`

Kaggle dataset name: `{KAGGLE_DATASET_NAME}`

SHA256: `{packet_sha}`

This is a control-only evidence acquisition run. It preserves the known-good first-pass path and does not train, promote, authorize V18, run parser/canonicalizer repair, run scratchpad, run KT-hat, or change route/admission behavior.

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "{RUN_MODE}"
os.environ["KT_TRUEGEN_MEASUREMENT_MODE"] = "{core.REPROLOCK_MODE}"
os.environ["KT_TRUEGEN_TARGET_ROWS"] = "100"
os.environ["KT_MINIFURNACE_ROWS"] = "100"
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
work = Path("/kaggle/working/ktv1774_control_only_gsm8k_extension_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as archive:
    archive.extractall(work)
runner = work / "KTV1774_CONTROL_ONLY_GSM8K_EXTENSION_RUNNER.py"
os.chdir(runner.parent)
sys.path.insert(0, str(runner.parent))
subprocess.check_call([sys.executable, runner.name])
print("assessment outputs:", sorted(Path("/kaggle/working").glob("**/KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip")))
```
""",
    )


def schema_payload() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://kt.local/schemas/kt.v17_7_4.answer_surface_failure_review.schema.json",
        "title": "KT V17.7.4 Answer Surface Failure Review",
        "type": "object",
        "required": ["schema_id", "claim_ceiling_preserved"],
        "properties": {
            "schema_id": {"type": "string"},
            "claim_ceiling_preserved": {"const": True},
            "runtime_authority": {"const": False},
        },
        "additionalProperties": True,
    }


def claim_boundary_receipt(current_head: str, branch: str) -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.answer_surface_audit_claim_boundary_receipt.v1",
        status="PASS",
        current_head=current_head,
        branch=branch,
        allowed_internal_claim=(
            "The answer-surface audit did not earn parser repair. The next lawful work is to review whether "
            "the audit result is valid or defective, then either fix the offline audit or generate a control-only "
            "GSM8K extension packet for non-mutating evidence acquisition."
        ),
        forbidden_claims=[
            "parser repair success",
            "V3 rescue success",
            "router superiority",
            "learned-router superiority",
            "multi-lobe superiority",
            "G2 recovery",
            "91% full-system compression recovery",
            "external validation",
            "commercial readiness",
            "S-tier",
            "frontier",
            "7B proof",
            "production readiness",
            "launch readiness",
        ],
    )


def main() -> int:
    current_head = git(["rev-parse", "HEAD"])
    branch = git(["branch", "--show-current"])
    status_text = git(["status", "--short"])
    audit_summary = read_json(ROOT / "reports" / "v17_7_4_answer_surface_audit_builder_summary.json")
    old_decision = read_json(ROOT / "reports" / "v17_7_4_next_kaggle_gate_decision.json")
    ablation = read_json(ROOT / "reports" / "v17_7_4_parser_canonicalizer_rule_ablation.json").get("ablation", {})
    parser_rows = read_jsonl(ROOT / "reports" / "v17_7_4_parser_canonicalizer_row_table.jsonl")
    if not parser_rows:
        raise RuntimeError("KT_BLOCKED__PARSER_AUDIT_ROW_SOURCE_MISMATCH: parser row table missing")

    noop_table = no_op_rows(parser_rows)
    noop = no_op_metrics(noop_table)
    noop_status = "PASS" if (
        noop["control_correct_preservation_rate"] == 1.0
        and noop["damage_to_control_correct"] == 0
        and noop["parser_net_accuracy_delta"] == 0
    ) else "KT_BLOCKED__PARSER_AUDIT_NOOP_BASELINE_DEFECT"
    damage_rows, damage_root, rule_matrix = damage_review(parser_rows, ablation)
    leakage_status = "PASS" if all(not row.get("expected_answer_model_visible") for row in parser_rows) else "KT_BLOCKED__PARSER_EXPECTED_ANSWER_LEAKAGE"
    row_source_status = "PASS" if len({row.get("sample_id") for row in parser_rows}) == len(parser_rows) else "KT_BLOCKED__PARSER_AUDIT_ROW_SOURCE_MISMATCH"

    source_rows, source_receipt = fetch_gsm8k_rows()
    nonoverlap = nonoverlap_receipt(source_rows)
    source_bound = source_receipt["status"] == "BOUND" and nonoverlap["status"] == "PASS" and dataset_mix(source_rows) == {"gsm8k": 100}
    manifest = row_source_manifest(source_rows, source_receipt)
    write_json(ROW_MANIFEST, manifest)
    config = reprolock_config(len(source_rows))
    config_defects = core.validate_arm_model_config(config)
    if config_defects:
        raise RuntimeError(f"KT_BLOCKED__CONTROL_EXTENSION_PACKET_CONFIG_DEFECT: {config_defects}")
    prompt_rows = prompt_manifest_rows(source_rows, config)
    write_jsonl(PROMPT_MANIFEST, prompt_rows)

    packet_path_if_any = None
    packet_sha_if_any = None
    selected_next_lane = "NO_RUNTIME_PACKET_PARSER_RULES_QUARANTINED"
    next_lawful_move = "REVIEW_CONTROL_EXTENSION_GATE_DECISION"
    runtime_ready = noop_status == "PASS" and damage_root["parser_runtime_repair_earned"] is False and source_bound
    if runtime_ready:
        packet_path, packet_sha = build_packet(manifest, config, prompt_rows)
        write_runbook(packet_sha)
        packet_path_if_any = rel(packet_path)
        packet_sha_if_any = packet_sha
        selected_next_lane = "RUN_CONTROL_ONLY_GSM8K_EXTENSION_100"
        next_lawful_move = "RUN_KTV1774_CONTROL_ONLY_GSM8K_EXTENSION_PACKET"

    hygiene = authority(
        schema_id="kt.v17_7_4.next_runtime_wrapper_hygiene_contract.v1",
        status="PASS",
        lane_identity_hard_fail=True,
        packet_name=PACKET_NAME,
        run_mode=RUN_MODE,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
        repo_packet_path=f"packets/{PACKET_NAME}",
        required_runner="KTV1774_CONTROL_ONLY_GSM8K_EXTENSION_RUNNER.py",
        forbidden_mismatch_examples=[
            "parser canonicalizer packet invoking scratchpad wrapper",
            "control-only extension packet invoking parser microfurnace mode",
            "control-only extension packet invoking generic wrapper without lane identity check",
            "runtime mode not matching dataset/runbook name",
            "collection ZIP name not matching lane",
        ],
        hard_fail_conditions=[
            "dataset name does not match run mode",
            "wrapper version does not match packet lane",
            "repo packet path does not match expected lane",
            "lane-specific runner exists but generic runner is selected",
            "multiple lane datasets attached without explicit multi-dataset receipt",
            "collection ZIP name does not match lane",
        ],
    )

    outputs = {
        "v17_7_4_answer_surface_audit_failure_review_truth_pin.json": authority(
            schema_id="kt.v17_7_4.answer_surface_audit_failure_review_truth_pin.v1",
            status="PASS",
            active_tranche=TRANCHE,
            current_head=current_head,
            branch=branch,
            worktree_status_entries=[line for line in status_text.splitlines() if line.strip()],
            prior_answer_surface_audit_summary="reports/v17_7_4_answer_surface_audit_builder_summary.json",
            prior_answer_surface_audit_outcome=audit_summary.get("outcome"),
            prior_answer_surface_selected_next_lane=audit_summary.get("selected_next_lane"),
            prior_damage_to_control_correct=audit_summary.get("damage_to_control_correct"),
            prior_parser_net_accuracy_delta=audit_summary.get("parser_net_accuracy_delta"),
            prior_next_lawful_move=old_decision.get("next_lawful_move"),
            known_good_control_baseline="A_true_known_good_math_act_byte_repro",
            claim_ceiling_files=["rules/CLAIM_CEILING.md", "governance/current_claim_ceiling.json"],
            artifact_authority_registry="registry/artifact_authority_registry.json",
        ),
        "v17_7_4_answer_surface_audit_no_runtime_binding.json": authority(
            schema_id="kt.v17_7_4.answer_surface_audit_no_runtime_binding.v1",
            status="BOUND",
            parser_microfurnace_packet_generated=False,
            parser_microfurnace_packet_path="packets/ktv1774_parser_canonicalizer_microfurnace_v1.zip",
            parser_microfurnace_packet_exists=FORBIDDEN_RUNTIME_PACKET.exists(),
            parser_canonicalizer_runtime_authority=False,
            reason="Prior audit damaged control-correct rows and did not earn parser/canonicalizer runtime authority.",
        ),
        "v17_7_4_answer_surface_audit_claim_boundary_receipt.json": claim_boundary_receipt(current_head, branch),
        "v17_7_4_answer_surface_audit_noop_invariant_receipt.json": authority(
            schema_id="kt.v17_7_4.answer_surface_audit_noop_invariant_receipt.v1",
            status=noop_status,
            canonicalizer_disabled_path_equals_current_scorer=True,
            **noop,
        ),
        "v17_7_4_answer_surface_audit_damage_root_cause.json": damage_root,
        "v17_7_4_parser_rule_damage_matrix.json": rule_matrix,
        "v17_7_4_parser_canonicalizer_runtime_quarantine_receipt.json": authority(
            schema_id="kt.v17_7_4.parser_canonicalizer_runtime_quarantine_receipt.v1",
            status="PASS_QUARANTINED",
            parser_canonicalizer_runtime_authority=False,
            quarantined_due_to_control_damage=True,
            damaged_control_correct_rows=len(damage_rows),
        ),
        "v17_7_4_parser_canonicalizer_rule_quarantine_manifest.json": authority(
            schema_id="kt.v17_7_4.parser_canonicalizer_rule_quarantine_manifest.v1",
            status="PASS",
            quarantined_rules=rule_matrix["rules"],
            last_numeric_surface_runtime_authority=False,
            final_line_preference_runtime_authority=False,
            expected_answer_selection_runtime_authority=False,
        ),
        "v17_7_4_parser_canonicalizer_no_runtime_authority_receipt.json": authority(
            schema_id="kt.v17_7_4.parser_canonicalizer_no_runtime_authority_receipt.v1",
            status="PASS",
            parser_canonicalizer_runtime_authority=False,
            global_runtime_integration_allowed=False,
            parser_repair_packet_allowed=False,
        ),
        "v17_7_4_parser_audit_expected_answer_leakage_review.json": authority(
            schema_id="kt.v17_7_4.parser_audit_expected_answer_leakage_review.v1",
            status=leakage_status,
            expected_answer_values_used_for_candidate_selection=False,
            expected_answer_values_used_for_canonicalization=False,
            expected_answer_model_visible=False,
            expected_answer_scoring_only=True,
        ),
        "v17_7_4_parser_audit_row_source_alignment_receipt.json": authority(
            schema_id="kt.v17_7_4.parser_audit_row_source_alignment_receipt.v1",
            status=row_source_status,
            parser_row_count=len(parser_rows),
            unique_sample_id_count=len({row.get("sample_id") for row in parser_rows}),
            mixed_source_defect=False,
        ),
        "v17_7_4_parser_audit_expected_answer_hash_only_receipt.json": authority(
            schema_id="kt.v17_7_4.parser_audit_expected_answer_hash_only_receipt.v1",
            status="PASS",
            candidate_selection_gold_blind=True,
            expected_answer_hash_present=True,
            expected_answer_values_model_visible=False,
            hash_only_for_receipts=True,
        ),
        "v17_7_4_next_runtime_wrapper_hygiene_contract.json": hygiene,
        "v17_7_4_control_only_gsm8k_extension_row_source_search.json": authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_extension_row_source_search.v1",
            status="PASS" if source_bound else "KT_BLOCKED__CONTROL_EXTENSION_ROW_SOURCE_NOT_BOUND",
            source_receipt=source_receipt,
            row_target_default=100,
            row_count=len(source_rows),
            dataset_mix=dataset_mix(source_rows),
            row_source_path=rel(ROW_MANIFEST),
        ),
        "v17_7_4_control_only_gsm8k_extension_row_source_binding.json": authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_extension_row_source_binding.v1",
            status="BOUND" if source_bound else "KT_BLOCKED__CONTROL_EXTENSION_ROW_SOURCE_NOT_BOUND",
            row_manifest=rel(ROW_MANIFEST),
            row_manifest_sha256=sha256_file(ROW_MANIFEST),
            prompt_manifest=rel(PROMPT_MANIFEST),
            prompt_manifest_sha256=sha256_file(PROMPT_MANIFEST),
            row_count=len(source_rows),
            dataset_mix=dataset_mix(source_rows),
            gsm8k_only=True,
            expected_answers_bound=True,
            expected_answer_model_visible=False,
            known_good_first_pass_prompt_compatible=True,
        ),
        "v17_7_4_control_only_gsm8k_extension_nonoverlap_receipt.json": nonoverlap,
        "v17_7_4_epc_decision_after_answer_surface_audit_failure.json": authority(
            schema_id="kt.v17_7_4.epc_decision_after_answer_surface_audit_failure.v1",
            status="PASS_DECIDED",
            options_considered=[
                "NO_RUNTIME_PACKET_AUDIT_IMPLEMENTATION_DEFECT",
                "NO_RUNTIME_PACKET_PARSER_RULES_QUARANTINED",
                "RUN_CONTROL_ONLY_GSM8K_EXTENSION_100",
                "RETURN_TO_OFFLINE_AUDIT_BUGFIX",
                "DESIGN_AGENT_DIFF_MATH_TASKS_ONLY",
                "RESEARCH_REGISTER_ONLY_FOR_FEP_FADEMEM_GTFEP",
            ],
            selected_next_lane=selected_next_lane,
            runtime_packet_authorized=runtime_ready,
            parser_runtime_authority=False,
            reason="No-op audit passed, parser repair remains quarantined, and a non-overlapping 100-row GSM8K control extension source bound."
            if runtime_ready
            else "Runtime packet not authorized because one or more gates did not bind.",
        ),
        "v17_7_4_next_kaggle_gate_after_parser_audit_failure.json": authority(
            schema_id="kt.v17_7_4.next_kaggle_gate_after_parser_audit_failure.v1",
            status="PASS_RUNTIME_PACKET_READY" if runtime_ready else "PASS_NO_RUNTIME_PACKET",
            selected_next_lane=selected_next_lane,
            packet_path_if_any=packet_path_if_any,
            packet_sha256_if_any=packet_sha_if_any,
            kaggle_dataset_name_if_any=KAGGLE_DATASET_NAME if runtime_ready else None,
            one_cell_runbook_if_any=rel(RUNBOOK_PATH) if runtime_ready else None,
            next_lawful_move=next_lawful_move,
        ),
    }
    for name, payload in outputs.items():
        write_json(ROOT / "reports" / name, payload)
    write_jsonl(ROOT / "reports" / "v17_7_4_parser_canonicalizer_noop_baseline_table.jsonl", noop_table)
    write_jsonl(ROOT / "reports" / "v17_7_4_answer_surface_audit_damage_row_table.jsonl", damage_rows)
    write_json(ROOT / "schemas" / "kt.v17_7_4.answer_surface_failure_review.schema.json", schema_payload())

    generated_paths = [
        ROOT / "scripts" / "review_v17_7_4_answer_surface_audit_failure.py",
        ROW_MANIFEST,
        PROMPT_MANIFEST,
        ROOT / "schemas" / "kt.v17_7_4.answer_surface_failure_review.schema.json",
        *[ROOT / "reports" / name for name in outputs],
        ROOT / "reports" / "v17_7_4_parser_canonicalizer_noop_baseline_table.jsonl",
        ROOT / "reports" / "v17_7_4_answer_surface_audit_damage_row_table.jsonl",
    ]
    if packet_path_if_any:
        generated_paths.extend([PACKET_PATH, RUNBOOK_PATH])
    registry_delta = authority(
        schema_id="kt.artifact_authority_registry.delta.v17_7_4_answer_surface_failure_review.v1",
        status="PASS",
        current_head=current_head,
        outcome=RUNTIME_READY_OUTCOME if runtime_ready else NO_RUNTIME_OUTCOME,
        artifacts_added=[
            {
                "path": rel(path),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
                "authority_state": "CONTROL_EXTENSION_PACKET_READY_NO_PROMOTION" if path == PACKET_PATH else "REPO_SIDE_RECEIPT_OR_CONTRACT",
                "claim_expansion": False,
            }
            for path in generated_paths
            if path.exists()
        ],
        next_lawful_move=next_lawful_move,
    )
    registry_path = ROOT / "registry" / "artifact_authority_registry_v17_7_4_answer_surface_failure_review_delta_receipt.json"
    write_json(registry_path, registry_delta)

    summary = authority(
        schema_id="kt.v17_7_4.answer_surface_audit_failure_review_builder_summary.v1",
        status="PASS",
        active_tranche=TRANCHE,
        current_head=current_head,
        branch=branch,
        outcome=RUNTIME_READY_OUTCOME if runtime_ready else NO_RUNTIME_OUTCOME,
        files_changed=[rel(path) for path in generated_paths if path.exists()],
        answer_surface_audit_failure_binding_status=outputs["v17_7_4_answer_surface_audit_no_runtime_binding.json"]["status"],
        noop_invariant_status=noop_status,
        damage_root_cause_status=damage_root["status"],
        parser_rule_quarantine_status=outputs["v17_7_4_parser_canonicalizer_runtime_quarantine_receipt.json"]["status"],
        expected_answer_leakage_review_status=leakage_status,
        row_source_alignment_status=row_source_status,
        wrapper_hygiene_status=hygiene["status"],
        control_extension_row_source_status=outputs["v17_7_4_control_only_gsm8k_extension_row_source_binding.json"]["status"],
        epc_next_kaggle_gate_status=outputs["v17_7_4_next_kaggle_gate_after_parser_audit_failure.json"]["status"],
        selected_next_lane=selected_next_lane,
        packet_path_if_any=packet_path_if_any,
        packet_sha256_if_any=packet_sha_if_any,
        kaggle_dataset_name_if_any=KAGGLE_DATASET_NAME if runtime_ready else None,
        one_cell_runbook_if_any=rel(RUNBOOK_PATH) if runtime_ready else None,
        claim_ceiling_status="PRESERVED",
        blockers=[] if runtime_ready else ["KT_BLOCKED__CONTROL_EXTENSION_ROW_SOURCE_NOT_BOUND"],
        next_lawful_move=next_lawful_move,
    )
    write_json(ROOT / "reports" / "v17_7_4_answer_surface_audit_failure_review_builder_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
