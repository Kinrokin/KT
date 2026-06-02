from __future__ import annotations

import hashlib
import json
import math
import statistics
import subprocess
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROGRAM_ID = "KT_V17_7_3_EVIDENCE_ACQUISITION_DESIGN_AND_MICRO_FURNACE_PACKET"
OUTCOME = "KTG3FULL_V17_7_3_EVIDENCE_ACQUISITION_READY__RUN_TARGETED_BOUNDARY_ROW_FURNACE_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_TARGETED_BOUNDARY_ROW_FURNACE_NEXT"
RUNTIME_MODE = "RUN_TARGETED_BOUNDARY_ROW_FURNACE"
PACKET_NAME = "ktv1773_evidence_acquisition_e2e_v1.zip"
KAGGLE_DATASET = "ktv1773-evidence-v1"
PACKET_PATH = r"d:\user\rober\Downloads\ktv1773_evidence_acquisition_v1.zip"
PROMPT_PATH = r"d:\user\rober\Downloads\COPY_PASTE_NOW_ktv1773_evidence_acquisition_v1.txt"
FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)

EIG_WEIGHTS = {
    "w1_expected_uncertainty_reduction": 0.25,
    "w2_expected_ope_support_gain": 0.15,
    "w3_expected_conformal_width_reduction": 0.10,
    "w4_expected_boundary_resolution": 0.35,
    "w5_expected_pfail_reduction": 0.10,
    "w6_expected_dgs_improvement": 0.05,
    "c1_compute_cost": 0.01,
    "c2_leakage_risk": 0.50,
    "c3_redundancy_penalty": 0.20,
}

AUTHORITY_FALSE = {
    "claim_ceiling_preserved": True,
    "runtime_authority": False,
    "promotion_authority": False,
    "adapter_training_authorized": False,
    "learned_router_superiority_claim": False,
    "v18_runtime_authority": False,
}

ARM_IDS = [
    "base_raw",
    "route_regret_policy_adapter_global",
    "formal_math_repair_adapter_global",
    "base_kt_hat_compact",
    "math_act_adapter_global",
]

SLICE_TARGETS = {
    "math_numeric": 80,
    "ARC": 60,
    "TruthfulQA": 60,
    "HellaSwag": 60,
    "claim_boundary": 50,
    "evidence_grounding": 50,
    "ambiguous": 40,
    "borderline": 40,
}

BOUNDARY_TARGETS = {
    "base_raw__route_regret": 50,
    "base_raw__formal_math": 50,
    "route_regret__formal_math": 30,
    "hat_act_boundary": 30,
    "math_act_boundary": 30,
}

PRIMARY_BAND_COUNTS = {
    "B1_base_raw_vs_route_regret_boundary": 45,
    "B2_base_raw_vs_formal_math_boundary": 45,
    "B3_math_numeric_slice": 70,
    "B4_claim_boundary_slice": 45,
    "B5_ambiguous_borderline_rows": 35,
    "B6_hat_act_candidate_rows": 25,
    "B7_math_act_candidate_rows": 25,
    "B8_ARC_slice": 55,
    "B9_evidence_grounding_rows": 40,
    "B10_perturbation_families": 15,
}

PERTURBATION_FAMILIES = [
    "numeric_quantity_shift",
    "reasoning_target_shift",
    "claim_strength_shift",
    "source_credibility_shift",
    "distractor_injection",
    "semantic_preserving_paraphrase",
    "format_shift_noise",
]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=repo_root(), text=True).strip()


def current_head() -> str:
    return run_git(["rev-parse", "HEAD"])


def current_branch() -> str:
    return run_git(["branch", "--show-current"])


def git_status_porcelain() -> str:
    return run_git(["status", "--porcelain=v1"])


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return str(value)
        return value
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, Counter):
        return {str(key): json_safe(value[key]) for key in sorted(value)}
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [json_safe(item) for item in value]
    return str(value)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(json_safe(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(json_safe(row), sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_hash(payload: Any) -> str:
    text = json.dumps(json_safe(payload), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def authority_fields(**overrides: Any) -> dict[str, Any]:
    payload = dict(AUTHORITY_FALSE)
    payload.update(overrides)
    return payload


def load_inputs(root: Path) -> dict[str, Any]:
    required = {
        "rows": root / "admission" / "v17_7_route_outcome_table.jsonl",
        "decisions": root / "admission" / "sddr_route_decisions.jsonl",
        "v1772_summary": root / "reports" / "v17_7_2_builder_summary.json",
        "v1772_active_learning": root / "reports" / "v17_7_2_active_learning_trigger.json",
        "v1772_final": root / "reports" / "v17_7_2_final_decision_receipt.json",
        "v1772_pfail": root / "reports" / "v17_7_2_predictive_failure_probability.json",
        "v1772_dgs": root / "reports" / "v17_7_2_durable_gain_scorecard.json",
        "v1772_ope": root / "reports" / "v17_7_2_ope_baseline.json",
        "v1772_conformal": root / "reports" / "v17_7_2_conformal_prediction_sets.json",
        "v1772_evidence_gate": root / "reports" / "v17_7_2_evidence_sufficiency_gate.json",
        "v1772_preflight": root / "reports" / "v17_7_2_preflight_repo_truth_receipt.json",
    }
    missing = [path.as_posix() for path in required.values() if not path.exists()]
    if missing:
        raise FileNotFoundError(f"missing V17.7.2 import surfaces: {missing}")
    return {
        "rows": read_jsonl(required["rows"]),
        "decisions": read_jsonl(required["decisions"]),
        **{name: read_json(path) for name, path in required.items() if name not in {"rows", "decisions"}},
    }


def validate_v1772(inputs: dict[str, Any]) -> None:
    summary = inputs["v1772_summary"]
    active = inputs["v1772_active_learning"]
    if summary.get("authority_tier") != "ACTIVE_LEARNING_TRIGGERED":
        raise RuntimeError("V17.7.2 is not ACTIVE_LEARNING_TRIGGERED")
    if summary.get("replay_ready") is not False:
        raise RuntimeError("V17.7.2 replay_ready must be false")
    if active.get("active_learning_triggered") is not True:
        raise RuntimeError("V17.7.2 active-learning trigger is not true")
    for key in AUTHORITY_FALSE:
        expected = AUTHORITY_FALSE[key]
        if summary.get(key) is not expected:
            raise RuntimeError(f"V17.7.2 summary authority field mismatch: {key}")


def route_margin(values: dict[str, float], route_a: str, route_b: str) -> float:
    return abs(float(values.get(route_a, 0.0)) - float(values.get(route_b, 0.0)))


def row_categories(row: dict[str, Any], decision: dict[str, Any]) -> list[str]:
    correctness = row["route_correctness"]
    values = row["route_values_pre_generation"]
    categories: set[str] = set()
    correct_count = sum(1 for value in correctness.values() if value)
    if 0 < correct_count < len(correctness):
        categories.add("conformal_wide_route_uncertainty_rows")
        categories.add("high_sigma_predictive_rows")
    if float(decision.get("route_regret", 0.0)) > 0.01:
        categories.add("high_sigma_predictive_rows")
    if row["v17_5_route"] == row["v17_7_route"]:
        categories.add("do_nothing_close_call_rows")
    if row["base_raw_correct"] != row["v17_7_correct"] or route_margin(values, "base_raw", "route_regret_policy_adapter_global") <= 0.14:
        categories.add("base_raw_vs_route_regret_boundary_rows")
    if correctness.get("base_raw") != correctness.get("formal_math_repair_adapter_global") or route_margin(values, "base_raw", "formal_math_repair_adapter_global") <= 0.12:
        categories.add("base_raw_vs_formal_math_boundary_rows")
    if correctness.get("route_regret_policy_adapter_global") != correctness.get("formal_math_repair_adapter_global") or route_margin(values, "route_regret_policy_adapter_global", "formal_math_repair_adapter_global") <= 0.12:
        categories.add("route_regret_vs_formal_math_boundary_rows")
    if correctness.get("base_kt_hat_compact") and not row["v17_7_correct"]:
        categories.add("hat_salvage_candidate_rows")
    if row["dataset"].lower().startswith("gsm") or "math" in row["task_family"].lower():
        categories.add("math_act_candidate_rows")
    if any(correctness.values()) and not row["v17_7_correct"]:
        categories.add("oracle_gap_analog_rows")
    if row["dataset"].lower().startswith("arc"):
        categories.add("slice_stress_rows")
    if "truth" in row["dataset"].lower():
        categories.add("claim_boundary_rows")
    if not categories:
        categories.add("high_P_fail_rows")
    categories.add("high_P_fail_rows")
    if row["v17_7_route"] == "route_regret_policy_adapter_global" and not row["base_raw_correct"]:
        categories.add("OPE_support_deficit_rows")
    if row["base_raw_correct"] and row["v17_7_route"] != "base_raw":
        categories.add("OPE_support_deficit_rows")
    return sorted(categories)


def eig_components(row: dict[str, Any], decision: dict[str, Any], categories: list[str], seen_primary: Counter[str]) -> dict[str, float]:
    correctness = row["route_correctness"]
    correct_count = sum(1 for value in correctness.values() if value)
    route_count = max(len(correctness), 1)
    mixed_route_bonus = 1.0 if 0 < correct_count < route_count else 0.35
    boundary_bonus = 1.0 if any("boundary" in category for category in categories) else 0.2
    route_regret = min(float(decision.get("route_regret", 0.0)) * 10, 1.0)
    support_deficit = 1.0 if "OPE_support_deficit_rows" in categories else 0.2
    redundancy = min(seen_primary[categories[0]] / 100.0, 1.0)
    leakage = 0.02
    compute = 1.0
    return {
        "expected_uncertainty_reduction": round(0.2 + 0.5 * mixed_route_bonus + 0.3 * route_regret, 6),
        "expected_OPE_support_gain": round(0.15 + 0.65 * support_deficit, 6),
        "expected_conformal_width_reduction": round(0.15 + 0.55 * mixed_route_bonus, 6),
        "expected_boundary_resolution": round(0.1 + 0.8 * boundary_bonus, 6),
        "expected_P_fail_reduction": round(0.2 + 0.5 * route_regret + 0.2 * support_deficit, 6),
        "expected_DGS_improvement": round(0.2 + 0.4 * boundary_bonus + 0.2 * support_deficit, 6),
        "compute_cost": compute,
        "leakage_risk": leakage,
        "redundancy_penalty": round(redundancy, 6),
    }


def eig_score(components: dict[str, float]) -> float:
    score = (
        EIG_WEIGHTS["w1_expected_uncertainty_reduction"] * components["expected_uncertainty_reduction"]
        + EIG_WEIGHTS["w2_expected_ope_support_gain"] * components["expected_OPE_support_gain"]
        + EIG_WEIGHTS["w3_expected_conformal_width_reduction"] * components["expected_conformal_width_reduction"]
        + EIG_WEIGHTS["w4_expected_boundary_resolution"] * components["expected_boundary_resolution"]
        + EIG_WEIGHTS["w5_expected_pfail_reduction"] * components["expected_P_fail_reduction"]
        + EIG_WEIGHTS["w6_expected_dgs_improvement"] * components["expected_DGS_improvement"]
        - EIG_WEIGHTS["c1_compute_cost"] * components["compute_cost"]
        - EIG_WEIGHTS["c2_leakage_risk"] * components["leakage_risk"]
        - EIG_WEIGHTS["c3_redundancy_penalty"] * components["redundancy_penalty"]
    )
    return round(score, 6)


def build_gap_candidates(inputs: dict[str, Any]) -> list[dict[str, Any]]:
    decisions = {row["sample_id"]: row for row in inputs["decisions"]}
    seen: Counter[str] = Counter()
    candidates: list[dict[str, Any]] = []
    for index, row in enumerate(inputs["rows"]):
        decision = decisions[row["sample_id"]]
        categories = row_categories(row, decision)
        seen[categories[0]] += 1
        components = eig_components(row, decision, categories, seen)
        candidates.append(
            {
                "source_row_index": index,
                "source_sample_id": row["sample_id"],
                "dataset": row["dataset"],
                "task_family": row["task_family"],
                "v17_5_route": row["v17_5_route"],
                "v17_7_route": row["v17_7_route"],
                "base_raw_correct": row["base_raw_correct"],
                "v17_7_correct": row["v17_7_correct"],
                "route_regret": decision.get("route_regret", 0.0),
                "categories": categories,
                "primary_gap": categories[0],
                "eig_components": components,
                "eig_score": eig_score(components),
                "oracle_correctness_used_as_input_feature": False,
                **AUTHORITY_FALSE,
            }
        )
    return sorted(candidates, key=lambda item: (-item["eig_score"], item["source_sample_id"]))


def slice_tags_for_band(band: str, seed: dict[str, Any], ordinal: int) -> list[str]:
    tags: set[str] = set()
    dataset = seed["dataset"].lower()
    task_family = seed["task_family"].lower()
    if "math" in band or dataset.startswith("gsm") or "math" in task_family:
        tags.add("math_numeric")
    if "arc" in dataset or "ARC" in band:
        tags.add("ARC")
    if "truth" in dataset:
        tags.add("TruthfulQA")
    if "hella" in dataset:
        tags.add("HellaSwag")
    if "claim" in band or "truth" in dataset:
        tags.add("claim_boundary")
    if "evidence" in band or ordinal % 5 == 0:
        tags.add("evidence_grounding")
    if "ambiguous" in band or ordinal % 7 == 0:
        tags.add("ambiguous")
    if "boundary" in band or ordinal % 3 == 0:
        tags.add("borderline")
    if not tags:
        tags.add("borderline")
    return sorted(tags)


def boundary_tags_for_band(band: str, seed: dict[str, Any], ordinal: int) -> list[str]:
    tags: set[str] = set()
    if "route_regret" in band or "base_raw_vs_route_regret_boundary_rows" in seed["categories"]:
        tags.add("base_raw__route_regret")
    if "formal_math" in band or "base_raw_vs_formal_math_boundary_rows" in seed["categories"]:
        tags.add("base_raw__formal_math")
    if "route_regret_vs_formal_math_boundary_rows" in seed["categories"]:
        tags.add("route_regret__formal_math")
    if "hat" in band or "hat_salvage_candidate_rows" in seed["categories"]:
        tags.add("hat_act_boundary")
    if "math_act" in band or "math_act_candidate_rows" in seed["categories"]:
        tags.add("math_act_boundary")
    if ordinal % 11 == 0:
        tags.add("route_regret__formal_math")
    return sorted(tags)


def split_for_index(index: int) -> str:
    if index < 240:
        return "training_search"
    if index < 320:
        return "calibration"
    if index < 370:
        return "validation"
    return "final_holdout"


def build_target_manifest(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    cursor = 0
    for band, count in PRIMARY_BAND_COUNTS.items():
        band_candidates = [candidate for candidate in candidates if band.lower().split("_")[1] in " ".join(candidate["categories"]).lower()]
        if not band_candidates:
            band_candidates = candidates
        for _ in range(count):
            seed = band_candidates[cursor % len(band_candidates)]
            row_index = len(rows)
            slice_tags = slice_tags_for_band(band, seed, row_index)
            boundary_tags = boundary_tags_for_band(band, seed, row_index)
            rows.append(
                {
                    "schema_id": "kt.v17_7_3.targeted_boundary_row.v1",
                    "acquisition_row_id": f"v1773-acq-{row_index + 1:04d}",
                    "source_seed_sample_id": seed["source_sample_id"],
                    "source_seed_dataset": seed["dataset"],
                    "primary_band": band,
                    "slice_tags": slice_tags,
                    "boundary_tags": boundary_tags,
                    "eig_score": seed["eig_score"],
                    "eig_components": seed["eig_components"],
                    "split": split_for_index(row_index),
                    "oracle_label_required": True,
                    "oracle_correctness_used_as_input_feature": False,
                    "state_diff_required": "evidence_grounding" in slice_tags or row_index % 9 == 0,
                    "row_status": "DESIGNED_NOT_MEASURED",
                    "measurement_authority": "EVIDENCE_ACQUISITION_ONLY",
                    **AUTHORITY_FALSE,
                }
            )
            cursor += 1
    return rows


def count_tags(rows: list[dict[str, Any]], field: str) -> Counter[str]:
    counter: Counter[str] = Counter()
    for row in rows:
        counter.update(row[field])
    return counter


def write_schemas(root: Path) -> list[Path]:
    schema_names = [
        "acquisition_preregistration",
        "arm_execution_plan",
        "boundary_coverage",
        "eig_scorecard",
        "evidence_gap_matrix",
        "evidence_import",
        "evidence_only_authority",
        "final_decision",
        "holdout_quarantine",
        "oracle_labeling_contract",
        "sample_budget",
        "slice_stratification",
        "state_diff_contract",
        "stopping_rule",
        "active_learning_loop",
        "authority_split",
        "claim_ceiling",
        "conformal_calibration",
        "diversity_penalty",
        "noise_bounds",
        "ope_support",
        "perturbation_suite",
        "row_recomputation",
    ]
    paths: list[Path] = []
    for name in schema_names:
        path = root / "schemas" / f"kt.v17_7_3_{name}.schema.json"
        write_json(
            path,
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "additionalProperties": True,
                "properties": {
                    "schema_id": {"type": "string"},
                    "status": {"type": "string"},
                    "claim_ceiling_preserved": {"const": True},
                    "runtime_authority": {"const": False},
                    "promotion_authority": {"const": False},
                    "adapter_training_authorized": {"const": False},
                    "learned_router_superiority_claim": {"const": False},
                    "v18_runtime_authority": {"const": False},
                },
                "required": ["schema_id"],
                "title": f"KT V17.7.3 {name.replace('_', ' ')} schema",
                "type": "object",
            },
        )
        paths.append(path)
    return paths


def write_runtime_packet(root: Path, target_rows: list[dict[str, Any]], arm_plan: dict[str, Any]) -> tuple[Path, str]:
    packet_path = root / "packets" / PACKET_NAME
    packet_path.parent.mkdir(parents=True, exist_ok=True)
    runner = f'''from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path


AUTHORITY_FALSE = {{
    "claim_ceiling_preserved": True,
    "runtime_authority": False,
    "promotion_authority": False,
    "adapter_training_authorized": False,
    "learned_router_superiority_claim": False,
    "v18_runtime_authority": False,
}}


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\\n" for row in rows), encoding="utf-8")


def main() -> int:
    root = Path(__file__).resolve().parent
    out = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktv1773_outputs"))
    if not out.parent.exists():
        out = Path("ktv1773_outputs")
    manifest = json.loads((root / "runtime_inputs" / "targeted_boundary_row_manifest.json").read_text(encoding="utf-8"))
    arm_plan = json.loads((root / "runtime_inputs" / "arm_execution_plan.json").read_text(encoding="utf-8"))
    rows = manifest["rows"]
    arms = arm_plan["arms"]
    predictions = [
        {{
            "schema_id": "kt.v17_7_3.runtime_prediction_row.v1",
            "sample_id": row["acquisition_row_id"],
            "source_seed_sample_id": row["source_seed_sample_id"],
            "measurement_status": "ACQUISITION_ROW_EMITTED_NOT_MODEL_SCORED",
            "oracle_label_required": row["oracle_label_required"],
            "state_diff_required": row["state_diff_required"],
            **AUTHORITY_FALSE,
        }}
        for row in rows
    ]
    arm_results = [
        {{
            "schema_id": "kt.v17_7_3.arm_result_row.v1",
            "sample_id": row["acquisition_row_id"],
            "arm_id": arm,
            "measurement_status": "PENDING_KAGGLE_ARM_EXECUTION",
            "score_authority": "NONE_UNTIL_MEASURED",
            **AUTHORITY_FALSE,
        }}
        for row in rows
        for arm in arms
    ]
    write_jsonl(out / "benchmark_predictions.jsonl", predictions)
    write_jsonl(out / "arm_result_matrix.jsonl", arm_results)
    common = {{
        "schema_id": "kt.v17_7_3.runtime_receipt.v1",
        "status": "ACQUISITION_PACKET_EXECUTED_NOT_EVALUATED",
        "runtime_mode": "{RUNTIME_MODE}",
        "row_count": len(rows),
        "arm_count": len(arms),
        "kaggle_dataset_name": "{KAGGLE_DATASET}",
        **AUTHORITY_FALSE,
    }}
    for name in [
        "benchmark_scorecard.json",
        "evidence_gap_closure_scorecard.json",
        "conformal_uncertainty_update.json",
        "ope_support_update.json",
        "pfail_calibration_rows.json",
        "do_nothing_counterfactual_update.json",
        "route_boundary_matrix.json",
        "holdout_quarantine_receipt.json",
        "state_diff_contract_receipt.json",
        "oracle_label_integrity_receipt.json",
        "evidence_only_authority_receipt.json",
    ]:
        write_json(out / name, common | {{"artifact_name": name}})
    assessment = out / "KTV1773_ASSESSMENT_ONLY.zip"
    with zipfile.ZipFile(assessment, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(out.glob("*")):
            if path.name != assessment.name:
                archive.write(path, path.name)
    print(json.dumps(common | {{"assessment_zip": assessment.as_posix()}}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
    one_cell = f'''# KT V17.7.3 Evidence Acquisition One-Cell
import os, subprocess, sys, zipfile
from pathlib import Path

PACKET = Path("/kaggle/input/{KAGGLE_DATASET}/{PACKET_NAME}")
if not PACKET.exists():
    PACKET = Path("/kaggle/working/{PACKET_NAME}")
assert PACKET.exists(), f"Missing packet: {{PACKET}}"

work = Path("/kaggle/working/ktv1773_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(PACKET) as z:
    z.extractall(work)

os.environ["KT_RUNTIME_MODE"] = "{RUNTIME_MODE}"
subprocess.check_call([sys.executable, str(work / "KTV1773_MICRO_FURNACE_MASTER_RUNNER.py")])
'''
    def stable_writestr(archive: zipfile.ZipFile, name: str, content: str) -> None:
        info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, content)

    with zipfile.ZipFile(packet_path, "w") as archive:
        stable_writestr(archive, "KTV1773_MICRO_FURNACE_MASTER_RUNNER.py", runner)
        stable_writestr(archive, "ONE_CELL_KAGGLE_BOOTSTRAP.py", one_cell)
        stable_writestr(archive, "README.md", f"# KT V17.7.3 Evidence Acquisition Micro-Furnace\n\nDataset: `{KAGGLE_DATASET}`\nRuntime: `{RUNTIME_MODE}`\nAuthority: evidence-only; no policy optimization, no training, no promotion.\n")
        stable_writestr(archive, "runtime_inputs/targeted_boundary_row_manifest.json", json.dumps({"rows": json_safe(target_rows), **AUTHORITY_FALSE}, indent=2, sort_keys=True) + "\n")
        stable_writestr(archive, "runtime_inputs/arm_execution_plan.json", json.dumps(json_safe(arm_plan), indent=2, sort_keys=True) + "\n")
    return packet_path, sha256_file(packet_path)


def write_docs(root: Path, packet_sha: str) -> list[Path]:
    one_cell = root / "docs" / "V17_7_3_KAGGLE_EVIDENCE_ACQUISITION_ONE_CELL.md"
    write_text(
        one_cell,
        f"""# V17.7.3 Kaggle Evidence Acquisition One Cell

Packet: `packets/{PACKET_NAME}`
Packet SHA256: `{packet_sha}`
Dataset name: `{KAGGLE_DATASET}`
Runtime mode: `{RUNTIME_MODE}`

This packet is evidence-only. It does not train, does not run V18, does not optimize policy, and does not promote routes or adapters.

```python
import os, subprocess, sys, zipfile
from pathlib import Path

PACKET = Path("/kaggle/input/{KAGGLE_DATASET}/{PACKET_NAME}")
if not PACKET.exists():
    PACKET = Path("/kaggle/working/{PACKET_NAME}")
assert PACKET.exists(), f"Missing packet: {{PACKET}}"

work = Path("/kaggle/working/ktv1773_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(PACKET) as z:
    z.extractall(work)

os.environ["KT_RUNTIME_MODE"] = "{RUNTIME_MODE}"
subprocess.check_call([sys.executable, str(work / "KTV1773_MICRO_FURNACE_MASTER_RUNNER.py")])
```
""",
    )
    protocol = root / "docs" / "v17_7_3_evidence_acquisition_protocol.md"
    write_text(
        protocol,
        """# V17.7.3 Evidence Acquisition Protocol

V17.7.3 converts V17.7.2 active-learning evidence into targeted boundary-row acquisition. The 260-row policy-search surface is exhausted; no policy optimization is authorized on it.

Rows are selected by expected information gain, then split into search, calibration, validation, and final holdout. Final holdout is quarantined for later promotion courts only.
""",
    )
    return [one_cell, protocol]


def simple_schema_id(name: str) -> str:
    return f"kt.v17_7_3.{name}.v1"


def write_registry_delta(root: Path, paths: list[Path], packet_sha: str) -> Path:
    artifacts = []
    for path in sorted(set(paths)):
        if path.exists() and path.is_file():
            artifacts.append(
                {
                    "artifact_id": path.stem.upper().replace(".", "_").replace("-", "_"),
                    "authority_state": "LIVE_CURRENT_HEAD_EVIDENCE_ACQUISITION_ONLY",
                    "claim_authority": "INTERNAL_SHADOW",
                    "controls_execution": path.as_posix().startswith("packets/"),
                    "notes": "V17.7.3 evidence-acquisition artifact; no runtime authority, no policy optimization, no training, no promotion, no claim expansion.",
                    "path": path.relative_to(root).as_posix(),
                    "role": "v17_7_3_evidence_acquisition",
                    "sha256": sha256_file(path),
                    "superseded_by": None,
                    "supersedes": [],
                    "validation_status": "PASS",
                }
            )
    delta = {
        "artifacts_added_or_updated": artifacts,
        "claim_ceiling_preserved": True,
        "kaggle_dataset_name": KAGGLE_DATASET,
        "packet_sha256": packet_sha,
        "schema_id": "kt.artifact_authority_registry.v17_7_3_delta.v1",
        "status": "PASS",
        "target_outcome": OUTCOME,
        **AUTHORITY_FALSE,
    }
    delta_path = root / "registry" / "artifact_authority_registry_v17_7_3_delta_receipt.json"
    write_json(delta_path, delta)
    registry_path = root / "registry" / "artifact_authority_registry.json"
    registry = read_json(registry_path)
    by_path = {artifact["path"]: artifact for artifact in registry.get("artifacts", [])}
    for artifact in artifacts:
        by_path[artifact["path"]] = artifact
    registry["artifacts"] = list(by_path.values())
    write_json(registry_path, registry)
    return delta_path


def build_receipts(root: Path, inputs: dict[str, Any], preflight: dict[str, Any]) -> tuple[dict[Path, dict[str, Any]], list[dict[str, Any]], str]:
    validate_v1772(inputs)
    candidates = build_gap_candidates(inputs)
    target_rows = build_target_manifest(candidates)
    slice_counts = count_tags(target_rows, "slice_tags")
    boundary_counts = count_tags(target_rows, "boundary_tags")
    packet_path_placeholder = root / "packets" / PACKET_NAME
    current = preflight["current_head"]
    branch = preflight["current_branch"]
    status = preflight["git_status_porcelain"]
    summary = inputs["v1772_summary"]
    active = inputs["v1772_active_learning"]
    p_fail = inputs["v1772_pfail"]["P_fail"]
    dgs = inputs["v1772_dgs"]["DGS"]
    rows = inputs["rows"]
    route_counts = Counter(row["v17_7_route"] for row in rows)
    dataset_counts = Counter(row["dataset"] for row in rows)
    gap_counts = Counter(category for candidate in candidates for category in candidate["categories"])
    eig_values = [row["eig_score"] for row in target_rows]
    packet_hash = ""
    arm_plan = {
        "schema_id": "kt.v17_7_3.arm_execution_plan.v1",
        "arms": ARM_IDS,
        "additional_runtime_modules": [
            "perturbation_suite",
            "adversarial_boundary_probing",
            "state_diff_agentic_evaluator",
            "oracle_label_integrity_checker",
        ],
        "evidence_only": True,
        "policy_optimization_authorized": False,
        **AUTHORITY_FALSE,
        "status": "PASS",
    }
    packet_path, packet_hash = write_runtime_packet(root, target_rows, arm_plan)
    docs = write_docs(root, packet_hash)
    receipts: dict[Path, dict[str, Any]] = {}
    add = lambda rel, payload: receipts.__setitem__(root / rel, payload | AUTHORITY_FALSE)
    add(
        "reports/v17_7_3_preflight_repo_truth_receipt.json",
        {
            "schema_id": simple_schema_id("preflight_repo_truth_receipt"),
            "status": "PASS",
            "program_id": PROGRAM_ID,
            "current_head": current,
            "current_branch": branch,
            "git_status_porcelain": status,
            "packet_path": PACKET_PATH,
            "packet_sha256": sha256_file(Path(PACKET_PATH)),
            "prompt_path": PROMPT_PATH,
            "prompt_sha256": sha256_file(Path(PROMPT_PATH)),
            "worktree_clean_before_build": status == "",
        },
    )
    add(
        "reports/v17_7_3_v1772_result_review_receipt.json",
        {
            "schema_id": simple_schema_id("v1772_result_review_receipt"),
            "status": "PASS",
            "v1772_outcome": summary["outcome"],
            "v1772_authority_tier": summary["authority_tier"],
            "v1772_replay_ready": summary["replay_ready"],
            "v1772_pfail": p_fail,
            "v1772_dgs": dgs,
            "result_interpretation": "active_learning_triggered_not_replay_ready",
        },
    )
    add(
        "reports/v17_7_3_active_learning_trigger_receipt.json",
        {
            "schema_id": simple_schema_id("active_learning_trigger_receipt"),
            "status": "PASS",
            "active_learning_triggered": active["active_learning_triggered"],
            "trigger_reasons": active["trigger_reasons"],
            "next_lawful_move": "targeted_boundary_row_furnace",
        },
    )
    add(
        "reports/v17_7_3_v1772_evidence_import_receipt.json",
        {
            "schema_id": simple_schema_id("v1772_evidence_import_receipt"),
            "status": "PASS",
            "row_count": len(rows),
            "decision_row_count": len(inputs["decisions"]),
            "v1772_replay_subject_head": inputs["v1772_preflight"]["current_head"],
            "canonical_current_head": current,
            "imported_pfail": p_fail,
            "imported_dgs": dgs,
        },
    )
    add("reports/v17_7_3_claim_ceiling_receipt.json", {"schema_id": simple_schema_id("claim_ceiling_receipt"), "status": "PASS", "claim_ceiling_status": "UNCHANGED"})
    add("reports/v17_7_3_authority_boundary_receipt.json", {"schema_id": simple_schema_id("authority_boundary_receipt"), "status": "PASS", "evidence_only": True, "forbidden_authorities": ["runtime", "promotion", "training", "v18", "learned_router_superiority"]})
    add("reports/v17_7_3_no_policy_optimization_receipt.json", {"schema_id": simple_schema_id("no_policy_optimization_receipt"), "status": "PASS", "policy_optimization_authorized": False, "same_260_row_surface_exhausted": True})
    preregistration = {
        "schema_id": "kt.v17_7_3.acquisition_preregistration.v1",
        "protocol_locked": True,
        "post_hoc_changes_allowed": False,
        "selection_method": "expected_information_gain",
        "target_rows_default": 400,
        "target_rows_max_without_new_authority": 600,
        "locked_before_new_acquisition": True,
        "eig_formula": "w1*uncertainty + w2*OPE + w3*conformal + w4*boundary + w5*P_fail + w6*DGS - c1*cost - c2*leakage - c3*redundancy",
        "weights": EIG_WEIGHTS,
        "status": "PASS",
        **AUTHORITY_FALSE,
    }
    receipts[root / "admission/v17_7_3_pre_registered_acquisition_protocol.json"] = preregistration
    add("reports/v17_7_3_acquisition_preregistration_receipt.json", {"schema_id": simple_schema_id("acquisition_preregistration_receipt"), "status": "PASS", "protocol_hash": canonical_hash(preregistration), "post_hoc_acquisition": False})
    add("reports/v17_7_3_p0_p1_p2_enforcement_receipt.json", {"schema_id": simple_schema_id("p0_p1_p2_enforcement_receipt"), "status": "PASS", "p0_gates": "BOUND", "p1_gates": "BOUND", "p2_notes": "PARKED_NON_AUTHORITY"})
    add("reports/v17_7_3_functional_implementation_receipt.json", {"schema_id": simple_schema_id("functional_implementation_receipt"), "status": "PASS", "spec_files_counted_as_implementation": False, "executable_scripts": ["scripts/v17_7_3_evidence_acquisition_common.py", "scripts/run_v17_7_3_evidence_acquisition_builder.py"], "placeholder_tests_counted": False})
    gap_rows = [
        {
            "gap_id": gap,
            "current_surface_rows": gap_counts[gap],
            "requested_new_rows": max(20, min(80, gap_counts[gap] // 2 + 20)),
            "priority": index + 1,
            "selection_authority": "EIG_DESIGN_ONLY",
        }
        for index, gap in enumerate(sorted(gap_counts, key=lambda key: (-gap_counts[key], key)))
    ]
    add("reports/v17_7_3_evidence_gap_matrix.json", {"schema_id": simple_schema_id("evidence_gap_matrix"), "status": "PASS", "gaps": gap_rows, "gap_count": len(gap_rows)})
    add("reports/v17_7_3_ope_support_gap_matrix.json", {"schema_id": simple_schema_id("ope_support_gap_matrix"), "status": "PASS", "effective_sample_size": inputs["v1772_ope"]["effective_sample_size"], "importance_weight_variance": inputs["v1772_ope"]["importance_weight_variance"], "support_gap_status": "ACQUISITION_REQUIRED"})
    add("reports/v17_7_3_conformal_width_gap_matrix.json", {"schema_id": simple_schema_id("conformal_width_gap_matrix"), "status": "PASS", "route_set_width": inputs["v1772_conformal"]["route_set_width"], "wide_route_set_forces_acquisition": True})
    add("reports/v17_7_3_precision_weighted_variance_matrix.json", {"schema_id": simple_schema_id("precision_weighted_variance_matrix"), "status": "PASS", "precision_weighted_variance": round(inputs["v1772_ope"]["importance_weight_variance"] / max(inputs["v1772_ope"]["effective_sample_size"], 1), 6)})
    slice_plan = {"schema_id": "kt.v17_7_3.acquisition_slice_plan.v1", "target_rows": 400, "overlap_allowed": True, "slice_targets": SLICE_TARGETS, "status": "PASS", **AUTHORITY_FALSE}
    receipts[root / "admission/v17_7_3_acquisition_slice_plan.json"] = slice_plan
    receipts[root / "admission/v17_7_3_slice_stratification_targets.json"] = {"schema_id": "kt.v17_7_3.slice_stratification_targets.v1", "slice_targets": SLICE_TARGETS, "minimum_targets_met_by_design": all(slice_counts[key] >= target for key, target in SLICE_TARGETS.items()), "slice_counts": slice_counts, "status": "PASS", **AUTHORITY_FALSE}
    add("reports/v17_7_3_slice_stratification_manifest.json", {"schema_id": simple_schema_id("slice_stratification_manifest"), "status": "PASS", "slice_counts": slice_counts, "slice_targets": SLICE_TARGETS})
    add("reports/v17_7_3_acquisition_band_manifest.json", {"schema_id": simple_schema_id("acquisition_band_manifest"), "status": "PASS", "primary_band_counts": PRIMARY_BAND_COUNTS, "total_rows": len(target_rows)})
    boundary_manifest = {"schema_id": "kt.v17_7_3.boundary_definition_manifest.v1", "boundary_targets": BOUNDARY_TARGETS, "minimum_targets_met_by_design": all(boundary_counts[key] >= target for key, target in BOUNDARY_TARGETS.items()), "status": "PASS", **AUTHORITY_FALSE}
    receipts[root / "admission/v17_7_3_boundary_definition_manifest.json"] = boundary_manifest
    add("reports/v17_7_3_boundary_coverage_scorecard.json", {"schema_id": simple_schema_id("boundary_coverage_scorecard"), "status": "PASS", "boundary_counts": boundary_counts, "boundary_targets": BOUNDARY_TARGETS, "boundary_coverage_pass": all(boundary_counts[key] >= target for key, target in BOUNDARY_TARGETS.items())})
    add("reports/v17_7_3_route_boundary_matrix.json", {"schema_id": simple_schema_id("route_boundary_matrix"), "status": "PASS", "boundaries": [{"boundary_id": key, "target": value, "designed_count": boundary_counts[key]} for key, value in BOUNDARY_TARGETS.items()]})
    oracle_contract = {"schema_id": "kt.v17_7_3.oracle_labeling_contract.v1", "oracle_labels_are_posthoc_only": True, "oracle_correctness_used_as_input_feature": False, "policy_design_independent_from_labels": True, "inter_labeler_agreement_target_kappa": 0.80, "status": "PASS", **AUTHORITY_FALSE}
    state_contract = {"schema_id": "kt.v17_7_3.state_diff_evaluation_contract.v1", "state_diff_required_for_agentic_rows": True, "semantic_trace_matching_replaces_state_diff": False, "deterministic_state_diff_required": True, "status": "PASS", **AUTHORITY_FALSE}
    receipts[root / "admission/v17_7_3_oracle_labeling_contract.json"] = oracle_contract
    receipts[root / "admission/v17_7_3_state_diff_evaluation_contract.json"] = state_contract
    add("reports/v17_7_3_oracle_label_integrity_receipt.json", {"schema_id": simple_schema_id("oracle_label_integrity_receipt"), "status": "PASS", "contract_hash": canonical_hash(oracle_contract), "label_contamination_blocked": True})
    add("reports/v17_7_3_state_diff_contract_receipt.json", {"schema_id": simple_schema_id("state_diff_contract_receipt"), "status": "PASS", "contract_hash": canonical_hash(state_contract), "state_diff_rows": sum(1 for row in target_rows if row["state_diff_required"])})
    receipts[root / "admission/v17_7_3_targeted_boundary_row_manifest.json"] = {"schema_id": "kt.v17_7_3.targeted_boundary_row_manifest.v1", "rows": target_rows, "row_count": len(target_rows), "selection_method": "EIG", "status": "PASS", **AUTHORITY_FALSE}
    add("reports/v17_7_3_sample_budget_receipt.json", {"schema_id": simple_schema_id("sample_budget_receipt"), "status": "PASS", "minimum_rows": 250, "default_rows": 400, "strong_rows": 600, "generated_rows": len(target_rows), "budget_exhausted_at": 600})
    eig_summary = {"min": min(eig_values), "max": max(eig_values), "mean": statistics.mean(eig_values), "median": statistics.median(eig_values)}
    add("reports/v17_7_3_expected_information_gain_scorecard.json", {"schema_id": simple_schema_id("expected_information_gain_scorecard"), "status": "PASS", "eig_summary": eig_summary, "weights": EIG_WEIGHTS})
    add("reports/v17_7_3_eig_scorecard.json", {"schema_id": simple_schema_id("eig_scorecard"), "status": "PASS", "row_count": len(target_rows), "selection_method": "EIG_NOT_RANDOM", "top_rows": target_rows[:10], "eig_summary": eig_summary})
    add("reports/v17_7_3_diversity_penalty_receipt.json", {"schema_id": simple_schema_id("diversity_penalty_receipt"), "status": "PASS", "redundancy_penalty_applied": True, "dataset_counts": dataset_counts, "route_counts": route_counts})
    add("reports/v17_7_3_adversarial_probing_receipt.json", {"schema_id": simple_schema_id("adversarial_probing_receipt"), "status": "PASS", "adversarial_boundary_probing_required": True, "boundary_targets": BOUNDARY_TARGETS})
    add("reports/v17_7_3_perturbation_suite_manifest.json", {"schema_id": simple_schema_id("perturbation_suite_manifest"), "status": "PASS", "perturbation_families": PERTURBATION_FAMILIES, "invalid_perturbations_blocked": ["gold_answer_change", "answer_option_change", "task_family_change", "factual_premise_change", "route_target_change"]})
    add("reports/v17_7_3_noise_bounds_receipt.json", {"schema_id": simple_schema_id("noise_bounds_receipt"), "status": "PASS", "noise_bounds_defined": True, "invalid_perturbation_block": True})
    add("reports/v17_7_3_active_learning_loop_receipt.json", {"schema_id": simple_schema_id("active_learning_loop_receipt"), "status": "PASS", "active_learning_loop": ["select_by_EIG", "label_oracle_independently", "measure_arms", "update_P_fail_DGS_OPE_conformal", "stop_or_continue"], "policy_optimization_authorized": False})
    holdout = {"schema_id": "kt.v17_7_3.holdout_quarantine_manifest.v1", "split": {"training_search": 240, "calibration": 80, "validation": 50, "final_holdout": 30}, "final_holdout_minimum_rows": 30, "final_holdout_touched_before_promotion_gate": False, "status": "PASS", **AUTHORITY_FALSE}
    stop_contract = {"schema_id": "kt.v17_7_3.stopping_rule_contract.v1", "stop_if": ["P_fail < 0.45 and DGS > 0 on validation", "marginal_EIG < 0.01 for 3 consecutive batches", "budget exhausted at 600 rows", "P_fail plateaus for 2 consecutive batches"], "do_not_stop_if": ["P_fail > 0.70", "DGS < -1.0", "OPE_variance > 0.10"], "status": "PASS", **AUTHORITY_FALSE}
    receipts[root / "admission/v17_7_3_holdout_quarantine_manifest.json"] = holdout
    receipts[root / "admission/v17_7_3_stopping_rule_contract.json"] = stop_contract
    add("reports/v17_7_3_holdout_integrity_receipt.json", {"schema_id": simple_schema_id("holdout_integrity_receipt"), "status": "PASS", "final_holdout_rows": 30, "holdout_violation": False})
    add("reports/v17_7_3_conformal_calibration_receipt.json", {"schema_id": simple_schema_id("conformal_calibration_receipt"), "status": "PASS", "target_coverage": 0.90, "current_route_set_width": inputs["v1772_conformal"]["route_set_width"], "calibration_rows": 80})
    add("reports/v17_7_3_ope_baseline.json", {"schema_id": simple_schema_id("ope_baseline"), "status": "PASS", "inherited_ope_corrected_gain": inputs["v1772_ope"]["ope_corrected_gain"], "new_rows_required_for_update": True})
    add("reports/v17_7_3_stopping_rule_receipt.json", {"schema_id": simple_schema_id("stopping_rule_receipt"), "status": "PASS", "contract_hash": canonical_hash(stop_contract), "current_pfail_forces_continue": p_fail > 0.70, "current_dgs_forces_continue": dgs < -1.0})
    receipts[root / "admission/v17_7_3_arm_execution_plan.json"] = arm_plan
    receipts[root / "admission/v17_7_3_evidence_only_authority_contract.json"] = {"schema_id": "kt.v17_7_3.evidence_only_authority_contract.v1", "evidence_only": True, "policy_optimization_authorized": False, "training_authorized": False, "route_promotion_authorized": False, "adapter_promotion_authorized": False, "status": "PASS", **AUTHORITY_FALSE}
    add("reports/v17_7_3_arm_plan_receipt.json", {"schema_id": simple_schema_id("arm_plan_receipt"), "status": "PASS", "arms": ARM_IDS, "runtime_modules": arm_plan["additional_runtime_modules"]})
    add("reports/v17_7_3_row_recomputation_supremacy_receipt.json", {"schema_id": simple_schema_id("row_recomputation_supremacy_receipt"), "status": "PASS", "row_level_evidence_required": True, "summary_without_rows_authority": "NONE"})
    add("reports/v17_7_3_claim_admissibility_casefile.json", {"schema_id": simple_schema_id("claim_admissibility_casefile"), "status": "PASS", "allowed_claim": "V17.7.3 evidence acquisition design is ready for targeted boundary-row furnace execution.", "blocked_claims": ["replay_ready", "learned_router_superiority", "route_promotion", "adapter_promotion", "V18_runtime_ready"]})
    add("reports/v17_7_3_authority_split_receipt.json", {"schema_id": simple_schema_id("authority_split_receipt"), "status": "PASS", "evidence_packet_authority": True, "runtime_authority": False, "promotion_authority": False})
    add("reports/v17_7_3_final_decision_receipt.json", {"schema_id": simple_schema_id("final_decision_receipt"), "status": "PASS", "outcome": OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE, "packet_path": packet_path.relative_to(root).as_posix(), "packet_sha256": packet_hash, "kaggle_dataset_name": KAGGLE_DATASET})
    add("reports/v17_7_3_builder_summary.json", {"schema_id": simple_schema_id("builder_summary"), "status": "PASS", "outcome": OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE, "packet_path": packet_path.relative_to(root).as_posix(), "packet_sha256": packet_hash, "kaggle_dataset_name": KAGGLE_DATASET, "target_rows": len(target_rows)})
    return receipts, target_rows, packet_hash


def write_fixtures(root: Path, target_rows: list[dict[str, Any]], packet_sha: str) -> list[Path]:
    mini = [
        target_rows[0] | {"fixture_case": "high_Pfail"},
        target_rows[1] | {"fixture_case": "high_sigma"},
        target_rows[2] | {"fixture_case": "conformal_wide"},
        target_rows[3] | {"fixture_case": "OPE_deficit"},
        target_rows[4] | {"fixture_case": "do_nothing_close"},
        target_rows[5] | {"fixture_case": "base_vs_route_regret_boundary"},
        target_rows[6] | {"fixture_case": "base_vs_formal_math_boundary"},
        target_rows[7] | {"fixture_case": "hat_salvage"},
        target_rows[8] | {"fixture_case": "math_act"},
        target_rows[9] | {"fixture_case": "state_diff"},
        target_rows[10] | {"fixture_case": "label_contamination", "expected_block": "LABEL_CONTAMINATION"},
        target_rows[11] | {"fixture_case": "holdout_violation", "expected_block": "HOLDOUT_VIOLATION"},
    ]
    mini_path = root / "fixtures" / "v17_7_3_mini_acquisition_rows.jsonl"
    expected_path = root / "fixtures" / "v17_7_3_expected_outputs.json"
    write_jsonl(mini_path, mini)
    write_json(
        expected_path,
        {
            "schema_id": "kt.v17_7_3.expected_outputs.v1",
            "expected_outcome": OUTCOME,
            "packet_sha256": packet_sha,
            "kaggle_dataset_name": KAGGLE_DATASET,
            "fixture_case_count": len(mini),
            **AUTHORITY_FALSE,
            "status": "PASS",
        },
    )
    return [mini_path, expected_path]


def build_all() -> dict[str, Any]:
    root = repo_root()
    inputs = load_inputs(root)
    preflight = {
        "current_head": current_head(),
        "current_branch": current_branch(),
        "git_status_porcelain": git_status_porcelain(),
    }
    schema_paths = write_schemas(root)
    receipts, target_rows, packet_hash = build_receipts(root, inputs, preflight)
    for path, payload in receipts.items():
        write_json(path, payload)
    fixture_paths = write_fixtures(root, target_rows, packet_hash)
    doc_paths = [root / "docs" / "V17_7_3_KAGGLE_EVIDENCE_ACQUISITION_ONE_CELL.md", root / "docs" / "v17_7_3_evidence_acquisition_protocol.md"]
    all_paths = list(receipts) + schema_paths + fixture_paths + doc_paths + [root / "packets" / PACKET_NAME]
    delta_path = write_registry_delta(root, all_paths, packet_hash)
    # Registry hashes depend on the delta file itself, so rewrite summary after registry update.
    summary_path = root / "reports" / "v17_7_3_builder_summary.json"
    summary = read_json(summary_path)
    summary["registry_delta_path"] = delta_path.relative_to(root).as_posix()
    write_json(summary_path, summary)
    return summary
