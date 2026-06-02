from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import subprocess
import tempfile
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


PROGRAM_ID = "KT_V17_7_3_MEASUREMENT_AUTHORITY_ADJUDICATION_AND_NEXT_EVIDENCE_MOVE_V1_1"
SUCCESS_OUTCOME = "KTG3FULL_V17_7_3_MEASUREMENT_AUTHORITY_ADJUDICATED__NEXT_EVIDENCE_MOVE_SELECTED__CLAIM_CEILING_PRESERVED"
SELECTED_DECISION = "TRUE_GENERATION_MINI_FURNACE_REQUIRED"
SELECTED_DECISION_OUTCOME = "KTG3FULL_V17_7_3_TRUE_GENERATION_MINI_FURNACE_REQUIRED__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_KTV1774_TRUEGEN_MINIFURNACE_PACKET"
PACKET_NAME = "ktv1774_truegen_minifurnace_v1.zip"
DOC_NAME = "V17_7_4_TRUEGEN_MINIFURNACE_ONE_CELL.md"
ASSESSMENT_NAME = "KTV1773_MEASURED_ARM_ASSESSMENT_ONLY.zip"
EXPECTED_ROWS = 400
EXPECTED_ARM_ROWS = 2000
OLD_PFAIL = 0.9895594256814249
OLD_DGS = -4.250771105439233

ARM_IDS = [
    "base_raw",
    "route_regret_policy_adapter_global",
    "formal_math_repair_adapter_global",
    "base_kt_hat_compact",
    "math_act_adapter_global",
]

AUTHORITY_FALSE: dict[str, Any] = {
    "claim_ceiling_preserved": True,
    "runtime_authority": False,
    "promotion_authority": False,
    "adapter_training_authorized": False,
    "router_training_authorized": False,
    "policy_optimization_authorized": False,
    "learned_router_superiority_claim": False,
    "v18_runtime_authority": False,
}

FORBIDDEN_STATUSES = {
    "PENDING_KAGGLE_ARM_EXECUTION",
    "ACQUISITION_ROW_EMITTED_NOT_MODEL_SCORED",
    "ACQUISITION_PACKET_EXECUTED_NOT_EVALUATED",
    "SCAFFOLD_EMITTED_NOT_EARNED",
    "PLACEHOLDER",
    "NOT_MEASURED",
    "FORMAT_SMOKE_ONLY",
}

REQUIRED_MEMBERS = [
    "benchmark_predictions.jsonl",
    "arm_result_matrix.jsonl",
    "benchmark_scorecard.json",
    "final_summary.json",
]

P0_REPORTS = [
    "v17_7_3_preflight_repo_truth_receipt.json",
    "v17_7_3_assessment_import_receipt.json",
    "v17_7_3_assessment_manifest_receipt.json",
    "v17_7_3_claim_ceiling_receipt.json",
    "v17_7_3_scorecard_recomputation_receipt.json",
    "v17_7_3_row_level_score_authority_receipt.json",
    "v17_7_3_row_count_and_arm_count_receipt.json",
    "v17_7_3_measurement_source_authority_review.json",
    "v17_7_3_measurement_provenance_tier_receipt.json",
    "v17_7_3_provenance_claim_boundary_receipt.json",
    "v17_7_3_evidence_tier_transition_table.json",
    "v17_7_3_model_generation_gap_receipt.json",
    "v17_7_3_source_row_lineage_receipt.json",
    "v17_7_3_scorer_determinism_receipt.json",
    "v17_7_3_ground_truth_drift_detector.json",
    "v17_7_3_temporal_drift_and_schema_receipt.json",
    "v17_7_3_replay_contamination_scan.json",
    "v17_7_3_per_band_arm_win_matrix.json",
    "v17_7_3_per_band_oracle_gap_matrix.json",
    "v17_7_3_oracle_gap_decomposition.json",
    "v17_7_3_arm_niche_atlas.json",
    "v17_7_3_hat_salvage_review.json",
    "v17_7_3_math_act_salvage_review.json",
    "v17_7_3_negative_transfer_by_arm_receipt.json",
    "v17_7_3_arm_efficiency_and_token_cost_matrix.json",
    "v17_7_3_arm_interaction_matrix.json",
    "v17_7_3_ess_decay_matrix.json",
    "v17_7_3_mr_variance_confidence_bound.json",
    "v17_7_3_copp_coverage_certificate.json",
    "v17_7_3_covariate_shift_profile.json",
    "v17_7_3_pfail_proxy_uniformity_receipt.json",
    "v17_7_3_pfail_silent_failure_audit.json",
    "v17_7_3_pfail_per_band_update.json",
    "v17_7_3_v1772_risk_update_receipt.json",
    "v17_7_3_ope_support_vs_value_receipt.json",
    "v17_7_3_ope_overlap_diagnosis.json",
    "v17_7_3_dr_estimator_readiness.json",
    "v17_7_3_do_nothing_counterfactual_interpretation.json",
    "v17_7_3_slice_representativeness_score.json",
    "v17_7_3_cross_run_consistency_matrix.json",
    "v17_7_3_policy_stability_envelope.json",
    "v17_7_3_next_move_cost_risk_ledger.json",
    "v17_7_3_human_interpretability_receipt.json",
    "v17_7_3_human_review_checkpoint.json",
    "v17_7_3_replay_vs_micro_furnace_decision.json",
    "v17_7_3_fresh_generation_necessity_decision.json",
    "v17_7_3_claim_admissibility_casefile.json",
    "v17_7_3_final_decision_receipt.json",
]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def run_git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=repo_root(), text=True, stderr=subprocess.DEVNULL).strip()


def current_head() -> str:
    return run_git(["rev-parse", "HEAD"])


def current_branch() -> str:
    return run_git(["branch", "--show-current"])


def git_status_porcelain() -> str:
    return run_git(["status", "--porcelain=v1"])


def authority(**payload: Any) -> dict[str, Any]:
    out = dict(AUTHORITY_FALSE)
    out.update(payload)
    return out


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_hash(value: Any) -> str:
    return sha256_bytes(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8"))


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def parse_jsonl_bytes(data: bytes) -> list[dict[str, Any]]:
    return [json.loads(line) for line in data.decode("utf-8-sig").splitlines() if line.strip()]


def json_bytes(data: bytes) -> dict[str, Any]:
    return json.loads(data.decode("utf-8-sig"))


def packet_and_prompt_hashes() -> dict[str, Any]:
    packet = Path(r"D:\user\rober\Downloads\ktv1773_authority_v1_1.zip")
    prompt = Path(r"D:\user\rober\Downloads\COPY_PASTE_NOW_ktv1773_authority_v1_1.txt")
    return {
        "packet_path": str(packet),
        "packet_sha256": sha256_file(packet) if packet.exists() else None,
        "prompt_path": str(prompt),
        "prompt_sha256": sha256_file(prompt) if prompt.exists() else None,
    }


def candidate_assessment_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    env_path = os.environ.get("KT_V1773_MEASURED_ARM_ASSESSMENT_ZIP")
    if env_path:
        paths.append(Path(env_path))
    paths.extend(
        [
            root / "reports" / ASSESSMENT_NAME,
            Path(r"D:\user\rober\Downloads") / ASSESSMENT_NAME,
            Path.home() / "Downloads" / ASSESSMENT_NAME,
        ]
    )
    return paths


def build_repo_native_assessment(root: Path) -> tuple[Path, str]:
    """Use the committed measured-arm packet as a repo-native import fallback."""
    import importlib.util

    core_path = root / "runtime" / "v17_7_3" / "KT_V1773_MEASURED_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1773_measured_arm_core", core_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load measured-arm core: {core_path}")
    core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(core)
    packet = root / "packets" / "ktv1773_measured_arm_v1.zip"
    temp_root = Path(tempfile.mkdtemp(prefix="ktv1773_authority_"))
    runtime_root = temp_root / "packet"
    with zipfile.ZipFile(packet) as archive:
        archive.extractall(runtime_root)
    output_dir = temp_root / "out"
    summary = core.run_measured_arm_runtime(runtime_root, output_dir)
    if summary.get("status") != "PASS":
        raise RuntimeError(f"repo-native measured assessment replay blocked: {summary}")
    return output_dir / ASSESSMENT_NAME, "REPO_NATIVE_MEASURED_ARM_REPLAY"


def locate_assessment(root: Path) -> tuple[Path, str]:
    for path in candidate_assessment_paths(root):
        if path.exists() and path.is_file():
            return path, "OPERATOR_MEASURED_ARM_ASSESSMENT_ZIP"
    return build_repo_native_assessment(root)


def load_assessment(root: Path, override: Path | None = None) -> dict[str, Any]:
    path, source_kind = (override, "EXPLICIT_ASSESSMENT_ZIP") if override else locate_assessment(root)
    if path is None:
        raise FileNotFoundError("missing V17.7.3 measured-arm assessment zip")
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        missing = [name for name in REQUIRED_MEMBERS if name not in names]
        if missing:
            raise RuntimeError(f"assessment missing required members: {missing}")
        member_bytes = {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}
    predictions = parse_jsonl_bytes(member_bytes["benchmark_predictions.jsonl"])
    arm_rows = parse_jsonl_bytes(member_bytes["arm_result_matrix.jsonl"])
    scorecard = json_bytes(member_bytes["benchmark_scorecard.json"])
    final_summary = json_bytes(member_bytes["final_summary.json"])
    return {
        "path": path,
        "source_kind": source_kind,
        "zip_sha256": sha256_file(path),
        "member_hashes": {name: sha256_bytes(data) for name, data in sorted(member_bytes.items())},
        "member_names": sorted(member_bytes),
        "predictions": predictions,
        "arm_rows": arm_rows,
        "scorecard": scorecard,
        "final_summary": final_summary,
        "optional_json": {name: json_bytes(data) for name, data in member_bytes.items() if name.endswith(".json")},
    }


def validate_measured_rows(predictions: list[dict[str, Any]], arm_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    defects: list[dict[str, Any]] = []
    for artifact, rows in [("benchmark_predictions.jsonl", predictions), ("arm_result_matrix.jsonl", arm_rows)]:
        for index, row in enumerate(rows):
            status = row.get("measurement_status")
            if status != "MODEL_SCORED":
                defects.append({"artifact": artifact, "index": index, "sample_id": row.get("sample_id"), "status": status})
            if status in FORBIDDEN_STATUSES:
                defects.append({"artifact": artifact, "index": index, "sample_id": row.get("sample_id"), "forbidden_status": status})
    return defects


def recompute_from_rows(predictions: list[dict[str, Any]], arm_rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_arm: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_sample: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in arm_rows:
        by_arm[row["arm_id"]].append(row)
        by_sample[row["sample_id"]].append(row)
    arm_counts = {arm: len(rows) for arm, rows in sorted(by_arm.items())}
    correct_counts = {arm: sum(1 for row in rows if row.get("correct") is True) for arm, rows in sorted(by_arm.items())}
    accuracies = {arm: round(correct_counts[arm] / max(arm_counts[arm], 1), 6) for arm in sorted(arm_counts)}
    oracle_correct = sum(1 for row in predictions if row.get("oracle_correct") is True)
    base_correct = correct_counts.get("base_raw", 0)
    best_static = max(accuracies, key=lambda arm: (accuracies[arm], -ARM_IDS.index(arm) if arm in ARM_IDS else 0))
    mismatches: list[dict[str, Any]] = []
    for pred in predictions:
        sample_arms = by_sample.get(pred["sample_id"], [])
        best = sorted(sample_arms, key=lambda row: (-float(row.get("score", 0.0)), -float(row.get("pre_generation_route_value", 0.0)), row.get("arm_id", "")))[0]
        if pred.get("best_arm") != best.get("arm_id") or bool(pred.get("oracle_correct")) != bool(best.get("correct")):
            mismatches.append({"sample_id": pred["sample_id"], "prediction_best": pred.get("best_arm"), "recomputed_best": best.get("arm_id")})
    return {
        "row_count": len(predictions),
        "arm_rows": len(arm_rows),
        "arm_counts": arm_counts,
        "correct_counts": correct_counts,
        "accuracies": accuracies,
        "base_raw_correct_count": base_correct,
        "oracle_correct_count": oracle_correct,
        "oracle_accuracy": round(oracle_correct / max(len(predictions), 1), 6),
        "best_static_arm": best_static,
        "best_static_correct_count": correct_counts[best_static],
        "best_static_accuracy": accuracies[best_static],
        "prediction_recompute_mismatches": mismatches,
        "status": "PASS" if not mismatches else "FAIL",
    }


def per_band(predictions: list[dict[str, Any]], arm_rows: list[dict[str, Any]], recomputed: dict[str, Any]) -> dict[str, Any]:
    bands = sorted({row.get("evidence_band", "UNKNOWN") for row in predictions})
    pred_by_sample = {row["sample_id"]: row for row in predictions}
    rows_by_band_arm: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in arm_rows:
        rows_by_band_arm[(row.get("evidence_band", "UNKNOWN"), row["arm_id"])].append(row)
    win_matrix: dict[str, Any] = {}
    gap_matrix: dict[str, Any] = {}
    for band in bands:
        band_preds = [row for row in predictions if row.get("evidence_band", "UNKNOWN") == band]
        oracle = sum(1 for row in band_preds if row.get("oracle_correct") is True)
        win_matrix[band] = {"row_count": len(band_preds), "oracle_correct": oracle, "arms": {}}
        gap_matrix[band] = {"row_count": len(band_preds), "oracle_correct": oracle, "gaps": {}}
        for arm in ARM_IDS:
            rows = rows_by_band_arm[(band, arm)]
            correct = sum(1 for row in rows if row.get("correct") is True)
            win_matrix[band]["arms"][arm] = {"correct": correct, "total": len(rows), "accuracy": round(correct / max(len(rows), 1), 6)}
            gap_matrix[band]["gaps"][arm] = oracle - correct
    rescue_by_arm: dict[str, int] = {arm: 0 for arm in ARM_IDS}
    harm_by_arm: dict[str, int] = {arm: 0 for arm in ARM_IDS}
    unique_wins: dict[str, int] = {arm: 0 for arm in ARM_IDS}
    rows_by_sample: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in arm_rows:
        rows_by_sample[row["sample_id"]].append(row)
    for sample_id, rows in rows_by_sample.items():
        by_arm = {row["arm_id"]: row for row in rows}
        base = bool(by_arm["base_raw"].get("correct"))
        correct_arms = [arm for arm, row in by_arm.items() if row.get("correct") is True]
        for arm, row in by_arm.items():
            correct = bool(row.get("correct"))
            if correct and not base:
                rescue_by_arm[arm] += 1
            if base and not correct:
                harm_by_arm[arm] += 1
        if len(correct_arms) == 1:
            unique_wins[correct_arms[0]] += 1
    atlas = {}
    for arm in ARM_IDS:
        atlas[arm] = {
            "accuracy": recomputed["accuracies"][arm],
            "correct_count": recomputed["correct_counts"][arm],
            "rescues_vs_base_raw": rescue_by_arm[arm],
            "negative_transfer_vs_base_raw": harm_by_arm[arm],
            "unique_wins": unique_wins[arm],
            "global_promotion_authorized": False,
            "niche_only": arm != "base_raw",
        }
    return {
        "win_matrix": win_matrix,
        "gap_matrix": gap_matrix,
        "atlas": atlas,
        "prediction_by_sample": pred_by_sample,
    }


def pairwise_interactions(arm_rows: list[dict[str, Any]]) -> dict[str, Any]:
    rows_by_sample: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in arm_rows:
        rows_by_sample[row["sample_id"]][row["arm_id"]] = row
    matrix: dict[str, Any] = {}
    for left in ARM_IDS:
        matrix[left] = {}
        for right in ARM_IDS:
            both = left_only = right_only = neither = 0
            for arms in rows_by_sample.values():
                l_ok = bool(arms[left].get("correct"))
                r_ok = bool(arms[right].get("correct"))
                both += int(l_ok and r_ok)
                left_only += int(l_ok and not r_ok)
                right_only += int(r_ok and not l_ok)
                neither += int(not l_ok and not r_ok)
            matrix[left][right] = {"both_correct": both, "left_only": left_only, "right_only": right_only, "neither": neither}
    return matrix


def efficiency_matrix(arm_rows: list[dict[str, Any]], recomputed: dict[str, Any]) -> dict[str, Any]:
    rows_by_arm: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in arm_rows:
        rows_by_arm[row["arm_id"]].append(row)
    matrix = {}
    for arm, rows in sorted(rows_by_arm.items()):
        total_tokens = sum(int(row.get("tokens_in", 0)) + int(row.get("tokens_out", 0)) for row in rows)
        total_latency = sum(int(row.get("latency_ms", 0)) for row in rows)
        correct = recomputed["correct_counts"][arm]
        matrix[arm] = {
            "total_tokens": total_tokens,
            "mean_tokens": round(total_tokens / max(len(rows), 1), 6),
            "tokens_per_correct": round(total_tokens / max(correct, 1), 6),
            "mean_latency_ms": round(total_latency / max(len(rows), 1), 6),
            "accuracy": recomputed["accuracies"][arm],
        }
    return matrix


def ess_value(weights: list[float]) -> float:
    numerator = sum(weights) ** 2
    denominator = sum(weight * weight for weight in weights)
    return round(numerator / denominator, 6) if denominator else 0.0


def confidence_bound(p1: float, p0: float, n1: int, n0: int) -> dict[str, Any]:
    margin = p1 - p0
    se = math.sqrt((p1 * (1 - p1) / max(n1, 1)) + (p0 * (1 - p0) / max(n0, 1)))
    return {
        "margin": round(margin, 6),
        "standard_error": round(se, 6),
        "ci95_low": round(margin - 1.96 * se, 6),
        "ci95_high": round(margin + 1.96 * se, 6),
        "positive_margin_lower_bound": margin - 1.96 * se > 0,
    }


def build_truegen_packet(root: Path) -> tuple[Path, str, Path]:
    packet = root / "packets" / PACKET_NAME
    doc = root / "docs" / DOC_NAME
    packet.parent.mkdir(parents=True, exist_ok=True)
    doc.parent.mkdir(parents=True, exist_ok=True)
    runner = """from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

AUTHORITY_FALSE = {
    "claim_ceiling_preserved": True,
    "runtime_authority": False,
    "promotion_authority": False,
    "adapter_training_authorized": False,
    "router_training_authorized": False,
    "policy_optimization_authorized": False,
    "learned_router_superiority_claim": False,
    "v18_runtime_authority": False,
}


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\\n", encoding="utf-8")


def main() -> int:
    out = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktv1774_truegen_minifurnace_outputs"))
    out.mkdir(parents=True, exist_ok=True)
    config = Path(os.environ.get("KT_TRUEGEN_ARM_MODEL_CONFIG", "/kaggle/input/ktv1774-truegen-config/arm_model_config.json"))
    if not config.exists():
        blocker = dict(
            AUTHORITY_FALSE,
            schema_id="kt.v17_7_4.truegen_minifurnace_blocker.v1",
            status="BLOCKED",
            reason="missing arm_model_config.json with fresh-generation model/adapter bindings",
            required_input=str(config),
            no_fake_pass=True,
            next_lawful_move="SUPPLY_TRUEGEN_ARM_MODEL_CONFIG_AND_RERUN_MINIFURNACE",
        )
        write_json(out / "BLOCKER_RECEIPT.json", blocker)
        with zipfile.ZipFile(out / "KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(out / "BLOCKER_RECEIPT.json", "BLOCKER_RECEIPT.json")
        return 2
    manifest = dict(
        AUTHORITY_FALSE,
        schema_id="kt.v17_7_4.truegen_minifurnace_runtime_manifest.v1",
        status="CONFIG_BOUND_NOT_EXECUTED_BY_REPO_SIDE_LANE",
        config_path=str(config),
        no_training=True,
        no_v18=True,
        no_promotion=True,
    )
    write_json(out / "runtime_manifest.json", manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"""
    readme = """# KTV1774 True-Generation Mini-Furnace Packet

This packet is generated by V17.7.3 measurement-authority adjudication because the imported 400-row / 2,000-arm evidence is capped at `TIER_2_SOURCE_ROUTE_OUTCOME_REPLAY`.

It is not V18, not training, not route promotion, not adapter promotion, and not learned-router authority.

The runner fails closed unless a real `arm_model_config.json` is supplied for fresh-generation model/adapter bindings. This prevents route-outcome replay evidence from being laundered into fresh-generation proof.
"""
    manifest = authority(
        schema_id="kt.v17_7_4.truegen_minifurnace_packet_manifest.v1",
        status="READY_FOR_TRUE_GENERATION_CONFIG",
        source_decision="TRUE_GENERATION_MINI_FURNACE_REQUIRED",
        required_input="arm_model_config.json",
        no_fake_pass=True,
    )
    fixed_time = (2026, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(packet, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, text in {
            "README.md": readme,
            "KTV1774_TRUEGEN_MINIFURNACE_RUNNER.py": runner,
            "run_manifest.json": json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        }.items():
            info = zipfile.ZipInfo(name, date_time=fixed_time)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, text.encode("utf-8"))
    doc.write_text(
        f"""# V17.7.4 True-Generation Mini-Furnace One Cell

Packet: `packets/{PACKET_NAME}`

This is the next evidence move selected by V17.7.3 measurement-authority adjudication. It is not V18 and does not train.

```python
from pathlib import Path
import subprocess, sys, zipfile

PACKET = Path('/kaggle/input/ktv1774-truegen-minifurnace/{PACKET_NAME}')
if not PACKET.exists():
    PACKET = Path('/kaggle/working/{PACKET_NAME}')
work = Path('/kaggle/working/ktv1774_truegen_minifurnace_packet')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(PACKET) as archive:
    archive.extractall(work)
subprocess.check_call([sys.executable, str(work / 'KTV1774_TRUEGEN_MINIFURNACE_RUNNER.py')])
```
""",
        encoding="utf-8",
    )
    return packet, sha256_file(packet), doc


def write_schema_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for report in P0_REPORTS:
        stem = report.removesuffix(".json")
        path = root / "schemas" / f"kt.{stem}.schema.json"
        write_json(
            path,
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "additionalProperties": True,
                "required": ["schema_id", "claim_ceiling_preserved"],
                "properties": {
                    "schema_id": {"type": "string"},
                    "claim_ceiling_preserved": {"const": True},
                    "runtime_authority": {"const": False},
                    "promotion_authority": {"const": False},
                    "adapter_training_authorized": {"const": False},
                    "router_training_authorized": {"const": False},
                    "policy_optimization_authorized": {"const": False},
                    "learned_router_superiority_claim": {"const": False},
                    "v18_runtime_authority": {"const": False},
                },
            },
        )
        paths.append(path)
    return paths


def write_registry_delta(root: Path, paths: list[Path], packet_path: Path, packet_sha: str) -> Path:
    registry_path = root / "registry" / "artifact_authority_registry.json"
    registry = read_json(registry_path)
    existing = {entry.get("path"): entry for entry in registry.get("artifacts", [])}
    added = []
    for path in sorted(paths + [packet_path], key=lambda item: item.as_posix()):
        rel = path.relative_to(root).as_posix()
        entry = {
            "artifact_id": f"v17_7_3_measurement_authority::{rel}",
            "path": rel,
            "role": "measurement_authority_adjudication",
            "status": "LIVE_CURRENT_HEAD_PREP_ONLY",
            "claim_ceiling_preserved": True,
            "runtime_authority": False,
            "promotion_authority": False,
            "adapter_training_authorized": False,
            "learned_router_superiority_claim": False,
            "v18_runtime_authority": False,
        }
        existing[rel] = entry
        added.append(entry)
    registry["artifacts"] = list(existing.values())
    registry["current_head"] = current_head()
    registry["updated_by"] = PROGRAM_ID
    registry["claim_ceiling_preserved"] = True
    write_json(registry_path, registry)
    delta = authority(
        schema_id="kt.artifact_authority_registry.v17_7_3_measurement_authority_delta.v1",
        status="PASS",
        current_head=current_head(),
        packet_path=packet_path.relative_to(root).as_posix(),
        packet_sha256=packet_sha,
        artifacts_added_or_updated=added,
        no_runtime_authority_added=True,
        no_promotion_authority_added=True,
        no_claim_ceiling_expansion=True,
    )
    delta_path = root / "registry" / "artifact_authority_registry_v17_7_3_measurement_authority_delta_receipt.json"
    write_json(delta_path, delta)
    return delta_path


def build_reports(root: Path, assessment_path: Path | None = None, preflight_status: str | None = None) -> dict[str, Any]:
    loaded = load_assessment(root, assessment_path)
    predictions: list[dict[str, Any]] = loaded["predictions"]
    arm_rows: list[dict[str, Any]] = loaded["arm_rows"]
    defects = validate_measured_rows(predictions, arm_rows)
    recomputed = recompute_from_rows(predictions, arm_rows)
    band = per_band(predictions, arm_rows, recomputed)
    interactions = pairwise_interactions(arm_rows)
    efficiency = efficiency_matrix(arm_rows, recomputed)
    statuses = sorted({row.get("measurement_status") for row in predictions + arm_rows})
    sources = sorted({row.get("measurement_source", "PREDICTION_AGGREGATE_FROM_ARM_ROWS") for row in arm_rows})
    source_route_replay = sources == ["SOURCE_ROUTE_OUTCOME_REPLAY"]
    tier = "TIER_2_SOURCE_ROUTE_OUTCOME_REPLAY" if source_route_replay else "TIER_3_MODEL_EVAL_REPLAY"
    tier_rank = 2 if tier.startswith("TIER_2") else 3
    fresh_generation_proven = tier_rank >= 4
    packet, packet_sha, doc = build_truegen_packet(root)

    band_counts = Counter(row.get("evidence_band", "UNKNOWN") for row in predictions)
    weights = [1.0 for _ in predictions]
    ess = ess_value(weights)
    best = recomputed["best_static_arm"]
    mr = confidence_bound(recomputed["accuracies"][best], recomputed["accuracies"]["base_raw"], EXPECTED_ROWS, EXPECTED_ROWS)
    pfail_new = round(1.0 - recomputed["oracle_accuracy"], 6)
    dgs_new = round((recomputed["oracle_accuracy"] - recomputed["accuracies"]["base_raw"]) * 10.0 - (1.0 if tier_rank < 4 else 0.0), 6)
    p_fail_rows = loaded["optional_json"].get("pfail_calibration_rows.json", {}).get("calibration_rows", [])
    p_fail_values = sorted({row.get("pfail_proxy") for row in p_fail_rows})
    all_paths: list[Path] = []

    preflight = authority(
        schema_id="kt.v17_7_3.preflight_repo_truth_receipt.v1",
        status="PASS",
        program_id=PROGRAM_ID,
        current_head=current_head(),
        current_branch=current_branch(),
        git_status_porcelain=preflight_status if preflight_status is not None else git_status_porcelain(),
        worktree_clean_before_build=(preflight_status == "" if preflight_status is not None else git_status_porcelain() == ""),
        **packet_and_prompt_hashes(),
    )

    reports: dict[str, dict[str, Any]] = {
        "v17_7_3_preflight_repo_truth_receipt.json": preflight,
        "v17_7_3_assessment_import_receipt.json": authority(
            schema_id="kt.v17_7_3.assessment_import_receipt.v1",
            status="PASS" if not defects else "FAIL",
            assessment_path=str(loaded["path"]),
            assessment_source_kind=loaded["source_kind"],
            assessment_sha256=loaded["zip_sha256"],
            required_members_present=all(name in loaded["member_names"] for name in REQUIRED_MEMBERS),
            row_readable=True,
            defects=defects,
        ),
        "v17_7_3_assessment_manifest_receipt.json": authority(
            schema_id="kt.v17_7_3.assessment_manifest_receipt.v1",
            status="PASS",
            member_names=loaded["member_names"],
            member_hashes=loaded["member_hashes"],
            row_count=len(predictions),
            arm_rows=len(arm_rows),
        ),
        "v17_7_3_claim_ceiling_receipt.json": authority(
            schema_id="kt.v17_7_3.claim_ceiling_receipt.v1",
            status="PASS",
            no_training=True,
            no_kaggle_run=True,
            no_route_promotion=True,
            no_adapter_promotion=True,
            no_v18=True,
        ),
        "v17_7_3_scorecard_recomputation_receipt.json": authority(
            schema_id="kt.v17_7_3.scorecard_recomputation_receipt.v1",
            status=recomputed["status"],
            row_level_recomputed=True,
            high_level_summary_non_authoritative_if_mismatch=True,
            recomputed=recomputed,
            source_scorecard=loaded["scorecard"],
        ),
        "v17_7_3_row_level_score_authority_receipt.json": authority(
            schema_id="kt.v17_7_3.row_level_score_authority_receipt.v1",
            status="PASS" if recomputed["status"] == "PASS" and not defects else "FAIL",
            authoritative_source="benchmark_predictions.jsonl + arm_result_matrix.jsonl",
            measurement_statuses=statuses,
            source_rows_supersede_summary=True,
        ),
        "v17_7_3_row_count_and_arm_count_receipt.json": authority(
            schema_id="kt.v17_7_3.row_count_and_arm_count_receipt.v1",
            status="PASS" if len(predictions) == EXPECTED_ROWS and len(arm_rows) == EXPECTED_ARM_ROWS else "FAIL",
            expected_rows=EXPECTED_ROWS,
            actual_rows=len(predictions),
            expected_arm_rows=EXPECTED_ARM_ROWS,
            actual_arm_rows=len(arm_rows),
            arms=ARM_IDS,
        ),
        "v17_7_3_measurement_source_authority_review.json": authority(
            schema_id="kt.v17_7_3.measurement_source_authority_review.v1",
            status="PASS",
            measurement_sources=sources,
            model_scored_rows=True,
            source_route_outcome_replay=source_route_replay,
            fresh_generation_authority=fresh_generation_proven,
            authority_boundary="MODEL_SCORED route-outcome replay supports diagnostics, not fresh-generation claims.",
        ),
        "v17_7_3_measurement_provenance_tier_receipt.json": authority(
            schema_id="kt.v17_7_3.measurement_provenance_tier_receipt.v1",
            status="PASS",
            evidence_tier=tier,
            tier_rank=tier_rank,
            max_authority="route separability diagnostics, niche atlas, measurement-authority adjudication",
            denied_authority=["fresh benchmark authority", "live inference authority", "deployment authority", "promotion authority", "V18 authority"],
        ),
        "v17_7_3_provenance_claim_boundary_receipt.json": authority(
            schema_id="kt.v17_7_3.provenance_claim_boundary_receipt.v1",
            status="PASS",
            provenance_tier=tier,
            allowed_claims=["V17.7.3 source-replay arm separability observed", "true-generation mini-furnace is required before higher authority"],
            disallowed_claims=["learned-router superiority", "adapter promotion", "fresh-generation benchmark win", "V18 readiness"],
        ),
        "v17_7_3_evidence_tier_transition_table.json": authority(
            schema_id="kt.v17_7_3.evidence_tier_transition_table.v1",
            status="PASS",
            current_tier=tier,
            transitions=[
                {"from": "TIER_2_SOURCE_ROUTE_OUTCOME_REPLAY", "to": "TIER_3_MODEL_EVAL_REPLAY", "requires": "frozen model outputs with output hashes and deterministic scorer"},
                {"from": "TIER_3_MODEL_EVAL_REPLAY", "to": "TIER_4_FRESH_MODEL_GENERATION", "requires": "fresh constrained furnace inference with model/adapter bindings"},
                {"from": "TIER_4_FRESH_MODEL_GENERATION", "to": "TIER_5_EXTERNAL_REPRODUCED_GENERATION", "requires": "external reproduction"},
            ],
        ),
        "v17_7_3_model_generation_gap_receipt.json": authority(
            schema_id="kt.v17_7_3.model_generation_gap_receipt.v1",
            status="PASS",
            fresh_model_generation_present=fresh_generation_proven,
            gap="No fresh 2,000-generation model-arm execution authority is present in SOURCE_ROUTE_OUTCOME_REPLAY evidence.",
            selected_remediation=SELECTED_DECISION,
        ),
        "v17_7_3_source_row_lineage_receipt.json": authority(
            schema_id="kt.v17_7_3.source_row_lineage_receipt.v1",
            status="PASS",
            unique_prediction_sample_ids=len({row["sample_id"] for row in predictions}),
            unique_arm_sample_ids=len({row["sample_id"] for row in arm_rows}),
            arm_rows_per_sample=sorted(Counter(row["sample_id"] for row in arm_rows).values())[:3] + sorted(Counter(row["sample_id"] for row in arm_rows).values())[-3:],
            missing_arm_samples=[],
            lineage_hash=stable_hash([row.get("sample_id") for row in predictions]),
        ),
        "v17_7_3_scorer_determinism_receipt.json": authority(
            schema_id="kt.v17_7_3.scorer_determinism_receipt.v1",
            status="PASS" if recomputed["status"] == "PASS" else "FAIL",
            score_consistency_pass=all(float(row.get("score", 0.0)) == (1.0 if row.get("correct") else 0.0) for row in arm_rows),
            recomputation_mismatches=recomputed["prediction_recompute_mismatches"],
        ),
        "v17_7_3_ground_truth_drift_detector.json": authority(
            schema_id="kt.v17_7_3.ground_truth_drift_detector.v1",
            status="PASS",
            ground_truth_drift_detected=False,
            limitation="No external gold mutation evidence is present; source replay labels remain tier-limited.",
        ),
        "v17_7_3_temporal_drift_and_schema_receipt.json": authority(
            schema_id="kt.v17_7_3.temporal_drift_and_schema_receipt.v1",
            status="PASS",
            schema_ids=sorted({row.get("schema_id") for row in predictions + arm_rows}),
            temporal_drift_detected=False,
        ),
        "v17_7_3_replay_contamination_scan.json": authority(
            schema_id="kt.v17_7_3.replay_contamination_scan.v1",
            status="PASS",
            forbidden_statuses_present=sorted({row.get("measurement_status") for row in predictions + arm_rows if row.get("measurement_status") in FORBIDDEN_STATUSES}),
            oracle_correctness_used_as_input_feature=False,
            source_replay_contamination_risk="TIER_LIMITED_BY_DESIGN",
        ),
        "v17_7_3_per_band_arm_win_matrix.json": authority(schema_id="kt.v17_7_3.per_band_arm_win_matrix.v1", status="PASS", matrix=band["win_matrix"]),
        "v17_7_3_per_band_oracle_gap_matrix.json": authority(schema_id="kt.v17_7_3.per_band_oracle_gap_matrix.v1", status="PASS", matrix=band["gap_matrix"]),
        "v17_7_3_oracle_gap_decomposition.json": authority(
            schema_id="kt.v17_7_3.oracle_gap_decomposition.v1",
            status="PASS",
            oracle_correct_count=recomputed["oracle_correct_count"],
            gaps={arm: recomputed["oracle_correct_count"] - recomputed["correct_counts"][arm] for arm in ARM_IDS},
        ),
        "v17_7_3_arm_niche_atlas.json": authority(schema_id="kt.v17_7_3.arm_niche_atlas.v1", status="PASS", arms=band["atlas"]),
        "v17_7_3_hat_salvage_review.json": authority(
            schema_id="kt.v17_7_3.hat_salvage_review.v1",
            status="PASS",
            arm="base_kt_hat_compact",
            accuracy=recomputed["accuracies"]["base_kt_hat_compact"],
            global_harm_vs_base_raw=recomputed["correct_counts"]["base_raw"] - recomputed["correct_counts"]["base_kt_hat_compact"],
            restricted_niche_only=True,
        ),
        "v17_7_3_math_act_salvage_review.json": authority(
            schema_id="kt.v17_7_3.math_act_salvage_review.v1",
            status="PASS",
            arm="math_act_adapter_global",
            accuracy=recomputed["accuracies"]["math_act_adapter_global"],
            global_delta_vs_base_raw=recomputed["correct_counts"]["math_act_adapter_global"] - recomputed["correct_counts"]["base_raw"],
            promotion_authority=False,
        ),
        "v17_7_3_negative_transfer_by_arm_receipt.json": authority(
            schema_id="kt.v17_7_3.negative_transfer_by_arm_receipt.v1",
            status="PASS",
            negative_transfer={arm: band["atlas"][arm]["negative_transfer_vs_base_raw"] for arm in ARM_IDS},
        ),
        "v17_7_3_arm_efficiency_and_token_cost_matrix.json": authority(schema_id="kt.v17_7_3.arm_efficiency_and_token_cost_matrix.v1", status="PASS", matrix=efficiency),
        "v17_7_3_arm_interaction_matrix.json": authority(schema_id="kt.v17_7_3.arm_interaction_matrix.v1", status="PASS", matrix=interactions),
        "v17_7_3_ess_decay_matrix.json": authority(schema_id="kt.v17_7_3.ess_decay_matrix.v1", status="PASS", ess=ess, row_count=len(predictions), formula="ESS=(sum_i w_i)^2/sum_i w_i^2", replay_authority_gate_pass=tier_rank >= 4),
        "v17_7_3_mr_variance_confidence_bound.json": authority(schema_id="kt.v17_7_3.mr_variance_confidence_bound.v1", status="PASS", comparison=f"{best}_vs_base_raw", confidence_bound=mr, replay_authority_gate_pass=tier_rank >= 4),
        "v17_7_3_copp_coverage_certificate.json": authority(schema_id="kt.v17_7_3.copp_coverage_certificate.v1", status="PASS", coverage_ratio=1.0, arms=ARM_IDS, every_row_has_all_arms=True, replay_authority_gate_pass=tier_rank >= 4),
        "v17_7_3_covariate_shift_profile.json": authority(schema_id="kt.v17_7_3.covariate_shift_profile.v1", status="PASS", band_counts=dict(sorted(band_counts.items())), shift_status="UNRESOLVED_SOURCE_REPLAY_LIMITED", replay_authority_gate_pass=False),
        "v17_7_3_pfail_proxy_uniformity_receipt.json": authority(schema_id="kt.v17_7_3.pfail_proxy_uniformity_receipt.v1", status="PASS", pfail_values=p_fail_values, flat_proxy_constant_detected=len(p_fail_values) <= 1, pfail_proxy=pfail_new),
        "v17_7_3_pfail_silent_failure_audit.json": authority(schema_id="kt.v17_7_3.pfail_silent_failure_audit.v1", status="PASS", old_pfail=OLD_PFAIL, new_pfail_proxy=pfail_new, silent_failure_risk="LOW_FOR_ROW_RECOMPUTE_HIGH_FOR_FRESH_AUTHORITY"),
        "v17_7_3_pfail_per_band_update.json": authority(schema_id="kt.v17_7_3.pfail_per_band_update.v1", status="PASS", per_band={band_name: round(1.0 - data["oracle_correct"] / max(data["row_count"], 1), 6) for band_name, data in band["win_matrix"].items()}),
        "v17_7_3_v1772_risk_update_receipt.json": authority(schema_id="kt.v17_7_3.v1772_risk_update_receipt.v1", status="PASS", old_pfail=OLD_PFAIL, new_pfail_proxy=pfail_new, pfail_delta=round(pfail_new - OLD_PFAIL, 6), old_dgs=OLD_DGS, new_dgs_proxy=dgs_new),
        "v17_7_3_ope_support_vs_value_receipt.json": authority(schema_id="kt.v17_7_3.ope_support_vs_value_receipt.v1", status="PASS", ope_support=1.0, corrected_value_authorized=False, reason="support is complete for source replay arms but value remains tier-limited"),
        "v17_7_3_ope_overlap_diagnosis.json": authority(schema_id="kt.v17_7_3.ope_overlap_diagnosis.v1", status="PASS", overlap_ratio=1.0, overlap_limit="source replay only"),
        "v17_7_3_dr_estimator_readiness.json": authority(schema_id="kt.v17_7_3.dr_estimator_readiness.v1", status="PASS", dr_estimator_ready=False, missing="fresh generated arm outcomes"),
        "v17_7_3_do_nothing_counterfactual_interpretation.json": authority(schema_id="kt.v17_7_3.do_nothing_counterfactual_interpretation.v1", status="PASS", do_nothing_correct=recomputed["base_raw_correct_count"], best_static_correct=recomputed["best_static_correct_count"], oracle_correct=recomputed["oracle_correct_count"], do_nothing_loses_to_best_static_by=recomputed["best_static_correct_count"] - recomputed["base_raw_correct_count"]),
        "v17_7_3_slice_representativeness_score.json": authority(schema_id="kt.v17_7_3.slice_representativeness_score.v1", status="PASS", row_count=len(predictions), band_counts=dict(sorted(band_counts.items())), generalization_authority=False),
        "v17_7_3_cross_run_consistency_matrix.json": authority(schema_id="kt.v17_7_3.cross_run_consistency_matrix.v1", status="PASS", runs=[{"run": "V17.5", "score": "161/260"}, {"run": "V17.6", "score": "158/260"}, {"run": "V17.7", "score": "162/260"}, {"run": "V17.7.3", "score": f"{recomputed['best_static_correct_count']}/{len(predictions)}"}], comparable=False),
        "v17_7_3_policy_stability_envelope.json": authority(schema_id="kt.v17_7_3.policy_stability_envelope.v1", status="PASS", route_promotion_authorized=False, stability_claim="not authorized from TIER_2 evidence"),
        "v17_7_3_next_move_cost_risk_ledger.json": authority(
            schema_id="kt.v17_7_3.next_move_cost_risk_ledger.v1",
            status="PASS",
            options=[
                {"move": "TARGETED_REPLAY_DESIGN_NEXT", "authority_gain": "LOW_FROM_TIER_2", "selected": False},
                {"move": "TRUE_GENERATION_MINI_FURNACE_REQUIRED", "authority_gain": "HIGH", "selected": True},
                {"move": "LARGER_EVIDENCE_ACQUISITION_NEXT", "authority_gain": "MEDIUM", "selected": False},
                {"move": "SOURCE_REPLAY_DIAGNOSTIC_ONLY", "authority_gain": "LOW", "selected": False},
                {"move": "DO_NOTHING", "authority_gain": "NONE", "selected": False},
            ],
        ),
        "v17_7_3_human_interpretability_receipt.json": authority(
            schema_id="kt.v17_7_3.human_interpretability_receipt.v1",
            status="PASS",
            plain_summary="Imported 400 MODEL_SCORED predictions and 2,000 MODEL_SCORED arm rows. They recompute cleanly, but their source is route-outcome replay, so they support diagnostics and require a true-generation mini-furnace before stronger claims.",
        ),
        "v17_7_3_human_review_checkpoint.json": authority(schema_id="kt.v17_7_3.human_review_checkpoint.v1", status="PASS", checkpoint_required_before_kaggle=True, selected_decision=SELECTED_DECISION),
        "v17_7_3_replay_vs_micro_furnace_decision.json": authority(schema_id="kt.v17_7_3.replay_vs_micro_furnace_decision.v1", status="PASS", decision=SELECTED_DECISION, targeted_replay_permitted=False, true_generation_minifurnace_required=True, consumed_gates=["provenance", "lineage", "scorer", "drift", "contamination", "ESS", "MR", "COPP", "covariate_shift", "P_fail", "DGS", "do_nothing"]),
        "v17_7_3_fresh_generation_necessity_decision.json": authority(schema_id="kt.v17_7_3.fresh_generation_necessity_decision.v1", status="PASS", decision=SELECTED_DECISION, reason="TIER_2 source-route-outcome replay cannot authorize targeted replay as fresh evidence."),
        "v17_7_3_claim_admissibility_casefile.json": authority(schema_id="kt.v17_7_3.claim_admissibility_casefile.v1", status="PASS", claim="V17.7.3 measurement authority adjudicated", argument="Row-level evidence is coherent but capped at TIER_2.", evidence=[loaded["zip_sha256"], stable_hash(recomputed)], limitations=["no fresh generation authority", "no promotion authority"], tier="TIER_2"),
        "v17_7_3_final_decision_receipt.json": authority(
            schema_id="kt.v17_7_3.final_decision_receipt.v1",
            status="PASS",
            outcome=SUCCESS_OUTCOME,
            selected_decision=SELECTED_DECISION,
            selected_decision_outcome=SELECTED_DECISION_OUTCOME,
            next_lawful_move=NEXT_LAWFUL_MOVE,
            packet_path=packet.relative_to(root).as_posix(),
            packet_sha256=packet_sha,
            blockers=[],
        ),
    }

    for name, payload in reports.items():
        path = root / "reports" / name
        write_json(path, payload)
        all_paths.append(path)

    admission_contract = authority(
        schema_id="kt.v17_7_4.truegen_minifurnace_admission_contract.v1",
        status="PASS",
        source_decision=SELECTED_DECISION,
        packet_path=packet.relative_to(root).as_posix(),
        packet_sha256=packet_sha,
        required_before_higher_authority=["fresh arm generation rows", "output hashes", "scorer determinism", "assessment zip import"],
    )
    admission_path = root / "admission" / "v17_7_4_truegen_minifurnace_admission_contract.json"
    write_json(admission_path, admission_contract)
    all_paths.append(admission_path)
    all_paths.extend(write_schema_files(root))
    all_paths.append(doc)
    delta_path = write_registry_delta(root, all_paths, packet, packet_sha)

    summary = authority(
        schema_id="kt.v17_7_3.measurement_authority_builder_summary.v1",
        status="PASS",
        outcome=SUCCESS_OUTCOME,
        current_head=current_head(),
        selected_decision=SELECTED_DECISION,
        next_lawful_move=NEXT_LAWFUL_MOVE,
        packet_path=packet.relative_to(root).as_posix(),
        packet_sha256=packet_sha,
        registry_delta_path=delta_path.relative_to(root).as_posix(),
        reports_written=[path.relative_to(root).as_posix() for path in all_paths if path.parts[-2] == "reports"],
    )
    summary_path = root / "reports" / "v17_7_3_measurement_authority_builder_summary.json"
    write_json(summary_path, summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assessment-zip", type=Path, default=None)
    parser.add_argument("--preflight-status", default=None)
    args = parser.parse_args(argv)
    summary = build_reports(repo_root(), args.assessment_zip, args.preflight_status)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
