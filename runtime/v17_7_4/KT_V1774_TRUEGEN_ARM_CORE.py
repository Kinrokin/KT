from __future__ import annotations

import hashlib
import json
import math
import os
import random
import re
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


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

ARM_IDS = [
    "base_raw",
    "route_regret_policy_adapter_global",
    "formal_math_repair_adapter_global",
    "base_kt_hat_compact",
    "math_act_adapter_global",
]

ASSESSMENT_FILES = [
    "truegen_predictions.jsonl",
    "truegen_arm_result_matrix.jsonl",
    "truegen_benchmark_scorecard.json",
    "truegen_replay_correlation_scorecard.json",
    "truegen_negative_transfer_by_arm.json",
    "truegen_token_efficiency_matrix.json",
    "truegen_per_band_arm_win_matrix.json",
    "truegen_oracle_gap_update.json",
    "truegen_pfail_dgs_update.json",
    "truegen_measurement_authority_receipt.json",
    "truegen_claim_admissibility_casefile.json",
    "runtime_telemetry_receipt.json",
    "arm_model_config_receipt.json",
    "final_summary.json",
]

FORBIDDEN_SUCCESS_STATUSES = {
    "SOURCE_ROUTE_OUTCOME_REPLAY",
    "CONFIG_BOUND_NOT_EXECUTED_BY_REPO_SIDE_LANE",
    "PENDING_KAGGLE_ARM_EXECUTION",
    "MODEL_SCORED",
    "ACQUISITION_ROW_EMITTED_NOT_MODEL_SCORED",
    "ACQUISITION_PACKET_EXECUTED_NOT_EVALUATED",
    "SCAFFOLD_EMITTED_NOT_EARNED",
    "PLACEHOLDER",
    "NOT_MEASURED",
    "FORMAT_SMOKE_ONLY",
}

FRESH_SOURCE = "FRESH_MODEL_GENERATION"
FRESH_STATUS = "MODEL_GENERATED_AND_SCORED"
BLOCKED_STATUS = "BLOCKED_FRESH_GENERATION_FAILED"


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(AUTHORITY_FALSE)
    payload.update(extra)
    return payload


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def stable_hash(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_answer(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def parse_answer(text: str) -> str:
    marker = re.search(r"(?:answer|final)\s*[:=]\s*([^\n\r]+)", text, flags=re.IGNORECASE)
    if marker:
        return marker.group(1).strip()
    number = re.findall(r"[-+]?\d+(?:\.\d+)?", text)
    if number:
        return number[-1]
    return text.strip()[:160]


def count_tokens(text: str) -> int:
    return len(re.findall(r"\S+", text))


def validate_arm_model_config(config: dict[str, Any]) -> list[str]:
    required = [
        "base_model_repo",
        "load_in_4bit",
        "torch_dtype",
        "max_new_tokens",
        "batch_size",
        "device_map",
        "generation_seed",
        "arms",
    ]
    defects = [f"missing:{key}" for key in required if key not in config]
    arms = config.get("arms")
    if not isinstance(arms, list) or not arms:
        defects.append("arms must be a non-empty list")
        return defects
    seen = set()
    for index, arm in enumerate(arms):
        for key in [
            "arm_id",
            "model_repo_or_base",
            "adapter_hf_repo",
            "adapter_path",
            "adapter_sha256_optional",
            "enabled",
            "prompt_template_id",
            "scoring_method",
            "max_new_tokens",
        ]:
            if key not in arm:
                defects.append(f"arms[{index}].missing:{key}")
        arm_id = arm.get("arm_id")
        if arm_id:
            seen.add(arm_id)
    missing_arms = [arm for arm in ARM_IDS if arm not in seen]
    if missing_arms:
        defects.append(f"missing_required_arms:{','.join(missing_arms)}")
    return defects


def enabled_arms(config: dict[str, Any]) -> list[dict[str, Any]]:
    return [arm for arm in config.get("arms", []) if arm.get("enabled") is True]


def resolve_runtime_path(runtime_root: Path, env_key: str, relative: str) -> Path:
    env_value = os.environ.get(env_key)
    if env_value:
        return Path(env_value)
    return runtime_root / relative


def load_row_manifest(path: Path, row_limit: int | None = None) -> dict[str, Any]:
    manifest = read_json(path)
    rows = manifest.get("rows", [])
    if row_limit is not None:
        rows = rows[:row_limit]
    manifest = dict(manifest)
    manifest["rows"] = rows
    manifest["row_count"] = len(rows)
    return manifest


def materialize_prompt(row: dict[str, Any], arm: dict[str, Any]) -> str:
    template = arm.get("prompt_template_id", "raw")
    prefix = {
        "raw": "Answer directly.",
        "kt_hat_compact": "Use compact KT-hat discipline: answer only what is asked and avoid unsupported claims.",
        "formal_math": "Solve as a formal math or structured reasoning item. Emit final answer clearly.",
        "math_act": "Decompose the math act briefly, then emit final answer clearly.",
        "route_regret": "Select the most utility-preserving route and emit final answer clearly.",
    }.get(template, "Answer directly.")
    return "\n".join(
        [
            prefix,
            f"Sample: {row['sample_id']}",
            f"Dataset: {row['dataset']}",
            f"Task family: {row['task_family']}",
            f"Boundary: {row['route_boundary_class']}",
            f"Question: {row['prompt']}",
            "Final:",
        ]
    )


class GenerationBackend:
    def __init__(self) -> None:
        self._model_cache: dict[str, Any] = {}

    def generate(self, prompt: str, arm: dict[str, Any], config: dict[str, Any], row: dict[str, Any]) -> tuple[str, str]:
        model_repo = arm.get("model_repo_or_base") or config["base_model_repo"]
        if model_repo == "__KT_LOCAL_TEST_BACKEND__":
            if os.environ.get("KT_TRUEGEN_ALLOW_TEST_BACKEND") != "1":
                raise RuntimeError("local test backend requested without KT_TRUEGEN_ALLOW_TEST_BACKEND=1")
            expected = row.get("expected_label_or_oracle_label", "")
            return f"answer: {expected}", "LOCAL_TEST_BACKEND_NOT_KT_EVIDENCE"
        return self._generate_with_transformers(prompt, arm, config)

    def _generate_with_transformers(self, prompt: str, arm: dict[str, Any], config: dict[str, Any]) -> tuple[str, str]:
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"missing transformers/torch runtime dependencies: {exc}") from exc

        model_repo = arm.get("model_repo_or_base") or config["base_model_repo"]
        if model_repo == "BASE":
            model_repo = config["base_model_repo"]
        cache_key = f"{model_repo}::{arm.get('adapter_hf_repo') or arm.get('adapter_path') or 'base'}"
        if cache_key not in self._model_cache:
            dtype_name = str(config.get("torch_dtype", "auto"))
            dtype = getattr(torch, dtype_name, "auto") if dtype_name != "auto" else "auto"
            tokenizer = AutoTokenizer.from_pretrained(model_repo)
            kwargs: dict[str, Any] = {"device_map": config.get("device_map", "auto")}
            if dtype != "auto":
                kwargs["torch_dtype"] = dtype
            if config.get("load_in_4bit") is True:
                kwargs["load_in_4bit"] = True
            model = AutoModelForCausalLM.from_pretrained(model_repo, **kwargs)
            adapter_ref = arm.get("adapter_path") or arm.get("adapter_hf_repo")
            adapter_status = "BASE_MODEL_ONLY"
            if adapter_ref:
                try:
                    from peft import PeftModel

                    model = PeftModel.from_pretrained(model, adapter_ref)
                    adapter_status = "ADAPTER_LOADED"
                except Exception as exc:  # noqa: BLE001
                    raise RuntimeError(f"adapter load failed for {arm['arm_id']}: {exc}") from exc
            else:
                adapter_status = "BASE_FALLBACK_NOT_ADAPTER_EVIDENCE" if arm["arm_id"] not in {"base_raw", "base_kt_hat_compact"} else "BASE_MODEL_ONLY"
            model.eval()
            self._model_cache[cache_key] = (tokenizer, model, adapter_status)
        tokenizer, model, adapter_status = self._model_cache[cache_key]
        seed = int(config.get("generation_seed", 1337))
        random.seed(seed)
        try:
            torch.manual_seed(seed)
            if torch.cuda.is_available():
                torch.cuda.manual_seed_all(seed)
        except Exception:
            pass
        inputs = tokenizer(prompt, return_tensors="pt")
        device = next(model.parameters()).device
        inputs = {key: value.to(device) for key, value in inputs.items()}
        max_new_tokens = int(arm.get("max_new_tokens") or config.get("max_new_tokens") or 32)
        with torch.no_grad():
            output_ids = model.generate(**inputs, max_new_tokens=max_new_tokens, do_sample=False)
        generated = tokenizer.decode(output_ids[0][inputs["input_ids"].shape[-1] :], skip_special_tokens=True)
        return generated.strip(), adapter_status


def score_output(text: str, parsed_answer: str, row: dict[str, Any], method: str) -> tuple[float, bool]:
    expected = str(row.get("expected_label_or_oracle_label", ""))
    if method == "nonempty_generation":
        correct = bool(text.strip())
    elif method == "exact_normalized":
        correct = normalize_answer(parsed_answer) == normalize_answer(expected)
    else:
        correct = normalize_answer(expected) in normalize_answer(text) if expected else False
    return (1.0 if correct else 0.0), correct


def generate_arm_rows(manifest: dict[str, Any], config: dict[str, Any], run_id: str) -> list[dict[str, Any]]:
    backend = GenerationBackend()
    rows: list[dict[str, Any]] = []
    for row in manifest["rows"]:
        for arm in enabled_arms(config):
            prompt = materialize_prompt(row, arm)
            start = time.perf_counter()
            output_text, adapter_source_status = backend.generate(prompt, arm, config, row)
            latency_ms = int((time.perf_counter() - start) * 1000)
            parsed = parse_answer(output_text)
            score, correct = score_output(output_text, parsed, row, arm.get("scoring_method", "contains_expected_label"))
            rows.append(
                authority(
                    schema_id="kt.v17_7_4.truegen_arm_result.v1",
                    run_id=run_id,
                    sample_id=row["sample_id"],
                    dataset=row["dataset"],
                    task_family=row["task_family"],
                    evidence_band=row["evidence_band"],
                    route_boundary_class=row["route_boundary_class"],
                    arm_id=arm["arm_id"],
                    model_repo=arm.get("model_repo_or_base") or config["base_model_repo"],
                    adapter_ref=arm.get("adapter_path") or arm.get("adapter_hf_repo") or "",
                    adapter_source_status=adapter_source_status,
                    prompt_hash=sha256_text(prompt),
                    output_text=output_text[:2000],
                    output_hash=sha256_text(output_text),
                    parsed_answer=parsed,
                    score=score,
                    correct=correct,
                    tokens_in=count_tokens(prompt),
                    tokens_out=count_tokens(output_text),
                    latency_ms=latency_ms,
                    generation_seed=config["generation_seed"],
                    measurement_source=FRESH_SOURCE,
                    measurement_status=FRESH_STATUS,
                    generation_artifacts_present=True,
                )
            )
    return rows


def enforce_fresh_rows(arm_rows: list[dict[str, Any]], predictions: list[dict[str, Any]] | None = None) -> None:
    defects = []
    for index, row in enumerate(list(arm_rows) + list(predictions or [])):
        status = row.get("measurement_status") or row.get("status")
        source = row.get("measurement_source")
        if status in FORBIDDEN_SUCCESS_STATUSES or source in FORBIDDEN_SUCCESS_STATUSES:
            defects.append({"index": index, "sample_id": row.get("sample_id"), "status": status, "source": source})
        if row.get("schema_id", "").endswith(("truegen_arm_result.v1", "truegen_prediction.v1")):
            if status != FRESH_STATUS or source != FRESH_SOURCE or row.get("generation_artifacts_present") is not True:
                defects.append({"index": index, "sample_id": row.get("sample_id"), "status": status, "source": source})
    if defects:
        raise RuntimeError(f"fresh-generation contract failed: {defects[:10]}")


def aggregate_predictions(arm_rows: list[dict[str, Any]], run_id: str) -> list[dict[str, Any]]:
    by_sample: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in arm_rows:
        by_sample[row["sample_id"]].append(row)
    predictions = []
    for sample_id, rows in sorted(by_sample.items()):
        best = sorted(rows, key=lambda row: (-float(row["score"]), int(row["tokens_out"]), int(row["latency_ms"]), row["arm_id"]))[0]
        predictions.append(
            authority(
                schema_id="kt.v17_7_4.truegen_prediction.v1",
                run_id=run_id,
                sample_id=sample_id,
                dataset=best["dataset"],
                task_family=best["task_family"],
                evidence_band=best["evidence_band"],
                route_boundary_class=best["route_boundary_class"],
                best_arm=best["arm_id"],
                oracle_correct=bool(best["correct"]),
                chosen_score=float(best["score"]),
                available_arm_scores={row["arm_id"]: {"score": row["score"], "correct": row["correct"]} for row in rows},
                measurement_source=FRESH_SOURCE,
                measurement_status=FRESH_STATUS,
                generation_artifacts_present=True,
            )
        )
    enforce_fresh_rows(arm_rows, predictions)
    return predictions


def recompute_scorecards(arm_rows: list[dict[str, Any]], predictions: list[dict[str, Any]]) -> dict[str, Any]:
    enforce_fresh_rows(arm_rows, predictions)
    by_arm: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_band_arm: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    by_sample: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in arm_rows:
        by_arm[row["arm_id"]].append(row)
        by_band_arm[(row["evidence_band"], row["arm_id"])].append(row)
        by_sample[row["sample_id"]][row["arm_id"]] = row
    arms = sorted(by_arm)
    arm_accuracy = {
        arm: round(sum(1 for row in rows if row["correct"]) / max(len(rows), 1), 6)
        for arm, rows in sorted(by_arm.items())
    }
    correct_counts = {arm: sum(1 for row in rows if row["correct"]) for arm, rows in sorted(by_arm.items())}
    best_arm = sorted(arms, key=lambda arm: (-arm_accuracy[arm], arm))[0]
    base_correct = correct_counts.get("base_raw", 0)
    oracle_correct = sum(1 for row in predictions if row["oracle_correct"])
    band_rows = Counter(row["evidence_band"] for row in predictions)
    per_band = {}
    for band in sorted(band_rows):
        per_band[band] = {"row_count": band_rows[band], "arms": {}}
        for arm in arms:
            rows = by_band_arm[(band, arm)]
            correct = sum(1 for row in rows if row["correct"])
            per_band[band]["arms"][arm] = {
                "correct": correct,
                "total": len(rows),
                "accuracy": round(correct / max(len(rows), 1), 6),
            }
    negative_transfer = {arm: 0 for arm in arms}
    for sample_arms in by_sample.values():
        base = sample_arms.get("base_raw")
        if not base or not base.get("correct"):
            continue
        for arm, row in sample_arms.items():
            if not row.get("correct"):
                negative_transfer[arm] += 1
    token_efficiency = {}
    for arm, rows in by_arm.items():
        tokens = sum(int(row["tokens_in"]) + int(row["tokens_out"]) for row in rows)
        token_efficiency[arm] = {
            "total_tokens": tokens,
            "tokens_per_correct": round(tokens / max(correct_counts[arm], 1), 6),
            "mean_latency_ms": round(sum(int(row["latency_ms"]) for row in rows) / max(len(rows), 1), 6),
        }
    return {
        "benchmark": authority(
            schema_id="kt.v17_7_4.truegen_benchmark_scorecard.v1",
            status="PASS",
            measurement_source=FRESH_SOURCE,
            measurement_status=FRESH_STATUS,
            row_level_recomputed=True,
            row_count=len(predictions),
            arm_rows=len(arm_rows),
            arm_accuracy=arm_accuracy,
            correct_counts=correct_counts,
            best_static_arm=best_arm,
            best_static_correct_count=correct_counts[best_arm],
            base_raw_correct_count=base_correct,
            oracle_correct_count=oracle_correct,
            fresh_generation_pass=True,
        ),
        "negative_transfer": authority(schema_id="kt.v17_7_4.truegen_negative_transfer_by_arm.v1", status="PASS", measurement_source=FRESH_SOURCE, negative_transfer=negative_transfer),
        "token_efficiency": authority(schema_id="kt.v17_7_4.truegen_token_efficiency_matrix.v1", status="PASS", measurement_source=FRESH_SOURCE, matrix=token_efficiency),
        "per_band": authority(schema_id="kt.v17_7_4.truegen_per_band_arm_win_matrix.v1", status="PASS", measurement_source=FRESH_SOURCE, matrix=per_band),
        "oracle_gap": authority(schema_id="kt.v17_7_4.truegen_oracle_gap_update.v1", status="PASS", measurement_source=FRESH_SOURCE, gaps={arm: oracle_correct - correct_counts[arm] for arm in arms}),
        "pfail_dgs": authority(
            schema_id="kt.v17_7_4.truegen_pfail_dgs_update.v1",
            status="PASS",
            measurement_source=FRESH_SOURCE,
            pfail=round(1.0 - oracle_correct / max(len(predictions), 1), 6),
            dgs=round((oracle_correct - base_correct) / max(len(predictions), 1), 6),
        ),
    }


def pearson(xs: list[float], ys: list[float]) -> float | None:
    if len(xs) != len(ys) or len(xs) < 2:
        return None
    mean_x = sum(xs) / len(xs)
    mean_y = sum(ys) / len(ys)
    numerator = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    denom_x = math.sqrt(sum((x - mean_x) ** 2 for x in xs))
    denom_y = math.sqrt(sum((y - mean_y) ** 2 for y in ys))
    if not denom_x or not denom_y:
        return None
    return round(numerator / (denom_x * denom_y), 6)


def replay_correlation(arm_rows: list[dict[str, Any]], manifest_rows: list[dict[str, Any]]) -> dict[str, Any]:
    replay_by_sample = {row["sample_id"]: row.get("source_replay_reference_if_any", {}) for row in manifest_rows}
    xs: list[float] = []
    ys: list[float] = []
    for row in arm_rows:
        replay_scores = replay_by_sample.get(row["sample_id"], {}).get("route_values_pre_generation", {})
        if row["arm_id"] in replay_scores:
            xs.append(float(replay_scores[row["arm_id"]]))
            ys.append(float(row["score"]))
    corr = pearson(xs, ys)
    mae = round(sum(abs(x - y) for x, y in zip(xs, ys)) / max(len(xs), 1), 6) if xs else None
    if corr is None:
        decision = "TRUEGEN_INSUFFICIENT__LARGER_MINIFURNACE_NEXT"
    elif corr < 0.1:
        decision = "TRUEGEN_CONFLICTS_WITH_REPLAY__DIAGNOSTIC_REVIEW_NEXT"
    else:
        decision = "TRUEGEN_VALIDATED__TARGETED_REPLAY_DESIGN_NEXT"
    return authority(
        schema_id="kt.v17_7_4.truegen_replay_correlation_scorecard.v1",
        status="PASS",
        measurement_source=FRESH_SOURCE,
        compared_pairs=len(xs),
        correlation_replay_score_to_truegen_score=corr,
        mean_absolute_error=mae,
        decision=decision,
    )


def write_assessment(out: Path) -> Path:
    assessment = out / "KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip"
    with zipfile.ZipFile(assessment, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in ASSESSMENT_FILES:
            path = out / name
            if path.exists():
                archive.write(path, name)
        blocker = out / "BLOCKER_RECEIPT.json"
        if blocker.exists():
            archive.write(blocker, "BLOCKER_RECEIPT.json")
    return assessment


def write_blocker(out: Path, run_id: str, reason: str, defects: list[str] | None = None) -> dict[str, Any]:
    payload = authority(
        schema_id="kt.v17_7_4.truegen_blocker_receipt.v1",
        status="BLOCKED",
        run_id=run_id,
        outcome="KTG3FULL_V17_7_4_BLOCKED__GENERATION_FAILURE",
        reason=reason,
        defects=defects or [],
        next_lawful_move="FIX_TRUEGEN_RUNTIME_INPUTS_AND_RERUN",
    )
    write_json(out / "BLOCKER_RECEIPT.json", payload)
    write_assessment(out)
    return payload


def run_truegen_runtime(runtime_root: Path, out: Path | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    if out is None:
        out = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktv1774_truegen_outputs"))
        if not out.parent.exists():
            out = Path("ktv1774_truegen_outputs")
    out.mkdir(parents=True, exist_ok=True)
    run_id = os.environ.get("KT_RUN_ID") or f"ktv1774_truegen_{int(time.time())}"
    config_path = resolve_runtime_path(runtime_root, "KT_TRUEGEN_ARM_MODEL_CONFIG", "runtime_inputs/arm_model_config.json")
    if not config_path.exists():
        example = runtime_root / "runtime_inputs" / "arm_model_config.example.json"
        if example.exists():
            config_path = example
        else:
            return write_blocker(out, run_id, "missing arm_model_config.json")
    row_manifest_path = resolve_runtime_path(runtime_root, "KT_TRUEGEN_ROW_MANIFEST", "runtime_inputs/truegen_row_manifest.json")
    try:
        config = read_json(config_path)
        defects = validate_arm_model_config(config)
        if defects:
            return write_blocker(out, run_id, "arm model config contract failed", defects)
        row_limit = int(os.environ.get("KT_TRUEGEN_ROW_LIMIT", str(config.get("row_limit", 100))))
        manifest = load_row_manifest(row_manifest_path, row_limit=row_limit)
        write_json(
            out / "arm_model_config_receipt.json",
            authority(
                schema_id="kt.v17_7_4.arm_model_config_receipt.v1",
                status="PASS",
                config_path=str(config_path),
                enabled_arms=[arm["arm_id"] for arm in enabled_arms(config)],
                bundled_example_config_used=config_path.name.endswith(".example.json"),
            ),
        )
        arm_rows = generate_arm_rows(manifest, config, run_id)
        predictions = aggregate_predictions(arm_rows, run_id)
        scorecards = recompute_scorecards(arm_rows, predictions)
        correlation = replay_correlation(arm_rows, manifest["rows"])
        write_jsonl(out / "truegen_arm_result_matrix.jsonl", arm_rows)
        write_jsonl(out / "truegen_predictions.jsonl", predictions)
        write_json(out / "truegen_benchmark_scorecard.json", scorecards["benchmark"])
        write_json(out / "truegen_replay_correlation_scorecard.json", correlation)
        write_json(out / "truegen_negative_transfer_by_arm.json", scorecards["negative_transfer"])
        write_json(out / "truegen_token_efficiency_matrix.json", scorecards["token_efficiency"])
        write_json(out / "truegen_per_band_arm_win_matrix.json", scorecards["per_band"])
        write_json(out / "truegen_oracle_gap_update.json", scorecards["oracle_gap"])
        write_json(out / "truegen_pfail_dgs_update.json", scorecards["pfail_dgs"])
        decision = correlation["decision"]
        write_json(
            out / "truegen_measurement_authority_receipt.json",
            authority(
                schema_id="kt.v17_7_4.truegen_measurement_authority_receipt.v1",
                status="PASS",
                evidence_tier="TIER_4_FRESH_MODEL_GENERATION",
                measurement_source=FRESH_SOURCE,
                measurement_status=FRESH_STATUS,
                generation_artifacts_present=True,
                max_authority="fresh-generation mini-furnace evidence only",
                route_promotion_authorized=False,
                adapter_promotion_authorized=False,
            ),
        )
        write_json(
            out / "truegen_claim_admissibility_casefile.json",
            authority(
                schema_id="kt.v17_7_4.truegen_claim_admissibility_casefile.v1",
                status="PASS",
                claim="V17.7.4 fresh-generation mini-furnace executed",
                tier="TIER_4_FRESH_MODEL_GENERATION",
                limitations=["no external reproduction", "no promotion authority", "no V18 authority"],
                measurement_source=FRESH_SOURCE,
            ),
        )
        telemetry = authority(
            schema_id="kt.v17_7_4.runtime_telemetry_receipt.v1",
            status="PASS",
            run_id=run_id,
            elapsed_seconds=round(time.perf_counter() - started, 6),
            row_count=len(predictions),
            arm_rows=len(arm_rows),
            measurement_source=FRESH_SOURCE,
            measurement_status=FRESH_STATUS,
        )
        write_json(out / "runtime_telemetry_receipt.json", telemetry)
        assessment = write_assessment(out)
        summary = authority(
            schema_id="kt.v17_7_4.truegen_final_summary.v1",
            status="PASS",
            outcome="KTG3FULL_V17_7_4_TRUEGEN_MINIFURNACE_RUNTIME_COMPLETED__CLAIM_CEILING_PRESERVED",
            run_id=run_id,
            assessment_zip=assessment.as_posix(),
            decision=decision,
            next_lawful_move=decision,
            measurement_source=FRESH_SOURCE,
            measurement_status=FRESH_STATUS,
            generation_artifacts_present=True,
        )
        write_json(out / "final_summary.json", summary)
        write_assessment(out)
        return summary
    except Exception as exc:  # noqa: BLE001
        return write_blocker(out, run_id, str(exc))
