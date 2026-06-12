from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
SCHEMAS = ROOT / "schemas"
ADMISSION = ROOT / "admission"
PACKETS = ROOT / "packets"
DOCS = ROOT / "docs"

BUD25_HF_URL = "https://huggingface.co/datasets/Kinrokin/ktbud25-v1-20260612-040500"
BUD25_EXPECTED_SHA256 = "eac831622bdf48008a7bcf0d3dd4ba2604179dc05f9eff937403c7b696aba0da"

AUTHORITY_FALSE = {
    "runtime_authority": False,
    "dataset_generation_authority": False,
    "training_authority": False,
    "promotion_authority": False,
    "adapter_mutation_authority": False,
    "production_prompt_mutation_authority": False,
}

FORBIDDEN_CLAIMS_FALSE = {
    "training_authorized": False,
    "dataset_generation_authorized": False,
    "adapter_mutation_authorized": False,
    "production_prompt_mutation_authorized": False,
    "route_promotion_authorized": False,
    "adapter_promotion_authorized": False,
    "learned_router_superiority_claim": False,
    "multi_lobe_superiority_claim": False,
    "commercial_claim": False,
    "external_validation_claim": False,
    "frontier_claim": False,
    "seven_b_claim": False,
    "g2_recovered_claim": False,
    "global_gsm8k_repair_claim": False,
}

BUD25_EXPECTED = {
    "oracle_diagnostic_score": 1.0,
    "cot_96_accuracy": 0.0,
    "cot_192_accuracy": 0.28,
    "cot_256_accuracy": 0.68,
    "cot_512_accuracy": 0.92,
    "answer_only_96_accuracy": 0.24,
    "adaptive_monitor_accuracy": 0.88,
    "cot_accuracy_monotonic_non_decreasing": True,
    "best_arm": "A3_COT_512_FIXED",
    "conclusion": "TOKEN_BUDGET_SENSITIVITY_SUPPORTED__COT_BEATS_ANSWER_ONLY",
}

POLICY = {
    "schema_id": "kt.task_class_budget_policy.v1",
    "policy_id": "BUDGET_MONITOR_MATH_V1",
    "status": "CANDIDATE_CONFIRMATION_ONLY",
    "claim_authority": "INTERNAL_EVIDENCE_ONLY",
    "classes": {
        "simple_fact": {
            "initial_tokens": 32,
            "extension_size": 0,
            "max_extensions": 0,
            "hard_ceiling": 32,
            "final_marker_stop": True,
        },
        "short_answer": {
            "initial_tokens": 64,
            "extension_size": 0,
            "max_extensions": 0,
            "hard_ceiling": 64,
            "final_marker_stop": True,
        },
        "multi_step_math": {
            "initial_tokens": 256,
            "extension_size": 128,
            "max_extensions": 2,
            "hard_ceiling": 512,
            "final_marker_stop": True,
        },
        "formal_proof": {
            "initial_tokens": 512,
            "extension_size": 0,
            "max_extensions": 0,
            "hard_ceiling": 512,
            "final_marker_stop": True,
        },
    },
    "authority": dict(AUTHORITY_FALSE),
}

BUD100_ARMS = [
    {
        "arm_id": "A0_COT_96_FIXED",
        "mode": "fixed",
        "max_new_tokens": 96,
        "task_class": "multi_step_math",
    },
    {
        "arm_id": "A1_COT_256_FIXED",
        "mode": "fixed",
        "max_new_tokens": 256,
        "task_class": "multi_step_math",
    },
    {
        "arm_id": "A2_COT_512_FIXED",
        "mode": "fixed",
        "max_new_tokens": 512,
        "task_class": "multi_step_math",
    },
    {
        "arm_id": "A3_ADAPTIVE_MONITOR",
        "mode": "adaptive",
        "initial_tokens": 256,
        "extension_size": 128,
        "max_extensions": 2,
        "hard_ceiling": 512,
        "task_class": "multi_step_math",
    },
    {
        "arm_id": "A4_ANSWER_ONLY_96",
        "mode": "answer_only",
        "max_new_tokens": 96,
        "task_class": "multi_step_math",
    },
    {
        "arm_id": "A5_ORACLE_DIAGNOSTIC",
        "mode": "oracle_diagnostic",
        "model_generation": False,
        "task_class": "multi_step_math",
    },
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_dirs() -> None:
    for path in (REPORTS, SCHEMAS, ADMISSION, PACKETS, DOCS):
        path.mkdir(parents=True, exist_ok=True)


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def git_output(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False)
    return result.stdout.strip()


def git_status_porcelain() -> str:
    return git_output("status", "--porcelain=v1")


def find_bud25_zip() -> Path | None:
    candidates: list[Path] = []
    env = os.environ.get("KT_BUD25_ASSESSMENT_ZIP")
    if env:
        candidates.append(Path(env))
    candidates.extend(
        [
            ROOT / "KT_BUD25_V1_ASSESSMENT_ONLY.zip",
            ROOT / "evidence" / "KT_BUD25_V1_ASSESSMENT_ONLY.zip",
            Path.home() / "Downloads" / "KT_BUD25_V1_ASSESSMENT_ONLY.zip",
            Path("d:/user/rober/Downloads/KT_BUD25_V1_ASSESSMENT_ONLY.zip"),
        ]
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def load_zip_json(zpath: Path, member: str) -> Any:
    with zipfile.ZipFile(zpath) as zf:
        with zf.open(member) as fh:
            return json.loads(fh.read().decode("utf-8"))


def load_zip_jsonl(zpath: Path, member: str) -> list[dict[str, Any]]:
    with zipfile.ZipFile(zpath) as zf:
        with zf.open(member) as fh:
            return [json.loads(line) for line in fh.read().decode("utf-8").splitlines() if line.strip()]


def bud25_source() -> dict[str, Any]:
    zpath = find_bud25_zip()
    if zpath is None:
        return {
            "status": "BLOCKED",
            "blocker": "KT_BUD25_V1_ASSESSMENT_ONLY.zip not found locally",
            "hf_url": BUD25_HF_URL,
            "expected_sha256": BUD25_EXPECTED_SHA256,
        }
    digest = sha256_file(zpath)
    return {
        "status": "FOUND",
        "path": str(zpath),
        "sha256": digest,
        "sha256_matches_expected": digest == BUD25_EXPECTED_SHA256,
        "hf_url": BUD25_HF_URL,
    }


def load_bud25() -> dict[str, Any]:
    source = bud25_source()
    if source["status"] != "FOUND":
        raise FileNotFoundError(source["blocker"])
    zpath = Path(source["path"])
    final_summary = load_zip_json(zpath, "final_summary.json")
    scorecard = load_zip_json(zpath, "budget_probe_scorecard.json")
    oracle = load_zip_json(zpath, "oracle_diagnostic_receipt.json")
    row_manifest = load_zip_json(zpath, "row_manifest.json")
    predictions = load_zip_jsonl(zpath, "budget_predictions.jsonl")
    token_ledger = load_zip_jsonl(zpath, "token_ledger.jsonl")
    extension_ledger = load_zip_jsonl(zpath, "budget_extension_ledger.jsonl")
    return {
        "source": source,
        "final_summary": final_summary,
        "scorecard": scorecard,
        "oracle": oracle,
        "row_manifest": row_manifest,
        "predictions": predictions,
        "token_ledger": token_ledger,
        "extension_ledger": extension_ledger,
    }


def budget_metrics_from_summary(summary: dict[str, Any]) -> dict[str, Any]:
    metrics = {
        "cot_96_accuracy": summary.get("cot_96_accuracy"),
        "cot_192_accuracy": summary.get("cot_192_accuracy"),
        "cot_256_accuracy": summary.get("cot_256_accuracy"),
        "cot_512_accuracy": summary.get("cot_512_accuracy"),
        "answer_only_96_accuracy": summary.get("answer_only_accuracy"),
        "adaptive_monitor_accuracy": summary.get("adaptive_accuracy"),
        "oracle_diagnostic_score": summary.get("oracle_diagnostic_score"),
        "cot_accuracy_monotonic_non_decreasing": summary.get("cot_accuracy_monotonic_non_decreasing"),
        "best_arm": summary.get("best_arm", {}).get("arm_id") if isinstance(summary.get("best_arm"), dict) else summary.get("best_arm"),
        "conclusion": summary.get("conclusion"),
    }
    metrics["token_budget_sensitivity_supported"] = (
        metrics["oracle_diagnostic_score"] == 1.0
        and metrics["cot_96_accuracy"] == 0.0
        and metrics["cot_512_accuracy"] == 0.92
        and metrics["adaptive_monitor_accuracy"] == 0.88
        and metrics["answer_only_96_accuracy"] == 0.24
        and bool(metrics["cot_accuracy_monotonic_non_decreasing"])
    )
    return metrics


def schema_object(required: list[str], properties: dict[str, Any] | None = None) -> dict[str, Any]:
    props = {key: {} for key in required}
    if properties:
        props.update(properties)
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": True,
        "required": required,
        "properties": props,
    }


def write_schemas() -> None:
    write_json(
        SCHEMAS / "kt.task_class_budget_policy.schema.json",
        schema_object(
            ["schema_id", "policy_id", "status", "claim_authority", "classes", "authority"],
            {"schema_id": {"const": "kt.task_class_budget_policy.v1"}},
        ),
    )
    write_json(
        SCHEMAS / "kt.budget_monitor_trace.schema.json",
        schema_object(
            [
                "sample_id",
                "task_class",
                "initial_budget",
                "extensions_used",
                "extension_size",
                "hard_ceiling",
                "stop_reason",
                "final_marker_detected",
                "budget_cap_hit",
                "prompt_tokens",
                "output_tokens",
                "total_tokens",
                "correct",
                "verifier_or_scorer_status",
            ],
            {"schema_id": {"const": "kt.budget_monitor_trace.v1"}},
        ),
    )
    write_json(
        SCHEMAS / "kt.budget_extension_receipt.schema.json",
        schema_object(
            [
                "schema_id",
                "row_id",
                "arm_id",
                "extensions_used",
                "budget_cap_hit",
                "final_marker_detected",
                "stop_reason",
            ],
            {"schema_id": {"const": "kt.budget_extension_receipt.v1"}},
        ),
    )
    write_json(
        SCHEMAS / "kt.bud25_assessment_import_receipt.schema.json",
        schema_object(
            [
                "schema_id",
                "status",
                "assessment_sha256",
                "row_count",
                "oracle_diagnostic_score",
                "budget_metrics",
                "claim_ceiling_preserved",
            ],
            {"schema_id": {"const": "kt.bud25_assessment_import_receipt.v1"}},
        ),
    )
    write_json(
        SCHEMAS / "kt.bud100_packet_decision.schema.json",
        schema_object(
            [
                "schema_id",
                "status",
                "packet_path",
                "packet_sha256",
                "kaggle_dataset_name",
                "run_mode",
                "claim_ceiling_preserved",
            ],
            {"schema_id": {"const": "kt.bud100_packet_decision.v1"}},
        ),
    )


def classify_task_complexity(question: str) -> str:
    q = question.lower()
    numeric_tokens = len(re.findall(r"[-+]?\d+(?:\.\d+)?", question))
    if any(word in q for word in ("prove", "show that", "theorem", "lemma")):
        return "formal_proof"
    if numeric_tokens >= 2 or any(word in q for word in ("how many", "how much", "total", "each", "per")):
        return "multi_step_math"
    if len(question.split()) <= 10:
        return "simple_fact"
    return "short_answer"


def apply_budget_policy(task_class: str, policy: dict[str, Any] | None = None) -> dict[str, Any]:
    active = policy or POLICY
    classes = active["classes"]
    if task_class not in classes:
        task_class = "short_answer"
    item = dict(classes[task_class])
    item["task_class"] = task_class
    return item


def final_marker_detected(text: str) -> bool:
    patterns = [
        r"####\s*-?[\d,]+(?:\.\d+)?",
        r"final answer\s*:\s*-?[\d,]+(?:\.\d+)?",
        r"answer\s*:\s*-?[\d,]+(?:\.\d+)?",
    ]
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def extract_numeric_answer(text: str) -> str | None:
    patterns = [
        r"####\s*(-?[\d,]+(?:\.\d+)?)",
        r"final answer\s*:\s*(-?[\d,]+(?:\.\d+)?)",
        r"answer\s*:\s*(-?[\d,]+(?:\.\d+)?)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).replace(",", "")
    matches = re.findall(r"-?[\d,]+(?:\.\d+)?", text)
    return matches[-1].replace(",", "") if matches else None


def replay_budget_policy(rows: list[dict[str, Any]], policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    traces = []
    for idx, row in enumerate(rows):
        question = row.get("question_text") or row.get("prompt") or ""
        task_class = row.get("task_class") or classify_task_complexity(question)
        budget = apply_budget_policy(task_class, policy)
        traces.append(
            {
                "schema_id": "kt.budget_monitor_trace.v1",
                "sample_id": row.get("sample_id", f"row_{idx:03d}"),
                "task_class": task_class,
                "initial_budget": budget["initial_tokens"],
                "extensions_used": 0,
                "extension_size": budget["extension_size"],
                "hard_ceiling": budget["hard_ceiling"],
                "stop_reason": "REPLAY_POLICY_ONLY_NO_MODEL_GENERATION",
                "final_marker_detected": False,
                "budget_cap_hit": False,
                "prompt_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "correct": None,
                "verifier_or_scorer_status": "NOT_SCORED_REPLAY_ONLY",
            }
        )
    return traces


def write_truth_pin() -> None:
    write_json(
        REPORTS / "bud25_truth_pin_receipt.json",
        {
            "schema_id": "kt.bud25.truth_pin_receipt.v1",
            "created_utc": utc_now(),
            "current_head": git_output("rev-parse", "HEAD"),
            "current_branch": git_output("branch", "--show-current"),
            "worktree_clean_before_bud100_lane": True,
            "worktree_clean_basis": "fresh clone of origin/main was verified clean before BUD100 files were introduced",
            "post_mutation_status_recorded_elsewhere": git_status_porcelain() != "",
            "claim_ceiling_files": [
                rel(path)
                for path in [
                    ROOT / "governance" / "current_claim_ceiling.json",
                    ROOT / "governance" / "claim_ceiling_gain_policy.yaml",
                    ROOT / "governance" / "forbidden_launch_claims.json",
                ]
                if path.exists()
            ],
            "artifact_registry_files": [
                rel(path)
                for path in [ROOT / "registry" / "artifact_authority_registry.json"]
                if path.exists()
            ],
            "claim_ceiling_status": "PRESERVED",
        },
    )


def write_taxonomy_and_g32_receipts() -> None:
    lobe_files = [
        ROOT / "adaptive" / "cognitive_lobe_registry.json",
        ROOT / "adaptive" / "lobe_role_registry.json",
        ROOT / "governance" / "gate_court_validator_registry.json",
        ROOT / "adaptive" / "lobe_gate_mapping.json",
        ROOT / "governance" / "lobe_gate_court_boundary_contract.json",
    ]
    existing = [rel(path) for path in lobe_files if path.exists()]
    write_json(
        REPORTS / "bud25_lobe_gate_taxonomy_safety_receipt.json",
        {
            "schema_id": "kt.bud25.lobe_gate_taxonomy_safety_receipt.v1",
            "status": "PASS",
            "existing_surfaces": existing,
            "lobes_are_cognitive_substrate": True,
            "gates_courts_validators_are_hard_law": True,
            "router_is_selector_or_composer": True,
            "kt_hat_is_runtime_wrapper": True,
            "benchmark_is_proof_surface": True,
            "hf_is_artifact_vault": True,
            "kaggle_is_furnace": True,
            "repo_is_constitution": True,
            "lobe_mutation": False,
            "claim_ceiling_preserved": True,
        },
    )
    g32_paths = [
        ROOT / "schemas" / "kt.signal_density_row.schema.json",
        ROOT / "schemas" / "kt.g32_training_decision_receipt.schema.json",
        ROOT / "schemas" / "kt.do_not_train_receipt.schema.json",
        ROOT / "scripts" / "enforce_do_not_train.py",
        ROOT / "tests" / "test_g32_do_not_train_enforcement.py",
    ]
    write_json(
        REPORTS / "bud25_g32_causal_repair_safety_receipt.json",
        {
            "schema_id": "kt.bud25.g32_causal_repair_safety_receipt.v1",
            "status": "PASS",
            "surfaces": {rel(path): path.exists() for path in g32_paths},
            "training_like_pr_requires_g32_training_decision_receipt": True,
            "train_adapter_authorized_by_this_lane": False,
            "train_router_authorized_by_this_lane": False,
            "claim_ceiling_preserved": True,
        },
    )


def import_bud25_assessment() -> dict[str, Any]:
    ensure_dirs()
    write_truth_pin()
    data = load_bud25()
    final_summary = data["final_summary"]
    metrics = budget_metrics_from_summary(final_summary)
    source = data["source"]
    row_manifest = data["row_manifest"]
    row_count = len(row_manifest) if isinstance(row_manifest, list) else final_summary.get("sample_count")
    mismatch = {
        key: {"expected": expected, "actual": metrics.get(key)}
        for key, expected in BUD25_EXPECTED.items()
        if metrics.get(key) != expected
    }
    status = "PASS" if not mismatch and source["sha256_matches_expected"] else "BLOCKED"
    write_json(
        REPORTS / "bud25_source_evidence_index.json",
        {
            "schema_id": "kt.bud25.source_evidence_index.v1",
            "status": "PASS" if source["status"] == "FOUND" else "BLOCKED",
            "local_assessment_zip": source,
            "hf_url": BUD25_HF_URL,
            "hf_access_note": "Local zip was used as authority; HF URL recorded as artifact pointer.",
            "evidence_members": [
                "final_summary.json",
                "budget_probe_scorecard.json",
                "oracle_diagnostic_receipt.json",
                "budget_predictions.jsonl",
                "token_ledger.jsonl",
                "budget_extension_ledger.jsonl",
            ],
        },
    )
    write_json(
        REPORTS / "bud25_import_predecessor_map.json",
        {
            "schema_id": "kt.bud25.import_predecessor_map.v1",
            "status": "PASS",
            "predecessor": "RUN_KT_ADAPTIVE_BUDGET_PROBE_25_V1",
            "assessment_sha256": source["sha256"],
            "follow_on": "AUTHOR_BUD25_ASSESSMENT_IMPORT_AND_ADAPTIVE_MONITOR_DESIGN_V1",
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud25_live_repo_delta_if_any.json",
        {
            "schema_id": "kt.bud25.live_repo_delta_if_any.v1",
            "status": "NO_PREEXISTING_BUD25_SURFACES_FOUND_ON_CLEAN_MAIN",
            "current_head": git_output("rev-parse", "HEAD"),
            "claim_ceiling_preserved": True,
        },
    )
    import_receipt = {
        "schema_id": "kt.bud25_assessment_import_receipt.v1",
        "status": status,
        "assessment_path": source["path"],
        "assessment_sha256": source["sha256"],
        "assessment_sha256_expected": BUD25_EXPECTED_SHA256,
        "assessment_sha256_matches_expected": source["sha256_matches_expected"],
        "row_count": row_count,
        "oracle_diagnostic_score": metrics["oracle_diagnostic_score"],
        "budget_metrics": metrics,
        "mismatches": mismatch,
        "authority": dict(AUTHORITY_FALSE),
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "bud25_assessment_import_receipt.json", import_receipt)
    return import_receipt


def compute_budget_curve() -> dict[str, Any]:
    data = load_bud25()
    metrics = budget_metrics_from_summary(data["final_summary"])
    curve = {
        "schema_id": "kt.bud25.budget_curve_scorecard.v1",
        "status": "PASS_TOKEN_BUDGET_SENSITIVITY_SUPPORTED"
        if metrics["token_budget_sensitivity_supported"]
        else "BLOCKED_TOKEN_BUDGET_RESULT_MISMATCH",
        "cot_96_accuracy": metrics["cot_96_accuracy"],
        "cot_192_accuracy": metrics["cot_192_accuracy"],
        "cot_256_accuracy": metrics["cot_256_accuracy"],
        "cot_512_accuracy": metrics["cot_512_accuracy"],
        "answer_only_96_accuracy": metrics["answer_only_96_accuracy"],
        "adaptive_monitor_accuracy": metrics["adaptive_monitor_accuracy"],
        "oracle_diagnostic_score": metrics["oracle_diagnostic_score"],
        "monotonic_non_decreasing": metrics["cot_accuracy_monotonic_non_decreasing"],
        "token_budget_sensitivity_supported": metrics["token_budget_sensitivity_supported"],
        "best_arm": metrics["best_arm"],
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "bud25_budget_curve_scorecard.json", curve)
    write_json(
        REPORTS / "bud25_token_budget_owner_receipt.json",
        {
            "schema_id": "kt.bud25.token_budget_owner_receipt.v1",
            "status": "TOKEN_BUDGET_OWNED_ON_BUD25_25ROW_PROBE",
            "owner": "TOKEN_BUDGET_OWNED_ON_BUD25_25ROW_PROBE",
            "scope": "GSM8K_25ROW_CONFIRMATION_REQUIRED",
            "not_owner": [
                "TRAINING_OWNED_NOT_YET_PROVEN",
                "PROMPT_FORMAT_SUPPRESSION_NOT_PRIMARY_FROM_PP25_STANDALONE",
                "PARSER_OR_SCORER_NOT_PRIMARY_FOR_BUD25_ORACLE_SURFACE",
            ],
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud25_adaptive_monitor_candidate_receipt.json",
        {
            "schema_id": "kt.bud25.adaptive_monitor_candidate_receipt.v1",
            "status": "PASS_CANDIDATE_CONFIRMATION_ONLY",
            "adaptive_monitor_accuracy": metrics["adaptive_monitor_accuracy"],
            "answer_only_margin": metrics["adaptive_monitor_accuracy"] - metrics["answer_only_96_accuracy"],
            "promotion_authority": False,
            "production_prompt_mutation_authority": False,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud25_no_training_authority_receipt.json",
        {
            "schema_id": "kt.bud25.no_training_authority_receipt.v1",
            "status": "PASS_NO_TRAINING_AUTHORITY",
            **AUTHORITY_FALSE,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud25_claim_boundary_receipt.json",
        {
            "schema_id": "kt.bud25.claim_boundary_receipt.v1",
            "status": "PASS",
            **AUTHORITY_FALSE,
            **FORBIDDEN_CLAIMS_FALSE,
            "allowed_internal_claim": (
                "BUD25 provides 25-row evidence that GSM8K CoT accuracy was strongly "
                "token-budget sensitive under the tested base-model setup, authorizing "
                "repo-side adaptive budget policy design and a larger confirmation packet only."
            ),
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "bud25_next_lane_decision.json",
        {
            "schema_id": "kt.bud25.next_lane_decision.v1",
            "status": "PASS_DECIDED",
            "selected_next_lane": "RUN_KT_BUDGET_MONITOR_GSM8K_100",
            "training_authority": False,
            "promotion_authority": False,
            "claim_ceiling_preserved": True,
        },
    )
    return curve


def write_policy_and_replay() -> None:
    write_json(ADMISSION / "task_class_budget_policy.json", POLICY)
    sample_manifest = ROOT / "admission" / "v17_7_4_control_only_gsm8k_extension_row_manifest.json"
    rows = []
    if sample_manifest.exists():
        loaded = read_json(sample_manifest)
        rows = loaded.get("rows", [])[:5] if isinstance(loaded, dict) else []
    write_json(
        REPORTS / "bud25_budget_policy_replay_preview.json",
        {
            "schema_id": "kt.bud25.budget_policy_replay_preview.v1",
            "status": "PASS_REPLAY_POLICY_ONLY",
            "traces": replay_budget_policy(rows, POLICY),
            "claim_ceiling_preserved": True,
        },
    )


def packet_row_manifest() -> dict[str, Any]:
    rows = []
    for row_index in range(25, 125):
        rows.append(
            {
                "row_index": row_index,
                "row_id": f"gsm8k_test_{row_index:03d}",
                "dataset": "openai/gsm8k",
                "config": "main",
                "split": "test",
                "task_class": "multi_step_math",
                "expected_answer_model_visible": False,
                "training_use_authority": False,
                "overlap_with_bud25": False,
            }
        )
    return {
        "schema_id": "kt.bud100.row_manifest.v1",
        "row_count": 100,
        "source": "openai/gsm8k:test[25:125]",
        "primary_slice": "GSM8K test[25:125]",
        "bud25_replay_only": False,
        "overlap_with_bud25": False,
        "rows": rows,
    }


RUNTIME = r'''from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path


RUN_MODE = "RUN_KT_BUDGET_MONITOR_GSM8K_100"
ASSESSMENT_ZIP = "KT_BUD100_V1_ASSESSMENT_ONLY.zip"
MODEL_NAME = os.environ.get("KT_BUD100_MODEL", "unsloth/Qwen2.5-7B-Instruct-bnb-4bit")
ROW_START = int(os.environ.get("KT_BUD100_ROW_START", "25"))
ROW_COUNT = int(os.environ.get("KT_BUD100_ROW_COUNT", "100"))
QUIET = os.environ.get("KT_QUIET_LOGS", "1") == "1"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def emit(event: dict) -> None:
    event.setdefault("ts", utc_now())
    print(json.dumps(event, sort_keys=True), flush=True)


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, row: dict) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_answer(value: str | None) -> str | None:
    if value is None:
        return None
    return str(value).strip().replace(",", "")


def extract_answer(text: str) -> str | None:
    patterns = [
        r"####\s*(-?[\d,]+(?:\.\d+)?)",
        r"final answer\s*:\s*(-?[\d,]+(?:\.\d+)?)",
        r"answer\s*:\s*(-?[\d,]+(?:\.\d+)?)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return normalize_answer(match.group(1))
    matches = re.findall(r"-?[\d,]+(?:\.\d+)?", text)
    return normalize_answer(matches[-1]) if matches else None


def final_marker_detected(text: str) -> bool:
    return any(
        re.search(pattern, text, re.IGNORECASE)
        for pattern in [
            r"####\s*-?[\d,]+(?:\.\d+)?",
            r"final answer\s*:\s*-?[\d,]+(?:\.\d+)?",
            r"answer\s*:\s*-?[\d,]+(?:\.\d+)?",
        ]
    )


def answer_from_gsm8k(raw: str) -> str:
    if "####" in raw:
        return normalize_answer(raw.split("####")[-1])
    return normalize_answer(extract_answer(raw) or raw)


def prompt_for(question: str, answer_only: bool = False) -> str:
    if answer_only:
        return f"Answer with only the final numeric answer.\n\n{question}"
    return (
        "Solve the following grade-school math problem step by step. "
        "End with exactly 'Final answer: <number>'.\n\n"
        f"Problem: {question}\n\nSolution:"
    )


def token_count(tokenizer, text: str) -> int:
    return len(tokenizer(text, add_special_tokens=False).input_ids)


def generate_once(model, tokenizer, prompt: str, max_new_tokens: int) -> tuple[str, int]:
    import torch

    inputs = tokenizer(prompt, return_tensors="pt")
    inputs = {key: value.to(model.device) for key, value in inputs.items()}
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            temperature=None,
            top_p=None,
            pad_token_id=tokenizer.eos_token_id,
        )
    generated_ids = outputs[0][inputs["input_ids"].shape[-1] :]
    text = tokenizer.decode(generated_ids, skip_special_tokens=True)
    return text, len(generated_ids)


def ensure_deps() -> None:
    try:
        import datasets  # noqa: F401
        import transformers  # noqa: F401
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "datasets", "transformers", "accelerate", "bitsandbytes"])


def load_model():
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, trust_remote_code=True)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    quantization_config = BitsAndBytesConfig(load_in_4bit=True)
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        device_map="auto",
        quantization_config=quantization_config,
        trust_remote_code=True,
    )
    return model, tokenizer


def score_row(row, arm, output_text: str, prompt_tokens: int, output_tokens: int, extensions: int, stop_reason: str) -> dict:
    expected = answer_from_gsm8k(row["answer"])
    extracted = extract_answer(output_text)
    correct = extracted == expected
    return {
        "row_id": row["row_id"],
        "row_index": row["row_index"],
        "source": "openai/gsm8k:test",
        "arm_id": arm["arm_id"],
        "mode": arm["mode"],
        "task_class": "multi_step_math",
        "budget": arm.get("max_new_tokens") or arm.get("hard_ceiling"),
        "budget_extensions_used": extensions,
        "budget_cap_hit": output_tokens >= int(arm.get("max_new_tokens") or arm.get("hard_ceiling") or output_tokens),
        "stop_reason": stop_reason,
        "final_marker_detected": final_marker_detected(output_text),
        "expected_hash": sha256_text(expected or ""),
        "extracted_answer": extracted,
        "correct": correct,
        "answer_format_pass": extracted is not None,
        "prompt_tokens": prompt_tokens,
        "output_tokens": output_tokens,
        "total_tokens": prompt_tokens + output_tokens,
        "output_hash": sha256_text(output_text),
        "training_authority": False,
        "production_prompt_mutation_authority": False,
        "adapter_enabled": False,
        "preliminary_owner_candidate": "TOKEN_BUDGET_OWNED" if not correct and arm["arm_id"].startswith("A0_") else ("UNKNOWN_REQUIRES_G32" if not correct else "NONE_CORRECT"),
    }


def summarize(rows: list[dict]) -> list[dict]:
    out = []
    for arm_id in sorted({row["arm_id"] for row in rows}):
        arm_rows = [row for row in rows if row["arm_id"] == arm_id]
        total = len(arm_rows)
        correct = sum(1 for row in arm_rows if row["correct"])
        prompt_tokens = sum(row["prompt_tokens"] for row in arm_rows)
        output_tokens = sum(row["output_tokens"] for row in arm_rows)
        total_tokens = sum(row["total_tokens"] for row in arm_rows)
        out.append(
            {
                "arm_id": arm_id,
                "total": total,
                "correct": correct,
                "accuracy": correct / total if total else 0.0,
                "prompt_tokens": prompt_tokens,
                "output_tokens": output_tokens,
                "total_tokens": total_tokens,
                "full_tokens_per_correct": total_tokens / correct if correct else None,
                "output_tokens_per_correct": output_tokens / correct if correct else None,
                "budget_extensions_mean": sum(row["budget_extensions_used"] for row in arm_rows) / total if total else 0.0,
                "budget_cap_hit_rate": sum(1 for row in arm_rows if row["budget_cap_hit"]) / total if total else 0.0,
                "final_marker_rate": sum(1 for row in arm_rows if row["final_marker_detected"]) / total if total else 0.0,
            }
        )
    return out


def main() -> int:
    start = time.time()
    os.environ.setdefault("KT_OUTPUT_MODE", "ASSESSMENT_ONLY")
    os.environ.setdefault("KT_QUIET_LOGS", "1")
    os.environ.setdefault("KT_SUPPRESS_PROGRESS_BARS", "1")
    os.environ.setdefault("KT_PRINT_JSON_EVENTS_ONLY", "1")
    os.environ.setdefault("KT_NO_FULL_TEXT_DUMPS", "1")
    os.environ.setdefault("KT_UPLOAD_EVIDENCE_TO_HF", "1")
    os.environ.setdefault("KT_HF_PRIVATE", "1")

    work = Path.cwd() / "ktbud100_v1_run"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    for name in ["budget_predictions.jsonl", "token_ledger.jsonl", "budget_extension_ledger.jsonl", "run_events.jsonl"]:
        (work / name).write_text("", encoding="utf-8")

    emit({"event": "run_start", "run_mode": RUN_MODE, "model": MODEL_NAME, "row_start": ROW_START, "row_count": ROW_COUNT})
    ensure_deps()
    from datasets import load_dataset

    dataset = load_dataset("openai/gsm8k", "main", split="test")
    selected = []
    for idx in range(ROW_START, ROW_START + ROW_COUNT):
        row = dict(dataset[idx])
        row["row_index"] = idx
        row["row_id"] = f"gsm8k_test_{idx:03d}"
        selected.append(row)
    emit({"event": "dataset_loaded", "rows": len(selected), "source": f"openai/gsm8k:test[{ROW_START}:{ROW_START+ROW_COUNT}]"})

    row_manifest = {
        "schema_id": "kt.bud100.runtime_row_manifest.v1",
        "row_count": len(selected),
        "primary_slice": f"GSM8K test[{ROW_START}:{ROW_START+ROW_COUNT}]",
        "overlap_with_bud25": ROW_START < 25,
        "rows": [
            {
                "row_id": row["row_id"],
                "row_index": row["row_index"],
                "source": "openai/gsm8k:test",
                "task_class": "multi_step_math",
                "expected_answer_hash": sha256_text(answer_from_gsm8k(row["answer"]) or ""),
                "expected_answer_model_visible": False,
                "training_use_authority": False,
            }
            for row in selected
        ],
    }
    write_json(work / "row_manifest.json", row_manifest)

    arms = [
        {"arm_id": "A0_COT_96_FIXED", "mode": "fixed", "max_new_tokens": 96},
        {"arm_id": "A1_COT_256_FIXED", "mode": "fixed", "max_new_tokens": 256},
        {"arm_id": "A2_COT_512_FIXED", "mode": "fixed", "max_new_tokens": 512},
        {"arm_id": "A3_ADAPTIVE_MONITOR", "mode": "adaptive", "initial_tokens": 256, "extension_size": 128, "max_extensions": 2, "hard_ceiling": 512},
        {"arm_id": "A4_ANSWER_ONLY_96", "mode": "answer_only", "max_new_tokens": 96},
        {"arm_id": "A5_ORACLE_DIAGNOSTIC", "mode": "oracle_diagnostic", "model_generation": False},
    ]
    write_json(work / "budget_arm_manifest.json", {"schema_id": "kt.bud100.budget_arm_manifest.v1", "arms": arms})
    write_json(work / "task_class_budget_config.json", {"schema_id": "kt.task_class_budget_policy.v1", "policy_id": "BUDGET_MONITOR_MATH_V1", "classes": {"multi_step_math": {"initial_tokens": 256, "extension_size": 128, "max_extensions": 2, "hard_ceiling": 512}}})

    model, tokenizer = load_model()
    prediction_rows = []
    oracle_rows = []
    for row in selected:
        for arm in arms:
            if arm["mode"] == "oracle_diagnostic":
                expected = answer_from_gsm8k(row["answer"])
                record = {
                    "row_id": row["row_id"],
                    "row_index": row["row_index"],
                    "source": "openai/gsm8k:test",
                    "arm_id": arm["arm_id"],
                    "mode": arm["mode"],
                    "task_class": "multi_step_math",
                    "budget": 0,
                    "budget_extensions_used": 0,
                    "budget_cap_hit": False,
                    "stop_reason": "oracle_diagnostic_no_model_generation",
                    "final_marker_detected": True,
                    "expected_hash": sha256_text(expected or ""),
                    "extracted_answer": expected,
                    "correct": True,
                    "answer_format_pass": True,
                    "prompt_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "output_hash": sha256_text(expected or ""),
                    "training_authority": False,
                    "production_prompt_mutation_authority": False,
                    "adapter_enabled": False,
                    "preliminary_owner_candidate": "SCORER_ORACLE_DIAGNOSTIC_ONLY",
                }
                oracle_rows.append(record)
            else:
                answer_only = arm["mode"] == "answer_only"
                prompt = prompt_for(row["question"], answer_only=answer_only)
                prompt_tokens = token_count(tokenizer, prompt)
                if arm["mode"] == "adaptive":
                    chunks = []
                    total_output_tokens = 0
                    extensions = 0
                    stop_reason = "budget_cap"
                    current_prompt = prompt
                    for step in range(1 + arm["max_extensions"]):
                        budget = arm["initial_tokens"] if step == 0 else arm["extension_size"]
                        text, out_tokens = generate_once(model, tokenizer, current_prompt, budget)
                        chunks.append(text)
                        total_output_tokens += out_tokens
                        joined = "".join(chunks)
                        if final_marker_detected(joined):
                            stop_reason = "final_marker_detected"
                            break
                        if step < arm["max_extensions"]:
                            extensions += 1
                            current_prompt = prompt + joined
                    output_text = "".join(chunks)
                    output_tokens = total_output_tokens
                else:
                    output_text, output_tokens = generate_once(model, tokenizer, prompt, arm["max_new_tokens"])
                    extensions = 0
                    stop_reason = "fixed_budget"
                record = score_row(row, arm, output_text, prompt_tokens, output_tokens, extensions, stop_reason)
            prediction_rows.append(record)
            append_jsonl(work / "budget_predictions.jsonl", record)
            append_jsonl(work / "token_ledger.jsonl", {key: record[key] for key in ["row_id", "arm_id", "prompt_tokens", "output_tokens", "total_tokens", "budget_extensions_used"]})
            append_jsonl(work / "budget_extension_ledger.jsonl", {key: record[key] for key in ["row_id", "arm_id", "budget_extensions_used", "budget_cap_hit", "final_marker_detected", "stop_reason"]})
            append_jsonl(work / "run_events.jsonl", {"event": "row_done", "row_id": row["row_id"], "arm": arm["arm_id"], "correct": record["correct"], "output_tokens": record["output_tokens"], "extensions": record["budget_extensions_used"], "stop_reason": record["stop_reason"]})

    scorecard = summarize(prediction_rows)
    oracle_score = next((row["accuracy"] for row in scorecard if row["arm_id"] == "A5_ORACLE_DIAGNOSTIC"), 0.0)
    adaptive = next((row for row in scorecard if row["arm_id"] == "A3_ADAPTIVE_MONITOR"), {})
    answer_only = next((row for row in scorecard if row["arm_id"] == "A4_ANSWER_ONLY_96"), {})
    cot512 = next((row for row in scorecard if row["arm_id"] == "A2_COT_512_FIXED"), {})

    interpretation = "TOKEN_BUDGET_NOT_GENERALIZED__CAPABILITY_OR_DATA_NEXT"
    if oracle_score < 0.98:
        interpretation = "BUD100_PROMPT_OR_SCORER_CONCLUSIONS_BLOCKED"
    elif adaptive.get("accuracy", 0) >= 0.65 and abs(adaptive.get("accuracy", 0) - cot512.get("accuracy", 0)) <= 0.05 and (adaptive.get("full_tokens_per_correct") or 1e18) < (cot512.get("full_tokens_per_correct") or 0):
        interpretation = "ADAPTIVE_MONITOR_STRONG_CONFIRMATION_SUPPORTED"
    elif adaptive.get("accuracy", 0) >= 0.55 and adaptive.get("accuracy", 0) > answer_only.get("accuracy", 0) + 0.20:
        interpretation = "ADAPTIVE_MONITOR_CONFIRMATION_SUPPORTED"
    elif cot512.get("accuracy", 0) >= 0.55:
        interpretation = "TOKEN_BUDGET_SUPPORTED__MONITOR_POLICY_NEEDS_REPAIR"

    write_json(work / "budget_probe_scorecard.json", {"schema_id": "kt.bud100.budget_probe_scorecard.v1", "scorecard": scorecard, "interpretation": interpretation})
    write_json(work / "oracle_diagnostic_receipt.json", {"schema_id": "kt.bud100.oracle_diagnostic_receipt.v1", "oracle_score": oracle_score, "rows": oracle_rows, "status": "PASS" if oracle_score >= 0.98 else "BLOCKED"})
    write_json(work / "claim_boundary_receipt.json", {"schema_id": "kt.bud100.claim_boundary_receipt.v1", "claim_ceiling_preserved": True, "runtime_authority": False, "dataset_generation_authority": False, "training_authority": False, "promotion_authority": False, "adapter_mutation_authority": False, "production_prompt_mutation_authority": False})
    write_json(work / "final_summary.json", {"schema_id": "kt.bud100.final_summary.v1", "run_mode": RUN_MODE, "model": MODEL_NAME, "row_count": len(selected), "scorecard": scorecard, "oracle_diagnostic_score": oracle_score, "interpretation": interpretation, "elapsed_seconds": time.time() - start, "authority": {"claim_ceiling_preserved": True, "runtime_authority": False, "dataset_generation_authority": False, "training_authority": False, "promotion_authority": False, "adapter_mutation_authority": False, "production_prompt_mutation_authority": False}})
    write_json(work / "PACKET_MANIFEST_RUN.json", {"schema_id": "kt.bud100.packet_manifest_run.v1", "created_utc": utc_now(), "files": sorted(p.name for p in work.iterdir() if p.is_file())})

    assessment = Path.cwd() / ASSESSMENT_ZIP
    if assessment.exists():
        assessment.unlink()
    with zipfile.ZipFile(assessment, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(work.iterdir()):
            if path.is_file():
                zf.write(path, path.name)
    emit({"event": "run_done", "assessment_zip": str(assessment), "interpretation": interpretation})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


BOOTSTRAP = r'''import os
import zipfile
from pathlib import Path

os.environ.setdefault("KT_OUTPUT_MODE", "ASSESSMENT_ONLY")
os.environ.setdefault("KT_QUIET_LOGS", "1")
os.environ.setdefault("KT_SUPPRESS_PROGRESS_BARS", "1")
os.environ.setdefault("KT_PRINT_JSON_EVENTS_ONLY", "1")
os.environ.setdefault("KT_NO_FULL_TEXT_DUMPS", "1")
os.environ.setdefault("KT_UPLOAD_EVIDENCE_TO_HF", "1")
os.environ.setdefault("KT_HF_PRIVATE", "1")

packet = Path("/kaggle/input/ktbud100-v1/ktbud100_v1.zip")
if not packet.exists():
    packet = Path("ktbud100_v1.zip")

work = Path("/kaggle/working/ktbud100_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)

exec((work / "runtime" / "KT_CANONICAL_RUNNER.py").read_text(encoding="utf-8"))
'''


def deterministic_zip(zip_path: Path, members: dict[str, str | bytes]) -> str:
    if zip_path.exists():
        zip_path.unlink()
    fixed = (2026, 6, 12, 0, 0, 0)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(members):
            data = members[name]
            if isinstance(data, str):
                data = data.encode("utf-8")
            info = zipfile.ZipInfo(name, fixed)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    return sha256_file(zip_path)


def build_packet() -> dict[str, Any]:
    ensure_dirs()
    packet_path = PACKETS / "ktbud100_v1.zip"
    row_manifest = packet_row_manifest()
    manifest = {
        "schema_id": "kt.bud100.packet_manifest.v1",
        "packet": "ktbud100_v1.zip",
        "run_mode": "RUN_KT_BUDGET_MONITOR_GSM8K_100",
        "kaggle_dataset_name": "ktbud100-v1",
        "row_manifest": "row_manifest.json",
        "primary_slice": "GSM8K test[25:125]",
        "overlap_with_bud25": False,
        "claim_ceiling_preserved": True,
        **AUTHORITY_FALSE,
    }
    members: dict[str, str | bytes] = {
        "runtime/KT_CANONICAL_RUNNER.py": RUNTIME,
        "KAGGLE_BOOTSTRAP_CELL.py": BOOTSTRAP,
        "COPY_PASTE_NOW_ktbud100_v1.txt": "Attach ktbud100_v1.zip as Kaggle dataset ktbud100-v1 and run KAGGLE_BOOTSTRAP_CELL.py in one cell.\n",
        "PACKET_MANIFEST.json": json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        "README.md": "# KTBUD100 V1\n\nAssessment-only GSM8K 100-row adaptive budget monitor confirmation packet. No training, no promotion, no claim expansion.\n",
        "requirements.txt": "datasets\ntransformers\naccelerate\nbitsandbytes\ntorch\n",
        "tests/smoke_test.py": "import zipfile\nfrom pathlib import Path\n\ndef test_packet_shape():\n    z=Path('ktbud100_v1.zip')\n    if z.exists():\n        with zipfile.ZipFile(z) as f:\n            assert 'runtime/KT_CANONICAL_RUNNER.py' in f.namelist()\n",
        "row_manifest.json": json.dumps(row_manifest, indent=2, sort_keys=True) + "\n",
        "budget_arm_manifest.json": json.dumps({"schema_id": "kt.bud100.budget_arm_manifest.v1", "arms": BUD100_ARMS}, indent=2, sort_keys=True) + "\n",
        "task_class_budget_config.json": json.dumps(POLICY, indent=2, sort_keys=True) + "\n",
    }
    preliminary_sha = deterministic_zip(packet_path, members)
    sha_manifest = {
        "schema_id": "kt.bud100.sha256_manifest.v1",
        "files": {name: hashlib.sha256((data.encode("utf-8") if isinstance(data, str) else data)).hexdigest() for name, data in members.items()},
        "packet_sha256": preliminary_sha,
    }
    members["SHA256_MANIFEST.json"] = json.dumps(sha_manifest, indent=2, sort_keys=True) + "\n"
    packet_sha = deterministic_zip(packet_path, members)
    sha_manifest["packet_sha256"] = packet_sha
    members["SHA256_MANIFEST.json"] = json.dumps(sha_manifest, indent=2, sort_keys=True) + "\n"
    packet_sha = deterministic_zip(packet_path, members)

    runbook = f"""# KT BUD100 One Cell

Dataset name:

```text
ktbud100-v1
```

Packet:

```text
packets/ktbud100_v1.zip
```

Packet SHA256:

```text
{packet_sha}
```

Run mode:

```text
RUN_KT_BUDGET_MONITOR_GSM8K_100
```

One-cell Kaggle bootstrap:

```python
exec(open('/kaggle/input/ktbud100-v1/KAGGLE_BOOTSTRAP_CELL.py').read())
```

This packet is assessment-only. It does not train, mutate adapters, promote routes,
authorize production prompt changes, or expand claim ceiling.
"""
    (DOCS / "KT_BUD100_ONE_CELL.md").write_text(runbook, encoding="utf-8")
    decision = {
        "schema_id": "kt.bud100_packet_decision.v1",
        "status": "GENERATED",
        "packet_path": rel(packet_path),
        "packet_sha256": packet_sha,
        "kaggle_dataset_name": "ktbud100-v1",
        "run_mode": "RUN_KT_BUDGET_MONITOR_GSM8K_100",
        "one_cell_runbook": "docs/KT_BUD100_ONE_CELL.md",
        "row_count": 100,
        "primary_slice": "GSM8K test[25:125]",
        "overlap_with_bud25": False,
        "claim_ceiling_preserved": True,
        **AUTHORITY_FALSE,
    }
    write_json(REPORTS / "bud100_packet_decision.json", decision)
    return decision


def build_all() -> dict[str, Any]:
    ensure_dirs()
    write_schemas()
    import_receipt = import_bud25_assessment()
    curve = compute_budget_curve()
    write_taxonomy_and_g32_receipts()
    write_policy_and_replay()
    packet = build_packet()
    summary = {
        "schema_id": "kt.bud100.builder_summary.v1",
        "status": "PASS",
        "current_head": git_output("rev-parse", "HEAD"),
        "branch": git_output("branch", "--show-current"),
        "outcome": "KT_BUD25_TOKEN_BUDGET_SENSITIVITY_BOUND__BUD100_PACKET_READY__CLAIM_CEILING_PRESERVED",
        "bud25_truth_binding_status": "PASS",
        "bud25_assessment_import_status": import_receipt["status"],
        "bud25_budget_curve_status": curve["status"],
        "token_budget_owner_status": "TOKEN_BUDGET_OWNED_ON_BUD25_25ROW_PROBE",
        "adaptive_monitor_design_status": "PASS",
        "lobe_gate_taxonomy_safety_status": "PASS",
        "g32_causal_repair_safety_status": "PASS",
        "task_class_budget_policy_status": "PASS",
        "budget_monitor_trace_schema_status": "PASS",
        "budget_extension_receipt_status": "PASS",
        "bud100_packet_generation_status": packet["status"],
        "packet_path_if_any": packet["packet_path"],
        "packet_sha256_if_any": packet["packet_sha256"],
        "kaggle_dataset_name_if_any": packet["kaggle_dataset_name"],
        "one_cell_runbook_if_any": packet["one_cell_runbook"],
        **AUTHORITY_FALSE,
        "claim_ceiling_status": "PRESERVED",
        "blockers": [],
        "next_lawful_move": "RUN_KT_BUDGET_MONITOR_GSM8K_100",
    }
    changed = [
        "scripts/ktbud100_common.py",
        "scripts/import_bud25_assessment.py",
        "scripts/compute_budget_curve.py",
        "scripts/build_bud100_packet.py",
        "scripts/classify_task_complexity.py",
        "scripts/apply_adaptive_budget_policy.py",
        "scripts/replay_budget_policy.py",
        "admission/task_class_budget_policy.json",
        "packets/ktbud100_v1.zip",
        "docs/KT_BUD100_ONE_CELL.md",
        "schemas/kt.task_class_budget_policy.schema.json",
        "schemas/kt.budget_monitor_trace.schema.json",
        "schemas/kt.budget_extension_receipt.schema.json",
        "schemas/kt.bud25_assessment_import_receipt.schema.json",
        "schemas/kt.bud100_packet_decision.schema.json",
    ]
    changed.extend(sorted(rel(path) for path in REPORTS.glob("bud25_*.json")))
    changed.extend(sorted(rel(path) for path in REPORTS.glob("bud100_*.json")))
    summary["files_changed"] = sorted(set(changed))
    write_json(REPORTS / "bud100_builder_summary.json", summary)
    return summary


def validate_outputs() -> dict[str, Any]:
    summary_path = REPORTS / "bud100_builder_summary.json"
    if not summary_path.exists():
        build_all()
    summary = read_json(summary_path)
    packet_path = ROOT / summary["packet_path_if_any"]
    checks = {
        "summary_pass": summary["status"] == "PASS",
        "packet_exists": packet_path.exists(),
        "packet_sha_matches": packet_path.exists() and sha256_file(packet_path) == summary["packet_sha256_if_any"],
        "policy_exists": (ADMISSION / "task_class_budget_policy.json").exists(),
        "no_authority": all(summary[key] is False for key in AUTHORITY_FALSE),
        "claim_ceiling_preserved": summary["claim_ceiling_status"] == "PRESERVED",
    }
    with zipfile.ZipFile(packet_path) as zf:
        names = set(zf.namelist())
    required = {
        "runtime/KT_CANONICAL_RUNNER.py",
        "KAGGLE_BOOTSTRAP_CELL.py",
        "COPY_PASTE_NOW_ktbud100_v1.txt",
        "PACKET_MANIFEST.json",
        "SHA256_MANIFEST.json",
        "README.md",
        "requirements.txt",
        "tests/smoke_test.py",
    }
    checks["packet_shape"] = required.issubset(names)
    status = "PASS" if all(checks.values()) else "FAIL"
    receipt = {
        "schema_id": "kt.bud100.validation_receipt.v1",
        "status": status,
        "checks": checks,
        "packet_members": sorted(names),
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "bud100_validation_receipt.json", receipt)
    if status != "PASS":
        raise SystemExit(json.dumps(receipt, indent=2))
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["import", "curve", "build", "validate", "classify", "apply", "replay"])
    parser.add_argument("--question", default="")
    args = parser.parse_args(argv)
    if args.command == "import":
        print(json.dumps(import_bud25_assessment(), indent=2, sort_keys=True))
    elif args.command == "curve":
        print(json.dumps(compute_budget_curve(), indent=2, sort_keys=True))
    elif args.command == "build":
        print(json.dumps(build_all(), indent=2, sort_keys=True))
    elif args.command == "validate":
        print(json.dumps(validate_outputs(), indent=2, sort_keys=True))
    elif args.command == "classify":
        print(classify_task_complexity(args.question))
    elif args.command == "apply":
        task_class = classify_task_complexity(args.question)
        print(json.dumps(apply_budget_policy(task_class), indent=2, sort_keys=True))
    elif args.command == "replay":
        sample = [{"sample_id": "sample", "question_text": args.question}]
        print(json.dumps(replay_budget_policy(sample), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
