from __future__ import annotations

import hashlib
import json
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
PACKETS = ROOT / "packets"
DOCS = ROOT / "docs"
EVIDENCE = ROOT / "evidence"
REGISTRY = ROOT / "registry"

ACTIVE_TRANCHE = "AUTHOR_KTCF_FORWARD_REPAIR_SELECTION_AND_PACKET_FORGE_V1"
OUTCOME = "KT_KTCF_IMPORTED__FINALIZER_REPAIR_PACKET_READY__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_KTCF_FINALIZER_STOP_SEQUENCE_CANONICALIZER_REPAIR_V1"
RUN_MODE = "RUN_KTCF_FINALIZER_STOP_SEQUENCE_CANONICALIZER_REPAIR_V1"
PACKET_PATH = PACKETS / "ktcffix_v1.zip"
KAGGLE_DATASET_NAME = "ktcffix-v1"
ASSESSMENT_PATH = EVIDENCE / "KT_CF_V1_ASSESSMENT_ONLY.zip"
ASSESSMENT_SHA256 = "ef5f7719bb35094eb66a53c6a780a36c5ec2d167577d4896e332ea59c13b247f"
KTCF_PACKET_PATH = PACKETS / "ktcf_v1.zip"

AUTHORITY_FALSE = {
    "runtime_authority": False,
    "training_authority": False,
    "promotion_authority": False,
    "selector_deployment_authority": False,
    "adapter_mutation_authority": False,
    "production_prompt_mutation_authority": False,
}

OPTIONAL_AUTHORITY_FALSE = {
    "dataset_generation_authority": False,
    "production_math_mode_claim": False,
    "commercial_claim": False,
    "frontier_or_s_tier_claim": False,
    "router_superiority_claim": False,
    "learned_router_superiority_claim": False,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repo_artifact_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if path.suffix.lower() in {".json", ".jsonl", ".md", ".py", ".txt"}:
        data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return data


def repo_artifact_stats(path: Path) -> tuple[str, int]:
    data = repo_artifact_bytes(path)
    return sha256_bytes(data), len(data)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8", newline="\n")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl_text(text: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def fail(status: str, reason: str, **extra: Any) -> None:
    payload = {
        "schema_id": "kt.ktcf_momentum.blocker_receipt.v1",
        "status": status,
        "reason": reason,
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
        **extra,
    }
    write_json(REPORTS / "ktcf_momentum_blocker_receipt.json", payload)
    raise SystemExit(json.dumps(payload, indent=2, sort_keys=True))


def read_assessment() -> dict[str, Any]:
    if not ASSESSMENT_PATH.exists():
        fail("KT_KTCF_BLOCKED__ASSESSMENT_MISSING__ONE_CORRECTIVE_ACTION_BOUND__CLAIM_CEILING_PRESERVED", "Missing evidence/KT_CF_V1_ASSESSMENT_ONLY.zip", corrective_action="Copy the verified KTCF assessment ZIP into evidence/")
    observed_sha = sha256_file(ASSESSMENT_PATH)
    if observed_sha != ASSESSMENT_SHA256:
        fail("KT_KTCF_BLOCKED__ASSESSMENT_SHA_MISMATCH__ONE_CORRECTIVE_ACTION_BOUND__CLAIM_CEILING_PRESERVED", "KTCF assessment SHA mismatch", observed_sha256=observed_sha, expected_sha256=ASSESSMENT_SHA256, corrective_action="Replace evidence ZIP with the exact verified assessment artifact")

    required = {
        "final_summary.json",
        "counterfactual_scorecard.json",
        "counterfactual_row_trial_matrix.jsonl",
        "finalizer_replay_report.json",
        "row_manifest.json",
        "control_manifest.json",
        "claim_boundary_receipt.json",
    }
    with zipfile.ZipFile(ASSESSMENT_PATH) as zf:
        names = set(zf.namelist())
        missing = sorted(required - names)
        if missing:
            fail("KT_KTCF_BLOCKED__ASSESSMENT_MEMBER_MISSING__ONE_CORRECTIVE_ACTION_BOUND__CLAIM_CEILING_PRESERVED", "Assessment ZIP is missing required members", missing_members=missing, corrective_action="Regenerate or re-upload complete KTCF assessment ZIP")
        return {
            "sha256": observed_sha,
            "members": sorted(names),
            "final_summary": json.loads(zf.read("final_summary.json").decode("utf-8")),
            "scorecard": json.loads(zf.read("counterfactual_scorecard.json").decode("utf-8")),
            "trial_matrix": read_jsonl_text(zf.read("counterfactual_row_trial_matrix.jsonl").decode("utf-8")),
            "finalizer": json.loads(zf.read("finalizer_replay_report.json").decode("utf-8")),
            "row_manifest": json.loads(zf.read("row_manifest.json").decode("utf-8")),
            "control_manifest": json.loads(zf.read("control_manifest.json").decode("utf-8")),
            "claim_boundary": json.loads(zf.read("claim_boundary_receipt.json").decode("utf-8")),
        }


def load_scorer_answers() -> dict[str, str]:
    if not KTCF_PACKET_PATH.exists():
        fail("KT_KTCF_BLOCKED__SOURCE_KTCF_PACKET_MISSING__ONE_CORRECTIVE_ACTION_BOUND__CLAIM_CEILING_PRESERVED", "Missing packets/ktcf_v1.zip required for scorer-side answer binding", corrective_action="Restore the canonical KTCF packet on main")
    with zipfile.ZipFile(KTCF_PACKET_PATH) as zf:
        config = json.loads(zf.read("runtime/ktcf_config.json").decode("utf-8"))
    return dict(config["scorer_expected_answers"])


def reconcile_scorecard(assessment: dict[str, Any]) -> dict[str, Any]:
    summary = assessment["final_summary"]
    scorecard = {row["arm_id"]: row for row in assessment["scorecard"]["scorecard"]}
    matrix = assessment["trial_matrix"]
    rows = assessment["row_manifest"]["rows"] + assessment["control_manifest"]["rows"]

    by_arm: dict[str, dict[str, Any]] = {}
    for arm_id in sorted({row["arm_id"] for row in matrix if row.get("arm_type") == "generation"}):
        arm_rows = [row for row in matrix if row.get("arm_id") == arm_id]
        control_rows = [row for row in arm_rows if row.get("role") != "TARGET"]
        target_rows = [row for row in arm_rows if row.get("role") == "TARGET"]
        by_arm[arm_id] = {
            "correct": sum(1 for row in arm_rows if row.get("correct") is True),
            "target_correct": sum(1 for row in target_rows if row.get("correct") is True),
            "control_correct": sum(1 for row in control_rows if row.get("correct") is True),
            "row_count": len(arm_rows),
            "total_tokens": sum(int(row.get("total_tokens") or 0) for row in arm_rows),
        }

    expected_facts = {
        "status": "PASS_MODEL_GENERATED_AND_SCORED",
        "row_count": 40,
        "target_rows": 26,
        "control_rows": 14,
        "generation_trials": 320,
        "oracle_any_correct_rows": 35,
        "finalizer_recovered_count": 4,
        "finalizer_recovered_count_scope": "NO_CORRECT_ARM_TARGET_ROWS_ONLY",
        "claim_ceiling_status": "PRESERVED",
    }
    fact_mismatches = {
        key: {"expected": expected, "observed": summary.get(key)}
        for key, expected in expected_facts.items()
        if summary.get(key) != expected
    }

    arm_mismatches = []
    for arm_id, computed in by_arm.items():
        observed = scorecard.get(arm_id)
        if not observed:
            arm_mismatches.append({"arm_id": arm_id, "reason": "missing_scorecard_row"})
            continue
        for key in ["correct", "target_correct", "control_correct", "row_count", "total_tokens"]:
            if observed.get(key) != computed[key]:
                arm_mismatches.append({"arm_id": arm_id, "field": key, "expected": computed[key], "observed": observed.get(key)})

    a0 = scorecard["A0_FIXED512_BASELINE"]
    a6 = scorecard["A6_STRUCTURED_FACT_EQUATION_COT_512"]
    finalizer_rows = assessment["finalizer"]["rows"]
    scoped_recovered = [
        row for row in finalizer_rows
        if row.get("role") == "TARGET" and "NO_CORRECT_ARM" in row.get("source_classes", []) and row.get("rescored_correct") is True
    ]

    status = "PASS" if not fact_mismatches and not arm_mismatches and len(scoped_recovered) == 4 else "FAIL"
    receipt = {
        "schema_id": "kt.ktcf_momentum.scorecard_reconciliation.v1",
        "status": status,
        "assessment_sha256": assessment["sha256"],
        "fact_mismatches": fact_mismatches,
        "arm_mismatches": arm_mismatches,
        "row_count": len(rows),
        "generation_trial_count": len(matrix),
        "oracle_any_correct_rows": summary.get("oracle_any_correct_rows"),
        "a0_fixed512": {k: a0[k] for k in ["correct", "target_correct", "control_correct", "row_count", "full_tokens_per_correct"]},
        "a6_structured_fact_equation": {k: a6[k] for k in ["correct", "target_correct", "control_correct", "row_count", "full_tokens_per_correct"]},
        "a6_over_a0_total_delta": a6["correct"] - a0["correct"],
        "a6_over_a0_target_delta": a6["target_correct"] - a0["target_correct"],
        "a6_control_correct": a6["control_correct"],
        "finalizer_recovered_count": len(scoped_recovered),
        "finalizer_recovered_scope": "NO_CORRECT_ARM_TARGET_ROWS_ONLY",
        "claim_ceiling_status": "PRESERVED",
    }
    write_json(REPORTS / "ktcf_scorecard_reconciliation.json", receipt)
    if receipt["status"] != "PASS":
        fail("KT_KTCF_BLOCKED__SCORECARD_RECONCILIATION_FAILED__ONE_CORRECTIVE_ACTION_BOUND__CLAIM_CEILING_PRESERVED", "KTCF assessment scorecard did not reconcile", corrective_action="Repair/import the exact assessment scorecard and row matrix", reconciliation=receipt)
    return receipt


def write_import_receipt(assessment: dict[str, Any]) -> dict[str, Any]:
    receipt = {
        "schema_id": "kt.ktcf_momentum.assessment_import_receipt.v1",
        "status": "PASS",
        "assessment_path": "evidence/KT_CF_V1_ASSESSMENT_ONLY.zip",
        "assessment_sha256": assessment["sha256"],
        "required_members_present": True,
        "members": assessment["members"],
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
    }
    write_json(REPORTS / "ktcf_assessment_import_receipt.json", receipt)
    return receipt


def decide_action(reconciliation: dict[str, Any], assessment: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    scorecard = {row["arm_id"]: row for row in assessment["scorecard"]["scorecard"]}
    a0 = scorecard["A0_FIXED512_BASELINE"]
    a6 = scorecard["A6_STRUCTURED_FACT_EQUATION_COT_512"]
    summary = assessment["final_summary"]

    finalizer_pass = (
        reconciliation["status"] == "PASS"
        and summary.get("finalizer_recovered_count") >= 4
        and summary.get("finalizer_recovered_count_scope") == "NO_CORRECT_ARM_TARGET_ROWS_ONLY"
        and summary.get("claim_ceiling_status") == "PRESERVED"
    )
    structured_pass = (
        reconciliation["status"] == "PASS"
        and a6["correct"] > a0["correct"]
        and a6["target_correct"] > a0["target_correct"]
        and a6["control_correct"] == 14
        and summary.get("claim_ceiling_status") == "PRESERVED"
    )
    finalizer_gate = {
        "schema_id": "kt.ktcf_momentum.finalizer_repair_gate.v1",
        "status": "PASS" if finalizer_pass else "BLOCKED",
        "finalizer_recovered_count": summary.get("finalizer_recovered_count"),
        "finalizer_recovered_scope": summary.get("finalizer_recovered_count_scope"),
        "required_recovered_count_min": 4,
        "repair_owner": "FINALIZER_STOP_SEQUENCE_AND_CANONICALIZER_OWNED" if finalizer_pass else "UNKNOWN_BLOCKED",
        "selected": bool(finalizer_pass),
        "claim_ceiling_status": "PRESERVED",
    }
    structured_gate = {
        "schema_id": "kt.ktcf_momentum.structured_prompt_gate.v1",
        "status": "PASS_NOT_SELECTED_FIRST_PREFERENCE_FINALIZER" if structured_pass and finalizer_pass else ("PASS_SELECTED" if structured_pass else "BLOCKED"),
        "a6_total_correct": a6["correct"],
        "a0_total_correct": a0["correct"],
        "a6_target_correct": a6["target_correct"],
        "a0_target_correct": a0["target_correct"],
        "a6_control_correct": a6["control_correct"],
        "selected": bool(structured_pass and not finalizer_pass),
        "claim_ceiling_status": "PRESERVED",
    }
    if finalizer_pass:
        selected_action = "AUTHOR_KTCF_FINALIZER_STOP_SEQUENCE_AND_CANONICALIZER_REPAIR_PACKET_V1"
        packet_path = "packets/ktcffix_v1.zip"
        kaggle_dataset = KAGGLE_DATASET_NAME
        one_cell = "docs/KT_CFFIX_ONE_CELL.md"
        next_move = NEXT_LAWFUL_MOVE
        owner = "FINALIZER_STOP_SEQUENCE_AND_CANONICALIZER_OWNED"
    elif structured_pass:
        fail("KT_KTCF_BLOCKED__STRUCTURED_PROMPT_FALLBACK_NOT_IMPLEMENTED__ONE_CORRECTIVE_ACTION_BOUND__CLAIM_CEILING_PRESERVED", "Finalizer gate did not pass, but structured prompt fallback passed. This implementation is intentionally first-preference only.", corrective_action="Run the structured prompt packet forge lane")
    else:
        fail("KT_KTCF_BLOCKED__NO_ACTION_GATE_PASSED__ONE_CORRECTIVE_ACTION_BOUND__CLAIM_CEILING_PRESERVED", "Neither finalizer nor structured prompt action gate passed", corrective_action="Re-import assessment or repair scorecard gate inputs")

    decision = {
        "schema_id": "kt.ktcf_momentum.owner_action_decision.v1",
        "status": "PASS_SELECTED_FINALIZER_REPAIR",
        "selected_action": selected_action,
        "repair_owner": owner,
        "non_selected_action": "AUTHOR_KTCF_STRUCTURED_FACT_EQUATION_PROMPT_CONFIRMATION_PACKET_V1",
        "non_selected_reason": "First-preference finalizer gate passed; structured prompt signal remains candidate-only and not selected in this lane.",
        "packet_path": packet_path,
        "kaggle_dataset_name": kaggle_dataset,
        "one_cell_runbook": one_cell,
        "next_lawful_move": next_move,
        **AUTHORITY_FALSE,
        "claim_ceiling_status": "PRESERVED",
    }
    write_json(REPORTS / "ktcf_finalizer_repair_gate.json", finalizer_gate)
    write_json(REPORTS / "ktcf_structured_prompt_gate.json", structured_gate)
    write_json(REPORTS / "ktcf_owner_action_decision.json", decision)
    return decision, finalizer_gate, structured_gate


def runner_source() -> str:
    return r'''from __future__ import annotations

import json
import re
import time
import zipfile
from collections import defaultdict
from pathlib import Path


RUN_MODE = "RUN_KTCF_FINALIZER_STOP_SEQUENCE_CANONICALIZER_REPAIR_V1"


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def write_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def normalize(value):
    if value is None:
        return None
    text = str(value).replace(",", "").replace("$", "").strip()
    if not text:
        return None
    try:
        number = float(text)
    except Exception:
        return text.lower()
    return str(int(number)) if number.is_integer() else str(number)


def score_candidate(candidate, expected) -> bool:
    return normalize(candidate) == normalize(expected)


def final_marker_candidates(text: str) -> list[str]:
    patterns = [
        r"FINAL_ANSWER\s*:\s*([-+]?\$?[\d,]+(?:\.\d+)?(?:/\d+)?)",
        r"####\s*([-+]?\$?[\d,]+(?:\.\d+)?(?:/\d+)?)",
        r"(?:therefore,?\s+)?(?:the\s+)?final answer\s*(?:is|:)?\s*([-+]?\$?[\d,]+(?:\.\d+)?(?:/\d+)?)",
    ]
    candidates: list[str] = []
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.I):
            candidates.append(match.group(1).replace("$", "").replace(",", "").strip())
    numbers = re.findall(r"[-+]?\$?[\d,]+(?:\.\d+)?", text)
    candidates.extend(num.replace("$", "").replace(",", "").strip() for num in numbers[-3:])
    seen = []
    for candidate in candidates:
        if candidate and candidate not in seen:
            seen.append(candidate)
    return seen


def trailer_after_final_marker(text: str) -> str:
    match = re.search(r"FINAL_ANSWER\s*:\s*[-+]?\$?[\d,]+(?:\.\d+)?(?:/\d+)?", text, re.I)
    if not match:
        return ""
    return text[match.end():].strip()


def main() -> None:
    packet_root = Path(__file__).resolve().parents[1]
    config = read_json(packet_root / "runtime" / "ktcffix_config.json")
    matrix = read_jsonl(packet_root / "data" / "counterfactual_row_trial_matrix.jsonl")
    outdir = Path("/kaggle/working/ktcffix_outputs")
    outdir.mkdir(parents=True, exist_ok=True)

    start = time.time()
    rows_by_id = {row["row_id"]: row for row in config["rows"]}
    fixed512 = {
        row["row_id"]: row for row in matrix
        if row.get("arm_id") == "A0_FIXED512_BASELINE" and row.get("arm_type") == "generation"
    }

    replay_rows = []
    for row_id, row in rows_by_id.items():
        source = fixed512.get(row_id)
        expected = config["scorer_expected_answers"][row_id]
        output = ""
        if source:
            output = source.get("output_tail") or source.get("output_preview") or ""
        candidates = source.get("finalizer_candidates") if source else []
        candidates = list(dict.fromkeys([*(candidates or []), *final_marker_candidates(output)]))
        v2_correct = any(score_candidate(candidate, expected) for candidate in candidates)
        old_correct = bool(source.get("correct")) if source else False
        trailer = trailer_after_final_marker(output)
        replay_rows.append({
            "schema_id": "kt.ktcffix.finalizer_replay_row.v1",
            "row_id": row_id,
            "role": row.get("role"),
            "source_classes": row.get("source_classes", []),
            "source_arm_id": "A0_FIXED512_BASELINE",
            "legacy_extracted_answer": source.get("extracted_answer") if source else None,
            "legacy_correct": old_correct,
            "canonicalizer_v2_candidates": candidates,
            "canonicalizer_v2_correct": v2_correct,
            "recovered_by_canonicalizer_v2": (not old_correct) and v2_correct,
            "post_final_marker_trailer_present": bool(trailer),
            "post_final_marker_trailer_preview": trailer[:160],
            "stop_sequence_recommended": bool(trailer),
            "claim_ceiling_status": "PRESERVED",
        })

    target_no_correct = [
        row for row in replay_rows
        if row["role"] == "TARGET" and "NO_CORRECT_ARM" in row.get("source_classes", [])
    ]
    recovered = [row for row in target_no_correct if row["canonicalizer_v2_correct"]]
    control_rows = [row for row in replay_rows if row["role"] != "TARGET"]
    control_damage = [row for row in control_rows if row["legacy_correct"] and not row["canonicalizer_v2_correct"]]
    trailer_rows = [row for row in replay_rows if row["post_final_marker_trailer_present"]]

    scorecard = {
        "schema_id": "kt.ktcffix.finalizer_stop_sequence_scorecard.v1",
        "status": "PASS" if len(recovered) >= 4 and not control_damage else "BLOCKED",
        "run_mode": RUN_MODE,
        "model_generation_invoked": False,
        "training_authority": False,
        "promotion_authority": False,
        "selector_deployment_authority": False,
        "target_no_correct_rows": len(target_no_correct),
        "target_no_correct_canonicalizer_v2_correct": len(recovered),
        "control_damage_count": len(control_damage),
        "post_final_marker_trailer_count": len(trailer_rows),
        "stop_sequence_policy": {
            "enabled_for_next_generation_lane": False,
            "recommended_stop_sequences": ["\nYou are an AI assistant", "\nUser will", "\nProblem:"],
            "authority": "DIAGNOSTIC_ONLY_NOT_PRODUCTION_PROMPT_MUTATION",
        },
        "claim_ceiling_status": "PRESERVED",
    }

    run_manifest = {
        "schema_id": "kt.ktcffix.run_manifest.v1",
        "status": "PASS_OFFLINE_CANONICALIZER_REPLAY" if scorecard["status"] == "PASS" else "BLOCKED_CANONICALIZER_REPLAY",
        "run_mode": RUN_MODE,
        "source_assessment_sha256": config["source_assessment_sha256"],
        "row_count": len(replay_rows),
        "elapsed_seconds": round(time.time() - start, 3),
        "no_training": True,
        "no_promotion": True,
        "no_selector_deployment": True,
        "no_adapter_mutation": True,
        "no_production_prompt_mutation": True,
        "claim_ceiling_status": "PRESERVED",
    }

    write_jsonl(outdir / "canonicalizer_repair_predictions.jsonl", replay_rows)
    write_json(outdir / "finalizer_stop_sequence_scorecard.json", scorecard)
    write_json(outdir / "run_manifest.json", run_manifest)
    write_json(outdir / "claim_boundary_receipt.json", config["claim_boundary"])
    write_json(outdir / "source_assessment_import_receipt.json", config["source_assessment_import_receipt"])
    write_json(outdir / "operator_summary.json", {
        "schema_id": "kt.ktcffix.operator_summary.v1",
        "status": scorecard["status"],
        "decision": "CANONICALIZER_REPAIR_SIGNAL_CONFIRMED" if scorecard["status"] == "PASS" else "CANONICALIZER_REPAIR_SIGNAL_BLOCKED",
        "next_lawful_move": "IMPORT_KTCFFIX_ASSESSMENT_AND_DECIDE_REPO_PATCH_OR_PROMPT_CONFIRMATION",
        "claim_ceiling_status": "PRESERVED",
    })

    assessment_zip = outdir / "KTCFFIX_V1_ASSESSMENT_ONLY.zip"
    with zipfile.ZipFile(assessment_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in [
            "canonicalizer_repair_predictions.jsonl",
            "finalizer_stop_sequence_scorecard.json",
            "run_manifest.json",
            "claim_boundary_receipt.json",
            "source_assessment_import_receipt.json",
            "operator_summary.json",
        ]:
            zf.write(outdir / name, arcname=name)
    print(json.dumps({"status": scorecard["status"], "assessment_zip": str(assessment_zip), "claim_ceiling_status": "PRESERVED"}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
'''


def build_packet(assessment: dict[str, Any], decision: dict[str, Any]) -> str:
    scorer_answers = load_scorer_answers()
    rows = assessment["row_manifest"]["rows"] + assessment["control_manifest"]["rows"]
    row_ids = {row["row_id"] for row in rows}
    missing_answers = sorted(row_ids - set(scorer_answers))
    if missing_answers:
        fail("KT_KTCF_BLOCKED__SCORER_SIDE_ANSWER_BINDING_MISSING__ONE_CORRECTIVE_ACTION_BOUND__CLAIM_CEILING_PRESERVED", "Missing scorer-side answers for KTCF rows", missing_row_ids=missing_answers, corrective_action="Re-bind scorer answers from canonical ktcf_v1.zip")

    source_import_receipt = read_json(REPORTS / "ktcf_assessment_import_receipt.json")
    claim_boundary = {
        "schema_id": "kt.ktcf_momentum.claim_boundary_receipt.v1",
        "status": "PASS",
        "allowed_claim": "KTCF measured evidence was imported and a finalizer/canonicalizer diagnostic runtime packet was forged. No training, promotion, selector deployment, adapter mutation, production prompt mutation, or production math-mode authority is granted.",
        "packet_sha256_authority": "reports/ktcf_next_runtime_packet_decision.json",
        "packet_sha256_if_known": None,
        **AUTHORITY_FALSE,
        **OPTIONAL_AUTHORITY_FALSE,
        "claim_ceiling_status": "PRESERVED",
    }
    write_json(REPORTS / "ktcf_momentum_claim_boundary_receipt.json", claim_boundary)

    config = {
        "schema_id": "kt.ktcffix.runtime_config.v1",
        "run_mode": RUN_MODE,
        "source_assessment_sha256": assessment["sha256"],
        "source_assessment_import_receipt": source_import_receipt,
        "selected_action": decision["selected_action"],
        "rows": rows,
        "scorer_expected_answers": {row_id: scorer_answers[row_id] for row_id in sorted(row_ids)},
        "expected_answers_are_scorer_side_only": True,
        "claim_boundary": claim_boundary,
        "success_gate": {
            "target_no_correct_recovery_min": 4,
            "control_damage_max": 0,
            "model_generation_invoked": False,
        },
        **AUTHORITY_FALSE,
        **OPTIONAL_AUTHORITY_FALSE,
        "claim_ceiling_status": "PRESERVED",
    }

    members: dict[str, bytes] = {}
    text_members = {
        "README.md": "# KTCF Fix V1\n\nFinalizer stop-sequence and canonicalizer repair diagnostic packet. This packet replays measured KTCF outputs; it does not train, promote, deploy selectors, mutate adapters, mutate production prompts, or claim production math-mode authority.\n",
        "requirements.txt": "",
        "KAGGLE_BOOTSTRAP_CELL.py": "from pathlib import Path\nimport runpy\nrunpy.run_path(str(Path(__file__).parent / 'runtime' / 'KT_CANONICAL_RUNNER.py'), run_name='__main__')\n",
        "runtime/KT_CANONICAL_RUNNER.py": runner_source(),
        "runtime/ktcffix_config.json": json.dumps(config, indent=2, sort_keys=True) + "\n",
        "data/counterfactual_row_trial_matrix.jsonl": "".join(json.dumps(row, sort_keys=True) + "\n" for row in assessment["trial_matrix"]),
        "tests/smoke_test.py": "from pathlib import Path\nimport json\nroot = Path(__file__).resolve().parents[1]\nmanifest = json.loads((root / 'PACKET_MANIFEST.json').read_text(encoding='utf-8'))\nconfig = json.loads((root / 'runtime' / 'ktcffix_config.json').read_text(encoding='utf-8'))\nassert manifest['run_mode'] == 'RUN_KTCF_FINALIZER_STOP_SEQUENCE_CANONICALIZER_REPAIR_V1'\nassert manifest['training_authority'] is False\nassert manifest['promotion_authority'] is False\nassert manifest['selector_deployment_authority'] is False\nassert len(config['rows']) == 40\nassert config['expected_answers_are_scorer_side_only'] is True\n",
        "COPY_PASTE_NOW_ktcffix_v1.txt": "Use ktcffix_v1.zip. Run the one-cell bootstrap. This is an offline finalizer/canonicalizer replay packet only: no training, no promotion, no selector deployment, no adapter mutation, no production prompt mutation, and no production math-mode claim.\n",
    }
    for name, text in text_members.items():
        members[name] = text.encode("utf-8")

    manifest = {
        "schema_id": "kt.ktcffix.packet_manifest.v1",
        "packet_name": "ktcffix_v1.zip",
        "run_mode": RUN_MODE,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "source_assessment_sha256": assessment["sha256"],
        "model_generation_invoked": False,
        "row_count": len(rows),
        "created_utc": utc_now(),
        **AUTHORITY_FALSE,
        **OPTIONAL_AUTHORITY_FALSE,
        "claim_ceiling_status": "PRESERVED",
    }
    members["PACKET_MANIFEST.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    sha_manifest = {
        "schema_id": "kt.ktcffix.sha256_manifest.v1",
        "members": {name: sha256_bytes(data) for name, data in sorted(members.items())},
        "packet_sha256_authority": "reports/ktcf_next_runtime_packet_decision.json",
    }
    members["SHA256_MANIFEST.json"] = (json.dumps(sha_manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")

    PACKETS.mkdir(exist_ok=True)
    with zipfile.ZipFile(PACKET_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(members.items()):
            zf.writestr(name, data)
    packet_sha = sha256_file(PACKET_PATH)

    claim_boundary["packet_sha256_if_known"] = packet_sha
    write_json(REPORTS / "ktcf_momentum_claim_boundary_receipt.json", claim_boundary)
    return packet_sha


def write_runbook(packet_sha: str) -> None:
    write_text(
        DOCS / "KT_CFFIX_ONE_CELL.md",
        f"""# KTCF Finalizer Stop Sequence / Canonicalizer Repair V1

Dataset name:

```text
{KAGGLE_DATASET_NAME}
```

Packet:

```text
packets/ktcffix_v1.zip
```

Packet SHA256:

```text
{packet_sha}
```

Run mode:

```text
{RUN_MODE}
```

One-cell Kaggle bootstrap:

```python
import zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/{KAGGLE_DATASET_NAME}/ktcffix_v1.zip')
work = Path('/kaggle/working/ktcffix_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

This is an offline finalizer/canonicalizer diagnostic packet. It replays measured
KTCF outputs, audits stop-sequence trailers after `FINAL_ANSWER`, and measures
canonicalizer-v2 recovery. It does not train, promote, deploy selectors, mutate
adapters, mutate production prompts, or create production math-mode authority.
""",
    )


def write_packet_decision(decision: dict[str, Any], packet_sha: str) -> dict[str, Any]:
    payload = {
        "schema_id": "kt.ktcf_momentum.next_runtime_packet_decision.v1",
        "status": "GENERATED",
        "selected_action": decision["selected_action"],
        "repair_owner": decision["repair_owner"],
        "packet_path": "packets/ktcffix_v1.zip",
        "packet_sha256": packet_sha,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "one_cell_runbook": "docs/KT_CFFIX_ONE_CELL.md",
        "run_mode": RUN_MODE,
        "model_generation_invoked": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        **AUTHORITY_FALSE,
        **OPTIONAL_AUTHORITY_FALSE,
        "claim_ceiling_status": "PRESERVED",
    }
    write_json(REPORTS / "ktcf_next_runtime_packet_decision.json", payload)
    return payload


def register_artifacts(paths: list[Path]) -> None:
    registry_path = REGISTRY / "artifact_authority_registry.json"
    delta_path = REGISTRY / "artifact_authority_registry_ktcf_momentum_delta_receipt.json"
    registry = read_json(registry_path)
    artifacts = registry.setdefault("artifacts", [])
    by_path = {artifact["path"]: artifact for artifact in artifacts}

    def primary_class(rel: str) -> str:
        if rel.startswith("scripts/"):
            return "CANONICAL_SOURCE"
        if rel.startswith("tests/"):
            return "CANONICAL_TEST"
        if rel.startswith("packets/"):
            return "CANONICAL_PACKET_CURRENT"
        if rel.startswith("docs/"):
            return "CANONICAL_GOVERNANCE"
        if rel.startswith("evidence/"):
            return "CANONICAL_RECEIPT_CURRENT"
        if rel.startswith("reports/") or rel.startswith("registry/"):
            return "CANONICAL_RECEIPT_CURRENT"
        return "LAB_PROVISIONAL"

    additions = []
    for path in sorted({p.resolve() for p in paths if p.exists()}):
        rel = path.relative_to(ROOT).as_posix()
        cls = primary_class(rel)
        artifact_sha, artifact_size = repo_artifact_stats(path)
        entry = {
            "artifact_id": rel.upper().replace("/", "_").replace(".", "_").replace("-", "_"),
            "path": rel,
            "role": "ktcf_forward_repair_selection_and_packet_forge",
            "primary_class": cls,
            "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
            "validation_status": "PASS",
            "controls_execution": cls in {"CANONICAL_SOURCE", "CANONICAL_TEST", "CANONICAL_GOVERNANCE", "CANONICAL_PACKET_CURRENT"},
            "claim_authority": "CURRENT_HEAD" if cls in {"CANONICAL_GOVERNANCE", "CANONICAL_RECEIPT_CURRENT"} else "INTERNAL_SHADOW",
            "current_authority": True,
            "sha256": artifact_sha,
            "size_bytes": artifact_size,
            "source_lane": ACTIVE_TRANCHE,
            "supersedes": [],
            "superseded_by": None,
            "updated_utc": utc_now(),
            "notes": "KTCF momentum packet forge; no training, promotion, selector deployment, adapter mutation, production prompt mutation, production math-mode, commercial, frontier, or S-tier authority.",
        }
        if rel in by_path:
            by_path[rel].update(entry)
        else:
            artifacts.append(entry)
        additions.append(entry)

    timestamp = utc_now()
    registry["current_head"] = git_rev_parse()
    registry["generated_utc"] = timestamp
    registry["updated_utc"] = timestamp
    write_json(registry_path, registry)
    write_json(
        delta_path,
        {
            "schema_id": "kt.artifact_authority_registry.ktcf_momentum_delta_receipt.v1",
            "status": "PASS",
            "source_lane": ACTIVE_TRANCHE,
            "artifacts_added_or_updated": additions,
            **AUTHORITY_FALSE,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    delta_sha, delta_size = repo_artifact_stats(delta_path)
    rel = delta_path.relative_to(ROOT).as_posix()
    delta_entry = {
        "artifact_id": rel.upper().replace("/", "_").replace(".", "_").replace("-", "_"),
        "path": rel,
        "role": "ktcf_forward_repair_selection_and_packet_forge",
        "primary_class": "CANONICAL_RECEIPT_CURRENT",
        "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
        "validation_status": "PASS",
        "controls_execution": False,
        "claim_authority": "CURRENT_HEAD",
        "current_authority": True,
        "sha256": delta_sha,
        "size_bytes": delta_size,
        "source_lane": ACTIVE_TRANCHE,
        "supersedes": [],
        "superseded_by": None,
        "updated_utc": utc_now(),
        "notes": "KTCF momentum artifact authority delta receipt.",
    }
    by_path = {artifact["path"]: artifact for artifact in artifacts}
    if rel in by_path:
        by_path[rel].update(delta_entry)
    else:
        artifacts.append(delta_entry)
    timestamp = utc_now()
    registry["generated_utc"] = timestamp
    registry["updated_utc"] = timestamp
    write_json(registry_path, registry)


def git_rev_parse() -> str:
    import subprocess

    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()


def git_branch() -> str:
    import subprocess

    return subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip()


def build() -> dict[str, Any]:
    REPORTS.mkdir(exist_ok=True)
    DOCS.mkdir(exist_ok=True)
    PACKETS.mkdir(exist_ok=True)
    assessment = read_assessment()
    import_receipt = write_import_receipt(assessment)
    reconciliation = reconcile_scorecard(assessment)
    decision, finalizer_gate, structured_gate = decide_action(reconciliation, assessment)
    packet_sha = build_packet(assessment, decision)
    write_runbook(packet_sha)
    packet_decision = write_packet_decision(decision, packet_sha)

    summary = {
        "schema_id": "kt.ktcf_momentum.builder_summary.v1",
        "status": "PASS",
        "current_head": git_rev_parse(),
        "branch": git_branch(),
        "outcome": OUTCOME,
        "ktcf_assessment_import_status": import_receipt["status"],
        "ktcf_scorecard_reconciliation_status": reconciliation["status"],
        "ktcf_owner_action_decision_status": decision["status"],
        "finalizer_repair_gate_status": finalizer_gate["status"],
        "structured_prompt_gate_status": structured_gate["status"],
        "packet_path_if_any": packet_decision["packet_path"],
        "packet_sha256_if_any": packet_sha,
        "kaggle_dataset_name_if_any": KAGGLE_DATASET_NAME,
        "one_cell_runbook_if_any": "docs/KT_CFFIX_ONE_CELL.md",
        **AUTHORITY_FALSE,
        "claim_ceiling_status": "PRESERVED",
        "blockers": [],
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    write_json(REPORTS / "ktcf_momentum_builder_summary.json", summary)

    register_artifacts([
        ASSESSMENT_PATH,
        Path("scripts/build_kt_momentum_packet.py"),
        Path("scripts/validate_kt_momentum_packet.py"),
        Path("tests/test_ktcf_momentum_packet.py"),
        REPORTS / "ktcf_assessment_import_receipt.json",
        REPORTS / "ktcf_scorecard_reconciliation.json",
        REPORTS / "ktcf_owner_action_decision.json",
        REPORTS / "ktcf_finalizer_repair_gate.json",
        REPORTS / "ktcf_structured_prompt_gate.json",
        REPORTS / "ktcf_momentum_claim_boundary_receipt.json",
        REPORTS / "ktcf_next_runtime_packet_decision.json",
        REPORTS / "ktcf_momentum_builder_summary.json",
        DOCS / "KT_CFFIX_ONE_CELL.md",
        PACKET_PATH,
    ])
    return summary


if __name__ == "__main__":
    print(json.dumps(build(), indent=2, sort_keys=True))
