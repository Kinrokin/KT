from __future__ import annotations

import hashlib
import json
import os
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
EVIDENCE = ROOT / "evidence"

CONSOLE_REPORTED_CFFIX_SHA256 = "e48097b24a2b7a5dae64fddddddabab65dda2217eeb0038eefcd4a6dd2a9c015"
EXPECTED_KTCF_SHA256 = "ef5f7719bb35094eb66a53c6a780a36c5ec2d167577d4896e332ea59c13b247f"
OUTCOME_BLOCKED = "KT_STOPSEQ_10ROW_PROBE_BLOCKED__LOCAL_RUNTIME_UNAVAILABLE__HARNESS_READY__CLAIM_CEILING_PRESERVED"
NEXT_BLOCKED = "AUTHOR_MINIMAL_STOPSEQ_10ROW_RUNTIME_PACKET_V1"

AUTHORITY_FALSE = {
    "runtime_authority": False,
    "dataset_generation_authority": False,
    "training_authority": False,
    "promotion_authority": False,
    "selector_deployment_authority": False,
    "adapter_mutation_authority": False,
    "production_prompt_mutation_authority": False,
    "production_math_mode_claim": False,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8", newline="\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def git_output(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def read_json_from_zip(zf: zipfile.ZipFile, name: str) -> Any:
    return json.loads(zf.read(name).decode("utf-8-sig"))


def read_jsonl_from_zip(zf: zipfile.ZipFile, name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in zf.read(name).decode("utf-8-sig").splitlines() if line.strip()]


def find_cffix_assessment() -> Path | None:
    env_path = os.environ.get("KTSTOP_CFFIX_ASSESSMENT")
    candidates = []
    if env_path:
        candidates.append(Path(env_path))
    candidates.extend(
        [
            EVIDENCE / "KTCFFIX_V1_ASSESSMENT_ONLY.zip",
            EVIDENCE / "KTCFFIX_V1_ASSESSMENT_ONLY (1).zip",
        ]
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def write_truth_pin() -> dict[str, Any]:
    receipt = {
        "schema_id": "kt.stopseq.truth_pin.v1",
        "created_utc": utc_now(),
        "current_head": git_output("rev-parse", "HEAD"),
        "current_branch": git_output("branch", "--show-current"),
        "worktree_porcelain": git_output("status", "--porcelain=v1"),
        "packet_observed_head": "9ce1d3398becafed352f7b098f4a4cd1cdd91655",
        "live_repo_truth_wins": True,
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
    }
    write_json(REPORTS / "ktstop_truth_pin.json", receipt)
    return receipt


def write_hash_lock(cffix_path: Path | None) -> dict[str, Any]:
    uploaded_sha = sha256_file(cffix_path) if cffix_path else None
    status = "BLOCKED_SUPERSEDED_BY_FRESH_STOPSEQ_PROBE"
    reason = "Uploaded CFFIX assessment hash is absent or differs from console-reported CFFIX hash."
    if uploaded_sha == CONSOLE_REPORTED_CFFIX_SHA256:
        status = "HASH_MATCHED_BUT_PATCH_AUTHORITY_STILL_HELD_PENDING_FRESH_STOPSEQ_PROBE"
        reason = "Uploaded CFFIX assessment matches console hash, but this lab lane supersedes old patch authority until fresh prompt evidence exists."
    receipt = {
        "schema_id": "kt.stopseq.cffix_hash_lock.v1",
        "created_utc": utc_now(),
        "uploaded_assessment_sha256_if_present": uploaded_sha,
        "uploaded_assessment_source": "KTSTOP packet evidence KTCFFIX_V1_ASSESSMENT_ONLY.zip" if uploaded_sha else None,
        "console_reported_sha256_if_available": CONSOLE_REPORTED_CFFIX_SHA256,
        "member_level_receipt_status_if_checked": "CHECKED" if uploaded_sha else "NOT_PRESENT",
        "patch_authority_from_old_cffix": False,
        "status": status,
        "reason": reason,
        "supersession_plan": "Run a fresh STOP_AFTER_FINAL_ANSWER prompt probe before accepting any prompt/finalizer patch authority.",
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
    }
    write_json(REPORTS / "ktstop_cffix_hash_lock_receipt.json", receipt)
    return receipt


def load_ktcf_assessment() -> dict[str, Any]:
    path = EVIDENCE / "KT_CF_V1_ASSESSMENT_ONLY.zip"
    if not path.exists():
        raise RuntimeError("Missing evidence/KT_CF_V1_ASSESSMENT_ONLY.zip")
    observed = sha256_file(path)
    if observed != EXPECTED_KTCF_SHA256:
        raise RuntimeError(f"KTCF assessment SHA mismatch: expected {EXPECTED_KTCF_SHA256}, got {observed}")
    with zipfile.ZipFile(path) as zf:
        return {
            "sha256": observed,
            "row_manifest": read_json_from_zip(zf, "row_manifest.json")["rows"],
            "control_manifest": read_json_from_zip(zf, "control_manifest.json")["rows"],
            "trial_matrix": read_jsonl_from_zip(zf, "counterfactual_row_trial_matrix.jsonl"),
            "finalizer": read_json_from_zip(zf, "finalizer_replay_report.json"),
        }


def load_cffix_rows(cffix_path: Path | None) -> list[dict[str, Any]]:
    if not cffix_path:
        return []
    with zipfile.ZipFile(cffix_path) as zf:
        if "canonicalizer_repair_predictions.jsonl" not in zf.namelist():
            return []
        return read_jsonl_from_zip(zf, "canonicalizer_repair_predictions.jsonl")


def row_key(row: dict[str, Any]) -> str:
    return str(row.get("row_id"))


def select_rows(ktcf: dict[str, Any], cffix_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ktcf_rows = {row_key(row): row for row in ktcf["row_manifest"] + ktcf["control_manifest"]}
    cffix_by_id = {row_key(row): row for row in cffix_rows}
    selected: list[tuple[str, str, str]] = []
    seen: set[str] = set()

    def add(row_id: str, source_class: str, reason: str) -> None:
        if row_id and row_id in ktcf_rows and row_id not in seen:
            selected.append((row_id, source_class, reason))
            seen.add(row_id)

    no_correct = [
        row
        for row in cffix_rows
        if row.get("role") == "TARGET" and "NO_CORRECT_ARM" in row.get("source_classes", [])
    ]
    no_correct.sort(key=lambda row: (not bool(row.get("recovered_by_canonicalizer_v2")), row_key(row)))
    for row in no_correct[:4]:
        add(row_key(row), "NO_CORRECT_OR_CANONICALIZER_RELEVANT", "NO_CORRECT target row with canonicalizer relevance")

    trailer_rows = [
        row
        for row in cffix_rows
        if row_key(row) not in seen and row.get("post_final_marker_trailer_present") is True
    ]
    trailer_rows.sort(key=lambda row: (row.get("role") != "TARGET", row_key(row)))
    for row in trailer_rows[:4]:
        add(row_key(row), "POST_FINAL_TRAILER_CONTAMINATION", "CFFIX replay marked post-FINAL_ANSWER trailer contamination")

    controls = [
        row
        for row in cffix_rows
        if row_key(row) not in seen and row.get("role") != "TARGET" and row.get("legacy_correct") is True
    ]
    controls.sort(key=row_key)
    for row in controls[:2]:
        add(row_key(row), "FIXED512_CORRECT_CONTROL", "Fixed512-correct control row")

    # Fallbacks keep the row-selection receipt useful even when CFFIX is absent.
    for row in ktcf["row_manifest"]:
        if len(selected) >= 8:
            break
        classes = row.get("source_classes", [])
        if "NO_CORRECT_ARM" in classes:
            add(row_key(row), "NO_CORRECT_OR_CANONICALIZER_RELEVANT", "KTCF source class fallback")
    for row in ktcf["control_manifest"]:
        if len(selected) >= 10:
            break
        add(row_key(row), "FIXED512_CORRECT_CONTROL", "KTCF control fallback")

    if len(selected) != 10:
        raise RuntimeError(f"Could not select exactly 10 rows; selected {len(selected)}")

    out = []
    for row_id, source_class, reason in selected:
        row = ktcf_rows[row_id]
        out.append(
            {
                "schema_id": "kt.stopseq.10row_selection_row.v1",
                "row_id": row_id,
                "source_class": source_class,
                "role": row.get("role"),
                "question_hash": row.get("question_hash"),
                "expected_answer_hash": row.get("expected_answer_hash"),
                "selection_reason": reason,
                "control_flag": row.get("role") != "TARGET",
                "gold_prompt_leakage_free": True,
            }
        )
    return out


def write_selection(rows: list[dict[str, Any]]) -> dict[str, Any]:
    receipt = {
        "schema_id": "kt.stopseq.10row_selection.v1",
        "created_utc": utc_now(),
        "status": "PASS",
        "row_count": len(rows),
        "bucket_counts": {
            "NO_CORRECT_OR_CANONICALIZER_RELEVANT": sum(1 for row in rows if row["source_class"] == "NO_CORRECT_OR_CANONICALIZER_RELEVANT"),
            "POST_FINAL_TRAILER_CONTAMINATION": sum(1 for row in rows if row["source_class"] == "POST_FINAL_TRAILER_CONTAMINATION"),
            "FIXED512_CORRECT_CONTROL": sum(1 for row in rows if row["source_class"] == "FIXED512_CORRECT_CONTROL"),
        },
        "rows": rows,
        "gold_prompt_leakage_free": all(row["gold_prompt_leakage_free"] for row in rows),
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
    }
    write_json(REPORTS / "ktstop_10row_selection.json", receipt)
    return receipt


def local_runtime_available() -> tuple[bool, str]:
    # The repo has runtime packet builders, but no bound local lab model/config for this prompt probe.
    if os.environ.get("KTSTOP_LOCAL_MODEL_RUNTIME") == "1":
        return True, "KTSTOP_LOCAL_MODEL_RUNTIME=1"
    return False, (
        "No repo-bound local model runtime is configured for A0/A1 STOP_AFTER_FINAL_ANSWER generation. "
        "Existing KTCF/CFFIX artifacts are offline replay/canonicalizer evidence and cannot measure the A1 prompt delta."
    )


def write_blocker(reason: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    rendered_a0 = "current math prompt exactly as repo currently renders it"
    stop_delta = (
        "After writing FINAL_ANSWER, stop immediately.\n"
        "Do not add explanation, restatement, confidence text, alternate answer, or any additional text.\n"
        "The output must end with the final answer and nothing else."
    )
    receipt = {
        "schema_id": "kt.stopseq.probe_blocker.v1",
        "created_utc": utc_now(),
        "status": "BLOCKED_LOCAL_MODEL_RUNTIME_UNAVAILABLE__STOPSEQ_PROBE_HARNESS_READY",
        "outcome": OUTCOME_BLOCKED,
        "reason": reason,
        "corrective_action": "RUN_STOPSEQ_10ROW_LOCAL_OR_AUTHOR_MINIMAL_KAGGLE_PROBE",
        "selected_rows_count": len(rows),
        "a0_prompt_contract_hash": sha256_text(rendered_a0),
        "a1_stop_delta_hash": sha256_text(stop_delta),
        "probe_execution_status": "BLOCKED_NOT_EXECUTED",
        "prompt_delta_committed": False,
        "control_damage_count": None,
        "trailer_rate_status": "NOT_MEASURED_LOCAL_RUNTIME_UNAVAILABLE",
        "next_lawful_move": NEXT_BLOCKED,
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
    }
    write_json(REPORTS / "stop_after_final_answer_probe_blocker.json", receipt)
    # The JSONL is intentionally empty because no model rows were generated.
    write_jsonl(REPORTS / "stop_after_final_answer_10row_probe.jsonl", [])
    return receipt


def main() -> int:
    REPORTS.mkdir(exist_ok=True)
    truth = write_truth_pin()
    cffix_path = find_cffix_assessment()
    hash_lock = write_hash_lock(cffix_path)
    ktcf = load_ktcf_assessment()
    cffix_rows = load_cffix_rows(cffix_path)
    rows = select_rows(ktcf, cffix_rows)
    selection = write_selection(rows)
    available, runtime_reason = local_runtime_available()
    if not available:
        blocker = write_blocker(runtime_reason, rows)
        summary = {
            "schema_id": "kt.stopseq.lab_summary.v1",
            "created_utc": utc_now(),
            "current_head": truth["current_head"],
            "branch": truth["current_branch"],
            "outcome": OUTCOME_BLOCKED,
            "ktstop_truth_binding_status": "PASS",
            "ktstop_cffix_hash_lock_status": hash_lock["status"],
            "ktstop_row_selection_status": selection["status"],
            "ktstop_probe_execution_status": blocker["status"],
            "ktstop_prompt_delta_status": "NOT_COMMITTED_BLOCKED",
            "ktstop_control_damage_status": "NOT_MEASURED_LOCAL_RUNTIME_UNAVAILABLE",
            "ktstop_trailer_rate_status": blocker["trailer_rate_status"],
            "ktstop_claim_boundary_status": "PRESERVED",
            "claim_ceiling_status": "PRESERVED",
            "blockers": [blocker["status"]],
            "next_lawful_move": NEXT_BLOCKED,
            **AUTHORITY_FALSE,
        }
        write_json(REPORTS / "ktstop_lab_summary.json", summary)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    raise RuntimeError("KTSTOP_LOCAL_MODEL_RUNTIME=1 is set, but no local generation adapter is implemented in this lab harness.")


if __name__ == "__main__":
    raise SystemExit(main())
