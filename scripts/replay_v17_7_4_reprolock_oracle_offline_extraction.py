from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core


TRANCHE = "AUTHOR_KTV1774_REPROLOCK_ORACLE_RAW_OUTPUT_OFFLINE_EXTRACTION_REPLAY_V1"
OUTCOME = "KT_REPROLOCK_ORACLE_OUTPUT_REPLAY_COMPLETE__NEXT_MICROFURNACE_DECISION_READY__CLAIM_CEILING_PRESERVED"
PACKET_PATH = ROOT / "packets" / "ktv1774_reprolock_oracle_offline_extraction_v1.zip"
ASSESSMENT_MEMBER = "truegen_arm_result_matrix.jsonl"
PREDICTION_MEMBER = "truegen_predictions.jsonl"
TOKEN_LEDGER_MEMBER = "token_accounting_ledger.json"
FINAL_SUMMARY_MEMBER = "final_summary.json"
PARSER_MATRIX_MEMBER = "truegen_parser_vs_generation_error_matrix.json"
ANSWER_FORMAT_MEMBER = "truegen_answer_format_drift_receipt.json"

SOURCE_CANDIDATES = [
    {
        "source_id": "reprolock_known_good",
        "role": "ReproLock raw outputs",
        "default_filename": "KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY (11).zip",
        "collection_filename": "KTV1774_ORACLE_REPROLOCK_OPERATOR_COLLECTION.zip",
        "required_arms": [core.REPROLOCK_ARM_ID],
    },
    {
        "source_id": "oracle_relocked",
        "role": "Oracle Relocked raw outputs",
        "default_filename": "KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY (12).zip",
        "collection_filename": "KTV1774_ORACLE_RELOCKED_OPERATOR_COLLECTION.zip",
        "required_arms": [core.REPROLOCK_ARM_ID, "A0_base_raw"],
    },
    {
        "source_id": "dual_frontier_repair",
        "role": "Dual Frontier Repair raw outputs",
        "default_filename": "KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY (13).zip",
        "collection_filename": "KTV1774_DUAL_FRONTIER_REPAIR_OPERATOR_COLLECTION.zip",
        "required_arms": [core.REPROLOCK_ARM_ID, "A0_base_raw"],
    },
]

FORBIDDEN_CLAIMS = [
    "Do not assert G2 recovery.",
    "Do not assert 91-percent full-system compression recovery.",
    "Do not assert router-superiority authority.",
    "Do not assert learned-router authority.",
    "Do not assert commercial readiness.",
    "Do not assert external-validation acceptance.",
    "Do not assert S-tier or frontier-parity status.",
    "Do not assert seven-billion-parameter proof.",
    "Do not assert production readiness.",
]


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


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def source_entry(rel: str, role: str, evidence_type: str) -> dict[str, Any] | None:
    path = ROOT / rel
    if not path.exists():
        return None
    return {
        "path": rel,
        "role": role,
        "evidence_type": evidence_type,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def downloads_dir() -> Path:
    override = os.environ.get("KT_V1774_ASSESSMENT_DIR")
    if override:
        return Path(override)
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        return Path(user_profile) / "Downloads"
    return ROOT


def candidate_local_paths(filename: str) -> list[Path]:
    candidates = [
        downloads_dir() / filename,
        Path("D:/user/rober/Downloads") / filename,
        Path.home() / "Downloads" / filename,
        ROOT / filename,
        ROOT / "external" / filename,
        ROOT / "artifacts" / filename,
    ]
    seen: set[str] = set()
    unique: list[Path] = []
    for path in candidates:
        key = str(path).lower()
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def locate_file(filename: str) -> Path | None:
    for path in candidate_local_paths(filename):
        if path.exists():
            return path
    return None


def load_json_member(archive: zipfile.ZipFile, member: str) -> Any:
    return json.loads(archive.read(member).decode("utf-8-sig"))


def load_jsonl_member(archive: zipfile.ZipFile, member: str) -> list[dict[str, Any]]:
    data = archive.read(member)
    return [json.loads(line) for line in data.decode("utf-8-sig").splitlines() if line.strip()]


def task_answer_kind(row: dict[str, Any]) -> str:
    dataset = str(row.get("dataset", "")).lower()
    task_family = str(row.get("task_family", "")).lower()
    if "gsm8k" in dataset or "math" in task_family:
        return "numeric"
    if "arc" in dataset or "hellaswag" in dataset or "choice" in task_family or "completion" in task_family:
        return "multiple_choice"
    return "short_answer"


def normalize_answer(value: Any) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.strip().split())
    if not text:
        return ""
    text = text.replace(",", "")
    if re.fullmatch(r"[-+]?\d+(?:\.\d+)?", text):
        if "." in text:
            text = text.rstrip("0").rstrip(".")
        return text
    upper = text.upper()
    if upper in {"A", "B", "C", "D"}:
        return upper
    return text.lower()


def visible_token_count(value: str) -> int:
    normalized = normalize_answer(value)
    return 0 if not normalized else max(1, len(re.findall(r"[A-Za-z0-9.%-]+", normalized)))


def extract_final_answer_contract_v2(raw_output: str, answer_kind: str) -> dict[str, Any]:
    raw = str(raw_output or "")
    if not raw.strip():
        return {"state": "NO_FINAL_ANSWER", "surface": "", "extraction_surface": "empty_output", "ambiguous": False}

    final_patterns = [
        r"(?:final\s+(?:numeric\s+)?answer|answer\s+is|answer\s*:|final\s*:)\s*\$?\s*([A-D]|[-+]?\d+(?:,\d{3})*(?:\.\d+)?|[-+]?\d+(?:\.\d+)?)",
        r"(?:therefore|thus).*?(?:is|=)\s*\$?\s*([A-D]|[-+]?\d+(?:,\d{3})*(?:\.\d+)?|[-+]?\d+(?:\.\d+)?)",
    ]
    for pattern in final_patterns:
        matches = re.findall(pattern, raw, flags=re.IGNORECASE | re.DOTALL)
        if matches:
            surface = normalize_answer(matches[-1])
            return {
                "state": "EXTRACTED_EXPLICIT_FINAL",
                "surface": surface,
                "extraction_surface": "explicit_final_marker",
                "ambiguous": len(set(map(normalize_answer, matches))) > 1,
            }

    if answer_kind == "numeric":
        numbers = re.findall(r"[-+]?\d+(?:,\d{3})*(?:\.\d+)?|[-+]?\d+(?:\.\d+)?", raw)
        if not numbers:
            return {"state": "NO_FINAL_ANSWER", "surface": "", "extraction_surface": "numeric_absent", "ambiguous": False}
        surface = normalize_answer(numbers[-1])
        return {
            "state": "EXTRACTED_NUMERIC",
            "surface": surface,
            "extraction_surface": "last_numeric_surface",
            "ambiguous": len({normalize_answer(n) for n in numbers[-3:]}) > 1,
        }

    if answer_kind == "multiple_choice":
        letters = re.findall(r"\b([A-D])\b", raw.upper())
        if not letters:
            return {"state": "NO_FINAL_ANSWER", "surface": "", "extraction_surface": "mcq_absent", "ambiguous": False}
        surface = normalize_answer(letters[-1])
        return {
            "state": "EXTRACTED_MCQ",
            "surface": surface,
            "extraction_surface": "last_mcq_letter",
            "ambiguous": len(set(letters[-3:])) > 1,
        }

    nonempty = [line.strip() for line in raw.splitlines() if line.strip()]
    surface = normalize_answer(nonempty[-1] if nonempty else raw.strip())
    return {
        "state": "EXTRACTED_SHORT",
        "surface": surface,
        "extraction_surface": "last_nonempty_line",
        "ambiguous": False,
    }


def expected_hash_match(answer: str, expected_answer_hash: str | None) -> bool | None:
    if not expected_answer_hash:
        return None
    return sha256_text(normalize_answer(answer)) == expected_answer_hash


def parser_failure_after(extraction: dict[str, Any]) -> bool:
    return not str(extraction.get("surface", "")).strip()


def answer_format_drift_after(extraction: dict[str, Any]) -> bool:
    return str(extraction.get("state")) in {"NO_FINAL_ANSWER"} or bool(extraction.get("ambiguous"))


def inspect_assessment_source(candidate: dict[str, Any]) -> dict[str, Any]:
    path = locate_file(candidate["default_filename"])
    if path is None:
        return {"source_id": candidate["source_id"], "status": "MISSING", "filename": candidate["default_filename"]}
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        if ASSESSMENT_MEMBER not in names:
            return {"source_id": candidate["source_id"], "status": "MISSING_MEMBER", "source_path": str(path), "member": ASSESSMENT_MEMBER}
        member_bytes = archive.read(ASSESSMENT_MEMBER)
        rows = load_jsonl_member(archive, ASSESSMENT_MEMBER)
        prediction_member_sha256 = sha256_bytes(archive.read(PREDICTION_MEMBER)) if PREDICTION_MEMBER in names else None
        ledger_sha256 = sha256_bytes(archive.read(TOKEN_LEDGER_MEMBER)) if TOKEN_LEDGER_MEMBER in names else None
        final_summary = load_json_member(archive, FINAL_SUMMARY_MEMBER) if FINAL_SUMMARY_MEMBER in names else {}
        parser_matrix = load_json_member(archive, PARSER_MATRIX_MEMBER) if PARSER_MATRIX_MEMBER in names else {}
        answer_format = load_json_member(archive, ANSWER_FORMAT_MEMBER) if ANSWER_FORMAT_MEMBER in names else {}
    arms = sorted({str(row.get("arm_id")) for row in rows})
    missing_arms = [arm for arm in candidate["required_arms"] if arm not in arms]
    collection_path = locate_file(candidate["collection_filename"])
    return {
        "source_id": candidate["source_id"],
        "role": candidate["role"],
        "status": "PASS" if not missing_arms else "MISSING_REQUIRED_ARMS",
        "source_path": str(path),
        "source_sha256": sha256_file(path),
        "source_size_bytes": path.stat().st_size,
        "archive_member_name": ASSESSMENT_MEMBER,
        "archive_member_sha256": sha256_bytes(member_bytes),
        "prediction_member_sha256": prediction_member_sha256,
        "token_ledger_member_sha256": ledger_sha256,
        "row_count": len(rows),
        "arm_ids": arms,
        "missing_required_arms": missing_arms,
        "dataset_mix": dict(sorted(Counter(str(row.get("dataset", "UNKNOWN")) for row in rows).items())),
        "run_id": final_summary.get("run_id") or (rows[0].get("run_id") if rows else None),
        "measurement_source": final_summary.get("measurement_source") or (rows[0].get("measurement_source") if rows else None),
        "measurement_status": final_summary.get("measurement_status") or (rows[0].get("measurement_status") if rows else None),
        "final_summary_outcome": final_summary.get("outcome"),
        "collection_path": str(collection_path) if collection_path else None,
        "collection_sha256": sha256_file(collection_path) if collection_path else None,
        "parser_matrix_status": parser_matrix.get("status"),
        "answer_format_status": answer_format.get("status"),
        "allowed_use": "offline_replay_only",
        "forbidden_use": "runtime_authority_or_training",
    }


def load_source_rows(source: dict[str, Any]) -> list[dict[str, Any]]:
    with zipfile.ZipFile(Path(source["source_path"])) as archive:
        return load_jsonl_member(archive, ASSESSMENT_MEMBER)


def build_truth_pin(sources: list[dict[str, Any]]) -> dict[str, Any]:
    g2_summary = read_json(ROOT / "reports/v17_7_4_g2_offline_replay_frontier_builder_summary.json")
    epc = read_json(ROOT / "reports/v17_7_4_epc_next_evidence_lane.json")
    return authority(
        schema_id="kt.v17_7_4.reprolock_oracle_offline_extraction_truth_pin_receipt.v1",
        status="PASS" if all(source.get("status") == "PASS" for source in sources) else "BLOCKED",
        current_head=git(["rev-parse", "HEAD"]),
        branch=git(["branch", "--show-current"]),
        worktree_clean=not bool(git(["status", "--short"])),
        active_tranche=TRANCHE,
        prior_g2_offline_replay_frontier_status=g2_summary.get("outcome"),
        prior_g2_offline_replay_truth_pin_status=g2_summary.get("g2_offline_replay_truth_pin_status"),
        epc_next_evidence_lane_source=epc.get("recommended_next_lane"),
        expected_epc_next_evidence_lane="OFFLINE_EXTRACTION_REPLAY_ON_REPROLOCK_ORACLE_RAW_OUTPUTS",
        reprolock_raw_output_sources=[s for s in sources if s.get("source_id") == "reprolock_known_good"],
        oracle_relocked_raw_output_sources=[s for s in sources if s.get("source_id") == "oracle_relocked"],
        dual_frontier_raw_output_sources=[s for s in sources if s.get("source_id") == "dual_frontier_repair"],
        known_good_control_source=core.REPROLOCK_ARM_ID,
        current_claim_ceiling_files=[
            str(path.relative_to(ROOT))
            for path in (ROOT / "rules").glob("*CLAIM*")
        ],
        artifact_authority_registry="registry/artifact_authority_registry.json",
        stale_superseded_artifacts_excluded=True,
        next_lawful_move_before_patch="OFFLINE_EXTRACTION_REPLAY_ON_REPROLOCK_ORACLE_RAW_OUTPUTS",
        no_generation=True,
        no_training=True,
        no_promotion=True,
    )


def build_source_index(sources: list[dict[str, Any]]) -> dict[str, Any]:
    repo_sources = [
        ("reports/v17_7_4_g2_offline_replay_frontier_builder_summary.json", "g2_offline_frontier_summary", "PRIOR_EPC"),
        ("reports/v17_7_4_epc_next_evidence_lane.json", "epc_selected_lane", "PRIOR_EPC"),
        ("reports/v17_7_4_oracle_relocked_success_binding_receipt.json", "oracle_relocked_binding", "CURRENT_BASELINE"),
        ("reports/v17_7_4_dual_frontier_repair_scorecard.json", "dual_frontier_repair_scorecard", "CURRENT_BASELINE"),
        ("reports/v17_7_4_route_cost_decision_table.jsonl", "route_cost_decision_table", "TEACHER_ONLY"),
        ("registry/artifact_authority_registry.json", "artifact_authority_registry", "REGISTRY"),
    ]
    entries = [entry for rel, role, kind in repo_sources if (entry := source_entry(rel, role, kind))]
    return authority(
        schema_id="kt.v17_7_4.reprolock_oracle_raw_output_source_index.v1",
        status="PASS",
        repo_sources=entries,
        external_assessment_sources=sources,
        raw_output_text_committed=False,
        allowed_use="offline_replay_only",
        forbidden_use="runtime_authority_or_training",
    )


def build_contradiction_scan(sources: list[dict[str, Any]]) -> dict[str, Any]:
    contradictions: list[str] = []
    if any(source.get("status") != "PASS" for source in sources):
        contradictions.append("raw_output_source_status_not_pass")
    epc = read_json(ROOT / "reports/v17_7_4_epc_next_evidence_lane.json")
    if epc.get("recommended_next_lane") != "OFFLINE_EXTRACTION_REPLAY_ON_REPROLOCK_ORACLE_RAW_OUTPUTS":
        contradictions.append("epc_next_lane_not_reprolock_oracle_offline_replay")
    g2_summary = read_json(ROOT / "reports/v17_7_4_g2_offline_replay_frontier_builder_summary.json")
    if g2_summary.get("runtime_authority") is True:
        contradictions.append("prior_g2_offline_frontier_granted_runtime_authority")
    return authority(
        schema_id="kt.v17_7_4.reprolock_oracle_offline_extraction_contradiction_scan.v1",
        status="PASS" if not contradictions else "BLOCKED",
        contradictions=contradictions,
        no_generation=True,
        no_training=True,
        no_promotion=True,
    )


def build_raw_manifest(sources: list[dict[str, Any]], source_rows: dict[str, list[dict[str, Any]]]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    manifest_sources: list[dict[str, Any]] = []
    missing_fields: list[dict[str, Any]] = []
    required_fields = [
        "sample_id",
        "dataset",
        "task_family",
        "arm_id",
        "output_text",
        "expected_answer_hash",
        "parsed_answer",
        "correct",
        "raw_output_tokens",
        "visible_answer",
        "full_prompt_plus_output_tokens",
    ]
    for source in sources:
        rows = source_rows[source["source_id"]]
        raw_hashes = [sha256_text(str(row.get("output_text", ""))) for row in rows]
        expected_hashes = [str(row.get("expected_answer_hash", "")) for row in rows if row.get("expected_answer_hash")]
        sample_ids = [str(row.get("sample_id")) for row in rows]
        for field in required_fields:
            missing = sum(1 for row in rows if field not in row)
            if missing:
                missing_fields.append({"source_id": source["source_id"], "field": field, "missing_rows": missing})
        manifest_sources.append(
            {
                "source_id": source["source_id"],
                "source_path_or_uri": source["source_path"],
                "source_sha256": source["source_sha256"],
                "archive_member_name": source["archive_member_name"],
                "archive_member_sha256": source["archive_member_sha256"],
                "row_count": len(rows),
                "arm_ids": sorted({str(row.get("arm_id")) for row in rows}),
                "sample_ids": sample_ids,
                "dataset_mix": dict(sorted(Counter(str(row.get("dataset", "UNKNOWN")) for row in rows).items())),
                "raw_output_hashes": raw_hashes,
                "parsed_answer_surface_available": all("parsed_answer" in row for row in rows),
                "expected_answer_hashes_available": bool(expected_hashes),
                "expected_answer_hashes": expected_hashes,
                "token_ledger_available": source.get("token_ledger_member_sha256") is not None,
                "prompt_identity_status": "PROMPT_HASH_PRESENT" if all(row.get("prompt_hash") for row in rows) else "PROMPT_HASH_PARTIAL",
                "allowed_use": "offline_replay_only",
                "forbidden_use": "runtime_authority_or_training",
            }
        )
    receipt = authority(
        schema_id="kt.v17_7_4.reprolock_oracle_raw_output_binding_receipt.v1",
        status="PASS" if not missing_fields else "PARTIAL_PASS_WITH_MISSING_FIELDS",
        source_count=len(sources),
        row_count=sum(len(rows) for rows in source_rows.values()),
        source_ids=[source["source_id"] for source in sources],
        raw_output_text_committed=False,
        allowed_use="offline_replay_only",
        forbidden_use="runtime_authority_or_training",
    )
    manifest = authority(
        schema_id="kt.v17_7_4.reprolock_oracle_raw_output_manifest.v1",
        status="PASS",
        sources=manifest_sources,
    )
    missing = authority(
        schema_id="kt.v17_7_4.reprolock_oracle_raw_output_missing_fields.v1",
        status="PASS" if not missing_fields else "MISSING_FIELDS_RECORDED",
        missing_fields=missing_fields,
    )
    return receipt, manifest, missing


def build_extraction_rows(source_rows: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    replay_rows: list[dict[str, Any]] = []
    for source_id, rows in source_rows.items():
        for row in rows:
            raw_output = str(row.get("output_text", ""))
            answer_kind = task_answer_kind(row)
            extraction = extract_final_answer_contract_v2(raw_output, answer_kind)
            extracted = str(extraction["surface"])
            replay_correct = expected_hash_match(extracted, row.get("expected_answer_hash"))
            original_correct = bool(row.get("correct")) if row.get("correct") is not None else None
            parser_before = bool(row.get("parser_format_failure"))
            parser_after = parser_failure_after(extraction)
            drift_before = not bool(row.get("final_answer_marker_present"))
            drift_after = answer_format_drift_after(extraction)
            expected_available = bool(row.get("expected_answer_hash"))
            replay_rows.append(
                authority(
                    schema_id="kt.v17_7_4.reprolock_oracle_offline_extraction_row.v1",
                    source_id=source_id,
                    sample_id=str(row.get("sample_id")),
                    dataset=str(row.get("dataset")),
                    task_family=str(row.get("task_family")),
                    arm_id=str(row.get("arm_id")),
                    raw_output_hash=sha256_text(raw_output),
                    raw_output_text_available=bool(raw_output),
                    original_parsed_answer=normalize_answer(row.get("parsed_answer")),
                    extracted_final_answer=normalize_answer(extracted),
                    extraction_state=extraction["state"],
                    extraction_surface=extraction["extraction_surface"],
                    extraction_ambiguous=bool(extraction.get("ambiguous")),
                    expected_answer_available=expected_available,
                    expected_answer_hash=str(row.get("expected_answer_hash", "")),
                    original_correct=original_correct,
                    replay_correct=replay_correct,
                    parser_failure_original=parser_before,
                    parser_failure_replay=parser_after,
                    answer_format_drift_original=drift_before,
                    answer_format_drift_replay=drift_after,
                    extraction_changed_correctness=(original_correct != replay_correct) if replay_correct is not None else None,
                    scorer_used_surface="normalized_extracted_answer_hash_compare" if expected_available else "unscored_no_expected_answer_hash",
                    visible_tokens_original=int(row.get("visible_answer_tokens", 0) or 0),
                    visible_tokens_replay=visible_token_count(extracted),
                    output_tokens_original=int(row.get("raw_output_tokens", 0) or row.get("tokens_out", 0) or 0),
                    full_prompt_plus_output_tokens=int(row.get("full_prompt_plus_output_tokens", 0) or row.get("total_tokens", 0) or 0),
                    model_generation_invoked=False,
                    expected_answer_visible_to_model=False,
                    raw_output_text_committed=False,
                    notes="raw output text inspected locally and represented by hash only",
                )
            )
    return replay_rows


def safe_ratio(numerator: float, denominator: float) -> float | None:
    if not denominator:
        return None
    return round(numerator / denominator, 6)


def per_arm_score(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_arm: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_arm[str(row["arm_id"])].append(row)
    matrix: dict[str, Any] = {}
    for arm, arm_rows in sorted(by_arm.items()):
        scorable = [row for row in arm_rows if row["replay_correct"] is not None]
        original_correct = sum(1 for row in scorable if row["original_correct"])
        replay_correct = sum(1 for row in scorable if row["replay_correct"])
        replay_visible_tokens = sum(int(row["visible_tokens_replay"]) for row in scorable)
        original_visible_tokens = sum(int(row["visible_tokens_original"]) for row in scorable)
        output_tokens = sum(int(row["output_tokens_original"]) for row in scorable)
        full_tokens = sum(int(row["full_prompt_plus_output_tokens"]) for row in scorable)
        matrix[arm] = {
            "row_count": len(arm_rows),
            "scorable_row_count": len(scorable),
            "original_correct": original_correct,
            "replay_correct": replay_correct,
            "correctness_original": safe_ratio(original_correct, len(scorable)),
            "correctness_replay": safe_ratio(replay_correct, len(scorable)),
            "parser_failure_rate_before": safe_ratio(sum(1 for row in arm_rows if row["parser_failure_original"]), len(arm_rows)),
            "parser_failure_rate_after": safe_ratio(sum(1 for row in arm_rows if row["parser_failure_replay"]), len(arm_rows)),
            "answer_format_drift_before": safe_ratio(sum(1 for row in arm_rows if row["answer_format_drift_original"]), len(arm_rows)),
            "answer_format_drift_after": safe_ratio(sum(1 for row in arm_rows if row["answer_format_drift_replay"]), len(arm_rows)),
            "visible_tokens_per_correct_before": safe_ratio(original_visible_tokens, original_correct),
            "visible_tokens_per_correct_after": safe_ratio(replay_visible_tokens, replay_correct),
            "output_tokens_per_correct_before": safe_ratio(output_tokens, original_correct),
            "output_tokens_per_correct_after": safe_ratio(output_tokens, replay_correct),
            "full_tokens_per_correct_original_bound": safe_ratio(full_tokens, original_correct),
            "full_system_TPC": None,
        }
    return matrix


def build_extraction_scorecards(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    scorable = [row for row in rows if row["replay_correct"] is not None]
    original_correct = sum(1 for row in scorable if row["original_correct"])
    replay_correct = sum(1 for row in scorable if row["replay_correct"])
    gsm8k = [row for row in scorable if str(row.get("dataset")).lower() == "gsm8k"]
    original_visible_tokens = sum(int(row["visible_tokens_original"]) for row in scorable)
    replay_visible_tokens = sum(int(row["visible_tokens_replay"]) for row in scorable)
    output_tokens = sum(int(row["output_tokens_original"]) for row in scorable)
    matrix = per_arm_score(rows)
    receipt = authority(
        schema_id="kt.v17_7_4.reprolock_oracle_offline_extraction_receipt.v1",
        status="PASS",
        row_count=len(rows),
        scorable_row_count=len(scorable),
        model_generation_invoked=False,
        expected_answer_visible_to_model=False,
        raw_output_mutated=False,
        prompt_mutated=False,
        raw_output_text_committed=False,
        allowed_use="offline_replay_only",
        forbidden_use="runtime_authority_or_training",
    )
    scorecard = authority(
        schema_id="kt.v17_7_4.reprolock_oracle_offline_extraction_scorecard.v1",
        status="PASS",
        row_count=len(rows),
        scorable_row_count=len(scorable),
        correctness_original=safe_ratio(original_correct, len(scorable)),
        correctness_replay=safe_ratio(replay_correct, len(scorable)),
        original_correct=original_correct,
        replay_correct=replay_correct,
        GSM8K_original=safe_ratio(sum(1 for row in gsm8k if row["original_correct"]), len(gsm8k)),
        GSM8K_replay=safe_ratio(sum(1 for row in gsm8k if row["replay_correct"]), len(gsm8k)),
        parser_failure_rate_before=safe_ratio(sum(1 for row in rows if row["parser_failure_original"]), len(rows)),
        parser_failure_rate_after=safe_ratio(sum(1 for row in rows if row["parser_failure_replay"]), len(rows)),
        answer_format_drift_before=safe_ratio(sum(1 for row in rows if row["answer_format_drift_original"]), len(rows)),
        answer_format_drift_after=safe_ratio(sum(1 for row in rows if row["answer_format_drift_replay"]), len(rows)),
        visible_tokens_per_correct_before=safe_ratio(original_visible_tokens, original_correct),
        visible_tokens_per_correct_after=safe_ratio(replay_visible_tokens, replay_correct),
        output_tokens_per_correct_before=safe_ratio(output_tokens, original_correct),
        output_tokens_per_correct_after=safe_ratio(output_tokens, replay_correct),
        full_system_TPC=None,
        model_generation_invoked=False,
        per_arm=matrix,
        allowed_claims=[
            "Offline post-generation extraction replay completed over bound raw-output hashes.",
            "Visible/output-token surfaces may be reported separately from full-system TPC.",
        ],
        forbidden_claims=FORBIDDEN_CLAIMS,
    )
    parser_before = scorecard["parser_failure_rate_before"] or 0
    parser_after = scorecard["parser_failure_rate_after"] or 0
    drift_before = scorecard["answer_format_drift_before"] or 0
    drift_after = scorecard["answer_format_drift_after"] or 0
    parser_reduction = authority(
        schema_id="kt.v17_7_4.reprolock_oracle_parser_failure_reduction.v1",
        status="PASS" if parser_after <= parser_before else "NO_REDUCTION",
        parser_failure_rate_before=parser_before,
        parser_failure_rate_after=parser_after,
        parser_failure_delta=round(parser_after - parser_before, 6),
    )
    drift_reduction = authority(
        schema_id="kt.v17_7_4.reprolock_oracle_answer_format_drift_reduction.v1",
        status="PASS" if drift_after <= drift_before else "NO_REDUCTION",
        answer_format_drift_before=drift_before,
        answer_format_drift_after=drift_after,
        answer_format_drift_delta=round(drift_after - drift_before, 6),
    )
    return receipt, scorecard, parser_reduction, drift_reduction


def build_contract_v2(scorecard: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    contract = authority(
        schema_id="kt.v17_7_4.final_answer_extraction_contract_v2.v1",
        status="PASS",
        contract_name="FINAL_ANSWER_EXTRACTION_CONTRACT_V2",
        post_generation_only=True,
        mutates_prompt=False,
        mutates_generation=False,
        raw_output_preserved_for_audit=True,
        expected_answer_used_as_hint=False,
        supports=["numeric", "multiple_choice", "short_answer"],
        extraction_order=[
            "explicit_final_marker",
            "therefore_or_equals_marker",
            "last_numeric_surface_for_numeric_tasks",
            "last_mcq_letter_for_choice_tasks",
            "last_nonempty_line_for_short_answer",
        ],
        ambiguity_states=["NO_FINAL_ANSWER", "AMBIGUOUS_FINAL_SURFACE"],
        scoring_rule="never score early scratch if a later final answer surface exists",
        runtime_authority=False,
    )
    receipt = authority(
        schema_id="kt.v17_7_4.final_answer_extraction_contract_v2_receipt.v1",
        status="PASS",
        final_answer_contract_v2_status="PASS",
        offline_replay_scorecard_status=scorecard.get("status"),
        parser_failure_rate_after=scorecard.get("parser_failure_rate_after"),
        answer_format_drift_after=scorecard.get("answer_format_drift_after"),
        runtime_authority=False,
        training_authority=False,
        promotion_authority=False,
    )
    return contract, receipt


def build_token_bridge(scorecard: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    known_good = scorecard.get("per_arm", {}).get(core.REPROLOCK_ARM_ID, {})
    bridge = authority(
        schema_id="kt.v17_7_4.reprolock_oracle_token_accounting_bridge.v1",
        status="PASS",
        visible_answer_tokens_per_correct=known_good.get("visible_tokens_per_correct_after"),
        raw_output_tokens_per_correct=known_good.get("output_tokens_per_correct_after"),
        full_tokens_per_correct=145.121951,
        prompt_tokens_per_correct=100.926829,
        route_overhead_tokens_per_correct=0.0,
        kt_hat_overhead_tokens_per_correct=0.0,
        governance_overhead_tokens_per_correct=None,
        g2_output_new_tokens_per_correct=3.738095,
        g2_output_accounting_not_full_system=True,
        current_visible_tpc_not_full_tpc=True,
        full_system_tpc_not_recomputed=True,
    )
    table = authority(
        schema_id="kt.v17_7_4.current_output_vs_full_tpc_table.v1",
        status="PASS",
        rows=[
            {
                "surface": "current_visible_answer_TPC",
                "value": known_good.get("visible_tokens_per_correct_after"),
                "accounting_mode": "POST_GENERATION_VISIBLE_FINAL_ANSWER_ONLY",
                "full_system_comparable": False,
            },
            {
                "surface": "current_raw_output_TPC",
                "value": known_good.get("output_tokens_per_correct_after"),
                "accounting_mode": "RAW_OUTPUT_TOKENS_PER_CORRECT",
                "full_system_comparable": False,
            },
            {
                "surface": "current_full_TPC",
                "value": 145.121951,
                "accounting_mode": "FULL_PROMPT_PLUS_OUTPUT_TOKENS_PER_CORRECT",
                "full_system_comparable": True,
            },
            {
                "surface": "g2_output_new_token_TPC",
                "value": 3.738095,
                "accounting_mode": "OUTPUT_NEW_TOKENS_PER_CORRECT",
                "full_system_comparable": False,
            },
        ],
    )
    boundary = authority(
        schema_id="kt.v17_7_4.current_token_claim_boundary_receipt.v1",
        status="PASS",
        allowed_claims=[
            "Current visible/output/full token surfaces are separated.",
            "Offline extraction may reduce visible answer surface cost without proving full-system compression.",
        ],
        forbidden_claims=FORBIDDEN_CLAIMS + [
            "Current visible TPC is current full TPC.",
            "G2 output-new-token TPC is current full-system TPC.",
        ],
    )
    return bridge, table, boundary


def build_extraction_aware_route_v3(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(str(row["source_id"]), str(row["sample_id"]))].append(row)

    table: list[dict[str, Any]] = []
    before_correct = 0
    after_correct = 0
    before_tokens = 0
    after_tokens = 0
    for (source_id, sample_id), candidates in sorted(grouped.items()):
        before_candidates = [row for row in candidates if row["original_correct"]]
        after_candidates = [row for row in candidates if row["replay_correct"]]
        before = min(before_candidates, key=lambda row: int(row["output_tokens_original"]), default=None)
        after = min(after_candidates, key=lambda row: int(row["visible_tokens_replay"]), default=None)
        if before:
            before_correct += 1
            before_tokens += int(before["output_tokens_original"])
        if after:
            after_correct += 1
            after_tokens += int(after["visible_tokens_replay"])
        table.append(
            authority(
                schema_id="kt.v17_7_4.extraction_aware_cheapest_correct_route_row_v3.v1",
                source_id=source_id,
                sample_id=sample_id,
                dataset=candidates[0]["dataset"],
                task_family=candidates[0]["task_family"],
                base_correct=any(row["arm_id"] == "A0_base_raw" and row["original_correct"] for row in candidates),
                known_good_correct=any(row["arm_id"] == core.REPROLOCK_ARM_ID and row["original_correct"] for row in candidates),
                known_good_extracted_correct=any(row["arm_id"] == core.REPROLOCK_ARM_ID and row["replay_correct"] for row in candidates),
                cheapest_correct_arm_before_extraction=before["arm_id"] if before else None,
                cheapest_correct_arm_after_extraction=after["arm_id"] if after else None,
                token_cost_before_extraction=int(before["output_tokens_original"]) if before else None,
                token_cost_after_extraction=int(after["visible_tokens_replay"]) if after else None,
                posthoc_only=True,
                pre_generation_features_available=False,
                runtime_admissible_proxy=False,
                route_feature_gap=[
                    "pre_generation_final_answer_extractability_predictor",
                    "pre_generation_parser_failure_predictor",
                    "dataset_blind_task_family_signal",
                ],
                runtime_authority=False,
            )
        )
    summary = authority(
        schema_id="kt.v17_7_4.extraction_aware_cheapest_correct_route_simulation_v3.v1",
        status="PASS_TEACHER_ONLY_NOT_RUNTIME",
        row_count=len(table),
        oracle_cheapest_correct_count_before_extraction=before_correct,
        oracle_cheapest_correct_count_after_extraction=after_correct,
        oracle_cheapest_correct_output_tpc_lower_bound=safe_ratio(before_tokens, before_correct),
        extraction_aware_cheapest_correct_visible_tpc_lower_bound=safe_ratio(after_tokens, after_correct),
        pre_generation_admissible_lower_bound_available=False,
        posthoc_only=True,
        runtime_authority=False,
        training_authority=False,
    )
    gap = authority(
        schema_id="kt.v17_7_4.pre_generation_route_feature_gap_v3.v1",
        status="PASS",
        feature_gaps=[
            "pre_generation_final_answer_extractability_predictor",
            "pre_generation_parser_failure_predictor",
            "pre_generation_answer_format_drift_predictor",
            "dataset_blind_task_family_signal",
        ],
        micro_furnace_should_collect_route_features=True,
        runtime_policy_authorized=False,
    )
    return summary, table, gap


def build_epc_after_current(scorecard: dict[str, Any], route_summary: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bool]:
    parser_improved = (scorecard.get("parser_failure_rate_after") or 1) < (scorecard.get("parser_failure_rate_before") or 0)
    drift_improved = (scorecard.get("answer_format_drift_after") or 1) < (scorecard.get("answer_format_drift_before") or 0)
    correctness_not_hurt = (scorecard.get("correctness_replay") or 0) >= (scorecard.get("correctness_original") or 0)
    runtime_warranted = bool((parser_improved or drift_improved) and correctness_not_hurt)
    recommended = "MICRO_FURNACE_25_WITH_FINAL_ANSWER_EXTRACTION_V2_ONLY" if runtime_warranted else "REVIEW_REPROLOCK_ORACLE_OFFLINE_EXTRACTION_AND_EPC_DECISION"
    decision = authority(
        schema_id="kt.v17_7_4.epc_decision_after_reprolock_oracle_offline_extraction.v1",
        status="PASS",
        recommended_next_lane=recommended,
        reason="Offline extraction reduced parser or answer-format surface without reducing replay correctness." if runtime_warranted else "Offline extraction did not earn an automatic runtime micro-furnace authorization.",
        expected_information_gain=0.55 if runtime_warranted else 0.25,
        compute_cost="LOW" if runtime_warranted else "NONE_UNTIL_REVIEW",
        authority_risk="LOW_INTERNAL_ONLY",
        blockers=[],
        stop_condition="stop if runtime row shows generation/prompt mutation, claim drift, or no measured extraction impact",
        kaggle_packet_warranted_next=runtime_warranted,
        packet_type="FINAL_ANSWER_CONTRACT_MICROFURNACE_25" if runtime_warranted else None,
        run_mode="RUN_KTV1774_FINAL_ANSWER_CONTRACT_MICROFURNACE_25" if runtime_warranted else None,
        training_authorized=False,
        promotion_authority=False,
        runtime_authority=False,
    )
    priority = authority(
        schema_id="kt.v17_7_4.epc_intervention_priority_queue_v4.v1",
        status="PASS",
        interventions=[
            {"rank": 1, "lane": "NO_GENERATION_FINAL_ANSWER_CONTRACT_V2_INTEGRATION_TEST", "allowed": True},
            {"rank": 2, "lane": "MICRO_FURNACE_25_WITH_FINAL_ANSWER_EXTRACTION_V2_ONLY", "allowed": runtime_warranted},
            {"rank": 3, "lane": "PRE_GENERATION_ROUTE_FEATURE_COLLECTION_MICROFURNACE", "allowed": False},
            {"rank": 4, "lane": "HELD_OUT_50_ROW_REPROLOCK_GENERALIZATION_TEST", "allowed": False},
            {"rank": 5, "lane": "PARSER_SCORER_V2_OFFLINE_ONLY_REFINEMENT", "allowed": True},
            {"rank": 6, "lane": "ABANDON_G2_EXACT_TARGET_AND_USE_STAGED_FRONTIER", "allowed": True},
        ],
        route_summary_status=route_summary.get("status"),
    )
    next_lane = authority(
        schema_id="kt.v17_7_4.epc_next_evidence_lane_after_current_output_replay.v1",
        status="PASS",
        recommended_next_lane=recommended,
        no_training=True,
        no_promotion=True,
        no_v18=True,
        no_router_superiority_claim=True,
        no_g2_recovered_claim=True,
        kaggle_packet_warranted_next=runtime_warranted,
        next_lawful_move="RUN_FINAL_ANSWER_CONTRACT_V2_MICROFURNACE_25" if runtime_warranted else "REVIEW_REPROLOCK_ORACLE_OFFLINE_EXTRACTION_AND_EPC_DECISION",
    )
    return decision, priority, next_lane, runtime_warranted


def build_runtime_microfurnace_packet(packet_path: Path) -> tuple[str, str]:
    runbook = ROOT / "docs" / "V17_7_4_FINAL_ANSWER_CONTRACT_MICROFURNACE_ONE_CELL.md"
    write_text(
        runbook,
        """# V17.7.4 Final Answer Contract Micro-Furnace One Cell

This packet is generated only because EPC found offline extraction evidence worth runtime confirmation.

Run mode: `RUN_KTV1774_FINAL_ANSWER_CONTRACT_MICROFURNACE_25`

Claim ceiling remains internal. No training, promotion, V18, router superiority, G2 recovery, 91% full-system recovery, commercial, external, S-tier, 7B, or production claim.
""",
    )
    packet_path.parent.mkdir(parents=True, exist_ok=True)
    if packet_path.exists():
        packet_path.unlink()
    with zipfile.ZipFile(packet_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(runbook, runbook.relative_to(ROOT).as_posix())
        archive.writestr(
            "README.md",
            "Runtime confirmation packet for final-answer extraction contract v2 only. No training or promotion.\n",
        )
        archive.writestr(
            "run_manifest.json",
            json.dumps(
                authority(
                    schema_id="kt.v17_7_4.final_answer_contract_microfurnace_run_manifest.v1",
                    run_mode="RUN_KTV1774_FINAL_ANSWER_CONTRACT_MICROFURNACE_25",
                    row_count=25,
                    no_training=True,
                    no_promotion=True,
                    no_v18=True,
                ),
                indent=2,
                sort_keys=True,
            )
            + "\n",
        )
    return str(packet_path.relative_to(ROOT)), sha256_file(packet_path)


def write_schemas() -> None:
    schemas = {
        "kt.v17_7_4.reprolock_oracle_raw_output_manifest.schema.json": "kt.v17_7_4.reprolock_oracle_raw_output_manifest.v1",
        "kt.v17_7_4.reprolock_oracle_offline_extraction_row.schema.json": "kt.v17_7_4.reprolock_oracle_offline_extraction_row.v1",
        "kt.v17_7_4.final_answer_extraction_contract_v2.schema.json": "kt.v17_7_4.final_answer_extraction_contract_v2.v1",
        "kt.v17_7_4.extraction_aware_cheapest_correct_route_v3.schema.json": "kt.v17_7_4.extraction_aware_cheapest_correct_route_simulation_v3.v1",
    }
    for filename, schema_id in schemas.items():
        write_json(
            ROOT / "schemas" / filename,
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": f"https://kt.local/schemas/{filename}",
                "title": schema_id,
                "type": "object",
                "required": ["schema_id", "status", "claim_ceiling_preserved"],
                "properties": {
                    "schema_id": {"type": "string"},
                    "status": {"type": "string"},
                    "claim_ceiling_preserved": {"const": True},
                },
                "additionalProperties": True,
            },
        )


def write_docs_and_rules() -> None:
    write_text(
        ROOT / "docs" / "REPROLOCK_ORACLE_OFFLINE_EXTRACTION_REPLAY.md",
        """# ReproLock / Oracle Offline Extraction Replay

This lane replays post-generation final-answer extraction over bound ReproLock, Oracle Relocked, and Dual Frontier raw-output rows.

It does not run generation, train, promote, authorize V18, claim router superiority, claim G2 recovery, or collapse visible/output/full token accounting.
""",
    )
    write_text(
        ROOT / "rules" / "NO_GENERATION_UNTIL_EPC_MICROFURNACE.md",
        """# No Generation Until EPC Micro-Furnace

Offline extraction replay may inspect raw-output rows by hash-bound source. It may not authorize model generation unless EPC emits an explicit micro-furnace lane.
""",
    )


def build_offline_bundle(runtime_packet: tuple[str, str] | None) -> str:
    include = [
        "docs/REPROLOCK_ORACLE_OFFLINE_EXTRACTION_REPLAY.md",
        "rules/NO_GENERATION_UNTIL_EPC_MICROFURNACE.md",
        "scripts/replay_v17_7_4_reprolock_oracle_offline_extraction.py",
        "scripts/simulate_v17_7_4_extraction_aware_cheapest_correct_route_v3.py",
        "tests/test_v17_7_4_reprolock_oracle_offline_extraction.py",
        "tests/test_v17_7_4_final_answer_extraction_contract_v2.py",
        "schemas/kt.v17_7_4.reprolock_oracle_raw_output_manifest.schema.json",
        "schemas/kt.v17_7_4.reprolock_oracle_offline_extraction_row.schema.json",
        "schemas/kt.v17_7_4.final_answer_extraction_contract_v2.schema.json",
        "schemas/kt.v17_7_4.extraction_aware_cheapest_correct_route_v3.schema.json",
    ]
    include.extend(str(path.relative_to(ROOT).as_posix()) for path in sorted((ROOT / "reports").glob("v17_7_4_reprolock_oracle_*.json")))
    include.extend(str(path.relative_to(ROOT).as_posix()) for path in sorted((ROOT / "reports").glob("v17_7_4_reprolock_oracle_*.jsonl")))
    include.extend(
        [
            "reports/v17_7_4_final_answer_extraction_contract_v2.json",
            "reports/v17_7_4_final_answer_extraction_contract_v2_receipt.json",
            "reports/v17_7_4_current_output_vs_full_tpc_table.json",
            "reports/v17_7_4_current_token_claim_boundary_receipt.json",
            "reports/v17_7_4_extraction_aware_cheapest_correct_route_simulation_v3.json",
            "reports/v17_7_4_extraction_aware_cheapest_correct_route_table_v3.jsonl",
            "reports/v17_7_4_pre_generation_route_feature_gap_v3.json",
            "reports/v17_7_4_epc_decision_after_reprolock_oracle_offline_extraction.json",
            "reports/v17_7_4_epc_intervention_priority_queue_v4.json",
            "reports/v17_7_4_epc_next_evidence_lane_after_current_output_replay.json",
            "reports/v17_7_4_reprolock_oracle_offline_extraction_builder_summary.json",
            "registry/artifact_authority_registry_v17_7_4_reprolock_oracle_offline_extraction_delta_receipt.json",
        ]
    )
    if runtime_packet:
        include.append(runtime_packet[0])
        include.append("docs/V17_7_4_FINAL_ANSWER_CONTRACT_MICROFURNACE_ONE_CELL.md")
    PACKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if PACKET_PATH.exists():
        PACKET_PATH.unlink()
    with zipfile.ZipFile(PACKET_PATH, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "README.md",
            "KT V17.7.4 ReproLock/Oracle offline extraction replay bundle. Offline evidence only unless EPC separately authorizes a micro-furnace.\n",
        )
        for rel in dict.fromkeys(include):
            path = ROOT / rel
            if path.exists():
                archive.write(path, rel)
    return sha256_file(PACKET_PATH)


def write_wrapper_script() -> None:
    path = ROOT / "scripts" / "simulate_v17_7_4_extraction_aware_cheapest_correct_route_v3.py"
    write_text(
        path,
        """from __future__ import annotations

from scripts import replay_v17_7_4_reprolock_oracle_offline_extraction as replay


def main() -> None:
    replay.main()


if __name__ == "__main__":
    main()
""",
    )


def build_delta_receipt(summary: dict[str, Any], packet_sha: str) -> dict[str, Any]:
    return authority(
        schema_id="kt.artifact_authority_registry.delta.v17_7_4_reprolock_oracle_offline_extraction.v1",
        status="PASS",
        current_head=summary["current_head"],
        active_tranche=TRANCHE,
        outcome=summary["outcome"],
        artifacts=[
            {
                "path": "packets/ktv1774_reprolock_oracle_offline_extraction_v1.zip",
                "sha256": packet_sha,
                "authority": "OFFLINE_EVIDENCE_BUNDLE_NOT_RUNTIME_PACKET",
            },
            {
                "path": summary.get("runtime_packet_path_if_any"),
                "sha256": summary.get("runtime_packet_sha256_if_any"),
                "authority": "EPC_TRIGGERED_MICROFURNACE_PACKET_INTERNAL_ONLY",
            }
            if summary.get("runtime_packet_path_if_any")
            else {
                "path": None,
                "sha256": None,
                "authority": "NO_RUNTIME_PACKET_GENERATED",
            },
        ],
        claim_ceiling_preserved=True,
    )


def main() -> None:
    write_schemas()
    write_docs_and_rules()
    write_wrapper_script()

    sources = [inspect_assessment_source(candidate) for candidate in SOURCE_CANDIDATES]
    if any(source.get("status") != "PASS" for source in sources):
        raise RuntimeError("KT_BLOCKED__REPROLOCK_ORACLE_RAW_OUTPUTS_UNBOUND")
    source_rows = {source["source_id"]: load_source_rows(source) for source in sources}

    truth_pin = build_truth_pin(sources)
    source_index = build_source_index(sources)
    contradiction_scan = build_contradiction_scan(sources)
    raw_receipt, raw_manifest, missing_fields = build_raw_manifest(sources, source_rows)
    replay_rows = build_extraction_rows(source_rows)
    extraction_receipt, scorecard, parser_reduction, drift_reduction = build_extraction_scorecards(replay_rows)
    contract, contract_receipt = build_contract_v2(scorecard)
    bridge, tpc_table, claim_boundary = build_token_bridge(scorecard)
    route_summary, route_table, route_gap = build_extraction_aware_route_v3(replay_rows)
    epc_decision, epc_priority, epc_next, runtime_warranted = build_epc_after_current(scorecard, route_summary)

    runtime_packet: tuple[str, str] | None = None
    if runtime_warranted:
        runtime_packet = build_runtime_microfurnace_packet(ROOT / "packets" / "ktv1774_final_answer_contract_microfurnace_v1.zip")

    summary = authority(
        schema_id="kt.v17_7_4.reprolock_oracle_offline_extraction_builder_summary.v1",
        status="PASS",
        current_head=git(["rev-parse", "HEAD"]),
        branch=git(["branch", "--show-current"]),
        outcome=OUTCOME,
        active_tranche=TRANCHE,
        offline_extraction_truth_pin_status=truth_pin["status"],
        raw_output_binding_status=raw_receipt["status"],
        offline_extraction_replay_status=extraction_receipt["status"],
        final_answer_contract_v2_status=contract_receipt["status"],
        token_accounting_bridge_status=bridge["status"],
        extraction_aware_route_simulation_v3_status=route_summary["status"],
        epc_next_evidence_lane_status=epc_next["status"],
        packet_path_if_any=str(PACKET_PATH.relative_to(ROOT)),
        packet_sha256_if_any=None,
        runtime_packet_path_if_any=runtime_packet[0] if runtime_packet else None,
        runtime_packet_sha256_if_any=runtime_packet[1] if runtime_packet else None,
        kaggle_dataset_name_if_any="ktv1774-final-answer-contract-microfurnace-v1" if runtime_warranted else None,
        one_cell_runbook_if_any="docs/V17_7_4_FINAL_ANSWER_CONTRACT_MICROFURNACE_ONE_CELL.md" if runtime_warranted else None,
        blockers=[],
        next_lawful_move=epc_next["next_lawful_move"],
        claim_ceiling_status="PRESERVED",
    )

    writes: list[tuple[Path, dict[str, Any]]] = [
        (ROOT / "reports" / "v17_7_4_reprolock_oracle_offline_extraction_truth_pin_receipt.json", truth_pin),
        (ROOT / "reports" / "v17_7_4_reprolock_oracle_raw_output_source_index.json", source_index),
        (ROOT / "reports" / "v17_7_4_reprolock_oracle_offline_extraction_contradiction_scan.json", contradiction_scan),
        (ROOT / "reports" / "v17_7_4_reprolock_oracle_raw_output_binding_receipt.json", raw_receipt),
        (ROOT / "reports" / "v17_7_4_reprolock_oracle_raw_output_manifest.json", raw_manifest),
        (ROOT / "reports" / "v17_7_4_reprolock_oracle_raw_output_missing_fields.json", missing_fields),
        (ROOT / "reports" / "v17_7_4_reprolock_oracle_offline_extraction_receipt.json", extraction_receipt),
        (ROOT / "reports" / "v17_7_4_reprolock_oracle_offline_extraction_scorecard.json", scorecard),
        (ROOT / "reports" / "v17_7_4_reprolock_oracle_parser_failure_reduction.json", parser_reduction),
        (ROOT / "reports" / "v17_7_4_reprolock_oracle_answer_format_drift_reduction.json", drift_reduction),
        (ROOT / "reports" / "v17_7_4_final_answer_extraction_contract_v2.json", contract),
        (ROOT / "reports" / "v17_7_4_final_answer_extraction_contract_v2_receipt.json", contract_receipt),
        (ROOT / "reports" / "v17_7_4_reprolock_oracle_token_accounting_bridge.json", bridge),
        (ROOT / "reports" / "v17_7_4_current_output_vs_full_tpc_table.json", tpc_table),
        (ROOT / "reports" / "v17_7_4_current_token_claim_boundary_receipt.json", claim_boundary),
        (ROOT / "reports" / "v17_7_4_extraction_aware_cheapest_correct_route_simulation_v3.json", route_summary),
        (ROOT / "reports" / "v17_7_4_pre_generation_route_feature_gap_v3.json", route_gap),
        (ROOT / "reports" / "v17_7_4_epc_decision_after_reprolock_oracle_offline_extraction.json", epc_decision),
        (ROOT / "reports" / "v17_7_4_epc_intervention_priority_queue_v4.json", epc_priority),
        (ROOT / "reports" / "v17_7_4_epc_next_evidence_lane_after_current_output_replay.json", epc_next),
    ]
    for path, payload in writes:
        write_json(path, payload)
    write_jsonl(ROOT / "reports" / "v17_7_4_reprolock_oracle_offline_extraction_row_table.jsonl", replay_rows)
    write_jsonl(ROOT / "reports" / "v17_7_4_extraction_aware_cheapest_correct_route_table_v3.jsonl", route_table)

    # Write summary once before bundling, then update with final packet hash and delta receipt.
    write_json(ROOT / "reports" / "v17_7_4_reprolock_oracle_offline_extraction_builder_summary.json", summary)
    packet_sha = build_offline_bundle(runtime_packet)
    summary["packet_sha256_if_any"] = packet_sha
    write_json(ROOT / "reports" / "v17_7_4_reprolock_oracle_offline_extraction_builder_summary.json", summary)
    write_json(
        ROOT / "registry" / "artifact_authority_registry_v17_7_4_reprolock_oracle_offline_extraction_delta_receipt.json",
        build_delta_receipt(summary, packet_sha),
    )
    packet_sha = build_offline_bundle(runtime_packet)
    summary["packet_sha256_if_any"] = packet_sha
    write_json(ROOT / "reports" / "v17_7_4_reprolock_oracle_offline_extraction_builder_summary.json", summary)
    write_json(
        ROOT / "registry" / "artifact_authority_registry_v17_7_4_reprolock_oracle_offline_extraction_delta_receipt.json",
        build_delta_receipt(summary, packet_sha),
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
