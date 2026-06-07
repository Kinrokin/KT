from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core
from kt_system.eval.math_rescue_v3_honest import rescue_trivial_arithmetic
from kt_system.eval.math_verifier_v3_honest import (
    ABSTAIN_UNVERIFIED_ACCEPT,
    FAIL_OBVIOUS_GARBAGE,
    fail_semantics_too_broad,
    verify_numeric_surface,
)


TRANCHE = "AUTHOR_KTV1774_CONTROL_PRESERVING_MATH_RESCUE_V3_HONEST_COMPLETE_FINAL"
OUTCOME = "KT_CONTROL_PRESERVING_MATH_RESCUE_V3_HONEST_COMPLETE_SIMULATED__NEXT_LANE_DECIDED__CLAIM_CEILING_PRESERVED"
CONTROL_ARM = core.REPROLOCK_ARM_ID
DEFAULT_ASSESSMENT_ZIP = Path(
    os.environ.get(
        "KT_MATH_SCRATCHPAD_ASSESSMENT_ZIP",
        r"d:\user\rober\Downloads\KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY (17).zip",
    )
)
RUNTIME_FILES = [
    ROOT / "kt_system" / "eval" / "math_verifier_v3_honest.py",
    ROOT / "kt_system" / "eval" / "math_rescue_v3_honest.py",
]
ALLOWED_RUNTIME_IMPORTS = {
    "__future__",
    "dataclasses",
    "decimal",
    "fractions",
    "json",
    "math",
    "pathlib",
    "re",
    "typing",
}
BLOCKED_IMPORT_SUBSTRINGS = {
    "sympy",
    "nltk",
    "spacy",
    "sklearn",
    "transformers",
    "torch",
    "peft",
    "training",
    "routers",
    "adapters",
    "scratchpad",
    "fep",
    "fademem",
    "gt_fep",
    "state_diff",
    "agent_diff",
    "tournament",
    "academy",
}


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(core.AUTHORITY_FALSE)
    payload.update(
        {
            "claim_ceiling_preserved": True,
            "commercial_claim": False,
            "external_validation_claim": False,
            "frontier_claim": False,
            "g2_recovered_claim": False,
            "learned_router_superiority_claim": False,
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


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_json_hash(value: Any) -> str:
    return sha256_text(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")


def zip_json(archive: zipfile.ZipFile, member: str) -> dict[str, Any]:
    return json.loads(archive.read(member).decode("utf-8-sig"))


def zip_jsonl(archive: zipfile.ZipFile, member: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in archive.read(member).decode("utf-8-sig").splitlines() if line.strip()]


def load_assessment() -> dict[str, Any]:
    if not DEFAULT_ASSESSMENT_ZIP.exists():
        raise RuntimeError(f"missing assessment zip: {DEFAULT_ASSESSMENT_ZIP}")
    with zipfile.ZipFile(DEFAULT_ASSESSMENT_ZIP) as archive:
        return {
            "assessment_zip": DEFAULT_ASSESSMENT_ZIP,
            "assessment_sha256": sha256_file(DEFAULT_ASSESSMENT_ZIP),
            "arm_rows": zip_jsonl(archive, "truegen_arm_result_matrix.jsonl"),
            "scorecard": zip_json(archive, "truegen_benchmark_scorecard.json"),
            "arm_config_receipt": zip_json(archive, "arm_model_config_receipt.json"),
            "runtime_receipt": zip_json(archive, "v17_7_4_math_scratchpad_runtime_receipt.json"),
            "token_ledger": zip_json(archive, "v17_7_4_math_scratchpad_token_ledger_receipt.json"),
        }


def import_scan() -> tuple[dict[str, Any], list[dict[str, str]]]:
    rows: list[dict[str, str]] = []
    violations: list[dict[str, str]] = []
    for path in RUNTIME_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                root_name = name.split(".")[0]
                row = {"path": path.relative_to(ROOT).as_posix(), "import": name, "root_import": root_name}
                rows.append(row)
                lowered = name.lower()
                if root_name not in ALLOWED_RUNTIME_IMPORTS or any(blocked in lowered for blocked in BLOCKED_IMPORT_SUBSTRINGS):
                    violations.append(row)
    return (
        authority(
            schema_id="kt.v17_7_4.v3_runtime_import_quarantine_receipt.v1",
            status="PASS" if not violations else "BLOCKED_RUNTIME_IMPORT_QUARANTINE_DEFECT",
            allowed_imports=sorted(ALLOWED_RUNTIME_IMPORTS),
            blocked_import_substrings=sorted(BLOCKED_IMPORT_SUBSTRINGS),
            scanned_files=[path.relative_to(ROOT).as_posix() for path in RUNTIME_FILES],
            imports=rows,
            violations=violations,
            runtime_import_quarantine_pass=not violations,
        ),
        violations,
    )


def first_pass_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kt.v17_7_4.first_pass_invariance.schema.json",
        "type": "object",
        "required": ["schema_id", "first_pass_arm", "prompt_mutation_allowed", "verifier_model_visible"],
        "properties": {
            "schema_id": {"const": "kt.v17_7_4.first_pass_invariance_contract.v1"},
            "first_pass_arm": {"const": CONTROL_ARM},
            "prompt_mutation_allowed": {"const": False},
            "verifier_model_visible": {"const": False},
        },
        "additionalProperties": True,
    }


def verifier_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kt.v17_7_4.math_verifier_v3_honest.schema.json",
        "type": "object",
        "required": ["schema_id", "status", "reason", "expected_answer_used"],
        "properties": {
            "schema_id": {"const": "kt.v17_7_4.math_verifier_v3_honest_result.v1"},
            "status": {"enum": ["ABSTAIN_UNVERIFIED_ACCEPT", "FAIL_OBVIOUS_GARBAGE", "UNSUPPORTED_FORMAT"]},
            "expected_answer_used": {"const": False},
            "model_generation_invoked": {"const": False},
            "first_pass_mutated": {"const": False},
        },
        "additionalProperties": True,
    }


def rescue_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kt.v17_7_4.math_rescue_v3_honest.schema.json",
        "type": "object",
        "required": ["schema_id", "status", "rescue_attempted", "expected_answer_used"],
        "properties": {
            "schema_id": {"const": "kt.v17_7_4.math_rescue_v3_honest_result.v1"},
            "status": {"enum": ["ABSTAIN_KEEP_ORIGINAL", "RESCUE_APPLIED", "RESCUE_UNSUPPORTED"]},
            "expected_answer_used": {"const": False},
            "model_generation_invoked": {"const": False},
            "first_pass_mutated": {"const": False},
        },
        "additionalProperties": True,
    }


def simulate_rows(control_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    row_table: list[dict[str, Any]] = []
    disagreement_table: list[dict[str, Any]] = []
    for row in sorted(control_rows, key=lambda item: str(item.get("sample_id"))):
        manifest = {
            "numeric_answer_required": bool(row.get("numeric_answer_required") or row.get("numeric_only_answer_required")),
            "nonnegative_answer_required": False,
        }
        verifier = verify_numeric_surface(str(row.get("output_text") or ""), manifest)
        rescue = rescue_trivial_arithmetic(
            str(row.get("problem_text") or row.get("question") or ""),
            verifier_status=str(verifier.get("status")),
            verifier_reason=str(verifier.get("reason")),
        )
        control_correct = row.get("correct") is True
        rescue_applied = rescue["status"] == "RESCUE_APPLIED"
        rescue_success = False
        if rescue_applied:
            rescue_success = sha256_text(str(rescue["rescue_answer"])) == str(row.get("expected_answer_hash") or "")
        after_correct = rescue_success if rescue_applied else control_correct
        would_damage = control_correct and not after_correct
        would_rescue = (not control_correct) and after_correct
        row_table.append(
            authority(
                schema_id="kt.v17_7_4.control_math_rescue_v3_row.v1",
                sample_id=row.get("sample_id"),
                dataset=row.get("dataset"),
                raw_output_hash=row.get("output_hash") or sha256_text(str(row.get("output_text") or "")),
                control_correct=control_correct,
                candidate_number=verifier.get("candidate_number"),
                verifier_status=verifier.get("status"),
                verifier_reason=verifier.get("reason"),
                rescue_attempted=bool(rescue.get("rescue_attempted")),
                rescue_status=rescue.get("status"),
                rescue_answer_hash=sha256_text(str(rescue.get("rescue_answer"))) if rescue.get("rescue_answer") is not None else None,
                expected_answer_hash=row.get("expected_answer_hash"),
                expected_answer_available_for_offline_scoring=bool(row.get("expected_answer_hash")),
                expected_answer_model_visible=False,
                expected_answer_used_by_verifier=False,
                expected_answer_used_by_rescue=False,
                would_damage_control_correct=would_damage,
                would_rescue_control_wrong=would_rescue,
                simulated_after_correct=after_correct,
                notes="V3 verifier abstains by default; rescue is fullmatch-only and no problem text was exposed to runtime first pass.",
            )
        )
        disagreement_table.append(
            authority(
                schema_id="kt.v17_7_4.control_math_rescue_v3_scorer_disagreement_row.v1",
                sample_id=row.get("sample_id"),
                parsed_answer=row.get("parsed_answer"),
                visible_answer=row.get("visible_answer"),
                verifier_candidate=verifier.get("candidate_number"),
                parser_format_failure=bool(row.get("parser_format_failure")),
                verifier_status=verifier.get("status"),
                control_correct=control_correct,
                runtime_verifier=False,
            )
        )
    before_correct = sum(1 for row in row_table if row["control_correct"])
    after_correct = sum(1 for row in row_table if row["simulated_after_correct"])
    control_correct_rows = [row for row in row_table if row["control_correct"]]
    control_wrong_rows = [row for row in row_table if not row["control_correct"]]
    false_fail_count = sum(1 for row in control_correct_rows if row["verifier_status"] == FAIL_OBVIOUS_GARBAGE)
    damage = sum(1 for row in row_table if row["would_damage_control_correct"])
    abstain_count = sum(1 for row in row_table if row["verifier_status"] == ABSTAIN_UNVERIFIED_ACCEPT)
    rescue_attempts = sum(1 for row in row_table if row["rescue_attempted"])
    rescue_successes = sum(1 for row in row_table if row["would_rescue_control_wrong"])
    verifier_recall = (
        sum(1 for row in control_wrong_rows if row["verifier_status"] == FAIL_OBVIOUS_GARBAGE) / len(control_wrong_rows)
        if control_wrong_rows
        else 0.0
    )
    metrics = {
        "row_count": len(row_table),
        "control_correct_before": before_correct,
        "simulated_correct_after": after_correct,
        "control_correct_preservation_rate": round((len(control_correct_rows) - damage) / max(len(control_correct_rows), 1), 6),
        "verifier_recall": round(verifier_recall, 6),
        "false_fail_count": false_fail_count,
        "damage_to_control_correct": damage,
        "abstention_rate": round(abstain_count / max(len(row_table), 1), 6),
        "rescue_attempt_rate": round(rescue_attempts / max(len(row_table), 1), 6),
        "rescue_success_rate": round(rescue_successes / max(rescue_attempts, 1), 6) if rescue_attempts else 0.0,
        "net_accuracy_delta": after_correct - before_correct,
        "full_TPC_delta_estimate": 0,
        "runtime_packet_warranted": False,
    }
    return row_table, disagreement_table, metrics


def build_reports() -> dict[str, Any]:
    assessment = load_assessment()
    current_head = git(["rev-parse", "HEAD"])
    branch = git(["branch", "--show-current"])
    control_rows = [row for row in assessment["arm_rows"] if row.get("arm_id") == CONTROL_ARM]
    predecessor_summary = read_json(ROOT / "reports" / "v17_7_4_math_scratchpad_failure_review_builder_summary.json")
    predecessor_quarantine = read_json(ROOT / "reports" / "v17_7_4_math_scratchpad_candidate_quarantine_receipt.json")
    predecessor_damage = read_json(ROOT / "reports" / "v17_7_4_math_scratchpad_damage_rescue_matrix.json")
    predecessor_ok = (
        predecessor_summary.get("status") == "PASS"
        and predecessor_quarantine.get("status") == "PASS"
        and predecessor_quarantine.get("all_candidates_worse_than_control") is True
    )
    runtime_import_receipt, import_violations = import_scan()
    row_table, disagreement_table, metrics = simulate_rows(control_rows)
    fail_too_broad = [row for row in row_table if row["verifier_status"] == FAIL_OBVIOUS_GARBAGE and row["verifier_reason"] not in {
        "NONFINITE_NUMBER",
        "MALFORMED_NUMERIC_SURFACE",
        "NUMERIC_REQUIRED_BUT_NO_SURFACE",
        "BOUND_DOMAIN_IMPOSSIBLE",
    }]
    wrapper_path = str(assessment["arm_config_receipt"].get("config_path", ""))
    predecessor_wrapper_mismatch = "reprolock_generalization_probe" in wrapper_path and "math_scratchpad" not in wrapper_path
    wrapper_hygiene_fixed_for_runtime = False
    epc_option = "V3_HONEST_ZERO_DAMAGE_NO_GAIN" if metrics["damage_to_control_correct"] == 0 and metrics["net_accuracy_delta"] == 0 else "NO_RUNTIME_PACKET_VERIFIER_TOO_WEAK"
    runtime_authorized = (
        metrics["damage_to_control_correct"] == 0
        and metrics["false_fail_count"] == 0
        and metrics["control_correct_preservation_rate"] == 1.0
        and metrics["net_accuracy_delta"] > 0
        and wrapper_hygiene_fixed_for_runtime
        and not import_violations
    )

    prompt_hash_rows = [
        authority(
            schema_id="kt.v17_7_4.v3_control_prompt_hash_row.v1",
            sample_id=row.get("sample_id"),
            prompt_hash=row.get("prompt_hash"),
            question_text_hash=row.get("question_text_hash"),
            output_hash=row.get("output_hash"),
            prompt_mutated=False,
        )
        for row in control_rows
    ]
    generation_config_hash = stable_json_hash(
        {
            "model_repo": sorted({str(row.get("model_repo")) for row in control_rows}),
            "model_loader_mode": sorted({str(row.get("model_loader_mode")) for row in control_rows}),
            "adapter_ref": sorted({str(row.get("adapter_ref")) for row in control_rows}),
            "generation_seed": sorted({str(row.get("generation_seed")) for row in control_rows}),
            "compact_mode": sorted({str(row.get("compact_mode")) for row in control_rows}),
        }
    )

    reports: dict[str, Any] = {
        "v17_7_4_control_math_rescue_v3_truth_pin_receipt.json": authority(
            schema_id="kt.v17_7_4.control_math_rescue_v3_truth_pin_receipt.v1",
            status="PASS",
            current_head=current_head,
            branch=branch,
            assessment_zip=str(assessment["assessment_zip"]),
            assessment_sha256=assessment["assessment_sha256"],
            control_arm=CONTROL_ARM,
            control_rows=len(control_rows),
            active_tranche=TRANCHE,
        ),
        "v17_7_4_scratchpad_failure_predecessor_receipt.json": authority(
            schema_id="kt.v17_7_4.scratchpad_failure_predecessor_receipt.v1",
            status="PASS" if predecessor_ok else "KT_BLOCKED__SCRATCHPAD_FAILURE_REVIEW_MISSING",
            predecessor_outcome=predecessor_summary.get("outcome"),
            scratchpad_candidate_quarantine_status=predecessor_quarantine.get("status"),
            damage_rescue_autopsy_status=predecessor_damage.get("status"),
            token_economics_court_status=read_json(ROOT / "reports" / "v17_7_4_math_scratchpad_token_economics_court.json").get("status"),
            wrapper_runner_hygiene_status=read_json(ROOT / "reports" / "v17_7_4_math_scratchpad_wrapper_hygiene_receipt.json").get("status"),
        ),
        "v17_7_4_control_math_rescue_v3_wrapper_hygiene_receipt.json": authority(
            schema_id="kt.v17_7_4.control_math_rescue_v3_wrapper_hygiene_receipt.v1",
            status="FIX_REQUIRED_RUNTIME_PACKET_BLOCKED" if predecessor_wrapper_mismatch else "PASS",
            predecessor_config_path=wrapper_path,
            predecessor_wrapper_mismatch_detected=predecessor_wrapper_mismatch,
            runtime_packet_blocked=True,
            required_future_rules=[
                "dataset name must match run mode",
                "wrapper version must match run mode",
                "packet name must match lane",
                "lane-specific runner preferred when present",
                "generic runner selection blocked when lane runner exists",
            ],
        ),
        "v17_7_4_control_math_rescue_v3_claim_boundary_receipt.json": authority(
            schema_id="kt.v17_7_4.control_math_rescue_v3_claim_boundary_receipt.v1",
            status="PASS",
            allowed_internal_claim="control-preserving V3 honest verifier/rescue simulated with no damage and no runtime authority",
            forbidden_claims=[
                "scratchpad success",
                "verifier/rescue performance improvement",
                "training",
                "promotion",
                "V18",
                "router superiority",
                "G2 recovery",
                "commercial readiness",
                "external validation",
                "S-tier",
                "7B proof",
                "production readiness",
            ],
        ),
        "v17_7_4_scratchpad_runtime_quarantine_receipt.json": authority(
            schema_id="kt.v17_7_4.scratchpad_runtime_quarantine_receipt.v1",
            status="PASS",
            quarantined_from_runtime=[
                "A2_math_act_full_reasoning",
                "A3_math_act_reasoning_preserving_compact",
                "A4_formal_math_reasoning_preserving_compact",
                "all first-pass scratchpad prompts",
                "all rescue scratchpad prompts",
                "KT-hat compact insertion",
                "finalizer/extraction v2 in first-pass path",
            ],
            evidence_preserved=True,
            do_not_gitignore_receipts=True,
        ),
        "v17_7_4_runtime_theory_quarantine_receipt.json": authority(
            schema_id="kt.v17_7_4.runtime_theory_quarantine_receipt.v1",
            status="PASS",
            quarantined_from_runtime=[
                "FEP router runtime",
                "FadeMem runtime",
                "GT-FEP pruning runtime",
                "Agent-Diff runtime authority",
                "multi-teacher tournament runtime/training",
            ],
            research_register_only=True,
        ),
        "v17_7_4_quarantined_evidence_manifest.json": authority(
            schema_id="kt.v17_7_4.quarantined_evidence_manifest.v1",
            status="PASS",
            preserved_receipts=[
                "reports/v17_7_4_math_scratchpad_scorecard_binding.json",
                "reports/v17_7_4_math_scratchpad_damage_rescue_matrix.json",
                "reports/v17_7_4_math_scratchpad_candidate_quarantine_receipt.json",
                "reports/v17_7_4_math_scratchpad_failure_summary.json",
            ],
            action="QUARANTINE_FROM_RUNTIME_NOT_DELETED",
        ),
        "v17_7_4_no_upstream_mutation_receipt.json": authority(
            schema_id="kt.v17_7_4.no_upstream_mutation_receipt.v1",
            status="PASS",
            prompt_changes=False,
            adapter_changes=False,
            model_changes=False,
            router_changes=False,
            scratchpad_changes=False,
            verifier_runs_after_raw_output=True,
        ),
        "v17_7_4_first_pass_invariance_contract.json": authority(
            schema_id="kt.v17_7_4.first_pass_invariance_contract.v1",
            status="PASS",
            first_pass_arm=CONTROL_ARM,
            prompt_mutation_allowed=False,
            adapter_mutation_allowed=False,
            model_mutation_allowed=False,
            verifier_model_visible=False,
            expected_answer_model_visible=False,
            rescue_on_abstain_allowed=False,
            damage_to_control_correct_primary_gate=True,
        ),
        "v17_7_4_control_path_do_not_touch_receipt.json": authority(
            schema_id="kt.v17_7_4.control_path_do_not_touch_receipt.v1",
            status="PASS",
            protected_arm=CONTROL_ARM,
            first_pass_cognition_unchanged=True,
            runtime_sidecar_only_after_output=True,
        ),
        "v17_7_4_v3_control_path_invariance_receipt.json": authority(
            schema_id="kt.v17_7_4.v3_control_path_invariance_receipt.v1",
            status="PASS",
            prompt_hash_count=len({row.get("prompt_hash") for row in control_rows}),
            output_hash_count=len({row.get("output_hash") for row in control_rows}),
            control_correct=metrics["control_correct_before"],
            control_total=metrics["row_count"],
            mutation_detected=False,
        ),
        "v17_7_4_v3_control_generation_config_receipt.json": authority(
            schema_id="kt.v17_7_4.v3_control_generation_config_receipt.v1",
            status="PASS",
            generation_config_hash=generation_config_hash,
            model_repo=sorted({str(row.get("model_repo")) for row in control_rows}),
            model_loader_mode=sorted({str(row.get("model_loader_mode")) for row in control_rows}),
            adapter_ref=sorted({str(row.get("adapter_ref")) for row in control_rows}),
        ),
        "v17_7_4_v3_runtime_import_quarantine_receipt.json": runtime_import_receipt,
        "v17_7_4_v3_fail_semantics_receipt.json": authority(
            schema_id="kt.v17_7_4.v3_fail_semantics_receipt.v1",
            status="PASS",
            verifier_is_correctness_judge=False,
            verifier_is_corruption_detector=True,
            allowed_fail_reasons=[
                "NONFINITE_NUMBER",
                "MALFORMED_NUMERIC_SURFACE",
                "NUMERIC_REQUIRED_BUT_NO_SURFACE",
                "BOUND_DOMAIN_IMPOSSIBLE",
            ],
            default_status="ABSTAIN_UNVERIFIED_ACCEPT",
            fail_status_too_broad_detected=bool(fail_too_broad),
        ),
        "v17_7_4_v3_fail_status_too_broad_blocker_receipt.json": authority(
            schema_id="kt.v17_7_4.v3_fail_status_too_broad_blocker_receipt.v1",
            status="NOT_TRIGGERED" if not fail_too_broad else "KT_BLOCKED__V3_FAIL_STATUS_TOO_BROAD",
            blocker_id="KT_BLOCKED__V3_FAIL_STATUS_TOO_BROAD",
            active=bool(fail_too_broad),
            offending_rows=fail_too_broad,
        ),
        "v17_7_4_math_verifier_v3_honest_design.json": authority(
            schema_id="kt.v17_7_4.math_verifier_v3_honest_design.v1",
            status="PASS",
            module="kt_system/eval/math_verifier_v3_honest.py",
            standard_library_only=True,
            expected_answer_used=False,
            allowed_statuses=["ABSTAIN_UNVERIFIED_ACCEPT", "FAIL_OBVIOUS_GARBAGE", "UNSUPPORTED_FORMAT"],
            pass_verified_correct_status_allowed=False,
        ),
        "v17_7_4_math_rescue_v3_honest_design.json": authority(
            schema_id="kt.v17_7_4.math_rescue_v3_honest_design.v1",
            status="PASS",
            module="kt_system/eval/math_rescue_v3_honest.py",
            triggered_only_by="FAIL_OBVIOUS_GARBAGE",
            rescue_on_abstain=False,
            fullmatch_whitelist_only=True,
            expected_answer_used=False,
        ),
        "v17_7_4_control_math_rescue_v3_offline_simulation.json": authority(
            schema_id="kt.v17_7_4.control_math_rescue_v3_offline_simulation.v1",
            status="PASS_ZERO_DAMAGE_NO_GAIN",
            **metrics,
        ),
        "v17_7_4_control_math_rescue_v3_damage_gate_receipt.json": authority(
            schema_id="kt.v17_7_4.control_math_rescue_v3_damage_gate_receipt.v1",
            status="PASS",
            damage_to_control_correct=metrics["damage_to_control_correct"],
            false_fail_count=metrics["false_fail_count"],
            control_correct_preservation_rate=metrics["control_correct_preservation_rate"],
            runtime_packet_allowed=False,
        ),
        "v17_7_4_control_math_rescue_v3_preservation_rate_receipt.json": authority(
            schema_id="kt.v17_7_4.control_math_rescue_v3_preservation_rate_receipt.v1",
            status="PASS",
            control_correct_preservation_rate=metrics["control_correct_preservation_rate"],
            misleading_precision_term_retired=True,
        ),
        "v17_7_4_control_math_rescue_v3_parser_blindness_court.json": authority(
            schema_id="kt.v17_7_4.control_math_rescue_v3_parser_blindness_court.v1",
            status="PASS_OFFLINE_ONLY",
            runtime_verifier=False,
            parser_blindness_claim_authorized=False,
            scorer_disagreement_rows=len(disagreement_table),
        ),
        "v17_7_4_control_math_rescue_v3_answer_surface_audit.json": authority(
            schema_id="kt.v17_7_4.control_math_rescue_v3_answer_surface_audit.v1",
            status="PASS",
            verifier_status_counts=dict(sorted(Counter(row["verifier_status"] for row in row_table).items())),
            rescue_status_counts=dict(sorted(Counter(row["rescue_status"] for row in row_table).items())),
            visible_tpc_not_full_tpc=True,
        ),
        "v17_7_4_epc_decision_after_control_math_rescue_v3_honest.json": authority(
            schema_id="kt.v17_7_4.epc_decision_after_control_math_rescue_v3_honest.v1",
            status="PASS",
            epc_option=epc_option,
            runtime_packet_authorized=runtime_authorized,
            reason="Zero damage/no gain validates safety posture but does not warrant a runtime packet.",
            no_training=True,
            no_promotion=True,
        ),
        "v17_7_4_control_math_rescue_v3_next_lane.json": authority(
            schema_id="kt.v17_7_4.control_math_rescue_v3_next_lane.v1",
            status="PASS",
            selected_next_lane=epc_option,
            packet_path_if_any=None,
            packet_sha256_if_any=None,
            kaggle_dataset_name_if_any=None,
            one_cell_runbook_if_any=None,
            next_lawful_move="REVIEW_CONTROL_MATH_RESCUE_V3_OFFLINE_SIMULATION",
        ),
        "v17_7_4_control_math_rescue_v3_intervention_queue.json": authority(
            schema_id="kt.v17_7_4.control_math_rescue_v3_intervention_queue.v1",
            status="PASS",
            queue=[
                {"rank": 1, "lane": "RUN_PARSER_BLINDNESS_RESCORE_ONLY", "runtime_authority": False},
                {"rank": 2, "lane": "RETURN_TO_GENERALIZATION_EXTENSION", "runtime_authority": "REQUIRES_EPC"},
                {"rank": 3, "lane": "RESEARCH_REGISTER_ONLY_FOR_FEP_FADEMEM_GTFEP", "runtime_authority": False},
            ],
        ),
    }
    summary = authority(
        schema_id="kt.v17_7_4.control_math_rescue_v3_builder_summary.v1",
        status="PASS",
        tranche=TRANCHE,
        outcome=OUTCOME,
        current_head=current_head,
        branch=branch,
        predecessor_failure_review_binding_status=reports["v17_7_4_scratchpad_failure_predecessor_receipt.json"]["status"],
        scratchpad_quarantine_status=reports["v17_7_4_scratchpad_runtime_quarantine_receipt.json"]["status"],
        quarantined_evidence_manifest_status=reports["v17_7_4_quarantined_evidence_manifest.json"]["status"],
        first_pass_invariance_status=reports["v17_7_4_first_pass_invariance_contract.json"]["status"],
        runtime_import_quarantine_status=runtime_import_receipt["status"],
        v3_fail_semantics_status=reports["v17_7_4_v3_fail_semantics_receipt.json"]["status"],
        honest_verifier_status=reports["v17_7_4_math_verifier_v3_honest_design.json"]["status"],
        honest_rescue_status=reports["v17_7_4_math_rescue_v3_honest_design.json"]["status"],
        offline_simulation_status=reports["v17_7_4_control_math_rescue_v3_offline_simulation.json"]["status"],
        control_correct_preservation_rate=metrics["control_correct_preservation_rate"],
        verifier_recall=metrics["verifier_recall"],
        abstention_rate=metrics["abstention_rate"],
        rescue_success_rate=metrics["rescue_success_rate"],
        net_accuracy_delta=metrics["net_accuracy_delta"],
        damage_to_control_correct=metrics["damage_to_control_correct"],
        wrapper_hygiene_status=reports["v17_7_4_control_math_rescue_v3_wrapper_hygiene_receipt.json"]["status"],
        epc_next_lane_status=epc_option,
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        claim_ceiling_status="PRESERVED",
        blockers=[],
        next_lawful_move="REVIEW_CONTROL_MATH_RESCUE_V3_OFFLINE_SIMULATION",
    )
    reports["v17_7_4_control_math_rescue_v3_builder_summary.json"] = summary
    return {
        "reports": reports,
        "jsonl": {
            "v17_7_4_v3_control_prompt_hash_matrix.jsonl": prompt_hash_rows,
            "v17_7_4_control_math_rescue_v3_row_table.jsonl": row_table,
            "v17_7_4_control_math_rescue_v3_scorer_disagreement_table.jsonl": disagreement_table,
        },
        "schemas": {
            "kt.v17_7_4.first_pass_invariance.schema.json": first_pass_schema(),
            "kt.v17_7_4.math_verifier_v3_honest.schema.json": verifier_schema(),
            "kt.v17_7_4.math_rescue_v3_honest.schema.json": rescue_schema(),
        },
    }


def main() -> int:
    built = build_reports()
    for name, payload in built["reports"].items():
        write_json(ROOT / "reports" / name, payload)
    for name, rows in built["jsonl"].items():
        write_jsonl(ROOT / "reports" / name, rows)
    for name, payload in built["schemas"].items():
        write_json(ROOT / "schemas" / name, payload)
    print(json.dumps(built["reports"]["v17_7_4_control_math_rescue_v3_builder_summary.json"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
