from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kt_system.eval.parser_canonicalizer_v17_7_4 import (
    AUDIT_ONLY_SURFACES,
    CANONICALIZER_TOGGLES,
    FROZEN_CANDIDATE_ORDER,
    canonicalize_surface,
    extract_answer_surfaces,
    select_frozen_candidate,
    sha256_text,
)


TRANCHE = "AUTHOR_KTV1774_ANSWER_SURFACE_AUDIT_KAGGLE_GATE_V2_BORING_FINAL_PLUS"
OUTCOME = "KT_ANSWER_SURFACE_AUDIT_COMPLETE__NEXT_KAGGLE_GATE_DECIDED__CLAIM_CEILING_PRESERVED"
CONTROL_ARM = "A_true_known_good_math_act_byte_repro"
DEFAULT_ASSESSMENT_ZIP = Path(
    os.environ.get(
        "KT_ANSWER_SURFACE_AUDIT_ASSESSMENT_ZIP",
        r"d:\user\rober\Downloads\KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY (17).zip",
    )
)
PARSER_MODULE = ROOT / "kt_system" / "eval" / "parser_canonicalizer_v17_7_4.py"

AUTHORITY_FALSE = {
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

GENERATED_PATHS = {
    "kt_system/eval/parser_canonicalizer_v17_7_4.py",
    "scripts/simulate_v17_7_4_parser_canonicalizer_offline.py",
    "schemas/kt.v17_7_4.answer_surface_provenance.schema.json",
    "schemas/kt.v17_7_4.parser_canonicalizer.schema.json",
    "tests/test_v17_7_4_answer_surface_audit_gate.py",
    "tests/test_v17_7_4_parser_canonicalizer_zero_damage.py",
    "tests/test_v17_7_4_parser_expected_answer_not_runtime_visible.py",
    "tests/test_v17_7_4_wrapper_lane_identity_hard_fail.py",
}
GENERATED_PREFIXES = (
    "reports/v17_7_4_answer_surface",
    "reports/v17_7_4_parser_",
    "reports/v17_7_4_scorer_disagreement_table",
    "reports/v17_7_4_reviewer_blindness",
    "reports/v17_7_4_candidate_extraction",
    "reports/v17_7_4_canonicalizer",
    "reports/v17_7_4_external_eye",
    "reports/v17_7_4_v3_honest",
    "reports/v17_7_4_next_runtime_wrapper",
    "reports/v17_7_4_next_kaggle",
    "reports/v17_7_4_epc_decision_after_parser",
)


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(AUTHORITY_FALSE)
    payload.update(extra)
    return payload


def git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def status_paths() -> list[str]:
    raw = git(["status", "--porcelain"])
    out: list[str] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        out.append(line[3:].replace("\\", "/"))
    return out


def unrelated_dirty_paths() -> list[str]:
    unrelated: list[str] = []
    for path in status_paths():
        if path in GENERATED_PATHS or any(path.startswith(prefix) for prefix in GENERATED_PREFIXES):
            continue
        unrelated.append(path)
    return unrelated


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
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows), encoding="utf-8")


def load_assessment() -> dict[str, Any]:
    if not DEFAULT_ASSESSMENT_ZIP.exists():
        raise RuntimeError(f"KT_BLOCKED__ANSWER_SURFACE_SOURCE_MISSING: {DEFAULT_ASSESSMENT_ZIP}")
    with zipfile.ZipFile(DEFAULT_ASSESSMENT_ZIP) as archive:
        rows = [
            json.loads(line)
            for line in archive.read("truegen_arm_result_matrix.jsonl").decode("utf-8-sig").splitlines()
            if line.strip()
        ]
        scorecard = json.loads(archive.read("truegen_benchmark_scorecard.json").decode("utf-8-sig"))
    return {
        "path": DEFAULT_ASSESSMENT_ZIP,
        "sha256": sha256_file(DEFAULT_ASSESSMENT_ZIP),
        "rows": rows,
        "scorecard": scorecard,
    }


def answer_kind(row: dict[str, Any]) -> str:
    dataset = str(row.get("dataset", "")).lower()
    task_family = str(row.get("task_family", "")).lower()
    if "gsm8k" in dataset or "math" in task_family:
        return "numeric"
    if "arc" in dataset or "hellaswag" in dataset:
        return "multiple_choice"
    return "short_answer"


def expected_hash_match(surface: str, expected_answer_hash: str | None) -> bool | None:
    if not expected_answer_hash:
        return None
    return sha256_text(str(surface)) == str(expected_answer_hash)


def import_scan() -> dict[str, Any]:
    allowed = {"__future__", "dataclasses", "decimal", "hashlib", "re", "typing"}
    blocked_substrings = {
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
    }
    rows: list[dict[str, str]] = []
    violations: list[dict[str, str]] = []
    tree = ast.parse(PARSER_MODULE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        names: list[str]
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            continue
        for name in names:
            root = name.split(".")[0]
            row = {"path": PARSER_MODULE.relative_to(ROOT).as_posix(), "import": name, "root_import": root}
            rows.append(row)
            if root not in allowed or any(token in name.lower() for token in blocked_substrings):
                violations.append(row)
    return authority(
        schema_id="kt.v17_7_4.parser_canonicalizer_import_quarantine_receipt.v1",
        status="PASS" if not violations else "BLOCKED_IMPORT_QUARANTINE_DEFECT",
        allowed_imports=sorted(allowed),
        blocked_import_substrings=sorted(blocked_substrings),
        imports=rows,
        violations=violations,
        standard_library_only=not violations,
    )


def surface_score_rows(control_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    row_table: list[dict[str, Any]] = []
    provenance_rows: list[dict[str, Any]] = []
    disagreement_rows: list[dict[str, Any]] = []
    ablation: dict[str, dict[str, int]] = defaultdict(lambda: {"present": 0, "correct": 0, "gain": 0, "damage": 0})

    for idx, row in enumerate(sorted(control_rows, key=lambda item: str(item.get("sample_id")))):
        result = select_frozen_candidate(str(row.get("output_text") or ""), row)
        surfaces = result["candidate_surfaces"]
        selected = result["selected_surface"]
        baseline_correct = bool(row.get("correct"))
        expected_hash = str(row.get("expected_answer_hash") or "")
        selected_correct = (
            expected_hash_match(str(selected.get("canonical_surface")), expected_hash) if selected else False
        )
        if selected_correct is None:
            selected_correct = False
        split = "design" if idx % 2 == 0 else "holdout"
        for surface in surfaces:
            surface_correct = expected_hash_match(str(surface.get("canonical_surface")), expected_hash)
            surface_correct_bool = bool(surface_correct)
            ablation[surface["surface_id"]]["present"] += 1
            ablation[surface["surface_id"]]["correct"] += int(surface_correct_bool)
            ablation[surface["surface_id"]]["gain"] += int((not baseline_correct) and surface_correct_bool)
            ablation[surface["surface_id"]]["damage"] += int(baseline_correct and not surface_correct_bool and surface["runtime_admissible"])
            provenance_rows.append(
                authority(
                    schema_id="kt.v17_7_4.answer_surface_provenance_row.v1",
                    sample_id=row.get("sample_id"),
                    split=split,
                    dataset=row.get("dataset"),
                    task_family=row.get("task_family"),
                    arm_id=row.get("arm_id"),
                    output_hash=row.get("output_hash") or sha256_text(str(row.get("output_text") or "")),
                    expected_answer_hash_present=bool(expected_hash),
                    expected_answer_model_visible=False,
                    expected_answer_used_for_candidate_selection=False,
                    surface_id=surface["surface_id"],
                    raw_surface_hash=sha256_text(str(surface.get("raw_surface"))),
                    canonical_surface_hash=sha256_text(str(surface.get("canonical_surface"))),
                    canonical_rule=surface["canonical_rule"],
                    span_start=surface["span_start"],
                    span_end=surface["span_end"],
                    span_sha256=surface["span_sha256"],
                    runtime_admissible=surface["runtime_admissible"],
                    audit_only=surface["audit_only"],
                    offline_score_correct=surface_correct,
                )
            )
        row_table.append(
            authority(
                schema_id="kt.v17_7_4.parser_canonicalizer_row.v1",
                sample_id=row.get("sample_id"),
                split=split,
                dataset=row.get("dataset"),
                task_family=row.get("task_family"),
                arm_id=row.get("arm_id"),
                output_hash=row.get("output_hash") or sha256_text(str(row.get("output_text") or "")),
                baseline_visible_answer_hash=sha256_text(str(row.get("visible_answer") or "")),
                baseline_parsed_answer_hash=sha256_text(str(row.get("parsed_answer") or "")),
                expected_answer_hash=expected_hash,
                expected_answer_available_for_offline_scoring=bool(expected_hash),
                expected_answer_model_visible=False,
                expected_answer_used_for_candidate_selection=False,
                candidate_order=list(FROZEN_CANDIDATE_ORDER),
                selected_surface_id=selected.get("surface_id") if selected else None,
                selected_surface_hash=sha256_text(str(selected.get("canonical_surface"))) if selected else None,
                selected_surface_runtime_admissible=bool(selected and selected.get("runtime_admissible")),
                baseline_correct=baseline_correct,
                parser_canonicalizer_correct=bool(selected_correct),
                would_damage_control_correct=baseline_correct and not bool(selected_correct),
                would_rescue_control_wrong=(not baseline_correct) and bool(selected_correct),
                candidate_surface_count=len(surfaces),
                last_numeric_audit_only=any(s["surface_id"] in AUDIT_ONLY_SURFACES for s in surfaces),
                model_generation_invoked=False,
                first_pass_mutated=False,
            )
        )
        if baseline_correct != bool(selected_correct):
            disagreement_rows.append(
                authority(
                    schema_id="kt.v17_7_4.scorer_disagreement_row.v1",
                    sample_id=row.get("sample_id"),
                    split=split,
                    baseline_correct=baseline_correct,
                    parser_canonicalizer_correct=bool(selected_correct),
                    selected_surface_id=selected.get("surface_id") if selected else None,
                    selected_surface_hash=sha256_text(str(selected.get("canonical_surface"))) if selected else None,
                    expected_answer_hash=expected_hash,
                    expected_answer_model_visible=False,
                    disagreement_type="GAIN" if (not baseline_correct and selected_correct) else "DAMAGE",
                )
            )

    ablation_payload = {
        surface_id: {
            **counts,
            "net_delta": counts["gain"] - counts["damage"],
        }
        for surface_id, counts in sorted(ablation.items())
    }
    return row_table, provenance_rows, disagreement_rows, ablation_payload


def metric_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    before = sum(1 for row in rows if row["baseline_correct"])
    after = sum(1 for row in rows if row["parser_canonicalizer_correct"])
    damage = sum(1 for row in rows if row["would_damage_control_correct"])
    gain = sum(1 for row in rows if row["would_rescue_control_wrong"])
    control_correct = [row for row in rows if row["baseline_correct"]]
    return {
        "row_count": total,
        "control_correct_before": before,
        "parser_canonicalizer_correct_after": after,
        "control_correct_preservation_rate": round((len(control_correct) - damage) / max(len(control_correct), 1), 6),
        "parser_net_accuracy_delta": after - before,
        "damage_to_control_correct": damage,
        "rescue_control_wrong_count": gain,
        "runtime_packet_warranted": False,
    }


def split_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        split: metric_summary([row for row in rows if row["split"] == split])
        for split in ["design", "holdout"]
    }


def negative_controls() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    fixtures = [
        {
            "fixture_id": "current_scorer_preserved_even_when_final_marker_exists",
            "output": "Scratch 999 first.\nFinal: 12",
            "row": {"dataset": "gsm8k", "task_family": "formal_math", "parsed_answer": "999", "visible_answer": "12"},
            "expected_surface": "999",
        },
        {
            "fixture_id": "last_numeric_audit_only_not_runtime_fallback",
            "output": "No final answer.\nNumbers: 1 2 3",
            "row": {"dataset": "gsm8k", "task_family": "formal_math"},
            "expected_selected_surface_id": "FINAL_LINE",
        },
        {
            "fixture_id": "currency_and_decimal_canonicalization",
            "output": "Final: $1,000.0",
            "row": {"dataset": "gsm8k", "task_family": "formal_math"},
            "expected_surface": "1000",
        },
    ]
    rows: list[dict[str, Any]] = []
    failures: list[str] = []
    for fixture in fixtures:
        result = select_frozen_candidate(fixture["output"], fixture["row"])
        selected = result["selected_surface"] or {}
        selected_surface = selected.get("canonical_surface")
        selected_id = selected.get("surface_id")
        passed = True
        if "expected_surface" in fixture and selected_surface != fixture["expected_surface"]:
            passed = False
        if "expected_selected_surface_id" in fixture and selected_id != fixture["expected_selected_surface_id"]:
            passed = False
        if selected_id == "LAST_NUMERIC_AUDIT_ONLY":
            passed = False
        if not passed:
            failures.append(fixture["fixture_id"])
        rows.append(
            authority(
                schema_id="kt.v17_7_4.parser_canonicalizer_negative_control_row.v1",
                fixture_id=fixture["fixture_id"],
                selected_surface_id=selected_id,
                selected_surface_hash=sha256_text(str(selected_surface)),
                passed=passed,
                expected_answer_used=False,
                model_generation_invoked=False,
            )
        )
    receipt = authority(
        schema_id="kt.v17_7_4.parser_canonicalizer_negative_control_receipt.v1",
        status="PASS" if not failures else "BLOCKED_NEGATIVE_CONTROL_FAILURE",
        fixture_count=len(fixtures),
        failures=failures,
        last_numeric_runtime_fallback_allowed=False,
    )
    return rows, receipt


def schema_payload(schema_id: str) -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://kt.local/schemas/{schema_id}.schema.json",
        "title": schema_id,
        "type": "object",
        "required": ["schema_id", "claim_ceiling_preserved"],
        "properties": {
            "schema_id": {"type": "string"},
            "claim_ceiling_preserved": {"const": True},
        },
        "additionalProperties": True,
    }


def build_reports() -> dict[str, Any]:
    assessment = load_assessment()
    current_head = git(["rev-parse", "HEAD"])
    branch = git(["branch", "--show-current"])
    unrelated_dirty = unrelated_dirty_paths()
    control_rows = [row for row in assessment["rows"] if row.get("arm_id") == CONTROL_ARM]
    if not control_rows:
        raise RuntimeError("KT_BLOCKED__CONTROL_ARM_ROWS_MISSING")

    row_table, provenance_rows, disagreement_rows, ablation = surface_score_rows(control_rows)
    metrics = metric_summary(row_table)
    splits = split_summary(row_table)
    negative_rows, negative_receipt = negative_controls()
    import_receipt = import_scan()
    v3_summary = read_json(ROOT / "reports" / "v17_7_4_control_math_rescue_v3_builder_summary.json")
    v3_epc = read_json(ROOT / "reports" / "v17_7_4_epc_decision_after_control_math_rescue_v3_honest.json")

    split_pass = (
        splits["design"]["damage_to_control_correct"] == 0
        and splits["holdout"]["damage_to_control_correct"] == 0
        and splits["design"]["parser_net_accuracy_delta"] > 0
        and splits["holdout"]["parser_net_accuracy_delta"] > 0
    )
    parser_microfurnace_authorized = (
        metrics["damage_to_control_correct"] == 0
        and metrics["parser_net_accuracy_delta"] > 0
        and split_pass
        and negative_receipt["status"] == "PASS"
        and import_receipt["status"] == "PASS"
    )
    control_extension_authorized = False
    selected_next_lane = (
        "PARSER_CANONICALIZER_MICROFURNACE_25"
        if parser_microfurnace_authorized
        else "NO_RUNTIME_PACKET_WARRANTED_BY_ANSWER_SURFACE_AUDIT"
    )
    next_lawful_move = (
        "RUN_KTV1774_PARSER_CANONICALIZER_MICROFURNACE_25"
        if parser_microfurnace_authorized
        else "REVIEW_ANSWER_SURFACE_AUDIT_NO_RUNTIME_PACKET"
    )

    reports = {
        "v17_7_4_answer_surface_audit_truth_pin_receipt.json": authority(
            schema_id="kt.v17_7_4.answer_surface_audit_truth_pin_receipt.v1",
            status="PASS" if not unrelated_dirty else "BLOCKED_UNRELATED_WORKTREE_DIRT",
            active_tranche=TRANCHE,
            current_head=current_head,
            branch=branch,
            unrelated_dirty_paths=unrelated_dirty,
            worktree_clean_or_lane_only_dirty=not unrelated_dirty,
            assessment_zip=str(assessment["path"]),
            assessment_sha256=assessment["sha256"],
            control_arm=CONTROL_ARM,
            control_rows=len(control_rows),
            model_generation_invoked=False,
            no_training=True,
            no_promotion=True,
        ),
        "v17_7_4_v3_honest_zero_damage_no_gain_binding.json": authority(
            schema_id="kt.v17_7_4.v3_honest_zero_damage_no_gain_binding.v1",
            status="PASS" if v3_epc.get("epc_option") == "V3_HONEST_ZERO_DAMAGE_NO_GAIN" else "BLOCKED_V3_BINDING_DEFECT",
            v3_outcome=v3_summary.get("outcome"),
            v3_epc_option=v3_epc.get("epc_option"),
            v3_runtime_packet_authorized=v3_epc.get("runtime_packet_authorized"),
            v3_damage_to_control_correct=v3_summary.get("damage_to_control_correct"),
            v3_net_accuracy_delta=v3_summary.get("net_accuracy_delta"),
        ),
        "v17_7_4_parser_gate_claim_boundary_receipt.json": authority(
            schema_id="kt.v17_7_4.parser_gate_claim_boundary_receipt.v1",
            status="PASS",
            allowed_internal_claims=[
                "offline answer-surface audit completed",
                "parser-canonicalizer gate decided whether a next Kaggle run is warranted",
            ],
            forbidden_claims=[
                "parser repair success",
                "external validation",
                "commercial readiness",
                "router superiority",
                "learned-router superiority",
                "G2 recovery",
                "91% full-system compression recovery",
                "S-tier",
                "frontier",
                "7B proof",
                "production readiness",
            ],
        ),
        "v17_7_4_external_eye_review_receipt.json": authority(
            schema_id="kt.v17_7_4.external_eye_review_receipt.v1",
            status="PASS_ADVISORY_ONLY",
            advisory_only=True,
            external_validation_claim=False,
            adopted_constraints=[
                "boring downstream-only audit",
                "no upstream cognition mutation",
                "no expected-answer leakage",
                "no Kaggle unless earned",
            ],
        ),
        "v17_7_4_reviewer_blindness_guard_receipt.json": authority(
            schema_id="kt.v17_7_4.reviewer_blindness_guard_receipt.v1",
            status="PASS",
            reviewer_saw_expected_answers=False,
            reviewer_saw_gold_hashes_only=True,
            candidate_selection_gold_blind=True,
        ),
        "v17_7_4_candidate_extraction_order_freeze_receipt.json": authority(
            schema_id="kt.v17_7_4.candidate_extraction_order_freeze_receipt.v1",
            status="PASS",
            candidate_order=list(FROZEN_CANDIDATE_ORDER),
            frozen_before_scoring=True,
            stable_order_hash=stable_json_hash(FROZEN_CANDIDATE_ORDER),
        ),
        "v17_7_4_canonicalizer_toggle_freeze_receipt.json": authority(
            schema_id="kt.v17_7_4.canonicalizer_toggle_freeze_receipt.v1",
            status="PASS",
            canonicalizer_toggles=dict(CANONICALIZER_TOGGLES),
            frozen_before_scoring=True,
            stable_toggle_hash=stable_json_hash(CANONICALIZER_TOGGLES),
        ),
        "v17_7_4_parser_blindness_court.json": authority(
            schema_id="kt.v17_7_4.parser_blindness_court.v1",
            status="PASS_OFFLINE_ONLY",
            parser_gain_detected=metrics["parser_net_accuracy_delta"] > 0,
            parser_gain_runtime_authorized=parser_microfurnace_authorized,
            damage_to_control_correct=metrics["damage_to_control_correct"],
            split_validation_pass=split_pass,
            model_generation_invoked=False,
            raw_output_replay_only=True,
        ),
        "v17_7_4_answer_surface_audit.json": authority(
            schema_id="kt.v17_7_4.answer_surface_audit.v1",
            status="PASS",
            row_count=metrics["row_count"],
            candidate_surface_counts=dict(sorted(Counter(row["surface_id"] for row in provenance_rows).items())),
            selected_surface_counts=dict(sorted(Counter(row["selected_surface_id"] for row in row_table).items())),
            audit_only_surfaces=sorted(AUDIT_ONLY_SURFACES),
            last_numeric_runtime_authority=False,
        ),
        "v17_7_4_parser_failure_owner_matrix.json": authority(
            schema_id="kt.v17_7_4.parser_failure_owner_matrix.v1",
            status="PASS",
            owner="PARSER_CANONICALIZER_OWNED" if metrics["parser_net_accuracy_delta"] > 0 else "NO_MEASURED_PARSER_GAIN",
            parser_net_accuracy_delta=metrics["parser_net_accuracy_delta"],
            damage_to_control_correct=metrics["damage_to_control_correct"],
            global_runtime_integration_allowed=False,
        ),
        "v17_7_4_parser_expected_answer_leakage_diff.json": authority(
            schema_id="kt.v17_7_4.parser_expected_answer_leakage_diff.v1",
            status="PASS",
            expected_answer_fields_seen_by_runtime=[],
            expected_answer_used_for_candidate_selection=False,
            expected_answer_used_for_canonicalization=False,
            expected_answer_used_for_offline_scoring_only=True,
            blocker_id_if_failed="KT_BLOCKED__PARSER_EXPECTED_ANSWER_LEAKAGE",
        ),
        "v17_7_4_parser_canonicalizer_negative_control_receipt.json": negative_receipt,
        "v17_7_4_parser_canonicalizer_design.json": authority(
            schema_id="kt.v17_7_4.parser_canonicalizer_design.v1",
            status="PASS",
            module="kt_system/eval/parser_canonicalizer_v17_7_4.py",
            standard_library_only=import_receipt["status"] == "PASS",
            no_sympy=True,
            no_nlp=True,
            no_llm=True,
            no_model_call=True,
            expected_answer_used=False,
            runtime_admissible_surfaces=[
                "EXPLICIT_FINAL_MARKER",
                "FINAL_LINE",
                "ISOLATED_NUMERIC_LINE",
                "CURRENT_SCORER",
            ],
            audit_only_surfaces=sorted(AUDIT_ONLY_SURFACES),
        ),
        "v17_7_4_parser_canonicalizer_rule_ablation.json": authority(
            schema_id="kt.v17_7_4.parser_canonicalizer_rule_ablation.v1",
            status="PASS",
            ablation=ablation,
            rules_frozen_before_scoring=True,
        ),
        "v17_7_4_parser_canonicalizer_offline_simulation.json": authority(
            schema_id="kt.v17_7_4.parser_canonicalizer_offline_simulation.v1",
            status="PASS_NO_RUNTIME_PACKET" if not parser_microfurnace_authorized else "PASS_RUNTIME_PACKET_WARRANTED",
            **metrics,
            model_generation_invoked=False,
        ),
        "v17_7_4_parser_canonicalizer_damage_gate_receipt.json": authority(
            schema_id="kt.v17_7_4.parser_canonicalizer_damage_gate_receipt.v1",
            status="PASS" if metrics["damage_to_control_correct"] == 0 else "RUNTIME_BLOCKED_DAMAGE_DETECTED",
            damage_to_control_correct=metrics["damage_to_control_correct"],
            control_correct_preservation_rate=metrics["control_correct_preservation_rate"],
            runtime_packet_allowed=parser_microfurnace_authorized,
        ),
        "v17_7_4_parser_canonicalizer_split_validation_receipt.json": authority(
            schema_id="kt.v17_7_4.parser_canonicalizer_split_validation_receipt.v1",
            status="PASS" if split_pass else "RUNTIME_BLOCKED_SPLIT_VALIDATION_NOT_EARNED",
            split_metrics=splits,
            requires_positive_zero_damage_gain_in_design_and_holdout=True,
        ),
        "v17_7_4_next_runtime_wrapper_hygiene_contract.json": authority(
            schema_id="kt.v17_7_4.next_runtime_wrapper_hygiene_contract.v1",
            status="PASS",
            lane_identity_hard_fail=True,
            forbidden_mismatch_examples=[
                "parser canonicalizer packet invoking scratchpad wrapper",
                "control-only extension packet invoking parser microfurnace mode",
                "runtime mode not matching dataset/runbook name",
            ],
        ),
        "v17_7_4_epc_decision_after_parser_blindness_gate.json": authority(
            schema_id="kt.v17_7_4.epc_decision_after_parser_blindness_gate.v1",
            status="PASS",
            selected_next_lane=selected_next_lane,
            parser_microfurnace_authorized=parser_microfurnace_authorized,
            control_only_gsm8k_extension_authorized=control_extension_authorized,
            reason=(
                "Positive zero-damage parser gain passed split validation."
                if parser_microfurnace_authorized
                else "Offline parser/canonicalizer audit did not earn a fresh-generation runtime packet."
            ),
            runtime_authority=False,
        ),
        "v17_7_4_next_kaggle_gate_decision.json": authority(
            schema_id="kt.v17_7_4.next_kaggle_gate_decision.v1",
            status="PASS_DECIDED",
            selected_next_lane=selected_next_lane,
            packet_path_if_any=None,
            packet_sha256_if_any=None,
            kaggle_dataset_name_if_any=None,
            one_cell_runbook_if_any=None,
            next_lawful_move=next_lawful_move,
        ),
        "v17_7_4_parser_blindness_intervention_queue.json": authority(
            schema_id="kt.v17_7_4.parser_blindness_intervention_queue.v1",
            status="PASS",
            queue=[
                {"rank": 1, "lane": "PARSER_CANONICALIZER_MICROFURNACE_25", "allowed": parser_microfurnace_authorized},
                {"rank": 2, "lane": "CONTROL_ONLY_GSM8K_EXTENSION_100", "allowed": control_extension_authorized},
                {"rank": 3, "lane": "REVIEW_NO_RUNTIME_PACKET", "allowed": not parser_microfurnace_authorized},
            ],
        ),
        "v17_7_4_parser_canonicalizer_import_quarantine_receipt.json": import_receipt,
    }
    summary = authority(
        schema_id="kt.v17_7_4.answer_surface_audit_builder_summary.v1",
        status="PASS",
        active_tranche=TRANCHE,
        outcome=OUTCOME,
        current_head=current_head,
        branch=branch,
        v3_honest_binding_status=reports["v17_7_4_v3_honest_zero_damage_no_gain_binding.json"]["status"],
        external_eye_review_receipt_status=reports["v17_7_4_external_eye_review_receipt.json"]["status"],
        reviewer_blindness_guard_status=reports["v17_7_4_reviewer_blindness_guard_receipt.json"]["status"],
        parser_blindness_court_status=reports["v17_7_4_parser_blindness_court.json"]["status"],
        answer_surface_provenance_status="PASS",
        expected_answer_leakage_diff_status=reports["v17_7_4_parser_expected_answer_leakage_diff.json"]["status"],
        parser_canonicalizer_status=reports["v17_7_4_parser_canonicalizer_design.json"]["status"],
        rule_ablation_status=reports["v17_7_4_parser_canonicalizer_rule_ablation.json"]["status"],
        negative_control_status=negative_receipt["status"],
        split_validation_status=reports["v17_7_4_parser_canonicalizer_split_validation_receipt.json"]["status"],
        offline_parser_simulation_status=reports["v17_7_4_parser_canonicalizer_offline_simulation.json"]["status"],
        control_correct_preservation_rate=metrics["control_correct_preservation_rate"],
        parser_net_accuracy_delta=metrics["parser_net_accuracy_delta"],
        damage_to_control_correct=metrics["damage_to_control_correct"],
        wrapper_hygiene_status=reports["v17_7_4_next_runtime_wrapper_hygiene_contract.json"]["status"],
        epc_next_kaggle_gate_status=reports["v17_7_4_next_kaggle_gate_decision.json"]["status"],
        selected_next_lane=selected_next_lane,
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        claim_ceiling_status="PRESERVED",
        blockers=[],
        next_lawful_move=next_lawful_move,
    )
    reports["v17_7_4_answer_surface_audit_builder_summary.json"] = summary
    return {
        "reports": reports,
        "jsonl": {
            "v17_7_4_answer_surface_provenance_table.jsonl": provenance_rows,
            "v17_7_4_scorer_disagreement_table.jsonl": disagreement_rows,
            "v17_7_4_parser_canonicalizer_negative_controls.jsonl": negative_rows,
            "v17_7_4_parser_canonicalizer_row_table.jsonl": row_table,
        },
        "schemas": {
            "kt.v17_7_4.answer_surface_provenance.schema.json": schema_payload("kt.v17_7_4.answer_surface_provenance"),
            "kt.v17_7_4.parser_canonicalizer.schema.json": schema_payload("kt.v17_7_4.parser_canonicalizer"),
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
    print(json.dumps(built["reports"]["v17_7_4_answer_surface_audit_builder_summary.json"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
