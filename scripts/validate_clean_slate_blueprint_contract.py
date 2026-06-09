from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ALLOWED_LICENSES = {"CC0", "CC-BY-4.0", "CC-BY-SA-4.0", "MIT", "Apache-2.0", "PUBLIC_DOMAIN", "ORIGINAL_AUTHORED"}
ALLOWED_TIERS = {"T1_FORMAT_ONLY", "T2_NUMERIC_VERIFIED", "T3_STEP_VERIFIED", "T4_HUMAN_REVIEWED"}
ALLOWED_VERIFICATION = {"V1_NUMERIC", "V2_STEP_CHECKED", "V3_CODE_OR_HUMAN_VERIFIED"}
REQUIRED_FIELDS = {
    "schema_id",
    "row_id",
    "source_id",
    "problem",
    "solution",
    "answer",
    "answer_visibility",
    "trust_tier",
    "verification_class",
    "curriculum_stage",
    "license",
    "split",
    "problem_hash",
    "answer_hash",
    "expected_answer_model_visible",
    "doctrine_contamination_scan_pass",
    "train_eval_firewall_pass",
}
BANNED_TERMS = [
    "KT-hat",
    "ReproLock",
    "EPC",
    "lobe",
    "router",
    "route",
    "court",
    "gate",
    "receipt",
    "claim ceiling",
    "scar",
    "delta",
    "truth engine",
    "governance",
    "H0",
    "operator",
    "oracle label",
    "safetensors",
]


def load_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError(f"row {line_no} is not an object")
        row["_line_no"] = line_no
        rows.append(row)
    return rows


def row_errors(row: dict[str, Any], split_hashes: dict[str, set[str]]) -> list[str]:
    errors: list[str] = []
    missing = sorted(REQUIRED_FIELDS.difference(row))
    if missing:
        errors.append("missing_fields:" + ",".join(missing))
    if row.get("schema_id") != "kt.v17_7_4.clean_slate_math_dataset_row.v1":
        errors.append("bad_schema_id")
    if row.get("trust_tier") not in ALLOWED_TIERS:
        errors.append("trust_tier_not_training_candidate")
    if row.get("verification_class") not in ALLOWED_VERIFICATION:
        errors.append("verification_class_not_training_candidate")
    if row.get("license") not in ALLOWED_LICENSES:
        errors.append("license_not_allowed")
    if row.get("answer_visibility") != "LABEL_ONLY":
        errors.append("answer_not_label_only")
    if row.get("expected_answer_model_visible") is not False:
        errors.append("expected_answer_model_visible")
    if row.get("doctrine_contamination_scan_pass") is not True:
        errors.append("doctrine_scan_failed")
    if row.get("train_eval_firewall_pass") is not True:
        errors.append("train_eval_firewall_failed")
    if not isinstance(row.get("curriculum_stage"), int) or not 0 <= row.get("curriculum_stage", -1) <= 9:
        errors.append("curriculum_stage_out_of_range")
    text = "\n".join(str(row.get(field, "")) for field in ("problem", "solution", "source_id", "source_origin"))
    lowered = text.lower()
    for term in BANNED_TERMS:
        if term.lower() in lowered:
            errors.append(f"doctrine_term:{term}")
            break
    problem_hash = str(row.get("problem_hash") or "")
    split = str(row.get("split") or "")
    other_splits = {candidate for candidate, hashes in split_hashes.items() if candidate != split and problem_hash in hashes}
    if other_splits:
        errors.append("problem_hash_cross_split_collision:" + ",".join(sorted(other_splits)))
    if row.get("trust_tier") in {"T3_STEP_VERIFIED", "T4_HUMAN_REVIEWED"} and len(str(row.get("solution") or "").split()) < 6:
        errors.append("verified_step_row_has_sparse_solution")
    return errors


def density(tier_counts: Counter[str], valid_count: int) -> float:
    if not valid_count:
        return 0.0
    return round((tier_counts.get("T4_HUMAN_REVIEWED", 0) + 0.5 * tier_counts.get("T3_STEP_VERIFIED", 0)) / valid_count, 6)


def validate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    split_hashes: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        split_hashes[str(row.get("split") or "")].add(str(row.get("problem_hash") or ""))

    valid_rows: list[dict[str, Any]] = []
    invalid_rows: list[dict[str, Any]] = []
    false_positives = 0
    false_negatives = 0
    expected_valid_total = 0
    expected_invalid_total = 0
    t0_escape = 0
    split_collision_count = 0
    tier_counts: Counter[str] = Counter()
    verification_counts: Counter[str] = Counter()

    for row in rows:
        errors = row_errors(row, split_hashes)
        observed_valid = not errors
        expected_valid = bool(row.get("synthetic_expected_valid", observed_valid))
        if expected_valid:
            expected_valid_total += 1
        else:
            expected_invalid_total += 1
        if observed_valid:
            valid_rows.append(row)
            tier_counts[str(row.get("trust_tier"))] += 1
            verification_counts[str(row.get("verification_class"))] += 1
        else:
            invalid_rows.append({"row_id": row.get("row_id"), "line_no": row.get("_line_no"), "errors": errors})
        if observed_valid and not expected_valid:
            false_positives += 1
        if not observed_valid and expected_valid:
            false_negatives += 1
        if observed_valid and row.get("trust_tier") == "T0_REJECT":
            t0_escape += 1
        if any(error.startswith("problem_hash_cross_split_collision") for error in errors):
            split_collision_count += 1

    false_positive_rate = round(false_positives / expected_invalid_total, 6) if expected_invalid_total else 0.0
    false_negative_rate = round(false_negatives / expected_valid_total, 6) if expected_valid_total else 0.0
    capability_density = density(tier_counts, len(valid_rows))
    passed = (
        len(rows) >= 100
        and t0_escape == 0
        and false_positive_rate < 0.02
        and false_negative_rate < 0.01
        and capability_density >= 0.30
        and split_collision_count > 0
    )
    return {
        "schema_id": "kt.v17_7_4.clean_slate_dry_run_manifest.v1",
        "status": "PASS" if passed else "FAIL",
        "pass": passed,
        "row_count": len(rows),
        "valid_candidate_count": len(valid_rows),
        "invalid_row_count": len(invalid_rows),
        "expected_valid_total": expected_valid_total,
        "expected_invalid_total": expected_invalid_total,
        "false_positive_count": false_positives,
        "false_negative_count": false_negatives,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
        "t0_escape_count": t0_escape,
        "split_hash_collision_count": split_collision_count,
        "tier_counts": dict(sorted(tier_counts.items())),
        "verification_class_counts": dict(sorted(verification_counts.items())),
        "capability_density": capability_density,
        "invalid_row_samples": invalid_rows[:20],
        "dataset_generation_authority": False,
        "training_authority": False,
        "runtime_authority": False,
        "promotion_authority": False,
        "claim_ceiling_preserved": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", required=True)
    parser.add_argument("--report")
    args = parser.parse_args()
    report = validate(load_rows(Path(args.rows)))
    if args.report:
        target = Path(args.report)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
