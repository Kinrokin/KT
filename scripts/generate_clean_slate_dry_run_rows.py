from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


LICENSES = ["CC0", "CC-BY-4.0", "MIT", "Apache-2.0", "ORIGINAL_AUTHORED"]


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_row(
    index: int,
    *,
    trust_tier: str,
    verification_class: str,
    curriculum_stage: int,
    license_name: str,
    split: str,
    expected_valid: bool,
    problem: str | None = None,
    solution: str | None = None,
    answer: str | None = None,
    answer_visibility: str = "LABEL_ONLY",
    expected_answer_model_visible: bool = False,
    doctrine_pass: bool = True,
    firewall_pass: bool = True,
    problem_hash_override: str | None = None,
) -> dict[str, Any]:
    a = answer if answer is not None else str(index + 7)
    p = problem or f"If a basket has {index + 2} apples and gains 5 apples, how many apples are there?"
    s = solution or f"Start with {index + 2}. Add 5. The total is {index + 7}."
    return {
        "schema_id": "kt.v17_7_4.clean_slate_math_dataset_row.v1",
        "row_id": f"dryrun_{index:03d}",
        "source_id": "SYNTHETIC_DRY_RUN_NOT_DATASET",
        "source_origin": "contract_test_generator",
        "problem": p,
        "solution": s,
        "answer": a,
        "answer_visibility": answer_visibility,
        "trust_tier": trust_tier,
        "verification_class": verification_class,
        "curriculum_stage": curriculum_stage,
        "license": license_name,
        "split": split,
        "problem_hash": problem_hash_override or digest(p),
        "answer_hash": digest(a),
        "expected_answer_model_visible": expected_answer_model_visible,
        "doctrine_contamination_scan_pass": doctrine_pass,
        "train_eval_firewall_pass": firewall_pass,
        "synthetic_expected_valid": expected_valid,
    }


def build_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    idx = 0
    for _ in range(40):
        rows.append(
            make_row(
                idx,
                trust_tier="T2_NUMERIC_VERIFIED",
                verification_class="V1_NUMERIC",
                curriculum_stage=idx % 4,
                license_name=LICENSES[idx % len(LICENSES)],
                split="train",
                expected_valid=True,
            )
        )
        idx += 1
    for _ in range(35):
        rows.append(
            make_row(
                idx,
                trust_tier="T3_STEP_VERIFIED",
                verification_class="V2_STEP_CHECKED",
                curriculum_stage=2 + (idx % 4),
                license_name=LICENSES[idx % len(LICENSES)],
                split="train",
                expected_valid=True,
                solution=f"Let x = {idx + 2}. The operation is x + 5. Therefore x + 5 = {idx + 7}.",
            )
        )
        idx += 1
    for _ in range(15):
        rows.append(
            make_row(
                idx,
                trust_tier="T4_HUMAN_REVIEWED",
                verification_class="V3_CODE_OR_HUMAN_VERIFIED",
                curriculum_stage=4 + (idx % 3),
                license_name=LICENSES[idx % len(LICENSES)],
                split="train",
                expected_valid=True,
                solution=f"Checked invariant: ({idx + 2}) + 5 == {idx + 7}. Answer: {idx + 7}.",
            )
        )
        idx += 1
    for _ in range(5):
        rows.append(
            make_row(
                idx,
                trust_tier="T1_FORMAT_ONLY",
                verification_class="V1_NUMERIC",
                curriculum_stage=idx % 3,
                license_name=LICENSES[idx % len(LICENSES)],
                split="review",
                expected_valid=True,
            )
        )
        idx += 1

    collision_hash = digest("collision problem")
    bad_rows = [
        make_row(idx, trust_tier="T0_REJECT", verification_class="V0_UNVERIFIED", curriculum_stage=0, license_name="UNKNOWN", split="train", expected_valid=False),
        make_row(idx + 1, trust_tier="T2_NUMERIC_VERIFIED", verification_class="V1_NUMERIC", curriculum_stage=1, license_name="UNKNOWN", split="train", expected_valid=False),
        make_row(
            idx + 2,
            trust_tier="T2_NUMERIC_VERIFIED",
            verification_class="V1_NUMERIC",
            curriculum_stage=1,
            license_name="CC0",
            split="train",
            expected_valid=False,
            problem="This row contains KT-hat doctrine contamination and must be rejected.",
            doctrine_pass=False,
        ),
        make_row(
            idx + 3,
            trust_tier="T2_NUMERIC_VERIFIED",
            verification_class="V1_NUMERIC",
            curriculum_stage=1,
            license_name="CC0",
            split="train",
            expected_valid=False,
            answer_visibility="MODEL_VISIBLE_BLOCKED",
            expected_answer_model_visible=True,
        ),
        make_row(
            idx + 4,
            trust_tier="T2_NUMERIC_VERIFIED",
            verification_class="V1_NUMERIC",
            curriculum_stage=1,
            license_name="CC0",
            split="train",
            expected_valid=False,
            problem="collision problem",
            problem_hash_override=collision_hash,
            firewall_pass=False,
        ),
        make_row(
            idx + 5,
            trust_tier="T2_NUMERIC_VERIFIED",
            verification_class="V1_NUMERIC",
            curriculum_stage=1,
            license_name="CC0",
            split="heldout",
            expected_valid=False,
            problem="collision problem",
            problem_hash_override=collision_hash,
            firewall_pass=False,
        ),
    ]
    rows.extend(bad_rows)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = build_rows()
    output.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows), encoding="utf-8")
    print(json.dumps({"schema_id": "kt.v17_7_4.clean_slate_dry_run_manifest.v1", "status": "PASS_GENERATED", "row_count": len(rows), "dataset_generation_authority": False, "training_authority": False}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
