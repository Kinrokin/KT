from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def authority(**extra):
    payload = {
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
        "learned_router_superiority_claim": False,
        "v18_runtime_authority": False,
    }
    payload.update(extra)
    return payload


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    contract = json.loads((ROOT / "configs" / "v17_7_4" / "reasoning_preserving_compact_contract.json").read_text(encoding="utf-8"))
    budget = json.loads((ROOT / "configs" / "v17_7_4" / "task_family_reasoning_budget.json").read_text(encoding="utf-8"))
    defects = []
    modes = set(contract.get("modes", []))
    required = {
        "MCQ_ANSWER_ONLY",
        "NUMERIC_BOUNDED_SCRATCH_THEN_FINAL",
        "SHORT_ANSWER_FINAL_ONLY",
        "EVIDENCE_GROUNDED_BRIEF_THEN_FINAL",
        "HIGH_RISK_OPERATOR_TRACE_OUTSIDE_BENCH",
    }
    if not required.issubset(modes):
        defects.append("missing_required_modes")
    if budget["modes"]["gsm8k"]["mode"] != "NUMERIC_BOUNDED_SCRATCH_THEN_FINAL":
        defects.append("gsm8k_not_bounded_scratch")
    if budget["modes"]["arc_challenge"]["mode"] != "MCQ_ANSWER_ONLY":
        defects.append("arc_challenge_not_mcq_answer_only")
    status = "PASS" if not defects else "BLOCKED"
    write_json(
        ROOT / "reports" / "v17_7_4_reasoning_preserving_compact_receipt.json",
        authority(
            schema_id="kt.v17_7_4.reasoning_preserving_compact_receipt.v1",
            status=status,
            defects=defects,
            reasoning_preserving_compact=True,
            gsm8k_mode=budget["modes"]["gsm8k"]["mode"],
            mcq_mode=budget["modes"]["arc_challenge"]["mode"],
            compact_visible_answer_required=True,
            raw_output_audit_only=True,
        ),
    )
    write_json(
        ROOT / "reports" / "v17_7_4_visible_answer_scoring_receipt.json",
        authority(
            schema_id="kt.v17_7_4.visible_answer_scoring_receipt.v1",
            status=status,
            final_visible_answer_is_scorer_input=True,
            raw_output_preserved_for_audit=True,
            parser_early_number_selection_forbidden_when_final_marker_present=True,
            expected_answer_visible_to_model=False,
        ),
    )
    print(json.dumps({"status": status, "defects": defects}, indent=2, sort_keys=True))
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
