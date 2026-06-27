#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]


def load(rel: str):
    return json.loads((ROOT / rel).read_text(encoding="utf-8-sig"))


def check(schema_rel: str, object_rel: str, transform=None) -> None:
    schema = load(schema_rel)
    obj = load(object_rel)
    if transform:
        obj = transform(obj)
    errors = sorted(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(obj), key=lambda e: list(e.path))
    if errors:
        detail = "; ".join(f"{'.'.join(map(str,e.path))}:{e.message}" for e in errors[:10])
        raise ValueError(f"schema_fail:{object_rel}:{detail}")


def main() -> int:
    pairs = [
        ("schemas/source_evidence_index_v2.schema.json", "SOURCE_EVIDENCE_INDEX.json", None),
        ("schemas/system_evidence_graph_payload.schema.json", "reports/livewire_pr_a_system_evidence_graph_payload.json", None),
        ("schemas/derivation_envelope.schema.json", "reports/livewire_pr_a_system_evidence_graph_payload.envelope.json", None),
        ("schemas/current_program_truth_payload.schema.json", "reports/livewire_pr_a_current_program_truth_payload.json", None),
        ("schemas/stop300_cleanroom_recomputation.schema.json", "evidence/stop300/stop300_cleanroom_recomputation_v2.json", None),
    ]
    for schema_rel, obj_rel, transform in pairs:
        check(schema_rel, obj_rel, transform)
    decisions = load("reports/livewire_pr_a_claim_decisions.json")["decisions"]
    schema = load("schemas/claim_decision.schema.json")
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for i, decision in enumerate(decisions):
        errors = list(validator.iter_errors(decision))
        if errors:
            raise ValueError(f"schema_fail:claim_decision:{i}:{errors[0].message}")
    print(f"json_schema_validation_pass:{len(pairs) + len(decisions)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
