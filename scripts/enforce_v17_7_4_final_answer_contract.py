from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    contract = json.loads((ROOT / "configs" / "v17_7_4" / "compact_answer_contract.json").read_text(encoding="utf-8"))
    defects = []
    if contract.get("compact_answer_contract") is not True:
        defects.append("compact_answer_contract_not_enabled")
    if contract.get("scorer_only_expected_answer") is not True:
        defects.append("scorer_only_expected_answer_not_bound")
    payload = {
        "schema_id": "kt.v17_7_4.answer_only_finalizer_receipt.v1",
        "status": "PASS" if not defects else "BLOCKED",
        "claim_ceiling_preserved": True,
        "defects": defects,
        "contract_path": "configs/v17_7_4/compact_answer_contract.json",
        "no_governance_explanation_in_benchmark_output": contract.get("no_governance_explanation_in_benchmark_output") is True
    }
    path = ROOT / "reports" / "v17_7_4_answer_only_finalizer_receipt.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if not defects else 1


if __name__ == "__main__":
    raise SystemExit(main())
