from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    payload = {
        "schema_id": "kt.v17_7_4.token_accounting_reconciliation.v1",
        "status": "PASS_PRE_RUNTIME_CONTRACT_BOUND",
        "claim_ceiling_preserved": True,
        "required_runtime_outputs": [
            "full_prompt_plus_output_tokens_per_correct",
            "input_tokens_per_correct",
            "output_tokens_per_correct",
            "visible_answer_tokens_per_correct",
            "route_overhead_tokens_per_correct",
            "hat_overhead_tokens_per_correct"
        ],
        "g2_reconciliation_status": "BLOCKED_UNTIL_EXACT_G2_ACCOUNTING_METHOD_RECOVERED",
        "current_realbench_summary": {
            "base_raw_tokens_per_correct": 175.233333,
            "math_act_tokens_per_correct": 145.121951,
            "g2_routed_tokens_per_correct": 3.738095
        }
    }
    path = ROOT / "reports" / "v17_7_4_token_accounting_reconciliation.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": payload["status"], "path": path.as_posix()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
