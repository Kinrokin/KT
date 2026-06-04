from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    candidates = []
    for path in [ROOT / "reports", ROOT / "admission", ROOT / "data", ROOT / "packets"]:
        if not path.exists():
            continue
        for child in path.rglob("*"):
            if child.is_file() and child.suffix.lower() in {".json", ".jsonl", ".md", ".txt"}:
                try:
                    text = child.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if "routed_13_lobe_kt_hat_compact" in text and ("119" in text or "126" in text):
                    candidates.append(child.relative_to(ROOT).as_posix())
    recovered = False
    payload = {
        "schema_id": "kt.v17_7_4.g2_sentinel_recovery_search_receipt.v1",
        "status": "BLOCKED",
        "outcome": "KT_BLOCKED__G2_SENTINEL_SOURCE_MISSING",
        "claim_ceiling_preserved": True,
        "exact_g2_prompts_recovered": recovered,
        "candidate_reference_files": candidates[:50],
        "required_missing": [
            "exact G2 sample IDs",
            "exact G2 prompt texts",
            "exact G2 expected answers",
            "exact G2 scoring parser",
            "exact G2 token accounting method"
        ]
    }
    for name in ["g2_sentinel_recovery_search_receipt.json", "g2_sentinel_source_status.json"]:
        path = ROOT / "reports" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    gap_payload = {
        "schema_id": "kt.v17_7_4.g2_compact_path_gap_analysis.v1",
        "status": "BLOCKED",
        "outcome": "KT_BLOCKED__G2_SENTINEL_SOURCE_MISSING",
        "claim_ceiling_preserved": True,
        "g2_anchor": {
            "base_raw_correct": 119,
            "base_raw_total": 200,
            "base_raw_tokens_per_correct": 42.857143,
            "compact_path": "routed_13_lobe_kt_hat_compact",
            "compact_path_correct": 126,
            "compact_path_total": 200,
            "compact_path_tokens_per_correct": 3.738095,
            "compression_gain": 0.912778,
        },
        "current_realbench_anchor": {
            "base_raw_correct": 30,
            "base_raw_total": 50,
            "base_raw_tokens_per_correct": 175.233333,
            "best_current_arm": "math_act_adapter_global",
            "best_current_correct": 41,
            "best_current_total": 50,
            "best_current_tokens_per_correct": 145.121951,
            "compression_gain_over_current_base": 0.171836,
        },
        "conclusion": "G2 compression is not recovered. Exact G2 sentinel prompts and accounting method are required before apples-to-apples compression adjudication.",
        "required_missing": payload["required_missing"],
    }
    path = ROOT / "reports" / "v17_7_4_g2_compact_path_gap_analysis.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(gap_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
