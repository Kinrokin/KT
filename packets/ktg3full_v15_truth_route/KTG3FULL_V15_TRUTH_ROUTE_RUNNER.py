from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PACKET_BUILD_HEAD = "380ba22ecb4c380d90d267e414603c89168c2e76"
EXPECTED_PACKET_PATH = "packets/ktg3full_v15_truth_route.zip"
SCAFFOLD_STATUS = "SCAFFOLD_EMITTED_NOT_EARNED"
REQUIRED_ARMS = [
  "base_raw",
  "base_kt_hat_compact",
  "formal_math_repair_adapter_global",
  "route_regret_policy_adapter_global",
  "math_act_adapter_global",
  "formal_math_router_label_bound",
  "formal_math_router_math_act_feature_bound",
  "oracle_math_router"
]
REQUIRED_SLICES = [
  "original_200_slice",
  "non_gsm8k_math_slice",
  "math_wording_variation_slice",
  "numeric_reasoning_slice",
  "logic_quantitative_slice",
  "claim_boundary_slice",
  "evidence_grounding_slice"
]


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_rows() -> list[dict]:
    candidates = [
        Path(os.environ.get("KT_V15_PREDICTIONS_JSONL", "")),
        Path(os.environ.get("KT_V15_INPUT_DIR", "/kaggle/input/ktg3full-v15-truth-route")) / "benchmark_predictions.jsonl",
        Path("benchmark_predictions.jsonl"),
    ]
    for path in candidates:
        if str(path) and path.exists() and path.is_file() and path.stat().st_size > 0:
            return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    return []


def emit_blocked(out: Path) -> int:
    blocker = {
        "schema_id": "kt.ktg3full_v15.blocker_receipt.v1",
        "status": SCAFFOLD_STATUS,
        "promotion_eligible": False,
        "requires_followup_measurement": True,
        "outcome": "KTG3FULL_V15_BLOCKED__MISSING_MEASURED_ROWS",
        "missing": "benchmark_predictions.jsonl",
        "claim_ceiling_preserved": True,
    }
    write_json(out / "BLOCKER_RECEIPT.json", blocker)
    write_json(out / "assessment_summary.json", blocker)
    print(json.dumps(blocker, indent=2, sort_keys=True))
    return 2


def main() -> int:
    out = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktg3full_v15_outputs")).resolve()
    out.mkdir(parents=True, exist_ok=True)
    rows = load_rows()
    if not rows:
        return emit_blocked(out)
    summary = {
        "schema_id": "kt.ktg3full_v15.assessment_summary.v1",
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "MEASURED_RUNTIME_INPUT_ACCEPTED",
        "rows": len(rows),
        "required_arms": REQUIRED_ARMS,
        "required_slices": REQUIRED_SLICES,
        "adapter_promotion_authorized": False,
        "route_promotion_authorized": False,
        "claim_ceiling_preserved": True,
    }
    receipts = {
        "score_reconciliation_receipt.json": summary,
        "adapter_identity_receipt.json": {
            "schema_id": "kt.adapter_identity_receipt.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "claim_ceiling_preserved": True,
        },
        "adapter_isolation_receipt.json": {
            "schema_id": "kt.adapter_isolation_receipt.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "claim_ceiling_preserved": True,
        },
        "dataset_label_blind_routing_receipt.json": {
            "schema_id": "kt.dataset_label_blind_routing_receipt.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "claim_ceiling_preserved": True,
        },
        "math_act_feature_router_receipt.json": {
            "schema_id": "kt.math_act_feature_router_receipt.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "claim_ceiling_preserved": True,
        },
        "structure_bound_routing_scorecard.json": {
            "schema_id": "kt.structure_bound_routing_scorecard.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "structure_bound_claim_authorized": False,
            "claim_ceiling_preserved": True,
        },
        "truth_integrity_audit_receipt.json": {
            "schema_id": "kt.truth_integrity_audit_receipt.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "claim_ceiling_preserved": True,
        },
        "emergency_repair_subprotocol_receipt.json": {
            "schema_id": "kt.emergency_repair_subprotocol_receipt.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "claim_ceiling_preserved": True,
        },
        "claim_admissibility_casefile.json": {
            "schema_id": "kt.claim_admissibility_casefile.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "claim_ceiling_preserved": True,
        },
        "self_deception_risk_scorecard.json": {
            "schema_id": "kt.self_deception_risk_scorecard.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "claim_ceiling_preserved": True,
        },
    }
    for name, payload in receipts.items():
        write_json(out / name, payload)
    (out / "operator_summary.md").write_text("V15 truth-route runtime accepted measured rows. Promotion remains unauthorized.\n", encoding="utf-8")
    assessment = out / "ASSESSMENT_ONLY.zip"
    with zipfile.ZipFile(assessment, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in sorted(out.iterdir()):
            if item.is_file() and item != assessment:
                zf.write(item, item.name)
    write_json(out / "assessment_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
