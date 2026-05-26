from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PROGRAM_ID = "KT_ACCOUNTABILITY_KERNEL_AND_SPECIALIST_ROUTING_SUPERLANE_V1"
PACKET_BUILD_HEAD = "9bede81ee8d9b73d177e9f196f0c36f94fe7f15a"
SCAFFOLD_STATUS = "SCAFFOLD_EMITTED_NOT_EARNED"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def scaffold(schema_id: str) -> dict:
    return {
        "schema_id": schema_id,
        "created_utc": utc_now(),
        "status": SCAFFOLD_STATUS,
        "promotion_eligible": False,
        "requires_followup_measurement": True,
        "claim_ceiling_preserved": True,
    }


def main() -> int:
    out = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktg3full_v12_outputs")).resolve()
    out.mkdir(parents=True, exist_ok=True)
    outputs = {
        "benchmark_scorecard.json": scaffold("kt.ktg3full_v12.benchmark_scorecard.v1"),
        "route_regret_closure_scorecard.json": scaffold("kt.ktg3full_v12.route_regret_closure_scorecard.v1"),
        "verified_work_per_token_scorecard.json": scaffold("kt.ktg3full_v12.verified_work_per_token_scorecard.v1"),
        "anti_goodhart_scorecard.json": scaffold("kt.ktg3full_v12.anti_goodhart_scorecard.v1"),
        "evaluator_integrity_receipt.json": scaffold("kt.ktg3full_v12.evaluator_integrity_receipt.v1"),
        "gpu_cleanup_receipt.json": scaffold("kt.ktg3full_v12.gpu_cleanup_receipt.v1"),
        "adapter_isolation_receipt.json": scaffold("kt.adapter_isolation_receipt.v1"),
        "adapter_niche_boundary_scorecard.json": scaffold("kt.adapter_niche_boundary.v1"),
        "formal_math_specialist_router_receipt.json": scaffold("kt.ktg3full_v12.formal_math_specialist_router_receipt.v1"),
        "failure_confession_receipt.json": scaffold("kt.failure_confession_receipt.v1"),
        "success_admissibility_receipt.json": scaffold("kt.success_admissibility_receipt.v1"),
        "self_deception_risk_scorecard.json": scaffold("kt.self_deception_risk_scorecard.v1"),
        "clinical_promotion_receipt.json": scaffold("kt.g3_promotion_ladder_receipt.v1"),
    }
    for name, obj in outputs.items():
        write_json(out / name, obj)
    (out / "benchmark_predictions.jsonl").write_text("", encoding="utf-8")
    (out / "signal_density_matrix.jsonl").write_text("", encoding="utf-8")
    (out / "route_regret_matrix.jsonl").write_text("", encoding="utf-8")
    (out / "operator_summary.md").write_text(
        "KTG3FULL V1.2 specialist-routing packet scaffold emitted. Runtime measurement required before any promotion claim.\n",
        encoding="utf-8",
    )
    assessment = out / "ASSESSMENT_ONLY.zip"
    with zipfile.ZipFile(assessment, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in sorted(out.iterdir()):
            if item.is_file() and item != assessment:
                zf.write(item, item.name)
    summary = {
        "schema_id": "kt.ktg3full_v12.assessment_summary.v1",
        "created_utc": utc_now(),
        "status": SCAFFOLD_STATUS,
        "assessment_zip": str(assessment),
        "promotion_eligible": False,
        "requires_followup_measurement": True,
        "claim_ceiling_preserved": True,
    }
    write_json(out / "assessment_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
