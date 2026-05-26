from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PROGRAM_ID = "KT_G3_2_SIGNAL_DENSITY_AND_CAUSAL_REPAIR_METALLURGY_SUPERLANE_V1_1"
PACKET_BUILD_HEAD = "8a100dd359d056db886f6409705f62d8195497a4"
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
    out = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktg3_v3_outputs")).resolve()
    out.mkdir(parents=True, exist_ok=True)
    outputs = {
        "expanded_detached_benchmark_receipt.json": scaffold("kt.g32.expanded_detached_benchmark_receipt.v1"),
        "benchmark_scorecard.json": scaffold("kt.g32.benchmark_scorecard.v1"),
        "verified_work_per_token_scorecard.json": scaffold("kt.g32.verified_work_per_token_scorecard.v1"),
        "route_regret_closure_scorecard.json": scaffold("kt.g32.route_regret_closure_scorecard.v1"),
        "scar_delta_receipt.json": scaffold("kt.g32.scar_delta_receipt.v1"),
        "anti_goodhart_scorecard.json": scaffold("kt.g32.anti_goodhart_scorecard.v1"),
        "evaluator_integrity_receipt.json": scaffold("kt.g32.evaluator_integrity_receipt.v1"),
        "human_anchor_anti_collapse_receipt.json": scaffold("kt.g32.human_anchor_anti_collapse_receipt.v1"),
        "lobe_specialization_scorecard.json": scaffold("kt.g32.lobe_specialization_scorecard.v1"),
        "long_horizon_state_tracking_receipt.json": scaffold("kt.g32.long_horizon_state_tracking_receipt.v1"),
        "assurance_case_claim_compiler_receipt.json": scaffold("kt.g32.assurance_case_claim_compiler_receipt.v1"),
        "clinical_promotion_receipt.json": scaffold("kt.g32.clinical_promotion_receipt.v1"),
        "repair_corpus_provenance_scan.json": scaffold("kt.g32.repair_corpus_provenance_scan.v1"),
        "g32_human_anchor_manifest.json": scaffold("kt.g32.human_anchor_manifest.v1"),
    }
    for name, obj in outputs.items():
        write_json(out / name, obj)
    (out / "benchmark_predictions.jsonl").write_text("", encoding="utf-8")
    (out / "route_regret_matrix.jsonl").write_text("", encoding="utf-8")
    (out / "operator_summary.md").write_text("G3.2 compute scaffold emitted; runtime measurement still required.\n", encoding="utf-8")
    assessment = out / "ASSESSMENT_ONLY.zip"
    with zipfile.ZipFile(assessment, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in sorted(out.iterdir()):
            if item.is_file() and item != assessment:
                zf.write(item, item.name)
    summary = {
        "schema_id": "kt.g32.compute_packet_summary.v1",
        "created_utc": utc_now(),
        "status": SCAFFOLD_STATUS,
        "promotion_eligible": False,
        "requires_followup_measurement": True,
        "assessment_zip": str(assessment),
        "claim_ceiling_preserved": True,
    }
    write_json(out / "assessment_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
