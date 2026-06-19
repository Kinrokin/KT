from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any

from ktstop300_common import (
    ADMISSION,
    PACKETS,
    REPORTS,
    ROOT,
    STOP300_PACKET,
    STOP300_RUN_MODE,
    read_json,
    rel,
    sha256_file,
    write_json,
)


CONSUMED_INTERVALS = {
    "BUD25": [0, 25],
    "BUD100": [25, 125],
    "512BASE": [125, 325],
    "PARETO": [325, 425],
    "STOP50": [425, 475],
}


def consumed_interval_ids() -> set[int]:
    out: set[int] = set()
    for start, end in CONSUMED_INTERVALS.values():
        out.update(range(start, end))
    return out


def row_id_to_int(row_id: str) -> int | None:
    match = re.fullmatch(r"gsm8k_test_(\d+)", str(row_id))
    return int(match.group(1)) if match else None


def packet_member_text(member: str) -> str:
    with zipfile.ZipFile(STOP300_PACKET) as zf:
        return zf.read(member).decode("utf-8-sig")


def packet_json(member: str) -> Any:
    return json.loads(packet_member_text(member))


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8-sig")


def main() -> int:
    errors: list[str] = []
    selected_manifest = read_json(ADMISSION / "stop300_stratified_hash_selected_manifest.json")
    timing_manifest = read_json(ADMISSION / "stop300_timing_panel_manifest.json")
    edge_manifest = read_json(ADMISSION / "stop300_edge_regression_manifest.json")
    config = packet_json("runtime/ktstop300_config.json")
    runner = packet_member_text("runtime/KT_CANONICAL_RUNNER.py")
    builder = source("scripts/build_ktstop300_packet.py")

    selected_indices = [int(row["split_index"]) for row in selected_manifest["rows"]]
    consumed = consumed_interval_ids()
    overlap_indices = sorted(idx for idx in selected_indices if idx in consumed)
    overlap_by_interval = {
        name: sorted(idx for idx in overlap_indices if start <= idx < end)
        for name, (start, end) in CONSUMED_INTERVALS.items()
    }

    defects = []
    if overlap_indices:
        defects.append("selected_fresh_rows_overlap_authoritative_consumed_rows")
    if '["L0_LEGACY_NO_DETECTOR", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]' in runner and "M0_STREAMING_DETECTOR_MONITOR_ONLY" not in runner.split("for row in rows", 1)[-1]:
        defects.append("m0_monitor_arm_declared_but_not_executed")
    if "timing_panel_rows" not in runner or "config[\"timing_panel_rows\"]" not in runner:
        defects.append("timing_panel_declared_but_not_executed")
    if "edge_regression_rows" not in runner or "config[\"edge_regression_rows\"]" not in runner:
        defects.append("edge_regression_declared_but_not_executed")
    if "MEASURED_OUTPUTS_EMITTED_PENDING_COURT" in runner or "result_court" not in runner:
        defects.append("final_hostile_result_court_not_executed")
    if "subprocess.check_output" in builder and "rg" in builder:
        defects.append("freshness_depends_on_repo_text_search_not_authority_registry")
    if "torch.cuda.Event" not in runner:
        defects.append("cuda_event_timing_absent")
    if "PARTIAL_MEASURED_OUTPUTS.zip" not in runner:
        defects.append("partial_checkpoint_publication_absent")

    if not STOP300_PACKET.exists():
        errors.append("missing V1 packet")
    if config.get("run_mode") != STOP300_RUN_MODE:
        errors.append("V1 run mode mismatch")
    if len(timing_manifest.get("rows", [])) != 60:
        errors.append("V1 timing manifest row count mismatch")
    edge_rows = edge_manifest.get("second_marker_rows", []) + edge_manifest.get("natural_eos_rows", [])
    if len(edge_rows) != 12:
        errors.append("V1 edge manifest row count mismatch")

    assessment_candidates = [
        ROOT / "evidence" / "KT_STOP300_V1_ASSESSMENT_ONLY.zip",
        ROOT / "downloads" / "KT_STOP300_V1_ASSESSMENT_ONLY.zip",
    ]
    v1_assessment_exists = any(path.exists() for path in assessment_candidates)
    status = "BLOCKED_PRE_GPU_EXECUTION_CONTRACT_MISMATCH" if defects or overlap_indices else "PASS_NO_BLOCKER_FOUND"
    receipt = {
        "schema_id": "kt.stop300.v1_pre_gpu_execution_audit.v1",
        "status": status,
        "packet_path": rel(STOP300_PACKET),
        "packet_sha256": sha256_file(STOP300_PACKET),
        "v1_gpu_run_status": "UNKNOWN_ASSESSMENT_PRESENT" if v1_assessment_exists else "NOT_RUN",
        "selected_row_count": len(selected_indices),
        "authoritative_consumed_interval_count": len(consumed),
        "overlap_count": len(overlap_indices),
        "overlap_indices": overlap_indices,
        "overlap_by_interval": overlap_by_interval,
        "defects": defects,
        "errors": errors,
        "inspected_files": [
            "scripts/build_ktstop300_packet.py",
            "packets/ktstop300_v1.zip",
            "admission/stop300_stratified_hash_selected_manifest.json",
            "admission/stop300_timing_panel_manifest.json",
            "admission/stop300_edge_regression_manifest.json",
        ],
        "claim_ceiling_status": "PRESERVED",
    }
    write_json(REPORTS / "stop300_v1_pre_gpu_execution_audit.json", receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    if errors:
        raise SystemExit("STOP300 V1 audit failed structurally: " + "; ".join(errors))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
