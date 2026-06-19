from __future__ import annotations

import json
import zipfile

from ktstop300_common import REPORTS, STOP300_V4_PACKET, rel, sha256_file, write_json


EXPECTED_V4_SHA = "32ed95da638d72dc3355277a9b0c70686c33e48fad76b48fb2efffc6d26c3ab3"


def main() -> int:
    packet_sha = sha256_file(STOP300_V4_PACKET)
    with zipfile.ZipFile(STOP300_V4_PACKET) as zf:
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
    posthoc_markers = [
        "outputs = model.generate(" in runner,
        "raw_ids = outputs[0].tolist()[len(prompt_token_ids):]" in runner,
        "for index, token_id in enumerate(raw_ids):" in runner,
        'if arm_id == "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE":' in runner and "break" in runner,
    ]
    online_markers_absent = "StoppingCriteriaList" not in runner and "stopping_criteria=" not in runner
    status = (
        "BLOCKED_POSTHOC_STOP_NOT_PHYSICAL_TERMINATION"
        if packet_sha == EXPECTED_V4_SHA and all(posthoc_markers) and online_markers_absent
        else "BLOCKER_V4_POSTHOC_AUDIT_INCONCLUSIVE"
    )
    audit = {
        "schema_id": "kt.stop300.v4.generation_time_execution_audit.v1",
        "status": status,
        "packet_path": rel(STOP300_V4_PACKET),
        "packet_sha256": packet_sha,
        "expected_packet_sha256": EXPECTED_V4_SHA,
        "v4_gpu_run_status": "NOT_RUN",
        "posthoc_evidence": {
            "full_generation_before_detector": posthoc_markers[0],
            "raw_ids_sliced_after_generation": posthoc_markers[1],
            "detector_iterates_over_completed_raw_ids": posthoc_markers[2],
            "s1_break_is_python_loop_not_transformers_stop": posthoc_markers[3],
            "transformers_stopping_criteria_absent": online_markers_absent,
        },
        "claim_ceiling_status": "PRESERVED",
    }
    supersession = {
        "schema_id": "kt.stop300.v4.supersession_receipt.v1",
        "status": "SUPERSEDED_BEFORE_GPU_EXECUTION" if status == "BLOCKED_POSTHOC_STOP_NOT_PHYSICAL_TERMINATION" else "BLOCKER",
        "superseded_packet": rel(STOP300_V4_PACKET),
        "superseded_packet_sha256": packet_sha,
        "replacement_packet": "packets/ktstop300_v4_1.zip",
        "replacement_reason": "S1 stop path must be wired through Transformers stopping_criteria for physical generation-time termination.",
        "claim_ceiling_status": "PRESERVED",
    }
    write_json(REPORTS / "stop300_v4_generation_time_execution_audit.json", audit)
    write_json(REPORTS / "stop300_v4_supersession_receipt.json", supersession)
    print(json.dumps({"audit": audit, "supersession": supersession}, indent=2, sort_keys=True))
    if status != "BLOCKED_POSTHOC_STOP_NOT_PHYSICAL_TERMINATION":
        raise SystemExit(status)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
