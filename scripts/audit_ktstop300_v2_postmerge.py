from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from ktstop300_common import REPORTS, STOP300_V2_PACKET, STOP300_V2_RUN_MODE, read_json, rel, sha256_file, write_json


EXPECTED_V2_SHA = "72948378246db869db4bb37f3c4f5f861c737034d63058331fe94eece02d4f93"


def read_member(zf: zipfile.ZipFile, name: str) -> str:
    return zf.read(name).decode("utf-8-sig")


def main() -> int:
    defects: list[str] = []
    errors: list[str] = []
    if not STOP300_V2_PACKET.exists():
        raise SystemExit("missing STOP300 V2 packet")
    actual_sha = sha256_file(STOP300_V2_PACKET)
    if actual_sha != EXPECTED_V2_SHA:
        errors.append(f"V2 sha mismatch: {actual_sha}")

    with zipfile.ZipFile(STOP300_V2_PACKET) as zf:
        names = set(zf.namelist())
        manifest = json.loads(read_member(zf, "PACKET_MANIFEST.json"))
        config = json.loads(read_member(zf, "runtime/ktstop300_v2_config.json"))
        bootstrap = read_member(zf, "KAGGLE_BOOTSTRAP_CELL.py")
        runner = read_member(zf, "runtime/KT_CANONICAL_RUNNER.py")
        result_court = read_member(zf, "runtime/result_court.py")
        hf_publisher = read_member(zf, "runtime/hf_publisher.py")
        checkpoint = read_member(zf, "runtime/checkpoint_manager.py")
        env = read_member(zf, "runtime/environment_preflight.py")

        if manifest.get("run_mode") != STOP300_V2_RUN_MODE:
            errors.append("V2 run mode mismatch")
        if "sys.path" not in bootstrap or "chdir" not in bootstrap:
            defects.append("bootstrap_import_path_can_fail_before_preflight")
        if config.get("packet_sha256") != EXPECTED_V2_SHA:
            defects.append("packet_embeds_stale_or_missing_first_build_sha")
        if "KT_AUTHORIZED_PACKET_SHA256" not in runner:
            defects.append("external_final_packet_sha_authority_absent")
        if "PARTIAL_MEASURED_OUTPUTS.zip" not in checkpoint:
            defects.append("partial_zip_present_but_not_hf_reset_durable")
        if "upload_file" not in hf_publisher and "upload_folder" not in hf_publisher:
            defects.append("hf_publisher_does_not_upload")
        if "linear4bit_module_count_gt_zero_required" in env and "Linear4bit" not in env:
            defects.append("model_level_4bit_attestation_absent")
        if "raw_generated_token_ids[:boundary_generated_token_index_exclusive]" not in runner:
            defects.append("authoritative_preserved_token_ids_not_exact_original_slice")
        if "first_boundary_decision" not in runner:
            defects.append("m0_first_accepted_boundary_not_immutable")
        if "range(3)" not in runner and "repetition in [0, 1, 2]" not in runner:
            defects.append("timing_full_3x3_panel_not_physically_executed")
        if "warmup" not in runner.lower() or "3" not in runner:
            defects.append("three_warmups_per_arm_not_executed")
        if "status = \"PASS_TOKEN_ONLY" in result_court and "BLOCK_CORRECTNESS_DAMAGE" not in result_court.split("status = \"PASS_TOKEN_ONLY", 1)[0]:
            defects.append("result_court_can_pass_correctness_damage")
        if "FIRST_WRONG_LATER_CORRECT" not in result_court:
            defects.append("result_court_lacks_first_wrong_later_correct_block")

    with tempfile.TemporaryDirectory() as td:
        extract = Path(td) / "packet"
        other = Path(td) / "other"
        extract.mkdir()
        other.mkdir()
        with zipfile.ZipFile(STOP300_V2_PACKET) as zf:
            zf.extractall(extract)
        proc = subprocess.run(
            [sys.executable, str(extract / "KAGGLE_BOOTSTRAP_CELL.py")],
            cwd=other,
            env={**dict(), **__import__("os").environ, "KT_STOP300_BOOTSTRAP_SMOKE_ONLY": "1"},
            text=True,
            capture_output=True,
            timeout=30,
        )
        if proc.returncode != 0:
            defects.append("bootstrap_subprocess_from_unrelated_cwd_failed")

    assessment_candidates = [Path("evidence/KT_STOP300_V2_ASSESSMENT_ONLY.zip"), Path("KT_STOP300_V2_ASSESSMENT_ONLY.zip")]
    checkpoint_candidates = [Path("evidence/KT_STOP300_V2_WRAPPER_COLLECTION.zip"), Path("PARTIAL_MEASURED_OUTPUTS.zip")]
    v2_run_exists = any(path.exists() for path in assessment_candidates + checkpoint_candidates)
    receipt = {
        "schema_id": "kt.stop300.v2_postmerge_semantic_audit.v1",
        "status": "BLOCKED_GPU_RUN_POSTMERGE_SEMANTIC_DEFECTS" if defects else "PASS_NO_POSTMERGE_DEFECT_FOUND",
        "packet_path": rel(STOP300_V2_PACKET),
        "packet_sha256": actual_sha,
        "v2_gpu_run_status": "UNKNOWN_DURABLE_ARTIFACT_PRESENT" if v2_run_exists else "NOT_RUN",
        "defects": defects,
        "errors": errors,
        "claim_ceiling_status": "PRESERVED",
    }
    write_json(REPORTS / "stop300_v2_postmerge_semantic_audit.json", receipt)
    write_json(
        REPORTS / "stop300_v2_supersession_receipt.json",
        {
            "schema_id": "kt.stop300.v2_supersession_receipt.v1",
            "status": "SUPERSEDED_BEFORE_GPU_EXECUTION" if defects and not v2_run_exists else "NOT_SUPERSEDED",
            "v2_packet_path": rel(STOP300_V2_PACKET),
            "v2_packet_sha256": actual_sha,
            "v2_gpu_run_status": receipt["v2_gpu_run_status"],
            "superseded_by": "packets/ktstop300_v3.zip",
            "claim_ceiling_status": "PRESERVED",
        },
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    if errors:
        raise SystemExit("; ".join(errors))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
