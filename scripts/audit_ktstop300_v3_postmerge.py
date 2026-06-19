from __future__ import annotations

import json
import tempfile
import zipfile
from pathlib import Path

from ktstop300_common import REPORTS, STOP300_V3_PACKET, read_json, rel, sha256_file, write_json


EXPECTED_V3_SHA = "2196dceafa858f910909e1c214c0402ab80868e19db66a25e8614096549d99d9"

REVIEW_THREADS = [
    {
        "id": "PRRT_kwDOQx5TJM6KuHEh",
        "severity": "P1",
        "path": "scripts/validate_ktstop300_v3_packet.py",
        "finding": "Authority flags validated with not manifest.get(key), allowing missing keys to pass.",
        "required_fix": "Require every authority key to exist and be exactly False.",
    },
    {
        "id": "PRRT_kwDOQx5TJM6KuHEq",
        "severity": "P2",
        "path": "scripts/build_ktstop300_v3_packet.py",
        "finding": "Checkpoint cadence rescans/parses every record after each S1 natural generation.",
        "required_fix": "Maintain and update an in-memory completed-key set; scan disk only on startup/recovery.",
    },
    {
        "id": "PRRT_kwDOQx5TJM6KuHLF",
        "severity": "P1",
        "path": "scripts/build_ktstop300_v3_packet.py",
        "finding": "Core result court receives evidence-upload status before final assessment upload and therefore blocks every otherwise-successful run.",
        "required_fix": "Separate core scientific verdict from final publication disposition; remove circular final-upload dependency.",
    },
    {
        "id": "PRRT_kwDOQx5TJM6KuHLG",
        "severity": "P1",
        "path": "scripts/build_ktstop300_v3_packet.py",
        "finding": "Publisher writes a final assessment receipt but returns the earlier evidence receipt.",
        "required_fix": "Return and persist the final receipt from the final-upload branch.",
    },
    {
        "id": "PRRT_kwDOQx5TJM6KuHLI",
        "severity": "P1",
        "path": "scripts/build_ktstop300_v3_packet.py",
        "finding": "Measured records hard-code prefix_equivalence/runtime_reference_agree/unsafe_stop to safe values.",
        "required_fix": "Derive every court predicate independently from immutable raw token, runtime, and reference evidence.",
    },
]

ADDITIONAL_FINDINGS = [
    "DEPENDENCY_INSTALLATION_ABSENT",
    "PREEXISTING_PIP_CONFLICTS_BLOCK_ALL_RUNS",
    "MERGE_HEAD_PLACEHOLDER_ACCEPTED",
    "PUBLICATION_COURT_CYCLE",
    "PHYSICAL_TOKEN_ECONOMICS_MISACCOUNTED",
    "EOS_REFERENCE_COURT_NOT_BOUND",
    "RESULT_COURT_INCOMPLETE_AND_PRECEDENCE_WEAK",
    "CHECKPOINT_NOT_DURABLE",
    "NUMBER_NORMALIZER_RECURSION_AND_SEMANTICS",
    "REVIEW_RACE_MERGED_BEFORE_BOT_FINDINGS",
]


def _member(zf: zipfile.ZipFile, name: str) -> str:
    return zf.read(name).decode("utf-8-sig")


def audit_v3_packet() -> dict:
    if not STOP300_V3_PACKET.exists():
        raise SystemExit("missing STOP300 V3 packet")
    packet_sha = sha256_file(STOP300_V3_PACKET)
    errors: list[str] = []
    defects: list[str] = []
    if packet_sha != EXPECTED_V3_SHA:
        errors.append(f"V3 sha mismatch: {packet_sha}")

    with zipfile.ZipFile(STOP300_V3_PACKET) as zf:
        names = set(zf.namelist())
        manifest = json.loads(_member(zf, "PACKET_MANIFEST.json"))
        config = json.loads(_member(zf, "runtime/ktstop300_v3_config.json"))
        bootstrap = _member(zf, "KAGGLE_BOOTSTRAP_CELL.py")
        runner = _member(zf, "runtime/KT_CANONICAL_RUNNER.py")
        result_court = _member(zf, "runtime/result_court.py")
        hf_publisher = _member(zf, "runtime/hf_publisher.py")
        checkpoint = _member(zf, "runtime/checkpoint_manager.py")
        token_boundary = _member(zf, "runtime/token_boundary_map.py")
        reference = _member(zf, "runtime/reference_court_v33.py")
        output_delivery = _member(zf, "runtime/output_delivery.py")

    if "runtime/dependency_preflight.py" not in names:
        defects.append("clean_kernel_dependency_installation_absent")
    if "MERGED_MAIN_HEAD_TO_BIND_AFTER_PROTECTED_MERGE" in Path("docs/KT_STOP300_V3_ONE_CELL.md").read_text(encoding="utf-8"):
        defects.append("runbook_accepts_literal_merge_head_placeholder")
    if config.get("authorized_merge_head") == "__BOUND_AFTER_PROTECTED_MERGE__":
        defects.append("packet_subject_head_not_bound")
    if "not manifest.get(key)" in Path("scripts/validate_ktstop300_v3_packet.py").read_text(encoding="utf-8"):
        defects.append("authority_keys_missing_can_pass_validator")
    if "publication_status=pub_pre[\"status\"]" in runner:
        defects.append("court_publication_sequence_self_blocks_clean_run")
    if "return receipt" in hf_publisher and "final_receipt" in hf_publisher:
        defects.append("publisher_returns_evidence_receipt_after_final_upload")
    if '"prefix_equivalence": True' in runner and '"unsafe_stop": False' in runner:
        defects.append("measured_records_hard_code_safe_court_fields")
    if "preserved_generated_token_count" in result_court and "raw_generated_token_count" in result_court:
        defects.append("physical_savings_use_preserved_instead_of_raw_s1_tokens")
    if "ended_on_eos" in reference and "terminal_token_id" not in reference:
        defects.append("reference_court_lacks_terminal_eos_token_truth")
    if "full_sequence_rescan_count" not in result_court or "semantic_trailer" not in result_court:
        defects.append("court_omits_preregistered_predicates")
    if "store.completed_keys()" in runner:
        defects.append("checkpoint_cadence_repeatedly_rescans_disk_records")
    if "upload_file" not in checkpoint and "upload_folder" not in checkpoint:
        defects.append("checkpoint_not_reset_durable")
    if "return normalize_number(match[-1])" in output_delivery:
        defects.append("numeric_normalizer_recursive_fallback")

    # Dynamic smoke: V3 court can be made to pass records where trusted safe
    # booleans are present even though no immutable reference derivation exists.
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        with zipfile.ZipFile(STOP300_V3_PACKET) as zf:
            zf.extract("runtime/result_court.py", root)
        import importlib.util
        import sys

        spec = importlib.util.spec_from_file_location("ktstop300_v3_court_audit", root / "runtime/result_court.py")
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        rows = []
        for index in range(300):
            rows.append({"phase": "natural", "row_id": f"r{index}", "arm_id": "L0_LEGACY_NO_DETECTOR", "correct": True, "raw_generated_token_count": 30, "preserved_generated_token_count": 30})
            rows.append({"phase": "natural", "row_id": f"r{index}", "arm_id": "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE", "correct": True, "raw_generated_token_count": 30, "preserved_generated_token_count": 10, "prefix_equivalence": True, "runtime_reference_agree": True, "unsafe_stop": False, "detector_telemetry": {"full_sequence_rescan_count": 0}})
        for index in range(60):
            for repetition in range(3):
                for arm in ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]:
                    rows.append({"phase": "timing", "row_id": f"t{index}", "repetition": repetition, "arm_id": arm})
        for index in range(12):
            for arm in ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]:
                rows.append({"phase": "edge", "row_id": f"e{index}", "arm_id": arm})
        verdict = module.execute_result_court(rows, {}, publication_status="PASS_HF_FINAL_ASSESSMENT_UPLOADED")
        if verdict["status"].startswith("PASS"):
            defects.append("v3_court_can_pass_without_independent_derived_predicates")

    assessment_candidates = [Path("evidence/KT_STOP300_V3_ASSESSMENT_ONLY.zip"), Path("KT_STOP300_V3_ASSESSMENT_ONLY.zip")]
    checkpoint_candidates = [Path("evidence/KT_STOP300_V3_WRAPPER_COLLECTION.zip"), Path("PARTIAL_MEASURED_OUTPUTS.zip")]
    v3_run_exists = any(path.exists() for path in assessment_candidates + checkpoint_candidates)
    return {
        "schema_id": "kt.stop300.v3_postmerge_execution_audit.v1",
        "status": "BLOCKED_GPU_RUN_UNRESOLVED_POSTMERGE_DEFECTS" if defects else "PASS_NO_POSTMERGE_DEFECT_FOUND",
        "pr_number": 384,
        "packet_path": rel(STOP300_V3_PACKET),
        "packet_sha256": packet_sha,
        "v3_gpu_run_status": "UNKNOWN_DURABLE_ARTIFACT_PRESENT" if v3_run_exists else "NOT_RUN",
        "unresolved_review_threads": REVIEW_THREADS,
        "additional_source_findings": ADDITIONAL_FINDINGS,
        "defects": sorted(set(defects)),
        "errors": errors,
        "verdict": "BLOCK_V3_GPU_RUN__UNRESOLVED_POSTMERGE_CORRECTNESS_AND_EXECUTION_DEFECTS",
        "claim_ceiling_status": "PRESERVED",
    }


def main() -> int:
    audit = audit_v3_packet()
    write_json(REPORTS / "stop300_v3_postmerge_execution_audit.json", audit)
    write_json(
        REPORTS / "stop300_v3_review_thread_binding.json",
        {
            "schema_id": "kt.stop300.v3_review_thread_binding.v1",
            "status": "BOUND_AND_SUPERSEDED",
            "pr_number": 384,
            "unresolved_count": len(REVIEW_THREADS),
            "threads": REVIEW_THREADS,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    write_json(
        REPORTS / "stop300_v3_supersession_receipt.json",
        {
            "schema_id": "kt.stop300.v3_supersession_receipt.v1",
            "status": "SUPERSEDED_BEFORE_GPU_EXECUTION" if audit["status"].startswith("BLOCKED") and audit["v3_gpu_run_status"] == "NOT_RUN" else "NOT_SUPERSEDED",
            "v3_packet_path": rel(STOP300_V3_PACKET),
            "v3_packet_sha256": audit["packet_sha256"],
            "v3_gpu_run_status": audit["v3_gpu_run_status"],
            "superseded_by": "packets/ktstop300_v4.zip",
            "claim_ceiling_status": "PRESERVED",
        },
    )
    print(json.dumps(audit, indent=2, sort_keys=True))
    if audit["errors"]:
        raise SystemExit("; ".join(audit["errors"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
