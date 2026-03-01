from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from tools.security.pack_guard_scan import scan_pack_and_write  # noqa: E402
from tools.training.fl3_factory.manifests import write_manifests_for_job_dir  # noqa: E402
from tools.verification.fl4_seal_verify import verify_fl4_seal_evidence_dir  # noqa: E402
from tools.verification.fl3_validators import FL3ValidationError  # noqa: E402
from tools.verification.replay_script_generator import write_replay_artifacts  # noqa: E402
from tools.verification.run_protocol_generator import build_run_protocol, write_run_protocol_pair  # noqa: E402
from tools.governance.governance_twin_runner import run_governance_twin_and_write  # noqa: E402
from tools.governance.promotion_rationale_collector import ensure_promotion_rationale_for_job_dir  # noqa: E402
from schemas.schema_files import schema_version_hash  # noqa: E402


def _touch(path: Path, content: str = "x\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _sha_id(record: dict, drop_keys: set[str]) -> str:
    payload = {k: v for k, v in record.items() if k not in drop_keys}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def _mk_min_evidence_dir(tmp_path: Path) -> tuple[Path, str]:
    out_dir = tmp_path / "out"
    job_dir = out_dir / "job_dir"
    # Must satisfy kt.factory.jobspec.v1 job_id constraints (64 hex) because job_dir_manifest is schema-bound.
    job_id = "a" * 64

    # Minimal top-level required files (excluding artifacts that will be generated).
    for name in (
        "command_transcript.txt",
        "pip_freeze.txt",
        "seal_doctrine.md",
        "env_lock.json",
        "io_guard_receipt.json",
        "supported_platforms.json",
        "determinism_contract.json",
        "law_bundle.json",
        "growth_e2e_gate_report.json",
        "behavioral_growth_summary.json",
        "meta_evaluator_receipt.json",
        "red_assault_report.json",
        "rollback_drill_report.json",
        "canary_artifact_pre.json",
        "canary_artifact_rerun.json",
        "canary_artifact_post_promotion.json",
        "metabolism_proof.json",
        "replay_from_receipts_report.json",
        "preflight_summary.json",
    ):
        _touch(out_dir / name)

    # law_bundle_hash.txt must be a 64-hex string (governance twin reads it).
    _touch(out_dir / "law_bundle_hash.txt", ("0" * 64) + "\n")

    # time_contract.json must be schema-valid (seal verify reads/validates it).
    tc = {
        "schema_id": "kt.time_contract.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.time_contract.v1.json"),
        "time_contract_id": "",
        "timestamp_policy": {
            "run_evidence_clock": "WALL_CLOCK_UTC_Z_SECONDS",
            "derived_artifacts_clock": "EVIDENCE_ANCHORED_MAX_CREATED_AT",
            "fallback_clock": "FIXED_EPOCH_0",
        },
        "hash_surface_policy": {"must_drop_keys": ["created_at"], "must_not_include_wall_clock_in_hashes": True},
        "created_at": "2026-01-01T00:00:00Z",
    }
    tc["time_contract_id"] = _sha_id(tc, {"created_at", "time_contract_id"})
    _write_json(out_dir / "time_contract.json", tc)

    # Required evidence job_dir files (excluding manifests that we will derive).
    for name, obj in (
        ("job.json", {"job_id": job_id, "adapter_id": "lobe.architect.v1", "adapter_version": "1"}),
        ("phase_trace.json", {"phases": []}),
        ("dataset.json", {"schema_id": "kt.factory.dataset.v1", "dataset_id": "d" * 64}),
        ("eval_report.json", {"final_verdict": "PASS", "utility_floor_pass": True, "metric_probes": [{"agreement": True}], "probe_policy": {"tolerance": 1e-9, "fail_on_disagreement": True}}),
        ("signal_quality.json", {"schema_id": "kt.signal_quality.v1", "signal_quality_id": "e" * 64}),
        ("judgement.json", {"schema_id": "kt.factory.judgement.v1", "judgement_id": "f" * 64}),
        ("promotion.json", {"decision": "NO_PROMOTE"}),
    ):
        _write_json(job_dir / name, obj)

    # Training admission receipt is a required job_dir artifact in FL4 seal packs.
    adm = {
        "schema_id": "kt.training_admission_receipt.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.training_admission_receipt.v1.json"),
        "admission_receipt_id": "",
        "lane_id": "FL3_FACTORY",
        "decision": "PASS",
        "reason_codes": [],
        "job_ref": "job_dir/job.json",
        "job_sha256": "0" * 64,
        "law_bundle_hash": "0" * 64,
        "failure_taxonomy_id": "0" * 64,
        "created_at": "1970-01-01T00:00:00Z",
    }
    adm["admission_receipt_id"] = _sha_id(adm, {"created_at", "admission_receipt_id"})
    _write_json(job_dir / "training_admission_receipt.json", adm)

    # Minimal behavioral growth certificate folder (required by seal).
    for name in (
        "H0.json",
        "E.json",
        "H1.json",
        "growth_protocol.json",
        "scores_H0.json",
        "scores_H1.json",
        "state_event.json",
        "growth_claim.json",
        "_tmp/state_ledger.jsonl",
    ):
        _touch(out_dir / "behavioral_growth" / name)
    (out_dir / "behavioral_growth" / "_tmp" / "state_payloads").mkdir(parents=True, exist_ok=True)
    _touch(out_dir / "behavioral_growth" / "_tmp" / "state_payloads" / "payload.json")

    # Derive job_dir manifests (hash_manifest.json + job_dir_manifest.json).
    _ = write_manifests_for_job_dir(
        job_dir=job_dir,
        job_id=job_id,
        parent_hash="0" * 64,
        required_relpaths=[
            "job.json",
            "training_admission_receipt.json",
            "dataset.json",
            "phase_trace.json",
            "eval_report.json",
            "signal_quality.json",
            "judgement.json",
            "promotion.json",
        ],
    )

    # Promotion rationale is a required governance artifact (not part of job_dir hash manifest).
    _ = ensure_promotion_rationale_for_job_dir(job_dir=job_dir, lane_id="FL4_SEAL")
    hash_manifest = json.loads((job_dir / "hash_manifest.json").read_text(encoding="utf-8"))
    root_hash = str(hash_manifest["root_hash"])

    # Replay artifacts (scripts + schema-bound replay_receipt.json).
    replay_command = "python -m tools.verification.fl4_replay_from_receipts --evidence-dir out --out out/replay.json"
    _sh, _ps1, _receipt, replay_hashes = write_replay_artifacts(
        out_dir=out_dir,
        replay_command=replay_command,
        run_id=job_id,
        lane_id="FL4_SEAL",
    )

    # Secret scan artifacts (PASS).
    report, _summary = scan_pack_and_write(pack_root=out_dir, out_dir=out_dir, run_id=job_id, lane_id="FL4_SEAL")
    secret_status = str(report.get("status", "ERROR"))
    assert secret_status == "PASS"

    # Run protocol (schema-bound + derived markdown).
    protocol = build_run_protocol(
        {
            "run_id": job_id,
            "lane_id": "FL4_SEAL",
            "timestamp_utc": "2026-01-01T00:00:00Z",
            "determinism_mode": "STRICT",
            "execution_environment_hash": "a" * 64,
            "governed_phase_start_hash": "b" * 64,
            "io_guard_status": "GUARDED",
            "base_model_id": "mistral-7b",
            "active_adapters": [{"adapter_id": "lobe.architect.v1", "adapter_hash": root_hash}],
            "replay_command": replay_command,
            "replay_script_hash": str(replay_hashes["replay_script_hash"]),
            "secret_scan_result": secret_status,
            "bundle_root_hash": root_hash,
            "notes": "unit test seal verify fixture",
        }
    )
    write_run_protocol_pair(out_dir=out_dir, protocol=protocol)

    # Governance twin artifacts (PASS).
    _man, rep = run_governance_twin_and_write(evidence_dir=out_dir, out_dir=out_dir)
    assert rep["status"] == "PASS"

    return out_dir, job_id


def test_fl4_seal_verify_passes_minimal_fixture(tmp_path: Path) -> None:
    out_dir, _job_id = _mk_min_evidence_dir(tmp_path)
    report = verify_fl4_seal_evidence_dir(evidence_dir=out_dir)
    assert report["status"] == "PASS"


def test_fl4_seal_verify_detects_job_dir_tamper(tmp_path: Path) -> None:
    out_dir, job_id = _mk_min_evidence_dir(tmp_path)
    job_path = out_dir / "job_dir" / "job.json"
    job = json.loads(job_path.read_text(encoding="utf-8"))
    job["job_id"] = job_id + "_tampered"
    job_path.write_text(json.dumps(job, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

    with pytest.raises(FL3ValidationError):
        verify_fl4_seal_evidence_dir(evidence_dir=out_dir)
