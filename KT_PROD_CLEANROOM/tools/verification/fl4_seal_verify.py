from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.training.fl3_factory.manifests import compute_hash_manifest_root_hash, sha256_file
from tools.verification.fl3_canonical import repo_root_from, sha256_json, sha256_text
from tools.verification.attestation_hmac import env_key_name_for_key_id, verify_hmac_signoff
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.preflight_fl4 import _assert_evidence_pack_complete
from tools.verification.replay_script_generator import render_replay_ps1, render_replay_sh
from tools.verification.run_protocol_generator import verify_run_protocol_pair


def _read_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"Unreadable JSON {name} (fail-closed): {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"{name} must be a JSON object (fail-closed): {path.as_posix()}")
    return obj


def _verify_hash_manifest(*, job_dir: Path) -> Dict[str, Any]:
    hm_path = job_dir / "hash_manifest.json"
    hm = _read_json_dict(hm_path, name="hash_manifest.json")
    validate_schema_bound_object(hm)

    entries = hm.get("entries")
    if not isinstance(entries, list) or not entries:
        raise FL3ValidationError("hash_manifest.entries must be non-empty list (fail-closed)")

    expected_root = compute_hash_manifest_root_hash(entries)
    got_root = str(hm.get("root_hash", "")).strip()
    if expected_root != got_root:
        raise FL3ValidationError("hash_manifest.root_hash mismatch vs canonical entries (fail-closed)")

    # Verify each entry against the filesystem (tamper detection).
    for item in entries:
        if not isinstance(item, dict):
            raise FL3ValidationError("hash_manifest entry must be object (fail-closed)")
        rel = str(item.get("path", "")).strip()
        expected_sha = str(item.get("sha256", "")).strip()
        if not rel or not expected_sha:
            raise FL3ValidationError("hash_manifest entries require path and sha256 (fail-closed)")
        p = (job_dir / rel).resolve()
        try:
            p.relative_to(job_dir.resolve())
        except Exception as exc:  # noqa: BLE001
            raise FL3ValidationError(f"hash_manifest entry escapes job_dir (fail-closed): {rel}") from exc
        if not p.exists() or not p.is_file():
            raise FL3ValidationError(f"hash_manifest entry missing on disk (fail-closed): {rel}")
        actual_sha = sha256_file(p)
        if actual_sha != expected_sha:
            raise FL3ValidationError(f"hash_manifest entry sha mismatch (fail-closed): {rel}")

    return hm


def _verify_job_dir_manifest(*, job_dir: Path, hash_manifest_root_hash: str) -> Dict[str, Any]:
    jd_path = job_dir / "job_dir_manifest.json"
    jd = _read_json_dict(jd_path, name="job_dir_manifest.json")
    validate_schema_bound_object(jd)

    got = str(jd.get("hash_manifest_root_hash", "")).strip()
    if got != hash_manifest_root_hash:
        raise FL3ValidationError("job_dir_manifest.hash_manifest_root_hash mismatch (fail-closed)")

    files = jd.get("files")
    if not isinstance(files, list) or not files:
        raise FL3ValidationError("job_dir_manifest.files must be non-empty list (fail-closed)")

    # Ensure job_dir_manifest includes the hash manifest file and that its sha matches.
    hm_sha_expected = sha256_file(job_dir / "hash_manifest.json")
    hm_rows = [f for f in files if isinstance(f, dict) and str(f.get("path")) == "hash_manifest.json"]
    if not hm_rows:
        raise FL3ValidationError("job_dir_manifest missing hash_manifest.json entry (fail-closed)")
    hm_sha_got = str(hm_rows[0].get("sha256", "")).strip()
    if hm_sha_got != hm_sha_expected:
        raise FL3ValidationError("job_dir_manifest hash_manifest.json sha mismatch (fail-closed)")

    return jd


def verify_fl4_seal_evidence_dir(*, evidence_dir: Path) -> Dict[str, Any]:
    evidence_dir = evidence_dir.resolve()
    _ = repo_root_from(Path(__file__))  # fail-fast if repo root isn't detectable

    # Evidence pack completeness (structural contract).
    _assert_evidence_pack_complete(out_dir=evidence_dir)

    # Canonical time contract must be present and schema-valid.
    time_contract = _read_json_dict(evidence_dir / "time_contract.json", name="time_contract.json")
    validate_schema_bound_object(time_contract)

    # Run protocol pair integrity (JSON source-of-truth + derived MD).
    run_protocol = verify_run_protocol_pair(
        json_path=evidence_dir / "run_protocol.json",
        md_path=evidence_dir / "RUN_PROTOCOL.md",
    )

    # Secret scan artifacts must be present and consistent.
    secret_report = _read_json_dict(evidence_dir / "secret_scan_report.json", name="secret_scan_report.json")
    secret_summary = _read_json_dict(evidence_dir / "secret_scan_summary.json", name="secret_scan_summary.json")
    validate_schema_bound_object(secret_report)
    validate_schema_bound_object(secret_summary)
    if str(secret_summary.get("report_hash")) != str(secret_report.get("report_hash")):
        raise FL3ValidationError("secret_scan_summary.report_hash mismatch (fail-closed)")
    if str(secret_summary.get("status")) != str(secret_report.get("status")):
        raise FL3ValidationError("secret_scan_summary.status mismatch (fail-closed)")
    secret_status = str(secret_report.get("status", "ERROR"))
    if run_protocol.get("secret_scan_result") != secret_status:
        raise FL3ValidationError("run_protocol.secret_scan_result mismatch vs secret scan status (fail-closed)")
    if secret_status != "PASS":
        raise FL3ValidationError(f"secret scan status={secret_status} (fail-closed)")

    # Replay scripts + replay receipt must bind to the run protocol.
    replay_receipt = _read_json_dict(evidence_dir / "replay_receipt.json", name="replay_receipt.json")
    validate_schema_bound_object(replay_receipt)
    if str(replay_receipt.get("replay_command")) != str(run_protocol.get("replay_command")):
        raise FL3ValidationError("replay_receipt.replay_command mismatch vs run protocol (fail-closed)")

    sh_path = evidence_dir / "replay.sh"
    ps1_path = evidence_dir / "replay.ps1"
    sh_text = sh_path.read_text(encoding="utf-8")
    ps1_text = ps1_path.read_text(encoding="utf-8")
    sh_expected = render_replay_sh(replay_command=str(run_protocol.get("replay_command")))
    ps1_expected = render_replay_ps1(replay_command=str(run_protocol.get("replay_command")))
    if sh_text != sh_expected:
        raise FL3ValidationError("replay.sh content mismatch vs canonical render (fail-closed)")
    if ps1_text != ps1_expected:
        raise FL3ValidationError("replay.ps1 content mismatch vs canonical render (fail-closed)")

    sh_sha = sha256_text(sh_text)
    ps1_sha = sha256_text(ps1_text)
    combined = sha256_json({"replay_ps1_sha256": ps1_sha, "replay_sh_sha256": sh_sha})
    if str(replay_receipt.get("replay_sh_sha256")) != sh_sha:
        raise FL3ValidationError("replay_receipt.replay_sh_sha256 mismatch (fail-closed)")
    if str(replay_receipt.get("replay_ps1_sha256")) != ps1_sha:
        raise FL3ValidationError("replay_receipt.replay_ps1_sha256 mismatch (fail-closed)")
    if str(replay_receipt.get("replay_script_hash")) != combined:
        raise FL3ValidationError("replay_receipt.replay_script_hash mismatch (fail-closed)")
    if str(run_protocol.get("replay_script_hash")) != combined:
        raise FL3ValidationError("run_protocol.replay_script_hash mismatch vs replay scripts (fail-closed)")

    # Hash manifest must match filesystem and bind into the run protocol's bundle_root_hash.
    job_dir = evidence_dir / "job_dir"
    hash_manifest = _verify_hash_manifest(job_dir=job_dir)
    root_hash = str(hash_manifest.get("root_hash", "")).strip()
    _ = _verify_job_dir_manifest(job_dir=job_dir, hash_manifest_root_hash=root_hash)

    if str(run_protocol.get("bundle_root_hash")) != root_hash:
        raise FL3ValidationError("run_protocol.bundle_root_hash mismatch vs job_dir/hash_manifest.root_hash (fail-closed)")

    # Promotion rationale must be present and schema-valid.
    job = _read_json_dict(job_dir / "job.json", name="job.json")
    promotion = _read_json_dict(job_dir / "promotion.json", name="promotion.json")
    job_id = str(job.get("job_id", "")).strip()
    if not job_id:
        raise FL3ValidationError("job.json.job_id missing (fail-closed)")
    decision = str(promotion.get("decision", "")).strip().upper()
    if not decision:
        raise FL3ValidationError("promotion.json.decision missing (fail-closed)")
    rationale = _read_json_dict(job_dir / "promotion_rationale.json", name="promotion_rationale.json")
    validate_schema_bound_object(rationale)
    if str(rationale.get("job_id")) != job_id:
        raise FL3ValidationError("promotion_rationale.job_id mismatch vs job.json (fail-closed)")
    if str(rationale.get("lane_id")) != str(run_protocol.get("lane_id")):
        raise FL3ValidationError("promotion_rationale.lane_id mismatch vs run_protocol.lane_id (fail-closed)")
    if str(rationale.get("decision")) != decision:
        raise FL3ValidationError("promotion_rationale.decision mismatch vs promotion.json.decision (fail-closed)")

    # Optional human override receipt (if present, must be schema-valid; canonical lanes require HMAC verification).
    override_path = evidence_dir / "human_override_receipt.json"
    if override_path.exists():
        override = _read_json_dict(override_path, name="human_override_receipt.json")
        validate_schema_bound_object(override)
        if str(override.get("run_id")) != str(run_protocol.get("run_id")):
            raise FL3ValidationError("human_override_receipt.run_id mismatch vs run_protocol.run_id (fail-closed)")
        if str(override.get("lane_id")) != str(run_protocol.get("lane_id")):
            raise FL3ValidationError("human_override_receipt.lane_id mismatch vs run_protocol.lane_id (fail-closed)")

        mode = str(override.get("attestation_mode", "")).strip().upper()
        # FL4_SEAL is treated as canonical: simulated overrides are forbidden; HMAC must verify with provided keys.
        if str(run_protocol.get("lane_id")) == "FL4_SEAL":
            if mode == "SIMULATED":
                raise FL3ValidationError("SIMULATED human override receipt is forbidden in canonical lane (fail-closed)")
            if mode != "HMAC":
                raise FL3ValidationError("Unsupported attestation_mode for human override receipt in canonical lane (fail-closed)")
            signoffs = override.get("signoffs")
            if not isinstance(signoffs, list) or len(signoffs) < 2:
                raise FL3ValidationError("human_override_receipt.signoffs missing/invalid (fail-closed)")
            for s in signoffs:
                if not isinstance(s, dict):
                    raise FL3ValidationError("human override signoffs must be objects (fail-closed)")
                key_id = str(s.get("key_id", "")).strip()
                env_key = env_key_name_for_key_id(key_id)
                key_val = os.environ.get(env_key)
                if not key_val:
                    raise FL3ValidationError(f"Missing {env_key} for HMAC override receipt verification (fail-closed)")
                ok, err = verify_hmac_signoff(signoff=s, key_bytes=key_val.encode("utf-8"))
                if not ok:
                    raise FL3ValidationError(f"HMAC override receipt verification failed: key_id={key_id} err={err} (fail-closed)")

    # Governance twin artifacts must be schema-valid and PASS.
    twin_manifest = _read_json_dict(evidence_dir / "governance_twin_manifest.json", name="governance_twin_manifest.json")
    twin_report = _read_json_dict(evidence_dir / "governance_twin_report.json", name="governance_twin_report.json")
    validate_schema_bound_object(twin_manifest)
    validate_schema_bound_object(twin_report)
    if str(twin_report.get("twin_manifest_id")) != str(twin_manifest.get("twin_manifest_id")):
        raise FL3ValidationError("governance_twin_report.twin_manifest_id mismatch (fail-closed)")
    if str(twin_report.get("status")) != "PASS":
        raise FL3ValidationError(f"governance twin status={twin_report.get('status')} (fail-closed)")
    if str(twin_manifest.get("run_protocol_json_hash")) != str(run_protocol.get("run_protocol_json_hash")):
        raise FL3ValidationError("governance_twin_manifest.run_protocol_json_hash mismatch (fail-closed)")
    if str(twin_manifest.get("bundle_root_hash")) != str(run_protocol.get("bundle_root_hash")):
        raise FL3ValidationError("governance_twin_manifest.bundle_root_hash mismatch (fail-closed)")
    law_bundle_hash = (evidence_dir / "law_bundle_hash.txt").read_text(encoding="utf-8").strip()
    if str(twin_manifest.get("law_bundle_hash")) != str(law_bundle_hash):
        raise FL3ValidationError("governance_twin_manifest.law_bundle_hash mismatch (fail-closed)")
    if str(twin_manifest.get("time_contract_id")) != str(time_contract.get("time_contract_id")):
        raise FL3ValidationError("governance_twin_manifest.time_contract_id mismatch (fail-closed)")

    report: Dict[str, Any] = {
        "status": "PASS",
        "inputs": {"evidence_dir": evidence_dir.as_posix()},
        "checks": {
            "evidence_pack_complete": True,
            "time_contract_present": True,
            "run_protocol_pair_valid": True,
            "secret_scan_pass": True,
            "replay_scripts_bound": True,
            "hash_manifest_verified": True,
            "promotion_rationale_present": True,
            "governance_twin_pass": True,
        },
    }
    return report


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Fail-closed verification of an FL4 seal evidence directory.")
    ap.add_argument("--evidence-dir", required=True)
    ap.add_argument("--out", default=None, help="Optional output path for seal_verify_report.json")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    evidence_dir = Path(args.evidence_dir)
    report = verify_fl4_seal_evidence_dir(evidence_dir=evidence_dir)
    if args.out:
        out_path = Path(args.out).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with out_path.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
        except FileExistsError as exc:
            raise FL3ValidationError("Refusing to overwrite existing seal verify report (fail-closed)") from exc
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FL3ValidationError as exc:
        raise SystemExit(f"FAIL_CLOSED: {exc}") from exc
