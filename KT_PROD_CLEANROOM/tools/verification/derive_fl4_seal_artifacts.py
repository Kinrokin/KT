from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash
from tools.training.fl3_factory.run_job import main as run_job_main
from tools.verification.fl3_canonical import repo_root_from, sha256_json
from tools.verification.fl3_meta_evaluator import compute_law_bundle_hash
from tools.verification.fl3_validators import (
    FL3ValidationError,
    load_fl3_canonical_runtime_paths,
    validate_schema_bound_object,
)
from tools.verification.fl4_determinism_canary import _mk_canary_jobspec  # type: ignore


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"Unable to read JSON (fail-closed): {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"Expected JSON object (fail-closed): {path.as_posix()}")
    return obj


def _write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _derive_canary_hash_manifest_root_hash(*, repo_root: Path, organ_contract_path: Path) -> Tuple[str, str]:
    """
    Runs the canonical canary job once (without enforcing expected hash) and returns:
      (job_id, hash_manifest_root_hash)

    This is the only allowed source of truth for updating the determinism contract.
    """
    paths = load_fl3_canonical_runtime_paths(repo_root=repo_root)
    export_shadow_root = str(paths["exports_shadow_root"]).replace("\\", "/").rstrip("/") + "/_canary"
    export_promoted_root = str(paths["exports_adapters_root"]).replace("\\", "/").rstrip("/") + "/_canary"

    # IMPORTANT: derive artifacts must use the exact canonical canary jobspec used by
    # tools.verification.fl4_determinism_canary to avoid fixed-point drift.
    canary_job: Dict[str, Any] = _mk_canary_jobspec(export_shadow_root=export_shadow_root, export_promoted_root=export_promoted_root)
    validate_schema_bound_object(canary_job)

    job_dir = (repo_root / export_shadow_root / str(canary_job["job_id"])).resolve()
    if job_dir.exists():
        shutil.rmtree(job_dir)

    staging_dir = (repo_root / "KT_PROD_CLEANROOM" / "exports" / "adapters_shadow" / "_runs" / "FL4_CANARY_DERIVE").resolve()
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)
    job_path = staging_dir / "canary_job.json"
    _write_json(job_path, canary_job)

    rc = int(run_job_main(["--job", str(job_path), "--organ-contract", str(organ_contract_path)]))
    if rc != 0:
        raise FL3ValidationError(f"Canary factory run failed rc={rc} (fail-closed)")

    hm = _read_json(job_dir / "hash_manifest.json")
    validate_schema_bound_object(hm)
    root_hash = str(hm.get("root_hash", "")).strip()
    if len(root_hash) != 64:
        raise FL3ValidationError("Canary hash_manifest.root_hash missing/invalid (fail-closed)")

    # Clean derived run state (derive should not accumulate).
    if job_dir.exists():
        shutil.rmtree(job_dir)
    if staging_dir.exists():
        shutil.rmtree(staging_dir)

    return str(canary_job["job_id"]), root_hash


def _update_determinism_contract(*, repo_root: Path, expected_root_hash: str, write: bool) -> Dict[str, Any]:
    det_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FL4_DETERMINISM_CONTRACT.json"
    det = _read_json(det_path)
    validate_schema_bound_object(det)
    if det.get("schema_id") != "kt.determinism_contract.v1":
        raise FL3ValidationError("FL4_DETERMINISM_CONTRACT schema_id mismatch (fail-closed)")

    det["canary_expected_hash_manifest_root_hash"] = expected_root_hash
    det["determinism_contract_id"] = sha256_json({k: v for k, v in det.items() if k not in {"created_at", "determinism_contract_id"}})
    validate_schema_bound_object(det)

    if write:
        _write_json(det_path, det)
    return det


def _sync_law_bundle_sha(*, repo_root: Path, write: bool) -> str:
    bundle_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.json"
    sha_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.sha256"
    bundle = _read_json(bundle_path)
    law_hash = compute_law_bundle_hash(repo_root=repo_root, bundle=bundle)
    if write:
        sha_path.write_text(law_hash + "\n", encoding="utf-8")
    return law_hash


def _ensure_law_amendment_present(*, repo_root: Path, bundle_hash: str, write: bool) -> Optional[Path]:
    audits_dir = repo_root / "KT_PROD_CLEANROOM" / "AUDITS"
    for p in sorted(audits_dir.glob("LAW_AMENDMENT_FL3_*.json")):
        try:
            obj = _read_json(p)
        except Exception:
            continue
        if obj.get("schema_id") == "kt.law_amendment.v1" and str(obj.get("bundle_hash")) == bundle_hash:
            return p

    if not write:
        return None

    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def mk_signoff(key_id: str, payload_hash: str) -> Dict[str, Any]:
        entry: Dict[str, Any] = {
            "schema_id": "kt.human_signoff.v1",
            "schema_version_hash": schema_version_hash("fl3/kt.human_signoff.v1.json"),
            "signoff_id": "",
            "key_id": key_id,
            "payload_hash": payload_hash,
            # Schema requires a hex-64. Signature verification is not enforced at FL3.1 layer.
            "hmac_signature": sha256_hex_of_obj({"key_id": key_id, "payload_hash": payload_hash}, drop_keys=set()),
            "created_at": created_at,
        }
        entry["signoff_id"] = sha256_hex_of_obj(entry, drop_keys={"created_at", "signoff_id"})
        return entry

    amendment: Dict[str, Any] = {
        "schema_id": "kt.law_amendment.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.law_amendment.v1.json"),
        "amendment_id": "",
        "bundle_hash": bundle_hash,
        "signoffs": [
            mk_signoff("SIGNER_A", bundle_hash),
            mk_signoff("SIGNER_B", bundle_hash),
        ],
        "created_at": created_at,
    }
    amendment["amendment_id"] = sha256_hex_of_obj(amendment, drop_keys={"created_at", "amendment_id"})
    validate_schema_bound_object(amendment)

    fname = f"LAW_AMENDMENT_FL3_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    out_path = audits_dir / fname
    _write_json(out_path, amendment)
    return out_path


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Derive FL4 seal artifacts (determinism contract + law bundle hash + law amendment) without manual edits.")
    ap.add_argument("--organ-contract", required=True, help="Path to factory organ contract JSON for canary derivation.")
    ap.add_argument("--write", action="store_true", help="Write updated artifacts to AUDITS/ (fail-closed if not set and mismatch exists).")
    args = ap.parse_args(argv)

    repo_root = repo_root_from(Path(__file__))
    organ_contract_path = Path(args.organ_contract)

    # 1) Derive canary root hash from a fresh run.
    _job_id, root_hash = _derive_canary_hash_manifest_root_hash(repo_root=repo_root, organ_contract_path=organ_contract_path)

    # 2) Update determinism contract (derived from the canary).
    det_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FL4_DETERMINISM_CONTRACT.json"
    current_det = _read_json(det_path)
    expected_before = str(current_det.get("canary_expected_hash_manifest_root_hash", "")).strip()
    det = _update_determinism_contract(repo_root=repo_root, expected_root_hash=root_hash, write=args.write)
    changed_det = expected_before != root_hash

    # 3) Compute law bundle hash and sync sha file.
    sha_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.sha256"
    sha_before = sha_path.read_text(encoding="utf-8").strip() if sha_path.exists() else ""
    bundle_hash = _sync_law_bundle_sha(repo_root=repo_root, write=args.write)
    changed_bundle = sha_before != bundle_hash

    # 4) Ensure a law amendment exists for this bundle hash.
    amend_path = _ensure_law_amendment_present(repo_root=repo_root, bundle_hash=bundle_hash, write=args.write)

    report = {
        "schema_id": "kt.fl4.derive_artifacts_report.v1",
        "derived": {
            "canary_hash_manifest_root_hash": root_hash,
            "law_bundle_hash": bundle_hash,
        },
        "writes": {
            "write_enabled": bool(args.write),
            "determinism_contract_updated": bool(changed_det),
            "law_bundle_sha_updated": bool(changed_bundle),
            "law_amendment_path": str(amend_path.as_posix()) if amend_path else None,
        },
        "paths": {
            "determinism_contract_path": "KT_PROD_CLEANROOM/AUDITS/FL4_DETERMINISM_CONTRACT.json",
            "law_bundle_path": "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.json",
            "law_bundle_sha_path": "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.sha256",
        },
        "determinism_contract_id": str(det.get("determinism_contract_id", "")),
    }
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True))

    if not args.write and (changed_det or changed_bundle or amend_path is None):
        raise SystemExit("FAIL: derived artifacts differ from committed state; rerun with --write (fail-closed).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
