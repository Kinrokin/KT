from __future__ import annotations

import argparse
import json
import subprocess
from importlib import metadata
from pathlib import Path
from typing import Any, Dict, List, Optional

from schemas.schema_files import schema_version_hash
from tools.training.fl3_factory.run_job import EXIT_OK, main as run_job_main
from tools.verification.fl3_canonical import repo_root_from, sha256_json
from tools.verification.fl3_meta_evaluator import compute_law_bundle_hash, load_law_bundle
from tools.verification.fl3_validators import FL3ValidationError, load_fl3_canonical_runtime_paths, validate_schema_bound_object


def _deps_fingerprint_hash() -> str:
    pkgs = []
    for dist in metadata.distributions():
        name = dist.metadata.get("Name") or dist.metadata.get("Summary") or "UNKNOWN"
        pkgs.append(f"{name}=={dist.version}")
    pkgs = sorted(set(pkgs))
    return sha256_json({"pip_freeze": pkgs})


def _git_sha(repo_root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(repo_root), text=True).strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def _load_schema_bound_json(path: Path) -> Dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"Expected JSON object (fail-closed): {path.as_posix()}")
    validate_schema_bound_object(obj)
    return obj


def _mk_canary_jobspec(*, export_shadow_root: str, export_promoted_root: str) -> Dict[str, Any]:
    job: Dict[str, Any] = {
        "schema_id": "kt.factory.jobspec.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.jobspec.v1.json"),
        "job_id": "",
        "adapter_id": "canary.adapter.v1",
        "adapter_version": "0",
        "role": "CANARY",
        "mode": "SMOKE",
        "run_kind": "STANDARD",
        "base_model_id": "mistral-7b",
        "training_mode": "head_only",
        "seed": 0,
        "export_shadow_root": export_shadow_root,
        "export_promoted_root": export_promoted_root,
    }
    job["job_id"] = sha256_json({k: v for k, v in job.items() if k != "job_id"})
    return job


def build_canary_artifact(*, repo_root: Path, canary_job: Dict[str, Any], hash_manifest_root_hash: str, canary_result: str) -> Dict[str, Any]:
    # Bind into the active law bundle.
    bundle = load_law_bundle(repo_root=repo_root)
    law_bundle_hash = compute_law_bundle_hash(repo_root=repo_root, bundle=bundle)

    supported = _load_schema_bound_json(repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FL4_SUPPORTED_PLATFORMS.json")
    det = _load_schema_bound_json(repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FL4_DETERMINISM_CONTRACT.json")
    up_manifest = _load_schema_bound_json(
        repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "UTILITY_PACK_V1" / "UTILITY_PACK_MANIFEST.json"
    )

    record: Dict[str, Any] = {
        "schema_id": "kt.canary_artifact.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.canary_artifact.v1.json"),
        "canary_id": "",
        "git_sha": _git_sha(repo_root),
        "platform_fingerprint": {
            "os": "unknown",
            "python": "unknown",
            "deps_hash": _deps_fingerprint_hash(),
        },
        "law_bundle_hash": law_bundle_hash,
        "determinism_contract_hash": sha256_json(det),
        "supported_platforms_hash": sha256_json(supported),
        "utility_pack_hash": str(up_manifest.get("utility_pack_hash")),
        "job_dir_manifest_schema_hash": schema_version_hash("fl3/kt.factory.job_dir_manifest.v1.json"),
        "hash_manifest_root_hash": hash_manifest_root_hash,
        "canary_job_id": str(canary_job["job_id"]),
        "canary_result": canary_result,
        "payload_hash": "",
        "created_at": "1970-01-01T00:00:00Z",
    }
    record["payload_hash"] = sha256_json({k: v for k, v in record.items() if k not in {"payload_hash", "canary_id", "created_at"}})
    record["canary_id"] = sha256_json({k: v for k, v in record.items() if k not in {"canary_id", "created_at"}})
    validate_schema_bound_object(record)
    return record


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--organ-contract", required=True, help="Path to factory organ contract JSON.")
    ap.add_argument("--budget-state", required=False, default="", help="Path to budget state JSON (optional).")
    ap.add_argument("--out", required=True, help="Write kt.canary_artifact.v1 JSON to this path.")
    args = ap.parse_args(argv)

    repo_root = repo_root_from(Path(__file__))

    # Load determinism contract; expected root hash is mandatory for canary enforcement.
    det_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FL4_DETERMINISM_CONTRACT.json"
    det = _load_schema_bound_json(det_path)
    expected_root = str(det.get("canary_expected_hash_manifest_root_hash") or "")
    if not expected_root or expected_root == "0" * 64:
        raise SystemExit("FAIL: determinism contract missing canary_expected_hash_manifest_root_hash (fail-closed)")

    # Derive export roots from canonical runtime paths.
    # This audit artifact is intentionally not schema-bound (it is a path map),
    # so we load it via the existing helper that validates schema_id only.
    paths = load_fl3_canonical_runtime_paths(repo_root=repo_root)
    export_shadow_root = str(paths["exports_shadow_root"]).replace("\\", "/").rstrip("/") + "/_canary"
    export_promoted_root = str(paths["exports_adapters_root"]).replace("\\", "/").rstrip("/") + "/_canary"

    canary_job = _mk_canary_jobspec(export_shadow_root=export_shadow_root, export_promoted_root=export_promoted_root)
    # Factory job_dir layout is export_shadow_root/<job_id>/ (canonical, immutable).
    out_root = (repo_root / export_shadow_root / canary_job["job_id"]).resolve()
    if out_root.exists():
        # Determinism canary must not depend on prior state.
        import shutil

        shutil.rmtree(out_root)

    tmp_dir = repo_root / "KT_PROD_CLEANROOM" / "exports" / "adapters_shadow" / "_runs" / "FL4_CANARY"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    job_path = tmp_dir / "canary_job.json"
    job_path.write_text(json.dumps(canary_job, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

    argv_run = ["--job", str(job_path), "--organ-contract", str(args.organ_contract)]
    if args.budget_state:
        argv_run += ["--budget-state", str(args.budget_state)]
    rc = int(run_job_main(argv_run))
    if rc != EXIT_OK:
        raise SystemExit(f"FAIL: canary factory run failed with rc={rc}")

    hm = _load_schema_bound_json(out_root / "hash_manifest.json")
    root_hash = str(hm.get("root_hash", ""))
    if not root_hash or len(root_hash) != 64:
        raise SystemExit("FAIL: missing hash_manifest.root_hash (fail-closed)")

    result = "PASS" if root_hash == expected_root else "FAIL"
    artifact = build_canary_artifact(repo_root=repo_root, canary_job=canary_job, hash_manifest_root_hash=root_hash, canary_result=result)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

    return 0 if result == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
