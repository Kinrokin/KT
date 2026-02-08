from __future__ import annotations

import argparse
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple

from tools.verification.strict_json import load_no_dupes


class Cohort0ManufactureError(RuntimeError):
    pass


def _repo_root_from(this_file: Path) -> Path:
    p = this_file.resolve()
    for parent in [p] + list(p.parents):
        if (parent / "KT_PROD_CLEANROOM").exists():
            return parent
    raise Cohort0ManufactureError("FAIL_CLOSED: unable to locate repo root (missing KT_PROD_CLEANROOM/)")


def _bootstrap_syspath(*, repo_root: Path) -> None:
    """
    Must be runnable via `python -m tools.verification.cohort0_manufacture` without relying on PYTHONPATH.
    """
    import sys

    src_root = (repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src").resolve()
    cleanroom_root = (repo_root / "KT_PROD_CLEANROOM").resolve()
    for p in (str(src_root), str(cleanroom_root)):
        if p not in sys.path:
            sys.path.insert(0, p)


def _canonical_json(obj: object) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_canonical_json(obj), encoding="utf-8", newline="\n")


def _sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_sha(repo_root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(repo_root), text=True).strip()
    except Exception:  # noqa: BLE001
        return "unknown"


@dataclass(frozen=True)
class LobeSpec:
    role_id: str
    adapter_id: str


def derive_canonical_13_lobes(*, role_weights: Mapping[str, Any]) -> List[LobeSpec]:
    roles = role_weights.get("roles")
    if not isinstance(roles, list):
        raise Cohort0ManufactureError("FAIL_CLOSED: ROLE_FITNESS_WEIGHTS.roles must be a list")
    role_ids: List[str] = []
    for r in roles:
        if not isinstance(r, dict):
            raise Cohort0ManufactureError("FAIL_CLOSED: ROLE_FITNESS_WEIGHTS.roles entries must be objects")
        rid = r.get("role_id")
        if not isinstance(rid, str) or not rid.strip():
            raise Cohort0ManufactureError("FAIL_CLOSED: ROLE_FITNESS_WEIGHTS.roles.role_id missing/invalid")
        role_ids.append(rid.strip())

    if len(set(role_ids)) != len(role_ids):
        raise Cohort0ManufactureError("FAIL_CLOSED: duplicate role_id found in ROLE_FITNESS_WEIGHTS")

    if "ARBITER" not in set(role_ids):
        raise Cohort0ManufactureError("FAIL_CLOSED: expected role_id ARBITER missing (doctrine mismatch)")

    lobe_roles = sorted([r for r in role_ids if r != "ARBITER"])
    if len(lobe_roles) != 13:
        raise Cohort0ManufactureError(f"FAIL_CLOSED: expected 13 lobe roles (excluding ARBITER); got {len(lobe_roles)}")

    lobes: List[LobeSpec] = []
    for rid in lobe_roles:
        adapter_id = f"lobe.{rid.lower()}.v1"
        lobes.append(LobeSpec(role_id=rid, adapter_id=adapter_id))

    # Stable ordering for downstream registry: sort by adapter_id.
    lobes.sort(key=lambda s: s.adapter_id)
    return lobes


def _mk_jobspec(
    *,
    adapter_id: str,
    adapter_version: str,
    role_id: str,
    base_model_id: str,
    seed: int,
    export_shadow_root: str,
    export_promoted_root: str,
) -> Dict[str, Any]:
    from schemas.schema_files import schema_version_hash  # type: ignore
    from tools.verification.fl3_canonical import sha256_json  # type: ignore
    from tools.verification.fl3_validators import validate_schema_bound_object  # type: ignore

    job: Dict[str, Any] = {
        "schema_id": "kt.factory.jobspec.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.jobspec.v1.json"),
        "job_id": "",
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "role": role_id,
        # Promotion eligibility requires SOVEREIGN mode (see tools.training.fl3_factory.promote.decide_promotion).
        "mode": "SOVEREIGN",
        "run_kind": "STANDARD",
        "base_model_id": base_model_id,
        # Canonical lane is MRT-0 AdapterType.A-only: metabolism proof, no weights.
        "training_mode": "head_only",
        "seed": int(seed),
        "export_shadow_root": export_shadow_root,
        "export_promoted_root": export_promoted_root,
    }
    job["job_id"] = sha256_json({k: v for k, v in job.items() if k != "job_id"})
    validate_schema_bound_object(job)
    return job


def _mk_min_contract(*, repo_root: Path) -> Dict[str, Any]:
    """
    Mirror the minimal FL4 organ contract created by preflight_fl4, but as a callable
    helper so Cohort-0 manufacturing uses the same allowlists.
    """
    from tools.verification.preflight_fl4 import _mk_min_contract as _mk  # type: ignore

    return _mk(repo_root)


def _runtime_registry_template_path(*, repo_root: Path) -> Path:
    return repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "docs" / "RUNTIME_REGISTRY.json"


def _role_weights_path(*, repo_root: Path) -> Path:
    return repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "ROLE_FITNESS_WEIGHTS.json"


def _build_runtime_registry_snapshot(
    *,
    repo_root: Path,
    promoted_reports: List[Dict[str, Any]],
    base_model_id: str,
    adapter_version: str,
) -> Dict[str, Any]:
    _bootstrap_syspath(repo_root=repo_root)
    from schemas.adapter_entry_schema import (  # type: ignore
        ADAPTER_ENTRY_SCHEMA_ID,
        ADAPTER_ENTRY_SCHEMA_VERSION_HASH,
        validate_adapter_entry,
    )
    from schemas.runtime_registry_schema import validate_runtime_registry  # type: ignore
    from core.runtime_registry import _parse_adapters_spec  # type: ignore

    template_path = _runtime_registry_template_path(repo_root=repo_root)
    template = load_no_dupes(template_path)
    if not isinstance(template, dict):
        raise Cohort0ManufactureError("FAIL_CLOSED: runtime registry template must be a JSON object")

    adapters = template.get("adapters")
    if not isinstance(adapters, dict):
        raise Cohort0ManufactureError("FAIL_CLOSED: runtime registry template.adapters must be an object")

    # IMPORTANT: actual repo export root lives under KT_PROD_CLEANROOM/exports/** (gitignored runtime outputs).
    allowed_export_roots = ["KT_PROD_CLEANROOM/exports/adapters"]

    entries: List[Dict[str, Any]] = []
    for pr in promoted_reports:
        adapter_id = str(pr.get("adapter_id", "")).strip()
        promoted_dir = str(pr.get("promoted_dir", "")).strip()
        content_hash = str(pr.get("content_hash", "")).strip()
        if not adapter_id or not promoted_dir or len(content_hash) != 64:
            raise Cohort0ManufactureError("FAIL_CLOSED: malformed promotion report surface (adapter_id/promoted_dir/content_hash)")

        entry = {
            "schema_id": ADAPTER_ENTRY_SCHEMA_ID,
            "schema_version_hash": ADAPTER_ENTRY_SCHEMA_VERSION_HASH,
            "adapter_id": adapter_id,
            "version": adapter_version,
            "base_model": base_model_id,
            "artifact_path": promoted_dir,
            "artifact_hash": content_hash,
            "capabilities": ["COHORT0", f"ROLE:{adapter_id}"],
            "constraints": ["MRT0_HEAD_ONLY", "OFFLINE_ONLY", "NO_NETWORK"],
            "training_receipt_ref": f"{promoted_dir}/train_manifest.json",
            "evaluation_receipt_ref": f"{promoted_dir}/eval_report.json",
            "status": "ACTIVE",
        }
        validate_adapter_entry(entry)
        entries.append(entry)

    # Deterministic ordering required by core.runtime_registry parser.
    entries.sort(key=lambda e: (str(e.get("adapter_id", "")), str(e.get("version", ""))))

    adapters_snapshot = {
        "registry_schema_id": str(adapters.get("registry_schema_id", "")).strip(),
        "allowed_export_roots": allowed_export_roots,
        "entries": entries,
    }
    # Parse adapter spec using the canonical runtime parser (fail-closed if any invariant violated).
    _parse_adapters_spec(adapters_snapshot)

    template["adapters"] = adapters_snapshot
    validate_runtime_registry(template)
    return template


def _parse_args(argv: List[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Cohort-0 manufacture+promote adapters and emit runtime registry snapshot.")
    ap.add_argument("--out-dir", required=True, help="Evidence output dir (must be outside repo).")
    ap.add_argument("--seed", type=int, default=0, help="Deterministic seed for cohort manufacturing.")
    ap.add_argument("--base-model-id", default="mistral-7b")
    ap.add_argument("--adapter-version", default="1")
    ap.add_argument(
        "--export-shadow-root",
        default="KT_PROD_CLEANROOM/exports/adapters_shadow/_cohort0",
        help="Relative export root for factory job dirs (shadow).",
    )
    ap.add_argument(
        "--export-promoted-root",
        default="KT_PROD_CLEANROOM/exports/adapters/_cohort0",
        help="Relative export root for promoted packages.",
    )
    return ap.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = _parse_args(argv)
    repo_root = _repo_root_from(Path(__file__))
    _bootstrap_syspath(repo_root=repo_root)

    if os.environ.get("KT_LIVE") not in {None, "0"}:
        raise SystemExit("FAIL_CLOSED: KT_LIVE must be 0 (offline) for cohort manufacturing")

    out_dir = Path(args.out_dir).resolve()
    # Fail-closed: out_dir must not be inside repo (avoid mutating code/law surfaces).
    try:
        out_dir.relative_to(repo_root.resolve())
        raise SystemExit("FAIL_CLOSED: --out-dir must be outside repo root")
    except ValueError:
        pass

    # Load doctrine-derived roles.
    role_weights_path = _role_weights_path(repo_root=repo_root)
    role_weights = load_no_dupes(role_weights_path)
    if not isinstance(role_weights, dict):
        raise SystemExit("FAIL_CLOSED: ROLE_FITNESS_WEIGHTS.json must be object")
    lobes = derive_canonical_13_lobes(role_weights=role_weights)

    # Write cohort adapter list evidence.
    pinned_sha = _git_sha(repo_root)
    cohort_list = {
        "kind": "cohort0_adapter_set",
        "pinned_sha": pinned_sha,
        "derived_from": str(role_weights_path.relative_to(repo_root).as_posix()),
        "excluded_role": "ARBITER",
        "count": len(lobes),
        "adapters": [{"role_id": s.role_id, "adapter_id": s.adapter_id} for s in lobes],
    }
    _write_json(out_dir / "cohort0_adapter_set.json", cohort_list)

    # Build organ contract (ephemeral, evidence-copied).
    contract = _mk_min_contract(repo_root=repo_root)
    contract_path = out_dir / "organ_contract.json"
    _write_json(contract_path, contract)

    # Determinism canary must PASS before any promotion.
    from tools.verification.fl4_determinism_canary import main as canary_main  # type: ignore

    canary_path = out_dir / "canary_artifact.json"
    rc = int(canary_main(["--organ-contract", str(contract_path), "--out", str(canary_path)]))
    if rc != 0:
        raise SystemExit(f"FAIL_CLOSED: determinism canary failed rc={rc}")

    # Manufacture + promote each adapter.
    from tools.training.fl3_factory.run_job import EXIT_OK, main as run_job_main  # type: ignore
    from tools.verification.fl3_meta_evaluator import main as meta_main  # type: ignore
    from tools.verification.fl4_promote import main as promote_main  # type: ignore

    promoted_reports: List[Dict[str, Any]] = []
    for s in lobes:
        job = _mk_jobspec(
            adapter_id=s.adapter_id,
            adapter_version=str(args.adapter_version),
            role_id=s.role_id,
            base_model_id=str(args.base_model_id),
            seed=int(args.seed),
            export_shadow_root=str(args.export_shadow_root),
            export_promoted_root=str(args.export_promoted_root),
        )
        job_path = out_dir / "jobs" / f"{s.adapter_id}.job.json"
        _write_json(job_path, job)

        rc_job = int(run_job_main(["--job", str(job_path), "--organ-contract", str(contract_path)]))
        if rc_job != EXIT_OK:
            raise SystemExit(f"FAIL_CLOSED: factory run failed rc={rc_job} for {s.adapter_id}")

        job_dir = (repo_root / str(args.export_shadow_root) / str(job["job_id"])).resolve()
        if not job_dir.exists():
            raise SystemExit(f"FAIL_CLOSED: expected job_dir missing: {job_dir.as_posix()}")

        # Full meta-evaluator verification (law bundle, amendment, anti-drift primitives).
        rc_meta = int(meta_main(["--verify-job-dir", str(job_dir)]))
        if rc_meta != 0:
            raise SystemExit(f"FAIL_CLOSED: meta-evaluator failed rc={rc_meta} for {s.adapter_id}")

        report_path = out_dir / "promotion_reports" / f"{s.adapter_id}.promotion_report.json"
        rc_promote = int(promote_main(["--job-dir", str(job_dir), "--canary-artifact", str(canary_path), "--out", str(report_path)]))
        if rc_promote != 0:
            raise SystemExit(f"FAIL_CLOSED: promotion failed rc={rc_promote} for {s.adapter_id}")

        pr = load_no_dupes(report_path)
        if not isinstance(pr, dict):
            raise SystemExit("FAIL_CLOSED: promotion report must be object")
        # Normalize minimal surfaces needed for registry snapshot.
        promoted_reports.append(
            {
                "adapter_id": s.adapter_id,
                "content_hash": str(pr.get("content_hash", "")),
                "promoted_dir": str(pr.get("promoted_dir", "")),
                "promotion_report_path": str(report_path.relative_to(out_dir).as_posix()),
                "promotion_report_sha256": _sha256_file(report_path),
            }
        )

    # Deterministic ordering for report bundle.
    promoted_reports.sort(key=lambda r: str(r.get("adapter_id", "")))
    cohort_snapshot = {
        "kind": "cohort0_registry_snapshot",
        "pinned_sha": pinned_sha,
        "base_model_id": str(args.base_model_id),
        "adapter_version": str(args.adapter_version),
        "exports_promoted_root": str(args.export_promoted_root),
        "exports_shadow_root": str(args.export_shadow_root),
        "count": len(promoted_reports),
        "entries": promoted_reports,
    }
    _write_json(out_dir / "cohort0_registry_snapshot.json", cohort_snapshot)

    # Emit a fully-valid runtime registry snapshot with adapters.entries populated.
    registry_snapshot = _build_runtime_registry_snapshot(
        repo_root=repo_root,
        promoted_reports=promoted_reports,
        base_model_id=str(args.base_model_id),
        adapter_version=str(args.adapter_version),
    )
    rr_path = out_dir / "runtime_registry.snapshot.json"
    _write_json(rr_path, registry_snapshot)

    final_report = {
        "kind": "cohort0_manufacture_report",
        "pinned_sha": pinned_sha,
        "out_dir": str(out_dir),
        "runtime_registry_snapshot_path": str(rr_path),
        "runtime_registry_snapshot_sha256": _sha256_file(rr_path),
        "cohort0_registry_snapshot_sha256": _sha256_file(out_dir / "cohort0_registry_snapshot.json"),
        "canary_artifact_sha256": _sha256_file(canary_path),
    }
    _write_json(out_dir / "cohort0_manufacture_report.json", final_report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

