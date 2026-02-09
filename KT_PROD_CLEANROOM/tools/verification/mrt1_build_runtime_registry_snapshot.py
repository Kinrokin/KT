from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.verification.strict_json import load_no_dupes


class MRT1SnapshotError(RuntimeError):
    pass


def _repo_root_from(this_file: Path) -> Path:
    p = this_file.resolve()
    for parent in [p] + list(p.parents):
        if (parent / "KT_PROD_CLEANROOM").exists():
            return parent
    raise MRT1SnapshotError("FAIL_CLOSED: unable to locate repo root (missing KT_PROD_CLEANROOM/)")


def _bootstrap_syspath(*, repo_root: Path) -> None:
    """
    Must be runnable via `python -m tools.verification.mrt1_build_runtime_registry_snapshot` without relying on PYTHONPATH.
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
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _derive_role_ids(*, repo_root: Path) -> List[str]:
    weights_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "ROLE_FITNESS_WEIGHTS.json"
    obj = load_no_dupes(weights_path)
    if not isinstance(obj, dict):
        raise MRT1SnapshotError("FAIL_CLOSED: ROLE_FITNESS_WEIGHTS.json must be object")
    roles = obj.get("roles")
    if not isinstance(roles, list):
        raise MRT1SnapshotError("FAIL_CLOSED: ROLE_FITNESS_WEIGHTS.roles must be list")
    role_ids: List[str] = []
    for r in roles:
        if isinstance(r, dict) and isinstance(r.get("role_id"), str):
            role_ids.append(r["role_id"].strip())
    if len(set(role_ids)) != 14 or "ARBITER" not in set(role_ids):
        raise MRT1SnapshotError("FAIL_CLOSED: doctrine drift (expected 14 roles incl ARBITER)")
    return sorted([r for r in role_ids if r != "ARBITER"])


@dataclass(frozen=True)
class _ExpectedAdapter:
    role_id: str
    adapter_id: str


def _expected_adapters(*, repo_root: Path) -> List[_ExpectedAdapter]:
    out: List[_ExpectedAdapter] = []
    for rid in _derive_role_ids(repo_root=repo_root):
        out.append(_ExpectedAdapter(role_id=rid, adapter_id=f"lobe.{rid.lower()}.v1"))
    out.sort(key=lambda e: e.adapter_id)
    if len(out) != 13:
        raise MRT1SnapshotError("FAIL_CLOSED: expected 13 doctrine-derived adapters")
    return out


def build_snapshot(*, repo_root: Path, adapter_version: str, out_path: Path) -> int:
    from schemas.runtime_registry_schema import validate_runtime_registry  # type: ignore
    from schemas.adapter_entry_schema import (
        ADAPTER_ENTRY_SCHEMA_ID,
        ADAPTER_ENTRY_SCHEMA_VERSION_HASH,
        validate_adapter_entry,
    )  # type: ignore
    from core.runtime_registry import parse_adapters_spec  # type: ignore
    from tools.verification.fl3_validators import load_fl3_canonical_runtime_paths, validate_schema_bound_object  # type: ignore

    paths = load_fl3_canonical_runtime_paths(repo_root=repo_root)
    template_rel = str(paths.get("runtime_registry_path", "")).strip()
    if not template_rel:
        raise MRT1SnapshotError("FAIL_CLOSED: missing runtime_registry_path in FL3 canonical runtime paths")
    template_path = (repo_root / template_rel).resolve()
    template = load_no_dupes(template_path)
    if not isinstance(template, dict):
        raise MRT1SnapshotError("FAIL_CLOSED: runtime registry template must be JSON object")

    adapters = template.get("adapters")
    if not isinstance(adapters, dict):
        raise MRT1SnapshotError("FAIL_CLOSED: runtime registry template.adapters must be object")

    exports_adapters_mrt1_root = str(paths.get("exports_adapters_mrt1_root", "")).strip()
    if not exports_adapters_mrt1_root:
        raise MRT1SnapshotError("FAIL_CLOSED: missing exports_adapters_mrt1_root in FL3 canonical runtime paths")

    promoted_root_abs = (repo_root / exports_adapters_mrt1_root).resolve()
    expected = _expected_adapters(repo_root=repo_root)

    entries: List[Dict[str, Any]] = []
    required_constraints = ["MRT1_LORA", "OFFLINE_ONLY", "NO_NETWORK"]
    for exp in expected:
        base_dir = (promoted_root_abs / exp.adapter_id / adapter_version).resolve()
        if not base_dir.exists():
            raise MRT1SnapshotError(f"FAIL_CLOSED: missing promoted MRT-1 adapter dir: {base_dir.as_posix()}")
        # Strict: exactly one content-hash directory per adapter/version.
        children = sorted([p for p in base_dir.iterdir() if p.is_dir()], key=lambda p: p.name)
        if len(children) != 1:
            raise MRT1SnapshotError(
                f"FAIL_CLOSED: expected exactly 1 content-hash dir under {base_dir.as_posix()}, got {len(children)}"
            )
        content_hash = children[0].name
        if len(content_hash) != 64 or any(c not in "0123456789abcdef" for c in content_hash):
            raise MRT1SnapshotError("FAIL_CLOSED: content-hash dir name must be 64 lowercase hex")

        pkg_dir = children[0]
        train_receipt_p = pkg_dir / "train_receipt.json"
        wt_manifest_p = pkg_dir / "adapter_weight_manifest.json"
        eval_report_p = pkg_dir / "eval_report.json"
        for p in (train_receipt_p, wt_manifest_p, eval_report_p):
            if not p.exists():
                raise MRT1SnapshotError(f"FAIL_CLOSED: missing required promoted package file: {p.as_posix()}")

        train_receipt = load_no_dupes(train_receipt_p)
        if not isinstance(train_receipt, dict):
            raise MRT1SnapshotError("FAIL_CLOSED: train_receipt must be JSON object")
        validate_schema_bound_object(train_receipt)
        if train_receipt.get("schema_id") != "kt.phase2_train_receipt.v1":
            raise MRT1SnapshotError("FAIL_CLOSED: train_receipt schema_id mismatch")
        if train_receipt.get("status") != "PASS":
            raise MRT1SnapshotError("FAIL_CLOSED: promoted package train_receipt status must be PASS")
        if str(train_receipt.get("adapter_id", "")).strip() != exp.adapter_id:
            raise MRT1SnapshotError("FAIL_CLOSED: train_receipt.adapter_id mismatch vs directory")
        if str(train_receipt.get("adapter_version", "")).strip() != adapter_version:
            raise MRT1SnapshotError("FAIL_CLOSED: train_receipt.adapter_version mismatch vs expected")
        if str((train_receipt.get("output_package") or {}).get("content_hash", "")).strip() != content_hash:
            raise MRT1SnapshotError("FAIL_CLOSED: train_receipt content_hash mismatch vs promoted dir name")

        wt_manifest = load_no_dupes(wt_manifest_p)
        if not isinstance(wt_manifest, dict):
            raise MRT1SnapshotError("FAIL_CLOSED: adapter_weight_manifest must be JSON object")
        validate_schema_bound_object(wt_manifest)
        if wt_manifest.get("schema_id") != "kt.adapter_weight_artifact_manifest.v1":
            raise MRT1SnapshotError("FAIL_CLOSED: adapter_weight_manifest schema_id mismatch")
        if str(wt_manifest.get("root_hash", "")).strip() != content_hash:
            raise MRT1SnapshotError("FAIL_CLOSED: weight manifest root_hash mismatch vs promoted dir name")

        artifact_rel = str(pkg_dir.relative_to(repo_root).as_posix())
        train_ref = f"{artifact_rel}/train_receipt.json"
        eval_ref = f"{artifact_rel}/eval_report.json"

        entry = {
            "schema_id": ADAPTER_ENTRY_SCHEMA_ID,
            "schema_version_hash": ADAPTER_ENTRY_SCHEMA_VERSION_HASH,
            "adapter_id": exp.adapter_id,
            "version": adapter_version,
            "base_model": str(train_receipt.get("base_model", {}).get("model_id", "")).strip(),
            "artifact_path": artifact_rel,
            "artifact_hash": content_hash,
            "capabilities": ["MRT1", f"ROLE:{exp.role_id}"],
            "constraints": required_constraints,
            "training_receipt_ref": train_ref,
            "evaluation_receipt_ref": eval_ref,
            "status": "ACTIVE",
        }
        validate_adapter_entry(entry)
        entries.append(entry)

    entries.sort(key=lambda e: (str(e.get("adapter_id", "")), str(e.get("version", ""))))

    adapters_snapshot = {
        "registry_schema_id": str(adapters.get("registry_schema_id", "")).strip(),
        "allowed_export_roots": [exports_adapters_mrt1_root],
        "entries": entries,
    }
    parse_adapters_spec(adapters_snapshot)

    template["adapters"] = adapters_snapshot
    validate_runtime_registry(template)
    _write_json(out_path, template)
    return 0


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Build a runtime registry snapshot for MRT-1 promoted adapters (fail-closed).")
    ap.add_argument("--adapter-version", default="1")
    ap.add_argument("--out", required=True, help="Output path for runtime_registry.mrt1.snapshot.json")
    return ap.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = _repo_root_from(Path(__file__))
    _bootstrap_syspath(repo_root=repo_root)
    out = Path(args.out).resolve()
    return int(build_snapshot(repo_root=repo_root, adapter_version=str(args.adapter_version).strip(), out_path=out))


if __name__ == "__main__":
    raise SystemExit(main())

