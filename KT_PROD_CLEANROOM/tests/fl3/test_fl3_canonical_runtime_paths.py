from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()


def _repo_root() -> Path:
    p = Path(__file__).resolve()
    for parent in p.parents:
        if (parent / "KT_PROD_CLEANROOM").is_dir():
            return parent
    raise RuntimeError("Unable to locate repo root (expected KT_PROD_CLEANROOM/)")


def test_fl3_canonical_runtime_paths_file_present_and_valid() -> None:
    repo_root = _repo_root()
    paths_file = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FL3_CANONICAL_RUNTIME_PATHS.json"
    assert paths_file.exists()

    obj = json.loads(paths_file.read_text(encoding="utf-8"))
    assert obj.get("schema_id") == "kt.fl3.canonical_runtime_paths.v1"

    required = [
        "runtime_registry_path",
        "schema_registry_root",
        "schema_registry_module",
        "state_vault_path_policy",
        "srr_schema_id",
        "air_schema_id",
        "exports_adapters_root",
        "exports_shadow_root",
    ]
    for k in required:
        assert isinstance(obj.get(k), str) and obj[k].strip()

    # Paths declared here must exist in-repo.
    for k in ["runtime_registry_path", "schema_registry_root", "schema_registry_module"]:
        p = (repo_root / obj[k]).resolve()
        assert p.exists(), f"{k} missing on disk: {p}"

    # Exports roots must exist or be creatable; require parent exists to keep path-jail meaningful.
    for k in ["exports_adapters_root", "exports_shadow_root"]:
        p = repo_root / obj[k]
        assert p.parent.exists(), f"{k} parent missing: {p.parent}"
