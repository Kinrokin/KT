from __future__ import annotations

import hashlib
import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()


def _bundle_hash(repo_root: Path, bundle_obj: dict) -> str:
    paths = [x["path"] for x in bundle_obj.get("files", [])]
    paths = sorted(paths)

    def hash_file(rel: str) -> str:
        p = (repo_root / rel).resolve()
        data = p.read_bytes()
        if p.suffix.lower() == ".json":
            obj = json.loads(data.decode("utf-8"))
            canon = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            return hashlib.sha256(canon).hexdigest()
        return hashlib.sha256(data).hexdigest()

    lines = [f"{rel}:{hash_file(rel)}\n" for rel in paths]
    laws = bundle_obj.get("laws", [])
    laws_canon = json.dumps(laws, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    lines.append(f"__LAWS__:{hashlib.sha256(laws_canon).hexdigest()}\n")
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def test_fl3_law_bundle_integrity() -> None:
    repo_root = _REPO_ROOT
    bundle_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.json"
    expected_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.sha256"

    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    assert bundle.get("bundle_id") == "LAW_BUNDLE_FL3"
    assert bundle.get("repo_root_anchor") == "REPO_ROOT"

    expected = expected_path.read_text(encoding="utf-8").strip()
    computed = _bundle_hash(repo_root, bundle)
    assert computed == expected
