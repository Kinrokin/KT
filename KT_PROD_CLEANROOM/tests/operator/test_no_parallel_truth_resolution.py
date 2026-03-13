from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import List

import pytest

from tools.operator.truth_authority import load_json_ref


def _find_repo_root(start: Path) -> Path:
    for candidate in [start] + list(start.parents):
        if (candidate / ".git").exists():
            return candidate
    raise RuntimeError("unable to locate repo root for static scan")


def test_branch_ref_does_not_fallback_to_filesystem_in_git_worktree(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(repo), "init"], check=True, capture_output=True, text=True)

    # If a branch ref can't be loaded via git, we must fail closed rather than silently
    # reading a filesystem fallback at the same relpath.
    fallback = repo / "ledger" / "current"
    fallback.mkdir(parents=True, exist_ok=True)
    (fallback / "current_pointer.json").write_text(json.dumps({"ok": True}), encoding="utf-8")

    with pytest.raises(RuntimeError) as exc:
        load_json_ref(root=repo, ref="kt_truth_ledger:ledger/current/current_pointer.json")
    assert "FAIL_CLOSED: unable to load branch ref" in str(exc.value)


def test_git_show_usage_is_singleton_in_truth_authority() -> None:
    repo_root = _find_repo_root(Path(__file__).resolve())
    operator_root = repo_root / "KT_PROD_CLEANROOM" / "tools" / "operator"
    hits: List[str] = []
    for path in sorted(operator_root.rglob("*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if '"show",' in text and '["git"' in text:
            hits.append(path.relative_to(repo_root).as_posix())

    assert hits == ["KT_PROD_CLEANROOM/tools/operator/truth_authority.py"]

