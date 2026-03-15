from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.canonical_tree_execute import ARCHIVE_DOCS_AUDIT_PREFIX, ARCHIVE_GLOB
from tools.operator.archive_externalization_test import scan_doc_link_failures, tracked_active_export_files


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _init_repo(root: Path) -> None:
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "kt@example.test"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "KT Test"], cwd=root, check=True, capture_output=True)


def test_tracked_active_export_files_excludes_archive_and_noncanonical_paths(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _init_repo(root)
    archived_doc = f"{ARCHIVE_DOCS_AUDIT_PREFIX}old.md"
    _write_text(root / "README.md", "root\n")
    _write_text(root / "docs/guide.md", "# guide\n")
    _write_text(root / Path(archived_doc), "# archived\n")
    _write_text(root / "KT_PROD_CLEANROOM/tools/operator/tool.py", "print('ok')\n")
    _write_text(root / "KT_PROD_CLEANROOM/reports/generated.json", "{}\n")
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "seed"], cwd=root, check=True, capture_output=True)

    manifest = {
        "included_paths": ["README.md", "docs/**", "KT_PROD_CLEANROOM/**"],
        "excluded_paths": [ARCHIVE_GLOB, "KT_PROD_CLEANROOM/reports/**"],
    }
    exported = tracked_active_export_files(root, manifest)

    assert "README.md" in exported
    assert "docs/guide.md" in exported
    assert "KT_PROD_CLEANROOM/tools/operator/tool.py" in exported
    assert archived_doc not in exported
    assert "KT_PROD_CLEANROOM/reports/generated.json" not in exported


def test_scan_doc_link_failures_detects_archive_and_missing_targets(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    archived_doc = f"{ARCHIVE_DOCS_AUDIT_PREFIX}old.md"
    _write_text(root / "README.md", f"[ok](docs/guide.md)\n[bad]({archived_doc})\n[missing](docs/missing.md)\n")
    _write_text(root / "docs/guide.md", "# guide\n")

    failures = scan_doc_link_failures(root, ["README.md", "docs/guide.md"])

    reasons = {(row["target"], row["reason"]) for row in failures}
    assert (archived_doc, "archive_link_target") in reasons
    assert ("docs/missing.md", "missing_local_target") in reasons
