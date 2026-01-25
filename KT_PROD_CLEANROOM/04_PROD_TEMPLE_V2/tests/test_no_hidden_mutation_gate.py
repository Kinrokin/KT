from __future__ import annotations

from pathlib import Path


def _import_gate():
    # Local import to mirror other tests that patch sys.path.
    import sys

    repo_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str((repo_root / "src").resolve()))
    from core.no_hidden_mutation import assert_no_hidden_mutation, scan_no_hidden_mutation  # noqa: E402

    return repo_root, assert_no_hidden_mutation, scan_no_hidden_mutation


def test_no_hidden_mutation_detects_forbidden_patterns(tmp_path: Path) -> None:
    _, _, scan_no_hidden_mutation = _import_gate()
    p = tmp_path / "run.sh"
    p.write_text("echo hi\nsed -i 's/x/y/g' file.txt\n", encoding="utf-8")
    findings = scan_no_hidden_mutation(root=tmp_path, exclude_substrings=())
    assert any(f.pattern_id == "SED_INPLACE" for f in findings)


def test_repository_no_hidden_mutation() -> None:
    repo_root, assert_no_hidden_mutation, _ = _import_gate()
    # Cleanroom-scoped scan (fail-closed if forbidden patterns exist in execution surfaces).
    assert_no_hidden_mutation(root=repo_root)

