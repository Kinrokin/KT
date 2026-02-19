from __future__ import annotations

from pathlib import Path


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    # .../KT_PROD_CLEANROOM/tests/fl3/test_operator_ui_assets.py -> repo root
    return here.parents[3]


def test_operator_ui_assets_exist() -> None:
    repo_root = _repo_root()
    ui_dir = repo_root / "KT_PROD_CLEANROOM" / "tools" / "operator" / "ui"
    assert (ui_dir / "index.html").is_file()
    assert (ui_dir / "app.js").is_file()
    assert (ui_dir / "style.css").is_file()

    html = (ui_dir / "index.html").read_text(encoding="utf-8", errors="replace")
    assert "KT Run Viewer" in html
    assert "fileInput" in html

