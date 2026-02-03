from __future__ import annotations

from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.verification.phase2_execute import Phase2Error, main as phase2_main  # noqa: E402


def test_phase2_red_assault_missing_env_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # offline required but env vars missing -> FAIL_CLOSED
    monkeypatch.delenv("KT_LIVE", raising=False)
    monkeypatch.delenv("PYTHONHASHSEED", raising=False)

    work_order = _REPO_ROOT / "KT_PROD_CLEANROOM" / "kt.phase2_work_order.v1.json"
    with pytest.raises(Phase2Error):
        phase2_main(["--work-order", str(work_order), "--out-dir", str(tmp_path / "out"), "--mode", "dry-run"])


def test_phase2_red_assault_out_dir_inside_repo_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KT_LIVE", "0")
    monkeypatch.setenv("PYTHONHASHSEED", "0")

    work_order = _REPO_ROOT / "KT_PROD_CLEANROOM" / "kt.phase2_work_order.v1.json"
    # Forbidden surface: code tree (must fail closed).
    out_dir_inside_repo = _REPO_ROOT / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "_tmp_phase2_out"
    if out_dir_inside_repo.exists():
        # Ensure the test does not leave artifacts in the repo tree.
        for p in sorted(out_dir_inside_repo.rglob("*"), reverse=True):
            if p.is_file():
                p.unlink()
            else:
                p.rmdir()
        out_dir_inside_repo.rmdir()

    with pytest.raises(Phase2Error):
        phase2_main(["--work-order", str(work_order), "--out-dir", str(out_dir_inside_repo), "--mode", "dry-run"])

    assert not out_dir_inside_repo.exists()


def test_phase2_red_assault_duplicate_keys_in_work_order_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KT_LIVE", "0")
    monkeypatch.setenv("PYTHONHASHSEED", "0")

    bad = tmp_path / "bad_work_order.json"
    # Duplicate keys must fail closed via strict JSON loader.
    bad.write_text('{"schema_id":"kt.phase2_work_order.v1","schema_id":"kt.phase2_work_order.v1"}', encoding="utf-8", newline="\n")

    with pytest.raises(Exception):
        phase2_main(["--work-order", str(bad), "--out-dir", str(tmp_path / "out"), "--mode", "dry-run"])
