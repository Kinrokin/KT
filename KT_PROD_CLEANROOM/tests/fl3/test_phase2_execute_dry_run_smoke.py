from __future__ import annotations

from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.verification.phase2_execute import Phase2Error, main as phase2_main  # noqa: E402
from tools.verification.strict_json import loads_no_dupes  # noqa: E402


def test_phase2_execute_dry_run_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Required by kt.phase2_work_order.v1.json inputs.runtime_environment.environment_vars_required
    monkeypatch.setenv("KT_LIVE", "0")
    monkeypatch.setenv("PYTHONHASHSEED", "0")

    work_order = _REPO_ROOT / "KT_PROD_CLEANROOM" / "kt.phase2_work_order.v1.json"
    out_dir = tmp_path / "phase2_out"

    rc = int(
        phase2_main(
            [
                "--work-order",
                str(work_order),
                "--out-dir",
                str(out_dir),
                "--mode",
                "dry-run",
            ]
        )
    )
    assert rc == 0

    plan_path = out_dir / "phase2_dry_run_plan.json"
    receipts_path = out_dir / "phase2_dry_run_receipts.json"
    assert plan_path.exists()
    assert receipts_path.exists()

    plan = loads_no_dupes(plan_path.read_text(encoding="utf-8"))
    receipts = loads_no_dupes(receipts_path.read_text(encoding="utf-8"))
    assert plan.get("kind") == "phase2_dry_run_plan"
    assert receipts.get("kind") == "phase2_dry_run_receipts"

    # Determinism: running twice (different out_dir) yields identical plan/receipts bytes.
    out_dir2 = tmp_path / "phase2_out_2"
    rc2 = int(
        phase2_main(
            [
                "--work-order",
                str(work_order),
                "--out-dir",
                str(out_dir2),
                "--mode",
                "dry-run",
            ]
        )
    )
    assert rc2 == 0
    assert plan_path.read_bytes() == (out_dir2 / "phase2_dry_run_plan.json").read_bytes()
    assert receipts_path.read_bytes() == (out_dir2 / "phase2_dry_run_receipts.json").read_bytes()


def test_phase2_execute_rejects_execute_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KT_LIVE", "0")
    monkeypatch.setenv("PYTHONHASHSEED", "0")

    work_order = _REPO_ROOT / "KT_PROD_CLEANROOM" / "kt.phase2_work_order.v1.json"
    out_dir = tmp_path / "phase2_out"

    with pytest.raises(Phase2Error):
        phase2_main(["--work-order", str(work_order), "--out-dir", str(out_dir), "--mode", "execute"])

