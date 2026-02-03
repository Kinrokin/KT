from __future__ import annotations

import json
from pathlib import Path
from typing import Tuple

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from tools.verification.fl3_validators import validate_schema_bound_object  # noqa: E402
from tools.verification.phase1c_execute import run_phase1c  # noqa: E402


def _read_json(path: Path) -> dict:
    obj = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(obj, dict)
    return obj


def test_phase1c_execute_smoke_emits_required_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out_dir = tmp_path / "out"

    # Avoid running the full growth lane in unit tests; Phase 1C execution is still validated
    # end-to-end by producing the same artifact names/receipts deterministically.
    def _fake_growth_gate(*, repo_root: Path, out_dir: Path) -> Tuple[str, Path]:
        report = out_dir / "growth_e2e_gate_report.json"
        report.write_text("{\"status\":\"PASS\"}\n", encoding="utf-8")
        return "PASS", report

    monkeypatch.setattr("tools.verification.phase1c_execute._run_growth_gate", _fake_growth_gate)

    rc = run_phase1c(
        work_order_path=Path("KT_PROD_CLEANROOM/kt.phase1c_work_order.v1.json"),
        out_dir=out_dir,
    )
    assert rc == 0

    dag_path = out_dir / "kt.runtime_dag.v1.json"
    judge_path = out_dir / "kt.judge_receipt.v1.json"
    promo_path = out_dir / "kt.promotion_report.v1.json"
    assert dag_path.exists()
    assert judge_path.exists()
    assert promo_path.exists()

    validate_schema_bound_object(_read_json(dag_path))
    validate_schema_bound_object(_read_json(judge_path))
    validate_schema_bound_object(_read_json(promo_path))

    judge = _read_json(judge_path)
    assert judge["verdict"] == "PASS"
    assert judge["checks"]["watcher_ignored_without_corroboration"] is True


def test_phase1c_execute_refuses_to_reemit_runtime_dag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Phase 1C must emit `kt.runtime_dag.v1.json` exactly once for a given out_dir.
    Re-running into the same out_dir is ambiguous and must fail-closed.
    """
    out_dir = tmp_path / "out"

    def _fake_growth_gate(*, repo_root: Path, out_dir: Path) -> Tuple[str, Path]:
        report = out_dir / "growth_e2e_gate_report.json"
        report.write_text("{\"status\":\"PASS\"}\n", encoding="utf-8")
        return "PASS", report

    monkeypatch.setattr("tools.verification.phase1c_execute._run_growth_gate", _fake_growth_gate)

    rc = run_phase1c(
        work_order_path=Path("KT_PROD_CLEANROOM/kt.phase1c_work_order.v1.json"),
        out_dir=out_dir,
    )
    assert rc == 0
    assert (out_dir / "kt.runtime_dag.v1.json").exists()

    with pytest.raises(Exception):
        run_phase1c(
            work_order_path=Path("KT_PROD_CLEANROOM/kt.phase1c_work_order.v1.json"),
            out_dir=out_dir,
        )
