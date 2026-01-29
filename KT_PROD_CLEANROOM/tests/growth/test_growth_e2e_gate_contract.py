from __future__ import annotations

from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath


def test_growth_e2e_gate_wrapper_defaults_point_to_real_plans() -> None:
    repo_root = bootstrap_syspath()

    from tools.verification.growth_e2e_gate import DEFAULT_MILESTONE_PLAN, DEFAULT_PRESSURE_PLAN

    milestone = (repo_root / Path(DEFAULT_MILESTONE_PLAN)).resolve()
    pressure = (repo_root / Path(DEFAULT_PRESSURE_PLAN)).resolve()

    assert milestone.exists(), f"Missing milestone plan: {milestone}"
    assert pressure.exists(), f"Missing pressure plan: {pressure}"

