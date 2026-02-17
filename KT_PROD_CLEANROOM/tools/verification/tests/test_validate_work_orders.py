from __future__ import annotations

from pathlib import Path

from tools.verification.fl3_canonical import repo_root_from
from tools.verification.validate_work_orders import validate_work_orders


def test_validate_work_orders_passes_on_repo_work_orders() -> None:
    repo_root = repo_root_from(Path(__file__))
    exports_root = (repo_root / "KT_PROD_CLEANROOM" / "exports").resolve()
    ok, failures = validate_work_orders(repo_root=repo_root, exports_root=exports_root, max_files=2000)
    assert failures == []
    assert (
        "KT_PROD_CLEANROOM/exports/mrt1_e2e/_runs/MRT1_E2E_20260215T205732Z/WORK_ORDER_MRT1_E2E.user_provided.json"
        in ok
    )
    assert "KT_PROD_CLEANROOM/exports/mrt1_e2e/_runs/MRT1_E2E_20260215T205732Z/WORK_ORDER_MRT1_E2E.resolved.json" in ok

