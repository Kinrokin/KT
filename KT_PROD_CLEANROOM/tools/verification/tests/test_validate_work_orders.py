from __future__ import annotations

from pathlib import Path

from tools.verification.fl3_canonical import repo_root_from
from tools.verification.validate_work_orders import validate_work_orders


def test_validate_work_orders_passes_on_repo_work_orders() -> None:
    repo_root = repo_root_from(Path(__file__))
    exports_root = (repo_root / "KT_PROD_CLEANROOM" / "exports").resolve()
    ok, failures = validate_work_orders(repo_root=repo_root, exports_root=exports_root, max_files=2000)
    assert failures == []

    # Clean ops clones may not carry historical export artifacts. This validator must be able to
    # succeed on an exports tree that contains *zero* work orders, as long as any present work
    # orders are schema-valid.
    assert isinstance(ok, list)
    assert all(isinstance(p, str) and p for p in ok)
