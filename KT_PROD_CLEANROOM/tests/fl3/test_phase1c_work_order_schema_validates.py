from __future__ import annotations

import json
from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.schema_registry import SchemaValidationError, validate_object_with_binding  # noqa: E402
from tools.verification.strict_json import DuplicateKeyError, loads_no_dupes  # noqa: E402


def test_phase1c_work_order_schema_validates_known_good() -> None:
    p = _REPO_ROOT / "KT_PROD_CLEANROOM" / "kt.phase1c_work_order.v1.json"
    obj = loads_no_dupes(p.read_text(encoding="utf-8"))
    validate_object_with_binding(obj)


def test_phase1c_work_order_schema_rejects_missing_constraints() -> None:
    p = _REPO_ROOT / "KT_PROD_CLEANROOM" / "kt.phase1c_work_order.v1.json"
    obj = loads_no_dupes(p.read_text(encoding="utf-8"))

    obj2 = dict(obj)
    obj2.pop("prime_constraints", None)
    with pytest.raises(SchemaValidationError):
        validate_object_with_binding(obj2)


def test_phase1c_work_order_rejects_duplicate_keys() -> None:
    # Ensure strict loader catches ambiguity (law must be unambiguous).
    with pytest.raises(DuplicateKeyError):
        loads_no_dupes('{"schema_id":"kt.phase1c_work_order.v1","schema_id":"kt.phase1c_work_order.v1"}')

