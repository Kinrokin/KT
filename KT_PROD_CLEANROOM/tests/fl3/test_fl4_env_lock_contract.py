from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.verification.fl3_validators import validate_schema_bound_object  # noqa: E402


def test_fl4_env_lock_contract_is_schema_valid() -> None:
    p = Path(_REPO_ROOT) / "KT_PROD_CLEANROOM" / "AUDITS" / "FL4_ENV_LOCK.json"
    obj = json.loads(p.read_text(encoding="utf-8"))
    validate_schema_bound_object(obj)

