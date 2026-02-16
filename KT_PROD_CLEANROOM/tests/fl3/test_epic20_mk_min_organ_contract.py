from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.schema_registry import validate_object_with_binding  # noqa: E402
from tools.verification.mk_min_organ_contract import build_min_organ_contract, main as mk_main  # noqa: E402


def test_epic20_mk_min_organ_contract_is_schema_valid_and_stable(tmp_path: Path) -> None:
    c1 = build_min_organ_contract(repo_root=_REPO_ROOT)
    c2 = build_min_organ_contract(repo_root=_REPO_ROOT)
    assert c1["contract_id"] == c2["contract_id"]
    validate_object_with_binding(c1)

    out_path = tmp_path / "organ_contract.json"
    assert mk_main(["--out", str(out_path)]) == 0
    assert mk_main(["--out", str(out_path)]) == 0  # WORM byte-identical no-op
    obj = json.loads(out_path.read_text(encoding="utf-8"))
    validate_object_with_binding(obj)
    assert obj["schema_id"] == "kt.factory.organ_contract.v1"

