from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = ROOT / "04_PROD_TEMPLE_V2" / "src"
sys.path.insert(0, str(SRC_ROOT))
sys.path.insert(0, str(ROOT))

import policy_c.sweep_runner as sr  # noqa: E402


def _looks_like_schema(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    schemaish = any(
        key in obj for key in ("$schema", "$id", "$ref", "definitions", "properties", "allOf", "oneOf", "anyOf")
    )
    planish = any(key in obj for key in ("runs", "grid"))
    return bool(schemaish and not planish)


def test_validator_exists() -> None:
    names = [name for name in dir(sr) if "validate" in name or "assert" in name or "plan" in name]
    callables = [name for name in names if callable(getattr(sr, name))]
    assert callables, f"No validator-like callable found in policy_c.sweep_runner: {names}"


def test_schema_rejected_by_resolver() -> None:
    schema_like = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "properties": {"x": {"type": "string"}},
        "required": ["x"],
    }
    assert _looks_like_schema(schema_like) is True
    plan_like = {"runs": [{"run_id": "x"}], "properties": {"x": {"type": "string"}}}
    assert _looks_like_schema(plan_like) is False


def test_autogen_writes_into_export(tmp_path: Path) -> None:
    export_root = tmp_path / "exports" / "policy_c" / "test_run" / "sweep_a"
    export_root.mkdir(parents=True)
    plan = {"runs": [{"run_id": "autogen-run", "dummy": 1}]}
    out_path = export_root / "policy_c_sweep_plan.autogen.json"
    out_path.write_text(json.dumps(plan), encoding="utf-8")
    assert out_path.exists()
    assert out_path.suffix == ".json"
    assert out_path.resolve().is_relative_to((tmp_path / "exports").resolve())

