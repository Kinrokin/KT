from __future__ import annotations

import json
from pathlib import Path

from schemas.fl3_suite_definition_schema import validate_fl3_suite_definition
from tools.suites.generate_metamorphic_variants import MetamorphicSpec, generate_metamorphic_suite


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    return here.parents[3]


def test_generate_metamorphic_suite_is_deterministic_and_schema_valid() -> None:
    repo_root = _repo_root()
    base_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "SUITES" / "SUITE_FORMAT_CONTROL.v1.json"
    base = json.loads(base_path.read_text(encoding="utf-8"))
    validate_fl3_suite_definition(base)

    spec = MetamorphicSpec(
        seed=123,
        variants_per_case=2,
        transforms=("whitespace", "punctuation", "format", "order"),
        counterpressure_level="mild",
    )
    out1 = generate_metamorphic_suite(base_suite=base, spec=spec, allow_sensitive_prompts=False)
    out2 = generate_metamorphic_suite(base_suite=base, spec=spec, allow_sensitive_prompts=False)
    assert out1["suite_definition_id"] == out2["suite_definition_id"]
    assert out1["cases"] == out2["cases"]
    validate_fl3_suite_definition(out1)

