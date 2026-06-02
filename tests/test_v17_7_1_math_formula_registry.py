from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import FORMULAS, read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_1_math_formula_registry_matches_locked_formulas() -> None:
    receipt = read_json(ROOT / "reports" / "v17_7_1_formula_registry_receipt.json")
    constitution = (ROOT / "rules" / "MATH_EVIDENCE_CONSTITUTION.md").read_text(encoding="utf-8")
    assert receipt["formula_lock_status"] == "PASS"
    assert receipt["formulas"] == FORMULAS
    for name, formula in FORMULAS.items():
        assert f"{name} = {formula}" in constitution
