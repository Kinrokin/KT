from __future__ import annotations

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.verification.cohort0_manufacture import derive_canonical_13_lobes  # noqa: E402
from tools.verification.strict_json import load_no_dupes  # noqa: E402


def test_cohort0_canonical_13_lobes_derived_from_doctrine() -> None:
    role_weights = load_no_dupes(_REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / "ROLE_FITNESS_WEIGHTS.json")
    assert isinstance(role_weights, dict)
    roles = role_weights.get("roles")
    assert isinstance(roles, list)
    # Tight drift alarm: doctrine currently defines 14 roles total (13 lobes + ARBITER).
    assert len(roles) == 14
    lobes = derive_canonical_13_lobes(role_weights=role_weights)

    assert len(lobes) == 13
    adapter_ids = [s.adapter_id for s in lobes]
    assert len(set(adapter_ids)) == 13

    # Deterministic mapping: lobe.<role_id.lower()>.v1, excluding ARBITER.
    role_ids = [s.role_id for s in lobes]
    assert "ARBITER" not in role_ids
    for s in lobes:
        assert s.adapter_id == f"lobe.{s.role_id.lower()}.v1"

    # Stable ordering requirement for runtime registry (sorted by adapter_id).
    assert adapter_ids == sorted(adapter_ids)
