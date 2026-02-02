from __future__ import annotations

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.training.fl3_factory.hypotheses import build_policy_bundles  # noqa: E402
from tools.verification.fl3_validators import validate_schema_bound_object  # noqa: E402


def test_fl4_hypotheses_emits_exact_count_unique_bundle_ids() -> None:
    bundles = build_policy_bundles(job_id="job", seed=1, parent_hash="0" * 64, count=48)
    assert len(bundles) == 48
    ids = [b.get("bundle_id") for b in bundles]
    assert len(set(ids)) == 48
    for b in bundles:
        validate_schema_bound_object(b)
        assert b.get("schema_id") == "kt.policy_bundle.v1"
        assert b.get("adapter_type") == "A"


def test_fl4_hypotheses_has_no_utility_pack_coupling() -> None:
    txt = (_REPO_ROOT / "KT_PROD_CLEANROOM" / "tools" / "training" / "fl3_factory" / "hypotheses.py").read_text(encoding="utf-8")
    # Fail closed on any sign that hypothesis generation is coupled to evaluation/utility logic.
    forbidden = [
        "UTILITY_PACK",
        "utility_floor",
        "thresholds.json",
        "scoring_spec",
        "metric_probes",
        "metric_bindings",
    ]
    for token in forbidden:
        assert token not in txt

