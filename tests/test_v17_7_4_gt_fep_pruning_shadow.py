from __future__ import annotations

from pruning.gt_fep_dividend_calculator import approximate_harsanyi_dividends, shadow_pruning_recommendations


def test_gt_fep_dividend_calculator_identifies_positive_marginal_contribution() -> None:
    def value_fn(coalition: set[str]) -> float:
        return (1.0 if "stable" in coalition else 0.0) + (0.2 if "compact" in coalition else 0.0)

    dividends = approximate_harsanyi_dividends(["stable", "compact"], value_fn)

    assert dividends["stable"] > dividends["compact"]
    assert dividends["stable"] > 0


def test_gt_fep_pruning_recommendations_never_mutate_runtime() -> None:
    def value_fn(coalition: set[str]) -> float:
        return 1.0 if "stable" in coalition else 0.0

    recs = shadow_pruning_recommendations(["stable", "dead_weight"], value_fn)

    assert recs["dead_weight"]["runtime_pruning_authorized"] is False
    assert recs["dead_weight"]["model_mutation_authorized"] is False
