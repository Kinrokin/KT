from __future__ import annotations

from itertools import combinations
from typing import Callable


def marginal_contribution(route_id: str, coalition: set[str], value_fn: Callable[[set[str]], float]) -> float:
    without = set(coalition) - {route_id}
    with_route = set(without) | {route_id}
    return float(value_fn(with_route) - value_fn(without))


def approximate_harsanyi_dividends(route_ids: list[str], value_fn: Callable[[set[str]], float]) -> dict[str, float]:
    contributions = {route_id: 0.0 for route_id in route_ids}
    counts = {route_id: 0 for route_id in route_ids}
    for size in range(1, len(route_ids) + 1):
        for coalition_tuple in combinations(route_ids, size):
            coalition = set(coalition_tuple)
            for route_id in coalition:
                contributions[route_id] += marginal_contribution(route_id, coalition, value_fn)
                counts[route_id] += 1
    return {route_id: contributions[route_id] / max(counts[route_id], 1) for route_id in route_ids}


def shadow_pruning_recommendations(route_ids: list[str], value_fn: Callable[[set[str]], float], threshold: float = 0.0) -> dict[str, dict[str, object]]:
    dividends = approximate_harsanyi_dividends(route_ids, value_fn)
    return {
        route_id: {
            "harsanyi_dividend_surrogate": dividend,
            "shadow_action": "REVIEW_LOW_MARGINAL_CONTRIBUTION" if dividend <= threshold else "PRESERVE_FOR_MEASUREMENT",
            "model_mutation_authorized": False,
            "runtime_pruning_authorized": False,
        }
        for route_id, dividend in dividends.items()
    }


__all__ = ["approximate_harsanyi_dividends", "marginal_contribution", "shadow_pruning_recommendations"]
