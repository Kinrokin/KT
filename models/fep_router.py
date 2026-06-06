from __future__ import annotations

import math
from dataclasses import dataclass, field


@dataclass
class FEPShadowRouter:
    beta: float = 0.82
    epsilon: float = 1e-6
    state: dict[str, float] = field(default_factory=dict)
    error_history: dict[str, list[float]] = field(default_factory=dict)
    runtime_authority: bool = False
    promotion_authority: bool = False

    def update_state(self, features: dict[str, float]) -> dict[str, float]:
        for key, value in features.items():
            prior = self.state.get(key, 0.0)
            self.state[key] = self.beta * prior + (1.0 - self.beta) * float(value)
        return dict(self.state)

    def observe_error(self, route_id: str, prediction_error: float) -> None:
        self.error_history.setdefault(route_id, []).append(float(prediction_error))

    def precision(self, route_id: str) -> float:
        values = self.error_history.get(route_id, [])
        if len(values) < 2:
            return 1.0
        mean = sum(values) / len(values)
        variance = sum((value - mean) ** 2 for value in values) / len(values)
        return 1.0 / (variance + self.epsilon)

    def route_scores(self, affinities: dict[str, float], costs: dict[str, float] | None = None) -> dict[str, float]:
        costs = costs or {}
        scores = {}
        state_mass = sum(abs(value) for value in self.state.values())
        for route_id, affinity in affinities.items():
            scores[route_id] = float(affinity) * math.log1p(self.precision(route_id)) + 0.01 * state_mass - float(costs.get(route_id, 0.0))
        return scores

    def choose_shadow_route(self, affinities: dict[str, float], costs: dict[str, float] | None = None) -> str:
        scores = self.route_scores(affinities, costs)
        return sorted(scores, key=lambda route_id: (-scores[route_id], route_id))[0]


__all__ = ["FEPShadowRouter"]
