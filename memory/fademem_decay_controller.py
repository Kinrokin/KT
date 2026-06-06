from __future__ import annotations

import math
from dataclasses import dataclass


NON_DECAYING_AUTHORITY_CLASSES = {"live_repo_truth", "merged_main_receipt", "claim_ceiling_law"}


@dataclass(frozen=True)
class FadeMemDecayController:
    base_lambda: float = 0.12
    access_bonus: float = 0.03
    relevance_bonus: float = 0.08

    def decay_rate(self, semantic_relevance: float, access_count: int, authority_class: str = "hypothesis") -> float:
        if authority_class in NON_DECAYING_AUTHORITY_CLASSES:
            return 0.0
        protected = self.relevance_bonus * max(min(semantic_relevance, 1.0), 0.0) + self.access_bonus * min(max(access_count, 0), 10)
        return max(self.base_lambda - protected, 0.005)

    def retention(self, age: float, semantic_relevance: float = 0.0, access_count: int = 0, authority_class: str = "hypothesis") -> float:
        rate = self.decay_rate(semantic_relevance, access_count, authority_class)
        return 1.0 if rate == 0.0 else math.exp(-rate * max(age, 0.0))

    def should_decay(self, age: float, semantic_relevance: float = 0.0, access_count: int = 0, authority_class: str = "hypothesis", threshold: float = 0.35) -> bool:
        if authority_class in NON_DECAYING_AUTHORITY_CLASSES:
            return False
        return self.retention(age, semantic_relevance, access_count, authority_class) < threshold


__all__ = ["FadeMemDecayController", "NON_DECAYING_AUTHORITY_CLASSES"]
