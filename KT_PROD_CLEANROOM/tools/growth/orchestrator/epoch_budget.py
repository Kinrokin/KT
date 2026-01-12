from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from KT_PROD_CLEANROOM.tools.growth.orchestrator.epoch_schemas import (
    EpochBudgets,
    EpochSchemaError,
)


@dataclass(frozen=True)
class BudgetCheckResult:
    ok: bool
    reason: Optional[str]


def validate_crucible_budgets(
    *,
    epoch_budgets: EpochBudgets,
    crucible_time_ms: int,
    crucible_rss_mb: int,
) -> BudgetCheckResult:
    if crucible_time_ms > epoch_budgets.per_crucible_timeout_ms:
        return BudgetCheckResult(
            ok=False,
            reason="crucible_time_ms exceeds epoch per_crucible_timeout_ms",
        )
    if crucible_rss_mb > epoch_budgets.per_crucible_rss_mb:
        return BudgetCheckResult(
            ok=False,
            reason="crucible_runner_memory_max_mb exceeds epoch per_crucible_rss_mb",
        )
    return BudgetCheckResult(ok=True, reason=None)


def assert_budget_ok(result: BudgetCheckResult) -> None:
    if not result.ok:
        raise EpochSchemaError(f"Budget violation: {result.reason} (fail-closed)")
