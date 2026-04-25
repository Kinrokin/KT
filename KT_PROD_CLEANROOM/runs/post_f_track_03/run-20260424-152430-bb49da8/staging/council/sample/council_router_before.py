from __future__ import annotations

class CouncilRouter:
    def __init__(self, providers: dict[str, object] | None = None):
        self.providers = providers or {}

    def plan(self, rmr: dict) -> list[str]:
        # Dry-run baseline: returns empty plan for non-commit rows.
        if rmr.get("decision_label") == "commit":
            return ["openai_hashed"]
        return []

    def execute(self, rmr: dict) -> dict:
        plan = self.plan(rmr)
        if not plan:
            return {"mode": "dry-run", "provider_calls": [], "decision_label": "defer"}
        return {"mode": "dry-run", "provider_calls": [], "decision_label": rmr.get("decision_label", "defer")}
