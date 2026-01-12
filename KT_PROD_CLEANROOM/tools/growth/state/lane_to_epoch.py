"""
Canonical mapping from internal lane names to epoch plan specs.
Keep this as the single source of truth for plan selection.
"""

from pathlib import Path

_BASE = Path(__file__).resolve().parents[3] / "tools" / "growth" / "orchestrator" / "examples"

LANE_TO_EPOCH = {
    "COVERAGE_HOP_RECOVERY": _BASE / "EPOCH_NEXT_AUTO.json",
    "REANCHOR": _BASE / "EPOCH_REANCHOR_CONSTRAINT.json",
    "STABILIZER": _BASE / "EPOCH_PASS_PAIR_SEED.json",
    "DEPTH_CONSOLIDATION": _BASE / "EPOCH_NEXT_AUTO.json",  # fallback to coverage-like plan
    "NONE": _BASE / "EPOCH_NEXT_AUTO.json",
}


def resolve_epoch_spec(lane: str) -> Path:
    if lane not in LANE_TO_EPOCH:
        raise RuntimeError(f"Unknown lane '{lane}' (fail-closed)")
    path = LANE_TO_EPOCH[lane]
    if not path.exists():
        raise RuntimeError(f"Epoch spec missing for lane '{lane}': {path}")
    return path


_PLAN_TO_LANE = {v.resolve(): k for k, v in LANE_TO_EPOCH.items()}


def lane_for_plan(plan_path: Path) -> str:
    p = plan_path.resolve()
    if p in _PLAN_TO_LANE:
        return _PLAN_TO_LANE[p]
    raise RuntimeError(f"Cannot infer lane for plan {p} (fail-closed)")
