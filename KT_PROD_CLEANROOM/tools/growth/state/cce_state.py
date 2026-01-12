from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional

CCE_STEP = 0.10
CCE_MAX = 1.00
CCE_DECAY = 0.05
HISTORY_MAX = 50


@dataclass
class CCEState:
    schema: str
    version: int
    updated_at_epoch_id: Optional[str]
    coverage_streak: int
    coverage_cost: float
    decay_events: int
    last_lane_executed: Optional[str]
    history: List[dict]

    def to_dict(self) -> dict:
        return asdict(self)


_STATE_PATH = Path(__file__).resolve().parent / "cce_state.json"


def _default_state() -> CCEState:
    return CCEState(
        schema="CCE_STATE_V1",
        version=1,
        updated_at_epoch_id=None,
        coverage_streak=0,
        coverage_cost=0.0,
        decay_events=0,
        last_lane_executed=None,
        history=[],
    )


def load_state() -> CCEState:
    if not _STATE_PATH.exists():
        return _default_state()
    try:
        payload = json.loads(_STATE_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"CCE state invalid JSON (fail-closed): {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != "CCE_STATE_V1":
        raise RuntimeError("CCE state missing or wrong schema (fail-closed)")
    return CCEState(
        schema="CCE_STATE_V1",
        version=int(payload.get("version", 1)),
        updated_at_epoch_id=payload.get("updated_at_epoch_id"),
        coverage_streak=int(payload.get("coverage_streak", 0) or 0),
        coverage_cost=float(payload.get("coverage_cost", 0.0) or 0.0),
        decay_events=int(payload.get("decay_events", 0) or 0),
        last_lane_executed=payload.get("last_lane_executed"),
        history=list(payload.get("history") or []),
    )


def save_state(state: CCEState) -> None:
    _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STATE_PATH.write_text(json.dumps(state.to_dict(), indent=2, sort_keys=True), encoding="utf-8")


def update_state(*, executed_lane: str, epoch_id: str) -> CCEState:
    if not executed_lane:
        raise RuntimeError("CCE update requires executed_lane (fail-closed)")
    state = load_state()
    streak = state.coverage_streak
    cost = state.coverage_cost
    decay_events = state.decay_events

    if executed_lane == "COVERAGE_HOP_RECOVERY":
        streak += 1
        cost = min(CCE_MAX, cost + CCE_STEP)
    else:
        streak = 0
        new_cost = max(0.0, cost - CCE_DECAY)
        if new_cost < cost:
            decay_events += 1
        cost = new_cost

    history = state.history + [
        {
            "epoch_id": epoch_id,
            "lane": executed_lane,
            "coverage_streak": streak,
            "coverage_cost": cost,
        }
    ]
    if len(history) > HISTORY_MAX:
        history = history[-HISTORY_MAX:]

    new_state = CCEState(
        schema="CCE_STATE_V1",
        version=state.version,
        updated_at_epoch_id=epoch_id,
        coverage_streak=streak,
        coverage_cost=cost,
        decay_events=decay_events,
        last_lane_executed=executed_lane,
        history=history,
    )
    save_state(new_state)
    return new_state


def cce_constants() -> dict:
    return {"cce_step": CCE_STEP, "cce_max": CCE_MAX, "cce_decay": CCE_DECAY}
