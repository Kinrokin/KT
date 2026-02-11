from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional

OCE_STEP = 0.08
OCE_MAX = 1.0
OCE_DECAY = 0.10
HISTORY_MAX = 50


@dataclass
class OCEState:
    schema: str
    version: int
    updated_at_epoch_id: Optional[str]
    missed_exploration_streak: int
    opportunity_cost: float
    last_lane_executed: Optional[str]
    decay_events: int
    history: List[dict]

    def to_dict(self) -> dict:
        return asdict(self)


_STATE_PATH = Path(__file__).resolve().parent / "oce_state.json"


def _default_state() -> OCEState:
    return OCEState(
        schema="OCE_STATE_V1",
        version=1,
        updated_at_epoch_id=None,
        missed_exploration_streak=0,
        opportunity_cost=0.0,
        last_lane_executed=None,
        decay_events=0,
        history=[],
    )


def load_state() -> OCEState:
    if not _STATE_PATH.exists():
        return _default_state()
    try:
        payload = json.loads(_STATE_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"OCE state invalid JSON (fail-closed): {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != "OCE_STATE_V1":
        raise RuntimeError("OCE state missing or wrong schema (fail-closed)")
    return OCEState(
        schema="OCE_STATE_V1",
        version=int(payload.get("version", 1)),
        updated_at_epoch_id=payload.get("updated_at_epoch_id"),
        missed_exploration_streak=int(payload.get("missed_exploration_streak", 0) or 0),
        opportunity_cost=float(payload.get("opportunity_cost", 0.0) or 0.0),
        last_lane_executed=payload.get("last_lane_executed"),
        decay_events=int(payload.get("decay_events", 0) or 0),
        history=list(payload.get("history") or []),
    )


def save_state(state: OCEState) -> None:
    _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STATE_PATH.write_text(json.dumps(state.to_dict(), indent=2, sort_keys=True), encoding="utf-8")


def update_state(*, executed_lane: str, epoch_id: str) -> OCEState:
    if not executed_lane:
        raise RuntimeError("OCE update requires executed_lane (fail-closed)")
    state = load_state()
    streak = state.missed_exploration_streak
    cost = state.opportunity_cost
    decay_events = state.decay_events

    if executed_lane == "COVERAGE_HOP_RECOVERY":
        streak += 1
        cost = min(OCE_MAX, cost + OCE_STEP)
    else:
        streak = 0
        new_cost = max(0.0, cost - OCE_DECAY)
        if new_cost < cost:
            decay_events += 1
        cost = new_cost

    history = state.history + [
        {
            "epoch_id": epoch_id,
            "lane": executed_lane,
            "missed_exploration_streak": streak,
            "opportunity_cost": cost,
        }
    ]
    if len(history) > HISTORY_MAX:
        history = history[-HISTORY_MAX:]

    new_state = OCEState(
        schema="OCE_STATE_V1",
        version=state.version,
        updated_at_epoch_id=epoch_id,
        missed_exploration_streak=streak,
        opportunity_cost=cost,
        last_lane_executed=executed_lane,
        decay_events=decay_events,
        history=history,
    )
    save_state(new_state)
    return new_state


def oce_constants() -> dict:
    return {"oce_step": OCE_STEP, "oce_max": OCE_MAX, "oce_decay": OCE_DECAY}
