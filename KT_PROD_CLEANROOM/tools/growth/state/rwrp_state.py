from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Optional

RWRP_ALPHA = 0.6
RWRP_BETA = 0.2
RWRP_MAX = 0.7


@dataclass
class LaneRegret:
    mean_regret: float
    replay_count: int
    penalty: float

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RWRPState:
    schema: str
    version: int
    updated_at_epoch_id: Optional[str]
    lane_regret_memory: Dict[str, LaneRegret]

    def to_dict(self) -> dict:
        return {
            "schema": self.schema,
            "version": self.version,
            "updated_at_epoch_id": self.updated_at_epoch_id,
            "lane_regret_memory": {k: v.to_dict() for k, v in self.lane_regret_memory.items()},
        }


_STATE_PATH = Path(__file__).resolve().parent / "rwrp_state.json"


def _default_state() -> RWRPState:
    return RWRPState(schema="RWRP_STATE_V1", version=1, updated_at_epoch_id=None, lane_regret_memory={})


def load_state() -> RWRPState:
    if not _STATE_PATH.exists():
        return _default_state()
    try:
        payload = json.loads(_STATE_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"RWRP state invalid JSON (fail-closed): {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != "RWRP_STATE_V1":
        raise RuntimeError("RWRP state missing or wrong schema (fail-closed)")
    mem = {}
    for lane, data in (payload.get("lane_regret_memory") or {}).items():
        mem[lane] = LaneRegret(
            mean_regret=float(data.get("mean_regret", 0.0) or 0.0),
            replay_count=int(data.get("replay_count", 0) or 0),
            penalty=float(data.get("penalty", 0.0) or 0.0),
        )
    return RWRPState(
        schema="RWRP_STATE_V1",
        version=int(payload.get("version", 1)),
        updated_at_epoch_id=payload.get("updated_at_epoch_id"),
        lane_regret_memory=mem,
    )


def save_state(state: RWRPState) -> None:
    _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STATE_PATH.write_text(json.dumps(state.to_dict(), indent=2, sort_keys=True), encoding="utf-8")


def update_state(*, executed_lane: str, epoch_id: str, regret_global: Optional[float]) -> RWRPState:
    if not executed_lane:
        raise RuntimeError("RWRP update requires executed_lane (fail-closed)")
    if regret_global is None:
        # fail-closed: cannot update without regret evidence
        raise RuntimeError("RWRP update requires regret_global (fail-closed)")
    state = load_state()
    mem = dict(state.lane_regret_memory)
    lane_mem = mem.get(executed_lane, LaneRegret(mean_regret=0.0, replay_count=0, penalty=0.0))

    # update rolling mean regret
    n = lane_mem.replay_count
    new_mean = (lane_mem.mean_regret * n + regret_global) / (n + 1)
    replay_count = n + 1
    penalty = min(RWRP_MAX, new_mean * (1 + RWRP_BETA * replay_count) * RWRP_ALPHA)

    mem[executed_lane] = LaneRegret(mean_regret=new_mean, replay_count=replay_count, penalty=penalty)
    new_state = RWRPState(
        schema="RWRP_STATE_V1",
        version=state.version,
        updated_at_epoch_id=epoch_id,
        lane_regret_memory=mem,
    )
    save_state(new_state)
    return new_state


def rwrp_constants() -> dict:
    return {"rwrp_alpha": RWRP_ALPHA, "rwrp_beta": RWRP_BETA, "rwrp_max": RWRP_MAX}
