from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Dict

from KT_PROD_CLEANROOM.tools.growth.orchestrator.epoch_schemas import EpochPlan


@dataclass(frozen=True)
class EpochManifest:
    epoch_id: str
    kernel_identity: Dict[str, str]
    crucible_order: list[str]
    crucible_specs: Dict[str, str]
    crucible_spec_hashes: Dict[str, str]
    runner_config: Dict[str, object]
    budgets: Dict[str, int]
    stop_conditions: Dict[str, int]
    seed: int
    epoch_hash: str

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def _sha256_json(obj: Dict[str, object]) -> str:
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return sha256(payload).hexdigest()


def compute_epoch_hash(plan: EpochPlan, *, crucible_spec_hashes: Dict[str, str]) -> str:
    # Deterministic: depends only on plan + crucible spec hashes + kernel identity.
    obj = {
        "epoch_id": plan.epoch_id,
        "kernel_identity": plan.kernel_identity.to_dict(),
        "crucible_order": list(plan.crucible_order),
        "crucible_specs": dict(plan.crucible_specs),
        "crucible_spec_hashes": dict(crucible_spec_hashes),
        "runner_config": plan.runner_config.to_dict(),
        "budgets": plan.budgets.to_dict(),
        "stop_conditions": plan.stop_conditions.to_dict(),
        "seed": plan.seed,
    }
    return _sha256_json(obj)


def build_manifest(plan: EpochPlan, *, crucible_spec_hashes: Dict[str, str]) -> EpochManifest:
    epoch_hash = compute_epoch_hash(plan, crucible_spec_hashes=crucible_spec_hashes)
    return EpochManifest(
        epoch_id=plan.epoch_id,
        kernel_identity=plan.kernel_identity.to_dict(),
        crucible_order=list(plan.crucible_order),
        crucible_specs=dict(plan.crucible_specs),
        crucible_spec_hashes=dict(crucible_spec_hashes),
        runner_config=plan.runner_config.to_dict(),
        budgets=plan.budgets.to_dict(),
        stop_conditions=plan.stop_conditions.to_dict(),
        seed=plan.seed,
        epoch_hash=epoch_hash,
    )
