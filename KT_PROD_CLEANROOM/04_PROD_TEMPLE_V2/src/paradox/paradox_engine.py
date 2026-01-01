from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from paradox.paradox_schemas import ParadoxResultSchema, ParadoxTaskSchema, ParadoxTriggerSchema
from schemas.schema_hash import sha256_json


RuntimeContext = Dict[str, Any]


@dataclass(frozen=True)
class ParadoxEngineError(RuntimeError):
    message: str

    def __str__(self) -> str:
        return self.message


class ParadoxEngine:
    _ELIGIBLE_TRIGGER_TYPES = {"PARADOX_SIGNAL"}
    _ELIGIBLE_CONDITIONS = {"contradiction", "self_reference", "infinite_loop"}

    @staticmethod
    def run(*, context: RuntimeContext, trigger: ParadoxTriggerSchema) -> ParadoxResultSchema:
        if not isinstance(context, dict):
            raise ParadoxEngineError("context must be a dict (fail-closed)")

        trigger_payload = trigger.to_dict()
        trigger_hash = sha256_json(trigger_payload)

        eligible = (
            trigger_payload["trigger_type"] in ParadoxEngine._ELIGIBLE_TRIGGER_TYPES
            and trigger_payload["condition"] in ParadoxEngine._ELIGIBLE_CONDITIONS
            and trigger_payload["severity"] >= 5
            and trigger_payload["confidence"] >= 50
        )

        if not eligible:
            task_hash = "0" * 64
            result_hash = ParadoxResultSchema.compute_result_hash(
                status=ParadoxResultSchema.STATUS_NOOP,
                eligible=False,
                trigger_hash=trigger_hash,
                task_hash=task_hash,
            )
            return ParadoxResultSchema.from_dict(
                {
                    "schema_id": ParadoxResultSchema.SCHEMA_ID,
                    "schema_version_hash": ParadoxResultSchema.SCHEMA_VERSION_HASH,
                    "status": ParadoxResultSchema.STATUS_NOOP,
                    "eligible": False,
                    "trigger_hash": trigger_hash,
                    "task_hash": task_hash,
                    "task": None,
                    "result_hash": result_hash,
                }
            )

        task_type = "PARADOX_INJECTION_V1"
        task_hash = sha256_json({"trigger_hash": trigger_hash, "task_type": task_type})
        task = ParadoxTaskSchema.from_dict(
            {
                "schema_id": ParadoxTaskSchema.SCHEMA_ID,
                "schema_version_hash": ParadoxTaskSchema.SCHEMA_VERSION_HASH,
                "task_hash": task_hash,
                "trigger_hash": trigger_hash,
                "task_type": task_type,
            }
        )

        result_hash = ParadoxResultSchema.compute_result_hash(
            status=ParadoxResultSchema.STATUS_INJECTED,
            eligible=True,
            trigger_hash=trigger_hash,
            task_hash=task_hash,
        )
        return ParadoxResultSchema.from_dict(
            {
                "schema_id": ParadoxResultSchema.SCHEMA_ID,
                "schema_version_hash": ParadoxResultSchema.SCHEMA_VERSION_HASH,
                "status": ParadoxResultSchema.STATUS_INJECTED,
                "eligible": True,
                "trigger_hash": trigger_hash,
                "task_hash": task_hash,
                "task": task.to_dict(),
                "result_hash": result_hash,
            }
        )

