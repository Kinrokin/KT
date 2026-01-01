from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any, Dict, Optional

from curriculum.curriculum_schemas import (
    CurriculumPackageSchema,
    CurriculumReceiptSchema,
    CurriculumRefusalError,
    REFUSE_FORBIDDEN_IMPORT,
    REFUSE_SCHEMA,
    STATUS_OK,
    STATUS_REFUSED,
)
from schemas.base_schema import SchemaValidationError


@dataclass(frozen=True)
class CurriculumIngestResult:
    receipt: CurriculumReceiptSchema
    refusal_code: Optional[str]


_FORBIDDEN_TRAINING_MODULE_TOPS = {
    "torch",
    "tensorflow",
    "jax",
    "transformers",
    "datasets",
    "accelerate",
    "pytorch_lightning",
    "lightning",
}


def _any_forbidden_module_loaded() -> bool:
    for name in list(sys.modules.keys()):
        if not name:
            continue
        top = name.split(".", 1)[0]
        if top in _FORBIDDEN_TRAINING_MODULE_TOPS:
            return True
    return False


class CurriculumIngest:
    @staticmethod
    def accept(*, context: Dict[str, Any], package: CurriculumPackageSchema) -> CurriculumReceiptSchema:
        # Binding API: schema-valid package only.
        return CurriculumIngest.accept_payload(context=context, package_payload=package.to_dict()).receipt

    @staticmethod
    def accept_payload(*, context: Dict[str, Any], package_payload: Any) -> CurriculumIngestResult:
        # Strictly validation + hash-only receipt. No external calls; no writes.
        if _any_forbidden_module_loaded():
            receipt = _refusal_receipt(runtime_registry_hash="0" * 64, package_hash="0" * 64, refusal_code=REFUSE_FORBIDDEN_IMPORT)
            return CurriculumIngestResult(receipt=receipt, refusal_code=REFUSE_FORBIDDEN_IMPORT)

        try:
            payload = package_payload if isinstance(package_payload, dict) else {}
            pkg = CurriculumPackageSchema.from_dict(payload)
        except CurriculumRefusalError as exc:
            runtime_registry_hash = payload.get("runtime_registry_hash") if isinstance(payload, dict) else None
            rrh = runtime_registry_hash if isinstance(runtime_registry_hash, str) and len(runtime_registry_hash) == 64 else ("0" * 64)
            receipt = _refusal_receipt(runtime_registry_hash=rrh, package_hash="0" * 64, refusal_code=exc.refusal_code)
            return CurriculumIngestResult(receipt=receipt, refusal_code=exc.refusal_code)
        except SchemaValidationError:
            receipt = _refusal_receipt(runtime_registry_hash="0" * 64, package_hash="0" * 64, refusal_code=REFUSE_SCHEMA)
            return CurriculumIngestResult(receipt=receipt, refusal_code=REFUSE_SCHEMA)

        pkg_dict = pkg.to_dict()
        package_hash = CurriculumPackageSchema.compute_package_hash(pkg_dict)
        runtime_registry_hash = str(pkg_dict["runtime_registry_hash"])
        receipt_payload: Dict[str, Any] = {
            "schema_id": CurriculumReceiptSchema.SCHEMA_ID,
            "schema_version_hash": CurriculumReceiptSchema.SCHEMA_VERSION_HASH,
            "status": STATUS_OK,
            "runtime_registry_hash": runtime_registry_hash,
            "package_hash": package_hash,
            "receipt_hash": "",
        }
        receipt_payload["receipt_hash"] = CurriculumReceiptSchema.compute_receipt_hash(receipt_payload)
        CurriculumReceiptSchema.validate(receipt_payload)
        return CurriculumIngestResult(receipt=CurriculumReceiptSchema.from_dict(receipt_payload), refusal_code=None)


def _refusal_receipt(*, runtime_registry_hash: str, package_hash: str, refusal_code: str) -> CurriculumReceiptSchema:
    payload: Dict[str, Any] = {
        "schema_id": CurriculumReceiptSchema.SCHEMA_ID,
        "schema_version_hash": CurriculumReceiptSchema.SCHEMA_VERSION_HASH,
        "status": STATUS_REFUSED,
        "runtime_registry_hash": runtime_registry_hash,
        "package_hash": package_hash,
        "refusal_code": refusal_code,
        "receipt_hash": "",
    }
    payload["receipt_hash"] = CurriculumReceiptSchema.compute_receipt_hash(payload)
    CurriculumReceiptSchema.validate(payload)
    return CurriculumReceiptSchema.from_dict(payload)

