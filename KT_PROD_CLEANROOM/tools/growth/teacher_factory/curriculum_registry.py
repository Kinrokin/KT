from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from teacher_schemas import CurriculumPackageSchema, CurriculumSignatureSchema, TeacherSchemaError


def register_signed_package(
    *,
    package: CurriculumPackageSchema,
    signature: CurriculumSignatureSchema,
    registry_path: Path,
    package_path: Optional[Path] = None,
) -> None:
    registry_path.parent.mkdir(parents=True, exist_ok=True)

    payload = package.to_dict()
    sig_payload = signature.to_dict()

    CurriculumPackageSchema.validate(payload)
    CurriculumSignatureSchema.validate(sig_payload)

    record = {
        "package_id": payload["package_id"],
        "runtime_registry_hash": payload["runtime_registry_hash"],
        "package_hash": sig_payload["package_hash"],
        "signature": sig_payload["signature"],
        "key_id": sig_payload["key_id"],
    }
    if package_path is not None:
        record["package_path"] = str(package_path)

    with registry_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")
