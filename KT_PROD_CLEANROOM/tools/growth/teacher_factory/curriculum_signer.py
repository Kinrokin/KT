from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from teacher_schemas import CurriculumPackageSchema, CurriculumSignatureSchema, TeacherSchemaError, sha256_text


@dataclass(frozen=True)
class SignedPackage:
    package: CurriculumPackageSchema
    signature: CurriculumSignatureSchema


def sign_package(*, package: CurriculumPackageSchema, key_id: str = "LOCAL_SHA256") -> SignedPackage:
    payload = package.to_dict()
    package_hash = CurriculumPackageSchema.compute_package_hash(payload)
    signature_hash = sha256_text(f"{key_id}:{package_hash}")
    sig_payload = {
        "schema_id": CurriculumSignatureSchema.SCHEMA_ID,
        "schema_version_hash": CurriculumSignatureSchema.SCHEMA_VERSION_HASH,
        "key_id": key_id,
        "package_hash": package_hash,
        "signature": signature_hash,
    }
    CurriculumSignatureSchema.validate(sig_payload)
    return SignedPackage(package=package, signature=CurriculumSignatureSchema.from_dict(sig_payload))


def verify_signature(*, package: CurriculumPackageSchema, signature: CurriculumSignatureSchema) -> bool:
    sig_payload = signature.to_dict()
    try:
        CurriculumSignatureSchema.validate(sig_payload)
    except TeacherSchemaError:
        return False
    package_hash = CurriculumPackageSchema.compute_package_hash(package.to_dict())
    if sig_payload["package_hash"] != package_hash:
        return False
    expected = sha256_text(f"{sig_payload['key_id']}:{package_hash}")
    return sig_payload["signature"] == expected

