from __future__ import annotations


class ConstitutionVersionError(Exception):
    pass


# V2 constitution binding (must remain consistent with C001 runtime invariants gate).
CONSTITUTION_VERSION_HASH = "7d41b58261ec85f1a1cb403a05722e3e8176ceefbddcb1de572d7ec847618b35"


def get_constitution_version_hash() -> str:
    return CONSTITUTION_VERSION_HASH


def validate_constitution_version_hash(value: str) -> None:
    if value != CONSTITUTION_VERSION_HASH:
        raise ConstitutionVersionError("Unknown constitution_version_hash (fail-closed)")

