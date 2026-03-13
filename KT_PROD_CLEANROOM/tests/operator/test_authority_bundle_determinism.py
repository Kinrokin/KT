from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from tools.operator.crypto_attestation import (
    AUTHORITY_BUNDLE_SCHEMA_ID,
    AUTHORITY_ENVELOPE_SCHEMA_ID,
    AUTHORITY_SUBJECT_SCHEMA_ID,
    mint_authority_bundle,
    mint_envelope,
    subject_sha256,
)
from tools.operator.titanium_common import repo_root
from tools.verification.strict_json import load_no_dupes


def _load_schema() -> dict:
    root = repo_root()
    schema_path = (root / "KT_PROD_CLEANROOM" / "governance" / "authority_bundle.schema.json").resolve()
    schema = load_no_dupes(schema_path)
    assert isinstance(schema, dict)
    return schema


def test_authority_subject_is_bit_for_bit_deterministic_and_envelope_is_not() -> None:
    subj = {
        "schema_id": AUTHORITY_SUBJECT_SCHEMA_ID,
        "truth_subject_commit": "0" * 40,
        "truth_produced_at_commit": "1" * 40,
        "law_surface_hashes": {"KT_PROD_CLEANROOM/governance/AUTHORITY_CONTRACT.md": "a" * 64},
        "supersedes_subject_sha256": "",
        "evidence": [
            {
                "name": "fresh_clone_admissibility_receipt",
                "ref": "KT_PROD_CLEANROOM/reports/fresh_clone_admissibility_receipt.json",
                "sha256": "b" * 64,
            }
        ],
    }

    h1 = subject_sha256(subj)
    h2 = subject_sha256(json.loads(json.dumps(subj)))  # ensure no object identity leakage
    assert h1 == h2

    env1 = mint_envelope(subject_sha256_hex=h1, attestation_mode="NONE", generated_utc="2026-01-01T00:00:00Z")
    env2 = mint_envelope(subject_sha256_hex=h1, attestation_mode="NONE", generated_utc="2026-01-02T00:00:00Z")
    assert env1 != env2
    assert env1["schema_id"] == AUTHORITY_ENVELOPE_SCHEMA_ID

    b1 = mint_authority_bundle(subject=subj, envelope=env1)
    b2 = mint_authority_bundle(subject=subj, envelope=env2)
    assert b1["schema_id"] == AUTHORITY_BUNDLE_SCHEMA_ID
    assert b2["schema_id"] == AUTHORITY_BUNDLE_SCHEMA_ID
    assert b1["subject_sha256"] == h1
    assert b2["subject_sha256"] == h1
    assert b1 != b2  # envelope differs

    schema = _load_schema()
    jsonschema.validate(instance=b1, schema=schema)
    jsonschema.validate(instance=b2, schema=schema)


def test_authority_subject_forbids_volatile_keys() -> None:
    subj = {
        "schema_id": AUTHORITY_SUBJECT_SCHEMA_ID,
        "truth_subject_commit": "0" * 40,
        "truth_produced_at_commit": "1" * 40,
        "law_surface_hashes": {"KT_PROD_CLEANROOM/governance/AUTHORITY_CONTRACT.md": "a" * 64},
        "supersedes_subject_sha256": "",
        "generated_utc": "2026-01-01T00:00:00Z",
        "evidence": [{"name": "x", "ref": "y", "sha256": "b" * 64}],
    }
    with pytest.raises(RuntimeError, match="forbidden key"):
        _ = subject_sha256(subj)

