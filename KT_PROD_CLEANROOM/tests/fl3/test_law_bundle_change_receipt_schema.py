from __future__ import annotations

import hashlib
import json

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from schemas.schema_files import schema_version_hash  # noqa: E402
from schemas.schema_registry import validate_object_with_binding  # noqa: E402


def _sha_id(record: dict, drop_keys: set[str]) -> str:
    payload = {k: v for k, v in record.items() if k not in drop_keys}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def test_law_bundle_change_receipt_schema_validates_minimal() -> None:
    obj = {
        "schema_id": "kt.law_bundle_change_receipt.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.law_bundle_change_receipt.v1.json"),
        "receipt_id": "",
        "bundle_id": "LAW_BUNDLE_FL3",
        "old_ref": "HEAD",
        "old_bundle_hash": "a" * 64,
        "new_bundle_hash": "b" * 64,
        "diff": {
            "added": [{"path": "KT_PROD_CLEANROOM/AUDITS/NEW.json", "sha256": "c" * 64}],
            "removed": [],
            "modified": [{"path": "KT_PROD_CLEANROOM/AUDITS/OLD.json", "old_sha256": "d" * 64, "new_sha256": "e" * 64}],
        },
        "counts": {"added": 1, "removed": 0, "modified": 1},
        "created_at": "2026-01-01T00:00:00Z",
    }
    obj["receipt_id"] = _sha_id(obj, {"created_at", "receipt_id"})
    validate_object_with_binding(obj)

