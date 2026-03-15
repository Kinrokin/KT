from __future__ import annotations

import json
from pathlib import Path

from tools.verification.fl3_validators import validate_schema_bound_object
from tools.verification.validate_receipts import validate_receipts_dir


def test_change_receipt_legacy_missing_schema_version_hash_is_valid() -> None:
    receipt = {
        "schema_id": "kt.change_receipt.v1",
        "actor": "dev-bot",
        "change_id": "1" * 64,
        "phase": "pre",
        "phase_id": "PHASE_X",
        "timestamp_utc": "2026-01-01T00:00:00Z",
        "files_checked": [{"path": "x", "sha256": "2" * 64}],
        "outcome": "PASS",
        "notes": "test",
    }
    validate_schema_bound_object(receipt)


def test_validate_receipts_dir_fails_closed_on_unknown_schema_id(tmp_path: Path) -> None:
    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)
    (receipts_dir / "bad.json").write_text(json.dumps({"schema_id": "kt.unknown.v1"}) + "\n", encoding="utf-8")
    report = validate_receipts_dir(receipts_dir=receipts_dir)
    assert report["status"] == "FAIL"
    assert report["counts"]["fail"] == 1


def test_validate_receipts_dir_passes_on_repo_receipts() -> None:
    receipts_dir = Path("KT_ARCHIVE/vault/receipts")
    report = validate_receipts_dir(receipts_dir=receipts_dir)
    assert report["status"] == "PASS"
