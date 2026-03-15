from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.delivery_integrity_validate import build_delivery_integrity_outputs_from_artifacts


def test_delivery_integrity_validate_passes_when_authority_delivery_blocker_is_cleared() -> None:
    outputs = build_delivery_integrity_outputs_from_artifacts(
        baseline_report={
            "grade": "B",
            "status": "HOLD",
            "blockers": [
                "DELIVERY_INTEGRITY_FAIL:S0_canonical_hmac:delivery pack dir missing",
            ],
        },
        current_report={
            "grade": "A",
            "status": "PASS",
            "integrity_failures": 0,
            "blockers": [],
        },
        canonical_facts={
            "contract_status": "PASS",
            "canonical_run_ref": "canonical_run",
            "delivery_manifest_ref": "canonical_run/delivery/delivery_manifest.json",
            "pack_manifest_ref": "canonical_run/delivery/KT_DELIVERY_X/delivery_pack_manifest.json",
            "zip_path": "canonical_run/delivery/KT_DELIVERY_X.zip",
            "delivery_pack_id": "a" * 64,
            "bundle_root_hash": "b" * 64,
            "delivery_pack_file_count": 7,
            "sha256_receipts": ["KT_DELIVERY_X.zip.sha256"],
            "run_id": "X",
            "lane": "canonical_hmac",
            "head": "subject-head",
        },
        subject_head="subject-head",
        changed_files=[
            "KT_PROD_CLEANROOM/tools/operator/authority_grade.py",
            "KT_PROD_CLEANROOM/tools/operator/delivery_integrity_validate.py",
            "KT_PROD_CLEANROOM/tests/operator/test_authority_grade.py",
            "KT_PROD_CLEANROOM/tests/operator/test_delivery_integrity_validate.py",
        ],
        prewrite_git_clean=True,
        baseline_authority_ref="baseline.json",
        current_authority_ref="current.json",
    )

    assert outputs["canonical_manifest"]["status"] == "PASS"
    assert outputs["authority_post_repair"]["status"] == "PASS"
    assert outputs["authority_post_repair"]["summary"]["delivery_integrity_blocker_cleared"] is True
    assert outputs["receipt"]["status"] == "PASS"
    assert outputs["receipt"]["pass_verdict"] == "DELIVERY_INTEGRITY_RESTORED"
