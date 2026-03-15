from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.hermetic_build_envelope_validate import build_hermetic_build_outputs_from_artifacts


def test_hermetic_build_envelope_validate_passes_with_scoped_artifacts() -> None:
    outputs = build_hermetic_build_outputs_from_artifacts(
        status_report={"status": "PASS", "head": "sealed-head"},
        authority_report={"status": "PASS", "grade": "A", "blockers": [], "head": "sealed-head"},
        canonical_facts={
            "head": "sealed-head",
            "contract_status": "PASS",
            "canonical_run_ref": "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS15_canonical_hmac_seal_b4789a5",
            "delivery_manifest_ref": "canonical/delivery/delivery_manifest.json",
            "pack_manifest_ref": "canonical/delivery/pack/delivery_pack_manifest.json",
            "operator_fingerprint_ref": "canonical/reports/operator_fingerprint.json",
            "critical_artifact_count": 3,
            "critical_artifact_root_sha256": "a" * 64,
            "critical_artifacts": [
                {"kind": "delivery_manifest", "path": "canonical/delivery/delivery_manifest.json", "sha256": "1" * 64},
            ],
            "envelope_mode": "NEAR_HERMETIC_LOCAL_ENV_FINGERPRINTED",
            "claim_ceiling": "current platform and python fingerprint only",
            "mve_environment_fingerprint": "b" * 64,
        },
        hermetic_report={
            "status": "PASS",
            "replay_run_ref": "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS16_hermetic_replay_proof",
            "replay_receipt_ref": "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS16_hermetic_replay_proof/reports/replay_receipt.json",
        },
        changed_files=[
            "KT_PROD_CLEANROOM/tools/operator/hermetic_build_envelope_validate.py",
            "KT_PROD_CLEANROOM/tests/operator/test_hermetic_build_envelope_validate.py",
            "KT_PROD_CLEANROOM/reports/kt_hermetic_build_envelope_manifest.json",
            "KT_PROD_CLEANROOM/reports/kt_hermetic_build_envelope_receipt.json",
        ],
        prewrite_git_clean=True,
    )

    assert outputs["manifest"]["status"] == "PASS"
    assert outputs["manifest"]["pass_verdict"] == "NEAR_HERMETIC_BUILD_ENVELOPE_PROVEN"
    assert outputs["receipt"]["status"] == "PASS"
    assert outputs["receipt"]["pass_verdict"] == "NEAR_HERMETIC_BUILD_ENVELOPE_PROVEN"
    assert outputs["receipt"]["summary"]["critical_artifact_count"] == 3


def test_hermetic_build_envelope_validate_blocks_on_unexpected_touch() -> None:
    try:
        build_hermetic_build_outputs_from_artifacts(
            status_report={"status": "PASS", "head": "sealed-head"},
            authority_report={"status": "PASS", "grade": "A", "blockers": [], "head": "sealed-head"},
            canonical_facts={
                "head": "sealed-head",
                "contract_status": "PASS",
                "canonical_run_ref": "canonical",
                "delivery_manifest_ref": "canonical/delivery/delivery_manifest.json",
                "pack_manifest_ref": "canonical/delivery/pack/delivery_pack_manifest.json",
                "operator_fingerprint_ref": "canonical/reports/operator_fingerprint.json",
                "critical_artifact_count": 1,
                "critical_artifact_root_sha256": "a" * 64,
                "critical_artifacts": [{"kind": "delivery_manifest", "path": "canonical", "sha256": "1" * 64}],
                "envelope_mode": "NEAR_HERMETIC_LOCAL_ENV_FINGERPRINTED",
                "claim_ceiling": "bounded",
                "mve_environment_fingerprint": "b" * 64,
            },
            hermetic_report={"status": "PASS", "replay_run_ref": "replay", "replay_receipt_ref": "replay/report.json"},
            changed_files=["KT_PROD_CLEANROOM/tools/operator/kt_cli.py"],
            prewrite_git_clean=True,
        )
    except RuntimeError as exc:
        assert "unexpected subject touches" in str(exc)
    else:
        raise AssertionError("expected RuntimeError")
