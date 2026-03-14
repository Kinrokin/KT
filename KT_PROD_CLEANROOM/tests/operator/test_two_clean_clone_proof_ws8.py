from __future__ import annotations

from tools.operator.two_clean_clone_proof import (
    build_proofrunbundle_index_payload,
    build_representative_authority_lane_receipt,
    build_twocleanclone_bundle_payload,
    build_twocleanclone_diff_summary,
)


def _proof(proof_id: str, status: str = "PASS") -> dict:
    return {
        "proof_id": proof_id,
        "program_id": {
            "certify": "program.certify.canonical_hmac",
            "hat_demo": "program.hat_demo",
            "red_assault_serious_v1": "program.red_assault.serious_v1",
        }[proof_id],
        "validated_head_sha": "h" * 40,
        "run_dir": f"KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/{proof_id}",
        "clone_provenance": {
            "clone_a": {"clean": True, "head": "h" * 40, "path": "C:/tmp/clone_a"},
            "clone_b": {"clean": True, "head": "h" * 40, "path": "C:/tmp/clone_b"},
        },
        "report": {
            "schema_id": "kt.operator.twocleanclone_proof.v1",
            "status": status,
            "compare_keys": [
                "delivery_root_hash",
                "bindingloop_check_hash",
                "evidence_core_merkle_root_sha256",
                "replay_receipt_hash",
                "governance_manifest_sha256",
                "constitution_epoch",
                "mve_environment_fingerprint",
            ],
            "run_a": "C:/tmp/clone_a/run",
            "run_b": "C:/tmp/clone_b/run",
            "violations": [] if status == "PASS" else ["delivery_root_hash"],
        },
    }


def test_ws8_bundle_marks_representative_lane_and_same_mve_ceiling() -> None:
    proofs = [_proof("certify"), _proof("hat_demo"), _proof("red_assault_serious_v1")]
    bundle = build_twocleanclone_bundle_payload(head_sha="h" * 40, generated_utc="2026-03-14T00:00:00Z", proofs=proofs)

    assert bundle["status"] == "PASS"
    assert bundle["minimum_scope_only"] is False
    assert bundle["representative_authority_lane_program_id"] == "program.red_assault.serious_v1"
    assert bundle["representative_authority_lane_proven"] is True
    assert bundle["cross_environment_controlled_variation_complete"] is False
    assert bundle["proof_scope"] == "clean_clone_reproducibility_representative_authority_lane_same_mve_only"
    assert bundle["published_head_authority_claimed"] is False


def test_ws8_receipt_stays_below_cross_environment_claims() -> None:
    bundle = build_twocleanclone_bundle_payload(
        head_sha="h" * 40,
        generated_utc="2026-03-14T00:00:00Z",
        proofs=[_proof("certify"), _proof("hat_demo"), _proof("red_assault_serious_v1")],
    )
    receipt = build_representative_authority_lane_receipt(
        head_sha="h" * 40,
        generated_utc="2026-03-14T00:00:00Z",
        bundle=bundle,
    )

    assert receipt["status"] == "PASS"
    assert receipt["representative_authority_lane_proven"] is True
    assert receipt["cross_environment_controlled_variation_complete"] is False
    assert receipt["cross_environment_controlled_variation_status"] == "NOT_RUN"
    assert receipt["published_head_authority_claimed"] is False
    assert receipt["h1_allowed"] is False


def test_ws8_index_and_summary_include_red_assault_lane() -> None:
    proofs = [_proof("certify"), _proof("hat_demo"), _proof("red_assault_serious_v1")]
    index_payload = build_proofrunbundle_index_payload(
        head_sha="h" * 40,
        generated_utc="2026-03-14T00:00:00Z",
        proofs=proofs,
    )
    summary = build_twocleanclone_diff_summary(head_sha="h" * 40, proofs=proofs)

    assert index_payload["status"] == "PASS"
    assert any(row["proof_id"] == "red_assault_serious_v1" for row in index_payload["bundles"])
    assert "WS8 red-assault serious_v1 proof: PASS" in summary
    assert "Representative authority lane: program.red_assault.serious_v1" in summary
    assert "Cross-environment controlled variation: NOT_RUN" in summary
