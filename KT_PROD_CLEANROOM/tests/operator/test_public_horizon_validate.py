from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.public_horizon_validate import (  # noqa: E402
    CREATED_FILES,
    STRONGER_CLAIM_NOT_MADE,
    build_public_horizon_outputs_from_artifacts,
)


def _ws18_receipt() -> dict:
    return {
        "status": "PASS",
        "pass_verdict": "BUILD_PROVENANCE_AND_VSA_ALIGNED",
        "subject_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
        "evidence_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
        "questions": {
            "exact_artifact_subjects_covered": [
                {"kind": "delivery_zip", "path": "a.zip", "sha256": "1" * 64},
                {"kind": "replay_receipt", "path": "b.json", "sha256": "2" * 64},
            ],
            "provenance_vsa_publication_subject_alignment": {
                "publication_surface_boundary": "bounded publication surface only",
            },
        },
        "summary": {
            "artifact_subject_root_sha256": "3" * 64,
        },
    }


def _ws19_manifest() -> dict:
    return {
        "detached_package_root_ref": "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS19_detached_public_verifier_proof/package",
        "detached_entrypoint": "python -m tools.operator.public_verifier_detached_runtime",
        "package_root_sha256": "4" * 64,
        "repo_local_parity_fields": ["status", "subject_verdict"],
    }


def _ws19_receipt() -> dict:
    return {
        "status": "PASS",
        "pass_verdict": "DETACHED_PUBLIC_VERIFIER_PACKAGE_PROVEN",
        "subject_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
        "evidence_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
    }


def _ws20_matrix() -> dict:
    return {
        "status": "PASS",
        "verification_scope": "TWO_CLEAN_ENVIRONMENTS_VERIFY_THE_SEALED_DETACHED_VERIFIER_PACKAGE",
        "environments": [
            {
                "environment_id": "clean_env_repo_copy",
                "status": "PASS",
                "package_root": "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS20_external_reproduction_proof/env_a/package",
                "package_root_inside_repo_root": True,
                "detached_runtime_receipt_ref": "env_a_receipt.json",
                "detached_public_verifier_report_ref": "env_a_report.json",
                "environment_metadata_ref": "env_a_metadata.json",
            },
            {
                "environment_id": "clean_env_temp_copy",
                "status": "PASS",
                "package_root": "C:/Temp/KT_WS20/package",
                "package_root_inside_repo_root": False,
                "detached_runtime_receipt_ref": "env_b_receipt.json",
                "detached_public_verifier_report_ref": "env_b_report.json",
                "environment_metadata_ref": "env_b_metadata.json",
            },
        ],
    }


def _ws20_receipt() -> dict:
    return {
        "status": "PASS",
        "pass_verdict": "INDEPENDENT_EXTERNAL_REPRODUCTION_MATRIX_PROVEN",
        "subject_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
        "evidence_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
    }


def _public_showability_receipt() -> dict:
    return {"status": "BLOCKED", "pass_verdict": "PUBLIC_SHOWABILITY_BLOCKED"}


def _tournament_receipt() -> dict:
    return {"status": "BLOCKED", "pass_verdict": "TOURNAMENT_GATE_BLOCKED"}


def _h1_receipt() -> dict:
    return {"status": "BLOCKED", "h1_gate_verdict": "H1_BLOCKED", "single_adapter_benchmarking_allowed": False}


def _publication_profile() -> dict:
    return {"current_status": "BLOCKED"}


def _competition_profile() -> dict:
    return {"current_status": "BLOCKED"}


def _final_completion_bundle() -> dict:
    return {
        "lawful_now": [
            "offline public verification using the released verifier bundle",
            "documentary commercial/doctrine use bounded by the active claim compiler",
        ]
    }


def _public_verifier_manifest() -> dict:
    return {
        "status": "PASS",
        "platform_governance_claim_admissible": False,
        "platform_governance_verdict": "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED",
    }


def _release_law() -> dict:
    return {
        "release_profiles": [
            {"profile_id": "commercial_documentary_only", "current_admissibility_ceiling": "documentary_only"},
            {"profile_id": "competition_and_publication_grade", "current_admissibility_ceiling": "competition_and_publication_on_bounded_surface_only"},
            {"profile_id": "h1_activation", "current_admissibility_ceiling": "blocked"},
        ]
    }


def _recipe() -> str:
    return "\n".join(
        [
            "PowerShell recipe",
            "KT_HMAC_KEY_SIGNER_A",
            "KT_HMAC_KEY_SIGNER_B",
            "python -m tools.operator.public_verifier_detached_runtime",
            "Success criteria",
        ]
    )


def test_public_horizon_receipt_passes_with_one_verifier_only_open_horizon() -> None:
    outputs = build_public_horizon_outputs_from_artifacts(
        current_repo_head="811c1d45554ab508c2604edd4ddb23617af789c1",
        ws18_receipt=_ws18_receipt(),
        ws19_manifest=_ws19_manifest(),
        ws19_receipt=_ws19_receipt(),
        ws20_matrix=_ws20_matrix(),
        ws20_recipe_text=_recipe(),
        ws20_receipt=_ws20_receipt(),
        public_showability_receipt=_public_showability_receipt(),
        tournament_receipt=_tournament_receipt(),
        h1_receipt=_h1_receipt(),
        publication_profile=_publication_profile(),
        competition_profile=_competition_profile(),
        final_completion_bundle=_final_completion_bundle(),
        public_verifier_manifest=_public_verifier_manifest(),
        release_law=_release_law(),
        changed_files=list(CREATED_FILES),
        prewrite_scope_clean=True,
    )
    receipt = outputs["receipt"]
    assert receipt["status"] == "PASS"
    assert receipt["pass_verdict"] == "VERIFIER_ONLY_BOUNDED_PUBLIC_HORIZON_OPENED"
    assert sum(1 for row in outputs["contract"]["horizon_matrix"] if row["status"] == "OPEN") == 1
    assert outputs["contract"]["stronger_claim_not_made"] == STRONGER_CLAIM_NOT_MADE


def test_public_horizon_receipt_blocks_if_broader_public_showability_is_not_still_blocked() -> None:
    public_showability_receipt = _public_showability_receipt()
    public_showability_receipt["status"] = "PASS"
    outputs = build_public_horizon_outputs_from_artifacts(
        current_repo_head="811c1d45554ab508c2604edd4ddb23617af789c1",
        ws18_receipt=_ws18_receipt(),
        ws19_manifest=_ws19_manifest(),
        ws19_receipt=_ws19_receipt(),
        ws20_matrix=_ws20_matrix(),
        ws20_recipe_text=_recipe(),
        ws20_receipt=_ws20_receipt(),
        public_showability_receipt=public_showability_receipt,
        tournament_receipt=_tournament_receipt(),
        h1_receipt=_h1_receipt(),
        publication_profile=_publication_profile(),
        competition_profile=_competition_profile(),
        final_completion_bundle=_final_completion_bundle(),
        public_verifier_manifest=_public_verifier_manifest(),
        release_law=_release_law(),
        changed_files=list(CREATED_FILES),
        prewrite_scope_clean=True,
    )
    receipt = outputs["receipt"]
    assert receipt["status"] == "BLOCKED"
    assert receipt["checks"][9]["status"] == "FAIL"
