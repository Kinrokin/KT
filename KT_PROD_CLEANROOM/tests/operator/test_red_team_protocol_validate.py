from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.red_team_protocol_validate import (  # noqa: E402
    CREATED_FILES,
    STRONGER_CLAIM_NOT_MADE,
    build_red_team_protocol_outputs_from_artifacts,
)


def _ws21_receipt() -> dict:
    return {
        "status": "PASS",
        "pass_verdict": "VERIFIER_ONLY_BOUNDED_PUBLIC_HORIZON_OPENED",
        "subject_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
        "evidence_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
        "summary": {"opened_horizon_id": "VERIFIER_ONLY_PUBLIC_VERIFICATION"},
    }


def _ws21_contract() -> dict:
    return {
        "selected_horizon": {
            "allowed_horizon_choice": "bounded public showability",
            "horizon_id": "VERIFIER_ONLY_PUBLIC_VERIFICATION",
            "status": "OPEN",
            "scope": "verifier only",
            "artifact_subject_root_sha256": "1" * 64,
            "exact_artifact_subjects_covered": [{"kind": "delivery_zip", "path": "a.zip", "sha256": "2" * 64}],
            "replay_contract": {"detached_entrypoint": "python -m tools.operator.public_verifier_detached_runtime"},
        },
        "horizon_matrix": [
            {"horizon_id": "VERIFIER_ONLY_PUBLIC_VERIFICATION", "status": "OPEN"},
            {"horizon_id": "BOUNDED_TOURNAMENT_LANE", "status": "BLOCKED"},
            {"horizon_id": "BOUNDED_H1_SINGLE_ADAPTER_LANE", "status": "BLOCKED"},
        ],
        "blocker_matrix": [
            {"surface_id": "BROADER_PUBLIC_SHOWABILITY", "status": "BLOCKED"},
            {"surface_id": "COMPETITION_HORIZON", "status": "BLOCKED"},
            {"surface_id": "PRODUCTION_HORIZON", "status": "BLOCKED"},
            {"surface_id": "ECONOMIC_HORIZON", "status": "BLOCKED"},
            {"surface_id": "H1_SINGLE_ADAPTER_HORIZON", "status": "BLOCKED"},
        ],
    }


def _ws21_replay_bundle() -> dict:
    return {
        "opened_horizon_id": "VERIFIER_ONLY_PUBLIC_VERIFICATION",
        "public_auditor_steps": ["a", "b", "c", "d"],
        "replay_surface": {
            "externally_inspectable_or_replayable": True,
            "detached_package_root_ref": "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS19_detached_public_verifier_proof/package",
            "detached_entrypoint": "python -m tools.operator.public_verifier_detached_runtime",
            "replay_recipe_ref": "KT_PROD_CLEANROOM/reports/kt_independent_replay_recipe.md",
        },
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


def test_red_team_protocol_receipt_passes_with_one_runnable_auditor_path() -> None:
    outputs = build_red_team_protocol_outputs_from_artifacts(
        current_repo_head="ccdf09f270033032836a1d94e00fda6dcd78f522",
        ws21_contract=_ws21_contract(),
        ws21_replay_bundle=_ws21_replay_bundle(),
        ws21_receipt=_ws21_receipt(),
        ws20_recipe_text=_recipe(),
        changed_files=list(CREATED_FILES),
        prewrite_scope_clean=True,
    )
    receipt = outputs["receipt"]
    assert receipt["status"] == "PASS"
    assert receipt["pass_verdict"] == "EXTERNAL_CHALLENGE_PROTOCOL_BOOTSTRAPPED"
    assert receipt["summary"]["auditor_path_count"] == 1
    assert outputs["protocol"]["stronger_claim_not_made"] == STRONGER_CLAIM_NOT_MADE


def test_red_team_protocol_blocks_if_broader_horizon_is_not_blocked() -> None:
    contract = _ws21_contract()
    contract["blocker_matrix"][1]["status"] = "OPEN"
    outputs = build_red_team_protocol_outputs_from_artifacts(
        current_repo_head="ccdf09f270033032836a1d94e00fda6dcd78f522",
        ws21_contract=contract,
        ws21_replay_bundle=_ws21_replay_bundle(),
        ws21_receipt=_ws21_receipt(),
        ws20_recipe_text=_recipe(),
        changed_files=list(CREATED_FILES),
        prewrite_scope_clean=True,
    )
    receipt = outputs["receipt"]
    assert receipt["status"] == "BLOCKED"
    assert receipt["checks"][4]["status"] == "FAIL"
