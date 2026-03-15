from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.external_reproduction_validate import (  # noqa: E402
    CREATED_FILES,
    STRONGER_CLAIM_NOT_MADE,
    build_external_reproduction_outputs_from_artifacts,
)


def _env(environment_id: str, package_root: str, *, inside_repo_root: bool, status: str = "PASS") -> dict:
    return {
        "environment_id": environment_id,
        "status": status,
        "package_root": package_root,
        "package_root_inside_repo_root": inside_repo_root,
        "environment_metadata": {
            "python_executable": "python",
            "mve_environment_fingerprint": "a" * 64,
            "runtime_fingerprint": "b" * 64,
        },
    }


def _matrix() -> dict:
    return {
        "source_package_root_ref": "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS19_detached_public_verifier_proof/package",
        "verification_scope": "TWO_CLEAN_ENVIRONMENTS_VERIFY_THE_SEALED_DETACHED_VERIFIER_PACKAGE",
        "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
        "environments": [
            _env("clean_env_repo_copy", "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS20_external_reproduction_proof/env_a/package", inside_repo_root=True),
            _env("clean_env_temp_copy", "C:/Temp/KT_WS20_external_env_b/package", inside_repo_root=False),
        ],
    }


def _recipe() -> str:
    return "\n".join(
        [
            "KT_HMAC_KEY_SIGNER_A",
            "KT_HMAC_KEY_SIGNER_B",
            "PowerShell recipe",
            "python -m tools.operator.public_verifier_detached_runtime",
            "Success criteria",
            STRONGER_CLAIM_NOT_MADE,
        ]
    )


def test_external_reproduction_receipt_passes_with_two_clean_envs() -> None:
    outputs = build_external_reproduction_outputs_from_artifacts(
        current_repo_head="f1b57402a3f2d199d50a1e3b71314ec6e7dd84ba",
        ws19_receipt={
            "status": "PASS",
            "pass_verdict": "DETACHED_PUBLIC_VERIFIER_PACKAGE_PROVEN",
            "subject_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
            "evidence_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
        },
        matrix=_matrix(),
        recipe_text=_recipe(),
        changed_files=list(CREATED_FILES),
        prewrite_scope_clean=True,
    )
    receipt = outputs["receipt"]
    assert receipt["status"] == "PASS"
    assert receipt["pass_verdict"] == "INDEPENDENT_EXTERNAL_REPRODUCTION_MATRIX_PROVEN"
    assert receipt["summary"]["successful_environment_count"] == 2


def test_external_reproduction_receipt_blocks_without_outside_repo_env() -> None:
    matrix = _matrix()
    matrix["environments"][1]["package_root_inside_repo_root"] = True
    outputs = build_external_reproduction_outputs_from_artifacts(
        current_repo_head="f1b57402a3f2d199d50a1e3b71314ec6e7dd84ba",
        ws19_receipt={
            "status": "PASS",
            "pass_verdict": "DETACHED_PUBLIC_VERIFIER_PACKAGE_PROVEN",
            "subject_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
            "evidence_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
        },
        matrix=matrix,
        recipe_text=_recipe(),
        changed_files=list(CREATED_FILES),
        prewrite_scope_clean=True,
    )
    receipt = outputs["receipt"]
    assert receipt["status"] == "BLOCKED"
    assert receipt["checks"][4]["status"] == "FAIL"
