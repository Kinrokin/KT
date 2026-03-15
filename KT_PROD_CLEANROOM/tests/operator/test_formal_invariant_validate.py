from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.formal_invariant_validate import (  # noqa: E402
    CREATED_FILES,
    STRONGER_CLAIM_NOT_MADE,
    build_formal_invariant_outputs_from_artifacts,
)


def _ws22_receipt() -> dict:
    return {
        "status": "PASS",
        "pass_verdict": "EXTERNAL_CHALLENGE_PROTOCOL_BOOTSTRAPPED",
        "subject_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
        "evidence_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
    }


def _organ_invariants() -> dict:
    return {
        "invariants": [
            {"invariant_id": "no_current_head_truth_overread"},
            {"invariant_id": "documentary_mirrors_are_non_authoritative"},
            {"invariant_id": "ledger_pointer_is_active_truth_source"},
        ]
    }


def _public_verifier_manifest() -> dict:
    return {
        "claim_boundary": "Consumers must not equate them unless evidence_equals_subject is true.",
    }


def _published_head_receipt() -> dict:
    return {
        "head_equals_subject": False,
        "current_head_authority_claimed": False,
        "current_head_claim_verdict": "HEAD_CONTAINS_TRANSPARENCY_VERIFIED_SUBJECT_EVIDENCE",
        "published_head_authority_claimed": True,
    }


def _documentary_policy() -> dict:
    return {
        "status": "ACTIVE",
        "active_current_head_truth_source": "kt_truth_ledger:ledger/current/current_pointer.json",
        "documentary_only_refs": [
            "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
            "KT_PROD_CLEANROOM/reports/current_state_receipt.json",
            "KT_PROD_CLEANROOM/reports/runtime_closure_audit.json",
        ],
    }


def _documentary_validation_receipt() -> dict:
    return {
        "status": "PASS",
        "checks": [
            {"check": "main_current_pointer_marked_documentary_only", "status": "PASS"},
            {"check": "main_current_state_marked_documentary_only", "status": "PASS"},
            {"check": "main_runtime_audit_marked_documentary_only", "status": "PASS"},
        ],
    }


def _authority_convergence_contract() -> dict:
    return {
        "status": "ACTIVE",
        "required_equalities": [
            "H1_ACTIVATION_ALLOWED == false until published self-convergence is proven",
        ],
    }


def _authority_convergence_receipt() -> dict:
    return {
        "proof_class": "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN",
        "observed": {"active_truth_source": "kt_truth_ledger:ledger/current/current_pointer.json"},
    }


def _authority_closure_receipt() -> dict:
    return {"status": "PASS", "pass_verdict": "AUTHORITY_AND_PUBLISHED_HEAD_CLOSED"}


def _h1_gate_receipt() -> dict:
    return {"h1_allowed": False}


def test_formal_invariant_receipt_passes_when_observed_state_is_modeled() -> None:
    outputs = build_formal_invariant_outputs_from_artifacts(
        current_repo_head="474a14f9d404e70524e60526d8fa427ae5948b94",
        ws22_receipt=_ws22_receipt(),
        organ_invariants=_organ_invariants(),
        public_verifier_manifest=_public_verifier_manifest(),
        published_head_receipt=_published_head_receipt(),
        documentary_policy=_documentary_policy(),
        documentary_validation_receipt=_documentary_validation_receipt(),
        authority_convergence_contract=_authority_convergence_contract(),
        authority_convergence_receipt=_authority_convergence_receipt(),
        authority_closure_receipt=_authority_closure_receipt(),
        h1_gate_receipt=_h1_gate_receipt(),
        changed_files=list(CREATED_FILES),
        prewrite_scope_clean=True,
    )
    receipt = outputs["receipt"]
    assert receipt["status"] == "PASS"
    assert receipt["pass_verdict"] == "CORE_RELEASE_INVARIANTS_MODELED_AND_BOUNDED_CHECKED"
    assert outputs["model_results"]["observed_current_state_match"]["status"] == "PASS"
    assert outputs["model_results"]["stronger_claim_not_made"] == STRONGER_CLAIM_NOT_MADE


def test_formal_invariant_receipt_blocks_if_registry_is_missing_required_invariant() -> None:
    organ_invariants = _organ_invariants()
    organ_invariants["invariants"] = organ_invariants["invariants"][:2]
    outputs = build_formal_invariant_outputs_from_artifacts(
        current_repo_head="474a14f9d404e70524e60526d8fa427ae5948b94",
        ws22_receipt=_ws22_receipt(),
        organ_invariants=organ_invariants,
        public_verifier_manifest=_public_verifier_manifest(),
        published_head_receipt=_published_head_receipt(),
        documentary_policy=_documentary_policy(),
        documentary_validation_receipt=_documentary_validation_receipt(),
        authority_convergence_contract=_authority_convergence_contract(),
        authority_convergence_receipt=_authority_convergence_receipt(),
        authority_closure_receipt=_authority_closure_receipt(),
        h1_gate_receipt=_h1_gate_receipt(),
        changed_files=list(CREATED_FILES),
        prewrite_scope_clean=True,
    )
    receipt = outputs["receipt"]
    assert receipt["status"] == "BLOCKED"
    assert receipt["checks"][3]["status"] == "FAIL"
