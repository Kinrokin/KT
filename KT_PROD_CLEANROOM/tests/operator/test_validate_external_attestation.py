from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import validate_external_attestation as validator


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _accepted_attestation() -> dict:
    return {
        "schema_id": "kt.external_reaudit.independent_attestation.v1",
        "verdict": "ACCEPTED",
        "prepared_by_kt": False,
        "authoring_entity_is_kt": False,
        "paid_reviewer": True,
        "paid_reviewer_disclosure": "Reviewer was paid for time; verdict remains independent.",
        "reviewer": {
            "name": "Independent Reviewer",
            "organization": "Outside Review LLC",
            "relationship_to_kt": "paid_independent_reviewer",
        },
        "scope": {
            "external_audit_packet_reviewed": True,
            "public_verifier_reviewed": True,
            "supply_chain_reviewed": True,
            "claim_boundary_reviewed": True,
            "commands_executed": True,
            "evidence_bundle_reviewed": True,
        },
        "evidence_review": {
            "evidence_bundle_hash": "a" * 64,
            "commands_run": ["python -m verifier.kt-verify --help"],
        },
        "commercial_claims_authorized": False,
        "commercial_activation_claim_authorized": False,
        "seven_b_amplification_proven": False,
        "beyond_sota_claimed": False,
        "s_tier_claimed": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
    }


def test_missing_attestation_fails_closed_with_named_blocker(tmp_path: Path) -> None:
    receipt = validator.evaluate_attestation(root=tmp_path)
    assert receipt["attestation_present"] is False
    assert receipt["decision"] == "BLOCKED_MISSING_OR_INCOMPLETE_INDEPENDENT_ATTESTATION"
    assert receipt["next_lawful_move"] == validator.BLOCKED_NEXT
    assert receipt["blockers"][0]["blocker_id"] == "independent_external_reaudit_attestation_missing"
    assert receipt["commercial_claims_authorized"] is False


def test_validate_for_acceptance_rejects_missing_attestation(tmp_path: Path) -> None:
    with pytest.raises(validator.AttestationFailure) as excinfo:
        validator.validate_for_acceptance(root=tmp_path)
    assert excinfo.value.code == "RC_EXTERNAL_ATTESTATION_NOT_ACCEPTED"


def test_accepted_independent_attestation_selects_reaudit_attempt_next(tmp_path: Path) -> None:
    _write(tmp_path / validator.TARGET_ATTESTATION, _accepted_attestation())
    receipt = validator.validate_for_acceptance(root=tmp_path)
    assert receipt["attestation_accepted"] is True
    assert receipt["next_lawful_move"] == validator.ACCEPTED_NEXT
    assert receipt["commercial_claims_authorized"] is False
    assert receipt["claim_boundary_passed"] is True


def test_kt_authored_attestation_is_rejected(tmp_path: Path) -> None:
    payload = _accepted_attestation()
    payload["prepared_by_kt"] = True
    _write(tmp_path / validator.TARGET_ATTESTATION, payload)
    receipt = validator.evaluate_attestation(root=tmp_path)
    assert receipt["attestation_accepted"] is False
    assert any(blocker["blocker_id"] == "prepared_by_kt_must_be_literal_false" for blocker in receipt["blockers"])


def test_missing_independence_flags_are_rejected(tmp_path: Path) -> None:
    payload = _accepted_attestation()
    payload.pop("prepared_by_kt")
    payload.pop("authoring_entity_is_kt")
    _write(tmp_path / validator.TARGET_ATTESTATION, payload)
    receipt = validator.evaluate_attestation(root=tmp_path)
    assert receipt["attestation_accepted"] is False
    blocker_ids = {blocker["blocker_id"] for blocker in receipt["blockers"]}
    assert "prepared_by_kt_must_be_literal_false" in blocker_ids
    assert "authoring_entity_is_kt_must_be_literal_false" in blocker_ids


def test_paid_reviewer_requires_disclosure(tmp_path: Path) -> None:
    payload = _accepted_attestation()
    payload.pop("paid_reviewer_disclosure")
    _write(tmp_path / validator.TARGET_ATTESTATION, payload)
    receipt = validator.evaluate_attestation(root=tmp_path)
    assert receipt["attestation_accepted"] is False
    assert any(blocker["blocker_id"] == "paid_reviewer_disclosure_missing" for blocker in receipt["blockers"])


def test_accepted_attestation_requires_full_scope(tmp_path: Path) -> None:
    payload = _accepted_attestation()
    payload["scope"]["supply_chain_reviewed"] = False
    _write(tmp_path / validator.TARGET_ATTESTATION, payload)
    receipt = validator.evaluate_attestation(root=tmp_path)
    assert receipt["attestation_accepted"] is False
    assert any(blocker["blocker_id"] == "accepted_attestation_scope_incomplete" for blocker in receipt["blockers"])


def test_claim_authorization_inside_attestation_fails_boundary(tmp_path: Path) -> None:
    payload = _accepted_attestation()
    payload["commercial_claims_authorized"] = True
    _write(tmp_path / validator.TARGET_ATTESTATION, payload)
    receipt = validator.evaluate_attestation(root=tmp_path)
    assert receipt["claim_boundary_passed"] is False
    assert any(blocker["blocker_id"] == "attestation_claim_boundary_breach" for blocker in receipt["blockers"])


def test_deferred_attestation_is_supported_but_does_not_unblock(tmp_path: Path) -> None:
    payload = _accepted_attestation()
    payload["verdict"] = "DEFERRED"
    _write(tmp_path / validator.TARGET_ATTESTATION, payload)
    receipt = validator.evaluate_attestation(root=tmp_path)
    assert receipt["attestation_deferred"] is True
    assert receipt["attestation_accepted"] is False
    assert receipt["next_lawful_move"] == validator.BLOCKED_NEXT


def test_rejected_attestation_routes_to_forensic_review(tmp_path: Path) -> None:
    payload = _accepted_attestation()
    payload["verdict"] = "REJECTED"
    _write(tmp_path / validator.TARGET_ATTESTATION, payload)
    receipt = validator.evaluate_attestation(root=tmp_path)
    assert receipt["attestation_rejected"] is True
    assert receipt["next_lawful_move"] == validator.REJECTED_NEXT


def test_missing_claim_boundary_flag_fails_closed(tmp_path: Path) -> None:
    payload = _accepted_attestation()
    payload.pop("commercial_claims_authorized")
    _write(tmp_path / validator.TARGET_ATTESTATION, payload)
    receipt = validator.evaluate_attestation(root=tmp_path)
    assert receipt["claim_boundary_passed"] is False
    assert any(blocker["blocker_id"] == "attestation_claim_boundary_breach" for blocker in receipt["blockers"])


def test_malformed_json_write_receipt_uses_structured_failure(tmp_path: Path) -> None:
    path = tmp_path / validator.TARGET_ATTESTATION
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(validator.AttestationFailure) as excinfo:
        validator.evaluate_attestation(root=tmp_path)
    receipt = validator._failure_receipt(tmp_path, path, excinfo.value)
    validator.write_outputs(tmp_path, receipt)
    dashboard = json.loads((tmp_path / validator.OUTPUT_BLOCKER_DASHBOARD).read_text(encoding="utf-8"))
    assert dashboard["blockers"][0]["blocker_id"] == "attestation_parse_or_validation_error"


def test_write_outputs_emits_receipt_and_dashboard(tmp_path: Path) -> None:
    receipt = validator.evaluate_attestation(root=tmp_path)
    validator.write_outputs(tmp_path, receipt)
    assert (tmp_path / validator.OUTPUT_RECEIPT).is_file()
    assert (tmp_path / validator.OUTPUT_BLOCKER_DASHBOARD).is_file()
