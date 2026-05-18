from __future__ import annotations

import json
import shutil
from pathlib import Path

from tools.operator import run_bounded_forward_streams as streams
from tools.operator import validate_external_attestation


def _copy_required_inputs(tmp_path: Path) -> None:
    root = streams.repo_root()
    for raw in [
        "commercial/customer_safe_language_pack.md",
        "commercial/one_page_current_state.md",
        "commercial/launch_boundary_notice.md",
        "commercial/quickstart.md",
        "commercial/operator_runbook.md",
        "commercial/pilot_scope.md",
        "commercial/pilot_limitations.md",
        "governance/allowed_launch_claims.json",
        "governance/current_claim_ceiling.json",
        "repo_cleanup/archive_manifest.json",
        "repo_cleanup/current_authority_manifest.json",
        "repo_cleanup/historical_receipt_index.json",
        "repo_cleanup/generated_artifact_retirement_plan.json",
        ".agentignore",
    ]:
        source = root / raw
        target = tmp_path / raw
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_run_does_not_create_independent_attestation(tmp_path: Path) -> None:
    _copy_required_inputs(tmp_path)
    streams.run(output_root=tmp_path)
    assert not (tmp_path / validate_external_attestation.TARGET_ATTESTATION).exists()
    receipt = _load(tmp_path / streams.OUTPUTS["attestation_collection_receipt"])
    assert receipt["self_authored_attestation_allowed"] is False
    assert receipt["attestation_accepted"] is False


def test_missing_attestation_keeps_external_audit_and_commercial_claims_blocked(tmp_path: Path) -> None:
    _copy_required_inputs(tmp_path)
    streams.run(output_root=tmp_path)
    receipt = _load(tmp_path / streams.OUTPUTS["bounded_streams_receipt"])
    assert receipt["external_attestation_accepted"] is False
    assert receipt["external_audit_completed"] is False
    assert receipt["commercial_claims_authorized"] is False
    assert receipt["seven_b_amplification_proven"] is False


def test_claim_scan_allows_negative_forbidden_context() -> None:
    text = "KT is not externally audited. S-tier remains blocked."
    assert streams.scan_claim_text(text, source="unit") == []


def test_claim_scan_rejects_positive_forbidden_claim() -> None:
    text = "KT is externally audited."
    violations = streams.scan_claim_text(text, source="unit")
    assert violations
    assert violations[0]["line"] == 1


def test_claim_scan_rejects_positive_claim_after_prior_negative_line() -> None:
    text = "Claim expansion is blocked.\nKT is externally audited."
    violations = streams.scan_claim_text(text, source="unit")
    assert violations
    assert violations[0]["line"] == 2


def test_claim_scan_rejects_positive_claim_after_prior_negative_sentence() -> None:
    text = "Claim expansion is blocked. KT is externally audited."
    violations = streams.scan_claim_text(text, source="unit")
    assert violations
    assert violations[0]["line"] == 1


def test_claim_scan_allows_explicit_forbidden_section() -> None:
    text = "Forbidden language:\n\n```text\nexternally audited\nS-tier\n```"
    assert streams.scan_claim_text(text, source="unit") == []


def test_launch_wedge_claim_scan_passes_current_docs(tmp_path: Path) -> None:
    _copy_required_inputs(tmp_path)
    receipt = streams.scan_launch_claims(tmp_path)
    assert receipt["claim_boundary_passed"] is True
    assert receipt["violation_count"] == 0


def test_highway_shadow_warn_has_no_canonical_authority(tmp_path: Path) -> None:
    _copy_required_inputs(tmp_path)
    streams.run(output_root=tmp_path)
    receipt = _load(tmp_path / streams.OUTPUTS["highway_shadow_warn_receipt"])
    assert receipt["shadow_ready_candidate"] is True
    assert receipt["warn_only_candidate"] is True
    assert receipt["canonical_active"] is False
    assert receipt["claim_expansion_allowed"] is False


def test_fp0_scorecard_preserves_json_canonical_and_no_7b_claim(tmp_path: Path) -> None:
    _copy_required_inputs(tmp_path)
    streams.run(output_root=tmp_path)
    receipt = _load(tmp_path / streams.OUTPUTS["fp0_shadow_scorecard"])
    assert receipt["json_remains_canonical"] is True
    assert receipt["seven_b_amplification_proven"] is False
    assert receipt["claim_expansion_allowed"] is False


def test_repo_cleanup_plan_indexes_without_delete_authority(tmp_path: Path) -> None:
    _copy_required_inputs(tmp_path)
    streams.run(output_root=tmp_path)
    receipt = _load(tmp_path / streams.OUTPUTS["repo_cleanup_receipt"])
    assert receipt["delete_authorized"] is False
    assert receipt["archive_index_before_move_required"] is True
    assert receipt["current_authority_first"] is True


def test_all_outputs_are_emitted(tmp_path: Path) -> None:
    _copy_required_inputs(tmp_path)
    streams.run(output_root=tmp_path)
    for raw in streams.OUTPUTS.values():
        assert (tmp_path / raw).is_file(), raw
