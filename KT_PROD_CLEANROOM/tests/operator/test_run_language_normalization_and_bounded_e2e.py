from __future__ import annotations

import json
import shutil
from pathlib import Path

from tools.operator import run_bounded_forward_streams
from tools.operator import run_language_normalization_and_bounded_e2e as language


def _copy_required_existing_inputs(tmp_path: Path) -> None:
    root = language.repo_root()
    for raw in [
        "commercial/quickstart.md",
        "commercial/operator_runbook.md",
        "commercial/deployment_profiles.yaml",
        "commercial/evidence_pack_manifest.json",
        "external/attestation_collection_packet.json",
        "repo_cleanup/archive_manifest.json",
    ]:
        source = root / raw
        target = tmp_path / raw
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def test_run_emits_required_language_outputs(tmp_path: Path) -> None:
    _copy_required_existing_inputs(tmp_path)
    summary = language.run(output_root=tmp_path)

    for raw in language.OUTPUTS.values():
        assert (tmp_path / raw).is_file(), raw
    assert summary["bounded_launch_readiness_delta_receipt"]["bounded_launch_wedge_ready_candidate"] is True
    assert summary["bounded_launch_readiness_delta_receipt"]["independent_attestation_pending"] is True
    assert summary["bounded_launch_readiness_delta_receipt"]["external_audit_accepted"] is False


def test_terminology_matrix_preserves_machine_vocabulary(tmp_path: Path) -> None:
    _copy_required_existing_inputs(tmp_path)
    language.run(output_root=tmp_path)

    matrix = _load(tmp_path / language.OUTPUTS["terminology_matrix"])
    assert matrix["internal_machine_vocabulary_preserved"] is True
    assert matrix["machine_outcome_ids_must_not_be_renamed_without_migration"] is True
    assert matrix["claim_expansion_allowed"] is False
    assert any(row["internal_term"] == "Truth Lock" and row["external_term"] == "Current State Lock" for row in matrix["terms"])
    assert any(row["internal_term"] == "S-tier" and "Blocked" in row["usage"] for row in matrix["terms"])


def test_normalized_language_claim_scan_passes(tmp_path: Path) -> None:
    _copy_required_existing_inputs(tmp_path)
    language.run(output_root=tmp_path)

    receipt = _load(tmp_path / language.OUTPUTS["language_normalization_receipt"])
    assert receipt["claim_boundary_passed"] is True
    assert receipt["claim_scan"]["violation_count"] == 0
    assert receipt["commercial_claims_authorized"] is False
    assert receipt["seven_b_amplification_proven"] is False


def test_positive_overclaim_in_normalized_language_fails_scan(tmp_path: Path) -> None:
    _copy_required_existing_inputs(tmp_path)
    language.run(output_root=tmp_path)

    target = tmp_path / language.OUTPUTS["reviewer_readme"]
    target.write_text(target.read_text(encoding="utf-8") + "\nKT is externally audited.\n", encoding="utf-8")
    scan = language._scan_outputs(tmp_path, ["reviewer_readme"])
    assert scan["claim_boundary_passed"] is False
    assert scan["violations"]


def test_blocked_claims_guide_can_list_forbidden_language_without_claiming_it(tmp_path: Path) -> None:
    _copy_required_existing_inputs(tmp_path)
    language.run(output_root=tmp_path)

    text = (tmp_path / language.OUTPUTS["blocked_claims_plain_language"]).read_text(encoding="utf-8")
    assert "Forbidden language:" in text
    assert run_bounded_forward_streams.scan_claim_text(text, source="blocked_claims") == []


def test_missing_existing_launch_artifact_blocks_ready_candidate(tmp_path: Path) -> None:
    summary = language.run(output_root=tmp_path)
    receipt = summary["bounded_launch_readiness_delta_receipt"]
    assert receipt["bounded_launch_wedge_ready_candidate"] is False
    assert "commercial/quickstart.md" in receipt["missing_paths"]
