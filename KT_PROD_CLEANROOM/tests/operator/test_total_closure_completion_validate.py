from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.total_closure_completion_validate import (
    ADAPTER_GATE_REL,
    ARCHIVE_SEPARATION_REL,
    AUTHORITY_CLOSURE_REL,
    CANONICAL_TREE_REL,
    CLAIM_COMPILER_ACTIVATION_REL,
    COMPLETION_RECEIPT_REL,
    COMPETITION_PROFILE_REL,
    DETERMINISM_REL,
    FINAL_BUNDLE_REL,
    LEDGER_AUTHORITY_REL,
    PLATFORM_FINAL_REL,
    PUBLIC_SHOWABILITY_REL,
    PUBLICATION_ATTESTATION_REL,
    PUBLICATION_PROFILE_REL,
    PUBLIC_VERIFIER_REL,
    RELEASE_LAW_REL,
    RUNTIME_BOUNDARY_REL,
    TOURNAMENT_GATE_REL,
    TUF_ROOT_REL,
    VERIFIER_RELEASE_REL,
    WS11_RECUT_REL,
    emit_total_closure_completion,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _init_repo(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test User")
    _write_text(tmp_path / "README.md", "base\n")


def _seed_inputs(tmp_path: Path) -> None:
    _write_json(tmp_path / AUTHORITY_CLOSURE_REL, {"status": "PASS", "authority_convergence_proof_class": "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN", "truth_subject_commit": "d" * 40, "truth_evidence_commit": "e" * 40})
    _write_json(tmp_path / PLATFORM_FINAL_REL, {"status": "PASS", "enterprise_legitimacy_ceiling": "WORKFLOW_GOVERNANCE_ONLY", "platform_governance_verdict": "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED", "platform_governance_subject_commit": "g" * 40, "platform_governance_claim_admissible": False})
    _write_json(tmp_path / PUBLIC_VERIFIER_REL, {"status": "PASS", "truth_pointer_ref": "kt_truth_ledger:ledger/current/current_pointer.json", "head_claim_verdict": "HEAD_CONTAINS_TRANSPARENCY_VERIFIED_SUBJECT_EVIDENCE"})
    _write_json(tmp_path / RUNTIME_BOUNDARY_REL, {"status": "PASS", "runtime_boundary_verdict": "CANONICAL_RUNTIME_BOUNDARY_SETTLED"})
    _write_json(tmp_path / ARCHIVE_SEPARATION_REL, {"status": "PASS", "pass_verdict": "ACTIVE_ARCHIVE_SEPARATION_PROVEN"})
    _write_json(tmp_path / CANONICAL_TREE_REL, {"status": "PASS", "pass_verdict": "ACTIVE_CANONICAL_TREE_SETTLED"})
    _write_json(tmp_path / DETERMINISM_REL, {"status": "PASS", "pass_verdict": "CROSS_ENV_REPRODUCIBILITY_PROVEN"})
    _write_json(tmp_path / LEDGER_AUTHORITY_REL, {"status": "PASS", "pass_verdict": "LEDGER_AUTHORITY_FINALIZED"})
    _write_json(tmp_path / PUBLICATION_ATTESTATION_REL, {"status": "PASS", "pass_verdict": "PUBLICATION_GRADE_ATTESTATION_PROVEN"})
    _write_json(tmp_path / CLAIM_COMPILER_ACTIVATION_REL, {"status": "PASS"})
    _write_json(tmp_path / VERIFIER_RELEASE_REL, {"manifest_id": "KT_PUBLIC_VERIFIER_RELEASE_MANIFEST_V1"})
    _write_json(tmp_path / ADAPTER_GATE_REL, {"status": "PASS", "adapter_testing_gate_status": "OPEN"})
    _write_json(tmp_path / TOURNAMENT_GATE_REL, {"status": "BLOCKED", "tournament_gate_status": "BLOCKED"})
    _write_json(tmp_path / WS11_RECUT_REL, {"status": "PASS", "pass_verdict": "FINAL_RECUT_AND_ADJUDICATION_COMPLETE"})
    _write_json(tmp_path / TUF_ROOT_REL, {"status": "PASS", "trust_root_id": "KT_TUF_ROOT_BOOTSTRAP_TEST", "root_policy_ref": "KT_PROD_CLEANROOM/governance/closure_foundation/kt_tuf_root_policy.json"})
    _write_json(tmp_path / RELEASE_LAW_REL, {"law_id": "KT_FOUNDATION_RELEASE_LAW_V1_TEST", "forbidden_release_claims": ["HEAD is the transparency-verified truth subject when evidence and subject SHAs differ"]})
    _write_json(tmp_path / PUBLICATION_PROFILE_REL, {"current_status": "BLOCKED"})
    _write_json(tmp_path / COMPETITION_PROFILE_REL, {"current_status": "BLOCKED"})
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", "seed ws12 inputs")


def test_emit_total_closure_completion_seals_campaign_with_blocked_public_showability(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    _seed_inputs(tmp_path)

    receipt = emit_total_closure_completion(root=tmp_path)

    assert receipt["status"] == "PASS"
    assert receipt["pass_verdict"] == "TOTAL_CLOSURE_CAMPAIGN_SEALED"
    assert receipt["unexpected_touches"] == []
    assert receipt["protected_touch_violations"] == []

    final_bundle = json.loads((tmp_path / FINAL_BUNDLE_REL).read_text(encoding="utf-8"))
    assert final_bundle["active_truth_source_ref"] == "kt_truth_ledger:ledger/current/current_pointer.json"
    assert final_bundle["trust_root_id"] == "KT_TUF_ROOT_BOOTSTRAP_TEST"
    assert final_bundle["gates"] == {
        "adapter_testing": "OPEN",
        "tournament": "BLOCKED",
        "public_showability": "BLOCKED",
        "h1": "BLOCKED",
    }

    public_showability = json.loads((tmp_path / PUBLIC_SHOWABILITY_REL).read_text(encoding="utf-8"))
    assert public_showability["status"] == "BLOCKED"
    assert "TOURNAMENT_GATE_BLOCKED" in public_showability["blocking_conditions"]
    assert "PUBLICATION_PROFILE_BLOCKED" in public_showability["blocking_conditions"]


def test_emit_total_closure_completion_fails_closed_when_required_receipt_missing(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    _seed_inputs(tmp_path)
    (tmp_path / TUF_ROOT_REL).unlink()

    with pytest.raises(RuntimeError, match="missing required artifact"):
        emit_total_closure_completion(root=tmp_path)

    assert not (tmp_path / COMPLETION_RECEIPT_REL).exists()
