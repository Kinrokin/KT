from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.final_recut_and_adjudication import (
    ADAPTER_GATE_REL,
    ARCHIVE_SEPARATION_REL,
    AUTHORITY_CLOSURE_REL,
    CANONICAL_TREE_REL,
    CLAIM_COMPILER_ACTIVATION_REL,
    COGNITIVE_ARCH_REL,
    DETERMINISM_REL,
    DOCTRINE_MANIFEST_REL,
    H1_GATE_REL,
    LEDGER_AUTHORITY_REL,
    MATH_GURU_PROFILE_REL,
    PARADOX_DOC_REL,
    PARADOX_REL,
    PLATFORM_FINAL_REL,
    PUBLICATION_PROFILE_REL,
    PUBLIC_VERIFIER_REL,
    READINESS_LATTICE_REL,
    READINESS_MATRIX_REL,
    RUNTIME_BOUNDARY_REL,
    RUNTIME_MEMORY_REL,
    TOURNAMENT_GATE_REL,
    TRUTH_PUBLICATION_REL,
    VERIFIER_RELEASE_REL,
    WS11_RECEIPT_REL,
    emit_final_recut_and_adjudication,
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


def _seed_common_inputs(tmp_path: Path, *, canonical_tree_status: str = "PASS") -> None:
    subject = "d" * 40
    evidence = "e" * 40
    _write_json(tmp_path / AUTHORITY_CLOSURE_REL, {"status": "PASS", "authority_convergence_proof_class": "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN", "truth_subject_commit": subject, "truth_evidence_commit": evidence})
    _write_json(tmp_path / PLATFORM_FINAL_REL, {"status": "PASS", "enterprise_legitimacy_ceiling": "WORKFLOW_GOVERNANCE_ONLY", "platform_governance_verdict": "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED", "platform_governance_subject_commit": "g" * 40})
    _write_json(tmp_path / PUBLIC_VERIFIER_REL, {"status": "PASS", "truth_subject_commit": subject, "evidence_commit": evidence})
    _write_json(tmp_path / RUNTIME_BOUNDARY_REL, {"status": "PASS", "runtime_boundary_verdict": "CANONICAL_RUNTIME_BOUNDARY_SETTLED", "runtime_boundary_subject_commit": "r" * 40})
    _write_json(tmp_path / H1_GATE_REL, {"status": "BLOCKED"})
    _write_json(tmp_path / TRUTH_PUBLICATION_REL, {"status": "PASS", "truth_publication_stabilized": True})
    _write_json(tmp_path / DETERMINISM_REL, {"status": "PASS", "pass_verdict": "CROSS_ENV_REPRODUCIBILITY_PROVEN"})
    _write_json(tmp_path / ARCHIVE_SEPARATION_REL, {"status": "PASS"})
    _write_json(tmp_path / CANONICAL_TREE_REL, {"status": canonical_tree_status})
    _write_json(tmp_path / LEDGER_AUTHORITY_REL, {"status": "PASS"})
    _write_json(tmp_path / CLAIM_COMPILER_ACTIVATION_REL, {"status": "PASS"})
    _write_json(tmp_path / VERIFIER_RELEASE_REL, {"manifest_id": "KT_PUBLIC_VERIFIER_RELEASE_MANIFEST_V1"})
    _write_json(tmp_path / PARADOX_REL, {"status": "PASS"})
    _write_json(tmp_path / RUNTIME_MEMORY_REL, {"status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_quality_policy.json", {"status": "ACTIVE"})
    _write_json(tmp_path / READINESS_LATTICE_REL, {"status": "ACTIVE"})
    _write_text(tmp_path / COGNITIVE_ARCH_REL, "# Cognitive\n")
    _write_text(tmp_path / PARADOX_DOC_REL, "# Paradox\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", "seed ws11 inputs")


def test_emit_final_recut_and_adjudication_refreshes_stale_surfaces_and_opens_adapter_gate(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    _seed_common_inputs(tmp_path)

    receipt = emit_final_recut_and_adjudication(root=tmp_path)

    assert receipt["status"] == "PASS"
    assert receipt["adapter_testing_gate_status"] == "OPEN"
    assert receipt["tournament_gate_status"] == "BLOCKED"
    assert receipt["unexpected_touches"] == []
    assert receipt["protected_touch_violations"] == []

    doctrine_manifest = json.loads((tmp_path / DOCTRINE_MANIFEST_REL).read_text(encoding="utf-8"))
    assert PLATFORM_FINAL_REL in doctrine_manifest["source_refs"]
    assert "KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json" not in doctrine_manifest["source_refs"]

    publication_profile = json.loads((tmp_path / PUBLICATION_PROFILE_REL).read_text(encoding="utf-8"))
    assert "published-head self-convergence remains unresolved" not in publication_profile["explicit_gaps"]
    assert "authority convergence remains unresolved" not in publication_profile["explicit_gaps"]

    readiness = json.loads((tmp_path / READINESS_MATRIX_REL).read_text(encoding="utf-8"))
    assert readiness["summary"] == {"profile_count": 14, "ready_with_boundaries_count": 6, "hold_count": 2, "blocked_count": 6}

    adapter_gate = json.loads((tmp_path / ADAPTER_GATE_REL).read_text(encoding="utf-8"))
    assert adapter_gate["status"] == "PASS"
    assert adapter_gate["adapter_testing_gate_status"] == "OPEN"

    tournament_gate = json.loads((tmp_path / TOURNAMENT_GATE_REL).read_text(encoding="utf-8"))
    assert tournament_gate["status"] == "BLOCKED"


def test_emit_final_recut_and_adjudication_blocks_adapter_gate_when_precondition_fails(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    _seed_common_inputs(tmp_path, canonical_tree_status="BLOCKED")

    receipt = emit_final_recut_and_adjudication(root=tmp_path)

    assert receipt["status"] == "PASS"
    adapter_gate = json.loads((tmp_path / ADAPTER_GATE_REL).read_text(encoding="utf-8"))
    assert adapter_gate["status"] == "BLOCKED"
    assert adapter_gate["adapter_testing_gate_status"] == "BLOCKED"
    assert json.loads((tmp_path / WS11_RECEIPT_REL).read_text(encoding="utf-8"))["status"] == "PASS"
    math_profile = json.loads((tmp_path / MATH_GURU_PROFILE_REL).read_text(encoding="utf-8"))
    assert "authority convergence remains fail-closed" not in math_profile["explicit_gaps"]
