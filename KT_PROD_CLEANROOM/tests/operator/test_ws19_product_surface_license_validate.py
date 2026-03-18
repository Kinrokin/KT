from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.ws19_product_surface_license_validate import (  # noqa: E402
    ACCEPTANCE_POLICY_REL,
    COMMERCIAL_COMPILER_REL,
    COMMERCIAL_PROGRAM_CATALOG_REL,
    DISTRIBUTION_POLICY_REL,
    EXECUTION_DAG_REL,
    LICENSE_REL,
    LICENSE_TRACK_POLICY_REL,
    PASS_VERDICT,
    PRODUCT_CLAIM_COMPILER_REL,
    PRODUCT_CLAIM_POLICY_REL,
    PRODUCT_SURFACE_MANIFEST_REL,
    PRODUCT_SURFACE_POLICY_REL,
    PRODUCT_SURFACE_RECEIPT_REL,
    README_REL,
    READINESS_SCOPE_REL,
    STATIC_RELEASE_MANIFEST_REL,
    STATIC_VERIFIER_ATTESTATION_REL,
    STATIC_VERIFIER_SBOM_REL,
    TEST_REL,
    TOOL_REL,
    WS14_RECEIPT_REL,
    WS15_COMPILER_REL,
    WS17A_RECEIPT_REL,
    WS17B_RECEIPT_REL,
    WS18_BLOCKER_MATRIX_REL,
    WS18_RECEIPT_REL,
    WS18_RELEASE_STATUS_REL,
    emit_ws19_product_surface_license,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _git(tmp_path: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(tmp_path), *args], text=True, encoding="utf-8").strip()


def _commit_all(tmp_path: Path, message: str) -> str:
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", message)
    return _git(tmp_path, "rev-parse", "HEAD")


def _init_git_repo(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test User")


def _seed_ws19_repo(tmp_path: Path) -> str:
    _init_git_repo(tmp_path)
    tool_source = Path(__file__).resolve().parents[2] / "tools/operator/ws19_product_surface_license_validate.py"
    (tmp_path / TOOL_REL).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / TOOL_REL).write_text(tool_source.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    (tmp_path / TEST_REL).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / TEST_REL).write_text("seed\n", encoding="utf-8", newline="\n")
    (tmp_path / LICENSE_REL).write_text(
        "KING'S THEOREM RESTRICTED RESEARCH LICENSE v1.1\nPermission is granted solely for non-commercial research.\nCommercial use requires a separate written license.\n",
        encoding="utf-8",
        newline="\n",
    )
    (tmp_path / README_REL).write_text(
        "KT is source-available for non-commercial research, evaluation, and educational use only.\nCommercial use requires a separate written license.\n",
        encoding="utf-8",
        newline="\n",
    )
    ws18_subject_head = _commit_all(tmp_path, "freeze ws18 boundary")

    _write_json(tmp_path / READINESS_SCOPE_REL, {"schema_id": "kt.governance.readiness_scope_manifest.v2", "status": "ACTIVE", "readiness_excludes_zones": ["COMMERCIAL", "ARCHIVE"]})
    _write_json(tmp_path / WS14_RECEIPT_REL, {"schema_id": "kt.operator.public_verifier_release_receipt.v1", "status": "PASS", "limitations": ["bounded only"]})
    _write_json(tmp_path / WS17A_RECEIPT_REL, {"schema_id": "kt.operator.ws17a.external_assurance_confirmation_receipt.v1", "status": "PASS", "bounded_assurance_surface": "KT_PROD_CLEANROOM/reports/ws13_determinism/ci/public_verifier_manifest.json"})
    _write_json(tmp_path / WS17B_RECEIPT_REL, {"schema_id": "kt.operator.ws17b.external_capability_confirmation_receipt.v1", "status": "PASS", "capability_scope": "HISTORICAL_BOUNDED_FRONTIER_TARGET_ONLY"})
    _write_json(
        tmp_path / WS18_RECEIPT_REL,
        {
            "schema_id": "kt.operator.ws18.final_readjudication_receipt.v1",
            "status": "PASS",
            "compiled_against": ws18_subject_head,
            "current_repo_head": ws18_subject_head,
            "final_verdict": {
                "release_eligibility": "NOT_ELIGIBLE",
                "campaign_completion_status": "NOT_PROVEN",
                "current_head_capability_status": "NOT_EXTERNALLY_CONFIRMED",
                "historical_capability_status": "PROVEN_HISTORICAL_BOUNDED_ONLY",
            },
        },
    )
    _write_json(tmp_path / WS18_RELEASE_STATUS_REL, {"schema_id": "kt.operator.ws18.release_ceremony_status_receipt.v1", "status": "PASS", "release_ceremony_status": "NON_EXECUTED_BLOCKED_BY_PREREQUISITES"})
    _write_json(
        tmp_path / WS18_BLOCKER_MATRIX_REL,
        {
            "schema_id": "kt.operator.ws18.blocker_matrix.v1",
            "status": "ACTIVE",
            "open_blockers": [
                "THRESHOLD_ROOT_VERIFIER_ACCEPTANCE_PENDING",
                "RELEASE_CEREMONY_NOT_EXECUTED",
                "CURRENT_HEAD_CAPABILITY_NOT_EXTERNALLY_CONFIRMED",
                "CAMPAIGN_COMPLETION_NOT_PROVEN",
            ],
        },
    )
    _write_json(tmp_path / WS15_COMPILER_REL, {"schema_id": "kt.operator.claim_proof_ceiling_compiler.v1", "status": "PASS", "blocked_current_claim_ids": ["campaign_completion_proven", "release_readiness_proven", "threshold_root_verifier_acceptance_active"]})
    _write_json(
        tmp_path / COMMERCIAL_COMPILER_REL,
        {
            "schema_id": "kt.operator.commercial_claim_compiler_receipt.v1",
            "status": "PASS",
            "claim_compiler_claim_boundary": "This receipt compiles admissible commercial claims for compiled_head_commit only. A later repository head that contains this receipt must not be described as the compiled head unless the SHAs match.",
        },
    )
    _write_json(
        tmp_path / COMMERCIAL_PROGRAM_CATALOG_REL,
        {
            "schema_id": "kt.commercial_program_catalog.v2",
            "status": "ACTIVE",
            "documentary_only": True,
            "compiled_head_commit": "2a6d3621491ce0ee167335f9fd8c97977e9fe292",
            "claim_compiler_claim_boundary": "This receipt compiles admissible commercial claims for compiled_head_commit only. A later repository head that contains this receipt must not be described as the compiled head unless the SHAs match.",
        },
    )
    for rel in [STATIC_RELEASE_MANIFEST_REL, STATIC_VERIFIER_SBOM_REL, STATIC_VERIFIER_ATTESTATION_REL, ACCEPTANCE_POLICY_REL, DISTRIBUTION_POLICY_REL]:
        _write_json(tmp_path / rel, {"schema_id": "seed", "status": "ACTIVE", "path": rel})
    _write_json(
        tmp_path / EXECUTION_DAG_REL,
        {
            "schema_id": "kt.governance.execution_dag.v1",
            "status": "ACTIVE",
            "current_node": "WS18_RELEASE_CEREMONY_AND_FINAL_READJUDICATION",
            "current_repo_head": ws18_subject_head,
            "next_lawful_workstream": "WS19_PRODUCT_SURFACE_AND_LICENSE_TRACK",
            "semantic_boundary": {"lawful_current_claim": "seed", "stronger_claim_not_made": []},
            "nodes": [
                {"id": "WS18_RELEASE_CEREMONY_AND_FINAL_READJUDICATION", "status": "PASS", "ratification_checkpoint": "kt_final_readjudication_receipt.json"},
                {"id": "WS19_PRODUCT_SURFACE_AND_LICENSE_TRACK", "status": "UNLOCKED", "ratification_checkpoint": "product_surface_receipt"},
            ],
        },
    )
    _commit_all(tmp_path, "seed ws19 inputs")
    return _git(tmp_path, "rev-parse", "HEAD")


def test_emit_ws19_passes_with_bounded_product_surface(tmp_path: Path) -> None:
    current_head = _seed_ws19_repo(tmp_path)
    receipt = emit_ws19_product_surface_license(root=tmp_path)
    assert receipt["status"] == "PASS"
    assert receipt["pass_verdict"] == PASS_VERDICT
    assert receipt["compiled_against"] == current_head
    assert receipt["campaign_completion_status"] == "STILL_BLOCKED"
    assert receipt["next_lawful_workstream"] is None
    assert (tmp_path / PRODUCT_SURFACE_POLICY_REL).exists()
    assert (tmp_path / LICENSE_TRACK_POLICY_REL).exists()
    assert (tmp_path / PRODUCT_CLAIM_POLICY_REL).exists()
    assert (tmp_path / PRODUCT_SURFACE_MANIFEST_REL).exists()
    assert (tmp_path / PRODUCT_CLAIM_COMPILER_REL).exists()
    assert (tmp_path / PRODUCT_SURFACE_RECEIPT_REL).exists()
    dag = json.loads((tmp_path / EXECUTION_DAG_REL).read_text(encoding="utf-8"))
    assert dag["current_node"] == "WS19_PRODUCT_SURFACE_AND_LICENSE_TRACK"
    assert dag["next_lawful_workstream"] is None


def test_emit_ws19_blocks_when_ws18_final_verdict_is_not_non_release_eligible(tmp_path: Path) -> None:
    _seed_ws19_repo(tmp_path)
    broken = json.loads((tmp_path / WS18_RECEIPT_REL).read_text(encoding="utf-8"))
    broken["final_verdict"]["release_eligibility"] = "ELIGIBLE_PENDING_OPERATOR_DECISION"
    _write_json(tmp_path / WS18_RECEIPT_REL, broken)
    _commit_all(tmp_path, "break ws18 final verdict boundary")
    receipt = emit_ws19_product_surface_license(root=tmp_path)
    assert receipt["status"] == "BLOCKED"
    assert "FINAL_VERDICT_NOT_BOUNDED_NON_RELEASE_ELIGIBLE" in receipt["blocked_by"]
