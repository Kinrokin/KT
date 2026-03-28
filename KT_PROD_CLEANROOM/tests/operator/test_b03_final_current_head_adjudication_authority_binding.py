from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from tools.operator import final_current_head_adjudication_validate as final_current

OVERLAY_REFS = [
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/final_current_head_adjudication_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _clean_clone(tmp_path: Path) -> Path:
    root = _repo_root()
    clone_root = tmp_path / "repo"
    subprocess.run(
        ["git", "clone", "--quiet", str(root), str(clone_root)],
        cwd=str(tmp_path),
        check=True,
    )
    for ref in OVERLAY_REFS:
        src = root / ref
        dst = clone_root / ref
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return clone_root


def test_final_current_head_adjudication_candidate_declares_authority_shape_on_current_repo() -> None:
    root = _repo_root()
    blockers = final_current.build_final_blocker_matrix(root=root)
    claims = final_current.build_final_claim_class_outcome(root=root, final_blockers=blockers)
    forbidden = final_current.build_final_forbidden_claims(root=root, claims=claims)
    product_boundary = final_current.build_final_product_truth_boundary(root=root, claims=claims)
    tier = final_current.build_final_tier_ruling(root=root, claims=claims, product_boundary=product_boundary)
    receipt = final_current.build_receipt(
        root=root,
        blockers=blockers,
        claims=claims,
        forbidden=forbidden,
        product_boundary=product_boundary,
        tier=tier,
    )

    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "FUTURE_GATE_C_EXIT_ADJUDICATION_AUTHORITY_FAMILY_CANDIDATE"
    assert receipt["subject_head"] == receipt["current_git_head"]
    assert receipt["gate_c_exit_claim_allowed"] is False
    assert receipt["live_beats_baseline_claim_allowed"] is False
    assert receipt["same_head_authority_contract_ref"] == "tools.operator.benchmark_constitution_validate.evaluate_counted_receipt_family_same_head_authority"
    assert receipt["tracked_counted_receipt_carrier_overread_contract_ref"] == "tools.operator.benchmark_constitution_validate.evaluate_tracked_counted_receipt_carrier_overread"
    assert receipt["exact_current_head_standing"]["open_current_head_claim_blocker_ids"] == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"]
    assert receipt["exact_current_head_standing"]["highest_truthful_tier_output"] == "NOT_FRONTIER"


def test_w3_cli_emits_t24_receipt_with_explicit_output(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    final_blocker_matrix_path = tmp_path / "final_blocker_matrix.json"
    final_claim_class_path = tmp_path / "final_claim_class_outcome.json"
    final_forbidden_claims_path = tmp_path / "final_forbidden_claims.json"
    final_product_truth_path = tmp_path / "final_product_truth_boundary.json"
    final_tier_ruling_path = tmp_path / "final_tier_ruling.json"

    final_proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.final_current_head_adjudication_validate",
            "--allow-tracked-output-refresh",
            "--final-blocker-matrix-output",
            str(final_blocker_matrix_path),
            "--final-claim-class-output",
            str(final_claim_class_path),
            "--final-forbidden-claims-output",
            str(final_forbidden_claims_path),
            "--final-product-truth-output",
            str(final_product_truth_path),
            "--final-tier-ruling-output",
            str(final_tier_ruling_path),
        ],
        cwd=str(root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert final_proc.returncode == 0, final_proc.stdout

    subprocess.run(["git", "config", "user.email", "t24-test@example.invalid"], cwd=str(root), check=True)
    subprocess.run(["git", "config", "user.name", "T24 Test"], cwd=str(root), check=True)
    subprocess.run(
        ["git", "add", "KT_PROD_CLEANROOM/reports/final_current_head_adjudication_receipt.json"],
        cwd=str(root),
        check=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "refresh final current head adjudication receipt for T24 test"],
        cwd=str(root),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    e2_path = tmp_path / "e2.json"
    atlas_path = tmp_path / "atlas.json"
    canonical_delta_path = tmp_path / "canonical_delta.json"
    advancement_delta_path = tmp_path / "advancement_delta.json"
    t24_receipt_path = tmp_path / "final_current_head_adjudication_authority_binding_receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.w3_externality_and_comparative_proof_validate",
            "--e2-output",
            str(e2_path),
            "--capability-atlas-output",
            str(atlas_path),
            "--canonical-delta-output",
            str(canonical_delta_path),
            "--advancement-delta-output",
            str(advancement_delta_path),
            "--emit-final-current-head-adjudication-authority-binding-receipt",
            "--final-current-head-adjudication-authority-binding-output",
            str(t24_receipt_path),
        ],
        cwd=str(root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["status"] == "PASS"
    assert payload["final_current_head_adjudication_authority_binding_status"] == "PASS"

    receipt = json.loads(t24_receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "COUNTED_T24_FINAL_CURRENT_HEAD_ADJUDICATION_AUTHORITY_BINDING_ARTIFACT_ONLY"
    assert receipt["tracked_final_current_head_adjudication_authority_class"] == "DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH"
    assert receipt["tracked_final_current_head_adjudication_contract"]["blocked"] is True
    assert receipt["tracked_final_current_head_adjudication_contract"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH"
    assert receipt["authoritative_current_head_final_current_adjudication_candidate_contract"]["pass"] is True
    assert receipt["authoritative_current_head_final_current_adjudication_candidate_contract"]["subject_head"] == receipt["current_git_head"]
