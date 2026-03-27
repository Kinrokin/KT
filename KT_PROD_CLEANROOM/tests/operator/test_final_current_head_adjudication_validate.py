from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

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


def test_final_current_head_adjudication_cli_compiles_bounded_final_verdict(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    final_blocker_matrix_path = tmp_path / "final_blocker_matrix.json"
    final_claim_class_path = tmp_path / "final_claim_class_outcome.json"
    final_forbidden_claims_path = tmp_path / "final_forbidden_claims.json"
    final_product_truth_path = tmp_path / "final_product_truth_boundary.json"
    final_tier_ruling_path = tmp_path / "final_tier_ruling.json"
    receipt_path = tmp_path / "final_current_head_adjudication_receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.final_current_head_adjudication_validate",
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
            "--receipt-output",
            str(receipt_path),
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
    assert payload["highest_truthful_tier_output"] == "NOT_FRONTIER"
    assert payload["open_current_head_claim_blocker_ids"] == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"]
    assert payload["product_truth_class"] == "BOUNDED_E1_BUYER_SIMPLE_PRODUCT_PLANE"
    assert payload["comparator_contract_status"] == "PASS"
    assert payload["documentary_carrier_consumer_status"] == "PASS"

    final_blocker_matrix = json.loads(final_blocker_matrix_path.read_text(encoding="utf-8"))
    final_claim_class = json.loads(final_claim_class_path.read_text(encoding="utf-8"))
    final_forbidden_claims = json.loads(final_forbidden_claims_path.read_text(encoding="utf-8"))
    final_product_truth = json.loads(final_product_truth_path.read_text(encoding="utf-8"))
    final_tier_ruling = json.loads(final_tier_ruling_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

    assert final_blocker_matrix["status"] == "PASS"
    assert final_blocker_matrix["active_current_head_claim_blocker_count"] == 1
    assert final_blocker_matrix["active_current_head_claim_blocker_ids"] == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"]

    assert final_claim_class["status"] == "PASS"
    assert final_claim_class["externality_class_max"] == "E1_SAME_HOST_DETACHED_REPLAY"
    assert final_claim_class["comparative_widening"] == "FORBIDDEN"
    assert final_claim_class["commercial_widening"] == "FORBIDDEN"
    assert final_claim_class["router_canonical_status"] == "STATIC_CANONICAL_BASELINE_ONLY"
    assert final_claim_class["router_superiority_earned"] is False
    assert final_claim_class["multi_lobe_promotion_allowed"] is False

    assert final_forbidden_claims["status"] == "PASS"
    assert final_forbidden_claims["forbidden_claim_count"] >= 8
    assert any("Do not claim E2" in row for row in final_forbidden_claims["forbidden_claims_remaining"])

    assert final_product_truth["status"] == "PASS"
    assert final_product_truth["product_truth_class"] == "BOUNDED_E1_BUYER_SIMPLE_PRODUCT_PLANE"
    assert final_product_truth["install_to_pass_fail_minutes"] == 15
    assert final_product_truth["max_externality_class"] == "E1_SAME_HOST_DETACHED_REPLAY"

    assert final_tier_ruling["status"] == "PASS"
    assert final_tier_ruling["highest_truthful_tier_output"] == "NOT_FRONTIER"
    assert final_tier_ruling["current_head_tier_id"] == "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1"

    assert receipt["status"] == "PASS"
    assert receipt["documentary_carrier_consumer_guard"]["status"] == "PASS"
    assert receipt["documentary_carrier_consumer_guard"]["documentary_carrier_attempt"]["failure_reason"] == "DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH"
    assert receipt["documentary_carrier_consumer_guard"]["shared_guard_helper_ref"] == "tools.operator.benchmark_constitution_validate.evaluate_documentary_carrier_fail_closed_consumer_guard"
    assert receipt["documentary_carrier_consumer_guard"]["shared_guard_helper_owner_ref"] == "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py"
    assert receipt["exact_current_head_standing"]["open_current_head_claim_blocker_ids"] == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"]
    assert receipt["exact_current_head_standing"]["highest_truthful_tier_output"] == "NOT_FRONTIER"
