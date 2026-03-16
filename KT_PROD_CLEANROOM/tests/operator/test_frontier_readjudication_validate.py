from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.frontier_readjudication_validate import (  # noqa: E402
    BLOCKED_VERDICT,
    PASS_VERDICT,
    STRONGER_CLAIM_NOT_MADE,
    build_frontier_readjudication_outputs_from_artifacts,
)


def _baseline() -> dict:
    return {
        "manifest_ref": "KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json",
        "packet_refs": [
            "docs/audit/KT_REPO_AUTHORITY_AUDIT_20260309/README.md",
            "docs/audit/KT_REPO_AUTHORITY_AUDIT_20260309/KT_FULL_COMPLETION_ATTEMPT_REPORT_20260310.md",
        ],
        "validated_head_sha": "7bd610b507328eb72622ce24678620f5469f3848",
        "baseline_target_head_commit": "46173df31a9242c2e8f4bd7a1494b3466d1a89b9",
        "clean_clone_equivalent": False,
        "ignored_local_residue_present": True,
        "secret_like_local_residue": ".env.secret",
        "main_problem": "authority drift between live evidence, tracked truth surfaces, and surrounding archive mass",
        "baseline_rows": {
            "repo_hygiene": {"status": "BLOCKED", "grade": "C-", "detail": "residue and secret-like root surface present"},
            "operator_factory_readiness": {"status": "HOLD", "grade": "B", "detail": "truth-sync gap between live runs and tracked receipts"},
            "external_verifiability": {"status": "HOLD", "grade": "C+", "detail": "clean-clone smoke skipped in the fresh run"},
            "bounded_public_horizon": {"status": "BLOCKED", "grade": "C", "detail": "no bounded public horizon open"},
        },
    }


def _ws12_receipt() -> dict:
    return {
        "status": "PASS",
        "subject_head_commit": "1518280c3b0dd7fb6a74c60537c7b8717722cdaa",
        "campaign_completion_state": "SEALED_WITH_BLOCKED_PUBLIC_HORIZONS",
        "adapter_testing_gate_status": "OPEN",
        "tournament_gate_status": "BLOCKED",
        "public_showability_gate_status": "BLOCKED",
    }


def _ws12_bundle() -> dict:
    return {
        "gates": {"h1": "BLOCKED"},
        "still_blocked": ["platform-enforced governance on main", "tournament readiness", "public showability", "H1 activation"],
        "proof_class_summary": {"governance_ceiling": "WORKFLOW_GOVERNANCE_ONLY"},
    }


def _pass_receipt(*, subject: str = "b4789a544954066ee6c225bc9cfa3fddb51c12ee", current_grade: str | None = None) -> dict:
    payload = {
        "status": "PASS",
        "subject_head_commit": subject,
        "evidence_head_commit": subject,
    }
    if current_grade is not None:
        payload["summary"] = {"current_grade": current_grade}
    return payload


def test_frontier_readjudication_passes_when_targets_and_hard_stops_clear() -> None:
    outputs = build_frontier_readjudication_outputs_from_artifacts(
        baseline_audit=_baseline(),
        ws12_receipt=_ws12_receipt(),
        ws12_bundle=_ws12_bundle(),
        ws13_receipt=_pass_receipt(),
        ws14_receipt=_pass_receipt(current_grade="A"),
        ws17_receipt=_pass_receipt(),
        ws18_receipt=_pass_receipt(),
        ws19_receipt=_pass_receipt(),
        ws20_receipt=_pass_receipt(),
        ws21_receipt=_pass_receipt(),
        ws22_receipt=_pass_receipt(),
        ws23_receipt=_pass_receipt(),
        ws15_status_verdict="KT_STATUS_PASS cmd=status profile=v1 allow_dirty=0 head=b4789...",
        ws15_canonical_hmac_verdict="KT_CERTIFY_PASS cmd=certify lane=canonical_hmac profile=v1 allow_dirty=0 head=b4789...",
        ws15_authority_verdict="KT_AUTHORITY_GRADE_A status=PASS blockers=0 integrity_failures=0 head=b4789...",
        changed_files=[
            "KT_PROD_CLEANROOM/tools/operator/frontier_readjudication_validate.py",
            "KT_PROD_CLEANROOM/tests/operator/test_frontier_readjudication_validate.py",
            "KT_PROD_CLEANROOM/reports/kt_frontier_audit_packet.json",
            "KT_PROD_CLEANROOM/reports/kt_frontier_rerun_scorecard.json",
            "KT_PROD_CLEANROOM/reports/kt_sota_readjudication_receipt.json",
        ],
        evaluated_repo_head_commit="0cf1ccdde5a5543678daffe9e60284c903b911ab",
    )

    receipt = outputs["receipt"]
    scorecard = outputs["scorecard"]
    assert receipt["status"] == "PASS"
    assert receipt["pass_verdict"] == PASS_VERDICT
    assert scorecard["final_readjudication"]["overall_bounded_system_grade"] == "A"
    assert scorecard["live_grade_contradiction_check"]["status"] == "PASS"
    assert receipt["questions"]["what_stronger_claim_is_not_made"] == STRONGER_CLAIM_NOT_MADE


def test_frontier_readjudication_blocks_when_live_authority_undercuts_claim() -> None:
    outputs = build_frontier_readjudication_outputs_from_artifacts(
        baseline_audit=_baseline(),
        ws12_receipt=_ws12_receipt(),
        ws12_bundle=_ws12_bundle(),
        ws13_receipt=_pass_receipt(),
        ws14_receipt=_pass_receipt(current_grade="B+"),
        ws17_receipt=_pass_receipt(),
        ws18_receipt=_pass_receipt(),
        ws19_receipt=_pass_receipt(),
        ws20_receipt=_pass_receipt(),
        ws21_receipt=_pass_receipt(),
        ws22_receipt=_pass_receipt(),
        ws23_receipt=_pass_receipt(),
        ws15_status_verdict="KT_STATUS_PASS cmd=status profile=v1 allow_dirty=0 head=b4789...",
        ws15_canonical_hmac_verdict="KT_CERTIFY_PASS cmd=certify lane=canonical_hmac profile=v1 allow_dirty=0 head=b4789...",
        ws15_authority_verdict="KT_AUTHORITY_GRADE_B status=PASS blockers=0 integrity_failures=0 head=b4789...",
        changed_files=[
            "KT_PROD_CLEANROOM/tools/operator/frontier_readjudication_validate.py",
            "KT_PROD_CLEANROOM/tests/operator/test_frontier_readjudication_validate.py",
            "KT_PROD_CLEANROOM/reports/kt_frontier_audit_packet.json",
            "KT_PROD_CLEANROOM/reports/kt_frontier_rerun_scorecard.json",
            "KT_PROD_CLEANROOM/reports/kt_sota_readjudication_receipt.json",
        ],
        evaluated_repo_head_commit="0cf1ccdde5a5543678daffe9e60284c903b911ab",
    )

    receipt = outputs["receipt"]
    scorecard = outputs["scorecard"]
    assert receipt["status"] == "BLOCKED"
    assert receipt["pass_verdict"] == BLOCKED_VERDICT
    assert scorecard["target_checks"][2]["status"] == "FAIL"
    assert scorecard["live_grade_contradiction_check"]["status"] == "FAIL"
