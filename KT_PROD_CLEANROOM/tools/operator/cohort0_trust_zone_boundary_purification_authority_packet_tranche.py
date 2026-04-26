from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_trust_zone_boundary_purification_authority_packet.json"
OUTPUT_RECEIPT = "cohort0_trust_zone_boundary_purification_authority_receipt.json"
OUTPUT_REPORT = "COHORT0_TRUST_ZONE_BOUNDARY_PURIFICATION_AUTHORITY_REPORT.md"

REQUIRED_BRANCH = "authoritative/trust-zone-boundary-purification"
EXECUTION_STATUS = "PASS__TRUST_ZONE_BOUNDARY_PURIFICATION_AUTHORITY_PACKET_BOUND"
OUTCOME = "TRUST_ZONE_BOUNDARY_PURIFICATION_PROMOTED_AS_AUTHORITATIVE_LANE"
NEXT_MOVE = "AUTHOR_TRUST_ZONE_BOUNDARY_PURIFICATION_REGISTRY_AND_SCOPE_CONTRACT"
EXPECTED_TRUST_ZONE_PREP_OUTCOME = "POST_F_TRUST_ZONE_BOUNDARY_PURIFICATION_PREP_DEFINED__NON_AUTHORITATIVE"


def _current_branch_name(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip() or "UNKNOWN_BRANCH"


def _git_status_porcelain(root: Path) -> str:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout


def build_outputs(*, audit_receipt: Dict[str, Any], prep_packet: Dict[str, Any], prep_receipt: Dict[str, Any]) -> Dict[str, Dict[str, Any] | str]:
    root = repo_root()
    packet = {
        "schema_id": "kt.operator.cohort0_trust_zone_boundary_purification_authority_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "outcome": OUTCOME,
        "authoritative_lane": REQUIRED_BRANCH,
        "claim_boundary": (
            "This packet promotes trust-zone/boundary purification as the next authoritative lane after canonical "
            "truth-engine replay. It does not perform package promotion, widen Gate F product truth, or alter "
            "truth-engine derivation law."
        ),
        "authority_inputs": common.output_ref_dict(
            post_merge_audit_receipt=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_merge_canonical_truth_boundary_readiness_audit_receipt.json"),
            prior_prep_packet=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_trust_zone_boundary_purification_packet.json"),
            prior_prep_receipt=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_trust_zone_boundary_purification_receipt.json"),
            truth_engine_handoff=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_post_pr_canonical_handoff_receipt.json"),
        ),
        "promotion_basis": {
            "post_merge_audit_outcome": str(audit_receipt.get("outcome", "")).strip(),
            "post_merge_audit_next_lawful_move": str(audit_receipt.get("next_lawful_move", "")).strip(),
            "prior_prep_outcome": str(prep_receipt.get("outcome", "")).strip(),
            "prior_prep_was_non_authoritative": True,
        },
        "mutable_surface_contract": {
            "allowed_mutable_surfaces": [
                "KT_PROD_CLEANROOM/governance/trust_zone_registry.json",
                "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json",
                "KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json",
                "KT_PROD_CLEANROOM/governance/runtime_boundary_contract.json",
                "KT_PROD_CLEANROOM/governance/canonical_freeze_manifest.json",
                "KT_PROD_CLEANROOM/governance/amendment_scope_manifest.json",
                "KT_PROD_CLEANROOM/reports/cohort0_trust_zone_boundary_purification_*",
            ],
            "allowed_operator_surfaces": [
                "KT_PROD_CLEANROOM/tools/operator/trust_zone_validate.py",
                "KT_PROD_CLEANROOM/tests/operator/test_trust_zone_validate.py",
                "KT_PROD_CLEANROOM/tools/operator/cohort0_trust_zone_boundary_purification_*",
                "KT_PROD_CLEANROOM/tests/operator/test_cohort0_trust_zone_boundary_purification_*",
            ],
            "forbidden_mutations": [
                "package promotion or stage_and_promote.sh execution",
                "truth-engine derivation law changes",
                "Track 01 bounded comparative claim widening",
                "Track 02 dual-audit historical baseline mutation",
                "Track 03 counted-path or human-review receipt mutation",
                "archive or KT-Codex resurrection into live authority",
            ],
        },
        "success_gates": [
            "trust_zone_validate must pass after every registry/scope change",
            "truth-engine recompute must remain zero blocking and zero advisory after boundary changes",
            "package truth must remain PACKAGE_PROMOTION_DEFERRED unless a separate promotion court authorizes otherwise",
            "noncanonical residue must be classified as lab, archive, commercial, generated truth, toolchain proving, or quarantine",
            "protected PR path remains required for canonical main adoption",
        ],
        "initial_boundary_inputs": {
            "canonical_scope_manifest_v2": dict(prep_packet.get("canonical_scope_manifest_v2", {})),
            "noncanonical_quarantine_candidate_list_v2": dict(prep_packet.get("noncanonical_quarantine_candidate_list_v2", {})),
            "promotion_safe_boundary_recommendations_v2": list(prep_packet.get("promotion_safe_boundary_recommendations_v2", [])),
        },
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_trust_zone_boundary_purification_authority_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "outcome": OUTCOME,
        "allowed_mutable_surface_count": len(packet["mutable_surface_contract"]["allowed_mutable_surfaces"]),
        "forbidden_mutation_count": len(packet["mutable_surface_contract"]["forbidden_mutations"]),
        "next_lawful_move": NEXT_MOVE,
    }
    report = common.report_lines(
        "Cohort0 Trust Zone Boundary Purification Authority Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Outcome: `{OUTCOME}`",
            f"- Authoritative lane: `{REQUIRED_BRANCH}`",
            "- Package promotion: `deferred`",
            "- Truth-engine law changes: `forbidden in this authority packet`",
            f"- Allowed mutable surface count: `{receipt['allowed_mutable_surface_count']}`",
            f"- Forbidden mutation count: `{receipt['forbidden_mutation_count']}`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(*, reports_root: Path, audit_receipt_path: Path, prep_packet_path: Path, prep_receipt_path: Path) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: trust-zone authority packet must run on {REQUIRED_BRANCH}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: trust-zone authority packet requires a clean worktree")
    audit_receipt = common.load_json_required(root, audit_receipt_path, label="post-merge boundary-readiness audit receipt")
    prep_packet = common.load_json_required(root, prep_packet_path, label="prior trust-zone prep packet")
    prep_receipt = common.load_json_required(root, prep_receipt_path, label="prior trust-zone prep receipt")
    common.ensure_pass(audit_receipt, label="post-merge boundary-readiness audit receipt")
    common.ensure_pass(prep_packet, label="prior trust-zone prep packet")
    common.ensure_pass(prep_receipt, label="prior trust-zone prep receipt")
    if str(audit_receipt.get("next_lawful_move", "")).strip() != "PROMOTE_TRUST_ZONE_BOUNDARY_PURIFICATION_AS_NEXT_AUTHORITATIVE_LANE":
        raise RuntimeError("FAIL_CLOSED: post-merge audit must authorize trust-zone boundary purification promotion")
    if str(prep_receipt.get("outcome", "")).strip() != EXPECTED_TRUST_ZONE_PREP_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: prior trust-zone prep receipt must preserve the expected non-authoritative prep outcome")
    outputs = build_outputs(audit_receipt=audit_receipt, prep_packet=prep_packet, prep_receipt=prep_receipt)
    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    return {"outcome": OUTCOME, "next_lawful_move": NEXT_MOVE}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Promote trust-zone boundary purification as the next authoritative lane.")
    parser.add_argument("--audit-receipt", default="KT_PROD_CLEANROOM/reports/cohort0_post_merge_canonical_truth_boundary_readiness_audit_receipt.json")
    parser.add_argument("--prep-packet", default="KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_trust_zone_boundary_purification_packet.json")
    parser.add_argument("--prep-receipt", default="KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_trust_zone_boundary_purification_receipt.json")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        audit_receipt_path=common.resolve_path(root, args.audit_receipt),
        prep_packet_path=common.resolve_path(root, args.prep_packet),
        prep_receipt_path=common.resolve_path(root, args.prep_receipt),
    )
    print(result["outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
