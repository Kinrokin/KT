from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_parallel_trust_zone_boundary_purification_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_parallel_trust_zone_boundary_purification_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_PARALLEL_TRUST_ZONE_BOUNDARY_PURIFICATION_REPORT.md"

REQUIRED_BRANCH = "authoritative/post-f-truth-engine"
EXECUTION_STATUS = "PASS__POST_F_TRUST_ZONE_BOUNDARY_PURIFICATION_PREP_BOUND"
OUTCOME = "POST_F_TRUST_ZONE_BOUNDARY_PURIFICATION_PREP_DEFINED__NON_AUTHORITATIVE"
NEXT_MOVE = "RERUN_POST_F_TRUTH_ENGINE_RECOMPUTE_ON_MAIN_AFTER_PR15_MERGE"


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


def build_outputs(*, scope_packet: Dict[str, Any], recompute_receipt: Dict[str, Any]) -> Dict[str, Dict[str, Any] | str]:
    root = repo_root()
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_parallel_trust_zone_boundary_purification_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "outcome": OUTCOME,
        "claim_boundary": "Non-authoritative trust-zone/boundary purification prep only. It does not rewrite live truth or package boundaries.",
        "trust_zone_registry_refined": {
            "canonical_live_truth": {
                "allowed_roots": [
                    "KT_PROD_CLEANROOM/reports/cohort0_successor_*",
                    "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_0*_final_summary_*",
                    "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_*",
                ],
                "forbidden_overrides": [
                    "prep lane packets",
                    "deferred package artifacts",
                    "historical quarantine surfaces",
                ],
            },
            "branch_local_execution_truth": {
                "allowed_roots": ["KT_PROD_CLEANROOM/runs/post_f_track_03/**"],
                "promotion_rule": "preserve as execution history only until separately promoted",
            },
        },
        "canonical_scope_manifest_v2": {
            "authoritative_branch": "main",
            "authoritative_successor_branch": REQUIRED_BRANCH,
            "live_truth_include": [
                "KT_PROD_CLEANROOM/reports/cohort0_successor_*",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_01_*",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_*",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_03_*",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_*",
            ],
            "live_truth_exclude": [
                "KT_PROD_CLEANROOM/runs/**",
                "KT-Codex/**",
                "KT_ARCHIVE/**",
                "reports/track02_partial_run_quarantine_*",
            ],
        },
        "noncanonical_quarantine_candidate_list_v2": {
            "candidates": [
                "KT_PROD_CLEANROOM/runs/post_f_track_03/**",
                "KT_PROD_CLEANROOM/runs/**/staging/scripts/stage_and_promote.sh",
                "KT-Codex/**",
                "KT_ARCHIVE/**",
                "root forensic freeze artifacts",
            ],
            "quarantine_reason": "prevent execution-history or deferred package material from driving canonical truth",
        },
        "promotion_safe_boundary_recommendations_v2": [
            "Truth-engine recompute outputs may become canonical only after remote main convergence.",
            "Deferred package artifacts remain excluded from repo truth until a separate package-promotion court.",
            "Trust-zone purification remains prep-only until separately promoted after canonical truth-engine replay on main.",
        ],
        "source_refs": common.output_ref_dict(
            prior_scope_packet=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_trust_zone_boundary_scope_packet.json"),
            recompute_receipt=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_recompute_receipt.json"),
        ),
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_parallel_trust_zone_boundary_purification_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "outcome": OUTCOME,
        "quarantine_candidate_count": len(packet["noncanonical_quarantine_candidate_list_v2"]["candidates"]),
        "next_lawful_move": NEXT_MOVE,
    }
    report = common.report_lines(
        "Cohort0 Post-F Parallel Trust Zone Boundary Purification Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Outcome: `{OUTCOME}`",
            "- Lane remains non-authoritative.",
            "- Package boundary remains unchanged.",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(*, reports_root: Path, scope_packet_path: Path, recompute_receipt_path: Path) -> Dict[str, Any]:
    root = repo_root()
    if _current_branch_name(root) != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: trust-zone purification prep must run on {REQUIRED_BRANCH}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: trust-zone purification prep requires a clean worktree")
    scope_packet = common.load_json_required(root, scope_packet_path, label="trust-zone scope packet")
    recompute_receipt = common.load_json_required(root, recompute_receipt_path, label="truth-engine recompute receipt")
    common.ensure_pass(scope_packet, label="trust-zone scope packet")
    common.ensure_pass(recompute_receipt, label="truth-engine recompute receipt")
    outputs = build_outputs(scope_packet=scope_packet, recompute_receipt=recompute_receipt)
    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    return {"outcome": OUTCOME}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Deepen the trust-zone boundary purification prep lane.")
    parser.add_argument(
        "--scope-packet",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_parallel_trust_zone_boundary_scope_packet.json",
    )
    parser.add_argument(
        "--recompute-receipt",
        default="KT_PROD_CLEANROOM/reports/cohort0_post_f_truth_engine_recompute_receipt.json",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        scope_packet_path=common.resolve_path(root, args.scope_packet),
        recompute_receipt_path=common.resolve_path(root, args.recompute_receipt),
    )
    print(result["outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
